// server.js (Atlas Backend — Fixed Auth + AI Tools)
const fs = require('fs');
const path = require('path');
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const app = express();

// Robust CORS for GH Pages + HTTPS
app.use(cors({
  origin: true,
  methods: ['GET','POST','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization'],
  maxAge: 86400
}));
app.options('*', cors());
app.use(bodyParser.json({ limit: '1mb' }));

const PORT = process.env.PORT || 8787;
const JWT_SECRET = process.env.JWT_SECRET || "dev-secret-change-me";
const DATA_FILE = process.env.DATA_FILE || path.join(__dirname, 'data.json');

function readDB(){
  try { return JSON.parse(fs.readFileSync(DATA_FILE,'utf8')); }
  catch(e){ return { users: [], jobs: JOBS_DEFAULT }; }
}
function writeDB(db){ fs.writeFileSync(DATA_FILE, JSON.stringify(db, null, 2), 'utf8'); }

const JOBS_DEFAULT = [
  { id: 1, company: 'Tech Corp', title: 'Senior Python Developer', date: '2024-10-11',
    skills: ['python','microservices','aws','docker','kubernetes','sql'],
    certs: ['aws solutions architect'], minYears: 5,
    keywords: ['backend','scalable','cloud','api','lambda','ec2','s3','rds'] },
  { id: 2, company: 'Data Systems Inc', title: 'Data Scientist', date: '2024-10-10',
    skills: ['python','pandas','numpy','ml','sklearn','sql','aws'],
    certs: [], minYears: 3,
    keywords: ['modeling','statistics','nlp','timeseries','notebook','experimentation'] },
  { id: 3, company: 'Cloud Solutions', title: 'DevOps Engineer', date: '2024-10-09',
    skills: ['docker','kubernetes','terraform','ci/cd','linux','aws'],
    certs: ['cka'], minYears: 4,
    keywords: ['observability','sre','prometheus','grafana','gitops'] },
  { id: 4, company: 'FinTech Global', title: 'Full Stack Developer', date: '2024-10-08',
    skills: ['javascript','react','node','sql','python'],
    certs: [], minYears: 4,
    keywords: ['payments','security','microfrontends','testing','cicd'] },
];

function normalize(text){ return (text || '').toLowerCase().replace(/[^a-z0-9+#.\-\s]/g,' ').replace(/\s+/g,' ').trim(); }
function tokenize(text){ return normalize(text).split(' ').filter(Boolean); }
function termFreq(tokens){
  const tf = Object.create(null);
  tokens.forEach(t => tf[t]=(tf[t]||0)+1);
  const len=tokens.length||1;
  Object.keys(tf).forEach(k=>tf[k]=tf[k]/len);
  return tf;
}
function vectorize(tf, vocab){ return vocab.map(t=>tf[t]||0); }
function cosine(a,b){
  let dot=0,na=0,nb=0;
  for(let i=0;i<a.length;i++){ dot+=a[i]*b[i]; na+=a[i]*a[i]; nb+=b[i]*b[i]; }
  if(!na||!nb) return 0;
  return dot/(Math.sqrt(na)*Math.sqrt(nb));
}
let VOCAB=[];
function buildVocab(jobs){
  VOCAB = Array.from(new Set(jobs.flatMap(j=>[...j.skills,...j.keywords,...tokenize(j.title), j.company.toLowerCase()]).map(w=>w.toLowerCase())));
}
function matchScore(cvText, job){
  const cv=normalize(cvText);
  const tokens=tokenize(cv);
  const tf=termFreq(tokens);
  const cvVec=vectorize(tf,VOCAB);

  const jobBag=[...job.skills,...job.keywords,...tokenize(job.title),job.company.toLowerCase()].join(' ');
  const jobTf=termFreq(tokenize(jobBag));
  const jobVec=vectorize(jobTf,VOCAB);
  const cos=cosine(cvVec,jobVec);

  const haveSkills=job.skills.filter(s=>cv.includes(s));
  const missingSkills=job.skills.filter(s=>!cv.includes(s));
  const skillCoverage=haveSkills.length/Math.max(1,job.skills.length);

  const haveCerts=job.certs.filter(c=>cv.includes(c));
  const missingCerts=job.certs.filter(c=>!cv.includes(c));
  const certCoverage=job.certs.length?haveCerts.length/job.certs.length:1;

  const yrsMatch=cv.match(/(\d+)\+?\s*(?:yrs|years|лет|года|г\.?)|experience\s*(\d+)/i);
  let years=0;
  if(yrsMatch){ years=parseInt(yrsMatch[1]||yrsMatch[2]||'0',10)||0; }
  else { const roleHits=(cv.match(/developer|engineer|analyst|manager/gi)||[]).length; years=Math.min(10,Math.floor(roleHits/2)); }
  const expFactor=Math.min(1, years/Math.max(1,job.minYears));

  const score=0.35*cos+0.35*skillCoverage+0.15*certCoverage+0.15*expFactor;
  return { score, gaps:{ missingSkills, missingCerts, expGapYears: Math.max(0, job.minYears - years) } };
}

// Auth helpers
function signToken(user){
  return jwt.sign({ uid:user.id, name:user.name, email:user.email }, JWT_SECRET, { expiresIn:'7d' });
}
function authMiddleware(req,res,next){
  const h=req.headers.authorization||'';
  const m=h.match(/^Bearer (.+)$/i);
  if(!m) return res.status(401).json({error:'Missing Authorization header'});
  try{ const payload=jwt.verify(m[1], JWT_SECRET); req.user=payload; next(); }
  catch(e){ return res.status(401).json({error:'Invalid token'}); }
}

// Routes
app.get('/api/health',(req,res)=>res.json({ok:true}));

app.post('/api/auth/signup', async (req,res)=>{
  const {name,email,password}=req.body||{};
  if(!name||!email||!password) return res.status(400).json({error:'name, email, password are required'});
  const db=readDB();
  const exists=db.users.find(u=>u.email.toLowerCase()===String(email).toLowerCase());
  if(exists) return res.status(409).json({error:'Email already registered'});
  const id=String(Date.now());
  const hash=await bcrypt.hash(password,10);
  const user={id,name,email,hash,createdAt:new Date().toISOString()};
  db.users.push(user);
  writeDB(db);
  const token=signToken(user);
  res.json({token, user:{id,name,email}});
});

app.post('/api/auth/login', async (req,res)=>{
  const {email,password}=req.body||{};
  if(!email||!password) return res.status(400).json({error:'email, password are required'});
  const db=readDB();
  const user=db.users.find(u=>u.email.toLowerCase()===String(email).toLowerCase());
  if(!user) return res.status(401).json({error:'Invalid email or password'});
  const ok=await bcrypt.compare(password,user.hash);
  if(!ok) return res.status(401).json({error:'Invalid email or password'});
  const token=signToken(user);
  res.json({token, user:{id:user.id,name:user.name,email:user.email}});
});

app.get('/api/auth/me', authMiddleware, (req,res)=>{
  const db=readDB();
  const user=db.users.find(u=>u.id===req.user.uid);
  if(!user) return res.status(404).json({error:'User not found'});
  res.json({user:{id:user.id,name:user.name,email:user.email}});
});

app.get('/api/jobs',(req,res)=>{
  const db=readDB();
  res.json(db.jobs||JOBS_DEFAULT);
});

app.post('/api/match', authMiddleware, (req,res)=>{
  const {cvText}=req.body||{};
  if(!cvText||typeof cvText!=='string') return res.status(400).json({error:'cvText (string) is required'});
  const db=readDB();
  const jobs=db.jobs||JOBS_DEFAULT;
  buildVocab(jobs);
  const results=jobs.map(j=>{
    const {score,gaps}=matchScore(cvText,j);
    return {id:j.id,company:j.company,title:j.title,date:j.date,score:Math.round(score*100),gaps};
  }).sort((a,b)=>b.score-a.score);
  res.json({results});
});

app.post('/api/align-cv', authMiddleware, (req,res)=>{
  const {cvText,targetJobId}=req.body||{};
  const db=readDB();
  const jobs=db.jobs||JOBS_DEFAULT;
  const job=jobs.find(j=>j.id===Number(targetJobId))||jobs[0];
  const base=(cvText||'').trim();
  const injected=[...job.skills,...job.keywords,...job.certs].map(w=>`• ${w}`).join('\n');
  const aligned=`# PROFESSIONAL SUMMARY\nResults-driven ${job.title} with hands-on experience in ${job.skills.slice(0,3).join(', ')}.\n\n# KEYWORDS TO SURFACE (ATS)\n${injected}\n\n${base || '# EXPERIENCE\n- Describe your most relevant accomplishments with metrics.'}`;
  res.json({aligned});
});

app.post('/api/cover-letter', authMiddleware, (req,res)=>{
  const {name='[Your Name]',targetJobId}=req.body||{};
  const db=readDB();
  const jobs=db.jobs||JOBS_DEFAULT;
  const job=jobs.find(j=>j.id===Number(targetJobId))||jobs[0];
  const letter=`${name}
[Address]
[City, State, ZIP]
[Email] · [Phone]
[Date]

Hiring Manager
${job.company}
[Company Address]

Dear Hiring Manager,

I am excited to apply for the ${job.title} role at ${job.company}. My background spans ${job.skills.slice(0,3).join(', ')} and building scalable, cloud-native systems.

Highlights:
${job.skills.slice(0,5).map(s=>`- ${s}`).join('\n')}

Thank you for your time.

Sincerely,
${name}`;
  res.json({letter});
});

app.listen(PORT,()=>{
  if(!fs.existsSync(DATA_FILE)) fs.writeFileSync(DATA_FILE, JSON.stringify({users:[], jobs:JOBS_DEFAULT},null,2));
  console.log('Atlas backend running on :'+PORT);
});
