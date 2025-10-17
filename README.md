# Atlas Backend (Fixed Registration + AI Tools)
Node/Express backend with JWT auth and AI endpoints. HTTPS/CORS friendly for GitHub Pages.

## Endpoints
Auth:
- POST /api/auth/signup { name, email, password } -> { token, user }
- POST /api/auth/login { email, password } -> { token, user }
- GET  /api/auth/me (Bearer) -> { user }

Public:
- GET  /api/jobs

Protected (Bearer):
- POST /api/match { cvText } -> { results: [...] }
- POST /api/align-cv { cvText, targetJobId } -> { aligned }
- POST /api/cover-letter { name, targetJobId } -> { letter }

## Run
npm install
npm start  # http://localhost:8787
(Optionally set PORT, JWT_SECRET, DATA_FILE)
