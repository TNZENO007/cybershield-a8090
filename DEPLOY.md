# 24/7 Global Hosting (PC off-la irundhaalum work aagum) - ellam FREE
Indha link-ah yaar vena, enga irundhu vena open panni phone/PC-la "Install app" pannalaam.

## 1. AI key (Ollama cloud)
ollama.com -> sign up -> Settings -> Keys -> Create API key. Copy pannunga. (PC-la Ollama venaam)

## 2. Database (Neon)
neon.tech -> sign up -> New project -> Connection string copy (postgres://...sslmode=require)

## 3. GitHub
github.com -> New repository (Private) -> indha folder-ah upload (public/ folder-um serthu).
.env upload pannaadheenga (.gitignore already block pannum).

## 4. Render
render.com -> New -> Blueprint -> repo select. 2 values kekkum:
- DATABASE_URL = Neon string
- OLLAMA_API_KEY = step 1 key
Deploy -> https://cybershield-ai.onrender.com maadhiri permanent link kidaikkum.

## 5. Always awake (important)
Render free app 15 min idle-na sleep aagum (first open 30-60s slow).
uptimerobot.com -> Add monitor (HTTP) -> https://<unga-link>/api/ping -> interval 5 min.

## 6. Check
https://<unga-link>/api/health -> "db":"PostgreSQL" and ai.up:true varanum.

## 7. Install as app
- Android Chrome: link open -> menu -> Install app (illana app-kulla "Install app" button)
- iPhone Safari: Share -> Add to Home Screen
- PC Chrome/Edge: address bar-la Install icon
Link-ah WhatsApp-la anuppunga, avanga install pannikkuvanga.

## Speed
render.yaml-la model gpt-oss:20b (120b-ah vida romba fast). Innum fast venumna OLLAMA_MODEL_FAST-um set pannalaam.
