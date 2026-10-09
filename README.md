# CyberShield AI Pro
Node.js + PostgreSQL (auto JSON fallback) + Ollama + JWT. No OTP.
- Local: run-windows.bat -> http://localhost:3100  (first time: run setup-ai.bat to install the AI model)
- Desktop shortcut with the CyberShield icon: make-desktop-app.bat
- Friend anywhere (your PC stays ON): run-global.bat -> send him the trycloudflare.com link
- Permanent hosting: Render/Railway + Neon Postgres (set DATABASE_URL, JWT_SECRET) + Ollama via tunnel (OLLAMA_URL)

## Cyber AI Pro
- Expert modes: General, Scam help, SOC / Blue team, Pentest (authorized), DFIR / Malware, Cloud / DevSecOps
- Fast / Balanced / Deep answers (Deep = long, structured, with commands + detection + prevention)
- Formatted replies: code blocks with Copy, copy answer, Stop, Regenerate, Export chat
- "Explain with AI" on every scan / link / fraud result, IOC Extractor (+ Analyse with AI)
- Built-in offline guide answers scam questions even if the AI engine is down

## "AI engine offline ... failed to allocate buffer" (low RAM)
Cause: the model (gemma3:4b needs ~3.5 GB free RAM) does not fit in memory.
CyberShield now handles this itself: it picks the biggest installed model that fits your free RAM, and if a model
fails to load it falls back to a smaller one automatically (the badge in AI Chat shows "low-RAM fallback").
Fix once: run setup-ai.bat (installs gemma3:1b, ~800 MB). Also set OLLAMA_MODEL=auto in .env, close heavy apps,
or use cloud Ollama (OLLAMA_URL=https://ollama.com + OLLAMA_API_KEY) so no RAM is needed on your PC.


### v6.4 - self-healing AI
- If the big model cannot load, the app downloads gemma3:1b (then gemma3:270m) by itself and switches to it; the badge shows the download %.
- Small models get a second try with tiny settings (1024 context) before being skipped.
- run-windows.bat / start-app.bat call ensure-ai.bat: starts Ollama with low-memory settings and installs the safety-net model.
- Chat shows a short friendly status instead of the raw llama-server error (details stay in the server console).
