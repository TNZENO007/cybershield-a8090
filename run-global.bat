@echo off
cd /d "%~dp0"
if not exist node_modules call npm install --omit=dev
where cloudflared >nul 2>nul || (echo Installing cloudflared... & winget install --id Cloudflare.cloudflared -e --accept-source-agreements --accept-package-agreements & echo. & echo Installed. CLOSE this window and run run-global.bat again. & pause & exit /b)
start "CyberShield server" cmd /k node server.js
timeout /t 5 >nul
echo Copy the https://....trycloudflare.com link below and send it to your friend:
cloudflared tunnel --url http://localhost:3100
pause
