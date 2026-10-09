@echo off
cd /d "%~dp0"
title CyberShield Server - DO NOT CLOSE
where node >nul 2>nul || (echo Node.js is not installed. Get it from https://nodejs.org & pause & exit /b)
for /f "tokens=5" %%P in ('netstat -ano ^| findstr ":3100 " ^| findstr LISTENING') do taskkill /F /PID %%P >nul 2>nul
if not exist node_modules call npm install --omit=dev
call ensure-ai.bat
start "" cmd /c "timeout /t 3 >nul & start http://localhost:3100"
node server.js
echo.
echo Server stopped. Read the error above.
pause
