@echo off
cd /d "%~dp0"
title CyberShield Server
for /f "tokens=5" %%P in ('netstat -ano ^| findstr ":3100 " ^| findstr LISTENING') do taskkill /F /PID %%P >nul 2>nul
call ensure-ai.bat
if not exist node_modules call npm install --omit=dev
start "CyberShield Server" /min cmd /c node server.js
timeout /t 3 >nul
start "" msedge --app=http://localhost:3100
