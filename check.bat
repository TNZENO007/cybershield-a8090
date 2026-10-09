@echo off
cd /d "%~dp0"
echo Folder: %cd%
dir /b
node -v
npm -v
echo --- port 3100 ---
netstat -ano | findstr :3100
echo --- server ---
curl -s http://localhost:3100/api/health
echo.
echo --- ollama models ---
curl -s http://127.0.0.1:11434/api/tags
echo.
pause
