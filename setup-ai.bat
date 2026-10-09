@echo off
cd /d "%~dp0"
title CyberShield AI - model setup
where ollama >nul 2>nul || (echo Ollama is not installed. Get it from https://ollama.com/download & pause & exit /b)
for /f %%R in ('powershell -NoProfile -Command "[math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory/1GB)"') do set RAM=%%R
echo Your PC has about %RAM% GB RAM.
echo Installing the small safety-net model gemma3:1b - about 800 MB, works on any PC...
ollama pull gemma3:1b
if %RAM% GEQ 12 (echo Enough RAM for the stronger model gemma3:4b too... & ollama pull gemma3:4b)
setx OLLAMA_NUM_PARALLEL 1 >nul
setx OLLAMA_MAX_LOADED_MODELS 1 >nul
setx OLLAMA_FLASH_ATTENTION 1 >nul
setx OLLAMA_KV_CACHE_TYPE q8_0 >nul
echo Low-memory Ollama settings saved. Quit Ollama from the system tray and start it again once.
echo.
echo Done. CyberShield now picks the best model that fits your free RAM automatically.
pause
