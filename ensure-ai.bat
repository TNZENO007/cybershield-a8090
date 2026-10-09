@echo off
rem Local AI helper. Skipped completely when cloud Ollama (OLLAMA_API_KEY in .env) is configured.
findstr /b /c:"OLLAMA_API_KEY=" .env 2>nul | findstr /v /c:"PASTE_" | findstr /r /c:"=.." >nul && (echo Cloud AI configured - no local model needed. & goto :eof)
where ollama >nul 2>nul || goto :eof
curl -s http://127.0.0.1:11434 >nul 2>nul || (
  set OLLAMA_NUM_PARALLEL=1
  set OLLAMA_MAX_LOADED_MODELS=1
  set OLLAMA_FLASH_ATTENTION=1
  set OLLAMA_KV_CACHE_TYPE=q8_0
  start "Ollama" /min ollama serve
  timeout /t 5 >nul
)
rem Download the small model in a separate background window so startup is never blocked
ollama list 2>nul | findstr /i /c:"gemma3:1b" /c:"gemma3:270m" >nul || start "Model download" /min cmd /c "ollama pull gemma3:270m"
