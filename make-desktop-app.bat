@echo off
cd /d "%~dp0"
powershell -NoProfile -Command "$w=New-Object -ComObject WScript.Shell;$d=@([Environment]::GetFolderPath('Desktop'),[Environment]::GetFolderPath('Programs'));foreach($p in $d){$s=$w.CreateShortcut($p+'\CyberShield AI.lnk');$s.TargetPath='%~dp0start-app.bat';$s.WorkingDirectory='%~dp0';$s.IconLocation='%~dp0cybershield-v2.ico';$s.WindowStyle=7;$s.Save()}"
ie4uinit.exe -show >nul 2>nul
echo.
echo Done! "CyberShield AI" is now on your Desktop and in the Start menu.
pause
