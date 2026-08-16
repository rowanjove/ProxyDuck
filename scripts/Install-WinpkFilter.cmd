@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Install-WinpkFilter.ps1"
if errorlevel 1 (
  echo.
  echo WinpkFilter installation failed. Review the message above.
  pause
)
endlocal
