@echo off
chcp 65001 >nul
echo Disk analizi baslatiliyor (salt okunur, hicbir dosya silinmez)...
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Disk-Analiz.ps1" %*
echo.
pause
