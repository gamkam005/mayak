@echo off
chcp 65001 >nul
rem Убрать МАЯК из автозапуска
powershell -NoProfile -Command "Remove-Item -ErrorAction SilentlyContinue ([Environment]::GetFolderPath('Startup')+'\MAYAK.lnk')"
echo Автозапуск МАЯК выключен.
pause
