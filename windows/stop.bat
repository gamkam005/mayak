@echo off
chcp 65001 >nul
rem Остановить МАЯК (если окно спрятано или зависло) и выключить системный прокси
taskkill /im mayak.exe /f >nul 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable /t REG_DWORD /d 0 /f >nul
echo МАЯК остановлен, системный прокси выключен.
pause
