@echo off
chcp 65001 >nul
rem Включить системный прокси Windows на МАЯК (браузеры Chrome/Edge начнут ходить через него)
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable /t REG_DWORD /d 1 /f >nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyServer /t REG_SZ /d "127.0.0.1:1080" /f >nul
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyOverride /t REG_SZ /d "localhost;127.*;10.*;192.168.*;<local>" /f >nul
echo Системный прокси включён: 127.0.0.1:1080. Выключить: proxy-off.bat
pause
