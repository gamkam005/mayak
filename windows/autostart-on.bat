@echo off
chcp 65001 >nul
rem Автозапуск МАЯК при входе в Windows: ярлык в папке «Автозагрузка», окно свёрнуто, браузер не открывается
set "DIR=%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -Command "$s=(New-Object -ComObject WScript.Shell).CreateShortcut([Environment]::GetFolderPath('Startup')+'\MAYAK.lnk'); $s.TargetPath='%DIR%mayak.exe'; $s.Arguments='client -easy -open=false'; $s.WorkingDirectory='%DIR%'; $s.WindowStyle=7; $s.Description='MAYAK'; $s.Save()"
if errorlevel 1 (echo Не получилось создать ярлык автозапуска.) else (echo Готово: МАЯК будет запускаться сам при входе в Windows ^(свёрнутым окном^). Отменить: autostart-off.bat)
pause
