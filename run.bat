@echo off
setlocal EnableExtensions
chcp 65001 >nul
cd /d "%~dp0"

if not exist ".venv\Scripts\netdoctor-gui.exe" (
    echo Виртуальное окружение не найдено. Запускаю первичную установку...
    call "%~dp0install.bat" --no-pause
    if errorlevel 1 exit /b 1
)

start "" ".venv\Scripts\netdoctor-gui.exe" %*
exit /b 0
