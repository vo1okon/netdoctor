@echo off
setlocal EnableExtensions
chcp 65001 >nul
cd /d "%~dp0"

set "NEED_INSTALL=0"
if not exist ".venv\Scripts\netdoctor-gui.exe" set "NEED_INSTALL=1"
if "%NEED_INSTALL%"=="0" (
    ".venv\Scripts\python.exe" -c "import netdoctor, httpx, dns, yaml, pydantic, typer, rich, aioquic, psutil, tkinter" >nul 2>&1
    if errorlevel 1 set "NEED_INSTALL=1"
)
if "%NEED_INSTALL%"=="0" (
    if not exist "bin\winws2.exe" set "NEED_INSTALL=1"
    if not exist "bin\sing-box.exe" set "NEED_INSTALL=1"
)

if "%NEED_INSTALL%"=="1" (
    echo Не найдены или повреждены компоненты/зависимости. Запускаю автоматическую установку...
    call "%~dp0install.bat" --no-pause
    if errorlevel 1 (
        echo.
        echo Не удалось завершить подготовку окружения.
        pause
        exit /b 1
    )
)

start "" ".venv\Scripts\netdoctor-gui.exe" %*
exit /b 0
