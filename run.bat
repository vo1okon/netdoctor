@echo off
setlocal EnableExtensions
cd /d "%~dp0"
chcp 65001 >nul 2>&1

if not exist "%~dp0src\netdoctor" (
    echo ==================================================
    echo [ОШИБКА] Файлы проекта не найдены!
    echo Похоже, вы запустили run.bat прямо из ZIP-архива без распаковки.
    echo Сначала распакуйте архив: клик правой кнопкой -^> "Извлечь все...".
    echo ==================================================
    pause
    exit /b 1
)

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
