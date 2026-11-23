@echo off
setlocal EnableExtensions
chcp 65001 >nul
cd /d "%~dp0"

echo ==================================================
echo   netdoctor — автоматическая установка для Windows
echo ==================================================
echo.

set "PY_EXE="
python -c "import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)" >nul 2>&1
if not errorlevel 1 (
    for /f "usebackq delims=" %%I in (`python -c "import sys; print(sys.executable)"`) do set "PY_EXE=%%I"
)
if not defined PY_EXE (
    py -3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)" >nul 2>&1
    if not errorlevel 1 (
        for /f "usebackq delims=" %%I in (`py -3 -c "import sys; print(sys.executable)"`) do set "PY_EXE=%%I"
    )
)

if not defined PY_EXE (
    echo [ОШИБКА] Не найден Python 3.11 или новее.
    echo.
    echo Установите Python 3.11+ любым удобным способом:
    echo   1. Скачайте с https://www.python.org/downloads/
    echo      ^(обязательно поставьте галочку "Add python.exe to PATH"^)
    echo   2. Либо выполните в PowerShell:
    echo      winget install -e --id Python.Python.3.12
    echo.
    if /i not "%~1"=="--no-pause" pause
    exit /b 1
)

echo Найден Python: %PY_EXE%
echo.

if not exist ".venv\Scripts\python.exe" (
    echo [1/4] Создание виртуального окружения ^(.venv^)...
    "%PY_EXE%" -m venv .venv
    if errorlevel 1 goto :fail
) else (
    echo [1/4] Виртуальное окружение .venv уже существует — пропуск.
)

echo [2/4] Установка Python-зависимостей...
".venv\Scripts\python.exe" -m pip install --upgrade pip
if errorlevel 1 goto :fail
".venv\Scripts\python.exe" -m pip install -e .
if errorlevel 1 goto :fail

echo.
echo [3/4] Скачивание и проверка внешних компонентов ^(bin/^)...
".venv\Scripts\netdoctor.exe" fetch-bins
if errorlevel 1 (
    echo.
    echo [ОШИБКА] Не удалось скачать или проверить внешние компоненты ^(bin/^).
    echo Проверьте подключение к интернету и повторите запуск install.bat.
    goto :fail
)

echo.
echo [4/4] Создание ярлыков запуска от имени Администратора...
".venv\Scripts\python.exe" -c "import ctypes; from ctypes import wintypes; from pathlib import Path; from netdoctor.tray import create_gui_shortcut; buf = ctypes.create_unicode_buffer(wintypes.MAX_PATH); rc = ctypes.windll.shell32.SHGetFolderPathW(None, 0x0010, None, 0, buf); desktop = Path(buf.value) if rc == 0 and buf.value else (Path.home() / 'Desktop'); root = Path.cwd(); exe = root / '.venv' / 'Scripts' / 'netdoctor-gui.exe'; ico = root / 'src' / 'netdoctor' / 'netdoctor.ico'; res = [create_gui_shortcut(p, exe, working_dir=root, icon_path=ico, run_as_admin=True) for p in (root / 'Netdoctor.lnk', desktop / 'Netdoctor.lnk')]; [print('  OK:', x.get('path')) if x.get('ok') else print('  WARN:', x.get('path'), x.get('error')) for x in res]; raise SystemExit(0 if all(x.get('ok') for x in res) else 1)"
if errorlevel 1 (
    echo [ПРЕДУПРЕЖДЕНИЕ] Не удалось создать один из ярлыков. Вы всегда можете запускать программу через run.bat.
)

echo.
echo ==================================================
echo   Установка завершена успешно!
echo   Запуск: двойной клик по ярлыку Netdoctor на Рабочем столе или по файлу run.bat
echo ==================================================
echo.
if /i not "%~1"=="--no-pause" pause
exit /b 0

:fail
echo.
echo Установка завершилась с ошибкой.
if /i not "%~1"=="--no-pause" pause
exit /b 1
