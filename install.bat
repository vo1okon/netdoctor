@echo off
setlocal EnableExtensions
cd /d "%~dp0"
chcp 65001 >nul 2>&1

echo ==================================================
echo   netdoctor — автоматическая установка для Windows
echo ==================================================
echo.

set "NO_PAUSE=0"
if /i "%~1"=="--no-pause" set "NO_PAUSE=1"

:: Проверка: распакован ли архив
if not exist "%~dp0src\netdoctor" (
    echo [ОШИБКА] Файлы проекта не найдены рядом с install.bat!
    echo.
    echo Похоже, вы запустили install.bat прямо из ZIP-архива без распаковки.
    echo Сначала распакуйте архив:
    echo   1. Кликните правой кнопкой по скачанному ZIP-файлу.
    echo   2. Нажмите "Извлечь все..." ^(Extract All^).
    echo   3. Перейдите в распакованную папку и запустите install.bat.
    echo.
    pause
    exit /b 1
)

call :find_python
if not defined PY_EXE (
    echo Python 3.11+ с поддержкой tkinter/venv не найден.
    echo [0/4] Скачивание и автоматическая установка Python 3.12.10 x64...
    call :install_python
    call :find_python
)

if not defined PY_EXE (
    echo.
    echo [ОШИБКА] Не удалось автоматически установить Python 3.11+.
    echo Установите Python 3.12 вручную с https://www.python.org/downloads/
    echo ^(отметьте "Add python.exe to PATH" и компонент "tcl/tk and IDLE"^)
    echo или выполните в PowerShell: winget install -e --id Python.Python.3.12
    goto :fail
)

echo Найден Python: %PY_EXE%
echo.

set "VENV_OK=0"
if exist ".venv\Scripts\python.exe" (
    ".venv\Scripts\python.exe" -c "import sys, tkinter; sys.exit(0 if sys.version_info >= (3, 11) else 1)" >nul 2>&1
    if not errorlevel 1 set "VENV_OK=1"
)

if "%VENV_OK%"=="0" (
    if exist ".venv" (
        echo [1/4] Обнаружено повреждённое окружение .venv — пересоздание...
        rmdir /s /q ".venv"
    ) else (
        echo [1/4] Создание виртуального окружения ^(.venv^)...
    )
    "%PY_EXE%" -m venv .venv
    if errorlevel 1 goto :fail
) else (
    echo [1/4] Виртуальное окружение .venv уже готово — пропуск.
)

echo [2/4] Установка Python-зависимостей...
".venv\Scripts\python.exe" -m pip install --upgrade pip
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
if "%NO_PAUSE%"=="0" pause
exit /b 0

:find_python
set "PY_EXE="

:: 1. Проверяем python из PATH
python -c "import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)" >nul 2>&1
if not errorlevel 1 (
    python -c "import tkinter, venv, ensurepip" >nul 2>&1
    if not errorlevel 1 (
        for /f "usebackq delims=" %%I in (`python -c "import sys; print(sys.executable)"`) do set "PY_EXE=%%I"
        if defined PY_EXE goto :eof
    ) else (
        echo [ПРЕДУПРЕЖДЕНИЕ] В системном python.exe отсутствует модуль tkinter/venv ^(версия из Microsoft Store^).
    )
)

:: 2. Проверяем лаунчер py -3
py -3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)" >nul 2>&1
if not errorlevel 1 (
    py -3 -c "import tkinter, venv, ensurepip" >nul 2>&1
    if not errorlevel 1 (
        for /f "usebackq delims=" %%I in (`py -3 -c "import sys; print(sys.executable)"`) do set "PY_EXE=%%I"
        if defined PY_EXE goto :eof
    )
)

:: 3. Проверяем стандартные каталоги установки Python
for %%P in (
    "%LocalAppData%\Programs\Python\Python312\python.exe"
    "%LocalAppData%\Programs\Python\Python313\python.exe"
    "%LocalAppData%\Programs\Python\Python311\python.exe"
    "%ProgramFiles%\Python312\python.exe"
    "%ProgramFiles%\Python313\python.exe"
    "%ProgramFiles%\Python311\python.exe"
    "C:\Python312\python.exe"
    "C:\Python313\python.exe"
    "C:\Python311\python.exe"
) do (
    if exist "%%~P" (
        "%%~P" -c "import sys, tkinter, venv, ensurepip; sys.exit(0 if sys.version_info >= (3, 11) else 1)" >nul 2>&1
        if not errorlevel 1 (
            set "PY_EXE=%%~P"
            goto :eof
        )
    )
)

:: 4. Проверяем реестр Windows
for /f "tokens=2*" %%A in ('reg query "HKCU\Software\Python\PythonCore\3.12\InstallPath" /ve 2^>nul') do (
    if exist "%%~B\python.exe" (
        "%%~B\python.exe" -c "import sys, tkinter, venv, ensurepip" >nul 2>&1
        if not errorlevel 1 (
            set "PY_EXE=%%~B\python.exe"
            goto :eof
        )
    )
)
for /f "tokens=2*" %%A in ('reg query "HKLM\Software\Python\PythonCore\3.12\InstallPath" /ve 2^>nul') do (
    if exist "%%~B\python.exe" (
        "%%~B\python.exe" -c "import sys, tkinter, venv, ensurepip" >nul 2>&1
        if not errorlevel 1 (
            set "PY_EXE=%%~B\python.exe"
            goto :eof
        )
    )
)
goto :eof

:install_python
set "PY_URL=https://www.python.org/ftp/python/3.12.10/python-3.12.10-amd64.exe"
set "PY_INST=%TEMP%\netdoctor-python-3.12.10-amd64.exe"
if exist "%PY_INST%" del /f /q "%PY_INST%" >nul 2>&1

where curl.exe >nul 2>&1
if not errorlevel 1 (
    curl.exe -4 -fL --retry 3 --connect-timeout 20 --progress-bar "%PY_URL%" -o "%PY_INST%"
)
if not exist "%PY_INST%" (
    echo Пробуем скачать установщик Python через PowerShell...
    powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "$ProgressPreference='SilentlyContinue'; [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; (New-Object Net.WebClient).DownloadFile($env:PY_URL, $env:PY_INST)"
)

if not exist "%PY_INST%" (
    echo Не удалось скачать установщик Python напрямую, пробуем winget...
    goto :try_winget
)
echo Запуск тихой установки Python 3.12.10 ^(без запроса UAC^)...
start /wait "" "%PY_INST%" /quiet InstallAllUsers=0 PrependPath=1 Include_test=0 Include_tcltk=1 Include_pip=1 Include_launcher=1
set "INST_RC=%ERRORLEVEL%"
del /f /q "%PY_INST%" >nul 2>&1
if "%INST_RC%"=="0" goto :eof
echo Прямой установщик завершился с кодом %INST_RC%, пробуем winget...

:try_winget
where winget.exe >nul 2>&1
if not errorlevel 1 (
    winget install -e --id Python.Python.3.12 --scope user --silent --accept-package-agreements --accept-source-agreements
)
goto :eof

:fail
echo.
echo ==================================================
echo   Установка завершилась с ошибкой.
echo ==================================================
pause
exit /b 1
