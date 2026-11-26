# netdoctor

Адаптивный оркестратор обхода блокировок для **Windows 10 / 11 (x64)**: диагностирует тип блокировки для каждого домена и протокола и подбирает минимально достаточный способ обхода — от простого DNS/DoH и DPI desync до мульти-серверного VPN.

> **Важно:** в репозитории хранится только исходный код, тесты и базовые списки/пресеты. **Ставить Python и библиотеки вручную не нужно** — при первом запуске [`install.bat`](install.bat) или [`run.bat`](run.bat) программа сама скачает и установит Python 3.12 (если его нет в системе), поставит зависимости и загрузит все внешние бинарники (`sing-box`, `winws2`, `tg-ws-proxy`, `byedpi`). Кроме того, GUI и CLI (`netdoctor apply`) умеют автоматически докачивать недостающие или повреждённые компоненты при запуске защиты.

---

## Возможности

- **Ступенчатый подбор обхода (`diag`)**:
  `Прямое соединение` → `DNS / DoH` → `DPI desync (winws2 / Zapret2, резервный ciadpi / ByeDPI)` → `Локальный Telegram WS-прокси` → `VPN (sing-box с urltest)`.
- **Мульти-серверный VPN**: поддержка подписок **Happ**, **Amnezia (`vpn://`)**, **V2Ray / Xray (base64)** и **Sing-box JSON** с автоматическим выбором самого быстрого сервера (`urltest`).
- **Графическая панель (GUI) + системный трей**:
  - **Главная** — запуск защиты в один клик (*Автопилот*), локальный MTProto WebSocket-прокси для Telegram (`tg-ws-proxy`), защита игр и анлокеров (*Unlocker Guard*).
  - **Домены и трафик** — диагностика и привязка правил к конкретным доменам.
  - **Пресеты Zapret** — переключение и импорт готовых пресетов (`presets/zapret2`, `presets/zapret-discord-youtube`).
  - **DNS и нейросети** — маршрутизация DNS-запросов (DoH / UDP) для AI-сервисов и общих доменов.
  - **VPN и журналы** — управление подписками и просмотр логов (`winws2.log`, `sing-box.log`, `tg-ws-proxy.log`).
  - **Сервис и конфиги** — проверка и автодокачка недостающих компонентов, настройка автозапуска Windows (*Планировщик заданий*), предпросмотр сгенерированных конфигов.
- **Автовосстановление и целостность**: все скачиваемые компоненты фиксируются с размерами и SHA-256 хешами в `bin/manifest.json` и автоматически докачиваются при отсутствии или повреждении.

---

## Требования

- **ОС:** Windows 10 или Windows 11 (x64).
- **Python:** версия **3.11+** (ставить заранее **не обязательно** — если подходящего Python с `tkinter` и `venv` нет, `install.bat` сам скачает и тихо установит официальный Python 3.12.10 x64 с `python.org` или через `winget`).
- **Права Администратора (UAC):** требуются при запуске защиты для работы драйвера `WinDivert` (`winws2.exe`) и `TUN`-интерфейса (`sing-box.exe`).
- **Интернет при первой установке:** для скачивания Python, пакетов и релизов с GitHub.

---

## Быстрая установка (в 1 клик)

Сборка `.exe` не требуется — программа сама подготавливает Python, окружение `.venv` и бинарники за один запуск:

1. **Скачайте проект:**
   - Либо через Git:
     ```powershell
     git clone https://github.com/vo1okon/netdoctor.git
     cd netdoctor
     ```
   - Либо нажмите на GitHub кнопку **Code → Download ZIP** и распакуйте архив в удобную папку (например, `C:\Tools\netdoctor`).

2. **Запустите [`install.bat`](install.bat) или сразу [`run.bat`](run.bat) двойным кликом.**
   Скрипт автоматически выполнит всё сам:
   1. Найдёт установленный Python 3.11+ (с поддержкой `tkinter`/`venv`/`ensurepip`), а если его нет — **автоматически скачает и установит Python 3.12.10 x64** без запроса UAC (`InstallAllUsers=0`, с резервным фолбэком на `winget`).
   2. Создаст (или восстановит при поломке) виртуальное окружение `.venv` и установит пакет `netdoctor` с зависимостями из [`pyproject.toml`](pyproject.toml).
   3. Запустит `netdoctor fetch-bins` — скачает в `bin/` и проверит по SHA-256 и PE-заголовкам:
      - `sing-box.exe` (`SagerNet/sing-box`)
      - `winws2.exe`, `WinDivert`, `cygwin`, `blockcheck2` (`bol-van/zapret-win-bundle`)
      - `tg-ws-proxy` (`Flowseal/tg-ws-proxy`)
      - `ciadpi.exe` (`hufrea/byedpi`)
      - базовые списки и пресеты (`Flowseal/zapret-discord-youtube`)
   4. Создаст ярлык **Netdoctor** (с иконкой и запуском от имени Администратора) в папке проекта и на **Рабочем столе**.

3. **Готово!** Запускайте программу ярлыком **Netdoctor** на Рабочем столе или двойным кликом по [`run.bat`](run.bat).

> **Автодокачка внутри самой программы:**
> - [`run.bat`](run.bat) при каждом старте проверяет `.venv`, импорт всех библиотек и ключевые бинарники — если чего-то не хватает, автоматически запускает восстановление.
> - GUI при запуске, нажатии **«Проверить и докачать компоненты»** или старте защиты, а также команда `netdoctor apply` сами докачивают отсутствующие или повреждённые бинарники через `fetch_all_bins`.

---

## Первый старт в программе (GUI)

1. Откройте **Netdoctor** (при запросе UAC подтвердите запуск от имени Администратора).
2. *(Опционально, для маршрутизации заблокированных сайтов через VPN)* перейдите во вкладку **«VPN и журналы»** и вставьте ссылку на подписку (Happ / V2Ray / Sing-box) или `vpn://` ссылку Amnezia.
3. На вкладке **«Главная»** нажмите кнопку запуска / **Автопилот**: программа проверит целевые домены, подберёт оптимальную стратегию `winws2`, сгенерирует конфиги и запустит защитный стек.
4. При закрытии окна программа может сворачиваться в системный трей; во вкладке **«Сервис и конфиги»** можно включить автозапуск при входе в Windows.

---

## Использование через консоль (CLI)

Все CLI-команды доступны внутри виртуального окружения (`.venv\Scripts\netdoctor.exe` или после активации `.venv\Scripts\activate`):

```powershell
# Запустить графическую панель управления
netdoctor gui

# Скачать или обновить внешние бинарники в bin/
netdoctor fetch-bins

# Только проверить целостность уже скачанных бинарников и списков
netdoctor fetch-bins --verify-only

# Продиагностировать конкретный домен или все домены из configs/targets.yaml
netdoctor diag discord.com
netdoctor diag --all

# Добавить или обновить VPN-подписку
netdoctor sub-add "https://example.com/sub" --id main
netdoctor sub-update

# Сгенерировать конфиги и запустить стек защиты (нужны права Администратора)
netdoctor apply
netdoctor apply --no-start   # только сгенерировать конфиги без запуска

# Проверить статус или остановить стек
netdoctor status
netdoctor stop

# Периодический мониторинг (canary-проверки и переключение при деградации)
netdoctor daemon --interval 60 --iterations 0
```

---

## Обновление до новой версии

Если вы ставили проект через `git clone`, для обновления достаточно выполнить в папке проекта:

```powershell
git pull
install.bat
```

Так как пакет ставится в editable-режиме (`pip install -e .`), изменения исходного кода в `src/` применяются сразу, а `install.bat` при необходимости доустановит новые Python-зависимости или недостающие бинарники.

---

## Структура проекта и приватность

```text
netdoctor/
├── install.bat          # Установка в 1 клик (.venv + pip + fetch-bins + ярлыки)
├── run.bat              # Быстрый запуск GUI (при необходимости сам запустит install.bat)
├── pyproject.toml       # Зависимости и точки входа (netdoctor, netdoctor-gui)
├── LICENSES.md          # Лицензии используемых внешних компонентов
├── configs/
│   ├── strategies.yaml  # Каталог DPI-стратегий
│   └── targets.yaml     # Базовые целевые домены для диагностики
├── lists/               # Базовые списки доменов и IP-подсетей
├── presets/             # Готовые пресеты Zapret / Zapret2
├── src/netdoctor/       # Исходный код оркестратора, GUI, трея и CLI
└── tests/               # Модульные и E2E-тесты (pytest)
```

Файлы с вашими личными ключами, подписками и локальным состоянием исключены в [`.gitignore`](.gitignore) и никогда не попадают в Git:
- `configs/sing-box.json`, `configs/winws2_preset.txt`, `configs/winws2_live_at.txt`
- `netdoctor.db`, `logs/`, `bin/`, `.venv/`, `*.lnk`

Подробнее о лицензиях внешних компонентов — в [`LICENSES.md`](LICENSES.md).

---

# netdoctor Blueprint

## System Overview
`netdoctor` is an adaptive censorship-circumvention orchestrator for Windows 10/11 (x64) structured around layered diagnostics and automated fallback routing (`Direct` → `DNS/DoH` → `DPI desync via winws2/ByeDPI` → `tg-ws-proxy` → `sing-box TUN/Xray bridge VPN`). All runtime orchestration, state persistence, binary management, CLI (`netdoctor`), and desktop/tray UI (`netdoctor-gui`) live inside the [`src`](./src/README.md) package tree, paired with static YAML catalogs (`configs/strategies.yaml`, `configs/targets.yaml`), domain/IP hostlists (`lists/`), Zapret/Zapret2 presets (`presets/`), and `pytest` unit/E2E suites (`tests/`).

## Subdirectories & System Boundaries
- [src](./src/README.md) - Source root containing the [`netdoctor`](./src/netdoctor/README.md) Python package implementing probing, verdict classification, strategy/preset compilation, multi-protocol VPN parsing, SQLite storage, process supervision, CLI, and Tkinter/Win32 tray UI.

## Global Invariants
- **Persistence & Schema Integrity**: SQLite state (`netdoctor.db`) enforces `PRAGMA user_version == 2` (`[storage.py:Storage._init_schema]`) with `WAL` mode, caps `domain_tests` at 30 rows per `(network_key, domain)` (`[storage.py:Storage.record_domain_test]`), and never auto-deletes pinned decisions (`[storage.py:Storage.cleanup_stale_decisions]`, `[storage.py:Storage.reset_unhealthy_state]`).
- **Privilege, Conflict & Integrity Gates**: Launching or reloading `winws2.exe` or `sing-box.exe` TUN requires Windows Administrator privileges (`_is_admin()`) and aborts on external bypass conflicts (`[probes.py:detect_bypass_active]`) unless forced (`[cli.py:cmd_apply]`, `[gui_backend.py:GuiBackend.start_services]`). Downloaded artifacts must pass ZipSlip path checks, `b'MZ'` PE validation, byte-size and SHA-256 verification against `bin/manifest.json`, and pinned `UPSTREAM_RELEASES` tag checks (`[supervisor.py:verify_binaries]`).
- **Routing & Unlocker Guard Isolation**: `stack_mode` is constrained to `('hybrid', 'dpi_only')` and `tun_stack` to `('gvisor', 'mixed', 'system')` (`[gui_backend.py:GuiBackend.trigger_apply_configs]`, `[config_gen.py:generate_singbox_config]`). Protected Antigravity/local/hosts domains and proxy IPs (`[orchestrators.py:build_unlocker_protection_context]`) are forced to `dns-local`/`direct` and excluded from DPI/VPN routing; when `enable_tun=True`, process and game bypass rules apply strictly to `inbound=['tun-in']`.
- **Failover & Preset Guardrails**: Zapret2 presets must compile with valid `--lua-init=` scripts, resolved positive `--hostlist=`/`--ipset=` files, and at least one `--lua-desync=` profile (`[presets.py:compile_zapret_preset]`). VPN node selection uses a circuit breaker with backoff `(60, 180, 600, 1800)` seconds (`[orchestrators.py:VpnLayerOrchestrator.record_node_result]`), and `[supervisor.py:ProcessSupervisor.start_stack]` atomically rolls back the stack if any process exits prematurely during startup.

## Global Side Effects
- **Local State & Generated Configs**: Mutates `netdoctor.db`, `configs/` (`winws2_preset.txt`, `winws2_live_at.txt`, `sing-box.json`, `xray.json`), `lists/` (`exclude_vpn_ips.txt`, `exclude_unlocker_domains.txt`, `ipset-telegram.txt`, strategy hostlists), `bin/` (`manifest.json`, downloaded executables/DLLs/WinDivert driver), and `logs/` (`*.log`, `*.prev.log`, `supervisor_state.json`).
- **OS & Subprocess Control**: Spawns and terminates `winws2.exe` (WinDivert kernel packet driver), `sing-box.exe` (TUN adapter), `xray.exe`, `tg-ws-proxy`, and `ciadpi.exe` (`[supervisor.py:ProcessSupervisor]`); invokes `schtasks`, `ipconfig /flushdns`, `arp -a`, `route print 0.0.0.0`, PowerShell `WScript.Shell` COM shortcuts, and Win32 tray/mutex/UAC APIs (`[tray.py:NetdoctorTrayIcon]`, `[gui_backend.py:elevate_gui]`).
- **External Network Traffic**: Sends DNS/DoH, TCP, TLS, HTTP(S), and QUIC probes (`[probes.py]`), fetches VPN subscriptions (`[vpn.py:fetch_subscription]`), queries GitHub Releases (`[supervisor.py:fetch_all_bins]`, `[updater.py:check_for_updates]`), and communicates with the local Clash controller at `127.0.0.1:19090` (`[clash_api.py:ClashApiClient]`).

## System Verification
- Run: `pytest`
