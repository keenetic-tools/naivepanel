# NaivePanel

Local web panel to manage a **NaiveProxy client** on a router running
**Entware** (Keenetic and other OpenWrt-like firmware). Flask backend + a single
HTML page — no CDN, no build step. MIT-licensed.

---

Локальная веб-панель управления **клиентом NaiveProxy** на роутере с **Entware**
(Keenetic и другие OpenWrt-подобные прошивки).

## Что это

- **Flask-приложение** (одна HTML-страница, без CDN / без build step).
- Хранит **N пресетов** конфигурации клиента в `/opt/etc/naive/proxy/conf.d/<name>.json`.
- По activate копирует пресет в `/opt/etc/naive/proxy/config.json` (`chmod 0600`)
  и перезапускает `/opt/etc/init.d/S99naiveproxy`.
- Bind по умолчанию `127.0.0.1:8089`. Доступ из LAN — через внешний reverse proxy
  или напрямую (см. «Доступ из LAN без reverse proxy»).

## Возможности UI (v0.5.0–v0.5.1)

- Карточка статуса: состояние, активный пресет, uptime, PID, версия панели.
- Поиск по пресетам (клавиша `/`), дублирование пресета в один клик (⧉ —
  пароль переносится, руками вводить не нужно).
- Экспорт/импорт всех пресетов JSON-файлом (бэкап/миграция между роутерами).
- Кнопка «пинг» в редакторе: TCP-доступность upstream с роутера (3с, без TLS).
- Светлая/тёмная тема: автоматически по системной, клик по ☀/☾ фиксирует выбор.
- Toast-уведомления, подсветка ERROR/WARNING в логе, горячие клавиши
  (Ctrl+S — сохранить, Esc — закрыть редактор).
- Визуальный полиш (v0.5.1): elevation-тени карточек, sticky-шапка
  с `backdrop-filter` (и фолбэком), пульсирующий индикатор «работает»,
  empty-states для пустого списка/поиска, `tabular-nums` для uptime/PID
  (цифры не «прыгают» при автообновлении), тонкий фоновый градиент.
  Всё в рамках прежних ограничений: один HTML-файл, без CDN, анимации
  только на `transform`/`opacity`, вес страницы +1.4 КБ к gzip.

## API

| Метод | Путь | Что делает |
|-------|------|------------|
| `GET` | `/api/status` | `{active, current, init_present, init_script, pid, uptime, version}` |
| `GET` | `/api/configs` | список пресетов `{name, active, listen, proxy, username}` |
| `GET` | `/api/configs/<name>` | полный JSON-конфиг пресета |
| `POST` | `/api/configs` | создать пресет |
| `PUT` | `/api/configs/<name>` | обновить (если активный — propagate в `config.json` **и restart**; ответ содержит `restart:{rc,...}`) |
| `DELETE` | `/api/configs/<name>` | удалить (если не активный) |
| `POST` | `/api/configs/<name>/activate` | сделать активным + restart (конфиг **валидируется** — битый не роняет рабочий прокси) |
| `POST` | `/api/configs/<name>/duplicate` | копия пресета server-side, **включая пароль** |
| `GET` | `/api/configs/export` | все пресеты одним JSON-файлом (attachment; содержит пароли!) |
| `POST` | `/api/configs/import` | импорт из файла export-формата; существующие не перезаписываются, битые отклоняются |
| `POST` | `/api/probe` | TCP-доступность upstream с роутера (`{upstream}` → `{ms}` или `{error}`) |
| `POST` | `/api/service/{start,stop,restart}` | управление через S99naiveproxy |
| `POST` | `/api/panel/restart` | перезапуск самой панели (после обновления файлов) |
| `GET` | `/api/logs?lines=100` | tail лог-файла |

## Локальный запуск (для разработки)

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install flask

# Пути по умолчанию под Entware; для Mac/Linux — подменить.
NAIVEPROXY_DIR=./etc/naiveproxy \
NAIVEPROXY_INIT=./etc/init.d/S99naiveproxy \
NAIVEPROXY_LOG=./var/log/naiveproxy.log \
NAIVEPANEL_BIND=127.0.0.1:8089 \
./.venv/bin/python naivepanel.py
```

Открыть `http://127.0.0.1:8089`.

Переменные окружения позволяют запускать панель где угодно без root —
главное, чтобы каталог пресетов существовал и был writable.

## Установка (install.sh)

Рекомендуемый способ — автоустановщик. Запускается **на роутере** (нужен
Entware с `opkg`). Скачивает файлы, закреплённые за тегом релиза, сверяет
контрольные суммы (`SHA256SUMS`), ставит init-скрипты и запускает панель:

```bash
curl -fsSL https://raw.githubusercontent.com/keenetic-tools/naivepanel/v0.5.1/install.sh | sh -s -- --with-auth
```

Запуск через пайп безопасен: подтверждение установки и ввод пароля читаются
с терминала (`/dev/tty`), а не из stdin скрипта. Для полностью неинтерактивного
режима добавьте `--yes`.

Флаги:

| Флаг | Что делает |
|------|------------|
| `--with-auth` | интерактивно создаёт `/opt/etc/naive/panel/admin.pass` (HTTP Basic) |
| `--bind HOST:PORT` | пишет `NAIVEPANEL_BIND` в `/opt/etc/naive/panel/panel.conf` |
| `--hosts LIST` | пишет `NAIVEPANEL_HOSTS` в `panel.conf` |
| `--ref TAG` | устанавливает конкретный тег (по умолчанию `v0.5.1`) |
| `--no-naive-init` | не ставить `S99naiveproxy` (если свой init-скрипт уже есть) |
| `--yes` | неинтерактивный режим (без подтверждения) |
| `--uninstall` | остановить сервисы и удалить файлы |
| `--purge` | вместе с `--uninstall` — снести и конфиги (`admin.pass`, `conf.d`) |

Установщик идемпотентен: повторный запуск = обновление. Файлы панели
обновляются, а `admin.pass` и пресеты в `conf.d/` остаются нетронутыми.

Каталоги продукта (начиная с v0.2.0): `/opt/etc/naive/panel` — код панели и
`admin.pass`, `/opt/etc/naive/proxy` — пресеты (`conf.d/`), активный
`config.json` и `.active`. Установка поверх схемы < v0.2.0 мигрирует
автоматически: `/opt/naivepanel`, `/opt/etc/naivepanel`,
`/opt/etc/naiveproxy` переносятся в новое дерево, данные сохраняются.

Зависимости ставятся через `opkg`, а не pip: `python3` (если его ещё нет в
`/opt`), `python3-flask`, при `--with-auth` — `python3-bcrypt`. На фидах без
`python3-flask` (например `aarch64-k3.10`) установщик ставит `python3-pip`
и flask через `pip3`. Отсутствие бинарника `naive` не блокирует установку —
только предупреждение.

Пример с LAN-доступом:

```bash
curl -fsSL https://raw.githubusercontent.com/keenetic-tools/naivepanel/v0.5.1/install.sh \
  | sh -s -- --with-auth --bind 192.168.1.1:8089 --hosts '192.168.1.1:8089,router.local:8089'
```

### Настройки панели (panel.conf)

Все настройки панели живут в **`/opt/etc/naive/panel/panel.conf`** — этот файл
читает сам `naivepanel.py`, поэтому настройки переживают любые обновления
(установщик перезаписывает init-скрипт при каждом апгрейде, так что вписывать
настройки туда нельзя). Файл создаётся установщиком один раз как шаблон;
**существующий файл никогда не перезаписывается** — правки руками сохраняются.

```ini
# KEY="VALUE"; комментарии — только с начала строки
NAIVEPANEL_BIND="192.168.1.1:8089"
NAIVEPANEL_HOSTS="192.168.1.1:8089,router.local:8089"
#NAIVEPANEL_PASS="/opt/etc/naive/panel/admin.pass"
#NAIVEPROXY_DIR="/opt/etc/naive/proxy"
#NAIVEPROXY_INIT="/opt/etc/init.d/S99naiveproxy"
#NAIVEPROXY_LOG="/opt/var/log/naiveproxy.log"
#NAIVEPROXY_PID="/opt/var/run/naiveproxy.pid"
```

Приоритет: **env > panel.conf > встроенный дефолт** — переменные окружения
удобны для dev-запуска, файл — для роутера. Ключи вне списка из шаблона
игнорируются (опечатка не применится молча — в лог уйдёт warning). После
правок: `/opt/etc/init.d/S99naivepanel restart`.

Флаги `--bind`/`--hosts` обновляют соответствующие ключи внутри существующего
файла. Историческая схема с `/opt/etc/init.d/rc.conf` не работала (файл никто
не читал) — установщик, начиная с v0.4.1, переносит найденные там
`NAIVEPANEL_BIND/HOSTS` в `panel.conf`.

### Установка бинарника naive

Панель управляет клиентом `naive`, но сам бинарник не ставит. Если его нет,
скачай готовую сборку с [klzgrad/naiveproxy releases](https://github.com/klzgrad/naiveproxy/releases):

1. Определи архитектуру роутера:

   ```bash
   uname -m          # mips / armv7l / aarch64 / x86_64
   cat /proc/cpuinfo # уточни модель ядра (mips 24kc, cortex-a7/a53/a72…)
   ```

2. Выбери `openwrt-*`-asset под свой CPU. Для Entware предпочтительны
   **`-static`** сборки — они musl-static и не зависят от библиотек в `/opt/lib`.

3. Распакуй и положи бинарник как `/opt/bin/naive` (имя, которое ждёт
   `S99naiveproxy`):

   ```bash
   tar -xJf naiveproxy-v*-openwrt-*.tar.xz
   cp naiveproxy-v*/naive /opt/bin/naive && chmod +x /opt/bin/naive
   ```

   Если бинарник уже лежит в другом месте — достаточно symlink:

   ```bash
   ln -sf /opt/naiveproxy/bin/naiveproxy /opt/bin/naive
   ```

## Ручной деплой на Keenetic (Entware)

> Требуется установленный пакет `naive-proxy` в Entware и, опционально,
> `python3` (если Python < 3.10 — ставим пакет `python3`). На Keenetic
> python3 в Entware уже есть.

```bash
# 1. Копируем файлы (через sshfs, scp или WebUI Keenetic)
ssh root@router
mkdir -p /opt/etc/naive/panel/templates
mkdir -p /opt/etc/naive/proxy/conf.d

# Положить naivepanel.py + templates/index.html (нужен для render_template)
scp naivepanel.py root@router:/opt/etc/naive/panel/
scp -r templates  root@router:/opt/etc/naive/panel/
scp S99naivepanel   root@router:/opt/etc/init.d/
scp S99naiveproxy   root@router:/opt/etc/init.d/    # если у тебя ещё нет
ssh root@router "chmod +x /opt/etc/init.d/S99naiveproxy /opt/etc/init.d/S99naivepanel"

# 2. (опционально) HTTP Basic auth
#    Панель слушает 127.0.0.1 — опасно без auth, если кто-то может
#    подключиться по SSH на роутер. Требуется пакет python3-bcrypt в Entware.
opkg update && opkg install python3-bcrypt
#    htpasswd в Entware отсутствует — генерируем bcrypt-хэш через python3
#    (пароль вводится скрыто). Формат строки: admin:$2b$…
python3 -c 'import bcrypt,getpass; print("admin:"+bcrypt.hashpw(getpass.getpass().encode(),bcrypt.gensalt()).decode())' \
  > /opt/etc/naive/panel/admin.pass
chmod 0600 /opt/etc/naive/panel/admin.pass

# 3. Запуск
/opt/etc/init.d/S99naivepanel start
/opt/etc/init.d/S99naivepanel status

# 4. (опционально) Автозапуск после перезагрузки
#    В WebUI Keenetic → Управление → Автозапуск → /opt/etc/init.d/S99naivepanel
#    или вручную:
ln -sf /opt/etc/init.d/S99naivepanel /opt/etc/rc.d/S99naivepanel
```

Панель будет доступна на `http://127.0.0.1:8089` (только с роутера).

### Доступ из LAN

Через существующий **Caddy** на роутере или **Xkeen-UI reverse proxy**:

```caddyfile
naivepanel.local.lan {
    basicauth {
        admin $2a$14$...
    }
    reverse_proxy 127.0.0.1:8089
}
```

Панель за reverse proxy видит чужой `Host` (`naivepanel.local.lan`) — добавь
его в allowlist, иначе 403 (см. «Безопасность»):

```ini
# в /opt/etc/naive/panel/panel.conf
NAIVEPANEL_HOSTS="naivepanel.local.lan"
```

Или просто SSH-туннель: `ssh -L 8089:127.0.0.1:8089 root@router`.

### Доступ из LAN без reverse proxy

Прокси не обязателен, если закрыты три вещи: auth, Host-allowlist и
доступность порта. Минимальный безопасный вариант:

```bash
# 1. Basic auth обязателен — без него LAN-bind = открытые пароли upstream-прокси
opkg update && opkg install python3-bcrypt
#    htpasswd в Entware отсутствует — генерируем bcrypt-хэш через python3
python3 -c 'import bcrypt,getpass; print("admin:"+bcrypt.hashpw(getpass.getpass().encode(),bcrypt.gensalt()).decode())' \
  > /opt/etc/naive/panel/admin.pass
chmod 0600 /opt/etc/naive/panel/admin.pass

# 2. Bind на LAN-адрес (НЕ 0.0.0.0 — иначе торчим и в WAN/VPN/guest-сегменты)
#    и allowlist Host-заголовков (анти-DNS-rebinding) — в /opt/etc/naive/panel/panel.conf.
#    Без NAIVEPANEL_HOSTS разрешены только адрес bind и loopback-алиасы —
#    доступ по имени роутера (router.lan и т.п.) потребует явного allowlist.
NAIVEPANEL_BIND="192.168.1.1:8089"
NAIVEPANEL_HOSTS="192.168.1.1:8089,router.local:8089"

# 3. Файрвол Keenetic: порт 8089 только с твоих устройств; guest-сегмент — закрыт.
```

Остаточный риск — открытый HTTP: пароль Basic auth можно перехватить активным
MITM в LAN (ARP-spoofing, скомпрометированное устройство). Для доверенной
домашней сети это обычно приемлемо; если в сегменте есть недоверенные
устройства — поднимай TLS через Caddy или ходи по SSH-туннелю.

Неудачные попытки auth (401) и отклонённые Host (403) пишутся в
`/opt/var/log/naivepanel.log`.

## Поля конфига

NaivePanel собирает минимальный JSON, совместимый с бинарником `naive` из
[klzgrad/naiveproxy](https://github.com/klzgrad/naiveproxy):

```json
{
  "listen": "socks://127.0.0.1:1080",
  "proxy": "https://user:pass@host"
}
```

Поле `listen` поддерживает несколько адресов — тогда это массив. В UI их вводят
по одному на строку (или через запятую); один адрес сохраняется как строка
(компактнее), несколько — как массив:

```json
{
  "listen": ["socks://127.0.0.1:1080", "http://127.0.0.1:8080"],
  "proxy": "https://user:pass@host"
}
```

Дополнительные поля (опционально, через раздел «Дополнительно» в UI):

| Поле в UI | Ключ в JSON | Назначение |
|-----------|-------------|------------|
| log | `log` | путь к лог-файлу |
| host-resolver-rules | `host-resolver-rules` | `MAP proxy.example.com 1.2.3.4` |
| extra-headers | `extra-headers` | дополнительные HTTP-заголовки (через `\r\n`) |
| insecure-concurrency | `insecure-concurrency` | 1..4 (см. USAGE.txt — снижает детектируемость) |

## Безопасность

- Bind по умолчанию только `127.0.0.1`; LAN-bind — по чеклисту
  «Доступ из LAN без reverse proxy».
- `config.json`, `.active`, `*.json` в `conf.d/` — `chmod 0600`.
- Если есть `/opt/etc/naive/panel/admin.pass` — **каждый** запрос требует HTTP Basic
  auth (bcrypt, формат htpasswd `user:$2y$…`). Без пакета `python3-bcrypt` в
  Entware auth fail-closed (401 на любой запрос + ошибка в лог).
- Успешная Basic-проверка кэшируется на 5 минут (сбрасывается сразу при
  изменении `admin.pass`) — поллинг UI каждые 3с не гоняет bcrypt постоянно.
- **Host-allowlist включён всегда** (с v0.4.0). Если задан `NAIVEPANEL_HOSTS`
  (список через запятую, точные строки Host с портом) — пропускаются только
  они. Если не задан — адрес bind + loopback-алиасы (`127.0.0.1[:8089]`,
  `localhost[:8089]`, IPv6-формы). Прочие Host — 403: чужое имя хоста —
  маркер DNS-rebinding. Поэтому reverse proxy со своим именем требует явного
  `NAIVEPANEL_HOSTS`.
- Активация пресета валидирует имя: `^[a-zA-Z0-9_\-.]{1,64}$` (нет path-traversal).
- **Схема конфига валидируется** перед activate/PUT/импортом: непустые
  `listen`/`proxy`, URI со схемой, диапазон `insecure-concurrency` 1..4 — битый
  (например, руками отредактированный) пресет не перезапишет рабочий `config.json`.
- **Security-заголовки** на каждом ответе: `Content-Security-Policy`
  (`default-src 'none'`, внешние скрипты/стили запрещены, `connect-src 'self'`
  против эксфильтрации), `X-Content-Type-Options: nosniff`,
  `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`.
- Bind на `0.0.0.0` — warning в лог: на роутере это ещё и WAN/VPN/guest-сегменты.
- 401 (auth failed) и 403 (host rejected) пишутся в лог панели.
- Мутирующие запросы (POST/PUT/DELETE) требуют заголовок `X-Requested-With`
  (ставит UI) — защита от CSRF: Basic-креды браузер прикладывает к кросс-сайтовым
  запросам автоматически, поэтому одной auth тут недостаточно. Неудачная auth
  замедляется на 0.5с (анти-перебор).
- Пароли upstream через API не возвращаются: `GET /api/configs/<name>` отдаёт
  upstream/username разобранными, но без пароля; пустое поле пароля в форме
  при сохранении означает «оставить прежний». Креденшалы в proxy-URI
  percent-encode'ятся (`@ : /` и т.п. в пароле не ломают URI).
- **Исключение — export**: `GET /api/configs/export` сознательно содержит
  proxy-URI с паролями — бэкап без кредов не был бы бэкапом. Файл уходит как
  `Content-Disposition: attachment` по явному клику «Экспорт»; импорт
  (`/api/configs/import`) существующие пресеты не перезаписывает и валидирует
  каждый. Не хранить экспорт-файл в общедоступных местах.
- `/api/logs` маскирует креды в URI (`scheme://user:pass@host` →
  `scheme://user:***@host`) и читает лог с конца файла, а не целиком.
- PUT активного пресета применяет изменения сразу (перезаписывает
  `config.json` и рестартует сервис, как activate); ответ содержит результат
  рестарта, UI показывает сбой, если он случился.
- Размер тела запроса ограничен 256 КБ (`MAX_CONTENT_LENGTH`).
- Пароль панели и `admin.pass` НЕ коммитить в git.

## Что НЕ реализовано (по спеке wiki)

- ❌ multi-user
- ❌ HTTPS termination (только через внешний reverse proxy)
- ❌ auto-update панели
- ❌ графики мониторинга (uptime-строка и проверка доступности upstream — есть)
- ❌ управление upstream-серверами

## Структура

```
naiveproxy-panel/
├── naivepanel.py            # Flask backend
├── templates/
│   └── index.html           # UI (vanilla HTML + JS, без CDN)
├── install.sh               # установщик для Entware (curl | sh, checksums)
├── S99naiveproxy            # init: бинарник naive
├── S99naivepanel            # init: Flask-приложение
├── tests/test_naivepanel.py # pytest: API-семантика без сети
├── docker-e2e.sh            # E2E: install.sh в Docker с настоящим Entware
├── SHA256SUMS               # контрольные суммы файлов релиза
└── README.md                # этот файл
```

## Разработка

Перед PR-ом:

```bash
./.venv/bin/python -c "import ast; ast.parse(open('naivepanel.py').read())"  # syntax
sh -n S99naiveproxy && sh -n S99naivepanel                                    # shell syntax
```

Smoke-тест после каждого изменения в `naivepanel.py`:

```bash
NAIVEPROXY_DIR=./etc/naiveproxy NAIVEPROXY_INIT=./etc/init.d/S99naiveproxy \
NAIVEPROXY_LOG=./var/log/naiveproxy.log NAIVEPANEL_BIND=127.0.0.1:8089 \
./.venv/bin/python naivepanel.py &
curl -s http://127.0.0.1:8089/api/status
```

Тестовая последовательность в UI:

1. Создать пресет `home` через "+ Новый" → форма → Сохранить.
2. Нажать "→" рядом с пресетом → проверить, что в `etc/naiveproxy/config.json`
   появился тот же JSON с `chmod 0600`.
3. PUT (изменить listen port) → проверить, что `config.json` обновился.
4. Создать второй пресет `work`, активировать его, удалить `home`.
5. ⧉ на пресете → появилась копия `work-copy` с тем же паролем (проверить
   `conf.d/work-copy.json`); «пинг» в редакторе → toast с мс или ошибкой.
6. «Экспорт» → скачался JSON со всеми пресетами; удалить один пресет,
   «Импорт» → пресет вернулся, существующие не перезаписаны.
7. `/` → фокус в поиске, фильтрация списка; Ctrl+S — сохранить; Esc — закрыть
   редактор; ☀/☾ — тема переключается и переживает перезагрузку.

## Лицензия

[MIT](LICENSE). Бинарник `naive` из [klzgrad/naiveproxy](https://github.com/klzgrad/naiveproxy)
распространяется под своей лицензией (BSD-3-Clause).
