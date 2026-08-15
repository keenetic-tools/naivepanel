# NaivePanel

Local web panel to manage a **NaiveProxy client** on a router running
**Entware** (Keenetic and other OpenWrt-like firmware). Flask backend + a single
HTML page — no CDN, no build step. MIT-licensed.

---

Локальная веб-панель управления **клиентом NaiveProxy** на роутере с **Entware**
(Keenetic и другие OpenWrt-подобные прошивки).

## Что это

- **Flask-приложение** (~390 строк, одна HTML-страница, без CDN / без build step).
- Хранит **N пресетов** конфигурации клиента в `/opt/etc/naiveproxy/conf.d/<name>.json`.
- По activate копирует пресет в `/opt/etc/naiveproxy/config.json` (`chmod 0600`)
  и перезапускает `/opt/etc/init.d/S99naiveproxy`.
- Bind по умолчанию `127.0.0.1:8089`. Доступ из LAN — через внешний reverse proxy
  или напрямую (см. «Доступ из LAN без reverse proxy»).

## API

| Метод | Путь | Что делает |
|-------|------|------------|
| `GET` | `/api/status` | `{active, current, init_present, init_script, pid, uptime}` |
| `GET` | `/api/configs` | список пресетов `{name, active, listen, proxy, username}` |
| `GET` | `/api/configs/<name>` | полный JSON-конфиг пресета |
| `POST` | `/api/configs` | создать пресет |
| `PUT` | `/api/configs/<name>` | обновить (если активный — propagate в `config.json`) |
| `DELETE` | `/api/configs/<name>` | удалить (если не активный) |
| `POST` | `/api/configs/<name>/activate` | сделать активным + restart |
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
curl -fsSL https://raw.githubusercontent.com/keenetic-tools/naivepanel/v0.1.0/install.sh | sh -s -- --with-auth
```

Флаги:

| Флаг | Что делает |
|------|------------|
| `--with-auth` | интерактивно создаёт `/opt/etc/naivepanel/admin.pass` (HTTP Basic) |
| `--bind HOST:PORT` | пишет `NAIVEPANEL_BIND` в `/opt/etc/init.d/rc.conf` |
| `--hosts LIST` | пишет `NAIVEPANEL_HOSTS` (allowlist Host-заголовков) |
| `--ref TAG` | устанавливает конкретный тег (по умолчанию `v0.1.0`) |
| `--no-naive-init` | не ставить `S99naiveproxy` (если свой init-скрипт уже есть) |
| `--yes` | неинтерактивный режим (без подтверждения) |
| `--uninstall` | остановить сервисы и удалить файлы |
| `--purge` | вместе с `--uninstall` — снести и конфиги (`admin.pass`, `conf.d`) |

Установщик идемпотентен: повторный запуск = обновление. Файлы панели
обновляются, а `admin.pass` и пресеты в `conf.d/` остаются нетронутыми.

Зависимости ставятся через `opkg`, а не pip: `python3` (если < 3.10),
`python3-flask`, при `--with-auth` — `python3-bcrypt`. Отсутствие бинарника
`naive` не блокирует установку — только предупреждение.

Пример с LAN-доступом:

```bash
curl -fsSL https://raw.githubusercontent.com/keenetic-tools/naivepanel/v0.1.0/install.sh \
  | sh -s -- --with-auth --bind 192.168.1.1:8089 --hosts '192.168.1.1:8089,router.local:8089'
```

## Ручной деплой на Keenetic (Entware)

> Требуется установленный пакет `naive-proxy` в Entware и, опционально,
> `python3` (если Python < 3.10 — ставим пакет `python3`). На Keenetic
> python3 в Entware уже есть.

```bash
# 1. Копируем файлы (через sshfs, scp или WebUI Keenetic)
ssh root@router
mkdir -p /opt/naivepanel
mkdir -p /opt/etc/naiveproxy/conf.d
mkdir -p /opt/etc/naivepanel

# Положить naivepanel.py + templates/index.html (нужен для render_template)
scp naivepanel.py root@router:/opt/naivepanel/
scp -r templates  root@router:/opt/naivepanel/
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
  > /opt/etc/naivepanel/admin.pass
chmod 0600 /opt/etc/naivepanel/admin.pass

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

Или просто SSH-туннель: `ssh -L 8089:127.0.0.1:8089 root@router`.

### Доступ из LAN без reverse proxy

Прокси не обязателен, если закрыты три вещи: auth, Host-allowlist и
доступность порта. Минимальный безопасный вариант:

```bash
# 1. Basic auth обязателен — без него LAN-bind = открытые пароли upstream-прокси
opkg update && opkg install python3-bcrypt
#    htpasswd в Entware отсутствует — генерируем bcrypt-хэш через python3
python3 -c 'import bcrypt,getpass; print("admin:"+bcrypt.hashpw(getpass.getpass().encode(),bcrypt.gensalt()).decode())' \
  > /opt/etc/naivepanel/admin.pass
chmod 0600 /opt/etc/naivepanel/admin.pass

# 2. Bind на LAN-адрес (НЕ 0.0.0.0 — иначе торчим и в WAN/VPN/guest-сегменты)
#    и allowlist Host-заголовков (анти-DNS-rebinding), в /opt/etc/init.d/rc.conf:
NAIVEPANEL_BIND=192.168.1.1:8089
NAIVEPANEL_HOSTS=192.168.1.1:8089,router.local:8089

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
- Если есть `/opt/etc/naivepanel/admin.pass` — **каждый** запрос требует HTTP Basic
  auth (bcrypt, формат htpasswd `user:$2y$…`). Без пакета `python3-bcrypt` в
  Entware auth fail-closed (401 на любой запрос + ошибка в лог).
- Если задан `NAIVEPANEL_HOSTS` (список через запятую, точные строки Host с
  портом) — запросы с чужим Host-заголовком отклоняются (403). Защита от
  DNS rebinding: обязательна при LAN-bind без reverse proxy.
- Активация пресета валидирует имя: `^[a-zA-Z0-9_\-.]{1,64}$` (нет path-traversal).
- Bind на `0.0.0.0` — warning в лог: на роутере это ещё и WAN/VPN/guest-сегменты.
- 401 (auth failed) и 403 (host rejected) пишутся в лог панели.
- Пароль панели и `admin.pass` НЕ коммитить в git.

## Что НЕ реализовано (по спеке wiki)

- ❌ multi-user
- ❌ HTTPS termination (только через внешний reverse proxy)
- ❌ auto-update панели
- ❌ мониторинг (latency / graphs / uptime)
- ❌ импорт/экспорт пресетов
- ❌ управление upstream-серверами

## Структура

```
naiveproxy-panel/
├── naivepanel.py            # Flask backend (~280 строк)
├── templates/
│   └── index.html           # UI (vanilla HTML + JS, без CDN)
├── S99naiveproxy            # init: бинарник naive
├── S99naivepanel            # init: Flask-приложение
├── README.md                # этот файл
└── .venv/                   # dev venv (в .gitignore)
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

## Лицензия

[MIT](LICENSE). Бинарник `naive` из [klzgrad/naiveproxy](https://github.com/klzgrad/naiveproxy)
распространяется под своей лицензией (BSD-3-Clause).
