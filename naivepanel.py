#!/usr/bin/env python3
"""NaivePanel — локальная веб-панель управления клиентом NaiveProxy на Keenetic/Entware.

Хранит пресеты конфигураций в /opt/etc/naive/proxy/conf.d/<name>.json,
при activate копирует один из них в /opt/etc/naive/proxy/config.json
(chmod 0600) и перезапускает init-скрипт S99naiveproxy.

Bind по умолчанию 127.0.0.1:8089 — публикация через внешний reverse proxy
или напрямую в LAN (admin.pass + NAIVEPANEL_HOSTS + firewall, см. README).
Постоянные настройки — /opt/etc/naive/panel/panel.conf (env перекрывает его).
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import secrets
import socket
# subprocess вызывается только с фиксированными argv-списками (shell=False)
import subprocess  # nosec B404
import time
from pathlib import Path
from typing import Any
from urllib.parse import quote, unquote

from flask import Flask, Response, abort, g, jsonify, make_response, render_template, request
from werkzeug.exceptions import HTTPException

# --- panel.conf: постоянные настройки панели (переживают апгрейды) --------
# Установщик перезаписывает init-скрипт при каждом обновлении, поэтому
# настройки живут в отдельном файле, который читает сам naivepanel.py.
# Формат: KEY="VALUE" (кавычки срезаются), комментарии — только с начала
# строки. Приоритет: env > panel.conf > встроенный дефолт.
# После правок: /opt/etc/init.d/S99naivepanel restart

PANEL_CONF = Path(os.environ.get("NAIVEPANEL_CONF", "/opt/etc/naive/panel/panel.conf"))

# Ключи, которые panel.conf имеет право задавать. Остальное игнорируем:
# файл разбирается до создания Flask-приложения, и опечатка не должна
# притащить в окружение произвольную переменную.
CONF_KEYS = frozenset({
    "NAIVEPANEL_BIND", "NAIVEPANEL_HOSTS", "NAIVEPANEL_PASS",
    "NAIVEPROXY_DIR", "NAIVEPROXY_INIT", "NAIVEPROXY_LOG", "NAIVEPROXY_PID",
    "NAIVEPANEL_INIT", "NAIVEPANEL_THREADS",
})

_CONF_SKIPPED: list[str] = []


def _parse_conf(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return out  # файла нет — работаем на env/дефолтах
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip().strip('"').strip("'")
        if key in CONF_KEYS:
            out[key] = value
        else:
            _CONF_SKIPPED.append(key)
    return out


def _apply_conf_file() -> None:
    for key, value in _parse_conf(PANEL_CONF).items():
        os.environ.setdefault(key, value)


_apply_conf_file()

# --- Конфигурация путей (на Keenetic/Entware) -----------------------------

NAIVEPROXY_DIR = Path(os.environ.get("NAIVEPROXY_DIR", "/opt/etc/naive/proxy"))
CONF_D = NAIVEPROXY_DIR / "conf.d"
ACTIVE_CONFIG = NAIVEPROXY_DIR / "config.json"
ACTIVE_POINTER = NAIVEPROXY_DIR / ".active"  # имя текущего активного пресета
INIT_SCRIPT = Path(os.environ.get("NAIVEPROXY_INIT", "/opt/etc/init.d/S99naiveproxy"))
LOG_FILE = Path(os.environ.get("NAIVEPROXY_LOG", "/opt/var/log/naiveproxy.log"))
PID_FILE = Path(os.environ.get("NAIVEPROXY_PID", "/opt/var/run/naiveproxy.pid"))
PANEL_ADMIN_PASS = Path(os.environ.get("NAIVEPANEL_PASS", "/opt/etc/naive/panel/admin.pass"))
PANEL_BIND = os.environ.get("NAIVEPANEL_BIND", "127.0.0.1:8089")
# Allowlist Host-заголовков (через запятую, с портом). Пусто — проверка выкл.
ALLOWED_HOSTS = {h.strip() for h in os.environ.get("NAIVEPANEL_HOSTS", "").split(",") if h.strip()}
# Init-скрипт самой панели — для self-restart после обновления файлов.
PANEL_INIT = Path(os.environ.get("NAIVEPANEL_INIT", "/opt/etc/init.d/S99naivepanel"))
# Прод-сервер waitress, если установлен; иначе — dev-сервер Werkzeug.
# На роутере (LAN-bind) waitress ограничивает число потоков и переживает
# медленных клиентов; в dev/Mac падать не должен.
# Опечатка в panel.conf не должна ронять импорт — предупредим в _serve.
_THREADS_RAW = os.environ.get("NAIVEPANEL_THREADS", "4") or "4"
try:
    WAITRESS_THREADS = max(1, int(_THREADS_RAW))
except (TypeError, ValueError):
    WAITRESS_THREADS = 4
    _THREADS_INVALID = True
else:
    _THREADS_INVALID = False

NAME_RE = re.compile(r"^[a-zA-Z0-9_\-.]{1,64}$")
# Разрешённые схемы proxy-URI: только реально поддерживаемые naive.
_ALLOWED_PROXY_SCHEMES = ("https://", "http://", "quic://")
# Имена, занятые статическими маршрутами /api/configs/export|import:
# такой пресет нельзя было бы получить через GET (роутинг отдаёт файл)
RESERVED_NAMES = frozenset({"export", "import"})

APP_VERSION = "0.6.1"


def _ensure_dirs() -> None:
    CONF_D.mkdir(parents=True, exist_ok=True)


def _parse_bind(bind: str) -> tuple[str, int]:
    """`HOST:PORT` → (host, port); понимает `[::1]:8089` и голый IPv6.

    Порт не задан или не числовой → 8089. Голый IPv6 (`::1`) ловим по лишнему
    `:` — rpartition иначе отрезал бы кусок адреса.
    """
    if bind.startswith("[") and "]" in bind:
        host = bind[1:bind.index("]")]
        rest = bind[bind.index("]") + 1:].lstrip(":")
        return host, (int(rest) if rest.isdigit() else 8089)
    host, sep, port = bind.rpartition(":")
    if host.count(":") > 0 or not sep or not port.isdigit():
        return bind or "127.0.0.1", 8089
    return host or "127.0.0.1", int(port)


def _default_allowed_hosts(bind: str) -> set[str]:
    """Host-заголовки, разрешённые без явного NAIVEPANEL_HOSTS.

    Прямой доступ из браузера всегда идёт на адрес bind (или loopback-алиас),
    поэтому их разрешаем; чужое имя хоста — маркер DNS-rebinding → 403.
    Reverse proxy со своим именем требует явного NAIVEPANEL_HOSTS (README).
    """
    host, port = _parse_bind(bind)
    hosts = {
        host, f"{host}:{port}",
        "localhost", f"localhost:{port}",
        "127.0.0.1", f"127.0.0.1:{port}",
    }
    if ":" in host:  # IPv6-браузеры шлют Host в квадратных скобках
        hosts |= {f"[{host}]", f"[{host}]:{port}"}
    return hosts


# --- Работа с конфигами ---------------------------------------------------

def _load_json(path: Path) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        abort(404, description=f"{path.name} not found")
    except json.JSONDecodeError as exc:
        abort(400, description=f"invalid JSON in {path.name}: {exc}")
    if not isinstance(data, dict):
        abort(400, description=f"{path.name}: expected object")
    return data


def _save_json(path: Path, data: dict[str, Any]) -> None:
    """Atomic write + chmod 0600 — пресеты тоже могут содержать креденшалы."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, sort_keys=False)
        fh.write("\n")
    os.chmod(tmp, 0o600)
    tmp.replace(path)
    # os.replace сохраняет режим tmp-файла, но на overlay FS перестрахуемся
    os.chmod(path, 0o600)


def _write_active(name: str, cfg: dict[str, Any]) -> None:
    NAIVEPROXY_DIR.mkdir(parents=True, exist_ok=True)
    _save_json(ACTIVE_CONFIG, cfg)
    ACTIVE_POINTER.write_text(name + "\n", encoding="utf-8")
    os.chmod(ACTIVE_POINTER, 0o600)


def _active_name() -> str | None:
    if not ACTIVE_POINTER.exists():
        return None
    try:
        name = ACTIVE_POINTER.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return name if NAME_RE.match(name) else None


def _split_proxy(proxy: str) -> tuple[str, str, str | None]:
    """Разбирает proxy-URI на (upstream, username, password).

    Зеркально _build_payload: тот собирает строго `https://user:pass@host`
    (креденшалы percent-encoded), поэтому тут пароль выделяется от последнего
    `@` (легаси-конфиги с raw `@` в пароле тоже читаются), username — до первого
    `:` в кредах, затем оба unquote. Если URI не https:// или кредов нет —
    upstream возвращается целиком, password=None (кредов не выделить).
    """
    if proxy.startswith("https://"):
        rest = proxy[len("https://"):]
        at = rest.rfind("@")
        if at != -1:
            creds, host = rest[:at], rest[at + 1:]
            colon = creds.find(":")
            if colon != -1:
                return host, unquote(creds[:colon]), unquote(creds[colon + 1:])
    return proxy, "", None


def _for_edit(cfg: dict[str, Any]) -> dict[str, Any]:
    """Конфигурация для формы редактирования — БЕЗ пароля.

    upstream и username отдаются уже разобранными, чтобы фронтенду не пришлось
    самому парсить proxy-URI (и ломаться на `@` в пароле). Пароль через API
    не возвращается вовсе: пустое поле в форме означает «оставить прежний».
    """
    upstream, username, _ = _split_proxy(cfg.get("proxy") or "")
    out = {k: v for k, v in cfg.items() if k != "proxy"}
    out["upstream"] = upstream
    out["username"] = username
    return out


def _summary(cfg: dict[str, Any]) -> dict[str, Any]:
    listen = cfg.get("listen")
    proxy = cfg.get("proxy")
    if isinstance(listen, list):
        listen_uri = listen[0] if listen else ""
        listen_count = len(listen)
    else:
        listen_uri = listen if isinstance(listen, str) else ""
        listen_count = 1 if listen_uri else 0
    proxy_uri = proxy if isinstance(proxy, str) else (proxy[0] if isinstance(proxy, list) and proxy else "")
    user = ""
    if "@" in proxy_uri:
        creds = proxy_uri.split("@", 1)[0]
        if "://" in creds:
            creds = creds.rsplit("://", 1)[-1]
        user = unquote(creds.split(":", 1)[0])
    return {
        "listen": listen_uri,
        "listen_count": listen_count,
        # пароль в списке не отдаём: маскируем до сериализации (username
        # извлекается из сырого значения выше)
        "proxy": _mask_creds(proxy_uri),
        "username": user,
    }


def _list_presets() -> list[dict[str, Any]]:
    _ensure_dirs()
    active = _active_name()
    out: list[dict[str, Any]] = []
    for p in sorted(CONF_D.glob("*.json")):
        try:
            cfg = _load_json(p)
        except Exception as exc:
            app.logger.warning("skipping %s: %s", p.name, exc)
            continue
        summary = _summary(cfg)
        out.append({"name": p.stem, "active": p.stem == active, **summary})
    return out


def _normalize_listen(raw: str) -> str | None:
    """Один listen-адрес → URI. Без схемы добавляет socks://.

    `127.0.0.1:1080` → `socks://127.0.0.1:1080`;
    `http://127.0.0.1:8080` остаётся как есть.
    """
    raw = raw.strip()
    if not raw:
        return None
    if "://" not in raw:
        raw = f"socks://{raw}"
    return raw


def _build_payload(data: dict[str, Any], old_proxy: str | None = None) -> dict[str, Any]:
    """Собирает JSON-конфиг клиента naive из данных формы.

    listen принимает строку (несколько адресов через запятую/перенос) или массив;
    при одном адресе → строка, при нескольких → массив. Пример массива:
      `{"listen": ["socks://127.0.0.1:1080","http://127.0.0.1:8080"], ...}`

    upstream поддерживает два формата:
      - `https://user:pass@host[:port]` — полный proxy URL, передаётся как есть
      - `host[:port]` или `https://host[:port]` — креденшалы подставляются из
        полей username/password

    Пароль через API не возвращается (GET отдаёт конфиг без него), поэтому при
    обновлении пустой password означает «оставить прежний» — он извлекается из
    old_proxy. То же с пустым username.
    """
    name = (data.get("name") or "").strip()
    upstream = (data.get("upstream") or "").strip()

    # listen — строка с разделителями (запятая/перенос), либо массив
    listen_raw = data.get("listen") or []
    if isinstance(listen_raw, str):
        parts = [s for s in (p.strip() for p in re.split(r"[\n,]+", listen_raw)) if s]
    elif isinstance(listen_raw, list):
        parts = [s.strip() for s in listen_raw if isinstance(s, str) and s.strip()]
    else:
        parts = []
    listen_uris = [u for u in (_normalize_listen(p) for p in parts) if u]

    if not (name and listen_uris and upstream):
        abort(400, description="name, listen, upstream are required")

    # Один адрес → строка (компактнее), несколько → массив
    listen = listen_uris[0] if len(listen_uris) == 1 else listen_uris

    if "@" in upstream:
        # Уже полный proxy URL с креденшалами
        proxy_uri = upstream
    else:
        username = (data.get("username") or "").strip()
        password = data.get("password") or ""
        if old_proxy:
            old_upstream, old_user, old_pass = _split_proxy(old_proxy)
            if not username and old_upstream == upstream:
                username = old_user
            if not password:
                password = old_pass or ""
        if not (username and password):
            abort(400, description="username and password are required")
        # Вытаскиваем хост из возможного `https://` префикса
        host = upstream
        if host.startswith(("https://", "http://", "quic://")):
            host = host.split("://", 1)[1]
        # Креденшалы percent-encode'им (RFC 3986): `@ : / ` и пр. в пароле
        # иначе ломают разбор URI. naive/Chromium userinfo декодирует.
        proxy_uri = f"https://{quote(username, safe='')}:{quote(password, safe='')}@{host.rstrip('/')}"

    cfg: dict[str, Any] = {"listen": listen, "proxy": proxy_uri}
    if data.get("log"):
        cfg["log"] = data["log"]
    if data.get("extra_headers"):
        cfg["extra-headers"] = data["extra_headers"]
    if data.get("host_resolver_rules"):
        cfg["host-resolver-rules"] = data["host_resolver_rules"]
    if data.get("insecure_concurrency"):
        try:
            cfg["insecure-concurrency"] = int(data["insecure_concurrency"])
        except ValueError:
            abort(400, description="insecure-concurrency must be integer")
    return cfg


def _validate_cfg(cfg: dict[str, Any], name: str) -> None:
    """Схема хранимого формата перед activate/PUT/импортом (400 при ошибке).

    Бинарник naive с битым конфигом падает в рантайме — activate такого
    пресета уронил бы РАБОТАЮЩИЙ прокси (config.json уже перезаписан, а
    рестарт не удался). Ловим очевидные проблемы заранее: отсутствующие
    listen/proxy, пустые адреса, URI без схемы, диапазон insecure-concurrency
    (HTML-форма ограничивает 1..4, но API — нет).
    """
    errors: list[str] = []
    listen = cfg.get("listen")
    if isinstance(listen, list):
        if not listen or any(not isinstance(l, str) or not l.strip() for l in listen):
            errors.append("listen: нужны непустые строки")
    elif not (isinstance(listen, str) and listen.strip()):
        errors.append("listen обязателен (строка или массив строк)")
    proxy = cfg.get("proxy")
    if not (isinstance(proxy, str) and proxy.strip()):
        errors.append("proxy обязателен")
    elif not proxy.strip().lower().startswith(_ALLOWED_PROXY_SCHEMES):
        errors.append("proxy: разрешены схемы https://, http://, quic://")
    ic = cfg.get("insecure-concurrency")
    if ic is not None and (not isinstance(ic, int) or isinstance(ic, bool) or not 1 <= ic <= 4):
        errors.append("insecure-concurrency: целое 1..4")
    for key in ("log", "extra-headers", "host-resolver-rules"):
        if cfg.get(key) is not None and not isinstance(cfg[key], str):
            errors.append(f"{key}: строка")
    if errors:
        abort(400, description=f"{name}: " + "; ".join(errors))


def _upstream_endpoint(upstream: str) -> tuple[str, int] | None:
    """Upstream (host, host:port или полный/неполный URI) → (host, port).

    Для TCP-проверки доступности нужны только адрес и порт: срезаем схему и
    креденшалы. Порт не указан → 443 (стандартный для https-upstream).
    Голый IPv6 без квадратных скобок не поддерживаем — в поле upstream
    такой формат не встречается.
    """
    host = (upstream or "").strip()
    if "://" in host:
        host = host.split("://", 1)[1]
    at = host.rfind("@")  # креды в userinfo
    if at != -1:
        host = host[at + 1:]
    host = host.split("/", 1)[0]
    if not host:
        return None
    if host.startswith("[") and "]" in host:  # IPv6: [::1] или [::1]:443
        inner = host[1:host.index("]")]
        rest = host[host.index("]") + 1:].lstrip(":")
        return inner, (int(rest) if rest.isdigit() else 443)
    head, sep, tail = host.rpartition(":")
    if sep:
        return (head, int(tail)) if head and tail.isdigit() else None
    return tail, 443  # rpartition без sep: head пуст, исходная строка в tail


# --- Service control ------------------------------------------------------

def _run(cmd: list[str], timeout: int = 10) -> dict[str, Any]:
    try:
        # cmd — фиксированный argv-список, shell не используется
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)  # nosec B603
        return {
            "rc": r.returncode,
            "stdout": r.stdout.strip(),
            "stderr": r.stderr.strip(),
        }
    except FileNotFoundError as exc:
        abort(500, description=f"command not found: {exc.filename}")
    except subprocess.TimeoutExpired:
        abort(504, description=f"timeout running {' '.join(cmd)}")


def _service(action: str) -> dict[str, Any]:
    if not INIT_SCRIPT.exists():
        abort(503, description=f"{INIT_SCRIPT} not found")
    # stop в S99naiveproxy ждёт до 10с, restart = stop+start — таймаут обязан
    # покрывать худший случай, иначе /bin/sh убивают посреди рестарта
    return _run(["/bin/sh", str(INIT_SCRIPT), action], timeout=30)


def _pid_is_naive(pid: int) -> bool:
    """Анти-pid-reuse: сверяем имя процесса, если /proc доступен.

    Не читается (нет /proc — macOS/dev-запуск, чужой uid) — считаем нашим:
    ложный «работает» безопаснее ложного «остановлен».
    """
    try:
        name = Path(f"/proc/{pid}/comm").read_text(encoding="utf-8").strip()
    except OSError:
        return True
    return name in {"naive", "naiveproxy"}


def _status() -> dict[str, Any]:
    active_name = _active_name()
    has_init = INIT_SCRIPT.exists()
    pid: int | None = None
    uptime: int | None = None
    running = False
    if PID_FILE.exists():
        try:
            pid = int(PID_FILE.read_text(encoding="utf-8").strip())
        except (ValueError, OSError):
            pid = None
        if pid is not None:
            # Проверяем, что процесс реально жив — pid-файл может пережить crash
            try:
                os.kill(pid, 0)
                running = True
            except ProcessLookupError:
                pid = None
            except PermissionError:
                # Процесс чужой (другой uid), но жив — считаем запущенным
                running = True
            if running and not _pid_is_naive(pid):
                pid = None  # pid переиспользован чужим процессом
                running = False
            if running:
                uptime = max(0, int(time.time() - PID_FILE.stat().st_mtime))
    return {
        "version": APP_VERSION,
        "active": running,
        "pid": pid,
        "uptime": uptime,
        "current": active_name,
        "init_script": str(INIT_SCRIPT),
        "init_present": has_init,
    }


_CRED_RE = re.compile(r"([a-zA-Z][a-zA-Z0-9+.\-]*://[^:/@\s]+):([^@\s]+)@")


def _mask_creds(text: str) -> str:
    """Маскирует userinfo в URI (`scheme://user:pass@host` → `user:***@`)."""
    return _CRED_RE.sub(r"\1:***@", text)


def _tail_log(lines: int = 100) -> str:
    """Последние `lines` строк лога — чтением с конца, а не всего файла.

    Между рестартами лог может вырасти далеко за урезающий лимит init-скрипта,
    а /api/logs дёргается поллингом каждые 3с — readlines() всего файла на
    роутере был бы заметен по памяти/CPU. Заодно маскируем креды в URI.
    """
    if not LOG_FILE.exists():
        return ""
    lines = max(1, min(lines, 1000))
    try:
        with LOG_FILE.open("rb") as fh:
            fh.seek(0, os.SEEK_END)
            end = fh.tell()
            chunk = 8192
            buf = b""
            while True:
                start = max(0, end - chunk)
                fh.seek(start)
                buf = fh.read(end - start) + buf
                if buf.count(b"\n") > lines or start == 0:
                    break
                end = start
                chunk = min(chunk * 2, 4 * 1024 * 1024)
            data = buf.decode("utf-8", errors="replace")
    except OSError as exc:
        return f"<log read error: {exc}>"
    return _mask_creds("".join(data.splitlines(keepends=True)[-lines:]))


# --- Flask app ------------------------------------------------------------

app = Flask(__name__)
# Конфиги крошечные — гигантский PUT иначе ронял бы память роутера
app.config["MAX_CONTENT_LENGTH"] = 256 * 1024

# Опечатки в panel.conf не должны молча теряться (NIVEPANEL_BIND и т.п.)
for _k in sorted(set(_CONF_SKIPPED)):
    app.logger.warning("panel.conf: ignoring unknown key %r", _k)


@app.errorhandler(HTTPException)
def _api_json_errors(exc: HTTPException):
    """Ошибки под /api/* — JSON, а не HTML-страница Flask.

    Фронтенд парсит тело ответа и показывает `error` в плашке; сырой HTML
    там выглядел мусором.
    """
    if request.path.startswith("/api/"):
        msg = exc.description or exc.name
        return jsonify({"error": msg, "description": msg}), exc.code
    return exc


# --- Security headers --------------------------------------------------------

# Скрипты разрешены только по nonce (уникален на запрос): инъекция <script>
# без nonce не выполнится, 'unsafe-inline' для script не нужен. style-src
# оставляем 'unsafe-inline' — inline-стили и style="" в шаблоне. Внешние
# origin'ы запрещены: connect-src 'self' не даёт внедрённому коду
# эксфильтрировать данные fetch'ем на сторонний домен.
def _csp(nonce: str) -> str:
    return (
        "default-src 'none'; "
        f"script-src 'nonce-{nonce}'; "
        "style-src 'unsafe-inline'; "
        "connect-src 'self'; "
        "img-src 'self' data:; "
        "base-uri 'none'; "
        "form-action 'self'; "
        "frame-ancestors 'none'"
    )


@app.after_request
def _security_headers(resp: Response) -> Response:
    resp.headers.setdefault("Content-Security-Policy", _csp(getattr(g, "csp_nonce", "")))
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    return resp


# --- CSP nonce ---------------------------------------------------------------

# Регистрируется до Host-allowlist: nonce нужен и на 403-ответах (after_request
# читает g.csp_nonce), поэтому должен существовать раньше любого abort.

@app.before_request
def _make_csp_nonce() -> None:
    g.csp_nonce = secrets.token_urlsafe(16)


@app.context_processor
def _inject_csp_nonce() -> dict[str, str]:
    return {"csp_nonce": getattr(g, "csp_nonce", "")}


# --- Host allowlist (анти-DNS-rebinding) -----------------------------------

# Дефолтный allowlist: адрес bind + loopback-алиасы. Прямой доступ из браузера
# всегда идёт на один из них; чужое имя в Host — маркер DNS-rebinding.
DEFAULT_ALLOWED_HOSTS = _default_allowed_hosts(PANEL_BIND)


@app.before_request
def _enforce_host_allowlist():
    """Allowlist Host-заголовков: анти-DNS-rebinding.

    При DNS-rebinding страница зловредного сайта резолвится в адрес панели, и
    браузер считает запросы same-origin: он может читать ответы и ставить
    кастомные заголовки — CSRF-проверка его не остановит. Единственный след
    атаки — чужое имя в Host. Правила: NAIVEPANEL_HOSTS задан → только эти
    точные строки (`192.168.1.1:8089,router.lan:8089`); не задан → адрес bind
    + loopback-алиасы. Reverse proxy со своим именем хоста требует явного
    NAIVEPANEL_HOSTS (см. README).
    """
    allowed = {h.lower() for h in (ALLOWED_HOSTS or DEFAULT_ALLOWED_HOSTS)}
    if request.host.lower() in allowed:
        return
    app.logger.warning("rejected Host %r from %s", request.host, request.remote_addr)
    abort(403, description="host not allowed (see NAIVEPANEL_HOSTS)")


# --- CSRF -------------------------------------------------------------------
# Basic-креды браузер прикладывает к кросс-сайтовым запросам автоматически,
# поэтому сама по себе auth от CSRF не защищает. POST без тела — «simple
# request» без preflight, так что зловредная страница могла бы дёргать
# /api/service/* и activate от имени залогиненного админа. Кастомный заголовок
# cross-origin JS не поставит без успешного CORS-preflight, а preflight-ответов
# мы не отдаём — запрос отклоняется ещё на нём.

@app.before_request
def _csrf_protect():
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return
    if request.headers.get("X-Requested-With") != "naivepanel":
        app.logger.warning(
            "csrf: no X-Requested-With, %s %s from %s",
            request.method, request.path, request.remote_addr,
        )
        abort(403, description="X-Requested-With header required")
    site = request.headers.get("Sec-Fetch-Site")
    if site is not None and site not in ("same-origin", "none"):
        abort(403, description="cross-site request rejected")


# --- HTTP Basic auth (опционально) ----------------------------------------

# Поллинг UI дёргает API каждые 3с: без кэша bcrypt-хэширование съедало бы CPU
# роутера постоянно. Кэшируем только УСПЕШНЫЕ проверки (ключ — sha256 креденшалов);
# смена admin.pass (mtime/size) сбрасывает кэш немедленно, как и удаление записи.
_AUTH_CACHE_TTL = 300.0
_AUTH_CACHE_LIMIT = 64
_auth_cache: dict[str, float] = {}  # sha256(user\x00pass) → expiry (monotonic)
_admin_pass_stamp: tuple[int, int] | None = None

# Анти-перебор: счётчик неудач на IP. До лимита — обычный 401; сверх лимита —
# 429 без time.sleep (флуд не должен держать рабочие потоки роутера).
_AUTH_FAIL_WINDOW = 60.0
_AUTH_FAIL_LIMIT = 5
_auth_fails: dict[str, list] = {}  # ip -> [count, window_start_monotonic]


def _auth_register_failure(ip: str) -> None:
    now = time.monotonic()
    rec = _auth_fails.get(ip)
    if rec is None or now - rec[1] > _AUTH_FAIL_WINDOW:
        _auth_fails[ip] = [1, now]
    else:
        rec[0] += 1


def _auth_throttled(ip: str) -> bool:
    rec = _auth_fails.get(ip)
    if not rec:
        return False
    if time.monotonic() - rec[1] > _AUTH_FAIL_WINDOW:
        _auth_fails.pop(ip, None)
        return False
    return rec[0] >= _AUTH_FAIL_LIMIT


@app.before_request
def _require_auth():
    """Если /opt/etc/naive/panel/admin.pass существует — требует HTTP Basic auth
    на каждый запрос. Формат файла — стандартный htpasswd: `user:bcrypt-hash`
    на строку. Создание: `htpasswd -B -c admin.pass user` (или python3-bcrypt —
    в Entware htpasswd отсутствует, см. README).

    Без пакета python3-bcrypt auth fail-closed (401 на любой запрос), в лог
    пишется ошибка. Это намеренно: лучше сломанная панель, чем открытая.
    """
    global _admin_pass_stamp
    if not PANEL_ADMIN_PASS.exists():
        return  # auth выключен — только 127.0.0.1, публично не торчим
    ip = request.remote_addr or ""
    if _auth_throttled(ip):
        abort(429, description="too many failed auth attempts, try later")
    try:
        st = PANEL_ADMIN_PASS.stat()
        stamp = (st.st_mtime_ns, st.st_size)
    except OSError:
        stamp = None
    if stamp != _admin_pass_stamp:
        _admin_pass_stamp = stamp
        _auth_cache.clear()
    auth = request.authorization
    if auth:
        key = hashlib.sha256(
            (auth.username or "").encode() + b"\x00" + (auth.password or "").encode()
        ).hexdigest()
        now = time.monotonic()
        exp = _auth_cache.get(key)
        if exp is not None and exp > now:
            _auth_fails.pop(ip, None)
            return
        stored = PANEL_ADMIN_PASS.read_text(encoding="utf-8")
        if _htpasswd_verify(stored, auth.username or "", auth.password or ""):
            if len(_auth_cache) >= _AUTH_CACHE_LIMIT:
                _auth_cache.clear()
            _auth_cache[key] = now + _AUTH_CACHE_TTL
            _auth_fails.pop(ip, None)
            return
    app.logger.warning(
        "auth failed: user=%r addr=%s path=%s",
        auth.username if auth else None,
        request.remote_addr,
        request.path,
    )
    if auth is not None:
        # неудачи считаем только при предъявленных кредах: анонимные пробы
        # (без Authorization) за reverse-proxy с общим remote_addr иначе
        # заблокировали бы всех админов
        _auth_register_failure(ip)
    return Response(
        "auth required",
        401,
        {"WWW-Authenticate": 'Basic realm="naivepanel"'},
    )


def _htpasswd_verify(stored: str, user: str, password: str) -> bool:
    """Проверка user:password по htpasswd-файлу.

    Поддержка только bcrypt ($2y$/$2a$/$2b$). apr1 намеренно не поддерживаем —
    слабее и требует отдельной крипто-зависимости. Файл может содержать
    несколько строк `user:hash`; совпадение по user, затем bcrypt.checkpw.
    """
    try:
        import bcrypt  # type: ignore
    except ImportError:
        app.logger.error(
            "admin.pass exists but bcrypt is not installed — auth disabled. "
            "Install python3-bcrypt in Entware or remove admin.pass."
        )
        return False
    for line in stored.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        u, h = line.split(":", 1)
        if u != user:
            continue
        if not h.startswith(("$2y$", "$2a$", "$2b$")):
            app.logger.warning("admin.pass: unsupported hash for %r (need bcrypt)", u)
            return False
        try:
            return bcrypt.checkpw(password.encode(), h.encode())
        except ValueError:
            # битый хэш в admin.pass не должен превращать каждый запрос в 500
            app.logger.warning("admin.pass: malformed bcrypt hash for %r", u)
            return False
    return False  # пользователь не найден


# --- Routes ---------------------------------------------------------------

@app.route("/")
def index() -> Response:
    # no-cache: браузер обязан ревалидировать HTML — после self-restart
    # (location.reload) Safari/др. не должны отдать эвристически закэшированную
    # старую версию панели.
    resp = make_response(render_template("index.html"))
    resp.headers["Cache-Control"] = "no-cache"
    return resp


@app.route("/api/status")
def api_status():
    return jsonify(_status())


@app.route("/api/configs")
def api_configs_list():
    resp = jsonify(_list_presets())
    resp.headers["Cache-Control"] = "no-store"  # список не должен кешироваться
    return resp


@app.route("/api/configs/<name>", methods=["GET"])
def api_configs_get(name: str):
    if not NAME_RE.match(name):
        abort(400, description="invalid name")
    cfg = _load_json(CONF_D / f"{name}.json")
    return jsonify(_for_edit(cfg))


@app.route("/api/configs", methods=["POST"])
def api_configs_create():
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    if not NAME_RE.match(name):
        abort(400, description="invalid name")
    if name in RESERVED_NAMES:
        abort(400, description=f"name {name!r} is reserved")
    cfg = _build_payload(data)
    _validate_cfg(cfg, name)
    path = CONF_D / f"{name}.json"
    if path.exists():
        abort(409, description=f"preset {name!r} already exists")
    _ensure_dirs()
    _save_json(path, cfg)
    return jsonify({"name": name, "saved": True}), 201


@app.route("/api/configs/<name>", methods=["PUT"])
def api_configs_update(name: str):
    if not NAME_RE.match(name):
        abort(400, description="invalid name")
    data = request.get_json(silent=True) or {}
    if "name" in data and data["name"] != name:
        abort(400, description="name in body must match URL")
    path = CONF_D / f"{name}.json"
    old = _load_json(path)  # 404, если пресета нет
    cfg = _build_payload(data, old_proxy=old.get("proxy"))
    _validate_cfg(cfg, name)
    _save_json(path, cfg)
    restart = None
    if _active_name() == name:
        # Активный пресет = работающий конфиг: применяем сразу, как activate,
        # иначе «Сохранено» врало бы — файл обновлён, а naive работает старым.
        _write_active(name, cfg)
        restart = _service("restart") if INIT_SCRIPT.exists() else {"rc": None, "note": "no init script"}
    return jsonify({"name": name, "updated": True, "restart": restart})


@app.route("/api/configs/<name>", methods=["DELETE"])
def api_configs_delete(name: str):
    if not NAME_RE.match(name):
        abort(400, description="invalid name")
    if _active_name() == name:
        abort(409, description="cannot delete active preset")
    path = CONF_D / f"{name}.json"
    if not path.exists():
        abort(404, description=f"preset {name!r} not found")
    path.unlink()
    return jsonify({"name": name, "deleted": True})


@app.route("/api/configs/<name>/activate", methods=["POST"])
def api_configs_activate(name: str):
    if not NAME_RE.match(name):
        abort(400, description="invalid name")
    src = CONF_D / f"{name}.json"
    if not src.exists():
        abort(404, description=f"preset {name!r} not found")
    cfg = _load_json(src)
    _validate_cfg(cfg, name)  # битый конфиг не должен ронять рабочий прокси
    _write_active(name, cfg)
    restart = _service("restart") if INIT_SCRIPT.exists() else {"rc": None, "note": "no init script"}
    return jsonify({"name": name, "active": True, "restart": restart})


@app.route("/api/configs/<name>/duplicate", methods=["POST"])
def api_configs_duplicate(name: str):
    """Копия пресета целиком, server-side — включая пароль.

    Через UI (GET → форма → POST) пароль не переносится: GET его не отдаёт,
    а create требует креды для host-only upstream. Копирование файла на
    сервере сохраняет работоспособный конфиг без повторного ввода секрета.
    """
    if not NAME_RE.match(name):
        abort(400, description="invalid name")
    src = CONF_D / f"{name}.json"
    if not src.exists():
        abort(404, description=f"preset {name!r} not found")
    cfg = _load_json(src)
    # имя копии: name-copy, при занятости name-copy2, name-copy3… NAME_RE
    # допускает 64 символа — урезаем базу, чтобы суффикс всегда влез
    base = f"{name}-copy"[:58]
    candidate, n = base, 2
    while (CONF_D / f"{candidate}.json").exists():
        if n > 99:
            abort(409, description=f"too many copies of {name!r}")
        candidate = f"{base}{n}"
        n += 1
    _save_json(CONF_D / f"{candidate}.json", cfg)
    return jsonify({"name": candidate, "copied_from": name}), 201


@app.route("/api/configs/export")
def api_configs_export():
    """Все пресеты одним JSON-файлом — бэкап / миграция на другой роутер.

    ВАЖНО: содержит proxy-URI с паролями — иначе восстановление теряло бы
    креды и не было бы бэкапом. Это единственный GET, отдающий секреты:
    осознанное действие пользователя (Content-Disposition: attachment —
    файл уходит в Downloads, а не в кеш браузера).
    """
    _ensure_dirs()
    presets: dict[str, Any] = {}
    for p in sorted(CONF_D.glob("*.json")):
        try:
            presets[p.stem] = _load_json(p)
        except Exception as exc:  # битый файл не должен ронять весь экспорт
            app.logger.warning("export: skipping %s: %s", p.name, exc)
    resp = jsonify({
        "format": 1,
        "version": APP_VERSION,
        "exported": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "presets": presets,
    })
    resp.headers["Content-Disposition"] = 'attachment; filename="naivepanel-presets.json"'
    resp.headers["Cache-Control"] = "no-store"  # ответ содержит секреты
    return resp


@app.route("/api/configs/import", methods=["POST"])
def api_configs_import():
    """Импорт пресетов из файла export-формата (поле presets: {name: cfg}).

    Существующие имена НЕ перезаписываются (причина — в ответе), каждый
    пресет проходит _validate_cfg — файл мог быть отредактирован руками.
    Лимит тела 256 КБ (MAX_CONTENT_LENGTH) покрывает ~сотни пресетов.
    """
    data = request.get_json(silent=True) or {}
    incoming = data.get("presets")
    if not isinstance(incoming, dict):
        abort(400, description="expected {presets: {name: config}}")
    imported: list[str] = []
    skipped: list[dict[str, str]] = []
    for name, cfg in sorted(incoming.items()):
        if not NAME_RE.match(name or ""):
            skipped.append({"name": name, "reason": "invalid name"})
            continue
        if name in RESERVED_NAMES:
            skipped.append({"name": name, "reason": "reserved name"})
            continue
        if not isinstance(cfg, dict):
            skipped.append({"name": name, "reason": "expected object"})
            continue
        try:
            _validate_cfg(cfg, name)
        except HTTPException as exc:
            skipped.append({"name": name, "reason": str(exc.description)})
            continue
        if (CONF_D / f"{name}.json").exists():
            skipped.append({"name": name, "reason": "already exists"})
            continue
        _save_json(CONF_D / f"{name}.json", cfg)
        imported.append(name)
    if imported:
        app.logger.info("import: created %s", ", ".join(imported))
    return jsonify({"imported": imported, "skipped": skipped})


@app.route("/api/probe", methods=["POST"])
def api_probe():
    """TCP-доступность upstream: коннект с роутера, таймаут 3с.

    Отличает «прокси лежит» от «сеть/файрвол»: панель ходит с того же хоста,
    что и naive. Только TCP-коннект — без TLS-хендшейка и без отправки
    кредов; недоступность — это нормальный ответ 200 с полем error.
    """
    data = request.get_json(silent=True) or {}
    ep = _upstream_endpoint(data.get("upstream") or "")
    if not ep:
        abort(400, description="upstream required (host[:port] or URI)")
    host, port = ep
    t0 = time.monotonic()
    try:
        with socket.create_connection(ep, timeout=3.0):
            pass
        return jsonify({"host": host, "port": port,
                        "ms": round((time.monotonic() - t0) * 1000)})
    except OSError as exc:  # refused/timeout/DNS — не ошибка панели
        return jsonify({"host": host, "port": port, "error": str(exc)})


@app.route("/api/service/<action>", methods=["POST"])
def api_service(action: str):
    if action not in {"start", "stop", "restart"}:
        abort(400, description="action must be start|stop|restart")
    return jsonify(_service(action))


@app.route("/api/panel/restart", methods=["POST"])
def api_panel_restart():
    """Перезапуск самой панели: отсоединённо spawn'ит `S99naivepanel restart`.

    Init-скрипт через ~1с (sleep даёт ответ уйти) убивает текущий процесс и
    поднимает новый. Используется после обновления naivepanel.py/templates,
    чтобы не логиниться по SSH ради `/opt/etc/init.d/S99naivepanel restart`.
    """
    if not PANEL_INIT.exists():
        abort(503, description=f"{PANEL_INIT} not found")
    # Новая сессия → ребёнок переживёт смерть Flask-процесса. Путь передаём
    # argv ($1), а не интерполяцией в shell-строку. Команда фиксированная.
    subprocess.Popen(  # nosec B603
        ["/bin/sh", "-c", 'sleep 1; exec /bin/sh "$1" restart', "sh", str(PANEL_INIT)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    app.logger.warning("panel self-restart triggered by %s", request.remote_addr)
    return jsonify({"restart": True, "note": "panel restarting in ~1s"}), 202


@app.route("/api/logs")
def api_logs():
    try:
        lines = int(request.args.get("lines", "100"))
    except ValueError:
        lines = 100
    resp = jsonify({"lines": lines, "content": _tail_log(lines)})
    resp.headers["Cache-Control"] = "no-store"  # логи могут содержать креды
    return resp


# --- Main -----------------------------------------------------------------


def _serve(application: Flask, host: str, port: int) -> None:
    if _THREADS_INVALID:
        app.logger.warning(
            "NAIVEPANEL_THREADS=%r is not a number — using %d",
            _THREADS_RAW, WAITRESS_THREADS,
        )
    try:
        from waitress import serve as waitress_serve  # type: ignore
    except ImportError:
        app.logger.warning(
            "waitress not installed — falling back to Werkzeug dev server; "
            "install python3-waitress (opkg) or `pip install waitress`"
        )
        application.run(host=host, port=port, debug=False, threaded=True)
        return
    app.logger.info("serving via waitress on %s:%s (threads=%s)", host, port, WAITRESS_THREADS)
    waitress_serve(application, host=host, port=port, threads=WAITRESS_THREADS)


if __name__ == "__main__":
    _ensure_dirs()
    host, port = _parse_bind(PANEL_BIND)
    # host берётся из env/panel.conf: предупреждаем только для unspecified
    # адресов (0.0.0.0 / ::) — фактического bind здесь нет.
    try:
        exposed = ipaddress.ip_address(host).is_unspecified
    except ValueError:
        exposed = False
    if exposed:
        app.logger.warning(
            "bind %s exposes the panel on ALL interfaces (on a router incl. "
            "WAN/VPN/guest segments). Prefer a LAN address; ensure admin.pass, "
            "NAIVEPANEL_HOSTS and firewall rules are in place.",
            PANEL_BIND,
        )
    # threaded: поллинг UI каждые 3с не должен стоять за медленным запросом
    # (bcrypt, рестарт сервиса до 30с)
    _serve(app, host, port)
