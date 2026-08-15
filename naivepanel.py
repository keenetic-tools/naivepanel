#!/usr/bin/env python3
"""NaivePanel — локальная веб-панель управления клиентом NaiveProxy на Keenetic/Entware.

Хранит пресеты конфигураций в /opt/etc/naiveproxy/conf.d/<name>.json,
при activate копирует один из них в /opt/etc/naiveproxy/config.json
(chmod 0600) и перезапускает init-скрипт S99naiveproxy.

Bind по умолчанию 127.0.0.1:8089 — публикация через внешний reverse proxy
или напрямую в LAN (admin.pass + NAIVEPANEL_HOSTS + firewall, см. README).
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import time
from pathlib import Path
from typing import Any

from flask import Flask, Response, abort, jsonify, make_response, render_template, request

# --- Конфигурация путей (на Keenetic/Entware) -----------------------------

NAIVEPROXY_DIR = Path(os.environ.get("NAIVEPROXY_DIR", "/opt/etc/naiveproxy"))
CONF_D = NAIVEPROXY_DIR / "conf.d"
ACTIVE_CONFIG = NAIVEPROXY_DIR / "config.json"
ACTIVE_POINTER = NAIVEPROXY_DIR / ".active"  # имя текущего активного пресета
INIT_SCRIPT = Path(os.environ.get("NAIVEPROXY_INIT", "/opt/etc/init.d/S99naiveproxy"))
LOG_FILE = Path(os.environ.get("NAIVEPROXY_LOG", "/opt/var/log/naiveproxy.log"))
PID_FILE = Path(os.environ.get("NAIVEPROXY_PID", "/opt/var/run/naiveproxy.pid"))
PANEL_ADMIN_PASS = Path(os.environ.get("NAIVEPANEL_PASS", "/opt/etc/naivepanel/admin.pass"))
PANEL_BIND = os.environ.get("NAIVEPANEL_BIND", "127.0.0.1:8089")
# Allowlist Host-заголовков (через запятую, с портом). Пусто — проверка выкл.
ALLOWED_HOSTS = {h.strip() for h in os.environ.get("NAIVEPANEL_HOSTS", "").split(",") if h.strip()}
# Init-скрипт самой панели — для self-restart после обновления файлов.
PANEL_INIT = Path(os.environ.get("NAIVEPANEL_INIT", "/opt/etc/init.d/S99naivepanel"))

NAME_RE = re.compile(r"^[a-zA-Z0-9_\-.]{1,64}$")


def _ensure_dirs() -> None:
    CONF_D.mkdir(parents=True, exist_ok=True)


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
        user = creds.split(":", 1)[0]
    return {
        "listen": listen_uri,
        "listen_count": listen_count,
        "proxy": proxy_uri,
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


def _build_payload(data: dict[str, Any]) -> dict[str, Any]:
    """Собирает JSON-конфиг клиента naive из данных формы.

    listen принимает строку (несколько адресов через запятую/перенос) или массив;
    при одном адресе → строка, при нескольких → массив. Пример массива:
      `{"listen": ["socks://127.0.0.1:1080","http://127.0.0.1:8080"], ...}`

    upstream поддерживает два формата:
      - `https://user:pass@host[:port]` — полный proxy URL, передаётся как есть
      - `host[:port]` или `https://host[:port]` — креденшалы подставляются из
        полей username/password
    """
    name = (data.get("name") or "").strip()
    upstream = (data.get("upstream") or "").strip()
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    # listen — строка с разделителями (запятая/перенос), либо массив
    listen_raw = data.get("listen") or []
    if isinstance(listen_raw, str):
        parts = [s for s in (p.strip() for p in re.split(r"[\n,]+", listen_raw)) if s]
    elif isinstance(listen_raw, list):
        parts = [s.strip() for s in listen_raw if isinstance(s, str) and s.strip()]
    else:
        parts = []
    listen_uris = [u for u in (_normalize_listen(p) for p in parts) if u]

    if not (name and listen_uris and upstream and username and password):
        abort(400, description="name, listen, upstream, username, password are required")

    # Один адрес → строка (компактнее), несколько → массив
    listen = listen_uris[0] if len(listen_uris) == 1 else listen_uris

    if "@" in upstream:
        # Уже полный proxy URL с креденшалами
        proxy_uri = upstream
    else:
        # Вытаскиваем хост из возможного `https://` префикса
        host = upstream
        if host.startswith(("https://", "http://", "quic://")):
            host = host.split("://", 1)[1]
        proxy_uri = f"https://{username}:{password}@{host.rstrip('/')}"

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


# --- Service control ------------------------------------------------------

def _run(cmd: list[str], timeout: int = 10) -> dict[str, Any]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
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
    return _run(["/bin/sh", str(INIT_SCRIPT), action])


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
            if running:
                uptime = max(0, int(time.time() - PID_FILE.stat().st_mtime))
    return {
        "active": running,
        "pid": pid,
        "uptime": uptime,
        "current": active_name,
        "init_script": str(INIT_SCRIPT),
        "init_present": has_init,
    }


def _tail_log(lines: int = 100) -> str:
    if not LOG_FILE.exists():
        return ""
    lines = max(1, min(lines, 1000))
    try:
        with LOG_FILE.open("r", encoding="utf-8", errors="replace") as fh:
            data = fh.readlines()
    except OSError as exc:
        return f"<log read error: {exc}>"
    return "".join(data[-lines:])


# --- Flask app ------------------------------------------------------------

app = Flask(__name__)


# --- Host allowlist (анти-DNS-rebinding) -----------------------------------

@app.before_request
def _enforce_host_allowlist():
    """Если NAIVEPANEL_HOSTS задан — отклоняет запросы с чужим Host.

    При bind на LAN-адрес страница зловредного сайта может через DNS rebinding
    резолвиться в IP роутера: браузер считает запросы same-origin и читает API.
    Такие запросы приходят с Host вида `evil.com:8089` — отклоняем их.
    Значения — точные строки Host с портом: `192.168.1.1:8089,router.lan:8089`.
    """
    if not ALLOWED_HOSTS or request.host in ALLOWED_HOSTS:
        return
    app.logger.warning("rejected Host %r from %s", request.host, request.remote_addr)
    abort(403, description="host not allowed")


# --- HTTP Basic auth (опционально) ----------------------------------------

@app.before_request
def _require_auth():
    """Если /opt/etc/naivepanel/admin.pass существует — требует HTTP Basic auth
    на каждый запрос. Формат файла — стандартный htpasswd: `user:bcrypt-hash`
    на строку. Создание: `htpasswd -B -c admin.pass user` (или python3-bcrypt —
    в Entware htpasswd отсутствует, см. README).

    Без пакета python3-bcrypt auth fail-closed (401 на любой запрос), в лог
    пишется ошибка. Это намеренно: лучше сломанная панель, чем открытая.
    """
    if not PANEL_ADMIN_PASS.exists():
        return  # auth выключен — только 127.0.0.1, публично не торчим
    stored = PANEL_ADMIN_PASS.read_text(encoding="utf-8")
    auth = request.authorization
    if auth and _htpasswd_verify(stored, auth.username or "", auth.password or ""):
        return
    app.logger.warning(
        "auth failed: user=%r addr=%s path=%s",
        auth.username if auth else None,
        request.remote_addr,
        request.path,
    )
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
        if bcrypt.checkpw(password.encode(), h.encode()):
            return True
        return False  # пользователь найден, пароль не совпал
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
    return jsonify(_list_presets())


@app.route("/api/configs/<name>", methods=["GET"])
def api_configs_get(name: str):
    if not NAME_RE.match(name):
        abort(400, description="invalid name")
    return jsonify(_load_json(CONF_D / f"{name}.json"))


@app.route("/api/configs", methods=["POST"])
def api_configs_create():
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    if not NAME_RE.match(name):
        abort(400, description="invalid name")
    cfg = _build_payload(data)
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
    cfg = _build_payload(data)
    path = CONF_D / f"{name}.json"
    if not path.exists():
        abort(404, description=f"preset {name!r} not found")
    _save_json(path, cfg)
    if _active_name() == name:
        _write_active(name, cfg)
    return jsonify({"name": name, "updated": True})


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
    _write_active(name, cfg)
    restart = _service("restart") if INIT_SCRIPT.exists() else {"rc": None, "note": "no init script"}
    return jsonify({"name": name, "active": True, "restart": restart})


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
    # Новая сессия → ребёнок переживёт смерть Flask-процесса.
    subprocess.Popen(
        ["sh", "-c", f"sleep 1; exec /bin/sh '{PANEL_INIT}' restart"],
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
    return jsonify({"lines": lines, "content": _tail_log(lines)})


# --- Main -----------------------------------------------------------------

if __name__ == "__main__":
    _ensure_dirs()
    host, _, port = PANEL_BIND.rpartition(":")
    host = host or "127.0.0.1"
    if host in ("0.0.0.0", "::"):
        app.logger.warning(
            "bind %s exposes the panel on ALL interfaces (on a router incl. "
            "WAN/VPN/guest segments). Prefer a LAN address; ensure admin.pass, "
            "NAIVEPANEL_HOSTS and firewall rules are in place.",
            PANEL_BIND,
        )
    app.run(host=host, port=int(port or 8089), debug=False)
