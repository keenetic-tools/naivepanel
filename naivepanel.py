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
import platform
import re
import queue
import secrets
import shutil
import socket
import ssl  # E2E-проверка: TLS через туннель прокси, только системные CA
# subprocess вызывается только с фиксированными argv-списками (shell=False)
import subprocess  # nosec B404
import threading
import time
from pathlib import Path
from typing import Any
from urllib.parse import quote, unquote, urlsplit

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
    "NAIVEPROXY_BIN", "NAIVEPROXY_SRC_REPO", "NAIVEPROXY_SRC_API",
    "NAIVEPROXY_UPDATE_LOG",
    "NAIVEPANEL_INIT", "NAIVEPANEL_THREADS",
    "NAIVEPANEL_LOG", "NAIVEPANEL_LOG_MAX", "NAIVEPANEL_LOG_KEEP",
    "NAIVEPANEL_WATCHDOG", "NAIVEPANEL_WATCHDOG_INTERVAL",
    "NAIVEPANEL_E2E_URL",
    "NAIVEPANEL_FAILOVER", "NAIVEPANEL_FAILOVER_INTERVAL",
    "NAIVEPANEL_FAILOVER_THRESHOLD", "NAIVEPANEL_FAILOVER_FAST",
    "NAIVEPANEL_FAILOVER_RETURN_ALIVE", "NAIVEPANEL_FAILOVER_RETURN_COOLDOWN",
    "NAIVEPANEL_E2E_HISTORY", "NAIVEPANEL_E2E_KEEP",
    "NAIVEPANEL_TG_TOKEN", "NAIVEPANEL_TG_CHAT", "NAIVEPANEL_NOTIFY_URL",
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
# Маркер «остановлен руками» — пишет init-скрипт S99naiveproxy в stop(),
# снимает в start(). Watchdog не поднимает прокси, пока маркер на месте:
# иначе он бы конфликтовал с сознательным stop (в т.ч. через SSH).
STOP_MARKER = NAIVEPROXY_DIR / ".stopped"

# --- Бинарник naive: источник и маркеры --------------------------------------
# Первичную установку делает install.sh (когда бинарника нет); панель лишь
# проверяет/обновляет его с релизов klzgrad/naiveproxy. Тег последней
# установки и openwrt-таргет хранятся маркерами рядом с конфигами — их пишут
# и установщик, и панель, поэтому available считается по точному тегу
# (вывод `naive --version` теряет суффикс пересборки -N).

NAIVE_BIN = Path(os.environ.get("NAIVEPROXY_BIN", "/opt/bin/naive"))
NAIVE_BUILD = NAIVEPROXY_DIR / "naive-build"    # напр. aarch64_cortex-a53-static
NAIVE_TAG = NAIVEPROXY_DIR / "naive-version"    # напр. v154.0.8037.49-2
NAIVE_SRC_REPO = os.environ.get("NAIVEPROXY_SRC_REPO", "klzgrad/naiveproxy")
NAIVE_SRC_API = os.environ.get("NAIVEPROXY_SRC_API", "https://api.github.com").rstrip("/")
NAIVE_UPDATE_LOG = Path(os.environ.get("NAIVEPROXY_UPDATE_LOG",
                                       "/opt/var/log/naivepanel-naive.log"))
NAIVE_UPDATE_STATE = NAIVEPROXY_DIR / "naive-update.state"
_NAIVE_CHECK_TTL = 6 * 3600.0    # как у панели: авто-check не должен расходовать
_NAIVE_ERR_TTL = 10 * 60.0       # лимит GitHub API; недоступный GitHub не долбим
_NAIVE_STALE_S = 15 * 60         # чаще раза в 10 минут (запись без прогресса)

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

# --- Периодическая обрезка логов -------------------------------------------
# Логи аппендятся без ограничений всё время, пока сервисы работают;
# init-скрипты обрезают их только при старте (см. инцидент с разросшимся
# /opt/var/log/naiveproxy.log на полный раздел entware). Панель и так
# крутится 24/7 — фоновый поток раз в час проверяет известные логи и у
# больших оставляет только хвост. NAIVEPANEL_LOG_MAX=0 отключает обрезку.
PANEL_LOG = Path(os.environ.get("NAIVEPANEL_LOG", "/opt/var/log/naivepanel.log"))
LOG_TRIM_INTERVAL = 3600.0
_LOG_MAX_RAW = os.environ.get("NAIVEPANEL_LOG_MAX", "5242880") or "5242880"
_LOG_KEEP_RAW = os.environ.get("NAIVEPANEL_LOG_KEEP", "524288") or "524288"


def _int_or_default(raw: str, default: int) -> tuple[int, bool]:
    try:
        return max(0, int(raw)), False
    except (TypeError, ValueError):
        return default, True


# 5 МБ — тот же порог, что у truncate_log в init-скриптах; хвост 512 КБ
LOG_TRIM_MAX, _LOG_MAX_INVALID = _int_or_default(_LOG_MAX_RAW, 5242880)
LOG_TRIM_KEEP, _LOG_KEEP_INVALID = _int_or_default(_LOG_KEEP_RAW, 524288)

# --- Watchdog: авто-рестарт упавшего naive ----------------------------------
# Поток в панели следит за переходом running→down: единственное событие, где
# рестарт однозначно нужен (после рестарта панели «изначально лежит» —
# не трогаем: неизвестно, остановили ли руками до нас). Штатный stop виден
# по маркеру STOP_MARKER (его пишет init-скрипт). Падающего в loop процесса
# не дёргаем бесконечно: после 3 рестартов за 10 минут watchdog отключается
# до перезапуска панели. NAIVEPANEL_WATCHDOG=0 в panel.conf выключает поток.
_WATCHDOG_RAW = os.environ.get("NAIVEPANEL_WATCHDOG", "1") or "1"
WATCHDOG_ENABLED = _WATCHDOG_RAW.strip().lower() not in {"0", "no", "off", "false"}
_WATCHDOG_INTERVAL_RAW = os.environ.get("NAIVEPANEL_WATCHDOG_INTERVAL", "15") or "15"
WATCHDOG_INTERVAL, _WATCHDOG_INTERVAL_INVALID = _int_or_default(_WATCHDOG_INTERVAL_RAW, 15)
WATCHDOG_INTERVAL = max(5, WATCHDOG_INTERVAL)
WATCHDOG_FLAP_MAX = 3          # рестартов за окно до отключения
WATCHDOG_FLAP_WINDOW = 600.0   # окно флаппинга, секунды
WATCHDOG_RECHECK_S = 3.0       # пауза до перепроверки up→down (гонка с stop/restart)

# --- E2E-проверка «прокси реально проксирует» --------------------------------
# В отличие от /api/probe (голый TCP до upstream), здесь запрос идёт ЧЕРЕЗ
# listen-порт naive как через настоящий прокси: CONNECT/SOCKS-туннель до
# echo-хоста + HTTPS GET. Проверяет всю цепочку: listen-сокет, креды к
# upstream, форвардинг, remote-DNS. Ответ показывает exit-IP. Хост можно
# поменять на свой (http:// тоже поддержан — для тестов без TLS).
E2E_URL = os.environ.get("NAIVEPANEL_E2E_URL", "https://api.ipify.org/")
E2E_TIMEOUT = 10.0

# --- История E2E-проверок ----------------------------------------------------
# Монитор (см. фейловер ниже) проверяет активный пресет не только ради
# переключений: каждая проверка пишется в кольцевой буфер JSONL и переживает
# рестарт панели. UI рисует из него спарклайн в статус-карте — момент сбоя
# и восстановления виден без чтения логов. По умолчанию храним сутки
# проверок при 30-секундном интервале (2880 записей ≈ 90 КБ).
E2E_HISTORY = Path(os.environ.get("NAIVEPANEL_E2E_HISTORY",
                                  str(NAIVEPROXY_DIR / "e2e-history.jsonl")))
_E2E_KEEP_RAW = os.environ.get("NAIVEPANEL_E2E_KEEP", "2880") or "2880"
E2E_KEEP, _E2E_KEEP_INVALID = _int_or_default(_E2E_KEEP_RAW, 2880)
E2E_KEEP = max(60, E2E_KEEP)
_E2E_TRIM_EVERY = 100  # аппендов между обрезками буфера до E2E_KEEP

# --- Автофейловер пресетов ---------------------------------------------------
# Цепочка «основной → запасной» в /opt/etc/naive/proxy/failover.json: фоновый
# поток раз в NAIVEPANEL_FAILOVER_INTERVAL секунд делает E2E-проверку активного
# пресета; NAIVEPANEL_FAILOVER_THRESHOLD неудач подряд (гистерезис против
# флаппинга) — переключение на следующий пресет цепочки тем же кодом, что и
# ручной activate. Работает только пока активен пресет из цепочки; назад, на
# основной, панель не возвращается сама — только вперёд (возврат ручной).
# Штатный stop (маркер) и активный-вне-цепочки монитор не трогают.
FAILOVER_CONF = NAIVEPROXY_DIR / "failover.json"
_FAILOVER_RAW = os.environ.get("NAIVEPANEL_FAILOVER", "1") or "1"
FAILOVER_ENABLED = _FAILOVER_RAW.strip().lower() not in {"0", "no", "off", "false"}
_FAILOVER_INTERVAL_RAW = os.environ.get("NAIVEPANEL_FAILOVER_INTERVAL", "30") or "30"
FAILOVER_INTERVAL, _FAILOVER_INTERVAL_INVALID = _int_or_default(_FAILOVER_INTERVAL_RAW, 30)
FAILOVER_INTERVAL = max(10, FAILOVER_INTERVAL)  # чаще 10с в спокойном режиме не нужно
# Двухскоростной монитор: пока прокси здоров, редкие проверки (30с); после
# первой неудачи — частые (5с), пока порог не добьётся или прокси не
# оживёт. Переключение за ~20–40с вместо минут, фоновая нагрузка та же.
_FAILOVER_FAST_RAW = os.environ.get("NAIVEPANEL_FAILOVER_FAST", "5") or "5"
FAILOVER_FAST, _FAILOVER_FAST_INVALID = _int_or_default(_FAILOVER_FAST_RAW, 5)
FAILOVER_FAST = max(2, min(FAILOVER_FAST, FAILOVER_INTERVAL))
_FAILOVER_THRESHOLD_RAW = os.environ.get("NAIVEPANEL_FAILOVER_THRESHOLD", "3") or "3"
FAILOVER_THRESHOLD, _FAILOVER_THRESHOLD_INVALID = _int_or_default(_FAILOVER_THRESHOLD_RAW, 3)
FAILOVER_THRESHOLD = min(10, max(1, FAILOVER_THRESHOLD))
FAILOVER_CHAIN_MAX = 8
# Авто-возврат на основной: N TCP-живых подряд у кандидата (раньше текущего
# в цепочке) → проба живым naive → E2E → активация. Неудачная проба кладёт
# кандидата в cooldown, чтобы не долбить больной upstream каждые полминуты.
_FAILOVER_RETURN_ALIVE_RAW = os.environ.get("NAIVEPANEL_FAILOVER_RETURN_ALIVE", "3") or "3"
FAILOVER_RETURN_ALIVE, _FAILOVER_RETURN_ALIVE_INVALID = _int_or_default(_FAILOVER_RETURN_ALIVE_RAW, 3)
FAILOVER_RETURN_ALIVE = max(1, FAILOVER_RETURN_ALIVE)
_FAILOVER_RETURN_COOLDOWN_RAW = os.environ.get("NAIVEPANEL_FAILOVER_RETURN_COOLDOWN", "900") or "900"
FAILOVER_RETURN_COOLDOWN, _FAILOVER_RETURN_COOLDOWN_INVALID = _int_or_default(_FAILOVER_RETURN_COOLDOWN_RAW, 900)
FAILOVER_RETURN_COOLDOWN = max(60, FAILOVER_RETURN_COOLDOWN)

# --- Уведомления (Telegram / webhook) ----------------------------------------
# События монитора (переключение/возврат/рестарт watchdog'ом/исчерпание)
# уходят ещё и в мессенджер: панель справилась сама — и доложила. Секреты
# живут ТОЛЬКО в panel.conf/env, в API и UI — лишь статус канала.
# Отправка напрямую с роутера (свой WAN): лежащий прокси не мешает.
TG_TOKEN = os.environ.get("NAIVEPANEL_TG_TOKEN", "")
TG_CHAT = os.environ.get("NAIVEPANEL_TG_CHAT", "")
NOTIFY_URL = os.environ.get("NAIVEPANEL_NOTIFY_URL", "")
NOTIFY_CHANNEL = ("telegram" if TG_TOKEN and TG_CHAT
                  else "webhook" if NOTIFY_URL else None)

# --- Self-update: репозиторий и пути ---------------------------------------
# Обновление из UI повторяет ручной флоу `install.sh --yes`: панель лишь
# узнаёт последний тег и отсоединённо spawn'ит установщик (см. /api/update/*).
# Базовые URL и репозиторий переопределяются env'ом — для зеркал и тестов.
UPDATE_REPO = os.environ.get("NAIVEPANEL_REPO", "keenetic-tools/naivepanel")
UPDATE_API_BASE = os.environ.get("NAIVEPANEL_UPDATE_API", "https://api.github.com").rstrip("/")
UPDATE_RAW_BASE = os.environ.get("NAIVEPANEL_UPDATE_RAW", "https://raw.githubusercontent.com").rstrip("/")
# Каталог самой панели (naivepanel.py + templates/): бэкапы и state обновления
PANEL_DIR = Path(os.environ.get("NAIVEPANEL_DIR", "/opt/etc/naive/panel"))
UPDATE_LOG = Path(os.environ.get("NAIVEPANEL_UPDATE_LOG", "/opt/var/log/naivepanel-update.log"))
UPDATE_STATE = PANEL_DIR / "update.state"
# Источник обновления — только строгие vX.Y.Z: ни веток, ни хэшей, ни main
_TAG_RE = re.compile(r"^v\d+\.\d+\.\d+$")
_UPDATE_CHECK_TTL = 6 * 3600.0  # авто-check при загрузке страницы не должен
_UPDATE_ERR_TTL = 10 * 60.0     # расходовать лимит GitHub API; недоступный
_UPDATE_STALE_S = 15 * 60       # GitHub не долбим чаще раза в 10 минут

NAME_RE = re.compile(r"^[a-zA-Z0-9_\-.]{1,64}$")
# Разрешённые схемы proxy-URI: только реально поддерживаемые naive.
_ALLOWED_PROXY_SCHEMES = ("https://", "http://", "quic://")
# Имена, занятые статическими маршрутами /api/configs/export|import:
# такой пресет нельзя было бы получить через GET (роутинг отдаёт файл)
RESERVED_NAMES = frozenset({"export", "import"})

APP_VERSION = "0.13.0"


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


# --- E2E-проверка: реальный запрос ЧЕРЕЗ прокси -----------------------------
# /api/probe отвечает «до upstream есть TCP» — но не «прокси проксирует».
# Здесь открываем listen-порт активного пресета как клиент и строим туннель
# до echo-хоста (E2E_URL): HTTP CONNECT для http-listen, SOCKS5 — для socks.
# Поднявшийся туннель доказывает всю цепочку: listen жив, креды upstream
# приняты, форвардинг работает, DNS резолвится на стороне прокси. Поверх
# туннеля — GET за exit-IP (при недоступности echo-хоста туннель всё равно
# считаем успехом: прокси свою часть выполнил).


def _listen_endpoint(listen: str) -> tuple[str, str, int] | None:
    """listen-URI пресета → (схема, host, port).

    `socks://127.0.0.1:1080` → ("socks", …); `http://127.0.0.1:8080` →
    ("http", …). Без схемы — socks (то же умолчание, что в _normalize_listen).
    Порт по умолчанию: 1080 для socks, 8080 для http.
    """
    raw = (listen or "").strip()
    scheme = "socks"
    if "://" in raw:
        prefix, _, raw = raw.partition("://")
        if prefix.lower() in ("socks", "socks5"):
            scheme = "socks"
        elif prefix.lower() == "http":
            scheme = "http"
        else:
            return None
    ep = _upstream_endpoint(raw or " ")
    if not ep:
        return None
    host, port = ep
    if not re.search(r":\d+$", raw):  # порт не указан — умолчания listen
        port = 1080 if scheme == "socks" else 8080
    return scheme, host, port


def _tcp_probe(host: str, port: int, timeout: float = 3.0) -> int | None:
    """Голый TCP-коннект до host:port; None = недоступен. Время в мс.

    Дешёвая разведка для ручного «пинга» и авто-возврата: без TLS и кредов.
    """
    t0 = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            pass
        return round((time.monotonic() - t0) * 1000)
    except OSError:
        return None


def _free_port() -> int:
    """Свободный localhost-порт (bind(0)); гонка с системой пренебрежима."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _probe_preset(cfg: dict[str, Any], timeout: float = 15.0) -> dict[str, Any]:
    """Полный E2E пресета-кандидата БЕЗ его активации.

    Поднимаем второй naive прямо из CLI — `--listen socks://127.0.0.1:<порт>
    --proxy <URI>`, без временных файлов — и гоняем обычную E2E-проверку
    через этот порт. Так авто-возврат и каскад переключают на проверенно
    живой пресет, а не на «первый существующий». Креды живут в argv пробного
    процесса ~15 секунд (однопользовательский роутер — приемлемо); команду
    в лог не пишем. Схема listen пробы — всегда socks (проверяем upstream).
    """
    if not NAIVE_BIN.exists():
        return {"ok": False, "error": f"бинарник не найден: {NAIVE_BIN}"}
    proxy_uri = cfg.get("proxy")
    if not isinstance(proxy_uri, str) or not proxy_uri.strip():
        return {"ok": False, "error": "у пресета нет proxy"}
    port = _free_port()
    # argv-список, shell не используется; команду не логируем (креды)
    proc = subprocess.Popen(  # nosec B603
        [str(NAIVE_BIN), f"--listen=socks://127.0.0.1:{port}",
         f"--proxy={proxy_uri}"],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline:
            if _tcp_probe("127.0.0.1", port, timeout=0.5) is not None:
                result = _proxy_e2e_check(f"socks://127.0.0.1:{port}",
                                          timeout=timeout)
                result["probe"] = True
                return result
            if proc.poll() is not None:
                return {"ok": False, "probe": True,
                        "error": "пробный naive упал при старте (проверьте proxy-URI)"}
            time.sleep(0.2)
        return {"ok": False, "probe": True,
                "error": "пробный naive не начал слушать за 3с"}
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


def _recv_until(sock: socket.socket, marker: bytes, limit: int = 8192) -> bytes:
    """Читает из сокета до marker (включительно) или лимита буфера."""
    buf = b""
    while marker not in buf and len(buf) < limit:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
    return buf


def _recv_exact(sock: socket.socket, count: int) -> bytes:
    """Ровно count байт; короткое чтение — что успели."""
    buf = b""
    while len(buf) < count:
        chunk = sock.recv(count - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


def _http_connect_via_proxy(sock: socket.socket, host: str, port: int,
                            timeout: float) -> str | None:
    """HTTP-прокси: CONNECT host:port; None = туннель поднят."""
    sock.settimeout(timeout)
    sock.sendall((f"CONNECT {host}:{port} HTTP/1.1\r\n"
                  f"Host: {host}:{port}\r\n"
                  "User-Agent: naivepanel-e2e\r\n\r\n").encode())
    head = _recv_until(sock, b"\r\n\r\n")
    if b"\r\n\r\n" not in head:
        return "прокси не ответил на CONNECT"
    status = head.split(b"\r\n", 1)[0]
    try:
        code = int(status.split()[1])
    except (IndexError, ValueError):
        return f"нечитаемый ответ на CONNECT: {status[:60]!r}"
    if code != 200:
        # 407/502 — например, upstream отверг креды из активного пресета
        return f"CONNECT отклонён прокси: HTTP {code}"
    return None


def _socks5_connect_via_proxy(sock: socket.socket, host: str, port: int,
                              timeout: float) -> str | None:
    """SOCKS5-прокси: greeting + CONNECT (без auth); None = туннель поднят."""
    sock.settimeout(timeout)
    sock.sendall(b"\x05\x01\x00")  # VER5, 1 метод, NO-AUTH
    hello = _recv_exact(sock, 2)
    if len(hello) < 2:
        return "прокси оборвал SOCKS-приветствие"
    if hello[0] != 5:
        return "listen-порт отвечает не по SOCKS5"
    if hello[1] != 0x00:
        return "SOCKS-прокси требует аутентификацию (проверка её не поддерживает)"
    # CONNECT с именем хоста (ATYP=домен): DNS резолвится на стороне прокси
    sock.sendall(b"\x05\x01\x00\x03" + bytes([len(host)]) + host.encode()
                 + port.to_bytes(2, "big"))
    head = _recv_exact(sock, 4)
    if len(head) < 4 or head[0] != 5:
        return "прокси оборвал/испортил SOCKS-ответ"
    if head[1] != 0:
        return f"SOCKS CONNECT отклонён прокси (rep={head[1]})"
    # остаток ответа (BND.ADDR/BND.PORT) вычитываем целиком — иначе он
    # попадёт в начало HTTP-ответа echo-сервера
    atyp = head[3]
    if atyp == 1:
        rest = _recv_exact(sock, 4 + 2)
    elif atyp == 3:
        ln = _recv_exact(sock, 1)
        if not ln:
            return "прокси оборвал SOCKS-ответ (ATYP=домен)"
        rest = _recv_exact(sock, ln[0] + 2)
    elif atyp == 4:
        rest = _recv_exact(sock, 16 + 2)
    else:
        return f"SOCKS-ответ с неизвестным ATYP={atyp}"
    if not rest:
        return "прокси оборвал SOCKS-ответ"
    return None


def _get_via_tunnel(sock: socket.socket, host: str, path: str,
                    use_tls: bool, timeout: float) -> tuple[str | None, str | None]:
    """GET через установленный туннель; (body, error) — ровно один не None.

    HTTP/1.0 + Connection: close: ответ без chunked, читаем до EOF.
    """
    if use_tls:
        try:
            sock = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
        except (ssl.SSLError, OSError) as exc:
            return None, f"TLS через туннель не поднялся: {exc}"
    sock.settimeout(timeout)
    sock.sendall((f"GET {path} HTTP/1.0\r\n"
                  f"Host: {host}\r\n"
                  "User-Agent: naivepanel-e2e\r\nAccept: */*\r\n"
                  "Connection: close\r\n\r\n").encode())
    buf = b""
    while len(buf) < 16384:
        try:
            chunk = sock.recv(4096)
        except (ssl.SSLEOFError, ssl.SSLError, OSError):
            break
        if not chunk:
            break
        buf += chunk
    head, sep, body = buf.partition(b"\r\n\r\n")
    if not sep:
        return None, "echo-сервер не вернул HTTP-ответ"
    code = head.split(b"\r\n", 1)[0].split()
    if len(code) < 2 or code[1] != b"200":
        got = code[1].decode("latin-1", "replace") if len(code) >= 2 else "?"
        return None, f"echo-сервер ответил HTTP {got}"
    # пустое тело — валидный ответ: прокси работает, exit-IP просто не распознан
    return body.decode("utf-8", "replace").strip(), None


_IPV4_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_IPV6_RE = re.compile(r"(?<![0-9a-fA-F:.])(?:[0-9a-fA-F]{0,4}:){3,7}[0-9a-fA-F]{0,4}(?![0-9a-fA-F:.])")


def _extract_exit_ip(text: str) -> str | None:
    """IPv4/IPv6 из ответа echo-сервера (plain или JSON)."""
    m = _IPV4_RE.search(text)
    if m:
        return m.group(1)
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        data = None
    if isinstance(data, dict) and isinstance(data.get("ip"), str):
        return data["ip"]
    m6 = _IPV6_RE.search(text)
    return m6.group(0) if m6 else None


def _proxy_e2e_check(listen_uri: str, timeout: float = E2E_TIMEOUT) -> dict[str, Any]:
    """Прогоняет один реальный запрос через listen naive (см. E2E_URL).

    ok=True — только полный ответ echo-хоста через туннель (exit_ip может
    быть None с note, если ответ не распознан). Подтверждённый, но
    «мёртвый» туннель (ACK, затем обрыв — так ведёт себя naive при лежащем
    upstream) — это ok:False с причиной.
    """
    t0 = time.monotonic()

    def _ms() -> int:
        return int((time.monotonic() - t0) * 1000)

    ep = _listen_endpoint(listen_uri)
    if not ep:
        return {"ok": False, "ms": _ms(), "error": f"listen не распознан: {listen_uri!r}"}
    scheme, lhost, lport = ep

    parts = urlsplit(E2E_URL)
    echo_host = parts.hostname
    if not echo_host:
        return {"ok": False, "ms": _ms(), "error": f"NAIVEPANEL_E2E_URL некорректен: {E2E_URL!r}"}
    echo_port = parts.port or (443 if parts.scheme == "https" else 80)
    echo_path = parts.path or "/"
    use_tls = parts.scheme == "https"

    sock: socket.socket | None = None
    try:
        sock = socket.create_connection((lhost, lport), timeout=min(5.0, timeout))
        tunnel = (_http_connect_via_proxy if scheme == "http"
                  else _socks5_connect_via_proxy)
        err = tunnel(sock, echo_host, echo_port, timeout)
        if err:
            return {"ok": False, "ms": _ms(), "error": err}
        body, err = _get_via_tunnel(sock, echo_host, echo_path, use_tls, timeout)
        if err is not None:
            # Туннель мог быть подтверждён формально, а данные не пошли —
            # так ведёт себя naive при лежащем upstream: ACK на CONNECT,
            # затем обрыв (TLS EOF). Это НЕУДАЧА проверки: успех — только
            # полный ответ echo-хоста через туннель. От разовых осечек
            # самого echo-хоста защищает порог фейловера, не «оговорка».
            return {"ok": False, "ms": _ms(), "error": err}
        ip = _extract_exit_ip(body)
        return {"ok": True, "ms": _ms(), "exit_ip": ip,
                "note": None if ip else "ответ echo-сервера получен, exit-IP не распознан"}
    except ConnectionRefusedError:
        return {"ok": False, "ms": _ms(),
                "error": f"{lhost}:{lport} не принимает соединения — прокси остановлен?"}
    except (socket.timeout, ssl.SSLError, OSError) as exc:
        return {"ok": False, "ms": _ms(), "error": f"{type(exc).__name__}: {exc}"}
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def _active_listen() -> str | None:
    """listen активного пресета из config.json (первый адрес, если массив)."""
    try:
        cfg = json.loads(ACTIVE_CONFIG.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    raw = cfg.get("listen")
    if isinstance(raw, list):
        raw = raw[0] if raw else None
    if isinstance(raw, str) and raw.strip():
        return raw.strip()
    return None


# --- История E2E-проверок: кольцевой буфер -----------------------------------

_e2e_since_trim = 0


def _e2e_history_append(ok: bool, ms: int | None) -> None:
    """Одна запись {t, ok, ms} в JSONL-буфер; периодически обрезаем хвост.

    Файл маленький (десятки КБ), пишет только поток монитора раз в интервал —
    простой append с редкой обрезкой дешевле переписывания всего файла.
    Ошибка записи не должна ронять монитор — предупреждение в лог.
    """
    global _e2e_since_trim
    try:
        E2E_HISTORY.parent.mkdir(parents=True, exist_ok=True)
        with E2E_HISTORY.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({"t": int(time.time()), "ok": bool(ok),
                                 "ms": int(ms or 0)}) + "\n")
        _e2e_since_trim += 1
        if _e2e_since_trim >= _E2E_TRIM_EVERY:
            _e2e_since_trim = 0
            _e2e_history_trim()
    except OSError as exc:
        app.logger.warning("e2e history append failed: %s", exc)


def _e2e_history_trim() -> None:
    """Оставляем последние E2E_KEEP записей (атомарная замена файла)."""
    try:
        lines = _e2e_history_read_all()
    except OSError:
        return
    if len(lines) <= E2E_KEEP:
        return
    tmp = E2E_HISTORY.with_suffix(".jsonl.tmp")
    try:
        with tmp.open("w", encoding="utf-8") as fh:
            # splitlines() срезает \n — восстанавливаем, иначе записи склеятся
            fh.write("\n".join(lines[-E2E_KEEP:]) + "\n")
        tmp.replace(E2E_HISTORY)
    except OSError as exc:
        app.logger.warning("e2e history trim failed: %s", exc)


def _e2e_history_read_all() -> list[str]:
    """Все строки буфера (сырые); отсутствие файла — пустой список."""
    try:
        return E2E_HISTORY.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return []


def _e2e_history_load(last: int) -> list[dict[str, Any]]:
    """Последние `last` записей буфера, старые → новые; битые строки skipped."""
    out: list[dict[str, Any]] = []
    for line in _e2e_history_read_all():
        try:
            entry = json.loads(line)
            if (isinstance(entry, dict) and isinstance(entry.get("t"), int)
                    and isinstance(entry.get("ok"), bool)):
                out.append({"t": entry["t"], "ok": entry["ok"],
                            "ms": int(entry.get("ms") or 0)})
        except (json.JSONDecodeError, ValueError, TypeError):
            continue  # обрыв записи (панель упала посреди append) — пропускаем
    return out[-last:]


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


def _proxy_running() -> tuple[bool, int | None, int | None]:
    """(running, pid, uptime_s) по pid-файлу — для /api/status и watchdog.

    Проверяем, что процесс реально жив — pid-файл может пережить crash.
    """
    pid: int | None = None
    uptime: int | None = None
    running = False
    if PID_FILE.exists():
        try:
            pid = int(PID_FILE.read_text(encoding="utf-8").strip())
        except (ValueError, OSError):
            pid = None
        if pid is not None:
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
    return running, pid, uptime


def _status() -> dict[str, Any]:
    active_name = _active_name()
    has_init = INIT_SCRIPT.exists()
    running, pid, uptime = _proxy_running()
    return {
        "version": APP_VERSION,
        "active": running,
        "pid": pid,
        "uptime": uptime,
        "current": active_name,
        "init_script": str(INIT_SCRIPT),
        "init_present": has_init,
        "watchdog": _watchdog.snapshot(),
        "failover": _failover.snapshot(),
        "notify": {"enabled": NOTIFY_CHANNEL is not None,
                   "channel": NOTIFY_CHANNEL},
    }


# --- Уведомления: очередь + sender-поток --------------------------------------

_notify_queue: "queue.Queue[tuple[str, str]]" = queue.Queue()
_notify_last: dict[str, float] = {}  # event → epoch последней постановки (дедуп)


def _notify(event: str, text: str, dedupe_s: float = 60.0) -> None:
    """Поставить событие в очередь уведомлений; вызывается из потоков монитора.

    Дедуп: одинаковое событие не чаще раза в dedupe_s — каскад из трёх
    переключений не должен заспамить чат. Для «доступно обновление» окно
    больше (6ч), чтобы не напоминать при каждом открытии страницы.
    """
    if NOTIFY_CHANNEL is None:
        return
    now = time.time()
    if now - _notify_last.get(event, 0.0) < dedupe_s:
        return
    _notify_last[event] = now
    _notify_queue.put((event, text))


def _notify_send(event: str, text: str) -> None:
    """Одна отправка: Telegram sendMessage или POST JSON в webhook.

    HTTP — через curl, как все внешние запросы панели (_http_get): curl
    обязателен при установке, а единый путь наружу проще audit'ить.
    """
    if NOTIFY_CHANNEL == "telegram":
        url = f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage"
        body: dict[str, Any] = {"chat_id": TG_CHAT, "text": text,
                                "disable_web_page_preview": True}
    else:
        url, body = NOTIFY_URL, {"event": event, "text": text,
                                 "ts": int(time.time())}
    try:
        # argv-список; команду не логируем (токен Telegram в URL)
        res = _run(["curl", "-fsS", "--max-time", "10",
                    "-H", "Content-Type: application/json",
                    "-d", json.dumps(body), url], timeout=15)
    except HTTPException as exc:  # curl нет / таймаут — монитор не должен страдать
        app.logger.warning("notify %s failed: %s", event, exc.description)
        return
    if res["rc"] != 0:
        app.logger.warning("notify %s failed: rc=%s %s", event, res["rc"],
                           (res["stderr"] or "")[:200])


def _notify_loop() -> None:
    while True:
        event, text = _notify_queue.get()
        _notify_send(event, text)


# --- Watchdog: авто-рестарт упавшего naive ----------------------------------


class _Watchdog:
    """Следит за переходом naive running→down и поднимает его обратно.

    Реагирует ТОЛЬКО на переход вниз, observed при живой панели: после
    старта панели «прокси не работает» — не сигнал (неизвестно, остановили
    ли его руками до нас; автозапуск делает init-скрипт). Штатный stop
    init-скрипт маркирует файлом STOP_MARKER — тогда панель не вмешивается.
    Флаппинг (падает сразу после старта) гасим: WATCHDOG_FLAP_MAX рестартов
    за WATCHDOG_FLAP_WINDOW — и watchdog отключается до рестарта панели.
    """

    def __init__(self, flap_max: int = WATCHDOG_FLAP_MAX,
                 flap_window: float = WATCHDOG_FLAP_WINDOW) -> None:
        self._prev_running: bool | None = None
        self._restarts: list[float] = []
        self._flap_max = flap_max
        self._flap_window = flap_window
        self.tripped = False   # отключился из-за флаппинга
        self.count = 0         # рестартов за жизнь панели

    def snapshot(self) -> dict[str, Any]:
        return {"enabled": WATCHDOG_ENABLED, "restarts": self.count,
                "tripped": self.tripped}

    def _flapped(self, now: float) -> bool:
        self._restarts = [t for t in self._restarts if now - t < self._flap_window]
        return len(self._restarts) >= self._flap_max

    def observe(self, recheck_delay: float = WATCHDOG_RECHECK_S) -> dict[str, Any] | None:
        """Один тик; возвращает событие (см. тесты) или None, если всё тихо."""
        running, _, _ = _proxy_running()
        prev, self._prev_running = self._prev_running, running
        if prev is None or prev == running:
            return None
        if running:  # down→up: поднялся (руками или сам) — просто фиксируем
            return None
        # up→down: crash или чей-то stop/restart. Пауза закрывает гонку с
        # init-скриптом: stop() пишет маркер ДО kill, а restart() между
        # stop и start пару секунд держит сервис вниз — за паузу маркер
        # появится (штатный stop) или сервис вернётся (рестарт).
        if recheck_delay > 0:
            time.sleep(recheck_delay)
            running, _, _ = _proxy_running()
            if running:
                return None
        if STOP_MARKER.exists():
            return {"event": "stopped"}   # штатный stop — не вмешиваемся
        if not INIT_SCRIPT.exists():
            return {"event": "no-init"}
        if self.tripped:
            return {"event": "down-tripped"}
        now = time.time()
        if self._flapped(now):
            self.tripped = True
            return {"event": "tripped"}
        self._restarts.append(now)
        self.count += 1
        res = _service("start")
        return {"event": "restarted", "rc": res.get("rc"),
                "stderr": res.get("stderr")}


_watchdog = _Watchdog()


def _watchdog_loop() -> None:
    # daemon-поток, как log-trim: каждая итерация под try, чтобы неожиданная
    # ошибка не убила цикл целиком
    while True:
        try:
            ev = _watchdog.observe()
            if ev is not None:
                if ev["event"] == "restarted":
                    if ev.get("rc") == 0:
                        app.logger.warning(
                            "watchdog: naive упал — перезапущен (рестартов: %d)",
                            _watchdog.count)
                        _notify("watchdog_restart",
                                f"NaivePanel: naive упал — watchdog перезапустил "
                                f"(рестартов: {_watchdog.count})")
                    else:
                        app.logger.error(
                            "watchdog: naive упал, перезапуск НЕ удался: rc=%s %s",
                            ev.get("rc"), ev.get("stderr") or "")
                        _notify("watchdog_restart_failed",
                                "NaivePanel: naive упал, перезапуск НЕ удался — "
                                "загляните в панель")
                elif ev["event"] == "tripped":
                    app.logger.error(
                        "watchdog: naive падает %d раз за %dс — авто-рестарт "
                        "отключён до перезапуска панели; проверьте лог прокси",
                        WATCHDOG_FLAP_MAX, int(WATCHDOG_FLAP_WINDOW))
                    _notify("watchdog_tripped",
                            f"NaivePanel: naive падает {WATCHDOG_FLAP_MAX} раз за "
                            f"{int(WATCHDOG_FLAP_WINDOW)}с — авто-рестарт отключён, "
                            f"нужно вмешательство")
                elif ev["event"] == "down-tripped":
                    app.logger.error("watchdog: naive снова вниз — стоим (отключён)")
                elif ev["event"] == "stopped":
                    app.logger.info("watchdog: штатный stop (маркер) — не вмешиваюсь")
        except Exception:  # один сбойный тик не должен останавливать поток
            app.logger.warning("watchdog cycle failed", exc_info=True)
        time.sleep(WATCHDOG_INTERVAL)


# --- Автофейловер: монитор цепочки пресетов ----------------------------------


def _load_failover_conf() -> dict[str, Any]:
    """failover.json → конфиг монитора; без файла — всё выключено.

    Битый файл трактуем как «выключен»: монитор не должен падать из-за
    руки, поправившей JSON мимо панели. auto_return — opt-in (v0.14).
    """
    empty = {"enabled": False, "chain": [], "auto_return": False}
    try:
        data = json.loads(FAILOVER_CONF.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return empty
    if not isinstance(data, dict):
        return empty
    chain = data.get("chain")
    if not isinstance(chain, list) or not all(isinstance(n, str) for n in chain):
        chain = []
    auto_return = data.get("auto_return")
    return {"enabled": bool(data.get("enabled")) and bool(chain),
            "chain": chain,
            "auto_return": auto_return is True}


def _preset_cfg(name: str) -> dict[str, Any] | None:
    """Конфиг пресета из conf.d для пробы (без HTTP-исключений)."""
    try:
        data = json.loads((CONF_D / f"{name}.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


class _Failover:
    """Периодическая E2E-проверка активного пресета, переключение по цепочке.

    Только вперёд, на следующий пресет цепочки; назад (на основной) —
    вручную: авто-возврат — источник флаппинга. Гистерезис — THRESHOLD
    неудач подряд: одна осечка (в т.ч. разовый сбой echo-хоста) — не повод
    переключать. Неудача — всё, кроме полного ответа echo-хоста, включая
    «туннель подтверждён, но данные не пошли» (лежащий upstream за живым
    naive; найдено в бою на v0.12.2, фикс в v0.13).
    """

    def __init__(self, threshold: int = FAILOVER_THRESHOLD) -> None:
        self._threshold = threshold
        self._fails = 0
        self._last_check: float | None = None
        self._last_ok: bool | None = None
        self._last_error: str | None = None
        self._last_ms: int | None = None
        self._last_switch: float | None = None
        self.switches = 0
        self.returns = 0          # авто-возвратов на основной
        self.hot = False          # последняя проверка провалена — пробуем часто
        self._exhausted_announced = False
        self.idle_reason: str | None = None
        self._streaks: dict[str, int] = {}    # TCP-живых подряд (авто-возврат)
        self._cooldown: dict[str, float] = {} # кандидат → epoch конца cooldown
        self._return_watch: dict[str, Any] | None = None  # для UI «ждём возврата»

    def snapshot(self) -> dict[str, Any]:
        conf = _load_failover_conf()
        active = _active_name()
        idx = conf["chain"].index(active) if active in conf["chain"] else None
        # Динамические причины паузы перепроверяем: idle_reason — итог
        # ПОСЛЕДНЕГО цикла монитора, и до следующего цикла (до 30с) мог
        # появиться пресет / сняться маркер stop. Показывать устаревшую
        # паузу рядом со свежим active_index — противоречие в статусе.
        idle = self.idle_reason
        if idle == "прокси остановлен вручную" and not STOP_MARKER.exists():
            idle = None
        elif idle == "нет активного пресета с listen" and active and _active_listen():
            idle = None
        return {
            "enabled": FAILOVER_ENABLED and conf["enabled"],
            "chain": conf["chain"],
            "active_index": idx,
            "threshold": self._threshold,
            "interval": FAILOVER_INTERVAL,
            "fast_interval": FAILOVER_FAST,
            "probing_fast": self.hot,
            "fails": self._fails,
            "last_check": self._last_check,
            "last_ok": self._last_ok,
            "last_error": self._last_error,
            "last_ms": self._last_ms,
            "switches": self.switches,
            "returns": self.returns,
            "auto_return": conf["auto_return"],
            "return_watch": self._return_watch,
            "last_switch": self._last_switch,
            "idle": idle,
        }

    def _idle(self, reason: str) -> None:
        self.idle_reason = reason
        self._fails = 0
        self.hot = False

    def cycle(self) -> dict[str, Any] | None:
        """Один тик монитора; возвращает событие для лога или None.

        Монитор всегда проверяет активный пресет и пишет результат в историю
        (спарклайн в UI); фейловер-переключения — только когда цепочка
        настроена и активный пресет в ней. idle_reason выставляется только
        когда проверки НЕ идут (прокси остановлен / нет пресета).
        """
        conf = _load_failover_conf()
        if not FAILOVER_ENABLED:
            self._idle("монитор выключен")
            return None
        if STOP_MARKER.exists():
            self._idle("прокси остановлен вручную")
            return None
        active = _active_name()
        listen = _active_listen() if active else None
        if not listen:
            self._idle("нет активного пресета с listen")
            return None
        self.idle_reason = None

        result = _proxy_e2e_check(listen)
        self._last_check = time.time()
        self._last_ok = bool(result.get("ok"))
        self._last_error = result.get("error") or result.get("note")
        self._last_ms = result.get("ms")
        _e2e_history_append(self._last_ok, self._last_ms)

        # дальше — только логика переключений; история пишется в любом случае
        armed = conf["enabled"] and active in conf["chain"]
        self.hot = armed and not result.get("ok")  # неудача → частые проверки
        if result.get("ok"):
            self._fails = 0
            self._exhausted_announced = False
            idx = conf["chain"].index(active) if armed else None
            if armed and conf["auto_return"] and idx and idx > 0:
                return self._try_return(conf, active, idx)
            return None
        if not armed:
            self._fails = 0  # копить порог без включённого фейловера незачем
            return None
        self._fails += 1
        if self._fails < self._threshold:
            return {"event": "failing", "fails": self._fails}

        self._fails = 0
        return self._switch_forward(conf, active)

    def _candidates_after(self, chain: list[str], idx: int) -> list[str]:
        """Пресеты позже idx в цепочке, существующие в conf.d, по порядку."""
        return [c for c in chain[idx + 1:] if (CONF_D / f"{c}.json").exists()]

    def _switch_forward(self, conf: dict[str, Any], active: str) -> dict[str, Any] | None:
        """Каскад вперёд: единственный кандидат — сразу (скорость важнее,
        E2E проверит следующим тиком); нескольких — пробуем каждого живым
        naive и активируем первого прошедшего («первый живой», не «первый
        существующий»): без рестартов сервиса на мёртвых запасных."""
        chain = conf["chain"]
        idx = chain.index(active)
        rest = self._candidates_after(chain, idx)
        if len(rest) == 1:
            return self._activate_and_count(active, rest[0])
        for candidate in rest:
            cfg = _preset_cfg(candidate)
            if cfg is None:
                continue
            probe = _probe_preset(cfg, timeout=10.0)
            if not probe.get("ok"):
                app.logger.info(
                    "фейловер: кандидат %s не прошёл пробу: %s",
                    candidate, probe.get("error"))
                continue
            return self._activate_and_count(active, candidate)
        if self._exhausted_announced:
            return None  # уже кричали; следующая волна — только после ok
        self._exhausted_announced = True
        return {"event": "exhausted", "active": active}

    def _activate_and_count(self, frm: str, to: str) -> dict[str, Any]:
        try:
            res = _activate_preset(to)
        except HTTPException:
            # битый пресет — валидация отвергла; каскад пойдёт дальше,
            # но для простоты single-кандидат пути считаем исчерпанием
            return {"event": "activate-failed", "to": to}
        self.switches += 1
        self._last_switch = time.time()
        self._streaks.clear()  # активный сменился — копить про прошлого незачем
        return {"event": "switched", "from": frm, "to": to,
                "restart": res.get("restart")}

    def _try_return(self, conf: dict[str, Any], active: str,
                    idx: int) -> dict[str, Any] | None:
        """Авто-возврат: пресеты РАНЬШЕ текущего. TCP-стрик у каждого;
        первый набравший RETURN_ALIVE и не в cooldown — проба живым naive,
        прошёл — активация. Дальше регулярная проверка нового активного
        подтвердит; не пройдёт — фейловер уведёт вперёд как обычно."""
        now = time.time()
        best: tuple[str, int] | None = None
        for candidate in conf["chain"][:idx]:
            cfg = _preset_cfg(candidate)
            ep = _upstream_endpoint(cfg.get("proxy") or "") if cfg else None
            alive = bool(ep and _tcp_probe(ep[0], ep[1], timeout=3.0) is not None)
            self._streaks[candidate] = self._streaks.get(candidate, 0) + 1 if alive else 0
            streak = self._streaks[candidate]
            if streak and (best is None or streak > best[1]):
                best = (candidate, streak)
        self._return_watch = ({"name": best[0], "streak": best[1],
                               "need": FAILOVER_RETURN_ALIVE}
                              if best else None)
        for candidate in conf["chain"][:idx]:
            if self._streaks.get(candidate, 0) < FAILOVER_RETURN_ALIVE:
                continue
            if now < self._cooldown.get(candidate, 0.0):
                continue  # уже обжигались — ждём конца cooldown
            cfg = _preset_cfg(candidate)
            if cfg is None:
                continue
            probe = _probe_preset(cfg, timeout=15.0)
            if probe.get("ok"):
                try:
                    res = _activate_preset(candidate)
                except HTTPException:
                    self._cooldown[candidate] = now + FAILOVER_RETURN_COOLDOWN
                    continue
                self.returns += 1
                self._streaks.clear()
                self._return_watch = None
                return {"event": "returned", "from": active, "to": candidate,
                        "restart": res.get("restart")}
            # TCP жив, а прокси нет (креды/TLS/защита) — кандидату cooldown
            self._cooldown[candidate] = now + FAILOVER_RETURN_COOLDOWN
            self._streaks[candidate] = 0
            return {"event": "return_probe_failed", "candidate": candidate,
                    "error": probe.get("error")}
        return None


_failover = _Failover()


def _failover_loop() -> None:
    # как watchdog: daemon-поток, сбойный тик не убивает цикл. Пустая цепочка
    # — честный idle, поэтому поток стартует всегда: цепочку можно задать из
    # UI без перезапуска панели.
    while True:
        try:
            ev = _failover.cycle()
            if ev is not None:
                if ev["event"] == "switched":
                    rst = ev.get("restart") or {}
                    rc = rst.get("rc") if isinstance(rst, dict) else None
                    if isinstance(rc, int) and rc != 0:
                        app.logger.error(
                            "фейловер: %s не прошёл E2E-проверки — переключение"
                            " на %s, но рестарт НЕ удался: rc=%s %s",
                            ev["from"], ev["to"], rc, rst.get("stderr") or "")
                    else:
                        app.logger.warning(
                            "фейловер: %s не прошёл %d E2E-проверок подряд — "
                            "переключение на %s",
                            ev["from"], FAILOVER_THRESHOLD, ev["to"])
                    _notify("failover_switch",
                            f"NaivePanel: {ev['from']} не работает — "
                            f"переключение на {ev['to']}")
                elif ev["event"] == "returned":
                    app.logger.warning(
                        "авто-возврат: %s жив (TCP %d подряд + проба E2E) — "
                        "возврат с %s", ev["to"], FAILOVER_RETURN_ALIVE, ev["from"])
                    _notify("failover_return",
                            f"NaivePanel: {ev['to']} снова жив — авто-возврат "
                            f"с {ev['from']}")
                elif ev["event"] == "return_probe_failed":
                    app.logger.warning(
                        "авто-возврат: %s TCP-жив, но проба E2E не прошла (%s) — "
                        "cooldown %dс", ev["candidate"], ev.get("error"),
                        FAILOVER_RETURN_COOLDOWN)
                    _notify("failover_return_probe_failed",
                            f"NaivePanel: авто-возврат на {ev['candidate']} "
                            f"отложен — проба не прошла")
                elif ev["event"] == "activate-failed":
                    app.logger.error(
                        "фейловер: активация %s не удалась (валидация)",
                        ev["to"])
                elif ev["event"] == "exhausted":
                    app.logger.error(
                        "фейловер: цепочка исчерпана — %s не работает и "
                        "запасных больше нет; проверка продолжается, возврат "
                        "на основной — вручную", ev["active"])
                    _notify("failover_exhausted",
                            f"NaivePanel: цепочка исчерпана — {ev['active']} "
                            f"не работает, запасных нет")
                # failing не логируем: до порога это нормальный шум сети
        except Exception:  # один сбойный тик не должен останавливать поток
            app.logger.warning("failover cycle failed", exc_info=True)
        # двухскоростной ритм: сбой → частые проверки до порога/восстановления
        time.sleep(FAILOVER_FAST if _failover.hot else FAILOVER_INTERVAL)


_CRED_RE = re.compile(r"([a-zA-Z][a-zA-Z0-9+.\-]*://[^:/@\s]+):([^@\s]+)@")


def _mask_creds(text: str) -> str:
    """Маскирует userinfo в URI (`scheme://user:pass@host` → `user:***@`)."""
    return _CRED_RE.sub(r"\1:***@", text)


def _tail_path(path: Path, lines: int = 100) -> str:
    """Последние `lines` строк файла — чтением с конца, а не всего файла.

    Между рестартами лог может вырасти далеко за урезающий лимит init-скрипта,
    а /api/logs дёргается поллингом каждые 3с — readlines() всего файла на
    роутере был бы заметен по памяти/CPU. Заодно маскируем креды в URI.
    """
    if not path.exists():
        return ""
    lines = max(1, min(lines, 1000))
    try:
        with path.open("rb") as fh:
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


# Активация из двух мест: API (ручной клик) и фейловер-монитор (авто).
# Лок страхует от гонки «пользователь активирует A в тот момент, когда
# монитор переключает на B»: два параллельных stop/start init-скрипта
# на медленном роутере могли бы перехлёстнуться.
_ACTIVATE_LOCK = threading.Lock()


def _activate_preset(name: str) -> dict[str, Any]:
    """Валидация + запись config.json/.active + рестарт сервиса.

    Используется ручным activate из UI и автофейловером — одна и та же
    семантика: битый конфиг не роняет рабочий прокси (валидация до записи).
    """
    if not NAME_RE.match(name):
        abort(400, description="invalid name")
    src = CONF_D / f"{name}.json"
    if not src.exists():
        abort(404, description=f"preset {name!r} not found")
    cfg = _load_json(src)
    _validate_cfg(cfg, name)  # битый конфиг не должен ронять рабочий прокси
    with _ACTIVATE_LOCK:
        _write_active(name, cfg)
        restart = _service("restart") if INIT_SCRIPT.exists() else {"rc": None, "note": "no init script"}
    return {"name": name, "active": True, "restart": restart}


@app.route("/api/configs/<name>/activate", methods=["POST"])
def api_configs_activate(name: str):
    return jsonify(_activate_preset(name))


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


@app.route("/api/e2e", methods=["POST"])
def api_e2e():
    """E2E-проверка прокси: реальный запрос через listen-порт активного пресета.

    Тело может задать {"listen": "..."} явно; без него берётся listen из
    config.json (первый адрес, если их несколько). Недоступность прокси —
    нормальный ответ 200 с ok:false и error (как у /api/probe).
    """
    data = request.get_json(silent=True) or {}
    listen = (data.get("listen") or "").strip()
    if not listen:
        listen = _active_listen()
        if not listen:
            abort(400, description="no active preset with listen: activate a preset first")
    resp = jsonify(_proxy_e2e_check(listen))
    resp.headers["Cache-Control"] = "no-store"  # результат живой, не кешируем
    return resp


@app.route("/api/e2e/history")
def api_e2e_history():
    """История периодических E2E-проверок монитора: спарклайн в UI.

    `?last=N` — сколько последних записей отдать (1..E2E_KEEP, дефолт 120
    ≈ 2 часа при минутном интервале). Битые строки буфера пропускаются.
    """
    try:
        last = int(request.args.get("last", "120"))
    except ValueError:
        last = 120
    last = max(1, min(last, E2E_KEEP))
    entries = _e2e_history_load(last)
    ok_n = sum(1 for e in entries if e["ok"])
    n = len(entries)
    avg_ms = round(sum(e["ms"] for e in entries) / n) if n else None
    resp = jsonify({
        "entries": entries,
        "keep": E2E_KEEP,
        "stats": {
            "total": n,
            "ok": ok_n,
            "fail": n - ok_n,
            "availability": round(100.0 * ok_n / n, 1) if n else None,
            "avg_ms": avg_ms,
            "window_s": (entries[-1]["t"] - entries[0]["t"]) if n > 1 else 0,
        },
    })
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.route("/api/failover")
def api_failover_get():
    resp = jsonify(_failover.snapshot())
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.route("/api/failover", methods=["PUT"])
def api_failover_put():
    """Задать цепочку: {"enabled": true, "chain": ["home", "backup"]}.

    Имена валидируются как у пресетов и проверяются на существование —
    опечатка не должна остаться в цепочке до первого сбоя.
    """
    data = request.get_json(silent=True) or {}
    enabled = bool(data.get("enabled"))
    chain_raw = data.get("chain")
    if enabled:
        if not isinstance(chain_raw, list) or not chain_raw:
            abort(400, description="chain required (non-empty list) when enabled")
        if len(chain_raw) > FAILOVER_CHAIN_MAX:
            abort(400, description=f"chain too long (max {FAILOVER_CHAIN_MAX})")
        seen: set[str] = set()
        for name in chain_raw:
            if not isinstance(name, str) or not NAME_RE.match(name):
                abort(400, description=f"invalid preset name: {name!r}")
            if name in seen:
                abort(400, description=f"duplicate preset in chain: {name!r}")
            seen.add(name)
            if not (CONF_D / f"{name}.json").exists():
                abort(404, description=f"preset {name!r} not found")
    else:
        chain_raw = []
    auto_return = data.get("auto_return", False)
    if not isinstance(auto_return, bool):
        abort(400, description="auto_return must be boolean")
    # авто-возврат осмыслен только с включённым фейловером
    if auto_return and not enabled:
        abort(400, description="auto_return requires enabled chain")
    _ensure_dirs()
    _save_json(FAILOVER_CONF, {"enabled": enabled, "chain": chain_raw,
                               "auto_return": auto_return})
    return jsonify(_failover.snapshot())


@app.route("/api/failover", methods=["DELETE"])
def api_failover_delete():
    try:
        FAILOVER_CONF.unlink()
    except FileNotFoundError:
        pass
    except OSError as exc:
        abort(500, description=f"cannot remove failover.json: {exc}")
    return jsonify(_failover.snapshot())


@app.route("/api/panel/restart", methods=["POST"])
def api_panel_restart():
    """Перезапуск самой панели: отсоединённо spawn'ит `S99naivepanel restart`.

    Init-скрипт через ~1с (sleep даёт ответ уйти) убивает текущий процесс и
    поднимает новый. Используется после обновления naivepanel.py/templates,
    чтобы не логиниться по SSH ради `/opt/etc/init.d/S99naivepanel restart`.
    """
    if not PANEL_INIT.exists():
        abort(503, description=f"{PANEL_INIT} not found")
    # Новая сессия → ребёнок переживёт смерть Flask-процесса. Путь — через
    # окружение, не позиционные аргументы -c: busybox на Keenetic их не
    # передаёт (тот же баг, что молча убивал self-update в v0.9.0–v0.9.1).
    # Команда фиксированная.
    env = {**os.environ, "NP_INIT": str(PANEL_INIT)}
    subprocess.Popen(  # nosec B603
        ["/bin/sh", "-c", 'sleep 1; exec /bin/sh "$NP_INIT" restart'],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    app.logger.warning("panel self-restart triggered by %s", request.remote_addr)
    return jsonify({"restart": True, "note": "panel restarting in ~1s"}), 202


# --- Self-update: проверка и установка обновлений из UI ---------------------

def _http_get(url: str, timeout: float = 6.0) -> str:
    """GET внешнего URL через curl/wget — как fetch() в install.sh.

    python-urllib на Entware завязан на системный CA-бандл, которого часто
    нет; curl же был обязателен при установке панели. Оба недоступны/упали —
    RuntimeError: панель нередко стоит в сетях без прямого хода в GitHub,
    это штатный отказ, а не авария.
    """
    last = ""
    for cmd in (["curl", "-fsSL", "--max-time", str(int(timeout)), url],
                ["wget", "-qO-", "-T", str(int(timeout)), url]):
        try:
            # cmd — фиксированный шаблон, url передаётся argv-элементом
            r = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=timeout + 2)  # nosec B603
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout
        last = f"{cmd[0]}: rc={r.returncode}"
    raise RuntimeError(f"GET {url} failed ({last or 'curl and wget not found'})")


def _http_download(url: str, dst: Path, timeout: float = 300.0) -> None:
    """Скачивание бинарного файла через curl/wget — как _http_get, но в файл.

    Архив бинарника (~3.5МБ) не проходит через stdout-подстановку; таймаут
    щедрый — на медленном линке роутера качается заметно дольше JSON.
    """
    for cmd in (["curl", "-fsSL", "--max-time", str(int(timeout)),
                 "-o", str(dst), url],
                ["wget", "-q", "-T", "60", "-t", "2", "-O", str(dst), url]):
        try:
            # cmd — фиксированный шаблон, url передаётся argv-элементом
            r = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=timeout + 30)  # nosec B603
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
        if r.returncode == 0 and dst.exists() and dst.stat().st_size > 0:
            return
    raise RuntimeError(f"download {url} failed")


def _ver_key(v: str) -> tuple[int, ...]:
    """Версия → числовой кортеж для сравнения: 0.10.0 > 0.9.0 (строкой — нет)."""
    parts: list[int] = []
    for p in v.strip().lstrip("vV").split("."):
        m = re.match(r"\d+", p)
        parts.append(int(m.group()) if m else 0)
    return tuple(parts) or (0,)


def _latest_release() -> dict[str, Any]:
    """Самый свежий тег репозитория + notes релиза, если тот оформлен.

    `releases/latest` отстаёт от тегов (релиз-ноту создают не под каждый
    тег), поэтому сверяем и список тегов, выбирая максимум по версии —
    независимо от порядка, который GitHub API не гарантирует.
    """
    rel: dict[str, Any] = {}
    try:
        data = json.loads(_http_get(f"{UPDATE_API_BASE}/repos/{UPDATE_REPO}/releases/latest"))
        tag = data.get("tag_name") or ""
        if _TAG_RE.match(tag):
            rel = {"tag": tag,
                   "notes": (data.get("body") or "").strip()[:4000],
                   "url": data.get("html_url") or ""}
    except (RuntimeError, ValueError):
        pass  # релизов нет или API недоступен — решит список тегов
    best: str | None = None
    try:
        tags = json.loads(_http_get(f"{UPDATE_API_BASE}/repos/{UPDATE_REPO}/tags?per_page=10"))
        names = (t.get("name") or "" for t in tags if isinstance(t, dict))
        best = max((n for n in names if _TAG_RE.match(n)),
                   key=_ver_key, default=None)
    except (RuntimeError, ValueError) as exc:
        if not rel:
            raise RuntimeError(f"cannot reach {UPDATE_API_BASE}: {exc}") from exc
    if best and (not rel or _ver_key(best) > _ver_key(rel["tag"])):
        return {"tag": best, "notes": "",
                "url": f"https://github.com/{UPDATE_REPO}/releases/tag/{best}"}
    if rel:
        return rel
    raise RuntimeError(f"no vX.Y.Z tags/releases found in {UPDATE_REPO}")


def _bind_is_loopback() -> bool:
    host, _ = _parse_bind(PANEL_BIND)
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False  # нераспознанный адрес считаем публичным (fail-closed)


def _update_state_read() -> dict[str, Any]:
    try:
        st = json.loads(UPDATE_STATE.read_text(encoding="utf-8"))
        return st if isinstance(st, dict) else {}
    except (OSError, ValueError):
        return {}


def _update_state_write(st: dict[str, Any]) -> None:
    try:
        UPDATE_STATE.parent.mkdir(parents=True, exist_ok=True)
        UPDATE_STATE.write_text(json.dumps(st) + "\n", encoding="utf-8")
    except OSError as exc:  # state не критичен: обновление переживёт и без него
        app.logger.warning("cannot write %s: %s", UPDATE_STATE, exc)


def _pid_alive(pid: Any) -> bool:
    """Жив ли процесс установщика (pid пишем в state с v0.8.1)."""
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return False  # pid нет (state от версии до v0.8.1) — считаем мёртвым
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # существует, но чужой — на роутере один пользователь
    return True


def _update_state() -> dict[str, Any]:
    """Состояние обновления с самодиагностикой после рестарта панели.

    Успешный апдейт перезапускает панель: новый процесс видит state
    «running» с целью, равной собственной версии, и закрывает его как
    «done». Умерший установщик (сеть/checksum/диск) распознаём по pid —
    state помечается «failed» и не блокирует retry фиктивным
    «already in progress». Записи без pid протухают через _UPDATE_STALE_S.
    """
    st = _update_state_read()
    if st.get("phase") == "running":
        if str(st.get("target") or "").lstrip("vV") == APP_VERSION:
            _update_state_write({**st, "phase": "done", "finished": time.time()})
            st["phase"] = "done"
        elif not _pid_alive(st.get("pid")):
            st["phase"] = "failed"
            _update_state_write(st)
        elif time.time() - float(st.get("started") or 0) > _UPDATE_STALE_S:
            st["stale"] = True
    return st


_update_check_cache: dict[str, Any] = {}


@app.route("/api/update/check")
def api_update_check():
    """Есть ли свежий релиз: APP_VERSION против тегов GitHub.

    Результат кэшируется на 6ч (?force=1 обходит кэш). Сеть/GitHub
    недоступны — 200 с полем error и available=false: UI показывает это
    тихой строкой, а не ошибкой.
    """
    force = request.args.get("force") in ("1", "true")
    now = time.monotonic()
    if not force and _update_check_cache:
        if now - _update_check_cache["at"] < _update_check_cache.get("ttl", _UPDATE_CHECK_TTL):
            out = dict(_update_check_cache["data"])
            out["cached"] = True
            return jsonify(out)
    checked = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    try:
        rel = _latest_release()
    except RuntimeError as exc:
        out = {"current": APP_VERSION, "latest": None, "available": False,
               "error": str(exc), "checked_at": checked}
        _update_check_cache.update({"at": now, "ttl": _UPDATE_ERR_TTL, "data": out})
        return jsonify(out)
    latest = rel["tag"].lstrip("vV")
    out = {
        "current": APP_VERSION,
        "latest": latest,
        "available": _ver_key(latest) > _ver_key(APP_VERSION),
        "notes": rel["notes"],
        "url": rel["url"],
        "checked_at": checked,
    }
    _update_check_cache.update({"at": now, "ttl": _UPDATE_CHECK_TTL, "data": out})
    return jsonify(out)


@app.route("/api/update/apply", methods=["POST"])
def api_update_apply():
    """Запуск обновления: spawn отсоединённого `install.sh --yes --from-update
    --ref <тег>` с записью exit-кода установщика в лог.

    Установщик скачивает файлы тега, сверяет SHA256SUMS, ставит их и в конце
    сам делает `S99naivepanel restart` — Flask-процесс умирает посреди
    установки, поэтому ребёнок живёт в новой сессии (как /api/panel/restart).
    Реф клиент не передаёт: сервер сам резолвит последний тег. Прокси
    (S99naiveproxy) установщик не перезапускает — соединения не рвутся.
    """
    # Обновление подменяет код панели: без пароля — только loopback-bind
    if not PANEL_ADMIN_PASS.exists() and not _bind_is_loopback():
        abort(403, description="panel is exposed without a password — set one "
                               "(install.sh --with-auth) before updating")
    state = _update_state()
    if state.get("phase") == "running" and not state.get("stale"):
        abort(409, description=f"update to {state.get('target')} already in "
                               f"progress — installer log: {UPDATE_LOG}")
    try:
        rel = _latest_release()
    except RuntimeError as exc:
        abort(502, description=str(exc))
    tag = rel["tag"]
    try:
        installer = _http_get(f"{UPDATE_RAW_BASE}/{UPDATE_REPO}/{tag}/install.sh",
                              timeout=30.0)
    except RuntimeError as exc:
        abort(502, description=f"cannot download install.sh@{tag}: {exc}")
    try:
        PANEL_DIR.mkdir(parents=True, exist_ok=True)
        # бэкап заменяемых файлов — для ручного отката после неудачного апдейта
        backup = PANEL_DIR / "backup" / f"v{APP_VERSION}"
        backup.mkdir(parents=True, exist_ok=True)
        for src in (PANEL_DIR / "naivepanel.py",
                    PANEL_DIR / "templates" / "index.html",
                    PANEL_INIT, INIT_SCRIPT):
            if src.exists():
                shutil.copy2(src, backup / src.name)
        stage = PANEL_DIR / ".update-install.sh"
        stage.write_text(installer, encoding="utf-8")
        os.chmod(stage, 0o700)
        UPDATE_LOG.parent.mkdir(parents=True, exist_ok=True)
        # Пролог панелью, а не установщиком: реальный кейс (v0.9.0, роутер) —
        # ребёнок умер до первой строки скрипта (OOM при exec) и лог остался
        # пустым, ничего не отличалось от «лог не создан». Теперь пустой лог
        # после пролога сам по себе диагноз.
        UPDATE_LOG.write_text(
            f"== self-update {APP_VERSION} -> {tag}, "
            f"spawn {time.strftime('%Y-%m-%d %H:%M:%S')}\n",
            encoding="utf-8")
    except OSError as exc:
        abort(500, description=f"cannot prepare update: {exc}")
    # Команда фиксированная, а tag и пути передаются ЧЕРЕЗ ОКРУЖЕНИЕ
    # (NP_STAGE/NP_TAG/NP_LOG), не argv после -c: busybox на Keenetic
    # (Entware) не передаёт позиционные аргументы после `sh -c 'строка'`
    # — реальные $1..$3 оказываются пустыми, и v0.9.0–v0.9.1 умирали
    # молча, не сумев открыть `>>""` (кейс тихой смерти self-update).
    # Обёртка без exec дожидается установщика и дописывает его exit-код
    # в лог: мгновенная смерть перестаёт быть невидимой. --from-update:
    # python/flask уже подняты самим фактом работы панели — установщик
    # пропускает их проверки и не форкает python на тесной памяти.
    env = {**os.environ,
           "NP_STAGE": str(stage), "NP_TAG": tag, "NP_LOG": str(UPDATE_LOG)}
    try:
        proc = subprocess.Popen(  # nosec B603
            ["/bin/sh", "-c",
             '/bin/sh "$NP_STAGE" --yes --from-update --ref "$NP_TAG" '
             '>>"$NP_LOG" 2>&1; '
             'rc=$?; echo "installer exit code: $rc" >>"$NP_LOG"'],
            env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except OSError as exc:
        # v0.7.0 писал state до спавна: ошибка fork/exec (ENOMEM на тесной
        # памяти роутера) оставляла «running» без процесса и с пустым логом
        abort(500, description=f"cannot spawn installer: {exc}")
    # pid в state: умерший установщик распознаётся при следующем же запросе,
    # а не через 15 минут (_update_state помечает такой state «failed»)
    _update_state_write({"phase": "running", "target": tag,
                         "started": time.time(), "pid": proc.pid})
    app.logger.warning("self-update to %s triggered by %s", tag, request.remote_addr)
    return jsonify({"started": True, "target": tag, "current": APP_VERSION,
                    "log": str(UPDATE_LOG)}), 202


@app.route("/api/update/log")
def api_update_log():
    """Tail лога установщика + state (UI поллит во время апдейта).

    `panel` — короткий хвост naivepanel.log: при зависшем/умершем
    установщике причина (spawn failure, ошибка записи state) попадает
    в лог самой панели, пока она ещё жива.
    """
    try:
        lines = int(request.args.get("lines", "60"))
    except ValueError:
        lines = 60
    resp = jsonify({"lines": lines,
                    "content": _tail_path(UPDATE_LOG, lines),
                    "panel": _tail_path(PANEL_LOG, 20),
                    "state": _update_state()})
    resp.headers["Cache-Control"] = "no-store"
    return resp


# --- Бинарник naive: проверка версии и обновление из UI ----------------------

def _naive_bin_version() -> str | None:
    """Версия из самого бинарника: `naive --version` → «naive 154.0.8037.49».

    Бинарника нет или он не запускается (битая ручная установка) → None.
    """
    if not NAIVE_BIN.exists():
        return None
    try:
        r = subprocess.run([str(NAIVE_BIN), "--version"], capture_output=True,
                           text=True, timeout=15)  # nosec B603
    except (OSError, subprocess.TimeoutExpired):
        return None
    out = (r.stdout or "").strip()
    if r.returncode != 0 or not out:
        return None
    line = out.splitlines()[0].strip()
    if line.lower().startswith("naive "):
        line = line[len("naive "):].strip()
    return line or None


def _naive_ver_key(tag_or_ver: str) -> tuple[int, ...]:
    """«v154.0.8037.49-2» → (154, 0, 8037, 49, 2) — для сравнения версий.

    Суффикс пересборки (-N) учитывается: v154...-2 новее v154...-1, а вывод
    `naive --version` без суффикса даёт (... ,0) — старше любого -N.
    """
    s = (tag_or_ver or "").strip().lower().lstrip("v")
    build = 0
    head, sep, tail = s.rpartition("-")
    if sep and tail.isdigit():
        s, build = head, int(tail)
    parts: list[int] = []
    for p in s.split("."):
        m = re.match(r"\d+", p)
        parts.append(int(m.group()) if m else 0)
    return (*parts, build)


def _naive_read(path: Path) -> str | None:
    try:
        v = path.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return v or None


def _naive_detect_target() -> str | None:
    """openwrt-таргет по железу — зеркало detect_naive_target из install.sh.

    NAIVEPROXY_UNAME_M / NAIVEPROXY_CPUINFO / NAIVEPROXY_ELF переопределяют
    источники (тесты); в проде — platform.machine(), /proc/cpuinfo и
    ELF-заголовок /bin/sh (энддиан MIPS: байт 5, 1=LE 2=BE). None — prebuilt
    под такое железо не существует (big-endian MIPS, экзотическая arch).
    """
    machine = (os.environ.get("NAIVEPROXY_UNAME_M") or platform.machine()).lower()
    try:
        info = Path(os.environ.get("NAIVEPROXY_CPUINFO", "/proc/cpuinfo")) \
            .read_text(encoding="utf-8", errors="replace")
    except OSError:
        info = ""

    def field(name: str) -> str:
        for line in info.splitlines():
            key, sep, value = line.partition(":")
            if sep and key.strip() == name:
                return value.strip()
        return ""

    part = field("CPU part").lower()
    if machine in ("x86_64", "amd64"):
        return "x86_64"
    if re.fullmatch(r"i[3-6]86", machine):
        return "x86"
    if machine in ("aarch64", "arm64"):
        return {"0xd03": "aarch64_cortex-a53",
                "0xd08": "aarch64_cortex-a72",
                "0xd0e": "aarch64_cortex-a76"}.get(part, "aarch64_generic")
    if machine.startswith("armv7"):
        feats = set(field("Features").split())
        neon, vfp4 = "neon" in feats, "vfpv4" in feats
        if part == "0xc05":
            return "arm_cortex-a5_vfpv4"
        if part == "0xc08":
            return "arm_cortex-a8_vfpv3"
        if part == "0xc09":
            return "arm_cortex-a9_neon" if neon else "arm_cortex-a9"
        if part == "0xc0f":
            return "arm_cortex-a15_neon-vfpv4"
        if neon and vfp4:
            return "arm_cortex-a7_neon-vfpv4"
        if vfp4:
            return "arm_cortex-a7_vfpv4"
        return "arm_cortex-a7"
    if machine.startswith("armv6"):
        return "arm_arm1176jzf-s_vfp"
    if machine.startswith("armv5"):
        return "arm_arm926ej-s"
    if machine == "mips":
        try:
            data = Path(os.environ.get("NAIVEPROXY_ELF", "/bin/sh")).read_bytes()
        except OSError:
            data = b""
        if data[5:6] == b"\x02":
            return None  # big-endian: prebuilt-сборок нет
        model = field("cpu model")
        if any(k in model for k in ("24Kc", "24KEc", "34Kc", "1004Kc", "mips32r2")):
            return "mipsel_24kc"
        return "mipsel_mips32"
    return None


def _naive_pick_asset(assets: list[tuple[str, str]],
                      target: str | None) -> tuple[str, str] | None:
    """Лучший (имя, url) ассета под таргет: точный → arch-фолбэк,
    в каждом сначала -static (musl, без зависимостей от библиотек /opt/lib).
    """
    if not target:
        return None
    fallback = ""
    if target.startswith("aarch64_"):
        fallback = "aarch64_generic"
    elif target.startswith("arm_"):
        fallback = "arm_cortex-a7"
    elif target.startswith("mipsel_"):
        fallback = "mipsel_mips32"
    for cand in (target, fallback):
        if not cand:
            continue
        for flavor in (f"{cand}-static", cand):
            for name, url in assets:
                if name.endswith(f"-openwrt-{flavor}.tar.xz"):
                    return name, url
    return None


def _naive_release() -> dict[str, Any]:
    """Последний релиз klzgrad/naiveproxy: тег + ассеты (+ заметка)."""
    data = json.loads(_http_get(f"{NAIVE_SRC_API}/repos/{NAIVE_SRC_REPO}/releases/latest"))
    tag = data.get("tag_name") or ""
    assets = [(a.get("name") or "", a.get("browser_download_url") or "")
              for a in data.get("assets") or [] if isinstance(a, dict)]
    if not tag or not assets:
        raise RuntimeError(f"unexpected release payload from {NAIVE_SRC_REPO}")
    return {"tag": tag, "notes": (data.get("body") or "").strip()[:4000],
            "url": data.get("html_url") or "", "assets": assets}


def _naive_state_read() -> dict[str, Any]:
    try:
        st = json.loads(NAIVE_UPDATE_STATE.read_text(encoding="utf-8"))
        return st if isinstance(st, dict) else {}
    except (OSError, ValueError):
        return {}


def _naive_state_write(st: dict[str, Any]) -> None:
    try:
        NAIVEPROXY_DIR.mkdir(parents=True, exist_ok=True)
        NAIVE_UPDATE_STATE.write_text(json.dumps(st) + "\n", encoding="utf-8")
    except OSError as exc:  # state не критичен: обновление переживёт и без него
        app.logger.warning("cannot write %s: %s", NAIVE_UPDATE_STATE, exc)


def _naive_state() -> dict[str, Any]:
    """State обновления бинарника; «running» без прогресса → stale.

    Воркер живёт потоком внутри панели: её рестарт убивает поток, pid для
    проверки взять неоткуда — потому только тайм-аут (скачивание ~3.5МБ
    укладывается в него с запасом, а реальный прогресс виден в логе).
    """
    st = _naive_state_read()
    if st.get("phase") == "running":
        if time.time() - float(st.get("started") or 0) > _NAIVE_STALE_S:
            st["stale"] = True
    return st


def _naive_log(msg: str) -> None:
    try:
        with NAIVE_UPDATE_LOG.open("a", encoding="utf-8") as fh:
            fh.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}\n")
    except OSError:
        pass  # лог не критичен


def _naive_update_worker() -> None:
    """Фоновое обновление /opt/bin/naive (запускается потоком из apply).

    Порядок страховит: скачали → распаковали → ПРОВЕРИЛИ `--version` →
    только тогда заменили (rename: работающий naive продолжает старый инод)
    и перезапустили сервис, если он работал. Любой сбой до rename не трогает
    рабочий бинарник; прежний образ остаётся бэкапом naive.previous.
    """
    try:
        rel = _naive_release()
        tag = rel["tag"]
        build = _naive_read(NAIVE_BUILD) or ""
        target = build.removesuffix("-static") or _naive_detect_target()
        picked = _naive_pick_asset(rel["assets"], target)
        if not picked:
            raise RuntimeError(f"release {tag} has no openwrt asset for "
                               f"target {target!r}")
        name, url = picked
        _naive_log(f"{tag}: asset {name} ({target})")
        stage = NAIVEPROXY_DIR / ".naive-update"
        shutil.rmtree(stage, ignore_errors=True)
        stage.mkdir(parents=True, exist_ok=True)
        tgz = stage / "naive.tar.xz"
        _naive_log(f"downloading {url}")
        _http_download(url, tgz)
        r = subprocess.run(["tar", "-xJf", str(tgz), "-C", str(stage)],
                           capture_output=True, text=True, timeout=120)  # nosec B603
        if r.returncode != 0:
            raise RuntimeError("tar -xJf failed (xz missing? opkg install xz): "
                               + (r.stderr.strip() or f"rc={r.returncode}"))
        bins = sorted(stage.glob("naiveproxy-*/naive"))
        if not bins:
            raise RuntimeError("tarball contains no naiveproxy-*/naive")
        new_bin = bins[0]
        new_bin.chmod(0o755)
        rv = subprocess.run([str(new_bin), "--version"], capture_output=True,
                            text=True, timeout=15)  # nosec B603
        if rv.returncode != 0:
            raise RuntimeError("downloaded binary failed --version check "
                               "(wrong target?) — keeping the current one")
        new_ver = (rv.stdout or "").strip().splitlines()[0].strip()
        _naive_log(f"check ok: {new_ver}")
        was_active = _status()["active"]
        if NAIVE_BIN.exists():
            backup = NAIVEPROXY_DIR / "backup" / "naive.previous"
            backup.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(NAIVE_BIN, backup)
        # cp в тот же каталог + os.replace = rename внутри ФС: открытый
        # для записи работающий бинарник дал бы ETXTBSY, а rename оставляет
        # старый образ выполняющемуся процессу
        placed = NAIVE_BIN.with_name(NAIVE_BIN.name + ".new")
        shutil.copy2(new_bin, placed)
        placed.chmod(0o755)
        os.replace(placed, NAIVE_BIN)
        NAIVE_TAG.write_text(tag + "\n", encoding="utf-8")
        NAIVE_BUILD.write_text(
            name.rsplit(".tar.xz", 1)[0].rsplit("-openwrt-", 1)[-1] + "\n",
            encoding="utf-8")
        shutil.rmtree(stage, ignore_errors=True)
        _naive_log(f"installed {tag} -> {NAIVE_BIN}")
        restarted = False
        if was_active and INIT_SCRIPT.exists():
            restarted = True
            rst = _service("restart")
            _naive_log(f"service restart rc={rst['rc']}")
        _naive_state_write({"phase": "done", "target": tag,
                            "finished": time.time(), "version": new_ver,
                            "restarted": restarted})
        app.logger.info("naive binary updated to %s (%s)", tag, name)
    except Exception as exc:  # любая ошибка воркера — в state и лог, не в панель
        _naive_log(f"failed: {exc}")
        app.logger.warning("naive update failed", exc_info=True)
        _naive_state_write({"phase": "failed", "error": str(exc)[:500],
                            "finished": time.time()})


_naive_check_cache: dict[str, Any] = {}


@app.route("/api/naive/check")
def api_naive_check():
    """Версия бинарника naive против последнего релиза klzgrad/naiveproxy.

    Текущая версия — из маркера (точный тег) с фолбэком на `naive --version`
    (бинарник, поставленный руками, маркера не имеет). Сеть/GitHub недоступны
    — 200 с error и available=False, как у /api/update/check.
    """
    force = request.args.get("force") in ("1", "true")
    now = time.monotonic()
    if not force and _naive_check_cache:
        if now - _naive_check_cache["at"] < _naive_check_cache.get("ttl", _NAIVE_CHECK_TTL):
            out = dict(_naive_check_cache["data"])
            out["cached"] = True
            return jsonify(out)
    checked = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    version = _naive_bin_version()
    tag = _naive_read(NAIVE_TAG)
    out: dict[str, Any] = {
        "version": version,
        "tag": tag,
        "path": str(NAIVE_BIN) if NAIVE_BIN.exists() else None,
        "target": _naive_read(NAIVE_BUILD) or _naive_detect_target(),
        "checked_at": checked,
    }
    try:
        rel = _naive_release()
    except (RuntimeError, ValueError) as exc:
        out.update({"latest": None, "available": False, "error": str(exc)})
        _naive_check_cache.update({"at": now, "ttl": _NAIVE_ERR_TTL, "data": out})
        return jsonify(out)
    latest = rel["tag"]
    cur = _naive_ver_key(tag) if tag else (_naive_ver_key(version) if version else None)
    out.update({"latest": latest,
                "available": cur is None or _naive_ver_key(latest) > cur,
                "notes": rel["notes"], "url": rel["url"]})
    _naive_check_cache.update({"at": now, "ttl": _NAIVE_CHECK_TTL, "data": out})
    return jsonify(out)


@app.route("/api/naive/update", methods=["POST"])
def api_naive_update():
    """Обновление (или первичная установка) бинарника naive фоновым потоком.

    Панель сама не перезапускается — воркер меняет только /opt/bin/naive и
    перезапускает прокси, если тот работал. Отсюда гейт как у /api/update/
    apply: замена root-исполняемого файла в LAN без auth недопустима.
    """
    if not PANEL_ADMIN_PASS.exists() and not _bind_is_loopback():
        abort(403, description="panel is exposed without a password — set one "
                               "(install.sh --with-auth) before updating")
    st = _naive_state()
    if st.get("phase") == "running" and not st.get("stale"):
        abort(409, description=f"naive update to {st.get('target')} already in "
                               f"progress — log: {NAIVE_UPDATE_LOG}")
    try:
        rel = _naive_release()
    except (RuntimeError, ValueError) as exc:
        abort(502, description=str(exc))
    tag = rel["tag"]
    try:
        NAIVE_UPDATE_LOG.parent.mkdir(parents=True, exist_ok=True)
        NAIVE_UPDATE_LOG.write_text(
            f"== naive binary update -> {tag}, "
            f"{time.strftime('%Y-%m-%d %H:%M:%S')}\n", encoding="utf-8")
    except OSError:
        pass  # лог не критичен
    _naive_state_write({"phase": "running", "target": tag, "started": time.time()})
    threading.Thread(target=_naive_update_worker, name="naive-update",
                     daemon=True).start()
    app.logger.warning("naive binary update to %s triggered by %s",
                       tag, request.remote_addr)
    return jsonify({"started": True, "target": tag, "log": str(NAIVE_UPDATE_LOG)}), 202


@app.route("/api/naive/status")
def api_naive_status():
    """State обновления бинарника + хвост лога (UI поллит из диалога)."""
    try:
        lines = int(request.args.get("lines", "40"))
    except ValueError:
        lines = 40
    resp = jsonify({"lines": lines,
                    "content": _tail_path(NAIVE_UPDATE_LOG, lines),
                    "state": _naive_state()})
    resp.headers["Cache-Control"] = "no-store"
    return resp


# Лог какого хвоста показывать: по умолчанию — naive, src=panel — сама панель
LOG_SOURCES: dict[str, Path] = {"proxy": LOG_FILE, "panel": PANEL_LOG}


@app.route("/api/logs")
def api_logs():
    try:
        lines = int(request.args.get("lines", "100"))
    except ValueError:
        lines = 100
    path = LOG_SOURCES.get(request.args.get("src", "proxy"), LOG_FILE)
    resp = jsonify({"lines": lines, "content": _tail_path(path, lines)})
    resp.headers["Cache-Control"] = "no-store"  # логи могут содержать креды
    return resp


# --- Периодическая обрезка логов (фоновый поток) ---------------------------


def _active_extra_log() -> Path | None:
    """Путь к log-файлу из активного config.json (ключ `log` у naive).

    Пресет может задавать naive собственный файл лога — его никто, кроме
    панели, не знает: init-скрипт обрезает только /opt/var/log/naiveproxy.log.
    """
    try:
        cfg = json.loads(ACTIVE_CONFIG.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    extra = cfg.get("log")
    if isinstance(extra, str) and extra.strip():
        return Path(extra)
    return None


def _trim_file(path: Path, max_bytes: int, keep: int) -> tuple[int, int] | None:
    """Обрезает файл до последних `keep` байт; возвращает (было, стало).

    Инод обязан сохраняться (r+b + truncate, не replace/rename): пишущий
    процесс держит файл открытым в append-режиме — при rename он продолжил
    бы писать в отсоединённый старый инод, и место не освободилось бы до
    рестарта. Строки, добавленные между чтением хвоста и truncate,
    теряются — для лога допустимо.
    """
    try:
        size = path.stat().st_size
    except OSError:
        return None
    if size <= max_bytes:
        return None
    keep = min(keep, size)
    try:
        with path.open("r+b") as fh:
            fh.seek(size - keep)
            tail = fh.read(keep)
            nl = tail.find(b"\n")
            if nl != -1:
                tail = tail[nl + 1:]  # хвост не должен начинаться с обрубка строки
            fh.seek(0)
            fh.write(tail)
            fh.truncate()
            fh.flush()
            os.fsync(fh.fileno())
    except OSError as exc:
        app.logger.warning("log trim %s: %s", path, exc)
        return None
    return size, len(tail)


def _trim_logs_once() -> list[tuple[Path, int, int]]:
    """Один проход по всем известным логам; возвращает обрезанные (путь, было, стало)."""
    if LOG_TRIM_MAX <= 0:
        return []
    targets: set[Path] = {LOG_FILE, PANEL_LOG, UPDATE_LOG, NAIVE_UPDATE_LOG}
    extra = _active_extra_log()
    if extra:
        targets.add(extra)
    trimmed: list[tuple[Path, int, int]] = []
    for path in sorted(targets):
        result = _trim_file(path, LOG_TRIM_MAX, LOG_TRIM_KEEP)
        if result:
            trimmed.append((path, *result))
    return trimmed


def _log_trim_loop() -> None:
    # daemon-поток: переживает рестарт панели вместе с процессом; каждая
    # итерация под try, чтобы поток не умер из-за неожиданной ошибки
    while True:
        try:
            for path, was, now in _trim_logs_once():
                app.logger.info("trimmed %s: %d -> %d bytes", path, was, now)
        except Exception:  # триммер не должен ронять поток целиком
            app.logger.warning("log trim cycle failed", exc_info=True)
        time.sleep(LOG_TRIM_INTERVAL)


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
    if _LOG_MAX_INVALID:
        app.logger.warning(
            "NAIVEPANEL_LOG_MAX=%r is not a number — using %d",
            _LOG_MAX_RAW, LOG_TRIM_MAX,
        )
    if _LOG_KEEP_INVALID:
        app.logger.warning(
            "NAIVEPANEL_LOG_KEEP=%r is not a number — using %d",
            _LOG_KEEP_RAW, LOG_TRIM_KEEP,
        )
    if LOG_TRIM_MAX > 0:
        threading.Thread(
            target=_log_trim_loop, name="log-trim", daemon=True
        ).start()
    if _WATCHDOG_INTERVAL_INVALID:
        app.logger.warning(
            "NAIVEPANEL_WATCHDOG_INTERVAL=%r is not a number — using %d",
            _WATCHDOG_INTERVAL_RAW, WATCHDOG_INTERVAL,
        )
    if WATCHDOG_ENABLED:
        app.logger.info(
            "watchdog enabled: interval=%ds flap=%d/%ds (штатный stop по маркеру %s)",
            WATCHDOG_INTERVAL, WATCHDOG_FLAP_MAX, int(WATCHDOG_FLAP_WINDOW),
            STOP_MARKER,
        )
        threading.Thread(
            target=_watchdog_loop, name="naive-watchdog", daemon=True
        ).start()
    else:
        app.logger.info("watchdog disabled by NAIVEPANEL_WATCHDOG=0")
    if _FAILOVER_INTERVAL_INVALID:
        app.logger.warning(
            "NAIVEPANEL_FAILOVER_INTERVAL=%r is not a number — using %d",
            _FAILOVER_INTERVAL_RAW, FAILOVER_INTERVAL,
        )
    if _FAILOVER_THRESHOLD_INVALID:
        app.logger.warning(
            "NAIVEPANEL_FAILOVER_THRESHOLD=%r is not a number — using %d",
            _FAILOVER_THRESHOLD_RAW, FAILOVER_THRESHOLD,
        )
    if _FAILOVER_FAST_INVALID:
        app.logger.warning(
            "NAIVEPANEL_FAILOVER_FAST=%r is not a number — using %d",
            _FAILOVER_FAST_RAW, FAILOVER_FAST,
        )
    if _E2E_KEEP_INVALID:
        app.logger.warning(
            "NAIVEPANEL_E2E_KEEP=%r is not a number — using %d",
            _E2E_KEEP_RAW, E2E_KEEP,
        )
    if FAILOVER_ENABLED:
        # монитор живёт всегда: проверяет активный пресет (история E2E для
        # спарклайна) и переключает по цепочке, если она задана из UI
        threading.Thread(
            target=_failover_loop, name="naive-monitor", daemon=True
        ).start()
    else:
        app.logger.info(
            "monitor (e2e history + failover) disabled by NAIVEPANEL_FAILOVER=0")
    if NOTIFY_CHANNEL is not None:
        app.logger.info("notifications enabled: %s", NOTIFY_CHANNEL)
        threading.Thread(
            target=_notify_loop, name="naive-notify", daemon=True
        ).start()
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
