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

import ipaddress
import json
import os
# subprocess вызывается только с фиксированными argv-списками (shell=False)
import threading
import subprocess  # noqa: F401 — тесты патчат глобальный модуль через m.subprocess
import socket  # noqa: F401 — тесты патчат глобальный модуль через app.socket
import time
from pathlib import Path

from flask import (Flask)

# --- Модульная архитектура (ARCH-01, Task 15) -------------------------------
# Конфигурация живёт в panel/config.py. naivepanel.py остаётся точкой входа
# и compatibility-модулем: реэкспортирует имена, тесты продолжают патчить
# и читать их здесь. reload(naivepanel) в тестах подменяет env — поэтому при
# каждом исполнении этого модуля подмодули пакета пересобираются (иначе
# константы остались бы от первого импорта).
import importlib as _il
import sys as _sys


def _reload_or_import(name: str):
    mod = _sys.modules.get(name)
    return _il.reload(mod) if mod is not None else _il.import_module(name)


_reload_or_import("panel.config")
from panel import config as cfg  # noqa: F401  # модуль-владелец констант (патчи тестов — сюда)
from panel.config import *  # noqa: F401,F403 — re-export для совместимости
_reload_or_import("panel.security")
from panel import security as sec  # noqa: F401  # модуль-владелец auth/CSRF/CSP (патчи тестов — сюда)
from panel.security import *  # noqa: F401,F403 — re-export для совместимости

_reload_or_import("panel.presets")
from panel import presets as pres  # noqa: F401  # модуль-владелец CRUD/валидации пресетов (патчи тестов — сюда)
from panel.presets import *  # noqa: F401,F403 — re-export для совместимости

_reload_or_import("panel.service")
from panel import service as svc  # noqa: F401  # модуль-владелец управления сервисом (патчи тестов — сюда)
from panel.service import *  # noqa: F401,F403 — re-export для совместимости

_reload_or_import("panel.monitor")
from panel import monitor as mon  # noqa: F401  # модуль-владелец мониторинга/автоматики (патчи тестов — сюда)
from panel.monitor import *  # noqa: F401,F403 — re-export для совместимости

_reload_or_import("panel.updates")
from panel import updates as upd  # noqa: F401  # модуль-владелец обновлений/отката (патчи тестов — сюда)
from panel.updates import *  # noqa: F401,F403 — re-export для совместимости

_reload_or_import("panel.app")
from panel import app as appmod  # noqa: F401  # модуль-владелец Flask-app и роутов
from panel.app import *  # noqa: F401,F403 — re-export (app, роуты)

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
        if not cfg._bind_is_loopback() and os.environ.get("NAIVEPANEL_DEV_SERVER") != "1":
            # Werkzeug dev-сервер в LAN — авария конфигурации, а не fallback:
            # он не для прод-нагрузки (SEC-06). Явный override — для отладки.
            app.logger.error(
                "refusing to serve on %s:%s via Werkzeug dev server: "
                "install waitress (opkg install python3-waitress) or set "
                "NAIVEPANEL_DEV_SERVER=1 to override explicitly", host, port)
            raise SystemExit(2)
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
            target=mon._watchdog_loop, name="naive-watchdog", daemon=True
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
            target=mon._failover_loop, name="naive-monitor", daemon=True
        ).start()
    else:
        app.logger.info(
            "monitor (e2e history + failover) disabled by NAIVEPANEL_FAILOVER=0")
    channel = mon._notify_channel()
    if channel:
        app.logger.info("notifications enabled: %s", channel)
    else:
        app.logger.info("notifications not configured — set up in the panel UI")
    threading.Thread(
        target=mon._notify_loop, name="naive-notify", daemon=True
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
