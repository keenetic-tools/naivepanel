"""Flask-приложение NaivePanel: фабрика app, error-хелпер и все роуты.

Шаг 7/7 модульного разделения (ARCH-01), финальный: сюда сошлись все
HTTP-маршруты; логика живёт в модулях пакета (cfg/sec/pres/svc/mon/upd),
роуты только валидируют вход, вызывают владельцев и формируют ответы.
naivepanel.py остаётся тонким entrypoint-ом (шим reload + log-trim +
_serve/main).

Патчи тестов — на модулях-владельцах (app.mon._proxy_running и т.п.),
не на функциях роутов.
"""

import json
import os
import queue
import shutil
import socket
import subprocess
import threading
import time
from pathlib import Path
from typing import Any

from flask import (Flask, Response, abort, jsonify, make_response,
                   render_template, request)
from werkzeug.exceptions import HTTPException

from panel import config as cfg
from panel import monitor as mon
from panel import presets as pres
from panel import security as sec
from panel import service as svc
from panel import updates as upd

# --- Flask app ------------------------------------------------------------

# Имя "naivepanel" — осознанно: app.logger = тот же логгер, что во
# всех модулях пакета. template_folder — от каталога панели (panel/
# app.py смотрит на ../templates), не от root_path по import_name.
app = Flask("naivepanel",
            template_folder=str(Path(__file__).resolve().parent.parent
                                  / "templates"))
# Конфиги крошечные — гигантский PUT иначе ронял бы память роутера
app.config["MAX_CONTENT_LENGTH"] = 256 * 1024

# Опечатки в panel.conf не должны молча теряться (NIVEPANEL_BIND и т.п.)
for _k in sorted(set(cfg._CONF_SKIPPED)):
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


# --- Security: хуки auth/CSRF/CSP (логика — panel/security.py) ----------------
# Порядок регистрации воспроизводит исходный: nonce раньше Host-allowlist
# (nonce нужен и на 403-ответах), host/fail-closed/CSRF раньше auth.
app.after_request(sec._security_headers)
app.before_request(sec._make_csp_nonce)
app.context_processor(sec._inject_csp_nonce)
app.before_request(sec._enforce_host_allowlist)
app.before_request(sec._reject_unauthenticated_exposure)
app.before_request(sec._csrf_protect)
app.before_request(sec._require_auth)


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
    return jsonify(mon._status())


@app.route("/api/notify")
def api_notify_get():
    cfgd = mon._notify_snapshot()
    channel = mon._notify_channel(cfgd)
    bot = mon._bot_cache.get(cfgd["token"], (None, 0.0))[0] if cfgd["token"] else None
    return jsonify({
        "channel": channel,
        "enabled": channel is not None,
        "telegram": {"configured": bool(cfgd["token"] and cfgd["chat"]),
                     "chat_id": cfgd["chat"], "bot": bot},
        "pending": len(mon._notify_pending_all()),
    })


@app.route("/api/notify/telegram", methods=["POST"])
def api_notify_telegram_save():
    global _notify_test_last
    sec._require_local_or_auth()
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        data = {}
    token = str(data.get("token") or "").strip()
    chat = str(data.get("chat_id") or "").strip()
    cfgd = mon._notify_snapshot()
    if not token and not (cfgd["token"] and cfgd["chat"]):
        abort(400, description="bot token is required")
    if token and not mon._TG_TOKEN_RE.match(token):
        abort(400, description="bot token format looks wrong (123456:ABC…)")
    if not mon._TG_CHAT_RE.match(chat):
        abort(400, description="chat_id must be numeric or @channel")

    updates: dict[str, str | None] = {"NAIVEPANEL_TG_CHAT": chat}
    if token:
        updates["NAIVEPANEL_TG_TOKEN"] = token
    warning = None
    shadowed = [k for k in updates
                if k in os.environ and k not in cfg._CONF_FILE_KEYS]
    if shadowed:
        warning = ("значение задано через окружение — после рестарта "
                   "оно переопределит сохранённое")
    cfg._conf_upsert(updates)
    with mon._notify_lock:
        if token:
            mon._notify_cfg["token"] = token
        mon._notify_cfg["chat"] = chat
        _notify_test_last = 0.0  # новый канал — тест сразу разрешён
    mon._bot_cache.pop(token, None)
    if cfgd["token"]:
        mon._bot_cache.pop(cfgd["token"], None)
    bot = mon._tg_bot_name(token or cfgd["token"])
    app.logger.info("notify: telegram configured by %s", request.remote_addr)
    return jsonify({"ok": True, "channel": mon._notify_channel(),
                    "telegram": {"configured": True, "chat_id": chat,
                                 "bot": bot},
                    "warning": warning})


@app.route("/api/notify/telegram", methods=["DELETE"])
def api_notify_telegram_delete():
    global _notify_test_last
    sec._require_local_or_auth()
    updates: dict[str, str | None] = {"NAIVEPANEL_TG_TOKEN": None,
                                      "NAIVEPANEL_TG_CHAT": None}
    shadowed = [k for k in updates
                if k in os.environ and k not in cfg._CONF_FILE_KEYS]
    warning = None
    if shadowed:
        warning = ("токен задан через окружение — после рестарта он снова "
                   "включится; уберите его из init-скрипта")
    cfg._conf_upsert(updates)
    with mon._notify_lock:
        mon._notify_cfg["token"] = ""
        mon._notify_cfg["chat"] = ""
        _notify_test_last = 0.0  # после удаления тест не должен троттлиться
    mon._bot_cache.clear()
    if mon._notify_channel() is None:
        # Telegram был единственным путём доставки — очередь и файл больше
        # некуда деть. Если настроен webhook, всё остаётся: события доставимы.
        while True:
            try:
                mon._notify_queue.get_nowait()
            except queue.Empty:
                break
        try:
            mon.NOTIFY_PENDING.unlink()
        except OSError:
            pass
    app.logger.info("notify: telegram disabled by %s", request.remote_addr)
    return jsonify({"ok": True, "channel": mon._notify_channel(),
                    "warning": warning})


_NOTIFY_TEST_MIN = 5.0
_notify_test_last = 0.0


@app.route("/api/notify/test", methods=["POST"])
def api_notify_test():
    global _notify_test_last
    sec._require_local_or_auth()
    if mon._notify_channel() is None:
        abort(409, description="уведомления не настроены")
    now = time.monotonic()
    with mon._notify_lock:
        if now - _notify_test_last < _NOTIFY_TEST_MIN:
            abort(429, description="тестовое сообщение можно отправлять "
                                   "не чаще одного раза в "
                                   f"{int(_NOTIFY_TEST_MIN)} секунд")
        _notify_test_last = now
    ok, err = mon._notify_send("test", "NaivePanel: тестовое уведомление",
                           detail=True)
    if not ok:
        abort(502, description=f"delivery failed: {err}")
    return jsonify({"ok": True})


@app.route("/api/configs")
def api_configs_list():
    resp = jsonify(pres._list_presets())
    resp.headers["Cache-Control"] = "no-store"  # список не должен кешироваться
    return resp


@app.route("/api/configs/<name>", methods=["GET"])
def api_configs_get(name: str):
    if not cfg.NAME_RE.match(name):
        abort(400, description="invalid name")
    cfgd = pres._load_json(cfg.CONF_D / f"{name}.json")
    resp = jsonify(pres._for_edit(cfgd))
    # username и структура ответа не для кеша (SEC-02)
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.route("/api/configs", methods=["POST"])
def api_configs_create():
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    if not cfg.NAME_RE.match(name):
        abort(400, description="invalid name")
    if name in cfg.RESERVED_NAMES:
        abort(400, description=f"name {name!r} is reserved")
    cfgd = pres._build_payload(data)
    pres._validate_cfg(cfgd, name)
    path = cfg.CONF_D / f"{name}.json"
    if path.exists():
        abort(409, description=f"preset {name!r} already exists")
    cfg._ensure_dirs()
    pres._save_json(path, cfgd)
    return jsonify({"name": name, "saved": True}), 201


@app.route("/api/configs/<name>", methods=["PUT"])
def api_configs_update(name: str):
    if not cfg.NAME_RE.match(name):
        abort(400, description="invalid name")
    data = request.get_json(silent=True) or {}
    if "name" in data and data["name"] != name:
        abort(400, description="name in body must match URL")
    path = cfg.CONF_D / f"{name}.json"
    old = pres._load_json(path)  # 404, если пресета нет
    cfgd = pres._build_payload(data, old_proxy=old.get("proxy"))
    pres._validate_cfg(cfgd, name)
    pres._save_json(path, cfgd)
    restart = None
    if pres._active_name() == name:
        # Активный пресет = работающий конфиг: применяем сразу, как activate,
        # иначе «Сохранено» врало бы — файл обновлён, а naive работает старым.
        restart = mon._apply_active(name, cfgd)
    return jsonify({"name": name, "updated": True, "restart": restart})


@app.route("/api/configs/<name>", methods=["DELETE"])
def api_configs_delete(name: str):
    if not cfg.NAME_RE.match(name):
        abort(400, description="invalid name")
    if pres._active_name() == name:
        abort(409, description="cannot delete active preset")
    path = cfg.CONF_D / f"{name}.json"
    if not path.exists():
        abort(404, description=f"preset {name!r} not found")
    path.unlink()
    # цепочка фейловера не должна ссылаться ни на удалённый пресет, ни на
    # прочие stale-имена: mon._load_failover_conf уже отфильтровывает всё, чего
    # нет в conf.d. Пишем нормализованный конфиг только если он отличается
    # от сырых значений — иначе не трогаем файл (в т.ч. битый).
    with mon._FAILOVER_LOCK:
        try:
            raw = json.loads(cfg.FAILOVER_CONF.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            raw = None
        if isinstance(raw, dict):
            conf = mon._load_failover_conf()
            stored = {"enabled": raw.get("enabled"),
                      "chain": raw.get("chain"),
                      "auto_return": raw.get("auto_return")}
            if conf != stored:
                try:
                    pres._save_json(cfg.FAILOVER_CONF, conf)
                except OSError as exc:
                    app.logger.warning(
                        "failover cleanup after deleting %s failed: %s",
                        name, exc)
    return jsonify({"name": name, "deleted": True})


@app.route("/api/configs/<name>/activate", methods=["POST"])
def api_configs_activate(name: str):
    return jsonify(mon._activate_preset(name))


@app.route("/api/configs/<name>/duplicate", methods=["POST"])
def api_configs_duplicate(name: str):
    """Копия пресета целиком, server-side — включая пароль.

    Через UI (GET → форма → POST) пароль не переносится: GET его не отдаёт,
    а create требует креды для host-only upstream. Копирование файла на
    сервере сохраняет работоспособный конфиг без повторного ввода секрета.
    """
    if not cfg.NAME_RE.match(name):
        abort(400, description="invalid name")
    src = cfg.CONF_D / f"{name}.json"
    if not src.exists():
        abort(404, description=f"preset {name!r} not found")
    cfgd = pres._load_json(src)
    # имя копии: name-copy, при занятости name-copy2, name-copy3… cfg.NAME_RE
    # допускает 64 символа — урезаем базу, чтобы суффикс всегда влез
    base = f"{name}-copy"[:58]
    candidate, n = base, 2
    while (cfg.CONF_D / f"{candidate}.json").exists():
        if n > 99:
            abort(409, description=f"too many copies of {name!r}")
        candidate = f"{base}{n}"
        n += 1
    pres._save_json(cfg.CONF_D / f"{candidate}.json", cfgd)
    return jsonify({"name": candidate, "copied_from": name}), 201


@app.route("/api/configs/export")
def api_configs_export():
    """Все пресеты одним JSON-файлом — бэкап / миграция на другой роутер.

    ВАЖНО: содержит proxy-URI с паролями — иначе восстановление теряло бы
    креды и не было бы бэкапом. Это единственный GET, отдающий секреты:
    осознанное действие пользователя (Content-Disposition: attachment —
    файл уходит в Downloads, а не в кеш браузера).
    """
    cfg._ensure_dirs()
    presets: dict[str, Any] = {}
    for p in sorted(cfg.CONF_D.glob("*.json")):
        try:
            presets[p.stem] = pres._load_json(p)
        except Exception as exc:  # битый файл не должен ронять весь экспорт
            app.logger.warning("export: skipping %s: %s", p.name, exc)
    fo = mon._load_failover_conf()
    # цепочка должна ссылаться только на реально экспортированные пресеты:
    # нечитаемый файл пропущен выше, и импорт такой цепочки провалился бы.
    fo["chain"] = [n for n in fo["chain"] if n in presets]
    fo["enabled"] = fo["enabled"] and bool(fo["chain"])
    fo["auto_return"] = fo["auto_return"] and fo["enabled"]
    resp = jsonify({
        "format": 1,
        "version": cfg.APP_VERSION,
        "exported": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "presets": presets,
        "failover": fo,
    })
    resp.headers["Content-Disposition"] = 'attachment; filename="naivepanel-presets.json"'
    resp.headers["Cache-Control"] = "no-store"  # ответ содержит секреты
    return resp


@app.route("/api/configs/import", methods=["POST"])
def api_configs_import():
    """Импорт пресетов из файла export-формата (поле presets: {name: cfg}).

    Существующие имена НЕ перезаписываются (причина — в ответе), каждый
    пресет проходит _validate_cfg — файл мог быть отредактирован руками.
    Блок failover применяется только на «пустой» цели: существующая цепочка
    не перезаписывается. Лимит тела 256 КБ (MAX_CONTENT_LENGTH) покрывает
    ~сотни пресетов.
    """
    data = request.get_json(silent=True) or {}
    incoming = data.get("presets")
    if not isinstance(incoming, dict):
        abort(400, description="expected {presets: {name: config}}")
    imported: list[str] = []
    skipped: list[dict[str, str]] = []
    for name, pc in sorted(incoming.items()):
        if not cfg.NAME_RE.match(name or ""):
            skipped.append({"name": name, "reason": "invalid name"})
            continue
        if name in cfg.RESERVED_NAMES:
            skipped.append({"name": name, "reason": "reserved name"})
            continue
        if not isinstance(pc, dict):
            skipped.append({"name": name, "reason": "expected object"})
            continue
        try:
            pres._validate_cfg(pc, name)
        except HTTPException as exc:
            skipped.append({"name": name, "reason": str(exc.description)})
            continue
        if (cfg.CONF_D / f"{name}.json").exists():
            skipped.append({"name": name, "reason": "already exists"})
            continue
        pres._save_json(cfg.CONF_D / f"{name}.json", pc)
        imported.append(name)
    fo_res: dict[str, Any] = {"applied": False, "reason": "no failover block"}
    incoming_fo = data.get("failover")
    if incoming_fo is not None:
        if not isinstance(incoming_fo, dict):
            fo_res = {"applied": False, "reason": "failover: expected object"}
        else:
            enabled = incoming_fo.get("enabled", False)
            chain = incoming_fo.get("chain")
            reason = None
            # Блокер-цель проверяем ДО разбора входящей цепочки: на роутере
            # с рабочей цепочкой причина должна быть про цель, а не про
            # случайный мусор в импортируемом файле.
            if mon._load_failover_conf()["chain"]:
                reason = "target already has a failover chain"
            elif not isinstance(enabled, bool):
                reason = "enabled must be boolean"
            elif "auto_return" in incoming_fo and not isinstance(
                    incoming_fo["auto_return"], bool):
                reason = "auto_return must be boolean"
            elif not isinstance(chain, list) or not all(
                    isinstance(n, str) for n in chain):
                reason = "failover chain must be a list of names"
            elif len(chain) > cfg.FAILOVER_CHAIN_MAX:
                reason = f"failover chain too long (max {cfg.FAILOVER_CHAIN_MAX})"
            elif len(set(chain)) != len(chain):
                reason = "failover chain has duplicates"
            elif not all(cfg.NAME_RE.match(n) for n in chain):
                reason = "failover chain has invalid preset names"
            elif not enabled and not chain:
                reason = "empty failover block"
            elif enabled and not chain:
                reason = "enabled failover needs a non-empty chain"
            elif incoming_fo.get("auto_return") is True and not enabled:
                # зеркало PUT: не понижаем молча в auto_return:false
                reason = "auto_return requires enabled chain"
            if reason is None:
                available = {p.stem for p in cfg.CONF_D.glob("*.json")}
                missing = [n for n in chain if n not in available]
                if missing:
                    reason = "unknown presets: " + ", ".join(missing)
            if reason is not None:
                fo_res = {"applied": False, "reason": reason}
            else:
                auto = incoming_fo.get("auto_return") is True
                # check-and-set под локом: параллельный PUT не должен
                # перезаписать уже существующую цепочку
                with mon._FAILOVER_LOCK:
                    if mon._load_failover_conf()["chain"]:
                        fo_res = {"applied": False,
                                  "reason": "target already has a failover chain"}
                    else:
                        # пресет мог исчезнуть после первой проверки —
                        # существование перепроверяем прямо перед записью
                        available = {p.stem for p in cfg.CONF_D.glob("*.json")}
                        missing = [n for n in chain if n not in available]
                        if missing:
                            fo_res = {"applied": False,
                                      "reason": "unknown presets: "
                                                + ", ".join(missing)}
                        else:
                            cfg._ensure_dirs()
                            pres._save_json(cfg.FAILOVER_CONF,
                                       {"enabled": enabled, "chain": chain,
                                        "auto_return": auto})
                            fo_res = {"applied": True, "reason": None}
    if imported:
        app.logger.info("import: created %s", ", ".join(imported))
    return jsonify({"imported": imported, "skipped": skipped,
                    "failover": fo_res})


@app.route("/api/probe", methods=["POST"])
def api_probe():
    """TCP-доступность upstream: коннект с роутера, таймаут 3с.

    Отличает «прокси лежит» от «сеть/файрвол»: панель ходит с того же хоста,
    что и naive. Только TCP-коннект — без TLS-хендшейка и без отправки
    кредов; недоступность — это нормальный ответ 200 с полем error.
    """
    data = request.get_json(silent=True) or {}
    ep = pres._upstream_endpoint(data.get("upstream") or "")
    if not ep:
        abort(400, description="upstream required (host[:port] or URI)")
    host, port = ep
    if not mon._EXPENSIVE_SEM.acquire(blocking=False):
        abort(429, description="too many concurrent checks, try later")
    t0 = time.monotonic()
    try:
        with socket.create_connection(ep, timeout=3.0):
            pass
        return jsonify({"host": host, "port": port,
                        "ms": round((time.monotonic() - t0) * 1000)})
    except OSError as exc:  # refused/timeout/DNS — не ошибка панели
        return jsonify({"host": host, "port": port, "error": str(exc)})
    finally:
        mon._EXPENSIVE_SEM.release()


@app.route("/api/service/<action>", methods=["POST"])
def api_service(action: str):
    if action not in {"start", "stop", "restart"}:
        abort(400, description="action must be start|stop|restart")
    with mon._SERVICE_LOCK:
        return jsonify(svc._service(action))


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
        listen = mon._active_listen()
        if not listen:
            abort(400, description="no active preset with listen: activate a preset first")
    if not mon._EXPENSIVE_SEM.acquire(blocking=False):
        abort(429, description="too many concurrent checks, try later")
    try:
        resp = jsonify(mon._proxy_e2e_check(listen))
    finally:
        mon._EXPENSIVE_SEM.release()
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
    last = max(1, min(last, cfg.E2E_KEEP))
    entries = mon._e2e_history_load(last)
    ok_n = sum(1 for e in entries if e["ok"])
    n = len(entries)
    avg_ms = round(sum(e["ms"] for e in entries) / n) if n else None
    resp = jsonify({
        "entries": entries,
        "keep": cfg.E2E_KEEP,
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
    resp = jsonify(mon._failover.snapshot())
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.route("/api/failover", methods=["PUT"])
def api_failover_put():
    """Задать цепочку: {"enabled": true, "chain": ["home", "backup"]}.

    Имена валидируются как у пресетов и проверяются на существование —
    опечатка не должна остаться в цепочке до первого сбоя. Цепочка
    валидируется и при enabled=false: сохранённая цепочка остаётся
    рабочей для следующего включения. Если при выключении chain не
    передан вовсе — сохраняется текущая (старые клиенты).
    """
    data = request.get_json(silent=True) or {}
    enabled = data.get("enabled", False)
    if not isinstance(enabled, bool):
        abort(400, description="enabled must be boolean")
    chain_raw = data.get("chain")
    # read-modify-write failover.json: chain-less PUT читает текущую цепочку,
    # поэтому чтение, зависящая от неё валидация и запись — под одним локом.
    with mon._FAILOVER_LOCK:
        if chain_raw is None:
            if enabled:
                abort(400, description="chain required (non-empty list) when enabled")
            chain_raw = mon._load_failover_conf()["chain"]
        if not isinstance(chain_raw, list):
            abort(400, description="chain must be a list")
        if len(chain_raw) > cfg.FAILOVER_CHAIN_MAX:
            abort(400, description=f"chain too long (max {cfg.FAILOVER_CHAIN_MAX})")
        seen: set[str] = set()
        for name in chain_raw:
            if not isinstance(name, str) or not cfg.NAME_RE.match(name):
                abort(400, description=f"invalid preset name: {name!r}")
            if name in seen:
                abort(400, description=f"duplicate preset in chain: {name!r}")
            seen.add(name)
            if not (cfg.CONF_D / f"{name}.json").exists():
                abort(404, description=f"preset {name!r} not found")
        if enabled and not chain_raw:
            abort(400, description="chain required (non-empty list) when enabled")
        auto_return = data.get("auto_return", False)
        if not isinstance(auto_return, bool):
            abort(400, description="auto_return must be boolean")
        # авто-возврат осмыслен только с включённым фейловером
        if auto_return and not enabled:
            abort(400, description="auto_return requires enabled chain")
        cfg._ensure_dirs()
        pres._save_json(cfg.FAILOVER_CONF, {"enabled": enabled, "chain": chain_raw,
                                   "auto_return": auto_return})
    return jsonify(mon._failover.snapshot())


@app.route("/api/failover", methods=["DELETE"])
def api_failover_delete():
    with mon._FAILOVER_LOCK:
        try:
            cfg.FAILOVER_CONF.unlink()
        except FileNotFoundError:
            pass
        except OSError as exc:
            abort(500, description=f"cannot remove failover.json: {exc}")
    return jsonify(mon._failover.snapshot())


@app.route("/api/panel/restart", methods=["POST"])
def api_panel_restart():
    """Перезапуск самой панели: отсоединённо spawn'ит `S99naivepanel restart`.

    Init-скрипт через ~1с (sleep даёт ответ уйти) убивает текущий процесс и
    поднимает новый. Используется после обновления naivepanel.py/templates,
    чтобы не логиниться по SSH ради `/opt/etc/init.d/S99naivepanel restart`.
    """
    if not cfg.PANEL_INIT.exists():
        abort(503, description=f"{cfg.PANEL_INIT} not found")
    # Новая сессия → ребёнок переживёт смерть Flask-процесса. Путь — через
    # окружение, не позиционные аргументы -c: busybox на Keenetic их не
    # передаёт (тот же баг, что молча убивал self-update в v0.9.0–v0.9.1).
    # Команда фиксированная.
    env = {**os.environ, "NP_INIT": str(cfg.PANEL_INIT)}
    subprocess.Popen(  # nosec B603
        ["/bin/sh", "-c", 'sleep 1; exec /bin/sh "$NP_INIT" restart'],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    app.logger.warning("panel self-restart triggered by %s", request.remote_addr)
    return jsonify({"restart": True, "note": "panel restarting in ~1s"}), 202


@app.route("/api/password", methods=["POST"])
def api_password():
    """Смена пароля текущего Basic-пользователя без SSH и рестарта."""
    try:
        stored = cfg.PANEL_ADMIN_PASS.read_text(encoding="utf-8")
    except OSError:
        abort(409, description="auth is disabled — no admin.pass to update")
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        data = {}
    current = data.get("current")
    new = data.get("new")
    auth = request.authorization
    user = (auth.username if auth else "") or ""
    if not user:
        abort(401, description="authentication required")
    # str() по объекту/number дал бы «пароль» из repr и 200 — UI-баг молча
    # поставил бы непригодные креды
    if not isinstance(current, str) or not isinstance(new, str):
        abort(400, description="current and new must be strings")
    if not sec._htpasswd_verify(stored, user, current):
        abort(400, description="current password is incorrect")
    if not 8 <= len(new.encode("utf-8")) <= 72:
        abort(400, description="new password must be 8–72 bytes")
    sec._write_admin_pass(user, new)
    app.logger.info("password changed: user=%r addr=%s", user,
                    request.remote_addr)
    return jsonify({"ok": True})


@app.route("/api/update/check")
def api_update_check():
    """Есть ли свежий релиз: cfg.APP_VERSION против тегов GitHub.

    Результат кэшируется на 6ч (?force=1 обходит кэш). Сеть/GitHub
    недоступны — 200 с полем error и available=false: UI показывает это
    тихой строкой, а не ошибкой.
    """
    force = request.args.get("force") in ("1", "true")
    arrived = time.monotonic()
    if not force and upd._update_check_cache:
        if arrived - upd._update_check_cache["at"] < upd._update_check_cache.get("ttl", cfg._UPDATE_CHECK_TTL):
            out = dict(upd._update_check_cache["data"])
            out["cached"] = True
            return jsonify(out)
    with mon._UPDATE_FETCH_LOCK:
        # кэш, заполненный ПОСЛЕ нашего прихода, — результат соседа по
        # залпу: берём его, второй внешний ход не нужен (в т.ч. для force —
        # его смысл «свежее, чем у меня», а не «обязательно лично сходить»;
        # сольный force после свежего чека ходит в сеть как раньше)
        if upd._update_check_cache and upd._update_check_cache["at"] >= arrived:
            out = dict(upd._update_check_cache["data"])
            out["cached"] = True
            return jsonify(out)
        if not mon._EXPENSIVE_SEM.acquire(blocking=False):
            abort(429, description="too many concurrent checks, try later")
        try:
            checked = time.strftime("%Y-%m-%dT%H:%M:%S%z")
            try:
                rel = upd._latest_release()
            except RuntimeError as exc:
                out = {"current": cfg.APP_VERSION, "latest": None, "available": False,
                       "error": str(exc), "checked_at": checked}
                # at = момент заполнения, не входа в лок: сосед по залпу,
                # пришедший позже входа, должен увидеть at >= своего прихода
                upd._update_check_cache.update({"at": time.monotonic(),
                                            "ttl": cfg._UPDATE_ERR_TTL, "data": out})
                return jsonify(out)
            latest = rel["tag"].lstrip("vV")
            out = {
                "current": cfg.APP_VERSION,
                "latest": latest,
                "available": upd._ver_key(latest) > upd._ver_key(cfg.APP_VERSION),
                "notes": rel["notes"],
                "url": rel["url"],
                "checked_at": checked,
            }
            upd._update_check_cache.update({"at": time.monotonic(),
                                        "ttl": cfg._UPDATE_CHECK_TTL, "data": out})
            return jsonify(out)
        finally:
            mon._EXPENSIVE_SEM.release()


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
    sec._require_local_or_auth()
    # сетевая фаза (резолв + скачивание install.sh) — до лока: секунды
    # ожидания не должны блокировать конкурентный запрос, который после
    # re-check под локом получит честный 409
    try:
        rel = upd._latest_release()
    except RuntimeError as exc:
        abort(502, description=str(exc))
    tag = rel["tag"]
    try:
        installer = mon._http_get(f"{cfg.UPDATE_RAW_BASE}/{cfg.UPDATE_REPO}/{tag}/install.sh",
                              timeout=30.0)
    except RuntimeError as exc:
        abort(502, description=f"cannot download install.sh@{tag}: {exc}")
    with upd._UPDATE_LAUNCH_LOCK:
        state = upd._update_state()
        if state.get("phase") == "running" and not state.get("stale"):
            abort(409, description=f"update to {state.get('target')} already in "
                                   f"progress — installer log: {cfg.UPDATE_LOG}")
        try:
            cfg.PANEL_DIR.mkdir(parents=True, exist_ok=True)
            # бэкап заменяемых файлов — для отката из UI после неудачного апдейта
            upd._backup_panel_files()
            stage = cfg.PANEL_DIR / ".update-install.sh"
            stage.write_text(installer, encoding="utf-8")
            os.chmod(stage, 0o700)
            cfg.UPDATE_LOG.parent.mkdir(parents=True, exist_ok=True)
            # Пролог панелью, а не установщиком: реальный кейс (v0.9.0, роутер) —
            # ребёнок умер до первой строки скрипта (OOM при exec) и лог остался
            # пустым, ничего не отличалось от «лог не создан». Теперь пустой лог
            # после пролога сам по себе диагноз.
            cfg.UPDATE_LOG.write_text(
                f"== self-update {cfg.APP_VERSION} -> {tag}, "
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
               "NP_STAGE": str(stage), "NP_TAG": tag, "NP_LOG": str(cfg.UPDATE_LOG)}
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
            # спавн не удался — не оставляем «ничего не происходило»:
            # фиксируем failed в той же критической секции
            upd._update_state_write({"phase": "failed", "target": tag,
                                 "finished": time.time(),
                                 "error": f"cannot spawn installer: {exc}"})
            abort(500, description=f"cannot spawn installer: {exc}")
        # pid в state: умерший установщик распознаётся при следующем же запросе,
        # а не через 15 минут (upd._update_state помечает такой state «failed»)
        upd._update_state_write({"phase": "running", "target": tag,
                             "started": time.time(), "pid": proc.pid})
    app.logger.warning("self-update to %s triggered by %s", tag, request.remote_addr)
    return jsonify({"started": True, "target": tag, "current": cfg.APP_VERSION,
                    "log": str(cfg.UPDATE_LOG)}), 202


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
                    "content": mon._tail_path(cfg.UPDATE_LOG, lines),
                    "panel": mon._tail_path(cfg.PANEL_LOG, 20),
                    "state": upd._update_state()})
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.route("/api/naive/check")
def api_naive_check():
    """Версия бинарника naive против последнего релиза klzgrad/naiveproxy.

    Текущая версия — из маркера (точный тег) с фолбэком на `naive --version`
    (бинарник, поставленный руками, маркера не имеет). Сеть/GitHub недоступны
    — 200 с error и available=False, как у /api/update/check.
    """
    force = request.args.get("force") in ("1", "true")
    arrived = time.monotonic()
    if not force and upd._naive_check_cache:
        if arrived - upd._naive_check_cache["at"] < upd._naive_check_cache.get("ttl", cfg._NAIVE_CHECK_TTL):
            out = dict(upd._naive_check_cache["data"])
            out["cached"] = True
            return jsonify(out)
    with mon._NAIVE_FETCH_LOCK:
        # коалесцирование, как у /api/update/check (см. mon._UPDATE_FETCH_LOCK)
        if upd._naive_check_cache and upd._naive_check_cache["at"] >= arrived:
            out = dict(upd._naive_check_cache["data"])
            out["cached"] = True
            return jsonify(out)
        if not mon._EXPENSIVE_SEM.acquire(blocking=False):
            abort(429, description="too many concurrent checks, try later")
        try:
            checked = time.strftime("%Y-%m-%dT%H:%M:%S%z")
            version = upd._naive_bin_version()
            tag = upd._naive_read(cfg.NAIVE_TAG)
            out: dict[str, Any] = {
                "version": version,
                "tag": tag,
                "path": str(cfg.NAIVE_BIN) if cfg.NAIVE_BIN.exists() else None,
                "target": upd._naive_read(cfg.NAIVE_BUILD) or upd._naive_detect_target(),
                "checked_at": checked,
            }
            try:
                rel = upd._naive_release()
            except (RuntimeError, ValueError) as exc:
                out.update({"latest": None, "available": False, "error": str(exc)})
                # at = момент заполнения (см. /api/update/check)
                upd._naive_check_cache.update({"at": time.monotonic(),
                                           "ttl": cfg._NAIVE_ERR_TTL, "data": out})
                return jsonify(out)
            latest = rel["tag"]
            cur = upd._naive_ver_key(tag) if tag else (upd._naive_ver_key(version) if version else None)
            out.update({"latest": latest,
                        "available": cur is None or upd._naive_ver_key(latest) > cur,
                        "notes": rel["notes"], "url": rel["url"]})
            upd._naive_check_cache.update({"at": time.monotonic(),
                                       "ttl": cfg._NAIVE_CHECK_TTL, "data": out})
            return jsonify(out)
        finally:
            mon._EXPENSIVE_SEM.release()


@app.route("/api/naive/update", methods=["POST"])
def api_naive_update():
    """Обновление (или первичная установка) бинарника naive фоновым потоком.

    Панель сама не перезапускается — воркер меняет только /opt/bin/naive и
    перезапускает прокси, если тот работал. Отсюда гейт как у /api/update/
    apply: замена root-исполняемого файла в LAN без auth недопустима.
    """
    sec._require_local_or_auth()
    # резолв релиза — по сети, до лока (см. upd._NAIVE_UPDATE_LAUNCH_LOCK)
    try:
        rel = upd._naive_release()
    except (RuntimeError, ValueError) as exc:
        abort(502, description=str(exc))
    tag = rel["tag"]
    with upd._NAIVE_UPDATE_LAUNCH_LOCK:
        st = upd._naive_state()
        if st.get("phase") == "running" and not st.get("stale"):
            abort(409, description=f"naive update to {st.get('target')} already "
                                   f"in progress — log: {cfg.NAIVE_UPDATE_LOG}")
        try:
            cfg.NAIVE_UPDATE_LOG.parent.mkdir(parents=True, exist_ok=True)
            cfg.NAIVE_UPDATE_LOG.write_text(
                f"== naive binary update -> {tag}, "
                f"{time.strftime('%Y-%m-%d %H:%M:%S')}\n", encoding="utf-8")
        except OSError:
            pass  # лог не критичен
        upd._naive_state_write({"phase": "running", "target": tag,
                            "started": time.time()})
        try:
            threading.Thread(target=upd._naive_update_worker, name="naive-update",
                             daemon=True).start()
        except RuntimeError as exc:
            # поток не создался — не висеть «running» до тайм-аута stale
            upd._naive_state_write({"phase": "failed", "target": tag,
                                "finished": time.time(),
                                "error": f"cannot start worker: {exc}"})
            abort(500, description=f"cannot start update worker: {exc}")
    app.logger.warning("naive binary update to %s triggered by %s",
                       tag, request.remote_addr)
    return jsonify({"started": True, "target": tag, "log": str(cfg.NAIVE_UPDATE_LOG)}), 202


@app.route("/api/naive/status")
def api_naive_status():
    """State обновления бинарника + хвост лога (UI поллит из диалога)."""
    try:
        lines = int(request.args.get("lines", "40"))
    except ValueError:
        lines = 40
    resp = jsonify({"lines": lines,
                    "content": mon._tail_path(cfg.NAIVE_UPDATE_LOG, lines),
                    "state": upd._naive_state()})
    resp.headers["Cache-Control"] = "no-store"
    return resp


# --- Rollback: откат панели и бинарника из бэкапов, без SSH -------------------
# Self-update перед заменой снапшотит файлы в panel/backup/vX.Y.Z/, обновление
# бинарника — в proxy/backup/naive.previous. До v0.15 доставать их можно было
# только руками по SSH — ровно тот случай, когда консоли под рукой нет. Здесь
# — чтение бэкапов, восстановление и чистка: откат панели перезапускает её саму
# (панель продолжает работать старым кодом, пока файлы не вернутся на место),
# откат бинарника — тот же паттерн, что обновление: rename + рестарт сервиса.

@app.route("/api/rollback")
def api_rollback_get():
    """Что можно откатить: версии панели в backup/ + прошлый бинарник.

    Тег бинарника — из naive.previous.tag (пишется с v0.15; у более старых
    бэкапов неизвестен, UI так и показывает). Сам бэкап не запускаем: GET
    должен остаться дешёвым.
    """
    binary: dict[str, Any] = {"present": False, "tag": None, "size": 0}
    try:
        if upd.NAIVE_PREV_BIN.is_file():
            binary = {"present": True,
                      "tag": upd._naive_read(upd.NAIVE_PREV_TAG),
                      "size": upd.NAIVE_PREV_BIN.stat().st_size}
    except OSError:
        pass
    return jsonify({"current": cfg.APP_VERSION,
                    "panel": upd._rollback_panel_versions(),
                    "binary": binary})



@app.route("/api/rollback", methods=["POST"])
def api_rollback_post():
    """Откат панели на версию из backup/ или бинарника на naive.previous.

    Тело: {"panel": "vX.Y.Z"} или {"binary": true}. Замена кода панели и
    root-бинарника — гейт как у update/apply: без пароля только loopback.
    Откат панели тоже снапшотит текущие файлы — обратим в обе стороны.
    """
    sec._require_local_or_auth()
    body = request.get_json(silent=True) or {}
    if body.get("binary"):
        # откат бинарника синхронный: гейт + сама операция — под тем же
        # локом, что и запуск naive-update воркера (state у них общий)
        with upd._NAIVE_UPDATE_LAUNCH_LOCK:
            st = upd._naive_state()
            if st.get("phase") == "running" and not st.get("stale"):
                abort(409, description=f"naive update to {st.get('target')} already "
                                       f"in progress — log: {cfg.NAIVE_UPDATE_LOG}")
            return upd._rollback_binary()
    version = str(body.get("panel") or "")
    if not cfg._TAG_RE.match(version):
        abort(400, description="bad version name — expected vX.Y.Z")
    if version.lstrip("vV") == cfg.APP_VERSION:
        abort(400, description=f"v{cfg.APP_VERSION} is already running")
    backup = cfg.PANEL_DIR / "backup" / version
    if not (backup / "naivepanel.py").is_file():
        abort(404, description=f"no usable backup {version} "
                               f"(need naivepanel.py inside)")
    with upd._UPDATE_LAUNCH_LOCK:
        # state общий с update/apply: re-check под локом (см. upd._UPDATE_LAUNCH_LOCK)
        state = upd._update_state()
        if state.get("phase") == "running" and not state.get("stale"):
            abort(409, description=f"update to {state.get('target')} already in "
                                   f"progress — installer log: {cfg.UPDATE_LOG}")
        if not cfg.PANEL_INIT.exists():
            abort(503, description=f"{cfg.PANEL_INIT} not found")
        try:
            upd._backup_panel_files()   # откат обратим: текущая версия — тоже в бэкап
            restored = []
            for dst in cfg.PANEL_UPDATE_FILES:
                src = backup / dst.name
                if not src.is_file():
                    continue
                # через tmp+rename: середина файла не мелькает на диске, а живущий
                # в памяти процесс вообще ничего не замечает до рестарта
                tmp = dst.with_name(dst.name + ".restore")
                shutil.copy2(src, tmp)
                os.replace(tmp, dst)
                restored.append(dst.name)
            pkg_backup = backup / "panel"
            if pkg_backup.is_dir():
                # недостающие файлы пакета докатываем точечно: новый файл из
                # старого бэкапа не должен переживать откат молча
                (cfg.PANEL_DIR / "panel").mkdir(parents=True, exist_ok=True)
                for src in pkg_backup.glob("*.py"):
                    dst = cfg.PANEL_DIR / "panel" / src.name
                    tmp = dst.with_name(dst.name + ".restore")
                    shutil.copy2(src, tmp)
                    os.replace(tmp, dst)
                    restored.append("panel/" + src.name)
            if "naivepanel.py" not in restored:  # проверено выше, но после копий — надёжнее
                abort(500, description="restore produced no naivepanel.py")
            cfg.UPDATE_LOG.parent.mkdir(parents=True, exist_ok=True)
            cfg.UPDATE_LOG.write_text(
                f"== rollback {cfg.APP_VERSION} -> {version}, "
                f"spawn {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
                f"restored: {', '.join(restored)}\n",
                encoding="utf-8")
        except OSError as exc:
            abort(500, description=f"cannot restore files: {exc}")
        # перезапуск — тот же отсоединённый spawn, что /api/panel/restart:
        # путь через env (NP_INIT), не позиционные аргументы busybox
        env = {**os.environ, "NP_INIT": str(cfg.PANEL_INIT)}
        try:
            proc = subprocess.Popen(  # nosec B603
                ["/bin/sh", "-c", 'sleep 1; exec /bin/sh "$NP_INIT" restart'],
                env=env,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
        except OSError as exc:
            upd._update_state_write({"phase": "failed", "target": version,
                                 "finished": time.time(),
                                 "error": f"cannot spawn restarter: {exc}"})
            abort(500, description=f"cannot spawn restarter: {exc}")
        # state переиспользуем от update: поднятая старая панель увидит цель,
        # равную своей версии, и закроет «running» как «done»
        upd._update_state_write({"phase": "running", "target": version,
                             "started": time.time(), "pid": proc.pid,
                             "rollback": True})
    app.logger.warning("rollback to %s triggered by %s", version,
                       request.remote_addr)
    return jsonify({"started": True, "target": version,
                    "current": cfg.APP_VERSION, "restored": restored,
                    "log": str(cfg.UPDATE_LOG)}), 202


@app.route("/api/rollback/<version>", methods=["DELETE"])
def api_rollback_delete(version: str):
    """Удалить один бэкап панели (строгий vX.Y.Z; текущая версия в бэкапах
    не лежит — удалять можно любой). Автоочистки нет: место занимает только
    по явному решению."""
    if not cfg._TAG_RE.match(version):
        abort(400, description="bad version name — expected vX.Y.Z")
    target = cfg.PANEL_DIR / "backup" / version
    if not target.is_dir():
        abort(404, description=f"no backup {version}")
    try:
        shutil.rmtree(target)
    except OSError as exc:
        abort(500, description=f"cannot remove {version}: {exc}")
    left = [v["version"] for v in upd._rollback_panel_versions()]
    app.logger.info("backup %s removed by %s, left: %s", version,
                    request.remote_addr, ", ".join(left) or "none")
    return jsonify({"deleted": version, "left": left})


@app.route("/api/rollback/cleanup", methods=["POST"])
def api_rollback_cleanup():
    """Удалить все бэкапы панели, кроме N новейших (по умолчанию 1).

    Типовой сценарий: «оставить ближайший откат, хвост из десятка версий
    убрать» — без выкалачивания крестиков по одному.
    """
    body = request.get_json(silent=True) or {}
    keep = body.get("keep", 1)
    if not isinstance(keep, int) or isinstance(keep, bool) or keep < 0:
        abort(400, description="keep must be a non-negative integer")
    versions = upd._rollback_panel_versions()
    removed = []
    for v in versions[keep:]:
        try:
            shutil.rmtree(cfg.PANEL_DIR / "backup" / v["version"])
        except OSError as exc:
            abort(500, description=f"cannot remove {v['version']}: {exc}")
        removed.append(v["version"])
    if removed:
        app.logger.info("backups removed by %s: %s", request.remote_addr,
                        ", ".join(removed))
    return jsonify({"removed": removed,
                    "left": [v["version"] for v in upd._rollback_panel_versions()]})


# Лог какого хвоста показывать: по умолчанию — naive, src=panel — сама панель
LOG_SOURCES: dict[str, Path] = {"proxy": cfg.LOG_FILE, "panel": cfg.PANEL_LOG}


@app.route("/api/logs")
def api_logs():
    try:
        lines = int(request.args.get("lines", "100"))
    except ValueError:
        lines = 100
    path = LOG_SOURCES.get(request.args.get("src", "proxy"), cfg.LOG_FILE)
    resp = jsonify({"lines": lines, "content": mon._tail_path(path, lines)})
    resp.headers["Cache-Control"] = "no-store"  # логи могут содержать креды
    return resp


__all__ = [
    "_NOTIFY_TEST_MIN",
    "_api_json_errors",
    "_notify_test_last",
    "api_configs_activate",
    "api_configs_create",
    "api_configs_delete",
    "api_configs_duplicate",
    "api_configs_export",
    "api_configs_get",
    "api_configs_import",
    "api_configs_list",
    "api_configs_update",
    "api_e2e",
    "api_e2e_history",
    "api_failover_delete",
    "api_failover_get",
    "api_failover_put",
    "api_logs",
    "api_naive_check",
    "api_naive_status",
    "api_naive_update",
    "api_notify_get",
    "api_notify_telegram_delete",
    "api_notify_telegram_save",
    "api_notify_test",
    "api_panel_restart",
    "api_password",
    "api_probe",
    "api_rollback_cleanup",
    "api_rollback_delete",
    "api_rollback_get",
    "api_rollback_post",
    "api_service",
    "api_status",
    "api_update_apply",
    "api_update_check",
    "api_update_log",
    "app",
    "index",
]
