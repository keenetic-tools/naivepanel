"""CRUD и валидация пресетов naive (шаг 3/7, ARCH-01).

Хранилище: один JSON-файл на пресет в CONF_D, активный — ACTIVE_CONFIG +
ACTIVE_POINTER (имя). Пароль в API не отдаём (GET/_for_edit), маскируем в
списках и логах (_mask_creds). Запись атомарная (mkstemp + os.replace, 0600):
пресеты содержат креды.

Перенесено из naivepanel.py дословно. Конфигурация — через атрибут
модуля-владельца (`cfg.CONF_D`, `cfg.NAME_RE`, ...): патчи тестов на
`app.cfg.*` и перечитывание env при reload видны здесь. Логгер — тот же
'naivepanel' (см. panel/config.py).
"""

import json
import logging
import os
import re
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import quote, unquote

from flask import abort

from panel import config as cfg

log = logging.getLogger("naivepanel")


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
    """Atomic write + chmod 0600 — пресеты тоже могут содержать креденшалы.

    tmp уникален (mkstemp в каталоге target): общий `<name>.tmp` делал
    параллельные записи одного файла гонкой — replace первого потока удалял
    tmp из-под второго. Уникальность устраняет гонку файлов; порядок
    «кто последний, тот и прав» сериализуется caller-lock'ами (REL-02).
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp")
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            os.fchmod(fh.fileno(), 0o600)
            json.dump(data, fh, indent=2, sort_keys=False)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)
    # os.replace сохраняет режим tmp-файла, но на overlay FS перестрахуемся
    os.chmod(path, 0o600)


def _write_active(name: str, cfgd: dict[str, Any]) -> None:
    cfg.NAIVEPROXY_DIR.mkdir(parents=True, exist_ok=True)
    _save_json(cfg.ACTIVE_CONFIG, cfgd)
    cfg.ACTIVE_POINTER.write_text(name + "\n", encoding="utf-8")
    os.chmod(cfg.ACTIVE_POINTER, 0o600)


def _active_name() -> str | None:
    if not cfg.ACTIVE_POINTER.exists():
        return None
    try:
        name = cfg.ACTIVE_POINTER.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return name if cfg.NAME_RE.match(name) else None


def _split_proxy(proxy: str) -> tuple[str, str, str | None]:
    """Разбирает proxy-URI на (upstream, username, password).

    Все поддерживаемые схемы (https/http/quic) несут креды одинаково:
    `scheme://user:pass@host`. Пароль выделяется от последнего `@`
    (легаси-конфиги с raw `@` в пароле тоже читаются), username — до первого
    `:` в кредах, затем оба unquote. Схема вне allowlist или кредов нет —
    upstream возвращается целиком, password=None (кредов не выделить).
    """
    idx = proxy.find("://")
    if idx != -1 and proxy[:idx].lower() in ("https", "http", "quic"):
        rest = proxy[idx + 3:]
        at = rest.rfind("@")
        if at != -1:
            creds, host = rest[:at], rest[at + 1:]
            colon = creds.find(":")
            if colon != -1:
                return host, unquote(creds[:colon]), unquote(creds[colon + 1:])
    return proxy, "", None


def _for_edit(cfgd: dict[str, Any]) -> dict[str, Any]:
    """Конфигурация для формы редактирования — БЕЗ пароля.

    upstream и username отдаются уже разобранными, чтобы фронтенду не пришлось
    самому парсить proxy-URI (и ломаться на `@` в пароле). Пароль через API
    не возвращается вовсе: пустое поле в форме означает «оставить прежний».
    """
    upstream, username, _ = _split_proxy(cfgd.get("proxy") or "")
    if "@" in upstream and "://" in upstream:
        # нестандартная схема с кредами не разобрана _split_proxy —
        # маскируем userinfo на выходе (SEC-02, defense-in-depth)
        upstream = _mask_creds(upstream)
    out = {k: v for k, v in cfgd.items() if k != "proxy"}
    out["upstream"] = upstream
    out["username"] = username
    return out


_CRED_RE = re.compile(r"([a-zA-Z][a-zA-Z0-9+.\-]*://[^:/@\s]+):([^@\s]+)@")


def _mask_creds(text: str) -> str:
    """Маскирует userinfo в URI (`scheme://user:pass@host` → `user:***@`)."""
    return _CRED_RE.sub(r"\1:***@", text)


def _summary(cfgd: dict[str, Any]) -> dict[str, Any]:
    listen = cfgd.get("listen")
    proxy = cfgd.get("proxy")
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
    cfg._ensure_dirs()
    active = _active_name()
    out: list[dict[str, Any]] = []
    for p in sorted(cfg.CONF_D.glob("*.json")):
        try:
            cfgd = _load_json(p)
        except Exception as exc:
            log.warning("skipping %s: %s", p.name, exc)
            continue
        summary = _summary(cfgd)
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

    cfgd: dict[str, Any] = {"listen": listen, "proxy": proxy_uri}
    if data.get("log"):
        cfgd["log"] = data["log"]
    if data.get("extra_headers"):
        cfgd["extra-headers"] = data["extra_headers"]
    if data.get("host_resolver_rules"):
        cfgd["host-resolver-rules"] = data["host_resolver_rules"]
    if data.get("insecure_concurrency"):
        try:
            cfgd["insecure-concurrency"] = int(data["insecure_concurrency"])
        except ValueError:
            abort(400, description="insecure-concurrency must be integer")
    return cfgd


_LISTEN_SCHEMES = ("socks", "socks5", "http")
_LISTEN_MAX = 8  # sanity: реальных listen-адресов у пресета 1–3


def _listen_problem(uri: str) -> str | None:
    """Один listen-адрес → текст проблемы или None.

    Серверная валидация не полагается на HTML-pattern: `file://`/`quic://`
    в listen, userinfo, path/query или порт вне 1..65535 бинарник naive
    либо отвергнет в рантайме (пресет активирован, рабочий прокси упал),
    либо истолкует неожиданно. Порт опционален (умолчания бинарника:
    1080/socks, 8080/http).
    """
    raw = (uri or "").strip()
    if not raw:
        return "пустой адрес"
    if len(raw) > 200:
        return f"слишком длинный адрес ({len(raw)} симв.)"
    rest = raw
    if "://" in raw:
        scheme, _, rest = raw.partition("://")
        if scheme.lower() not in _LISTEN_SCHEMES:
            return f"схема {scheme}:// не поддерживается (разрешены socks/socks5/http)"
        if not rest:
            return "нет адреса после схемы"
    if "@" in rest:
        return "userinfo в listen не поддерживается"
    if any(c in rest for c in "/?#"):
        return "path/query/fragment в listen не поддерживается"
    if rest.startswith("["):  # IPv6: [::1]:1080 или [::1]
        end = rest.find("]")
        if end == -1:
            return "незакрытая скобка IPv6-адреса"
        host, tail = rest[: end + 1], rest[end + 1:]
        if tail and not tail.startswith(":"):
            return f"мусор после IPv6-адреса: {tail!r}"
        port_str = tail[1:]
    else:
        host, sep, port_str = rest.rpartition(":")
        if not sep:  # голый host без порта
            host, port_str = rest, ""
    if not re.search(r"[A-Za-z0-9]", host):
        return "пустой или некорректный host"
    if port_str:
        if not port_str.isdigit():
            return f"порт не число: {port_str!r}"
        if not 1 <= int(port_str) <= 65535:
            return f"порт вне диапазона 1..65535: {port_str}"
    return None


def _validate_cfg(cfgd: dict[str, Any], name: str) -> None:
    """Схема хранимого формата перед activate/PUT/импортом (400 при ошибке).

    Бинарник naive с битым конфигом падает в рантайме — activate такого
    пресета уронил бы РАБОТАЮЩИЙ прокси (config.json уже перезаписан, а
    рестарт не удался). Ловим очевидные проблемы заранее: отсутствующие
    listen/proxy, пустые адреса, URI без схемы, диапазон insecure-concurrency
    (HTML-форма ограничивает 1..4, но API — нет).
    """
    errors: list[str] = []
    listen = cfgd.get("listen")
    listen_items: list[str]
    if isinstance(listen, list):
        if not listen or any(not isinstance(l, str) or not l.strip() for l in listen):
            errors.append("listen: нужны непустые строки")
        elif len(listen) > _LISTEN_MAX:
            errors.append(f"listen: не больше {_LISTEN_MAX} адресов")
        listen_items = [l for l in listen if isinstance(l, str)]
    elif isinstance(listen, str) and listen.strip():
        listen_items = [listen]
    else:
        listen_items = []
        errors.append("listen обязателен (строка или массив строк)")
    for l in listen_items:
        problem = _listen_problem(l)
        if problem:
            errors.append(f"listen {l!r}: {problem}")
            break  # адресов немного; одной понятной ошибки достаточно
    proxy = cfgd.get("proxy")
    if not (isinstance(proxy, str) and proxy.strip()):
        errors.append("proxy обязателен")
    elif not proxy.strip().lower().startswith(cfg._ALLOWED_PROXY_SCHEMES):
        errors.append("proxy: разрешены схемы https://, http://, quic://")
    ic = cfgd.get("insecure-concurrency")
    if ic is not None and (not isinstance(ic, int) or isinstance(ic, bool) or not 1 <= ic <= 4):
        errors.append("insecure-concurrency: целое 1..4")
    for key in ("log", "extra-headers", "host-resolver-rules"):
        if cfgd.get(key) is not None and not isinstance(cfgd[key], str):
            errors.append(f"{key}: строка")
    if errors:
        abort(400, description=f"{name}: " + "; ".join(errors))


def _name_suggest(host: str) -> str:
    """Хост из строки подключения → кандидат в имена пресета.

    Порт и IPv6-скобки отрезаем, символы вне NAME_RE меняем на '-', лимит 64
    (как у NAME_RE). Получившаяся строка обязана матчить NAME_RE — иначе
    quickImport в UI положил бы в форму имя, которое save отвергнет.
    """
    host = host.split(":", 1)[0].strip().strip("[]")
    cleaned = re.sub(r"[^a-zA-Z0-9_.\-]", "-", host).strip("-.").lower()
    cleaned = cleaned[:64].rstrip("-.") or "preset"
    if not cfg.NAME_RE.match(cleaned):  # страховка на случай смены NAME_RE
        cleaned = "preset"
    return cleaned


def parse_connection_uri(raw: str) -> dict[str, Any]:
    """Строка подключения `https://user:pass@host[:port]` → поля редактора (3.2).

    Один парсер на сервере: правила те же, что при чтении конфигов
    (_split_proxy — креды до последнего `@`, percent-декодирование), JS-копия
    на них разъехалась бы. https раскладывается по полям (upstream без схемы —
    в том же виде его отдаёт _for_edit); http/quic остаются в upstream целиком:
    _build_payload при пересборке из полей всегда строит `https://…`, и quic-
    пресет молча превратился бы в https. Кредов может не быть — поля пустые,
    creds=false (UI попросит заполнить username/password).

    Ответ повторяет пароль из запроса: это ввод пользователя, а не секрет из
    хранилища (SEC-02 про GET хранимых конфигов).
    """
    raw = (raw or "").strip()
    idx = raw.find("://")
    scheme = raw[:idx].lower() if idx != -1 else ""
    if scheme not in ("https", "http", "quic"):
        abort(400, description="expected user:pass@host URI with https://, "
                               "http:// or quic:// scheme (socks:// — это "
                               "схема listen, не upstream)")
    host_part, username, password = _split_proxy(raw)
    creds = password is not None
    if not creds:
        host_part = raw[idx + 3:]
        username, password = "", ""
    if scheme == "https":
        upstream, username_out, password_out = host_part, username, password or ""
        decomposed = True
    else:
        upstream, username_out, password_out = raw, "", ""
        decomposed = False
    return {
        "scheme": scheme,
        "upstream": upstream,
        "username": username_out,
        "password": password_out,
        "creds": creds,
        "decomposed": decomposed,
        "name": _name_suggest(host_part),
    }


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


__all__ = [
    "_LISTEN_MAX", "_LISTEN_SCHEMES", "_active_name", "_build_payload",
    "_for_edit", "_listen_problem", "_list_presets", "_load_json",
    "_mask_creds", "_name_suggest", "_normalize_listen", "_save_json",
    "_split_proxy", "_summary", "_upstream_endpoint", "_validate_cfg",
    "_write_active", "parse_connection_uri",
]
