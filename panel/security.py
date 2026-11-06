"""Security-слой панели: CSP/nonce, Host-allowlist, CSRF, HTTP Basic auth.

Шаг 2/7 модульного разделения (ARCH-01). Функции перенесены из naivepanel.py
дословно; регистрация хуков (before/after_request, context_processor)
остаётся в naivepanel.py рядом с созданием Flask-app — ПОРЯДОК регистрации
воспроизводит исходный: nonce раньше Host-allowlist (нужен и на 403-ответах),
host/fail-closed/CSRF раньше auth.

Конфигурацию читаем через атрибут модуля-владельца (`cfg.PANEL_ADMIN_PASS`,
`cfg._bind_is_loopback()`) — патчи тестов на `app.cfg.*` обязаны быть видны
здесь. Логгер — `logging.getLogger("naivepanel")`, тот же объект, что
Flask app.logger (как в panel/config.py).
"""

import hashlib
import logging
import os
import secrets
import tempfile
import time
from pathlib import Path

from flask import Response, abort, g, request

from panel import config as cfg

log = logging.getLogger("naivepanel")

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


def _security_headers(resp: Response) -> Response:
    resp.headers.setdefault("Content-Security-Policy", _csp(getattr(g, "csp_nonce", "")))
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    return resp


# --- CSP nonce ---------------------------------------------------------------

# Регистрируется до Host-allowlist: nonce нужен и на 403-ответах (after_request
# читает g.csp_nonce), поэтому должен существовать раньше любого abort.

def _make_csp_nonce() -> None:
    g.csp_nonce = secrets.token_urlsafe(16)


def _inject_csp_nonce() -> dict[str, str]:
    return {"csp_nonce": getattr(g, "csp_nonce", "")}


# --- Host allowlist (анти-DNS-rebinding) -----------------------------------

# Дефолтный allowlist: адрес bind + loopback-алиасы. Прямой доступ из браузера
# всегда идёт на один из них; чужое имя в Host — маркер DNS-rebinding.
DEFAULT_ALLOWED_HOSTS = cfg._default_allowed_hosts(cfg.PANEL_BIND)


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
    allowed = {h.lower() for h in (cfg.ALLOWED_HOSTS or DEFAULT_ALLOWED_HOSTS)}
    if request.host.lower() in allowed:
        return
    log.warning("rejected Host %r from %s", request.host, request.remote_addr)
    abort(403, description="host not allowed (see NAIVEPANEL_HOSTS)")


# --- fail-closed: LAN-bind без пароля (SEC-01) -------------------------------
# _require_auth без admin.pass пропускает всех («только 127.0.0.1, публично
# не торчим») — но это верно лишь при loopback-bind. Если панель привязана к
# LAN-интерфейсу без пароля, открыты ВСЕ маршруты: список/экспорт пресетов с
# паролями, service/panel restart, update. Один централизованный guard до
# CSRF/auth надёжнее проверок в каждом handler; _require_local_or_auth()
# остаётся на критичных роутах как defense-in-depth.

def _panel_is_exposed_without_auth() -> bool:
    return not cfg.PANEL_ADMIN_PASS.exists() and not cfg._bind_is_loopback()


def _reject_unauthenticated_exposure():
    if _panel_is_exposed_without_auth():
        abort(403, description="panel is exposed without a password — "
                               "set one (install.sh --with-auth) first")


# --- CSRF -------------------------------------------------------------------
# Basic-креды браузер прикладывает к кросс-сайтовым запросам автоматически,
# поэтому сама по себе auth от CSRF не защищает. POST без тела — «simple
# request» без preflight, так что зловредная страница могла бы дёргать
# /api/service/* и activate от имени залогиненного админа. Кастомный заголовок
# cross-origin JS не поставит без успешного CORS-preflight, а preflight-ответов
# мы не отдаём — запрос отклоняется ещё на нём.

def _csrf_protect():
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return
    if request.headers.get("X-Requested-With") != "naivepanel":
        log.warning(
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


def _require_auth():
    """Если /opt/etc/naive/panel/admin.pass существует — требует HTTP Basic auth
    на каждый запрос. Формат файла — стандартный htpasswd: `user:bcrypt-hash`
    на строку. Создание: `htpasswd -B -c admin.pass user` (или python3-bcrypt —
    в Entware htpasswd отсутствует, см. README).

    Без пакета python3-bcrypt auth fail-closed (401 на любой запрос), в лог
    пишется ошибка. Это намеренно: лучше сломанная панель, чем открытая.
    """
    global _admin_pass_stamp
    if not cfg.PANEL_ADMIN_PASS.exists():
        return  # auth выключен — только 127.0.0.1, публично не торчим
    ip = request.remote_addr or ""
    if _auth_throttled(ip):
        abort(429, description="too many failed auth attempts, try later")
    try:
        st = cfg.PANEL_ADMIN_PASS.stat()
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
        stored = cfg.PANEL_ADMIN_PASS.read_text(encoding="utf-8")
        if _htpasswd_verify(stored, auth.username or "", auth.password or ""):
            if len(_auth_cache) >= _AUTH_CACHE_LIMIT:
                _auth_cache.clear()
            _auth_cache[key] = now + _AUTH_CACHE_TTL
            _auth_fails.pop(ip, None)
            return
    log.warning(
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
        log.error(
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
            log.warning("admin.pass: unsupported hash for %r (need bcrypt)", u)
            return False
        try:
            return bcrypt.checkpw(password.encode(), h.encode())
        except ValueError:
            # битый хэш в admin.pass не должен превращать каждый запрос в 500
            log.warning("admin.pass: malformed bcrypt hash for %r", u)
            return False
    return False  # пользователь не найден


def _htpasswd_replace(stored: str, user: str, new_hash: str) -> str:
    """Заменить хэш одного пользователя, сохранив комментарии и чужие строки."""
    out: list[str] = []
    found = False
    for line in stored.splitlines():
        s = line.strip()
        if s and not s.startswith("#") and ":" in s:
            u = s.split(":", 1)[0]
            if u == user:
                out.append(f"{user}:{new_hash}")
                found = True
                continue
        out.append(line)
    if not found:
        raise LookupError(user)
    return "\n".join(out) + "\n"


def _write_admin_pass(user: str, new_password: str) -> None:
    """Атомарно заменить хэш пользователя; кэш успешных проверок сбросить."""
    global _admin_pass_stamp
    import bcrypt  # type: ignore

    # bcrypt принимает не больше 72 байт: 5.x кидает ValueError, 4.x молча
    # обрезает. Проверяем до записи, чтобы файл не остался в странном виде.
    if not 8 <= len(new_password.encode("utf-8")) <= 72:
        abort(400, description="new password must be 8–72 bytes")
    try:
        stored = cfg.PANEL_ADMIN_PASS.read_text(encoding="utf-8")
    except OSError:
        abort(409, description="auth is not configured")
    try:
        new_hash = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()
    except ValueError:
        abort(400, description="new password must be 8–72 bytes")
    try:
        updated = _htpasswd_replace(stored, user, new_hash)
    except LookupError:
        abort(404, description=f"user {user!r} not found in admin.pass")

    tmp = None
    try:
        cfg.PANEL_ADMIN_PASS.parent.mkdir(parents=True, exist_ok=True)
        # уникальное имя: фиксированный .tmp давал гонку между запросами
        fd, tmp = tempfile.mkstemp(dir=str(cfg.PANEL_ADMIN_PASS.parent),
                                   prefix=".admin.pass.", suffix=".tmp")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            os.fchmod(fh.fileno(), 0o600)
            fh.write(updated)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, cfg.PANEL_ADMIN_PASS)
    except OSError as exc:
        # путь в тело ответа не отдаём — только в лог
        log.error("cannot write %s: %s", cfg.PANEL_ADMIN_PASS, exc)
        abort(500, description="cannot write admin.pass")
    finally:
        if tmp is not None:
            try:
                Path(tmp).unlink()
            except OSError:
                pass
    _auth_cache.clear()
    _admin_pass_stamp = None


def _require_local_or_auth() -> None:
    """Секреты/код панели нельзя менять без пароля с внешнего интерфейса."""
    if not cfg.PANEL_ADMIN_PASS.exists() and not cfg._bind_is_loopback():
        abort(403, description="panel is exposed without a password — "
                               "set one (install.sh --with-auth) first")


__all__ = [
    "DEFAULT_ALLOWED_HOSTS",
    "_AUTH_CACHE_LIMIT", "_AUTH_CACHE_TTL", "_AUTH_FAIL_LIMIT",
    "_AUTH_FAIL_WINDOW", "_admin_pass_stamp", "_auth_cache", "_auth_fails",
    "_auth_register_failure", "_auth_throttled", "_csrf_protect", "_csp",
    "_enforce_host_allowlist", "_htpasswd_replace", "_htpasswd_verify",
    "_inject_csp_nonce", "_make_csp_nonce", "_panel_is_exposed_without_auth",
    "_reject_unauthenticated_exposure", "_require_auth",
    "_require_local_or_auth", "_security_headers", "_write_admin_pass",
]
