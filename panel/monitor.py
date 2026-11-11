"""Мониторинг и автоматика: E2E-проверка + история, watchdog, автофейловер,
уведомления (Telegram/webhook + pending), статус панели.

Шаг 5/7 модульного разделения (ARCH-01). Перенесено из naivepanel.py
дословно; сюда же переехала активация пресетов (_activate_preset/
_apply_active + _SERVICE_LOCK): её зовут и фейловер, и роуты, и updates.
_http_get — общий сетевой хелпер (нужен Telegram-валидации), updates
зовёт его через mon.

Конфигурация — через атрибут модуля-владельца (cfg.*); сервис — svc.*,
пресеты — pres.*. Локальные переменные cfgd (бывший cfg) в функциях
с модульной ручкой cfg не затеняют её. Логгер — тот же 'naivepanel'.
"""

import ipaddress
import json
import logging
import os
import queue
import re
import socket
import ssl
import subprocess
import threading
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from flask import abort, has_request_context, request
from werkzeug.exceptions import HTTPException

from panel import config as cfg
from panel import connections
from panel import presets as pres
from panel import service as svc

log = logging.getLogger("naivepanel")

# --- Фейловер: лок read-modify-write (модуль monitor, ARCH-01) --------
_FAILOVER_LOCK = threading.Lock()  # PUT / delete / import: read-modify-write

# --- Уведомления (Telegram / webhook) ----------------------------------------
# Конфиг изменяемый: UI пишет его в panel.conf и сразу обновляет runtime,
# не перезапуская панель. Секреты живут только здесь и в panel.conf.
_notify_lock = threading.Lock()
_notify_cfg: dict[str, str] = {
    "token": os.environ.get("NAIVEPANEL_TG_TOKEN", ""),
    "chat": os.environ.get("NAIVEPANEL_TG_CHAT", ""),
    "url": os.environ.get("NAIVEPANEL_NOTIFY_URL", ""),
}


def _notify_snapshot() -> dict[str, str]:
    with _notify_lock:
        return dict(_notify_cfg)


def _notify_channel(cfgd: dict[str, str] | None = None) -> str | None:
    c = cfgd if cfgd is not None else _notify_snapshot()
    if c.get("token") and c.get("chat"):
        return "telegram"
    if c.get("url"):
        return "webhook"
    return None

# Дорогие операции (TCP-коннект probe, туннель E2E, внешние update-check)
# держат worker-поток секунды. Залп таких запросов исчерпал бы все потоки
# waitress — и панель молчала бы даже на /api/status. Лимит обязан быть
# МЕНЬШЕ пула потоков (иначе запросы просто сериализует сам waitress, а
# дешёвые роуты стоят в общей очереди); сверх лимита — немедленный 429.
_EXPENSIVE_LIMIT = max(1, min(4, cfg.WAITRESS_THREADS - 2))
_EXPENSIVE_SEM = threading.BoundedSemaphore(_EXPENSIVE_LIMIT)
# Коалесцирование параллельных update-check'ов: один внешний резолв на
# залп; ждавшие получают только что заполненный кэш (и force тоже — его
# смысл «свежее, чем TTL», а не «обязательно лично сходить»).
_UPDATE_FETCH_LOCK = threading.Lock()
_NAIVE_FETCH_LOCK = threading.Lock()
# Границы внешних HTTP-запросов метаданных: зависший коннект не должен
# съедать весь таймаут, безразмерный ответ — память.
_HTTP_CONNECT_TIMEOUT = 5
_HTTP_MAX_BYTES = 2 * 1024 * 1024

# --- E2E-проверка: реальный запрос ЧЕРЕЗ прокси -----------------------------
# /api/probe отвечает «до upstream есть TCP» — но не «прокси проксирует».
# Здесь открываем listen-порт активного пресета как клиент и строим туннель
# до echo-хоста (cfg.E2E_URL): HTTP CONNECT для http-listen, SOCKS5 — для socks.
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
    ep = pres._upstream_endpoint(raw or " ")
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


def _probe_preset(cfgd: dict[str, Any], timeout: float = 15.0) -> dict[str, Any]:
    """Полный E2E пресета-кандидата БЕЗ его активации.

    Поднимаем второй naive прямо из CLI — `--listen socks://127.0.0.1:<порт>
    --proxy <URI>`, без временных файлов — и гоняем обычную E2E-проверку
    через этот порт. Так авто-возврат и каскад переключают на проверенно
    живой пресет, а не на «первый существующий». Креды живут в argv пробного
    процесса ~15 секунд (однопользовательский роутер — приемлемо); команду
    в лог не пишем. Схема listen пробы — всегда socks (проверяем upstream).
    """
    if not cfg.NAIVE_BIN.exists():
        return {"ok": False, "error": f"бинарник не найден: {cfg.NAIVE_BIN}"}
    proxy_uri = cfgd.get("proxy")
    if not isinstance(proxy_uri, str) or not proxy_uri.strip():
        return {"ok": False, "error": "у пресета нет proxy"}
    port = _free_port()
    # argv-список, shell не используется; команду не логируем (креды)
    proc = subprocess.Popen(  # nosec B603
        [str(cfg.NAIVE_BIN), f"--listen=socks://127.0.0.1:{port}",
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


def _proxy_e2e_check(listen_uri: str, timeout: float = cfg.E2E_TIMEOUT) -> dict[str, Any]:
    """Прогоняет один реальный запрос через listen naive (см. cfg.E2E_URL).

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

    parts = urlsplit(cfg.E2E_URL)
    echo_host = parts.hostname
    if not echo_host:
        return {"ok": False, "ms": _ms(), "error": f"NAIVEPANEL_E2E_URL некорректен: {cfg.E2E_URL!r}"}
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


def _active_listen_uris() -> list[str]:
    """Все listen-адреса активного пресета (строка или массив)."""
    try:
        cfgd = json.loads(cfg.ACTIVE_CONFIG.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    raw = cfgd.get("listen")
    if isinstance(raw, str):
        return [raw.strip()] if raw.strip() else []
    if isinstance(raw, list):
        return [item.strip() for item in raw
                if isinstance(item, str) and item.strip()]
    return []


def _active_listen() -> str | None:
    """listen активного пресета из config.json (первый адрес, если массив)."""
    uris = _active_listen_uris()
    return uris[0] if uris else None


def _host_is_loopback(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _active_listen_ports() -> tuple[set[int], bool]:
    """Порты активного пресета и «весь listen привязан к loopback»."""
    ports: set[int] = set()
    hosts: list[str] = []
    for uri in _active_listen_uris():
        ep = _listen_endpoint(uri)
        if ep is None:
            continue
        _scheme, host, port = ep
        ports.add(port)
        hosts.append(host)
    allow_loopback = bool(ports) and all(_host_is_loopback(h) for h in hosts)
    return ports, allow_loopback


# --- PAC-файл для устройств LAN (3.1) ----------------------------------------

def _pac_directives(host_header: str) -> list[str]:
    """PAC-директивы listen'ов активного пресета: PROXY/SOCKS5 host:port.

    Неопределённые хосты listen (0.0.0.0, ::, пустой) заменяются на хост из
    Host-заголовка запроса: устройство получило PAC по адресу панели — по
    нему же оно достигнет listen, привязанный ко «всем интерфейсам». Порядок:
    не-loopback сначала (чужим устройствам полезны только они), loopback в
    конце — бесполезны, но не мешают как последний фолбэк. Дубликаты
    (socks:// и socks5:// на одном порту) схлопываются.
    """
    # Host: 192.168.1.1:8089 | router.lan | [::1]:8089 → хост без порта
    own = host_header.rpartition(":")[0].strip("[]") or host_header
    direct_: list[str] = []
    loopback_: list[str] = []
    for uri in _active_listen_uris():
        ep = _listen_endpoint(uri)
        if ep is None:
            continue
        scheme, host, port = ep
        if host in ("0.0.0.0", "::", ""):  # nosec B104 — сравнение, не bind
            host = own
        entry = f"{'PROXY' if scheme == 'http' else 'SOCKS5'} {host}:{port}"
        (loopback_ if _host_is_loopback(host) else direct_).append(entry)
    return list(dict.fromkeys(direct_ + loopback_))


def _pac_body(host_header: str, direct_fallback: bool = False) -> str:
    """Тело /proxy.pac. Без активного listen — честный DIRECT (устройство
    продолжает ходить напрямую, а не падает с ошибкой PAC)."""
    active = pres._active_name()
    directives = _pac_directives(host_header)
    if not directives:
        directives = ["DIRECT"]
    elif direct_fallback:
        directives.append("DIRECT")
    head = [
        "// NaivePanel PAC — автогенерация, не редактировать",
        f"// активный пресет: {active or '—'} · {time.strftime('%Y-%m-%d %H:%M:%S')}",
    ]
    if not _active_listen_uris():
        head.append("// нет активного пресета с listen — только DIRECT")
    return "\n".join(head) + "\n" + (
        "function FindProxyForURL(url, host) {\n"
        f'  return "{"; ".join(directives)}";\n'
        "}\n"
    )


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
        cfg.E2E_HISTORY.parent.mkdir(parents=True, exist_ok=True)
        with cfg.E2E_HISTORY.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({"t": int(time.time()), "ok": bool(ok),
                                 "ms": int(ms or 0)}) + "\n")
        _e2e_since_trim += 1
        if _e2e_since_trim >= cfg._E2E_TRIM_EVERY:
            _e2e_since_trim = 0
            _e2e_history_trim()
    except OSError as exc:
        log.warning("e2e history append failed: %s", exc)


def _e2e_history_trim() -> None:
    """Оставляем последние cfg.E2E_KEEP записей (атомарная замена файла)."""
    try:
        lines = _e2e_history_read_all()
    except OSError:
        return
    if len(lines) <= cfg.E2E_KEEP:
        return
    tmp = cfg.E2E_HISTORY.with_suffix(".jsonl.tmp")
    try:
        with tmp.open("w", encoding="utf-8") as fh:
            # splitlines() срезает \n — восстанавливаем, иначе записи склеятся
            fh.write("\n".join(lines[-cfg.E2E_KEEP:]) + "\n")
        tmp.replace(cfg.E2E_HISTORY)
    except OSError as exc:
        log.warning("e2e history trim failed: %s", exc)


def _e2e_history_read_all() -> list[str]:
    """Все строки буфера (сырые); отсутствие файла — пустой список."""
    try:
        return cfg.E2E_HISTORY.read_text(encoding="utf-8").splitlines()
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


# --- Статистика аптайма: журнал переходов up/down (2.3) -----------------------

# Последнее наблюдённое состояние процесса; None = ещё не наблюдали (первый
# тик монитора после старта панели). Модульный глобал: поток монитора один.
_uptime_last: bool | None = None


def _uptime_journal_append(up: bool) -> None:
    """Один переход {t, up} в JSONL-журнал; ошибка записи не роняет монитор."""
    try:
        cfg.UPTIME_HISTORY.parent.mkdir(parents=True, exist_ok=True)
        with cfg.UPTIME_HISTORY.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({"t": int(time.time()), "up": bool(up)}) + "\n")
    except OSError as exc:
        log.warning("uptime journal append failed: %s", exc)


def _uptime_journal_load() -> list[dict[str, Any]]:
    """Записи журнала, старые → новые; битые строки пропускаем."""
    out: list[dict[str, Any]] = []
    try:
        lines = cfg.UPTIME_HISTORY.read_text(encoding="utf-8").splitlines()
    except OSError:
        return out
    for line in lines:
        try:
            entry = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue
        if (isinstance(entry, dict) and isinstance(entry.get("t"), int)
                and isinstance(entry.get("up"), bool)):
            out.append({"t": entry["t"], "up": entry["up"]})
    return out


def _uptime_trim(now: float | None = None) -> None:
    """Дроп записей старее _UPTIME_KEEP_S (30д) — окна 24ч/7д с запасом."""
    now = time.time() if now is None else now
    try:
        entries = _uptime_journal_load()
    except OSError:
        return
    kept = [e for e in entries if now - e["t"] <= cfg._UPTIME_KEEP_S]
    if len(kept) == len(entries):
        return
    tmp = cfg.UPTIME_HISTORY.with_suffix(".jsonl.tmp")
    try:
        with tmp.open("w", encoding="utf-8") as fh:
            fh.write("".join(json.dumps(e) + "\n" for e in kept))
        tmp.replace(cfg.UPTIME_HISTORY)
    except OSError as exc:
        log.warning("uptime journal trim failed: %s", exc)


def _uptime_observe(running: bool | None = None) -> None:
    """Тик наблюдения за процессом naive: пишет в журнал только ПЕРЕХОДЫ.

    Вызывается из начала каждого цикла монитора (до idle-веток: осознанный
    stop — честный downtime). Первый тик после старта панели — «якорь»:
    если последняя запись журнала совпадает с текущим состоянием, НЕ пишем
    (считаем, что состояние пережило простой панели; иначе каждая
    перезагрузка панели рождала бы ложный переход).
    """
    global _uptime_last
    if running is None:
        running = svc._proxy_running()[0]
    if _uptime_last is None:
        entries = _uptime_journal_load()
        last_up = entries[-1]["up"] if entries else None
        if last_up is None or last_up != running:
            _uptime_journal_append(running)
            _uptime_trim()
    elif _uptime_last != running:
        _uptime_journal_append(running)
        _uptime_trim()  # переходы редки — обрезка на каждом дёшева
    _uptime_last = running


def _uptime_stats(now: float | None = None) -> dict[str, Any]:
    """% аптайма за 24ч и 7д + рестарты за сутки, из журнала переходов.

    Каждая запись — «с этого момента состояние up»; интервал до следующей
    записи несёт состояние ПРЕДЫДУЩЕЙ. Хвост [последняя запись .. now] тоже
    несёт её состояние — свежесть ограничена тиком монитора (~30с), на окнах
    в сутки это неощутимо. До первой записи данных нет: знаменатель —
    наблюдаемый отрезок (мин(окно, now − t первой записи)), поэтому свежая
    установка не показывает «неделю нулей»; отрезок короче минуты → null.
    """
    now = time.time() if now is None else now
    entries = _uptime_journal_load()
    running = svc._proxy_running()[0]
    points = entries + [{"t": now, "up": running}]  # sentинель для хвоста
    day_from = now - 86400
    week_from = now - 7 * 86400

    def window(from_ts: float) -> dict[str, Any] | None:
        first_in = points[0]["t"]
        if now - first_in < cfg._UPTIME_MIN_SPAN_S:
            return None
        span_start = max(from_ts, first_in)
        up_s = 0.0
        prev_t = max(span_start, first_in)
        # интервал до первой записи — состояние первой записи (данных раньше нет)
        state = points[0]["up"]
        for p in points[1:]:
            if p["t"] <= span_start:
                state = p["up"]
                continue
            seg_start = max(prev_t, span_start)
            seg_end = min(p["t"], now)
            if seg_end > seg_start and state:
                up_s += seg_end - seg_start
            state = p["up"]
            prev_t = p["t"]
            if prev_t >= now:
                break
        observed = now - span_start
        return {"pct": round(100.0 * up_s / observed, 1),
                "observed_s": int(observed)}

    day = window(day_from)
    week = window(week_from)
    restarts = sum(1 for i in range(1, len(points) - 1)
                   if not points[i - 1]["up"] and points[i]["up"]
                   and points[i]["t"] > day_from)
    return {"day": day, "week": week, "restarts_day": restarts}

# --- Service control ------------------------------------------------------

def _status() -> dict[str, Any]:
    active_name = pres._active_name()
    has_init = cfg.INIT_SCRIPT.exists()
    running, pid, uptime = svc._proxy_running()
    # _status() зовут и фоновые потоки (naive-update, rollback): вне request
    # context request.authorization бросил бы RuntimeError.
    auth = request.authorization if has_request_context() else None
    channel = _notify_channel()
    # Счётчик диагностический: сбой чтения /proc не должен ронять статус.
    try:
        ports, allow_loopback = _active_listen_ports()
        conns = connections.snapshot(ports, allow_loopback)
    except Exception:  # noqa: BLE001 — граница диагностического снимка
        log.debug("connections snapshot failed", exc_info=True)
        conns = None
    return {
        "version": cfg.APP_VERSION,
        "active": running,
        "pid": pid,
        "uptime": uptime,
        "connections": conns,
        "current": active_name,
        "init_script": str(cfg.INIT_SCRIPT),
        "init_present": has_init,
        "watchdog": _watchdog.snapshot(),
        "failover": _failover.snapshot(),
        "uptime_stats": _uptime_stats(),
        "notify": {"enabled": channel is not None,
                   "channel": channel,
                   "pending": len(_notify_pending_all())},
        "auth": {"enabled": cfg.PANEL_ADMIN_PASS.exists(),
                 "user": auth.username if auth else None},
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
    if _notify_channel() is None:
        return
    now = time.time()
    if now - _notify_last.get(event, 0.0) < dedupe_s:
        return
    _notify_last[event] = now
    _notify_queue.put((event, text))


def _notify_send(event: str, text: str,
                 detail: bool = False) -> bool | tuple[bool, str]:
    """Доставка: сначала через активный naive, затем напрямую.

    detail=True → (ok, error) для кнопки «тест»; иначе bool (как раньше).
    """
    cfgd = _notify_snapshot()
    channel = _notify_channel(cfgd)
    if channel is None:
        return (False, "уведомления не настроены") if detail else False
    if channel == "telegram":
        url = f"https://api.telegram.org/bot{cfgd['token']}/sendMessage"
        body: dict[str, Any] = {"chat_id": cfgd["chat"], "text": text,
                                "disable_web_page_preview": True}
    else:
        url, body = cfgd["url"], {"event": event, "text": text,
                                 "ts": int(time.time())}
    post = ["-H", "Content-Type: application/json", "-d", json.dumps(body)]
    errors: list[str] = []

    def attempt(prefix: list[str], timeout: int) -> bool:
        try:
            res = svc._run([*prefix, *post, url], timeout=timeout)
        except HTTPException as exc:
            errors.append(str(exc.description or exc))
            return False
        if res["rc"] == 0:
            return True
        errors.append(res["stderr"] or f"curl rc={res['rc']}")
        return False

    listen = _active_listen()
    ep = _listen_endpoint(listen) if listen else None
    if ep and _tcp_probe(ep[1], ep[2], timeout=1.0) is not None:
        proxy = f"{'socks5h' if ep[0] == 'socks' else 'http'}://{ep[1]}:{ep[2]}"
        if attempt(["curl", "-fsS", "--max-time", "15", "-x", proxy], 20):
            return (True, "") if detail else True
    if attempt(["curl", "-fsS", "--max-time", "10"], 15):
        return (True, "") if detail else True
    if detail:
        err = errors[-1] if errors else "delivery failed"
        for secret in (cfgd.get("token"), cfgd.get("url")):
            if secret:
                err = err.replace(secret, "***")
        return False, err[:300]
    return False


# --- Pending: недоставленные события ждут оживания любого пути ---------------

NOTIFY_PENDING = cfg.PANEL_DIR / "notify-pending.jsonl"
_NOTIFY_PENDING_CAP = 50


def _notify_pending_append(event: str, text: str) -> None:
    """Событие в файл-очередь (переживает рестарт панели); cap по последним."""
    try:
        cfg.PANEL_DIR.mkdir(parents=True, exist_ok=True)
        lines = [str(x) for x in _notify_pending_all(raw=True)]
        lines.append(json.dumps({"event": event, "text": text,
                                 "ts": int(time.time())}))
        tmp = NOTIFY_PENDING.with_suffix(".jsonl.tmp")
        with tmp.open("w", encoding="utf-8") as fh:
            fh.write("\n".join(lines[-_NOTIFY_PENDING_CAP:]) + "\n")
        tmp.replace(NOTIFY_PENDING)
    except OSError as exc:
        log.warning("notify pending append failed: %s", exc)


def _notify_pending_all(raw: bool = False) -> list[Any]:
    """Отложенные события (старые → новые); битые строки пропускаем."""
    try:
        lines = NOTIFY_PENDING.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    if raw:
        return lines
    out: list[Any] = []
    for line in lines:
        try:
            item = json.loads(line)
            if isinstance(item, dict) and item.get("event") and item.get("text"):
                out.append(item)
        except (json.JSONDecodeError, ValueError):
            continue
    return out


def _notify_flush_pending() -> int:
    """Доставить отложенные: до 5 за тик, стоп на первой неудаче (не долбим)."""
    items = _notify_pending_all()
    if not items:
        return 0
    delivered = 0
    kept_from: int | None = None
    for i, item in enumerate(items[:5]):
        if _notify_send(item["event"], item["text"]):
            delivered += 1
            log.warning(
                "notify: доставлено отложенное %s (событие %s)",
                item["event"],
                time.strftime("%H:%M:%S", time.localtime(item.get("ts", 0))))
        else:
            kept_from = i
            break
    if delivered:
        kept = items[kept_from:] if kept_from is not None else items[5:]
        try:
            tmp = NOTIFY_PENDING.with_suffix(".jsonl.tmp")
            with tmp.open("w", encoding="utf-8") as fh:
                fh.write("\n".join(json.dumps(i) for i in kept)
                         + ("\n" if kept else ""))
            tmp.replace(NOTIFY_PENDING)
        except OSError as exc:
            log.warning("notify pending flush failed: %s", exc)
    return delivered


def _notify_tick(timeout: float = 30.0) -> None:
    if _notify_channel() is not None:
        _notify_flush_pending()
    try:
        event, text = _notify_queue.get(timeout=timeout)
    except queue.Empty:
        return
    if _notify_send(event, text):
        return
    if _notify_channel() is None:
        log.info("notify %s: канал отключён — событие отброшено", event)
        return
    log.warning(
        "notify %s: все пути недоступны (прокси и напрямую) — отложено",
        event)
    _notify_pending_append(event, text)


def _notify_loop() -> None:
    while True:
        try:
            _notify_tick()
        except Exception:
            log.exception("notify loop error — продолжаю")
            time.sleep(1)


# --- Настройка Telegram: валидация, кэш имени бота, upsert panel.conf --------

_TG_TOKEN_RE = re.compile(r"^[0-9]{5,}:[A-Za-z0-9_-]{20,}$")
_TG_CHAT_RE = re.compile(r"^(-?[0-9]{1,20}|@[A-Za-z][A-Za-z0-9_]{3,31})$")
_bot_cache: dict[str, tuple[str | None, float]] = {}
_BOT_TTL = 3600.0
_BOT_NEG_TTL = 300.0


def _tg_bot_name(token: str) -> str | None:
    """@username бота через getMe; положительный кэш 1ч, отрицательный 5м."""
    if not token:
        return None
    now = time.monotonic()
    hit = _bot_cache.get(token)
    if hit and hit[1] > now:
        return hit[0]
    name = None
    try:
        raw = _http_get(f"https://api.telegram.org/bot{token}/getMe", timeout=5)
        payload = json.loads(raw)
        result = payload.get("result") if isinstance(payload, dict) else None
        username = result.get("username") if isinstance(result, dict) else None
        name = f"@{username}" if username else None
    except (RuntimeError, ValueError, KeyError, TypeError):
        pass
    _bot_cache[token] = (name, now + (_BOT_TTL if name else _BOT_NEG_TTL))
    return name

# --- Watchdog: авто-рестарт упавшего naive ----------------------------------


class _Watchdog:
    """Следит за переходом naive running→down и поднимает его обратно.

    Реагирует ТОЛЬКО на переход вниз, observed при живой панели: после
    старта панели «прокси не работает» — не сигнал (неизвестно, остановили
    ли его руками до нас; автозапуск делает init-скрипт). Штатный stop
    init-скрипт маркирует файлом cfg.STOP_MARKER — тогда панель не вмешивается.
    Флаппинг (падает сразу после старта) гасим: cfg.WATCHDOG_FLAP_MAX рестартов
    за cfg.WATCHDOG_FLAP_WINDOW — и watchdog отключается до рестарта панели.
    """

    def __init__(self, flap_max: int = cfg.WATCHDOG_FLAP_MAX,
                 flap_window: float = cfg.WATCHDOG_FLAP_WINDOW) -> None:
        self._prev_running: bool | None = None
        self._restarts: list[float] = []
        self._flap_max = flap_max
        self._flap_window = flap_window
        self.tripped = False   # отключился из-за флаппинга
        self.count = 0         # рестартов за жизнь панели

    def snapshot(self) -> dict[str, Any]:
        return {"enabled": cfg.WATCHDOG_ENABLED, "restarts": self.count,
                "tripped": self.tripped}

    def _flapped(self, now: float) -> bool:
        self._restarts = [t for t in self._restarts if now - t < self._flap_window]
        return len(self._restarts) >= self._flap_max

    def observe(self, recheck_delay: float = cfg.WATCHDOG_RECHECK_S) -> dict[str, Any] | None:
        """Один тик; возвращает событие (см. тесты) или None, если всё тихо."""
        running, _, _ = svc._proxy_running()
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
            running, _, _ = svc._proxy_running()
            if running:
                return None
        if cfg.STOP_MARKER.exists():
            return {"event": "stopped"}   # штатный stop — не вмешиваемся
        if not cfg.INIT_SCRIPT.exists():
            return {"event": "no-init"}
        if self.tripped:
            return {"event": "down-tripped"}
        now = time.time()
        if self._flapped(now):
            self.tripped = True
            return {"event": "tripped"}
        self._restarts.append(now)
        self.count += 1
        with _SERVICE_LOCK:
            res = svc._service("start")
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
                        log.warning(
                            "watchdog: naive упал — перезапущен (рестартов: %d)",
                            _watchdog.count)
                        _notify("watchdog_restart",
                                f"NaivePanel: naive упал — watchdog перезапустил "
                                f"(рестартов: {_watchdog.count})")
                    else:
                        log.error(
                            "watchdog: naive упал, перезапуск НЕ удался: rc=%s %s",
                            ev.get("rc"), ev.get("stderr") or "")
                        _notify("watchdog_restart_failed",
                                "NaivePanel: naive упал, перезапуск НЕ удался — "
                                "загляните в панель")
                elif ev["event"] == "tripped":
                    log.error(
                        "watchdog: naive падает %d раз за %dс — авто-рестарт "
                        "отключён до перезапуска панели; проверьте лог прокси",
                        cfg.WATCHDOG_FLAP_MAX, int(cfg.WATCHDOG_FLAP_WINDOW))
                    _notify("watchdog_tripped",
                            f"NaivePanel: naive падает {cfg.WATCHDOG_FLAP_MAX} раз за "
                            f"{int(cfg.WATCHDOG_FLAP_WINDOW)}с — авто-рестарт отключён, "
                            f"нужно вмешательство")
                elif ev["event"] == "down-tripped":
                    log.error("watchdog: naive снова вниз — стоим (отключён)")
                elif ev["event"] == "stopped":
                    log.info("watchdog: штатный stop (маркер) — не вмешиваюсь")
        except Exception:  # один сбойный тик не должен останавливать поток
            log.warning("watchdog cycle failed", exc_info=True)
        time.sleep(cfg.WATCHDOG_INTERVAL)

# --- Автофейловер: монитор цепочки пресетов ----------------------------------


def _load_failover_conf() -> dict[str, Any]:
    """failover.json → конфиг монитора; без файла — всё выключено.

    Битый файл трактуем как «выключен»: монитор не должен падать из-за
    руки, поправившей JSON мимо панели. auto_return — opt-in (v0.14).
    """
    empty = {"enabled": False, "chain": [], "auto_return": False}
    try:
        data = json.loads(cfg.FAILOVER_CONF.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return empty
    if not isinstance(data, dict):
        return empty
    chain = data.get("chain")
    if not isinstance(chain, list):
        chain = []
    # stale/невалидные имена (в т.ч. попытки path traversal) не участвуют
    chain = [n for n in chain
             if isinstance(n, str) and cfg.NAME_RE.match(n)
             and (cfg.CONF_D / f"{n}.json").exists()]
    enabled = bool(data.get("enabled")) and bool(chain)
    auto_return = data.get("auto_return") is True and enabled
    return {"enabled": enabled, "chain": chain,
            "auto_return": auto_return}


def _preset_cfg(name: str) -> dict[str, Any] | None:
    """Конфиг пресета из conf.d для пробы (без HTTP-исключений)."""
    try:
        data = json.loads((cfg.CONF_D / f"{name}.json").read_text(encoding="utf-8"))
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

    def __init__(self, threshold: int = cfg.FAILOVER_THRESHOLD) -> None:
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
        active = pres._active_name()
        idx = conf["chain"].index(active) if active in conf["chain"] else None
        # Динамические причины паузы перепроверяем: idle_reason — итог
        # ПОСЛЕДНЕГО цикла монитора, и до следующего цикла (до 30с) мог
        # появиться пресет / сняться маркер stop. Показывать устаревшую
        # паузу рядом со свежим active_index — противоречие в статусе.
        idle = self.idle_reason
        if idle == "прокси остановлен вручную" and not cfg.STOP_MARKER.exists():
            idle = None
        elif idle == "нет активного пресета с listen" and active and _active_listen():
            idle = None
        return {
            "enabled": cfg.FAILOVER_ENABLED and conf["enabled"],
            "monitor": cfg.FAILOVER_ENABLED,
            "chain": conf["chain"],
            "chain_max": cfg.FAILOVER_CHAIN_MAX,
            "active_index": idx,
            "threshold": self._threshold,
            "interval": cfg.FAILOVER_INTERVAL,
            "fast_interval": cfg.FAILOVER_FAST,
            "probing_fast": self.hot,
            "fails": self._fails,
            "last_check": self._last_check,
            "last_ok": self._last_ok,
            "last_error": self._last_error,
            "last_ms": self._last_ms,
            "switches": self.switches,
            "returns": self.returns,
            "auto_return": cfg.FAILOVER_ENABLED and conf["auto_return"],
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
        # до idle-веток: осознанный stop — тоже downtime, журнал обязан его
        # видеть; пишутся только переходы (см. _uptime_observe)
        _uptime_observe()
        conf = _load_failover_conf()
        if not cfg.FAILOVER_ENABLED:
            self._idle("монитор выключен")
            return None
        if cfg.STOP_MARKER.exists():
            self._idle("прокси остановлен вручную")
            return None
        active = pres._active_name()
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
        return [c for c in chain[idx + 1:] if (cfg.CONF_D / f"{c}.json").exists()]

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
            cfgd = _preset_cfg(candidate)
            if cfgd is None:
                continue
            probe = _probe_preset(cfgd, timeout=10.0)
            if not probe.get("ok"):
                log.info(
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
            cfgd = _preset_cfg(candidate)
            ep = pres._upstream_endpoint(cfgd.get("proxy") or "") if cfgd else None
            alive = bool(ep and _tcp_probe(ep[0], ep[1], timeout=3.0) is not None)
            self._streaks[candidate] = self._streaks.get(candidate, 0) + 1 if alive else 0
            streak = self._streaks[candidate]
            if streak and (best is None or streak > best[1]):
                best = (candidate, streak)
        self._return_watch = ({"name": best[0], "streak": best[1],
                               "need": cfg.FAILOVER_RETURN_ALIVE}
                              if best else None)
        for candidate in conf["chain"][:idx]:
            if self._streaks.get(candidate, 0) < cfg.FAILOVER_RETURN_ALIVE:
                continue
            if now < self._cooldown.get(candidate, 0.0):
                continue  # уже обжигались — ждём конца cooldown
            cfgd = _preset_cfg(candidate)
            if cfgd is None:
                continue
            probe = _probe_preset(cfgd, timeout=15.0)
            if probe.get("ok"):
                try:
                    res = _activate_preset(candidate)
                except HTTPException:
                    self._cooldown[candidate] = now + cfg.FAILOVER_RETURN_COOLDOWN
                    continue
                self.returns += 1
                self._streaks.clear()
                self._return_watch = None
                return {"event": "returned", "from": active, "to": candidate,
                        "restart": res.get("restart")}
            # TCP жив, а прокси нет (креды/TLS/защита) — кандидату cooldown
            self._cooldown[candidate] = now + cfg.FAILOVER_RETURN_COOLDOWN
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
                        log.error(
                            "фейловер: %s не прошёл E2E-проверки — переключение"
                            " на %s, но рестарт НЕ удался: rc=%s %s",
                            ev["from"], ev["to"], rc, rst.get("stderr") or "")
                    else:
                        log.warning(
                            "фейловер: %s не прошёл %d E2E-проверок подряд — "
                            "переключение на %s",
                            ev["from"], cfg.FAILOVER_THRESHOLD, ev["to"])
                    _notify("failover_switch",
                            f"NaivePanel: {ev['from']} не работает — "
                            f"переключение на {ev['to']}")
                elif ev["event"] == "returned":
                    log.warning(
                        "авто-возврат: %s жив (TCP %d подряд + проба E2E) — "
                        "возврат с %s", ev["to"], cfg.FAILOVER_RETURN_ALIVE, ev["from"])
                    _notify("failover_return",
                            f"NaivePanel: {ev['to']} снова жив — авто-возврат "
                            f"с {ev['from']}")
                elif ev["event"] == "return_probe_failed":
                    log.warning(
                        "авто-возврат: %s TCP-жив, но проба E2E не прошла (%s) — "
                        "cooldown %dс", ev["candidate"], ev.get("error"),
                        cfg.FAILOVER_RETURN_COOLDOWN)
                    _notify("failover_return_probe_failed",
                            f"NaivePanel: авто-возврат на {ev['candidate']} "
                            f"отложен — проба не прошла")
                elif ev["event"] == "activate-failed":
                    log.error(
                        "фейловер: активация %s не удалась (валидация)",
                        ev["to"])
                elif ev["event"] == "exhausted":
                    log.error(
                        "фейловер: цепочка исчерпана — %s не работает и "
                        "запасных больше нет; проверка продолжается, возврат "
                        "на основной — вручную", ev["active"])
                    _notify("failover_exhausted",
                            f"NaivePanel: цепочка исчерпана — {ev['active']} "
                            f"не работает, запасных нет")
                # failing не логируем: до порога это нормальный шум сети
        except Exception:  # один сбойный тик не должен останавливать поток
            log.warning("failover cycle failed", exc_info=True)
        # двухскоростной ритм: сбой → частые проверки до порога/восстановления
        time.sleep(cfg.FAILOVER_FAST if _failover.hot else cfg.FAILOVER_INTERVAL)




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
    return pres._mask_creds("".join(data.splitlines(keepends=True)[-lines:]))

# Активация из двух мест: API (ручной клик) и фейловер-монитор (авто); плюс
# PUT активного пресета, ручные service start/stop/restart и рестарты после
# обновления/отката бинарника. Один лок сериализует их все: параллельные
# stop/start init-скрипта на медленном роутере перехлёстываются, а два
# писателя config.json/.active оставляют файлы, врущие о состоянии сервиса.
_SERVICE_LOCK = threading.Lock()


def _apply_active(name: str, cfgd: dict[str, Any]) -> dict[str, Any]:
    """config.json/.active + рестарт под _SERVICE_LOCK, с откатом при фейле.

    Рестарт с новым конфигом упал (rc != 0) → файлы не должны врать, будто
    конфиг применён: восстанавливаем прежний config.json/.active и пробуем
    вернуть сервис на старом конфиге. Неудача отката не скрывается —
    результат помечается degraded, обе ошибки видны вызывающему/UI.
    """
    with _SERVICE_LOCK:
        prev_name = pres._active_name()
        prev_cfg = None
        if prev_name is not None:
            try:
                prev_cfg = json.loads(cfg.ACTIVE_CONFIG.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                prev_cfg = None
        pres._write_active(name, cfgd)
        restart = svc._service("restart") if cfg.INIT_SCRIPT.exists() \
            else {"rc": None, "note": "no init script"}
        if restart.get("rc") not in (None, 0):
            restart = dict(restart)
            restart["degraded"] = True
            if prev_cfg is not None and prev_name is not None:
                pres._write_active(prev_name, prev_cfg)
                restart["rollback"] = svc._service("restart") \
                    if cfg.INIT_SCRIPT.exists() else {"rc": None, "note": "no init script"}
            else:
                # до активации ничего не работало — не оставляем ссылки на
                # неприменённый конфиг
                cfg.ACTIVE_CONFIG.unlink(missing_ok=True)
                cfg.ACTIVE_POINTER.unlink(missing_ok=True)
            log.warning(
                "activate %s degraded: restart rc=%s, restored=%s",
                name, restart.get("rc"), prev_name)
        return restart


def _activate_preset(name: str) -> dict[str, Any]:
    """Валидация + запись config.json/.active + рестарт сервиса.

    Используется ручным activate из UI и автофейловером — одна и та же
    семантика: битый конфиг не роняет рабочий прокси (валидация до записи).
    """
    if not cfg.NAME_RE.match(name):
        abort(400, description="invalid name")
    src = cfg.CONF_D / f"{name}.json"
    if not src.exists():
        abort(404, description=f"preset {name!r} not found")
    cfgd = pres._load_json(src)
    pres._validate_cfg(cfgd, name)  # битый конфиг не должен ронять рабочий прокси
    restart = _apply_active(name, cfgd)
    return {"name": name, "active": True, "restart": restart}

def _http_get(url: str, timeout: float = 6.0) -> str:
    """GET внешнего URL через curl/wget — как fetch() в install.sh.

    python-urllib на Entware завязан на системный CA-бандл, которого часто
    нет; curl же был обязателен при установке панели. Оба недоступны/упали —
    RuntimeError: панель нередко стоит в сетях без прямого хода в GitHub,
    это штатный отказ, а не авария.
    """
    last = ""
    for cmd in (["curl", "-fsSL",
                 "--connect-timeout", str(_HTTP_CONNECT_TIMEOUT),
                 "--max-time", str(int(timeout)),
                 "--max-filesize", str(_HTTP_MAX_BYTES), url],
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


__all__ = [
    "NOTIFY_PENDING",
    "_BOT_NEG_TTL",
    "_BOT_TTL",
    "_EXPENSIVE_LIMIT",
    "_EXPENSIVE_SEM",
    "_FAILOVER_LOCK",
    "_Failover",
    "_HTTP_CONNECT_TIMEOUT",
    "_HTTP_MAX_BYTES",
    "_IPV4_RE",
    "_IPV6_RE",
    "_NAIVE_FETCH_LOCK",
    "_pac_body",
    "_pac_directives",
    "_uptime_journal_append",
    "_uptime_journal_load",
    "_uptime_last",
    "_uptime_observe",
    "_uptime_stats",
    "_uptime_trim",
    "_NOTIFY_PENDING_CAP",
    "_SERVICE_LOCK",
    "_TG_CHAT_RE",
    "_TG_TOKEN_RE",
    "_UPDATE_FETCH_LOCK",
    "_Watchdog",
    "_activate_preset",
    "_active_listen",
    "_active_listen_ports",
    "_active_listen_uris",
    "_apply_active",
    "_bot_cache",
    "_e2e_history_append",
    "_e2e_history_load",
    "_e2e_history_read_all",
    "_e2e_history_trim",
    "_e2e_since_trim",
    "_extract_exit_ip",
    "_failover",
    "_failover_loop",
    "_free_port",
    "_get_via_tunnel",
    "_http_connect_via_proxy",
    "_http_get",
    "_listen_endpoint",
    "_load_failover_conf",
    "_notify",
    "_notify_cfg",
    "_notify_channel",
    "_notify_flush_pending",
    "_notify_last",
    "_notify_lock",
    "_notify_loop",
    "_notify_pending_all",
    "_notify_pending_append",
    "_notify_queue",
    "_notify_send",
    "_notify_snapshot",
    "_notify_tick",
    "_preset_cfg",
    "_probe_preset",
    "_proxy_e2e_check",
    "_recv_exact",
    "_recv_until",
    "_socks5_connect_via_proxy",
    "_status",
    "_tail_path",
    "_tcp_probe",
    "_tg_bot_name",
    "_watchdog",
    "_watchdog_loop",
]
