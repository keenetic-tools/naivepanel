"""Конфигурация NaivePanel: env, panel.conf, пути и константы.

Выделено из naivepanel.py поэтапным рефакторингом (ARCH-01, план аудита
2026-11-05 Task 15). Правило пакета: константы читаются здесь один раз
при (ре)импорте — тесты перечитывают env через importlib.reload; мутабельные
локи/кэши живут в своих доменных модулях, а не здесь.
"""
from __future__ import annotations

import ipaddress
import logging
import os
import re
import tempfile
from pathlib import Path

from flask import abort

_log = logging.getLogger("naivepanel")  # тот же логгер, что у Flask app

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
    "NAIVEPANEL_UPTIME_HISTORY",
    "NAIVEPANEL_TG_TOKEN", "NAIVEPANEL_TG_CHAT", "NAIVEPANEL_NOTIFY_URL",
})

_CONF_SKIPPED: list[str] = []
# Ключи, которые реально пришли из panel.conf (а не были уже в env):
# по ним UI понимает, что env перекроет сохранённое значение после рестарта.
_CONF_FILE_KEYS: set[str] = set()


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
        if key not in os.environ:
            os.environ[key] = value
            _CONF_FILE_KEYS.add(key)


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

# --- Статистика аптайма (2.3) -------------------------------------------------
# Журнал ПЕРЕХОДОВ процесса naive up/down (JSONL, по записи на переход) —
# переходы редки, файл крошечный. % за 24ч/7д и рестарты считаются на лету
# из журнала + текущего состояния. Храним 30 дней (окно 7д с запасом);
# дольше — бессмысленно для роутера.
UPTIME_HISTORY = Path(os.environ.get("NAIVEPANEL_UPTIME_HISTORY",
                                     str(NAIVEPROXY_DIR / "uptime-history.jsonl")))
_UPTIME_KEEP_S = 30 * 86400
_UPTIME_MIN_SPAN_S = 60  # меньше минуты наблюдений — проценты врут, показываем «—»

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
# Файлы, заменяемые обновлением панели — их же восстанавливает откат
# (бэкап хранит под именем оригинала; S99naivepanel/S99naiveproxy различаются)
PANEL_UPDATE_FILES = (PANEL_DIR / "naivepanel.py",
                      PANEL_DIR / "templates" / "index.html",
                      PANEL_INIT, INIT_SCRIPT)
# Источник обновления — только строгие vX.Y.Z: ни веток, ни хэшей, ни main
_TAG_RE = re.compile(r"^v\d+\.\d+\.\d+$")
_UPDATE_CHECK_TTL = 6 * 3600.0  # авто-check при загрузке страницы не должен
_UPDATE_ERR_TTL = 10 * 60.0     # расходовать лимит GitHub API; недоступный
_UPDATE_STALE_S = 15 * 60       # GitHub не долбим чаще раза в 10 минут

NAME_RE = re.compile(r"^[a-zA-Z0-9_\-.]{1,64}$")

# GET-пути без HTTP Basic auth: LAN-устройства не умеют предъявлять креды.
# PAC отдаёт только адрес прокси (порт и так достижим из LAN — в этом смысл
# PAC). Host-allowlist и SEC-01 (LAN-bind без пароля) на эти пути остаются.
_PUBLIC_GET_PATHS = frozenset({"/proxy.pac"})
# Разрешённые схемы proxy-URI: только реально поддерживаемые naive.
_ALLOWED_PROXY_SCHEMES = ("https://", "http://", "quic://")
# Имена, занятые статическими маршрутами /api/configs/export|import:
# такой пресет нельзя было бы получить через GET (роутинг отдаёт файл)
RESERVED_NAMES = frozenset({"export", "import"})
APP_VERSION = "0.23.0"


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


def _bind_is_loopback() -> bool:
    host, _ = _parse_bind(PANEL_BIND)
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False  # нераспознанный адрес считаем публичным (fail-closed)


def _conf_upsert(updates: dict[str, str | None]) -> None:
    """Атомарно обновить/удалить ключи panel.conf, сохранив остальные строки.

    Дубли ключа схлопываются: _parse_conf работает по принципу last-wins,
    поэтому оставленная старая копия победила бы после рестарта (и вернула
    бы удалённый токен). Первое вхождение переписываем, остальные выкидываем.
    """
    try:
        lines = PANEL_CONF.read_text(encoding="utf-8").splitlines()
    except OSError:
        lines = []
    pending = dict(updates)
    seen: set[str] = set()
    out: list[str] = []
    for line in lines:
        s = line.strip()
        key = (s.split("=", 1)[0].strip()
               if s and not s.startswith("#") and "=" in s else None)
        if key in pending:
            if key not in seen and pending[key] is not None:
                out.append(f'{key}="{pending[key]}"')
            seen.add(key)
            continue
        out.append(line)
    for key, value in pending.items():
        if key not in seen and value is not None:
            out.append(f'{key}="{value}"')
    text = "\n".join(out) + ("\n" if out else "")
    tmp: Path | None = None
    try:
        PANEL_CONF.parent.mkdir(parents=True, exist_ok=True)
        # Уникальный temp на каждый вызов: waitress обслуживает запросы потоками,
        # общий panel.conf.tmp давал гонку (replace → FileNotFoundError, потеря
        # ключа, чужой finally удалял файл посреди записи).
        fd, tmp_name = tempfile.mkstemp(
            dir=str(PANEL_CONF.parent), prefix=".panel.conf.", suffix=".tmp")
        tmp = Path(tmp_name)
        # install.sh кладёт panel.conf с 0644, а внутри секреты: всегда 0600.
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, PANEL_CONF)
    except OSError as exc:
        # путь в тело ответа не отдаём — только в лог
        _log.error("panel.conf write failed: %s", exc)
        abort(500, description="cannot write panel.conf")
    finally:
        if tmp is not None:
            try:
                tmp.unlink()
            except OSError:
                pass


__all__ = [
    "PANEL_CONF", "CONF_KEYS", "_CONF_SKIPPED", "_CONF_FILE_KEYS",
    "_parse_conf", "_apply_conf_file", "_conf_upsert",
    "NAIVEPROXY_DIR", "CONF_D", "ACTIVE_CONFIG", "ACTIVE_POINTER",
    "INIT_SCRIPT", "LOG_FILE", "PID_FILE", "STOP_MARKER",
    "NAIVE_BIN", "NAIVE_BUILD", "NAIVE_TAG", "NAIVE_SRC_REPO",
    "NAIVE_SRC_API", "NAIVE_UPDATE_LOG", "NAIVE_UPDATE_STATE",
    "_NAIVE_CHECK_TTL", "_NAIVE_ERR_TTL", "_NAIVE_STALE_S",
    "PANEL_ADMIN_PASS", "PANEL_BIND", "ALLOWED_HOSTS", "PANEL_INIT",
    "_THREADS_RAW", "WAITRESS_THREADS", "_THREADS_INVALID",
    "PANEL_LOG", "LOG_TRIM_INTERVAL", "_LOG_MAX_RAW", "_LOG_KEEP_RAW",
    "_int_or_default", "LOG_TRIM_MAX", "_LOG_MAX_INVALID",
    "LOG_TRIM_KEEP", "_LOG_KEEP_INVALID",
    "_WATCHDOG_RAW", "WATCHDOG_ENABLED", "_WATCHDOG_INTERVAL_RAW",
    "WATCHDOG_INTERVAL", "_WATCHDOG_INTERVAL_INVALID", "WATCHDOG_FLAP_MAX", "WATCHDOG_FLAP_WINDOW",
    "WATCHDOG_RECHECK_S",
    "E2E_URL", "E2E_TIMEOUT", "E2E_HISTORY", "_E2E_KEEP_RAW", "E2E_KEEP",
    "UPTIME_HISTORY", "_UPTIME_KEEP_S", "_UPTIME_MIN_SPAN_S",
    "_E2E_KEEP_INVALID", "_E2E_TRIM_EVERY",
    "FAILOVER_CONF", "_FAILOVER_RAW", "FAILOVER_ENABLED",
    "_FAILOVER_INTERVAL_RAW", "FAILOVER_INTERVAL", "_FAILOVER_INTERVAL_INVALID",
    "_FAILOVER_FAST_RAW", "FAILOVER_FAST", "_FAILOVER_FAST_INVALID",
    "_FAILOVER_THRESHOLD_RAW", "FAILOVER_THRESHOLD",
    "_FAILOVER_THRESHOLD_INVALID", "FAILOVER_CHAIN_MAX",
    "_FAILOVER_RETURN_ALIVE_RAW", "FAILOVER_RETURN_ALIVE",
    "_FAILOVER_RETURN_ALIVE_INVALID", "_FAILOVER_RETURN_COOLDOWN_RAW",
    "FAILOVER_RETURN_COOLDOWN", "_FAILOVER_RETURN_COOLDOWN_INVALID",
    "UPDATE_REPO", "UPDATE_API_BASE", "UPDATE_RAW_BASE",
    "PANEL_DIR", "UPDATE_LOG", "UPDATE_STATE", "PANEL_UPDATE_FILES",
    "_TAG_RE", "_UPDATE_CHECK_TTL", "_UPDATE_ERR_TTL", "_UPDATE_STALE_S",
    "NAME_RE", "_ALLOWED_PROXY_SCHEMES", "_PUBLIC_GET_PATHS", "RESERVED_NAMES",
    "APP_VERSION",
    "_ensure_dirs", "_parse_bind", "_default_allowed_hosts",
    "_bind_is_loopback",
]
