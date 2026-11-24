"""Управление сервисом naive: init-скрипт, pid-файл, живость процесса.

Шаг 4/7 модульного разделения (ARCH-01). Перенесено из naivepanel.py
дословно. `_status()` остаётся в naivepanel.py — это агрегатор поверх
watchdog/failover/notify (переедет вместе с monitor-шагом).

Здесь же — здоровье собственного рантайма панели (`_runtime_*`): сможет ли
СВЕЖИЙ интерпретатор поднять её после рестарта.

Конфигурация — через атрибут модуля-владельца (`cfg.INIT_SCRIPT`,
`cfg.PID_FILE`): перезапись `app.cfg.INIT_SCRIPT = stub` в тестах и
перечитывание env при reload видны здесь.
"""

import logging
import os
import re
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

from flask import abort

from panel import config as cfg

log = logging.getLogger("naivepanel")


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
    if not cfg.INIT_SCRIPT.exists():
        abort(503, description=f"{cfg.INIT_SCRIPT} not found")
    # stop в S99naiveproxy ждёт до 10с, restart = stop+start — таймаут обязан
    # покрывать худший случай, иначе /bin/sh убивают посреди рестарта
    return _run(["/bin/sh", str(cfg.INIT_SCRIPT), action], timeout=30)


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
    if cfg.PID_FILE.exists():
        try:
            pid = int(cfg.PID_FILE.read_text(encoding="utf-8").strip())
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
                uptime = max(0, int(time.time() - cfg.PID_FILE.stat().st_mtime))
    return running, pid, uptime


# --- Сможет ли панель подняться снова ----------------------------------------
# Работающий процесс держит код в памяти и не замечает, что интерпретатор или
# зависимости подменили на диске. Реальный кейс (Entware, ноя 2026): `opkg
# upgrade` сменил minor Python (3.13 → 3.14), pip-пакеты flask/waitress
# остались в каталоге старой версии — панель продолжала отвечать, но любой
# рестарт («Обновить», «Перезапуск», откат) был для неё последним. Поэтому
# перед рестартом спрашиваем не себя, а СВЕЖИЙ процесс: тем же интерпретатором
# (sys.executable — им же стартует init-скрипт) импортируем нужное на старте.

PANEL_STARTED = time.time()  # момент старта процесса: UI отличит перезапущенную панель

_RUNTIME_RECHECK_S = 120.0        # подменено/сломано → фоновая перепроверка не чаще
_RUNTIME_MIN_S = 5.0              # но смена признака на диске — сразу (не чаще 5с)
_RUNTIME_TIMEOUT_S = 30.0         # холодный старт python на медленном MIPS
_RUNTIME_LOCK = threading.Lock()  # вердикт + «один пробник одновременно»
# Пока признаков поломки нет, верим «ok» и не форкаем вовсе: раз процесс
# стартовал, свежий интерпретатор только что всё это импортировал.
# reason_at_probe — признак на диске в момент последней проверки: его смена
# (зависимость пропала или починили) запускает проверку вне общего интервала.
_RUNTIME: dict[str, Any] = {"state": "ok", "probed_at": 0.0, "thread": None,
                            "reason_at_probe": None}
# Крючок «впервые сломано» (переход в broken): monitor вешает на него
# уведомление — service не импортирует monitor (зависимость односторонняя).
_RUNTIME_ON_BROKEN: Any = None

# Код пробника — константа; список модулей приходит через окружение (NP_DEPS)
# — тот же контракт, что у deps_check в install.sh. exit 3 = что-то не
# импортируется (имена — в stdout), 0 = всё на месте.
_RUNTIME_PROBE = (
    "import importlib, os, sys\n"
    "missing = []\n"
    "for name in os.environ.get('NP_DEPS', '').split():\n"
    "    try:\n"
    "        importlib.import_module(name)\n"
    "    except ImportError:\n"
    "        missing.append(name)\n"
    "print(' '.join(missing))\n"
    "sys.exit(3 if missing else 0)\n"
)


def _runtime_modules() -> tuple[str, ...]:
    """Что обязан импортировать свежий интерпретатор, иначе панель не служит."""
    mods = ["flask"]
    if not cfg._bind_is_loopback():
        # Werkzeug fallback разрешён только на loopback (SEC-06): на LAN
        # панель без waitress принципиально не стартует
        mods.append("waitress")
    if cfg.PANEL_ADMIN_PASS.exists():
        mods.append("bcrypt")  # без него стартует, но не пускает никого
    return tuple(mods)


def _runtime_disk_version() -> tuple[int, int] | None:
    """(major, minor) интерпретатора на диске — по имени файла (python3.14).

    На Entware /opt/bin/python3 — symlink на python3.<minor>; имя без версии
    не распознаётся (None) — тогда подмену видит признак «stdlib нет на диске».
    """
    try:
        real = os.path.realpath(sys.executable or "")
    except (OSError, ValueError):
        return None
    m = re.search(r"python(\d+)\.(\d+)$", os.path.basename(real))
    return (int(m[1]), int(m[2])) if m else None


def _runtime_reason() -> str | None:
    """Безфорковое «почему так вышло» — по следам подмены на диске; None — следов нет.

    Проверяем только модули с реальным файлом: frozen/built-in (на Entware
    `os` — frozen, а `os.__file__` указывает на несуществующий os.py: пакет
    ставит только os.pyc) файла не имеют, и их «отсутствие» — не поломка.
    """
    disk = _runtime_disk_version()
    if disk and disk != sys.version_info[:2]:
        now = ".".join(str(x) for x in sys.version_info[:3])
        return (f"Python на роутере обновлён: {now} → "
                f"{'.'.join(str(x) for x in disk)}. Пакеты, установленные pip, "
                "остались со старой версией.")
    for name in _runtime_modules():
        mod = sys.modules.get(name)
        spec = getattr(mod, "__spec__", None)
        origin = getattr(spec, "origin", None)
        if origin in (None, "frozen", "built-in"):
            continue  # файла нет по природе модуля — судить не о чем
        path = getattr(mod, "__file__", None)
        if path and not os.path.exists(path):
            return "Зависимости панели удалены или переустановлены на диске."
    return None


def _runtime_run(python: str, mods: tuple[str, ...]) -> dict[str, Any]:
    """Свежий процесс импортирует mods; любой исход нормализован в вердикт."""
    try:
        # python — интерпретатор самого процесса; код — константа
        r = subprocess.run(  # nosec B603
            [python, "-c", _RUNTIME_PROBE], capture_output=True, text=True,
            timeout=_RUNTIME_TIMEOUT_S,
            env={**os.environ, "NP_DEPS": " ".join(mods)})
    except subprocess.TimeoutExpired:
        return {"state": "unknown", "missing": [],
                "detail": f"проверка не завершилась за {_RUNTIME_TIMEOUT_S:.0f}с"}
    except OSError as exc:
        return {"state": "unknown", "missing": [],
                "detail": f"не удалось запустить {python}: {exc}"}
    if r.returncode == 0:
        return {"state": "ok", "missing": []}
    if r.returncode == 3:
        return {"state": "broken", "missing": r.stdout.split()}
    return {"state": "unknown", "missing": [],
            "detail": f"проверка завершилась с кодом {r.returncode}"}


def _runtime_override() -> str | None:
    """Подмена вердикта для тестов и демо (NAIVEPANEL_RUNTIME_OVERRIDE), если задана.

    Только env (в panel.conf ключа нет) и читается при вызове, а не при
    импорте — reload-фикстуры её видят. В проде не задана.
    """
    forced = os.environ.get("NAIVEPANEL_RUNTIME_OVERRIDE")
    return forced if forced in ("ok", "broken", "unknown") else None


def _runtime_hint() -> str:
    """Рецепт для SSH — теми же командами, что чинит deps_ensure в install.sh.

    bcrypt — только opkg: pip собирает его из исходников (нужен Rust), а
    пересборка пакета под новый Python не меняет версию — opkg upgrade такое
    пропускает, поэтому с --force-reinstall.
    """
    mods = _runtime_modules()
    steps = []
    pip = [m for m in mods if m != "bcrypt"]
    if pip:
        steps.append(f"{sys.executable} -m pip install --no-cache-dir "
                     f"{' '.join(pip)}")
    if "bcrypt" in mods:
        steps.append("opkg install --force-reinstall python3-bcrypt")
    return "; ".join(steps)


def _runtime_probe() -> dict[str, Any]:
    """Вердикт свежего интерпретатора: ok | broken | unknown (+ reason/detail)."""
    mods = _runtime_modules()
    forced = _runtime_override()
    if forced is not None:
        res = {"state": forced, "missing": list(mods) if forced == "broken" else []}
    elif sys.executable:
        res = _runtime_run(sys.executable, mods)
    else:
        res = {"state": "unknown", "missing": [],
               "detail": "интерпретатор процесса неизвестен"}
    if res["state"] == "broken":
        res["detail"] = ("свежий интерпретатор не импортирует: "
                         + ", ".join(res.get("missing") or mods))
        res["hint"] = _runtime_hint()
    res["reason"] = _runtime_reason()
    return res


def _runtime_refresh() -> dict[str, Any]:
    """Пробник и запись вердикта в кэш — фоновый поток и синхронные вызовы."""
    try:
        res = _runtime_probe()
    except Exception:  # noqa: BLE001 — фон не должен умирать молча
        log.warning("runtime probe crashed", exc_info=True)
        res = {"state": "unknown", "missing": [],
               "detail": "проверка рантайма сломалась — см. лог панели"}
    with _RUNTIME_LOCK:
        was = _RUNTIME["state"]
        _RUNTIME.update(res, probed_at=time.monotonic(), thread=None,
                        reason_at_probe=res.get("reason"))
    if res["state"] == "broken":
        log.warning("runtime is broken: %s %s", res.get("detail", ""),
                    res.get("reason") or "")
    elif was != "ok":
        log.info("runtime is %s (was %s)", res["state"], was)
    if res["state"] == "broken" and was != "broken" and _RUNTIME_ON_BROKEN is not None:
        try:
            _RUNTIME_ON_BROKEN(res)
        except Exception:  # noqa: BLE001 — уведомление не должно портить вердикт
            log.warning("runtime alert failed", exc_info=True)
    return res


def _runtime_status() -> dict[str, Any]:
    """Блок `runtime` для /api/status — сам без форков: пробник только в фоне."""
    reason = _runtime_reason()
    with _RUNTIME_LOCK:
        res = {k: v for k, v in _RUNTIME.items()
               if k not in ("probed_at", "thread", "reason_at_probe")}
        now = time.monotonic()
        since = now - _RUNTIME["probed_at"]
        # признак на диске сменился после последней проверки — зависимость
        # пропала или её починили: проверяем сразу, не дожидаясь RECHECK_S
        changed = _RUNTIME["reason_at_probe"] != reason and since >= _RUNTIME_MIN_S
        stale = since >= _RUNTIME_RECHECK_S
        # без признаков и со «здоровым» вердиктом не форкаем вовсе; «сломано»
        # перепроверяем по интервалу, принудительный вердикт — тоже
        want = changed or (stale and (reason is not None
                                      or _RUNTIME["state"] == "broken"
                                      or _runtime_override() == "broken"))
        if _RUNTIME["thread"] is None and want:
            _RUNTIME["thread"] = threading.Thread(
                target=_runtime_refresh, name="runtime-probe", daemon=True)
            _RUNTIME["thread"].start()
        if _RUNTIME["thread"] is not None:
            res["checking"] = True
    res["reason"] = reason
    return res


def _runtime_restart_block() -> str | None:
    """Вердикт перед рестартом панели; не-None — текст отказа (409).

    Синхронно, а не из кэша: рестарт — редкое действие, а диск мог измениться
    с последней фоновой проверки (зависимости починили по SSH — клик по
    «Перезапуск» тут же это видит).
    """
    res = _runtime_refresh()
    if res["state"] != "broken":
        return None
    return (f"панель не запустится после перезапуска — {res.get('detail', '')}. "
            "Восстановите зависимости: кнопка «Исправить и перезапустить» вверху "
            f"страницы или по SSH `{res.get('hint') or _runtime_hint()}`.")


__all__ = ["PANEL_STARTED", "_pid_is_naive", "_proxy_running", "_run", "_service",
           "_runtime_modules", "_runtime_reason", "_runtime_override", "_runtime_run",
           "_runtime_hint", "_runtime_probe", "_runtime_refresh", "_runtime_status",
           "_runtime_restart_block"]
