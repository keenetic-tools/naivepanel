"""Управление сервисом naive: init-скрипт, pid-файл, живость процесса.

Шаг 4/7 модульного разделения (ARCH-01). Перенесено из naivepanel.py
дословно. `_status()` остаётся в naivepanel.py — это агрегатор поверх
watchdog/failover/notify (переедет вместе с monitor-шагом).

Конфигурация — через атрибут модуля-владельца (`cfg.INIT_SCRIPT`,
`cfg.PID_FILE`): перезапись `app.cfg.INIT_SCRIPT = stub` в тестах и
перечитывание env при reload видны здесь.
"""

import os
import subprocess
import time
from pathlib import Path
from typing import Any

from flask import abort

from panel import config as cfg


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


__all__ = ["_pid_is_naive", "_proxy_running", "_run", "_service"]
