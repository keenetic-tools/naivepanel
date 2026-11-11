"""Обновления панели и бинарника naive, откат из бэкапов (ARCH-01, шаг 6/7).

Перенесено из naivepanel.py дословно: резолв релизов, state/логи апдейтов,
фоновый воркер бинарника naive, rollback панели/бинарника. Роуты
(/api/update/*, /api/naive/*, /api/rollback*) остаются в naivepanel.py и
зовут функции отсюда через `upd.*`.

Конфигурация — cfg.*, пресеты — pres.*, сервис — svc.*; сетевой хелпер и
статус прокси — mon.*. Логгер — тот же 'naivepanel'.
"""

import json
import logging
import os
import platform
import re
import shutil
import subprocess  # nosec B404 — только фиксированные argv, shell=False
import tarfile
import threading
import time
from pathlib import Path
from typing import Any

try:  # не весь Entware-минималистичный python3 несёт lzma
    import lzma  # noqa: F401
    _HAS_LZMA = True
except ImportError:
    _HAS_LZMA = False

from flask import abort, jsonify, request

from panel import config as cfg
from panel import monitor as mon
from panel import presets as pres
from panel import service as svc

log = logging.getLogger("naivepanel")


# --- Self-update: проверка и установка обновлений из UI ---------------------

def _http_download(url: str, dst: Path, timeout: float = 300.0) -> None:
    """Скачивание бинарного файла через curl/wget — как mon._http_get, но в файл.

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
        data = json.loads(mon._http_get(f"{cfg.UPDATE_API_BASE}/repos/{cfg.UPDATE_REPO}/releases/latest"))
        tag = data.get("tag_name") or ""
        if cfg._TAG_RE.match(tag):
            rel = {"tag": tag,
                   "notes": (data.get("body") or "").strip()[:4000],
                   "url": data.get("html_url") or ""}
    except (RuntimeError, ValueError):
        pass  # релизов нет или API недоступен — решит список тегов
    best: str | None = None
    try:
        tags = json.loads(mon._http_get(f"{cfg.UPDATE_API_BASE}/repos/{cfg.UPDATE_REPO}/tags?per_page=10"))
        names = (t.get("name") or "" for t in tags if isinstance(t, dict))
        best = max((n for n in names if cfg._TAG_RE.match(n)),
                   key=_ver_key, default=None)
    except (RuntimeError, ValueError) as exc:
        if not rel:
            raise RuntimeError(f"cannot reach {cfg.UPDATE_API_BASE}: {exc}") from exc
    if best and (not rel or _ver_key(best) > _ver_key(rel["tag"])):
        return {"tag": best, "notes": "",
                "url": f"https://github.com/{cfg.UPDATE_REPO}/releases/tag/{best}"}
    if rel:
        return rel
    raise RuntimeError(f"no vX.Y.Z tags/releases found in {cfg.UPDATE_REPO}")


def _update_state_read() -> dict[str, Any]:
    try:
        st = json.loads(cfg.UPDATE_STATE.read_text(encoding="utf-8"))
        return st if isinstance(st, dict) else {}
    except (OSError, ValueError):
        return {}


# Резервирование запуска update-операций: резолв релиза и скачивание идут
# по сети секунды и выполняются ВНЕ лока; сам запуск (re-check state →
# spawn → запись «running») — под локом. Без этого два параллельных запроса
# на медленной сети проходят гейт до первой записи «running» и поднимают
# два установщика/воркера над одними файлами.
_UPDATE_LAUNCH_LOCK = threading.Lock()        # panel apply + panel rollback
_NAIVE_UPDATE_LAUNCH_LOCK = threading.Lock()  # naive update + naive rollback


def _update_state_write(st: dict[str, Any]) -> None:
    try:
        # атомарно (rename): неатомарный write_text оставлял читателю пустой
        # файл, ридер возвращал {} — панель сочла бы апдейт завершённым
        pres._save_json(cfg.UPDATE_STATE, st)
    except OSError as exc:  # state не критичен: обновление переживёт и без него
        log.warning("cannot write %s: %s", cfg.UPDATE_STATE, exc)


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
        if str(st.get("target") or "").lstrip("vV") == cfg.APP_VERSION:
            _update_state_write({**st, "phase": "done", "finished": time.time()})
            st["phase"] = "done"
        elif not _pid_alive(st.get("pid")):
            st["phase"] = "failed"
            _update_state_write(st)
        elif time.time() - float(st.get("started") or 0) > cfg._UPDATE_STALE_S:
            st["stale"] = True
    return st


def _backup_panel_files() -> Path:
    """Снапшот заменяемых файлов панели в backup/v{APP_VERSION}.

    Вызывается и перед self-update, и перед откатом: оба пути обязаны быть
    обратимыми. Файл хранится под именем оригинала — откат ищет по имени.
    """
    backup = cfg.PANEL_DIR / "backup" / f"v{cfg.APP_VERSION}"
    backup.mkdir(parents=True, exist_ok=True)
    for src in cfg.PANEL_UPDATE_FILES:
        if src.exists():
            shutil.copy2(src, backup / src.name)
    # backend-пакет (ARCH-01): backup/vX/panel/*.py, откат знает ту же схему
    pkg = cfg.PANEL_DIR / "panel"
    if pkg.is_dir():
        pkg_backup = backup / "panel"
        pkg_backup.mkdir(parents=True, exist_ok=True)
        for f in pkg.glob("*.py"):
            shutil.copy2(f, pkg_backup / f.name)
    return backup


_update_check_cache: dict[str, Any] = {}


# --- Бинарник naive: проверка версии и обновление из UI ----------------------

def _naive_bin_version() -> str | None:
    """Версия из самого бинарника: `naive --version` → «naive 154.0.8037.49».

    Бинарника нет или он не запускается (битая ручная установка) → None.
    """
    if not cfg.NAIVE_BIN.exists():
        return None
    try:
        r = subprocess.run([str(cfg.NAIVE_BIN), "--version"], capture_output=True,
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
    data = json.loads(mon._http_get(f"{cfg.NAIVE_SRC_API}/repos/{cfg.NAIVE_SRC_REPO}/releases/latest"))
    tag = data.get("tag_name") or ""
    assets = [(a.get("name") or "", a.get("browser_download_url") or "")
              for a in data.get("assets") or [] if isinstance(a, dict)]
    if not tag or not assets:
        raise RuntimeError(f"unexpected release payload from {cfg.NAIVE_SRC_REPO}")
    return {"tag": tag, "notes": (data.get("body") or "").strip()[:4000],
            "url": data.get("html_url") or "", "assets": assets}


def _naive_state_read() -> dict[str, Any]:
    try:
        st = json.loads(cfg.NAIVE_UPDATE_STATE.read_text(encoding="utf-8"))
        return st if isinstance(st, dict) else {}
    except (OSError, ValueError):
        return {}


def _naive_state_write(st: dict[str, Any]) -> None:
    try:
        cfg.NAIVEPROXY_DIR.mkdir(parents=True, exist_ok=True)
        # атомарно, как _update_state_write — по той же причине
        pres._save_json(cfg.NAIVE_UPDATE_STATE, st)
    except OSError as exc:  # state не критичен: обновление переживёт и без него
        log.warning("cannot write %s: %s", cfg.NAIVE_UPDATE_STATE, exc)


def _naive_state() -> dict[str, Any]:
    """State обновления бинарника; «running» без прогресса → stale.

    Воркер живёт потоком внутри панели: её рестарт убивает поток, pid для
    проверки взять неоткуда — потому только тайм-аут (скачивание ~3.5МБ
    укладывается в него с запасом, а реальный прогресс виден в логе).
    """
    st = _naive_state_read()
    if st.get("phase") == "running":
        if time.time() - float(st.get("started") or 0) > cfg._NAIVE_STALE_S:
            st["stale"] = True
    return st


def _naive_log(msg: str) -> None:
    try:
        with cfg.NAIVE_UPDATE_LOG.open("a", encoding="utf-8") as fh:
            fh.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}\n")
    except OSError:
        pass  # лог не критичен


def _validate_tar_members(tgz: Path) -> None:
    """Проверка ВСЕХ members архива до распаковки (SEC-03).

    Артефакт приходит из внешнего релиза: member с absolute path/`..` или
    symlink/hardlink мог бы писать вне stage. Основной путь — stdlib
    tarfile (одинаковая семантика на всех платформах); без python3-lzma
    (минимальные Entware-сборки) — хотя бы имена из `tar -tf`: path
    traversal отсекаем, типы members — нет. Распаковка в обоих случаях
    остаётся системному tar (зависимость xz не меняется).
    """
    if _HAS_LZMA:
        with tarfile.open(tgz, "r:xz") as archive:
            for member in archive.getmembers():
                member_path = Path(member.name)
                if member_path.is_absolute() or ".." in member_path.parts:
                    raise RuntimeError(f"unsafe archive path: {member.name!r}")
                if member.issym() or member.islnk() \
                        or not (member.isfile() or member.isdir()):
                    raise RuntimeError(f"unsupported archive member: {member.name!r}")
        return
    r = subprocess.run(["tar", "-tf", str(tgz)], capture_output=True,
                       text=True, timeout=60)  # nosec B603
    if r.returncode != 0:
        raise RuntimeError("cannot list archive (tar/xz missing?): "
                           + (r.stderr.strip() or f"rc={r.returncode}"))
    for name in r.stdout.splitlines():
        member_path = Path(name)
        if member_path.is_absolute() or ".." in member_path.parts:
            raise RuntimeError(f"unsafe archive path: {name!r}")


def _untar_xz(tgz: Path, dest: Path) -> None:
    """Распаковка .tar.xz: `tar -xJf`, при неудаче — `xz -dc | tar -xf -`.

    busybox-тар новых фидов Entware (1.38) не умеет -J, и пакет xz опцию в
    таре не появляется — распаковываем по частям: настоящий xz наружу
    (best-effort `opkg install xz`, как в install.sh), plain tar из stdin.
    """
    # nosec на последних строках вызовов (bandit привязывает их так);
    # частичный PATH ("tar"/"xz") осознан: busybox или GNU выбирает окружение
    r = subprocess.run(["tar", "-xJf", str(tgz), "-C", str(dest)],
                       capture_output=True, text=True, timeout=120)  # nosec B603
    if r.returncode == 0:
        return
    why = r.stderr.strip() or f"rc={r.returncode}"
    subprocess.run(["opkg", "install", "xz"], capture_output=True,
                   timeout=120)  # nosec B603 — best-effort, xz мог уже стоять
    try:
        xz = subprocess.Popen(["xz", "-dc", str(tgz)],
                              stdout=subprocess.PIPE)  # nosec B603
    except FileNotFoundError as exc:
        raise RuntimeError(f"tar -xJf failed ({why}); xz not found either") from exc
    try:
        tar = subprocess.run(["tar", "-xf", "-", "-C", str(dest)],
                             stdin=xz.stdout, capture_output=True, text=True,
                             timeout=120)  # nosec B603
    finally:
        if xz.stdout:
            xz.stdout.close()
        xz_rc = xz.wait(timeout=120)
    if tar.returncode != 0 or xz_rc != 0:
        raise RuntimeError("xz -dc | tar -xf failed: "
                           + (tar.stderr.strip()
                              or f"tar rc={tar.returncode}, xz rc={xz_rc}"))


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
        build = _naive_read(cfg.NAIVE_BUILD) or ""
        target = build.removesuffix("-static") or _naive_detect_target()
        picked = _naive_pick_asset(rel["assets"], target)
        if not picked:
            raise RuntimeError(f"release {tag} has no openwrt asset for "
                               f"target {target!r}")
        name, url = picked
        _naive_log(f"{tag}: asset {name} ({target})")
        stage = cfg.NAIVEPROXY_DIR / ".naive-update"
        shutil.rmtree(stage, ignore_errors=True)
        stage.mkdir(parents=True, exist_ok=True)
        tgz = stage / "naive.tar.xz"
        _naive_log(f"downloading {url}")
        _http_download(url, tgz)
        _validate_tar_members(tgz)  # до распаковки: вне stage писать нельзя
        _untar_xz(tgz, stage)  # busybox-тар без -J — см. фолбэк внутри
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
        was_active = mon._status()["active"]
        if cfg.NAIVE_BIN.exists():
            backup = cfg.NAIVEPROXY_DIR / "backup" / "naive.previous"
            backup.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(cfg.NAIVE_BIN, backup)
            # тег откатываемой версии: без него откатчик не знает, что вернёт
            prev_tag = _naive_read(cfg.NAIVE_TAG)
            if prev_tag:
                backup.with_name(backup.name + ".tag").write_text(
                    prev_tag + "\n", encoding="utf-8")
        # cp в тот же каталог + os.replace = rename внутри ФС: открытый
        # для записи работающий бинарник дал бы ETXTBSY, а rename оставляет
        # старый образ выполняющемуся процессу
        placed = cfg.NAIVE_BIN.with_name(cfg.NAIVE_BIN.name + ".new")
        shutil.copy2(new_bin, placed)
        placed.chmod(0o755)
        os.replace(placed, cfg.NAIVE_BIN)
        cfg.NAIVE_TAG.write_text(tag + "\n", encoding="utf-8")
        cfg.NAIVE_BUILD.write_text(
            name.rsplit(".tar.xz", 1)[0].rsplit("-openwrt-", 1)[-1] + "\n",
            encoding="utf-8")
        shutil.rmtree(stage, ignore_errors=True)
        _naive_log(f"installed {tag} -> {cfg.NAIVE_BIN}")
        restarted = False
        restart_rc = None
        if was_active and cfg.INIT_SCRIPT.exists():
            with mon._SERVICE_LOCK:
                rst = svc._service("restart")
            restart_rc = rst["rc"]
            restarted = restart_rc == 0  # как в rollback: rc==0 или честный провал
            _naive_log(f"service restart rc={restart_rc}")
        _naive_state_write({"phase": "done", "target": tag,
                            "finished": time.time(), "version": new_ver,
                            "restarted": restarted, "restart_rc": restart_rc})
        log.info("naive binary updated to %s (%s)", tag, name)
    except Exception as exc:  # любая ошибка воркера — в state и лог, не в панель
        _naive_log(f"failed: {exc}")
        log.warning("naive update failed", exc_info=True)
        _naive_state_write({"phase": "failed", "error": str(exc)[:500],
                            "finished": time.time()})


_naive_check_cache: dict[str, Any] = {}


# --- Rollback: откат панели и бинарника из бэкапов, без SSH -------------------
# Self-update перед заменой снапшотит файлы в panel/backup/vX.Y.Z/, обновление
# бинарника — в proxy/backup/naive.previous. До v0.15 доставать их можно было
# только руками по SSH — ровно тот случай, когда консоли под рукой нет. Здесь
# — чтение бэкапов, восстановление и чистка: откат панели перезапускает её саму
# (панель продолжает работать старым кодом, пока файлы не вернутся на место),
# откат бинарника — тот же паттерн, что обновление: rename + рестарт сервиса.

NAIVE_PREV_BIN = cfg.NAIVEPROXY_DIR / "backup" / "naive.previous"
NAIVE_PREV_TAG = cfg.NAIVEPROXY_DIR / "backup" / "naive.previous.tag"


def _rollback_panel_versions() -> list[dict[str, Any]]:
    """Версии панели в backup/: [{version, size, ts}], новые сверху.

    Считаем только каталоги строгого vX.Y.Z — мусорные имена туда не попадают.
    """
    out: list[dict[str, Any]] = []
    try:
        dirs = [d for d in (cfg.PANEL_DIR / "backup").iterdir()
                if d.is_dir() and cfg._TAG_RE.match(d.name)]
    except OSError:
        return out
    for d in dirs:
        size = 0
        try:
            size = sum(f.stat().st_size for f in d.iterdir() if f.is_file())
            ts = int(d.stat().st_mtime)
        except OSError:
            continue
        out.append({"version": d.name, "size": size, "ts": ts})
    out.sort(key=lambda v: _ver_key(v["version"]), reverse=True)
    return out


def _rollback_binary():
    """Возврат naive.previous на место бинарника: проверили — заменили —
    перезапустили, если прокси работал. Синхронно: сеть не нужна, это
    локальный rename, сервер при этом живёт."""
    bprev = NAIVE_PREV_BIN
    if not bprev.is_file():
        abort(404, description="no naive.previous backup — nothing to roll back to")
    try:
        rv = subprocess.run([str(bprev), "--version"], capture_output=True,
                            text=True, timeout=15)  # nosec B603
    except (OSError, subprocess.TimeoutExpired) as exc:
        abort(500, description=f"cannot run backup binary: {exc}")
    out = (rv.stdout or "").strip().splitlines()
    if rv.returncode != 0 or not out:
        abort(500, description="backup binary failed --version check — "
                               "keeping the current one")
    new_ver = out[0].strip()
    prev_tag = _naive_read(NAIVE_PREV_TAG)
    was_active = mon._status()["active"]
    try:
        # тот же rename-паттерн, что обновление: работающий naive доживает
        # свой инод, ETXTBSY не бывает
        placed = cfg.NAIVE_BIN.with_name(cfg.NAIVE_BIN.name + ".new")
        shutil.copy2(bprev, placed)
        placed.chmod(0o755)
        os.replace(placed, cfg.NAIVE_BIN)
        if prev_tag:
            cfg.NAIVE_TAG.write_text(prev_tag + "\n", encoding="utf-8")
        else:
            # тег прошлой версии неизвестен; оставить тег текущей — врать
            # в /api/naive/check, лучше без тега (check возьмёт из бинарника)
            cfg.NAIVE_TAG.unlink(missing_ok=True)
    except OSError as exc:
        abort(500, description=f"cannot restore binary: {exc}")
    _naive_log(f"rollback -> {prev_tag or new_ver}")
    restarted = False
    restart_rc = None
    if was_active and cfg.INIT_SCRIPT.exists():
        with mon._SERVICE_LOCK:
            rst = svc._service("restart")
        restart_rc = rst["rc"]
        restarted = restart_rc == 0  # «перезапущен» = только при rc==0 (REL-05)
        _naive_log(f"service restart rc={restart_rc}")
    _naive_state_write({"phase": "done", "target": prev_tag or new_ver,
                        "finished": time.time(), "version": new_ver,
                        "restarted": restarted, "restart_rc": restart_rc,
                        "rollback": True})
    log.warning("naive binary rolled back to %s by %s",
                prev_tag or new_ver, request.remote_addr)
    return jsonify({"restored": prev_tag or new_ver, "version": new_ver,
                    "restarted": restarted, "restart_rc": restart_rc})


__all__ = [
    "NAIVE_PREV_BIN",
    "NAIVE_PREV_TAG",
    "_NAIVE_UPDATE_LAUNCH_LOCK",
    "_UPDATE_LAUNCH_LOCK",
    "_backup_panel_files",
    "_http_download",
    "_latest_release",
    "_naive_bin_version",
    "_naive_check_cache",
    "_naive_detect_target",
    "_naive_log",
    "_naive_pick_asset",
    "_naive_read",
    "_naive_release",
    "_naive_state",
    "_naive_state_read",
    "_naive_state_write",
    "_naive_update_worker",
    "_naive_ver_key",
    "_pid_alive",
    "_rollback_binary",
    "_rollback_panel_versions",
    "_update_check_cache",
    "_update_state",
    "_update_state_read",
    "_update_state_write",
    "_untar_xz",
    "_validate_tar_members",
    "_ver_key",
]
