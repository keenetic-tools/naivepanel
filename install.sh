#!/bin/sh
# NaivePanel installer for Entware routers (Keenetic and other OpenWrt-like
# firmware with Entware). Runs ON the router.
#
# Bootstrap (pin to a release tag, not `main`):
#   curl -fsSL https://raw.githubusercontent.com/keenetic-tools/naivepanel/v0.10.0/install.sh | sh -s -- --with-auth
#
# Safe to pipe into `sh`: the confirmation and password prompts read the
# terminal (/dev/tty), never the piped stdin. Add --yes to skip confirmation.
#
# Idempotent upgrade: just run it again. Config (admin.pass, conf.d/*) is kept;
# a pre-0.2.0 layout is migrated automatically.
#
# The naive client binary: when missing, the installer detects the openwrt
# target from the hardware (uname/cpuinfo) and downloads a matching prebuilt
# from klzgrad/naiveproxy releases (see README «Установка бинарника naive»).
# An existing binary is never touched — updates go through the panel's
# «Бинарник naive» section.
#
# Flags:
#   --with-auth          create /opt/etc/naive/panel/admin.pass (interactive)
#   --bind HOST:PORT     write NAIVEPANEL_BIND to /opt/etc/naive/panel/panel.conf
#   --hosts LIST         write NAIVEPANEL_HOSTS to /opt/etc/naive/panel/panel.conf
#   --ref TAG            git tag/ref to install (default: v0.10.0)
#   --naive-target TGT   openwrt target for the naive binary, overrides
#                        hardware detection (e.g. aarch64_cortex-a53)
#   --naive-ref TAG      klzgrad/naiveproxy tag to install (default: latest)
#   --naive-force        (re)install the naive binary even if one exists
#   --skip-naive         never touch the naive binary, warn only
#   --from-update        internal: spawned by the panel's self-update —
#                        skips python/deps checks (the running panel already
#                        proves they work; their forks die on tight router RAM)
#                        and the naive step (panel updates binary separately)
#   --no-naive-init      do not install S99naiveproxy init script
#   --yes                non-interactive (no confirmation prompt)
#   --uninstall          stop services and remove installed files
#   --purge              with --uninstall: also remove configs and admin.pass

set -u

# NAIVEPANEL_REPO: переопределение репозитория (зеркала, e2e-тесты с локальным
# сервером). Панель при self-update передаёт его в окружение потомку.
REPO="${NAIVEPANEL_REPO:-keenetic-tools/naivepanel}"
REF="v0.10.0"
# Источник prebuilt-бинарников naive (зеркала, e2e с локальным сервером).
NAIVE_SRC_REPO="${NAIVEPROXY_SRC_REPO:-klzgrad/naiveproxy}"
NAIVE_SRC_API="${NAIVEPROXY_SRC_API:-https://api.github.com}"
NAIVE_TARGET=""   # --naive-target: override детекта таргета
NAIVE_REF=""      # --naive-ref: конкретный тег naiveproxy вместо latest
NAIVE_FORCE=0     # --naive-force: заменить даже существующий бинарник
SKIP_NAIVE=0      # --skip-naive: не трогать бинарник вовсе
BIND=""
HOSTS=""
WITH_AUTH=0
FROM_UPDATE=0
NO_NAIVE_INIT=0
YES=0
UNINSTALL=0
PURGE=0

NAIVE_ROOT=/opt/etc/naive
PANEL_DIR=/opt/etc/naive/panel
NAIVEPROXY_DIR=/opt/etc/naive/proxy
INIT_DIR=/opt/etc/init.d
PANEL_CONF=/opt/etc/naive/panel/panel.conf
# legacy (pre-0.4.1): настройки писались сюда, но не читались init-скриптом
RC_CONF=/opt/etc/init.d/rc.conf

info() { echo "==> $*"; }
warn() { echo "WARN: $*" >&2; }
die()  { echo "ERROR: $*" >&2; exit 1; }

fetch() {  # $1=url -> stdout
    # таймауты обязательны: self-update из панели крутит этот скрипт в фоне,
    # и зависший curl оставлял бы update.state «running» до протухания
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --connect-timeout 15 --retry 2 "$1" || die "download failed: $1"
    elif command -v wget >/dev/null 2>&1; then
        wget -q -T 30 -t 2 -O- "$1" || die "download failed: $1"
    else
        die "need curl or wget (opkg install curl)"
    fi
}

usage() {
    cat <<'EOF'
Usage: install.sh [flags]

  --with-auth          create /opt/etc/naive/panel/admin.pass (interactive)
  --bind HOST:PORT     write NAIVEPANEL_BIND to /opt/etc/naive/panel/panel.conf
  --hosts LIST         write NAIVEPANEL_HOSTS to /opt/etc/naive/panel/panel.conf
  --ref TAG            git tag/ref to install (default: v0.10.0)
  --naive-target TGT   openwrt target for naive binary (override detection)
  --naive-ref TAG      klzgrad/naiveproxy tag (default: latest release)
  --naive-force        (re)install naive binary even if one exists
  --skip-naive         never touch the naive binary
  --from-update        internal: spawned by self-update, skips python checks
  --no-naive-init      do not install S99naiveproxy init script
  --yes                non-interactive (no confirmation prompt)
  --uninstall          stop services and remove installed files
  --purge              with --uninstall: also remove configs and admin.pass
EOF
    exit 0
}

gen_admin_pass() {  # -> stdout: `admin:<bcrypt-hash>`; пароль спрашивается дважды
    "$PYTHON" - <<'PY'
import bcrypt, getpass, sys
for _ in range(3):
    pw = getpass.getpass("password: ")
    if not pw:
        print("empty password is not allowed", file=sys.stderr)
        continue
    if pw != getpass.getpass("confirm: "):
        print("passwords do not match", file=sys.stderr)
        continue
    sys.stdout.write("admin:" + bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode() + "\n")
    sys.exit(0)
sys.exit(1)
PY
}

# panel.conf: единственное место настроек панели — его читает сам
# naivepanel.py, поэтому файл переживает любые обновления init-скрипта.
conf_upsert() {  # $1=KEY $2=value — обновить ключ, остальное не трогать
    [ -f "$PANEL_CONF" ] || : >"$PANEL_CONF"
    sed -i "/^[[:space:]]*$1=/d" "$PANEL_CONF"
    echo "$1=\"$2\"" >>"$PANEL_CONF"
}

# --- arg parsing -----------------------------------------------------------

while [ $# -gt 0 ]; do
    case "$1" in
        --with-auth)      WITH_AUTH=1 ;;
        --from-update)    FROM_UPDATE=1 ;;
        --no-naive-init)  NO_NAIVE_INIT=1 ;;
        --yes)            YES=1 ;;
        --uninstall)      UNINSTALL=1 ;;
        --purge)          PURGE=1 ;;
        --bind)           BIND="${2:-}"; shift ;;
        --hosts)          HOSTS="${2:-}"; shift ;;
        --ref)            REF="${2:-}"; shift ;;
        --naive-target)   NAIVE_TARGET="${2:-}"; shift ;;
        --naive-ref)      NAIVE_REF="${2:-}"; shift ;;
        --naive-force)    NAIVE_FORCE=1 ;;
        --skip-naive)     SKIP_NAIVE=1 ;;
        -h|--help)        usage ;;
        *) die "unknown flag: $1 (try --help)" ;;
    esac
    shift
done

# --- validate values (попадают в panel.conf и в Host-allowlist) -------------

if [ -n "$BIND" ]; then
    echo "$BIND" | grep -Eq '^\[?[A-Za-z0-9.:-]+\]?:[0-9]+$' \
        || die "--bind: expected HOST:PORT (e.g. 192.168.1.1:8089), got '$BIND'"
fi
if [ -n "$HOSTS" ]; then
    echo "$HOSTS" | grep -Eq '^(\[?[A-Za-z0-9.:-]+\]?(:[0-9]+)?)(,\[?[A-Za-z0-9.:-]+\]?(:[0-9]+)?)*$' \
        || die "--hosts: expected comma-separated HOST[:PORT] list, got '$HOSTS'"
fi

# --- uninstall -------------------------------------------------------------

if [ "$UNINSTALL" = 1 ]; then
    for init in S99naivepanel S99naiveproxy; do
        [ -x "$INIT_DIR/$init" ] && "$INIT_DIR/$init" stop >/dev/null 2>&1 || true
        rm -f "/opt/etc/rc.d/$init"
        [ "$PURGE" = 1 ] && rm -f "$INIT_DIR/$init"
    done
    if [ "$PURGE" = 1 ]; then
        rm -f "$PANEL_DIR/admin.pass" "$PANEL_CONF"
        rm -rf "$NAIVEPROXY_DIR" /opt/etc/naiveproxy /opt/etc/naivepanel /opt/naivepanel
        sed -i '/^[[:space:]]*NAIVEPANEL_BIND=/d;/^[[:space:]]*NAIVEPANEL_HOSTS=/d' "$RC_CONF" 2>/dev/null || true
        info "purged configs (admin.pass, panel.conf, proxy configs, legacy rc.conf vars)"
    fi
    rm -f "$PANEL_DIR/naivepanel.py" /opt/naivepanel/naivepanel.py
    rm -rf "$PANEL_DIR/templates" /opt/naivepanel/templates
    rmdir "$PANEL_DIR" /opt/naivepanel /opt/etc/naivepanel "$NAIVE_ROOT" 2>/dev/null || true
    info "uninstall complete"
    exit 0
fi

# --- preflight -------------------------------------------------------------

command -v opkg >/dev/null 2>&1 || die "opkg not found — is Entware installed on /opt?"
[ -d /opt ] || die "/opt not found — is Entware installed?"

if [ "$YES" != 1 ]; then
    # `curl … | sh` feeds the script itself on stdin: a plain `read` would
    # swallow script text instead of the answer, so always ask on the terminal.
    printf "Install NaivePanel from %s @ %s? [y/N] " "$REPO" "$REF" >&2
    if [ -t 0 ]; then
        read -r ans || true
    elif [ -c /dev/tty ] && : 2>/dev/null </dev/tty; then
        read -r ans </dev/tty || true
    else
        die "no terminal to confirm the install — re-run with --yes"
    fi
    case "$ans" in y|Y|yes|YES) ;; *) echo "aborted" >&2; exit 1 ;; esac
fi

# --- migrate pre-0.2.0 layout -----------------------------------------------

OLD_PANEL_DIR=/opt/naivepanel
OLD_PANEL_ETC=/opt/etc/naivepanel
OLD_PROXY_DIR=/opt/etc/naiveproxy

if [ -d "$OLD_PANEL_DIR" ] || [ -d "$OLD_PANEL_ETC" ] || [ -d "$OLD_PROXY_DIR" ]; then
    info "migrating pre-0.2.0 layout → $NAIVE_ROOT"
    # services hold absolute paths — stop before moving anything
    "$INIT_DIR/S99naivepanel" stop >/dev/null 2>&1 || true
    "$INIT_DIR/S99naiveproxy" stop >/dev/null 2>&1 || true
    mkdir -p "$NAIVE_ROOT"
    if [ -d "$OLD_PROXY_DIR" ]; then
        if [ -d "$NAIVEPROXY_DIR" ]; then
            warn "both $OLD_PROXY_DIR and $NAIVEPROXY_DIR exist — keeping the new one"
        else
            mv "$OLD_PROXY_DIR" "$NAIVEPROXY_DIR" || die "mv $OLD_PROXY_DIR"
        fi
    fi
    mkdir -p "$PANEL_DIR"
    if [ -f "$OLD_PANEL_ETC/admin.pass" ]; then
        if [ -f "$PANEL_DIR/admin.pass" ]; then
            warn "admin.pass exists in both places — keeping $PANEL_DIR/admin.pass"
        else
            mv "$OLD_PANEL_ETC/admin.pass" "$PANEL_DIR/admin.pass" || die "mv admin.pass"
        fi
        rmdir "$OLD_PANEL_ETC" 2>/dev/null || true
    fi
    # the old app dir holds only distributive files — the fresh copy now lives
    # in $PANEL_DIR; drop the stale one so there is no second copy to edit
    rm -f "$OLD_PANEL_DIR/naivepanel.py"
    rm -rf "$OLD_PANEL_DIR/templates"
    rmdir "$OLD_PANEL_DIR" 2>/dev/null \
        || warn "kept $OLD_PANEL_DIR (contains unexpected files)"
fi

# --- python + deps ---------------------------------------------------------

# The panel must run on Entware's python (opkg flask/bcrypt land in /opt as
# well), so on an opkg system never settle for a system python3.
PYTHON=/opt/bin/python3
[ -x "$PYTHON" ] || PYTHON=/opt/bin/python

if [ "$FROM_UPDATE" = 1 ]; then
    # Проверки ниже трижды форкают python, чтобы убедиться в том, что уже
    # доказано самим фактом работы панели, из которой мы запущены. На тесной
    # памяти роутера (naive + панель) именно эти форки — самое вероятное
    # место тихой смерти фонового обновления (кейс v0.9.0).
    [ -x "$PYTHON" ] || PYTHON=$(command -v python3 2>/dev/null || echo python3)
    info "python/deps checks skipped (--from-update)"
else
    if [ ! -x "$PYTHON" ] && command -v opkg >/dev/null 2>&1; then
        info "Entware python3 missing — installing via opkg"
        opkg update >/dev/null
        opkg install python3 || die "opkg install python3 failed"
        PYTHON=/opt/bin/python3
        [ -x "$PYTHON" ] || PYTHON=/opt/bin/python
    fi
    [ -x "$PYTHON" ] || PYTHON=$(command -v python3 2>/dev/null || echo python3)

    if ! "$PYTHON" -c 'import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)' 2>/dev/null; then
        info "python3 >= 3.10 missing — installing via opkg"
        opkg update >/dev/null
        opkg install python3 || die "opkg install python3 failed"
        PYTHON=/opt/bin/python3
        [ -x "$PYTHON" ] || PYTHON=/opt/bin/python
    fi

    info "python: $("$PYTHON" -V 2>&1)"

    if ! "$PYTHON" -c 'import flask' 2>/dev/null; then
        info "flask missing — installing via opkg"
        opkg update >/dev/null
        # some Entware targets (e.g. aarch64-k3.10) ship no python3-flask package
        if ! opkg install python3-flask 2>/dev/null; then
            warn "python3-flask unavailable via opkg — falling back to pip"
            opkg install python3-pip || die "opkg install python3-pip failed"
            /opt/bin/pip3 install --no-cache-dir flask || die "pip install flask failed"
        fi
    fi

    if ! "$PYTHON" -c 'import waitress' 2>/dev/null; then
        info "waitress missing — installing via opkg"
        opkg update >/dev/null
        if ! opkg install python3-waitress 2>/dev/null; then
            warn "python3-waitress unavailable via opkg — falling back to pip"
            opkg install python3-pip || die "opkg install python3-pip failed"
            /opt/bin/pip3 install --no-cache-dir waitress || warn "pip install waitress failed"
        fi
    fi

    if [ "$WITH_AUTH" = 1 ]; then
        if ! "$PYTHON" -c 'import bcrypt' 2>/dev/null; then
            info "python3-bcrypt missing — installing via opkg"
            opkg update >/dev/null
            opkg install python3-bcrypt || warn "python3-bcrypt unavailable via opkg (fallback: pip install bcrypt)"
        fi
    fi
fi

# --- naive binary: детект таргета и установка -------------------------------

naive_hint() {  # ручная установка — когда авто-детект не справился
    echo "  Download a prebuilt client from klzgrad/naiveproxy releases:"
    echo "    https://github.com/klzgrad/naiveproxy/releases"
    echo "  Pick the openwrt-* asset matching your router CPU (prefer -static), then:"
    echo "    tar -xJf naiveproxy-v*-openwrt-*.tar.xz"
    echo "    cp naiveproxy-v*/naive /opt/bin/naive && chmod +x /opt/bin/naive"
    echo "  Or re-run the installer with --naive-target <openwrt-target>."
    echo "  See README «Установка бинарника naive» for CPU/asset matching."
}

naive_fetch() {  # $1=url $2=dst — без die: бинарник вторичен, панель важнее
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --connect-timeout 15 --retry 2 -o "$2" "$1" && return 0
    fi
    command -v wget >/dev/null 2>&1 && wget -q -T 30 -t 2 -O "$2" "$1" && return 0
    return 1
}

# openwrt-таргет по железу (имена ассетов klzgrad/naiveproxy = таргеты OpenWrt):
# uname -m даёт базу, /proc/cpuinfo — модель ядра (CPU part / Features /
# cpu model). Для MIPS энддиан берём из ELF-заголовка (EI_DATA, байт 5):
# 1 = little, 2 = big. NAIVEPROXY_UNAME_M / NAIVEPROXY_CPUINFO / NAIVEPROXY_ELF
# переопределяют источники (тесты); в проде всегда системные значения.
detect_naive_target() {  # -> stdout: таргет; return 1 — сборки под железо нет
    um="${NAIVEPROXY_UNAME_M:-$(uname -m)}"
    ci="${NAIVEPROXY_CPUINFO:-/proc/cpuinfo}"
    part=$(sed -n 's/^CPU part[^:]*:[[:space:]]*//p' "$ci" 2>/dev/null | head -n 1 | tr 'A-F' 'a-f')
    case "$um" in
        x86_64|amd64) echo "x86_64"; return 0 ;;
        i?86)         echo "x86";    return 0 ;;
        aarch64|arm64)
            case "$part" in
                0xd03) echo "aarch64_cortex-a53" ;;
                0xd08) echo "aarch64_cortex-a72" ;;
                0xd0e) echo "aarch64_cortex-a76" ;;
                *)     echo "aarch64_generic" ;;
            esac
            return 0 ;;
        armv7*)
            feats=$(sed -n 's/^Features[^:]*:[[:space:]]*//p' "$ci" 2>/dev/null | head -n 1)
            has_neon=0; has_vfp4=0
            echo "$feats" | grep -qw neon  && has_neon=1
            echo "$feats" | grep -qw vfpv4 && has_vfp4=1
            case "$part" in
                0xc05) echo "arm_cortex-a5_vfpv4" ;;
                0xc08) echo "arm_cortex-a8_vfpv3" ;;
                0xc09) if [ "$has_neon" = 1 ]; then echo "arm_cortex-a9_neon"; else echo "arm_cortex-a9"; fi ;;
                0xc0f) echo "arm_cortex-a15_neon-vfpv4" ;;
                0xc07|*)
                    if [ "$has_neon" = 1 ] && [ "$has_vfp4" = 1 ]; then
                        echo "arm_cortex-a7_neon-vfpv4"
                    elif [ "$has_vfp4" = 1 ]; then
                        echo "arm_cortex-a7_vfpv4"
                    else
                        echo "arm_cortex-a7"
                    fi ;;
            esac
            return 0 ;;
        armv6*) echo "arm_arm1176jzf-s_vfp"; return 0 ;;
        armv5*) echo "arm_arm926ej-s";       return 0 ;;
        mips)
            elf="${NAIVEPROXY_ELF:-/bin/sh}"
            ei=$(od -An -tu1 -j5 -N1 "$elf" 2>/dev/null | tr -d '[:space:]')
            [ -n "$ei" ] || ei=$(hexdump -s 5 -n 1 -e '1/1 "%u"' "$elf" 2>/dev/null | tr -d '[:space:]')
            if [ -z "$ei" ]; then
                warn "cannot detect MIPS endianness — assuming little-endian"
                ei=1
            fi
            [ "$ei" = "2" ] && return 1  # big-endian: prebuilt-сборок нет
            model=$(sed -n 's/^cpu model[^:]*:[[:space:]]*//p' "$ci" 2>/dev/null | head -n 1)
            case "$model" in
                *24Kc*|*24KEc*|*34Kc*|*1004Kc*|*mips32r2*) echo "mipsel_24kc" ;;
                *) echo "mipsel_mips32" ;;
            esac
            return 0 ;;
    esac
    return 1
}

install_naive() {  # ставит /opt/bin/naive из релиза klzgrad/naiveproxy
    target="$NAIVE_TARGET"
    if [ -z "$target" ]; then
        target=$(detect_naive_target) || target=""
        if [ -z "$target" ]; then
            warn "cannot map this hardware to an openwrt-* target — naive NOT installed"
            naive_hint
            return 1
        fi
    fi
    if [ -n "$NAIVE_REF" ]; then
        rel="releases/tags/$NAIVE_REF"
    else
        rel="releases/latest"
    fi
    info "naive: resolving ${NAIVE_SRC_REPO} ${NAIVE_REF:-latest} for target '$target'"
    if ! naive_fetch "${NAIVE_SRC_API}/repos/${NAIVE_SRC_REPO}/${rel}" "$STAGE/naive-rel.json"; then
        warn "cannot reach ${NAIVE_SRC_API} — naive NOT installed"
        naive_hint
        return 1
    fi
    tag=$(sed -n 's/.*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' "$STAGE/naive-rel.json" | head -n 1)
    [ -n "$tag" ] || { warn "no tag_name in release JSON — naive NOT installed"; return 1; }
    # кандидаты: точный таргет, затем arch-фолбэк; в каждом сначала -static
    # (musl, без зависимостей от библиотек в /opt/lib — см. README)
    fb=""
    case "$target" in
        aarch64_*) fb="aarch64_generic" ;;
        arm_*)     fb="arm_cortex-a7" ;;
        mipsel_*)  fb="mipsel_mips32" ;;
    esac
    url=""
    build=""
    for cand in "$target" "$fb"; do
        [ -n "$cand" ] || continue
        for flavor in "$cand-static" "$cand"; do
            url=$(grep -o '"browser_download_url":[[:space:]]*"[^"]*"' "$STAGE/naive-rel.json" \
                  | sed 's/.*"\(https:[^"]*\)"$/\1/' \
                  | grep -E -- "-openwrt-${flavor}\.tar\.xz$" | head -n 1)
            if [ -n "$url" ]; then build="$flavor"; break 2; fi
        done
    done
    [ -n "$url" ] || {
        warn "release $tag has no openwrt asset for target '$target' — naive NOT installed"
        naive_hint
        return 1
    }
    info "naive: downloading $tag ($build)"
    if ! naive_fetch "$url" "$STAGE/naive.tar.xz"; then
        warn "download failed: $url — naive NOT installed"
        naive_hint
        return 1
    fi
    if ! tar -xJf "$STAGE/naive.tar.xz" -C "$STAGE" 2>/dev/null; then
        opkg install xz >/dev/null 2>&1
        tar -xJf "$STAGE/naive.tar.xz" -C "$STAGE" || {
            warn "tar -xJf failed (xz missing? try: opkg install xz)"
            return 1
        }
    fi
    nb=""
    for f in "$STAGE"/naiveproxy-*/naive; do [ -f "$f" ] && nb="$f" && break; done
    [ -n "$nb" ] || { warn "tarball contains no naiveproxy-*/naive"; return 1; }
    chmod +x "$nb"
    if ! nout=$("$nb" --version 2>&1); then
        # несовместимый таргет умирает с illegal instruction — ловим ДО
        # того, как сломали рабочий бинарник
        warn "downloaded naive fails to run (wrong target '$build'?) — NOT installed"
        naive_hint
        return 1
    fi
    # заменяем через rename в той же ФС: открытый для записи работающий
    # бинарник дал бы ETXTBSY, rename оставляет старый образ процессу
    if ! cp -f "$nb" /opt/bin/naive.new || ! chmod 0755 /opt/bin/naive.new \
       || ! mv -f /opt/bin/naive.new /opt/bin/naive; then
        rm -f /opt/bin/naive.new
        warn "cannot install /opt/bin/naive"
        return 1
    fi
    mkdir -p "$NAIVEPROXY_DIR"
    echo "$tag"   > "$NAIVEPROXY_DIR/naive-version"
    echo "$build" > "$NAIVEPROXY_DIR/naive-build"
    info "naive: installed $(echo "$nout" | head -n 1) -> /opt/bin/naive ($build)"
    [ -n "$NAIVE_PATH" ] && echo "  previous binary replaced; restart the proxy service to apply"
    return 0
}

# --- download + verify -----------------------------------------------------

BASE="https://raw.githubusercontent.com/${REPO}/${REF}"
STAGE=$(mktemp -d /tmp/naivepanel.XXXXXX) || die "mktemp failed"
trap 'rm -rf "$STAGE"' EXIT

info "downloading @ $REF"
fetch "$BASE/SHA256SUMS"              >"$STAGE/SHA256SUMS"          || die "SHA256SUMS"
fetch "$BASE/naivepanel.py"           >"$STAGE/naivepanel.py"       || die "naivepanel.py"
mkdir -p "$STAGE/templates"
fetch "$BASE/templates/index.html"    >"$STAGE/templates/index.html" || die "templates/index.html"
fetch "$BASE/S99naivepanel"           >"$STAGE/S99naivepanel"       || die "S99naivepanel"
fetch "$BASE/S99naiveproxy"           >"$STAGE/S99naiveproxy"       || die "S99naiveproxy"

if command -v sha256sum >/dev/null 2>&1; then
    ( cd "$STAGE" && sha256sum -c SHA256SUMS ) || die "checksum verification failed"
else
    warn "sha256sum not found — skipping checksum verification"
fi

# --- install files ---------------------------------------------------------

putfile() {  # $1=src $2=dst $3=mode
    cp -f "$1" "$2" || die "cp $2"
    chmod "$3" "$2"
}

mkdir -p "$PANEL_DIR/templates" "$NAIVEPROXY_DIR/conf.d"

putfile "$STAGE/naivepanel.py" "$PANEL_DIR/naivepanel.py" 0644
putfile "$STAGE/templates/index.html" "$PANEL_DIR/templates/index.html" 0644
putfile "$STAGE/S99naivepanel" "$INIT_DIR/S99naivepanel" 0755

if [ "$NO_NAIVE_INIT" = 1 ]; then
    warn "skipping S99naiveproxy (--no-naive-init)"
elif [ -f "$INIT_DIR/S99naiveproxy" ] \
     && ! grep -q '/opt/etc/naiveproxy' "$INIT_DIR/S99naiveproxy"; then
    info "S99naiveproxy already present — keeping it"
else
    # скрипт, ссылающийся на pre-0.2.0 пути, не может запустить proxy после
    # переезда конфигов — заменяем независимо от того, мигрировали мы только
    # что или это случилось при прошлом апгрейде
    [ -f "$INIT_DIR/S99naiveproxy" ] \
        && info "S99naiveproxy updated (existing copy points at pre-0.2.0 paths)"
    putfile "$STAGE/S99naiveproxy" "$INIT_DIR/S99naiveproxy" 0755
fi

# autostart symlinks (idempotent; rc.d is absent on a fresh alternative Entware)
mkdir -p /opt/etc/rc.d
ln -sf "$INIT_DIR/S99naivepanel" /opt/etc/rc.d/S99naivepanel
[ -f "$INIT_DIR/S99naiveproxy" ] && ln -sf "$INIT_DIR/S99naiveproxy" /opt/etc/rc.d/S99naiveproxy

# --- naive binary: поставить, если нет ---------------------------------------
# Существующий бинарник не трогаем (обновление — кнопкой в панели): self-update
# панели крутит этот скрипт с --from-update и не должен качать 3.5МБ и трогать
# прокси — README обещает его непрерывную работу при обновлении панели.

NAIVE_PATH=""
for cand in /opt/bin/naive /opt/bin/naiveproxy /opt/naiveproxy/bin/naiveproxy; do
    [ -x "$cand" ] && NAIVE_PATH="$cand" && break
done
[ -z "$NAIVE_PATH" ] && command -v naive >/dev/null 2>&1 && NAIVE_PATH="$(command -v naive)"

if [ "$FROM_UPDATE" = 1 ]; then
    :  # см. комментарий выше — бинарник обновляется панелью отдельно
elif [ "$SKIP_NAIVE" = 1 ]; then
    info "naive: install skipped (--skip-naive)"
elif [ -n "$NAIVE_PATH" ] && [ "$NAIVE_FORCE" != 1 ]; then
    nver=$("$NAIVE_PATH" --version 2>/dev/null | head -n 1)
    info "naive: found $NAIVE_PATH${nver:+ ($nver)}"
    if [ "$NAIVE_PATH" != "/opt/bin/naive" ]; then
        warn "S99naiveproxy expects /opt/bin/naive"
        echo "  Fix with: ln -sf '$NAIVE_PATH' /opt/bin/naive"
    fi
else
    [ "$NAIVE_FORCE" = 1 ] && [ -n "$NAIVE_PATH" ] \
        && info "naive: --naive-force — replacing $NAIVE_PATH"
    install_naive || true
fi

# --- config ----------------------------------------------------------------

# panel.conf создаём один раз, существующий НИКОГДА не перезаписываем
# целиком: пользовательские правки должны переживать обновления.
if [ ! -f "$PANEL_CONF" ]; then
    cat >"$PANEL_CONF" <<'EOF'
# NaivePanel settings - this file is read by naivepanel.py at startup.
# Format: KEY="VALUE" (quotes optional). Comments only on their own line.
# Explicit environment variables override values from this file.
# After editing run: /opt/etc/init.d/S99naivepanel restart

# Where the panel listens (LAN address, NOT 0.0.0.0 - it would also expose
# WAN/VPN/guest segments on a router):
#NAIVEPANEL_BIND="127.0.0.1:8089"

# Host-header allowlist (anti DNS-rebinding). Required when binding to a LAN
# address or behind a reverse proxy with its own hostname. Default (unset):
# bind address + loopback aliases.
#NAIVEPANEL_HOSTS="192.168.1.1:8089,router.local:8089"

# Point at the bcrypt htpasswd file (its presence enables HTTP Basic auth):
#NAIVEPANEL_PASS="/opt/etc/naive/panel/admin.pass"

# Advanced: relocate the proxy assets the panel manages
#NAIVEPROXY_DIR="/opt/etc/naive/proxy"
#NAIVEPROXY_INIT="/opt/etc/init.d/S99naiveproxy"
#NAIVEPROXY_LOG="/opt/var/log/naiveproxy.log"
#NAIVEPROXY_PID="/opt/var/run/naiveproxy.pid"

# Advanced: the naive binary itself (install.sh puts it at /opt/bin/naive;
# the panel checks/updates it — mirrors and tests override the source)
#NAIVEPROXY_BIN="/opt/bin/naive"
#NAIVEPROXY_SRC_REPO="klzgrad/naiveproxy"
#NAIVEPROXY_SRC_API="https://api.github.com"

# Log trimming: a background thread in the panel checks known logs hourly
# and trims files over NAIVEPANEL_LOG_MAX bytes down to the last
# NAIVEPANEL_LOG_KEEP bytes (same 5M threshold as init scripts).
# NAIVEPANEL_LOG_MAX=0 disables trimming entirely.
#NAIVEPANEL_LOG="/opt/var/log/naivepanel.log"
#NAIVEPANEL_LOG_MAX="5242880"
#NAIVEPANEL_LOG_KEEP="524288"
EOF
    chmod 0644 "$PANEL_CONF"
    info "created $PANEL_CONF (settings template — uncomment what you need)"
fi

# legacy: перенести NAIVEPANEL_BIND/HOSTS из rc.conf (v0.4.0 и раньше писали
# их туда, но init-скрипт этот файл никогда не читал — настройки не работали)
if [ -f "$RC_CONF" ] && grep -qE '^[[:space:]]*NAIVEPANEL_(BIND|HOSTS)=' "$RC_CONF"; then
    mig=0
    for k in NAIVEPANEL_BIND NAIVEPANEL_HOSTS; do
        v=$(sed -n "s/^[[:space:]]*$k=//p" "$RC_CONF" 2>/dev/null | head -n 1 | tr -d '"')
        if [ -n "$v" ] && ! grep -qE "^[[:space:]]*$k=" "$PANEL_CONF"; then
            conf_upsert "$k" "$v"
            mig=1
        fi
    done
    if [ "$mig" = 1 ]; then
        sed -i '/^[[:space:]]*NAIVEPANEL_BIND=/d;/^[[:space:]]*NAIVEPANEL_HOSTS=/d' "$RC_CONF"
        info "migrated NAIVEPANEL_BIND/HOSTS: rc.conf → $PANEL_CONF"
    fi
fi

# явные флаги — последний word: обновляют ключи даже в существующем файле
[ -n "$BIND" ]  && conf_upsert NAIVEPANEL_BIND "$BIND"
[ -n "$HOSTS" ] && conf_upsert NAIVEPANEL_HOSTS "$HOSTS"

if [ "$WITH_AUTH" = 1 ]; then
    # python getpass falls back to stdin when no tty is available — under a
    # pipe that would silently read script text as the password.
    if [ ! -t 0 ] && ! { [ -c /dev/tty ] && : 2>/dev/null </dev/tty; }; then
        die "--with-auth needs an interactive terminal for the password prompt"
    fi
    info "setting up panel password (stored in $PANEL_DIR/admin.pass)"
    if ! gen_admin_pass >"$PANEL_DIR/admin.pass"; then
        rm -f "$PANEL_DIR/admin.pass"
        die "password setup failed"
    fi
    chmod 0600 "$PANEL_DIR/admin.pass"
fi

# --- start + smoke ---------------------------------------------------------

# restart (не start): при идемпотентном апгрейде процесс уже живёт со старым
# кодом — start вернул бы "already running" и обновление не применилось бы
"$INIT_DIR/S99naivepanel" restart || true
# при апгрейде/миграции поднимаем и proxy, если активная конфигурация уже есть
[ -f "$NAIVEPROXY_DIR/config.json" ] && "$INIT_DIR/S99naiveproxy" start >/dev/null 2>&1 || true

BIND_ADDR="${BIND:-127.0.0.1:8089}"
# panel.conf — источник правды о bind (флаг --bind уже учтён выше)
if [ -f "$PANEL_CONF" ]; then
    v=$(sed -n 's/^[[:space:]]*NAIVEPANEL_BIND=//p' "$PANEL_CONF" 2>/dev/null | head -n 1 | tr -d '"')
    [ -n "$v" ] && BIND_ADDR="$v"
fi

sleep 1
if command -v curl >/dev/null 2>&1; then
    # flask cold start on a slow router can exceed 1s — retry before warning
    code=""
    for _ in 1 2 3 4 5; do
        code=$(curl -s -o /dev/null -w '%{http_code}' "http://$BIND_ADDR/api/status" 2>/dev/null || true)
        case "$code" in 200|401) break ;; esac
        sleep 1
    done
    case "$code" in
        200|401) info "smoke OK — panel answers on http://$BIND_ADDR (HTTP $code)" ;;
        *) warn "smoke check inconclusive (HTTP ${code:-none}); see /opt/var/log/naivepanel.log" ;;
    esac
else
    warn "curl not found — skipping smoke check"
fi

info "done. Panel: http://$BIND_ADDR"
echo ""
echo "Reminders:"
echo "  - settings: /opt/etc/naive/panel/panel.conf (bind, hosts, paths) — survives upgrades"
echo "  - auth: add a password with --with-auth if the panel is reachable from LAN"
echo "  - LAN bind: set NAIVEPANEL_BIND=192.168.1.1:8089 and NAIVEPANEL_HOSTS in panel.conf"
echo "  - reverse proxy: add its hostname via --hosts (other Host headers get 403)"
echo "  - firewall: only expose the port to trusted devices"
