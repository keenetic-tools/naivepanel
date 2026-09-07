#!/bin/sh
# NaivePanel installer for Entware routers (Keenetic and other OpenWrt-like
# firmware with Entware). Runs ON the router.
#
# Bootstrap (pin to a release tag, not `main`):
#   curl -fsSL https://raw.githubusercontent.com/keenetic-tools/naivepanel/v0.5.0/install.sh | sh -s -- --with-auth
#
# Safe to pipe into `sh`: the confirmation and password prompts read the
# terminal (/dev/tty), never the piped stdin. Add --yes to skip confirmation.
#
# Idempotent upgrade: just run it again. Config (admin.pass, conf.d/*) is kept;
# a pre-0.2.0 layout is migrated automatically.
#
# Flags:
#   --with-auth          create /opt/etc/naive/panel/admin.pass (interactive)
#   --bind HOST:PORT     write NAIVEPANEL_BIND to /opt/etc/naive/panel/panel.conf
#   --hosts LIST         write NAIVEPANEL_HOSTS to /opt/etc/naive/panel/panel.conf
#   --ref TAG            git tag/ref to install (default: v0.5.0)
#   --no-naive-init      do not install S99naiveproxy init script
#   --yes                non-interactive (no confirmation prompt)
#   --uninstall          stop services and remove installed files
#   --purge              with --uninstall: also remove configs and admin.pass

set -u

REPO="keenetic-tools/naivepanel"
REF="v0.5.0"
BIND=""
HOSTS=""
WITH_AUTH=0
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
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$1" || die "download failed: $1"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO- "$1" || die "download failed: $1"
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
  --ref TAG            git tag/ref to install (default: v0.5.0)
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
        --no-naive-init)  NO_NAIVE_INIT=1 ;;
        --yes)            YES=1 ;;
        --uninstall)      UNINSTALL=1 ;;
        --purge)          PURGE=1 ;;
        --bind)           BIND="${2:-}"; shift ;;
        --hosts)          HOSTS="${2:-}"; shift ;;
        --ref)            REF="${2:-}"; shift ;;
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

if [ "$WITH_AUTH" = 1 ]; then
    if ! "$PYTHON" -c 'import bcrypt' 2>/dev/null; then
        info "python3-bcrypt missing — installing via opkg"
        opkg update >/dev/null
        opkg install python3-bcrypt || warn "python3-bcrypt unavailable via opkg (fallback: pip install bcrypt)"
    fi
fi

# --- naive binary check -----------------------------------------------------

NAIVE_PATH=""
for cand in /opt/bin/naive /opt/bin/naiveproxy /opt/naiveproxy/bin/naiveproxy; do
    [ -x "$cand" ] && NAIVE_PATH="$cand" && break
done
[ -z "$NAIVE_PATH" ] && command -v naive >/dev/null 2>&1 && NAIVE_PATH="$(command -v naive)"

if [ -z "$NAIVE_PATH" ]; then
    warn "naive binary not found (the panel does NOT install it)"
    echo "  Download a prebuilt client from klzgrad/naiveproxy releases:"
    echo "    https://github.com/klzgrad/naiveproxy/releases"
    echo "  Pick the openwrt-* asset matching your router CPU (prefer -static), then:"
    echo "    tar -xJf naiveproxy-v*-openwrt-*.tar.xz"
    echo "    cp naiveproxy-v*/naive /opt/bin/naive && chmod +x /opt/bin/naive"
    echo "  See README «Установка бинарника naive» for CPU/asset matching."
elif [ "$NAIVE_PATH" != "/opt/bin/naive" ]; then
    warn "naive found at $NAIVE_PATH, but S99naiveproxy expects /opt/bin/naive"
    echo "  Fix with: ln -sf '$NAIVE_PATH' /opt/bin/naive"
fi

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
