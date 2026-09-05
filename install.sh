#!/bin/sh
# NaivePanel installer for Entware routers (Keenetic and other OpenWrt-like
# firmware with Entware). Runs ON the router.
#
# Bootstrap (pin to a release tag, not `main`):
#   curl -fsSL https://raw.githubusercontent.com/keenetic-tools/naivepanel/v0.1.1/install.sh | sh -s -- --with-auth
#
# Safe to pipe into `sh`: the confirmation and password prompts read the
# terminal (/dev/tty), never the piped stdin. Add --yes to skip confirmation.
#
# Idempotent upgrade: just run it again. Config (admin.pass, conf.d/*) is kept.
#
# Flags:
#   --with-auth          create /opt/etc/naivepanel/admin.pass (interactive)
#   --bind HOST:PORT     write NAIVEPANEL_BIND to /opt/etc/init.d/rc.conf
#   --hosts LIST         write NAIVEPANEL_HOSTS to /opt/etc/init.d/rc.conf
#   --ref TAG            git tag/ref to install (default: v0.1.1)
#   --no-naive-init      do not install S99naiveproxy init script
#   --yes                non-interactive (no confirmation prompt)
#   --uninstall          stop services and remove installed files
#   --purge              with --uninstall: also remove configs and admin.pass

set -u

REPO="keenetic-tools/naivepanel"
REF="v0.1.1"
BIND=""
HOSTS=""
WITH_AUTH=0
NO_NAIVE_INIT=0
YES=0
UNINSTALL=0
PURGE=0

PANEL_DIR=/opt/naivepanel
PANEL_ETC=/opt/etc/naivepanel
INIT_DIR=/opt/etc/init.d
NAIVEPROXY_DIR=/opt/etc/naiveproxy
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

  --with-auth          create /opt/etc/naivepanel/admin.pass (interactive)
  --bind HOST:PORT     write NAIVEPANEL_BIND to /opt/etc/init.d/rc.conf
  --hosts LIST         write NAIVEPANEL_HOSTS to /opt/etc/init.d/rc.conf
  --ref TAG            git tag/ref to install (default: v0.1.1)
  --no-naive-init      do not install S99naiveproxy init script
  --yes                non-interactive (no confirmation prompt)
  --uninstall          stop services and remove installed files
  --purge              with --uninstall: also remove configs and admin.pass
EOF
    exit 0
}

rc_conf_set() {  # $1=VAR $2=value
    [ -f "$RC_CONF" ] || : >"$RC_CONF"
    sed -i "/^[[:space:]]*$1=/d" "$RC_CONF"
    echo "$1=\"$2\"" >>"$RC_CONF"
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

# --- uninstall -------------------------------------------------------------

if [ "$UNINSTALL" = 1 ]; then
    for init in S99naivepanel S99naiveproxy; do
        [ -x "$INIT_DIR/$init" ] && "$INIT_DIR/$init" stop >/dev/null 2>&1 || true
        rm -f "/opt/etc/rc.d/$init"
        [ "$PURGE" = 1 ] && rm -f "$INIT_DIR/$init"
    done
    rm -f "$PANEL_DIR/naivepanel.py"
    rm -rf "$PANEL_DIR/templates"
    rmdir "$PANEL_DIR" 2>/dev/null || true
    if [ "$PURGE" = 1 ]; then
        rm -f "$PANEL_ETC/admin.pass"
        rm -rf "$NAIVEPROXY_DIR/conf.d"
        rmdir "$PANEL_ETC" 2>/dev/null || true
        sed -i '/^[[:space:]]*NAIVEPANEL_BIND=/d;/^[[:space:]]*NAIVEPANEL_HOSTS=/d' "$RC_CONF" 2>/dev/null || true
        info "purged configs (admin.pass, conf.d, rc.conf vars)"
    fi
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

mkdir -p "$PANEL_DIR/templates" "$PANEL_ETC" "$NAIVEPROXY_DIR/conf.d"

putfile "$STAGE/naivepanel.py" "$PANEL_DIR/naivepanel.py" 0644
putfile "$STAGE/templates/index.html" "$PANEL_DIR/templates/index.html" 0644
putfile "$STAGE/S99naivepanel" "$INIT_DIR/S99naivepanel" 0755

if [ "$NO_NAIVE_INIT" = 1 ]; then
    warn "skipping S99naiveproxy (--no-naive-init)"
elif [ -f "$INIT_DIR/S99naiveproxy" ]; then
    info "S99naiveproxy already present — keeping it"
else
    putfile "$STAGE/S99naiveproxy" "$INIT_DIR/S99naiveproxy" 0755
fi

# autostart symlinks (idempotent; rc.d is absent on a fresh alternative Entware)
mkdir -p /opt/etc/rc.d
ln -sf "$INIT_DIR/S99naivepanel" /opt/etc/rc.d/S99naivepanel
[ -f "$INIT_DIR/S99naiveproxy" ] && ln -sf "$INIT_DIR/S99naiveproxy" /opt/etc/rc.d/S99naiveproxy

# --- config ----------------------------------------------------------------

[ -n "$BIND" ]  && rc_conf_set NAIVEPANEL_BIND "$BIND"
[ -n "$HOSTS" ] && rc_conf_set NAIVEPANEL_HOSTS "$HOSTS"

if [ "$WITH_AUTH" = 1 ]; then
    # python getpass falls back to stdin when no tty is available — under a
    # pipe that would silently read script text as the password.
    if [ ! -t 0 ] && ! { [ -c /dev/tty ] && : 2>/dev/null </dev/tty; }; then
        die "--with-auth needs an interactive terminal for the password prompt"
    fi
    info "setting up panel password (stored in $PANEL_ETC/admin.pass)"
    "$PYTHON" -c 'import bcrypt,getpass,sys; sys.stdout.write("admin:"+bcrypt.hashpw(getpass.getpass("password: ").encode(), bcrypt.gensalt()).decode()+"\n")' \
        >"$PANEL_ETC/admin.pass" || die "bcrypt hash generation failed"
    chmod 0600 "$PANEL_ETC/admin.pass"
fi

# --- start + smoke ---------------------------------------------------------

"$INIT_DIR/S99naivepanel" start || true

BIND_ADDR="${BIND:-127.0.0.1:8089}"
# init script sets default 127.0.0.1:8089; if rc.conf overrides it, read it back
if [ -f "$RC_CONF" ]; then
    . "$RC_CONF" 2>/dev/null
    [ -n "${NAIVEPANEL_BIND:-}" ] && BIND_ADDR="$NAIVEPANEL_BIND"
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
echo "  - auth: add a password with --with-auth if the panel is reachable from LAN"
echo "  - LAN bind: use --bind 192.168.1.1:8089 --hosts '192.168.1.1:8089,router.local:8089'"
echo "  - firewall: only expose the port to trusted devices"
