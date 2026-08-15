#!/bin/sh
# NaivePanel installer for Entware routers (Keenetic and other OpenWrt-like
# firmware with Entware). Runs ON the router.
#
# Bootstrap (pin to a release tag, not `main`):
#   curl -fsSL https://raw.githubusercontent.com/keenetic-tools/naivepanel/v0.1.0/install.sh | sh -s -- --with-auth
#
# Idempotent upgrade: just run it again. Config (admin.pass, conf.d/*) is kept.
#
# Flags:
#   --with-auth          create /opt/etc/naivepanel/admin.pass (interactive)
#   --bind HOST:PORT     write NAIVEPANEL_BIND to /opt/etc/init.d/rc.conf
#   --hosts LIST         write NAIVEPANEL_HOSTS to /opt/etc/init.d/rc.conf
#   --ref TAG            git tag/ref to install (default: v0.1.0)
#   --no-naive-init      do not install S99naiveproxy init script
#   --yes                non-interactive (no confirmation prompt)
#   --uninstall          stop services and remove installed files
#   --purge              with --uninstall: also remove configs and admin.pass

set -u

REPO="keenetic-tools/naivepanel"
REF="v0.1.0"
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
  --ref TAG            git tag/ref to install (default: v0.1.0)
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
    printf "Install NaivePanel from %s @ %s? [y/N] " "$REPO" "$REF"
    read -r ans || true
    case "$ans" in y|Y|yes|YES) ;; *) echo "aborted"; exit 1 ;; esac
fi

# --- python + deps ---------------------------------------------------------

PYTHON=/opt/bin/python3
[ -x "$PYTHON" ] || PYTHON=/opt/bin/python
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
    info "python3-flask missing — installing via opkg"
    opkg update >/dev/null
    opkg install python3-flask || warn "python3-flask unavailable via opkg (fallback: pip install flask)"
fi

if [ "$WITH_AUTH" = 1 ]; then
    if ! "$PYTHON" -c 'import bcrypt' 2>/dev/null; then
        info "python3-bcrypt missing — installing via opkg"
        opkg update >/dev/null
        opkg install python3-bcrypt || warn "python3-bcrypt unavailable via opkg (fallback: pip install bcrypt)"
    fi
fi

command -v /opt/bin/naive >/dev/null 2>&1 \
    || warn "naive binary not found — install the naive-proxy package (opkg install naive-proxy)"

# --- download + verify -----------------------------------------------------

BASE="https://raw.githubusercontent.com/${REPO}/${REF}"
STAGE=$(mktemp -d /tmp/naivepanel.XXXXXX) || die "mktemp failed"
trap 'rm -rf "$STAGE"' EXIT

info "downloading @ $REF"
fetch "$BASE/SHA256SUMS"              >"$STAGE/SHA256SUMS"          || die "SHA256SUMS"
fetch "$BASE/naivepanel.py"           >"$STAGE/naivepanel.py"       || die "naivepanel.py"
fetch "$BASE/templates/index.html"    >"$STAGE/index.html"          || die "templates/index.html"
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
putfile "$STAGE/index.html"    "$PANEL_DIR/templates/index.html" 0644
putfile "$STAGE/S99naivepanel" "$INIT_DIR/S99naivepanel" 0755

if [ "$NO_NAIVE_INIT" = 1 ]; then
    warn "skipping S99naiveproxy (--no-naive-init)"
elif [ -f "$INIT_DIR/S99naiveproxy" ]; then
    info "S99naiveproxy already present — keeping it"
else
    putfile "$STAGE/S99naiveproxy" "$INIT_DIR/S99naiveproxy" 0755
fi

# autostart symlinks (idempotent)
ln -sf "$INIT_DIR/S99naivepanel" /opt/etc/rc.d/S99naivepanel
[ -f "$INIT_DIR/S99naiveproxy" ] && ln -sf "$INIT_DIR/S99naiveproxy" /opt/etc/rc.d/S99naiveproxy

# --- config ----------------------------------------------------------------

[ -n "$BIND" ]  && rc_conf_set NAIVEPANEL_BIND "$BIND"
[ -n "$HOSTS" ] && rc_conf_set NAIVEPANEL_HOSTS "$HOSTS"

if [ "$WITH_AUTH" = 1 ]; then
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
    code=$(curl -s -o /dev/null -w '%{http_code}' "http://$BIND_ADDR/api/status" 2>/dev/null || true)
    case "$code" in
        200|401) info "smoke OK — panel answers on http://$BIND_ADDR (HTTP $code)" ;;
        *) warn "smoke check inconclusive (HTTP ${code:-none}); see $PANEL_ETC/../var/log/naivepanel.log" ;;
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
