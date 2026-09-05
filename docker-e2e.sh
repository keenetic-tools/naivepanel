#!/bin/sh
# docker-e2e.sh — прогон install.sh в Docker с НАСТОЯЩИМ Entware (opkg, python3,
# flask/bcrypt из тех же фидов, что на Keenetic). Запускать с хоста с Docker.
#
#   ./docker-e2e.sh                  # установка без пароля (--yes)
#   ./docker-e2e.sh --with-auth      # интерактивно: ответить y и ввести пароль
#
# Скачивание install.sh с raw.githubusercontent.com имитируется локальным
# HTTPS-сервером (test-CA + /etc/hosts внутри контейнера), поэтому тег можно
# не пушить — проверяется содержимое рабочей копии репозитория.
#
# Если Docker Hub недоступен (pull зависает), укажите локальный образ-базу
# с Debian внутри, например:
#   BASE_IMAGE=postgres:16 ./docker-e2e.sh

set -eu

REPO_DIR=$(cd "$(dirname "$0")" && pwd)
REF=v0.4.0
BASE_IMAGE="${BASE_IMAGE:-debian:bookworm-slim}"
AUTH_FLAG=""
MODE_FLAGS="--yes"

for a in "$@"; do
    case "$a" in
        --with-auth) AUTH_FLAG="--with-auth"; MODE_FLAGS="" ;;
        *) echo "unknown flag: $a" >&2; exit 2 ;;
    esac
done

if [ -n "$AUTH_FLAG" ] && { [ ! -t 0 ] || [ ! -t 1 ]; }; then
    echo "ERROR: --with-auth needs an interactive terminal (confirmation and password prompts)" >&2
    exit 1
fi
# -it only when the caller itself is on a terminal; automated runs are headless
RUN_FLAGS="--rm"
[ -t 0 ] && [ -t 1 ] && RUN_FLAGS="$RUN_FLAGS -it"

WORK=$(mktemp -d /tmp/naivepanel-e2e.XXXXXX)
trap 'rm -rf "$WORK"' EXIT

# --- docroot: содержимое «raw.githubusercontent.com» из рабочей копии ------

WWW="$WORK/www/keenetic-tools/naivepanel/$REF"
mkdir -p "$WWW/templates"
cp "$REPO_DIR/install.sh" "$REPO_DIR/SHA256SUMS" "$REPO_DIR/naivepanel.py" \
   "$REPO_DIR/S99naivepanel" "$REPO_DIR/S99naiveproxy" "$WWW/"
cp "$REPO_DIR/templates/index.html" "$WWW/templates/"

# --- сертификаты -----------------------------------------------------------

CERTS="$WORK/certs"
mkdir -p "$CERTS"
openssl req -x509 -newkey rsa:2048 -keyout "$CERTS/ca-key.pem" -out "$CERTS/ca.crt" \
    -days 3 -nodes -subj "/CN=np-e2e-test-ca" \
    -addext "basicConstraints=critical,CA:TRUE" 2>/dev/null
openssl req -newkey rsa:2048 -keyout "$CERTS/srv-key.pem" -out "$CERTS/srv.csr" \
    -nodes -subj "/CN=raw.githubusercontent.com" 2>/dev/null
printf "subjectAltName=DNS:raw.githubusercontent.com\n" > "$CERTS/srv-ext.cnf"
openssl x509 -req -in "$CERTS/srv.csr" -CA "$CERTS/ca.crt" -CAkey "$CERTS/ca-key.pem" \
    -CAcreateserial -out "$CERTS/srv.crt" -days 3 -extfile "$CERTS/srv-ext.cnf" 2>/dev/null

cat > "$WORK/server.py" <<'PY'
import http.server, ssl, os
os.chdir("/www")
httpd = http.server.HTTPServer(("127.0.0.1", 443), http.server.SimpleHTTPRequestHandler)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain("/certs/srv.crt", "/certs/srv-key.pem")
httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
httpd.serve_forever()
PY

cat > "$WORK/Dockerfile" <<'DOCKER'
ARG BASE_IMAGE=debian:bookworm-slim
FROM ${BASE_IMAGE}
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl wget xz-utils python3 openssl \
 && rm -rf /var/lib/apt/lists/*
COPY certs/ca.crt /usr/local/share/ca-certificates/np-e2e-ca.crt
RUN update-ca-certificates
DOCKER

echo "==> building image (base: $BASE_IMAGE)"
docker build --build-arg BASE_IMAGE="$BASE_IMAGE" -t naivepanel-e2e "$WORK" >/dev/null

cat > "$WORK/entrypoint.sh" <<EOF
set -e
python3 /srv/server.py &
sleep 1
echo "==> fake raw.githubusercontent.com: OK"
mkdir -p /opt
curl -fsSL https://bin.entware.net/aarch64-k3.10/installer/alternative.sh | sh
/opt/bin/opkg update
export PATH=/opt/bin:/opt/sbin:\$PATH
echo "==> install: curl -fsSL .../install.sh | sh -s -- $AUTH_FLAG \$EXTRA"
curl -fsSL https://raw.githubusercontent.com/keenetic-tools/naivepanel/$REF/install.sh | sh -s -- $AUTH_FLAG \$EXTRA
echo "==> post-install state"
/opt/etc/init.d/S99naivepanel status || true
echo "smoke http_code=\$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8089/api/status)"
ls -l /opt/etc/rc.d/

echo "==> API checks (CSRF + write-only password)"
H='-H X-Requested-With:naivepanel'
code=\$(curl -s -o /tmp/create.json -w '%{http_code}' \$H -H 'Content-Type: application/json' \
  -d '{"name":"home","listen":"127.0.0.1:1080","upstream":"proxy.example.com","username":"user","password":"p@ss:word"}' \
  http://127.0.0.1:8089/api/configs)
echo "create=\$code (expect 201)"
if curl -s http://127.0.0.1:8089/api/configs/home | grep -q '"password"'; then
  echo "FAIL: password leaked via GET"; exit 1
fi
echo "get raw: \$(curl -s http://127.0.0.1:8089/api/configs/home)"
echo "csrf_no_header=\$(curl -s -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:8089/api/service/stop) (expect 403)"
echo "csrf_with_header=\$(curl -s \$H -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:8089/api/service/stop) (expect 200)"
echo "==> E2E DONE"
EOF

docker run $RUN_FLAGS \
    --add-host raw.githubusercontent.com:127.0.0.1 \
    -e EXTRA="$MODE_FLAGS" \
    -v "$WORK/www:/www:ro" -v "$CERTS:/certs:ro" \
    -v "$WORK/server.py:/srv/server.py:ro" \
    -v "$WORK/entrypoint.sh:/test/entrypoint.sh:ro" \
    --entrypoint /bin/sh \
    naivepanel-e2e /test/entrypoint.sh
