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
REF=v0.21.0
BASE_IMAGE="${BASE_IMAGE:-debian:bookworm-slim}"
AUTH_FLAG=""
MODE_FLAGS="--yes"

# Контейнер наследует архитектуру хоста. Entware-фид выбираем под неё,
# иначе E2E не запустится на x86_64 CI-runner (Apple/ARM — aarch64).
case "$(uname -m)" in
    x86_64|amd64)  ENTWARE_ARCH=x86-64 ;;
    arm64|aarch64) ENTWARE_ARCH=aarch64-k3.10 ;;
    *) echo "unsupported host arch: $(uname -m)" >&2; exit 2 ;;
esac

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
mkdir -p "$WWW/templates" "$WWW/panel"
cp "$REPO_DIR/install.sh" "$REPO_DIR/SHA256SUMS" "$REPO_DIR/naivepanel.py" \
   "$REPO_DIR/S99naivepanel" "$REPO_DIR/S99naiveproxy" "$WWW/"
cp "$REPO_DIR/templates/index.html" "$WWW/templates/"
cp "$REPO_DIR"/panel/*.py "$WWW/panel/"

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

if [ -n "$AUTH_FLAG" ]; then PW_EXPECT=401; else PW_EXPECT=409; fi

cat > "$WORK/entrypoint.sh" <<EOF
set -e
python3 /srv/server.py &
sleep 1
echo "==> fake raw.githubusercontent.com: OK"
mkdir -p /opt
curl -fsSL https://bin.entware.net/$ENTWARE_ARCH/installer/alternative.sh | sh
/opt/bin/opkg update
export PATH=/opt/bin:/opt/sbin:\$PATH
echo "==> install: curl -fsSL .../install.sh | sh -s -- $AUTH_FLAG \$EXTRA"
curl -fsSL https://raw.githubusercontent.com/keenetic-tools/naivepanel/$REF/install.sh | sh -s -- $AUTH_FLAG \$EXTRA
echo "==> post-install state"
/opt/etc/init.d/S99naivepanel status || true
echo "smoke http_code=\$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8089/api/status)"
ls -l /opt/etc/rc.d/
test -f /opt/etc/naive/panel/panel.conf && echo "panel.conf: present"
grep -c '^#' /opt/etc/naive/panel/panel.conf >/dev/null && echo "panel.conf: template comments intact"

echo "==> API checks (CSRF + write-only password)"
H='-H X-Requested-With:naivepanel'
code=\$(curl -s -o /tmp/create.json -w '%{http_code}' \$H -H 'Content-Type: application/json' \
  -d '{"name":"home","listen":"127.0.0.1:1080","upstream":"proxy.example.com","username":"user","password":"p@ss:word"}' \
  http://127.0.0.1:8089/api/configs)
echo "create=\$code (expect 201)"
if curl -s http://127.0.0.1:8089/api/configs/home | grep -q '"password"'; then
  echo "FAIL: password key leaked via GET"; exit 1
fi
# сам секрет не встречается нигде в теле: ни raw, ни percent-encoded
if curl -s http://127.0.0.1:8089/api/configs/home | grep -q 'p@ss:word\|p%40ss%3Aword'; then
  echo "FAIL: upstream password value leaked via GET"; exit 1
fi
# SEC-02: quic full-URI тоже write-only + одиночный GET no-store
code=\$(curl -s -o /dev/null -w '%{http_code}' \$H -H 'Content-Type: application/json' \
  -d '{"name":"qc","listen":"127.0.0.1:1081","upstream":"quic://u:quics3cret@proxy.example.com:443","username":"","password":""}' \
  http://127.0.0.1:8089/api/configs)
echo "create quic=\$code (expect 201)"
[ "\$code" = "201" ] || { echo "FAIL: quic preset not created"; exit 1; }
if curl -s http://127.0.0.1:8089/api/configs/qc | grep -q 'quics3cret'; then
  echo "FAIL: quic password leaked via GET"; exit 1
fi
curl -s -D - -o /dev/null http://127.0.0.1:8089/api/configs/home | tr -d '\r' \
  | grep -qi '^Cache-Control: no-store' \
  || { echo "FAIL: single GET missing no-store"; exit 1; }
echo "get raw: \$(curl -s http://127.0.0.1:8089/api/configs/home)"
echo "csrf_no_header=\$(curl -s -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:8089/api/service/stop) (expect 403)"
echo "csrf_with_header=\$(curl -s \$H -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:8089/api/service/stop) (expect 200)"
echo "password_no_auth=\$(curl -s -o /dev/null -w '%{http_code}' \$H \\
  -H 'Content-Type: application/json' -X POST \\
  -d '{"current":"x","new":"12345678"}' \\
  http://127.0.0.1:8089/api/password) (expect $PW_EXPECT)"

echo "==> API hardening checks (list no-store + masking, scheme allowlist, server)"
# список не должен светить пароль upstream и обязан быть no-store
list_hdr=\$(curl -s -D - -o /tmp/list.json http://127.0.0.1:8089/api/configs)
echo "\$list_hdr" | grep -qi '^Cache-Control: no-store' \
  && echo "list no-store: OK" \
  || { echo "FAIL: list missing no-store"; echo "\$list_hdr"; exit 1; }
if grep -q 'p%40ss%3Aword\|p@ss:word' /tmp/list.json; then
  echo "FAIL: list leaks upstream password"; cat /tmp/list.json; exit 1
fi
echo "list: \$(cat /tmp/list.json)"
# схема proxy вне allowlist (https/http/quic) отклоняется на create
bad=\$(curl -s -o /tmp/bad.json -w '%{http_code}' \$H -H 'Content-Type: application/json' \
  -d '{"name":"bad","listen":"127.0.0.1:1080","upstream":"file://x@y"}' \
  http://127.0.0.1:8089/api/configs)
echo "scheme reject=\$bad (expect 400)"
[ "\$bad" = "400" ] || { echo "FAIL: file:// scheme accepted"; cat /tmp/bad.json; exit 1; }
# сервер: waitress, если установился, иначе Werkzeug — оба допустимы
echo "server: \$(curl -sI http://127.0.0.1:8089/api/status | tr -d '\r' | sed -n 's/^[Ss]erver: //p')"

echo "==> SEC-04/05: panel.conf mode + stale-pid safety"
pc_mode=\$(stat -c %a /opt/etc/naive/panel/panel.conf 2>/dev/null || echo '?')
echo "panel.conf mode: \$pc_mode (expect 600)"
[ "\$pc_mode" = "600" ] || { echo "FAIL: panel.conf is \$pc_mode, not 0600"; exit 1; }
# протухший pidfile: чужой процесс под pid naive — stop не должен его убить
sleep 300 &
foreign=\$!
echo "\$foreign" > /opt/var/run/naiveproxy.pid
/opt/etc/init.d/S99naiveproxy stop >/tmp/stale-stop.log 2>&1
if kill -0 "\$foreign" 2>/dev/null; then
  echo "foreign process survived stale-pid stop: OK"
else
  echo "FAIL: S99naiveproxy stop killed a foreign pid"; exit 1
fi
kill "\$foreign" 2>/dev/null || true
grep -qi "stale" /tmp/stale-stop.log \
  && echo "stale-pid message: OK" \
  || { echo "FAIL: no stale-pid message in stop output"; cat /tmp/stale-stop.log; exit 1; }

echo "==> naive binary: auto-install via install.sh (real GitHub API + asset)"
# контейнер той же архитектуры, что хост (aarch64 или x86_64); musl-static
# сборка запускается в Debian — проверяем реальным --version
test -x /opt/bin/naive || { echo "FAIL: /opt/bin/naive not installed"; exit 1; }
echo "naive: \$(/opt/bin/naive --version 2>&1 | head -n 1)"
echo "marker version: \$(cat /opt/etc/naive/proxy/naive-version)"
echo "marker build:   \$(cat /opt/etc/naive/proxy/naive-build)"

echo "==> naive: check + update via panel API"
# имитируем устаревший маркер — панель должна увидеть доступное обновление
echo "v113.0.5672.3-1" > /opt/etc/naive/proxy/naive-version
chk=\$(curl -s 'http://127.0.0.1:8089/api/naive/check?force=1')
echo "check: \$chk"
echo "\$chk" | grep -q '"available": *true' || { echo "FAIL: stale naive not detected"; exit 1; }
code=\$(curl -s -o /tmp/nupd.json -w '%{http_code}' \$H -X POST http://127.0.0.1:8089/api/naive/update)
echo "update=\$code (expect 202)"
[ "\$code" = "202" ] || { cat /tmp/nupd.json; exit 1; }
phase=""
for i in \$(seq 1 120); do
  phase=\$(curl -s http://127.0.0.1:8089/api/naive/status \
    | grep -o '"phase": *"[a-z]*"' | head -n1 | sed 's/.*"\([a-z]*\)"\$/\1/')
  { [ "\$phase" = "done" ] || [ "\$phase" = "failed" ]; } && break
  sleep 2
done
[ "\$phase" = "done" ] || {
  echo "FAIL: naive update did not finish (phase=\$phase)"; curl -s http://127.0.0.1:8089/api/naive/status; exit 1
}
echo "naive after update: \$(/opt/bin/naive --version 2>&1 | head -n 1)"
echo "marker version: \$(cat /opt/etc/naive/proxy/naive-version)"
# после обновления тот же чек обязан говорить «актуально»
curl -s 'http://127.0.0.1:8089/api/naive/check?force=1' \
  | grep -q '"available": *false' || { echo "FAIL: still available after update"; exit 1; }

echo "==> upgrade: rc.conf migration + --bind upsert + stale S99naiveproxy"
mkdir -p /opt/etc/init.d
# имитируем протухший S99naiveproxy (как после апгрейда v0.4.0 с pre-0.2.0):
printf '#!/bin/sh\nDAEMON_OPTS=/opt/etc/naiveproxy/config.json\n[ -f /opt/etc/naiveproxy/config.json ] || DAEMON_OPTS=\n' > /opt/etc/init.d/S99naiveproxy
printf 'OTHER_VAR="keep"\nNAIVEPANEL_BIND="10.9.9.9:1234"\n' > /opt/etc/init.d/rc.conf
# SEC-01 preflight: явный LAN-bind без пароля установщик отвергает; для
# позитивного апгрейд-сценария (flag wins) создаём admin.pass — префлайт
# проверяет его существование
printf 'admin:dummy-for-preflight\n' > /opt/etc/naive/panel/admin.pass
curl -fsSL https://raw.githubusercontent.com/keenetic-tools/naivepanel/$REF/install.sh | sh -s -- --yes --bind 192.168.1.1:8089
if grep -q '^NAIVEPANEL_BIND="192.168.1.1:8089"' /opt/etc/naive/panel/panel.conf \
   && ! grep -q 'NAIVEPANEL' /opt/etc/init.d/rc.conf \
   && grep -q '^OTHER_VAR=' /opt/etc/init.d/rc.conf; then
  echo "panel.conf migration: OK (flag wins, rc.conf cleaned, other keys kept)"
else
  echo "FAIL: panel.conf migration"; cat /opt/etc/naive/panel/panel.conf /opt/etc/init.d/rc.conf; exit 1
fi
# а без пароля тот же флаг обязан валить установку (fail-closed)
rm -f /opt/etc/naive/panel/admin.pass
if curl -fsSL https://raw.githubusercontent.com/keenetic-tools/naivepanel/$REF/install.sh \
     | sh -s -- --yes --bind 192.168.1.1:8089 >/tmp/bind-preflight.log 2>&1; then
  echo "FAIL: LAN bind without password accepted"; exit 1
fi
grep -q "exposes the panel" /tmp/bind-preflight.log \
  && echo "SEC-01 preflight: OK (dies on LAN bind without password)" \
  || { echo "FAIL: unexpected install failure"; cat /tmp/bind-preflight.log; exit 1; }
if grep -q '/opt/etc/naive/proxy/config.json' /opt/etc/init.d/S99naiveproxy \
   && ! grep -q '/opt/etc/naiveproxy' /opt/etc/init.d/S99naiveproxy; then
  echo "stale S99naiveproxy replaced: OK"
else
  echo "FAIL: stale S99naiveproxy not replaced"; head -5 /opt/etc/init.d/S99naiveproxy; exit 1
fi
# повторный прогон установщика не трогает уже установленный бинарник
test -x /opt/bin/naive || { echo "FAIL: naive lost after upgrade rerun"; exit 1; }
echo "naive survived upgrade rerun: \$(/opt/bin/naive --version 2>&1 | head -n 1)"
echo "==> E2E DONE"
EOF

# shellcheck disable=SC2086  # RUN_FLAGS намеренно разбивается на аргументы
docker run $RUN_FLAGS \
    --add-host raw.githubusercontent.com:127.0.0.1 \
    -e EXTRA="$MODE_FLAGS" \
    -v "$WORK/www:/www:ro" -v "$CERTS:/certs:ro" \
    -v "$WORK/server.py:/srv/server.py:ro" \
    -v "$WORK/entrypoint.sh:/test/entrypoint.sh:ro" \
    --entrypoint /bin/sh \
    naivepanel-e2e /test/entrypoint.sh
