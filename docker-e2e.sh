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
REF=v0.27.4
NEXT_REF=v0.27.5
BASE_IMAGE="${BASE_IMAGE:-debian:bookworm-slim}"
AUTH_FLAG=""
MODE_FLAGS="--yes"

# Контейнер наследует архитектуру хоста. Entware-фид выбираем под неё,
# иначе E2E не запустится на x86_64 CI-runner (Apple/ARM — aarch64).
case "$(uname -m)" in
    x86_64|amd64)  ENTWARE_ARCH=x64-k3.2 ;;
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
cp "$REPO_DIR/install.sh" "$REPO_DIR/SHA256SUMS" "$REPO_DIR/SHA256SUMS.minisig" \
   "$REPO_DIR/naivepanel.py" \
   "$REPO_DIR/S99naivepanel" "$REPO_DIR/S99naiveproxy" "$WWW/"
cp "$REPO_DIR/templates/index.html" "$WWW/templates/"
cp "$REPO_DIR"/panel/*.py "$WWW/panel/"
mkdir -p "$WWW/panel/static"
cp "$REPO_DIR"/panel/static/app.js "$REPO_DIR"/panel/static/styles.css "$WWW/panel/static/"

# Оба served-релиза подписываются одноразовым ключом: рабочая копия уже может
# отличаться от последней опубликованной подписи. Файлы репозитория не меняем.
NEXT_WWW="$WORK/www/keenetic-tools/naivepanel/$NEXT_REF"
cp -R "$WWW" "$NEXT_WWW"
KEYGEN_OUT=$(python3 "$REPO_DIR/tools/release_sign.py" keygen --secret "$WORK/release.sec")
TEST_KEYID=$(printf '%s\n' "$KEYGEN_OUT" | sed -n 's/^keyid: //p')
TEST_PUB=$(printf '%s\n' "$KEYGEN_OUT" | sed -n 's/^pub:   //p')
python3 - "$WWW" "$NEXT_WWW" "$TEST_KEYID" "$TEST_PUB" <<'PY'
import hashlib
import re
import sys
from pathlib import Path

current, next_release = map(Path, sys.argv[1:3])
keyid, pub = sys.argv[3:]
for root in (current, next_release):
    installer = root / "install.sh"
    text = installer.read_text(encoding="utf-8")
    text = re.sub(r'^NP_SIGN_KEYID=.*$', f'NP_SIGN_KEYID="{keyid}"', text,
                  flags=re.M)
    text = re.sub(r'^NP_SIGN_PUBKEY=.*$', f'NP_SIGN_PUBKEY="{pub}"', text,
                  flags=re.M)
    if root == next_release:
        config = root / "panel/config.py"
        config.write_text(re.sub(r'^APP_VERSION = .*$', 'APP_VERSION = "0.27.5"',
                                 config.read_text(encoding="utf-8"), flags=re.M),
                          encoding="utf-8")
        text = text.replace("set -u\n", """set -u

if [ ! -f /tmp/naivepanel-e2e-update.failed ]; then
    : > /tmp/naivepanel-e2e-update.failed
    echo "E2E: intentional self-update failure (rc=3)" >&2
    exit 3
fi
""", 1)
    installer.write_text(text, encoding="utf-8")
    sums = root / "SHA256SUMS"
    lines = []
    for line in sums.read_text(encoding="utf-8").splitlines():
        name = line.split(maxsplit=1)[1]
        digest = hashlib.sha256((root / name).read_bytes()).hexdigest()
        lines.append(f"{digest}  {name}")
    sums.write_text("\n".join(lines) + "\n", encoding="utf-8")
PY
for release in "$WWW" "$NEXT_WWW"; do
    python3 "$REPO_DIR/tools/release_sign.py" sign --secret "$WORK/release.sec" \
        --data "$release/SHA256SUMS" >/dev/null
done

API="$WORK/www/api/repos/keenetic-tools/naivepanel"
mkdir -p "$API/releases"
cat > "$API/releases/latest" <<EOF
{"tag_name":"$NEXT_REF","body":"E2E signed update","html_url":"https://example.invalid/$NEXT_REF"}
EOF
cat > "$API/tags" <<EOF
[{"name":"$NEXT_REF"}]
EOF

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
 && apt-get install -y --no-install-recommends ca-certificates curl wget xz-utils python3 openssl musl \
# musl: openwrt-x86_64 сборка naive динамическая (ld-musl-x86_64.so.1);
#       aarch64-ассеты -static, а x86_64 static не выпускается
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
# libgcc: openwrt-x86_64 сборка naive динамическая (musl + libgcc_s.so.1);
# на реальном роутере её даёт Entware-рантайм, в чистом Debian её нет.
# musl ищет библиотеки по /etc/ld-musl-<arch>.path (дефолт /lib:/usr/lib),
# а opkg кладёт всё в /opt/lib — учим интерпретатор этому пути.
/opt/bin/opkg install libgcc
echo /opt/lib >> /etc/ld-musl-$(uname -m).path
export PATH=/opt/bin:/opt/sbin:\$PATH
export NAIVEPANEL_UPDATE_API=https://raw.githubusercontent.com/api
export NAIVEPANEL_UPDATE_RAW=https://raw.githubusercontent.com
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
# /usr/bin/stat — именно GNU-стат Debian: /opt/bin/stat ссылается на busybox
# (фид 1.38), чей stat-апплет не умеет -c
pc_mode=\$(/usr/bin/stat -c %a /opt/etc/naive/panel/panel.conf 2>/dev/null || echo '?')
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
# контейнер той же архитектуры, что хост; musl-static сборка запускается в
# Debian реальным --version. НО: klzgrad не выпускает x86_64-static, а
# динамический openwrt-x86_64 требует новый libgcc (старая в Entware-фиде
# x64-k3.2 без __cpu_indicator_init) — на x86_64 установщик штатно
# отклоняет бинарник («fails to run»), сценарии naive пропускаем.
if [ ! -x /opt/bin/naive ]; then
  case "$(uname -m)" in
    x86_64) echo "SKIP naive scenarios: no x86_64-static asset upstream" ;;
    *) echo "FAIL: /opt/bin/naive not installed"; exit 1 ;;
  esac
else
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
fi  # /opt/bin/naive есть

echo "==> upgrade: rc.conf migration + --bind upsert + stale S99naiveproxy"
mkdir -p /opt/etc/init.d
# имитируем протухший S99naiveproxy (как после апгрейда v0.4.0 с pre-0.2.0):
printf '#!/bin/sh\nDAEMON_OPTS=/opt/etc/naiveproxy/config.json\n[ -f /opt/etc/naiveproxy/config.json ] || DAEMON_OPTS=\n' > /opt/etc/init.d/S99naiveproxy
printf 'OTHER_VAR="keep"\nNAIVEPANEL_BIND="10.9.9.9:1234"\n' > /opt/etc/init.d/rc.conf
# SEC-01 preflight: явный LAN-bind без пароля установщик отвергает; для
# позитивного апгрейд-сценария (flag wins) создаём admin.pass — префлайт
# проверяет его существование.
# Позитивный bind — 127.0.0.2: любой 127/8 в Linux доступен без настройки
# интерфейса, поэтому панель реально стартует и smoke что-то проверяет.
# 192.168.1.1 в контейнере не принадлежит интерфейсу: install.sh выживал
# (restart/smoke — warning), но smoke ждал TCP-таймаут ~2 мин × 5.
printf 'admin:dummy-for-preflight\n' > /opt/etc/naive/panel/admin.pass
curl -fsSL https://raw.githubusercontent.com/keenetic-tools/naivepanel/$REF/install.sh | sh -s -- --yes --bind 127.0.0.2:8089
if grep -q '^NAIVEPANEL_BIND="127.0.0.2:8089"' /opt/etc/naive/panel/panel.conf \
   && ! grep -q 'NAIVEPANEL' /opt/etc/init.d/rc.conf \
   && grep -q '^OTHER_VAR=' /opt/etc/init.d/rc.conf; then
  echo "panel.conf migration: OK (flag wins, rc.conf cleaned, other keys kept)"
else
  echo "FAIL: panel.conf migration"; cat /opt/etc/naive/panel/panel.conf /opt/etc/init.d/rc.conf; exit 1
fi
# миграция bind должна не только записать panel.conf, но и поднять панель
code=\$(curl -s -o /dev/null -w '%{http_code}' --connect-timeout 2 --max-time 3 http://127.0.0.2:8089/api/status || true)
case "\$code" in
  200|401) echo "panel on migrated bind: OK (HTTP \$code)" ;;
  *) echo "FAIL: panel did not start on migrated bind (HTTP \${code:-none})"
     cat /opt/var/log/naivepanel.log; exit 1 ;;
esac
# а без пароля тот же флаг обязан валить установку (fail-closed)
rm -f /opt/etc/naive/panel/admin.pass
if curl -fsSL https://raw.githubusercontent.com/keenetic-tools/naivepanel/$REF/install.sh \
     | sh -s -- --yes --bind 192.168.1.1:8089 >/tmp/bind-preflight.log 2>&1; then
  echo "FAIL: LAN bind without password accepted"; exit 1
fi
grep -q "exposes the panel" /tmp/bind-preflight.log \
  && echo "SEC-01 preflight: OK (dies on LAN bind without password)" \
  || { echo "FAIL: unexpected install failure"; cat /tmp/bind-preflight.log; exit 1; }
# SEC-07: встроенный верификатор из install.sh — позитив на релизных файлах
# и негатив на подменённом SHA256SUMS (тот код, что гоняется при каждой
# установке и self-update; здесь он же, извлечённый маркерами)
curl -fsSL https://raw.githubusercontent.com/keenetic-tools/naivepanel/$REF/install.sh > /tmp/np-install.sh
sed -n '/^#@np-verify-begin/,/^#@np-verify-end/p' /tmp/np-install.sh > /tmp/npverify.py
np_keyid=\$(grep '^NP_SIGN_KEYID=' /tmp/np-install.sh | cut -d'"' -f2)
np_pub=\$(grep '^NP_SIGN_PUBKEY=' /tmp/np-install.sh | cut -d'"' -f2)
rel=/www/keenetic-tools/naivepanel/$REF
np_py=/opt/bin/python3
[ -x "\$np_py" ] || np_py=python3
if NP_VERIFY_KEYID="\$np_keyid" NP_VERIFY_PUB="\$np_pub" \
   NP_VERIFY_SIG="\$rel/SHA256SUMS.minisig" NP_VERIFY_DATA="\$rel/SHA256SUMS" \
   "\$np_py" /tmp/npverify.py 2>/tmp/npverify-err.log; then
  echo "SEC-07 verify: OK (embedded verifier accepts the release)"
else
  echo "FAIL: embedded verifier rejects the release"; cat /tmp/npverify-err.log; exit 1
fi
cp "\$rel/SHA256SUMS" /tmp/tampered-sums && echo "deadbeef  naivepanel.py" >> /tmp/tampered-sums
if NP_VERIFY_KEYID="\$np_keyid" NP_VERIFY_PUB="\$np_pub" \
   NP_VERIFY_SIG="\$rel/SHA256SUMS.minisig" NP_VERIFY_DATA=/tmp/tampered-sums \
   "\$np_py" /tmp/npverify.py 2>/dev/null; then
  echo "FAIL: embedded verifier accepted tampered SHA256SUMS"; exit 1
else
  echo "SEC-07 tamper: OK (embedded verifier rejects tampered data)"
fi
if grep -q '/opt/etc/naive/proxy/config.json' /opt/etc/init.d/S99naiveproxy \
   && ! grep -q '/opt/etc/naiveproxy' /opt/etc/init.d/S99naiveproxy; then
  echo "stale S99naiveproxy replaced: OK"
else
  echo "FAIL: stale S99naiveproxy not replaced"; head -5 /opt/etc/init.d/S99naiveproxy; exit 1
fi
# повторный прогон установщика не трогает уже установленный бинарник
if [ -x /opt/bin/naive ]; then
  echo "naive survived upgrade rerun: \$(/opt/bin/naive --version 2>&1 | head -n 1)"
fi
echo "==> self-update: first attempt fails with rc=3 (expect \"exit_code\": 3)"
PANEL_URL=http://127.0.0.2:8089
before=\$(sha256sum /opt/etc/naive/panel/naivepanel.py | cut -d' ' -f1)
code=\$(curl -s -o /tmp/self-update-first.json -w '%{http_code}' \$H -X POST \
  \$PANEL_URL/api/update/apply)
echo "first apply=\$code (expect 202)"
[ "\$code" = "202" ] || { cat /tmp/self-update-first.json; exit 1; }
python3 - <<'PY'
import json
attempt = json.load(open("/tmp/self-update-first.json", encoding="utf-8"))
assert attempt["started"] is True
assert attempt["attempt_started"] > 0
assert attempt["pid"] > 0
assert attempt["target"] == "v0.27.5"
PY
phase=""
for i in \$(seq 1 60); do
  curl -s "\$PANEL_URL/api/update/log?lines=30" > /tmp/self-update-first-state.json
  phase=\$(python3 -c 'import json; print(json.load(open("/tmp/self-update-first-state.json"))["state"].get("phase", ""))')
  [ "\$phase" = "failed" ] && break
  sleep 1
done
[ "\$phase" = "failed" ] || {
  echo "FAIL: first self-update did not fail (phase=\$phase)"
  cat /tmp/self-update-first-state.json; exit 1
}
python3 - <<'PY'
import json
state = json.load(open("/tmp/self-update-first-state.json", encoding="utf-8"))["state"]
assert state["exit_code"] == 3, state
assert state["target"] == "v0.27.5", state
assert "code 3" in state["error"], state
PY
after=\$(sha256sum /opt/etc/naive/panel/naivepanel.py | cut -d' ' -f1)
[ "\$before" = "\$after" ] || { echo "FAIL: failed attempt changed panel files"; exit 1; }
curl -fsS "\$PANEL_URL/api/status" > /tmp/self-update-before-retry.json
python3 -c 'import json; assert json.load(open("/tmp/self-update-before-retry.json"))["version"] == "0.27.4"'

echo "==> self-update: manual retry installs the signed release"
code=\$(curl -s -o /tmp/self-update-retry.json -w '%{http_code}' \$H -X POST \
  \$PANEL_URL/api/update/apply)
echo "retry apply=\$code (expect 202)"
[ "\$code" = "202" ] || { cat /tmp/self-update-retry.json; exit 1; }
python3 - <<'PY'
import json
first = json.load(open("/tmp/self-update-first.json", encoding="utf-8"))
retry = json.load(open("/tmp/self-update-retry.json", encoding="utf-8"))
assert retry["attempt_started"] >= first["attempt_started"]
assert retry["pid"] != first["pid"]
assert retry["target"] == "v0.27.5"
PY
updated=0
for i in \$(seq 1 120); do
  if curl -fsS --connect-timeout 2 --max-time 3 "\$PANEL_URL/api/status" \
      > /tmp/self-update-status.json 2>/dev/null; then
    version=\$(python3 -c 'import json; print(json.load(open("/tmp/self-update-status.json"))["version"])')
    if [ "\$version" = "0.27.5" ]; then
      updated=1
      break
    fi
  fi
  sleep 1
done
[ "\$updated" = "1" ] || {
  echo "FAIL: signed retry did not bring up v0.27.5"
  cat /opt/var/log/naivepanel-update.log /opt/var/log/naivepanel.log; exit 1
}
curl -fsS "\$PANEL_URL/api/update/log?lines=60" > /tmp/self-update-final.json
python3 - <<'PY'
import json
state = json.load(open("/tmp/self-update-final.json", encoding="utf-8"))["state"]
assert state["phase"] == "done", state
assert state["target"] == "v0.27.5", state
PY
grep -q 'release signature verified' /opt/var/log/naivepanel-update.log \
  || { echo "FAIL: retry did not verify the release signature"; exit 1; }
echo "self-update: signed retry succeeded (v0.27.5, state done)"

echo "==> runtime gate: python deps broken under a running panel"
# Имитируем то, что делает opkg upgrade со сменившимся minor Python: pip-пакеты
# панели исчезли из site-packages текущего интерпретатора. Работающая панель
# этого не видит (код в памяти) — раньше любой рестарт был для неё последним.
jfield() {  # \$1=url \$2=выражение над json -> stdout; пусто, если не ответило
  curl -s --max-time 5 "\$1" | python3 -c "import json, sys
try:
    print((\$2)(json.load(sys.stdin)))
except Exception:
    pass"
}
site=\$("\$np_py" -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])')
echo "site-packages: \$site"
mkdir -p /tmp/rt-deps-bak
mv "\$site/flask" /tmp/rt-deps-bak/flask
for d in "\$site"/flask-*.dist-info; do mv "\$d" /tmp/rt-deps-bak/; done
started_before=\$(jfield "\$PANEL_URL/api/status" 'lambda d: d["panel"]["started"]')
runtime=""
for i in \$(seq 1 60); do
  runtime=\$(jfield "\$PANEL_URL/api/status" 'lambda d: d["runtime"]["state"]')
  [ "\$runtime" = "broken" ] && break
  sleep 1
done
[ "\$runtime" = "broken" ] || {
  echo "FAIL: broken runtime not surfaced (state=\$runtime) after \$i polls"
  echo "--- diagnostics: /api/status → runtime"; jfield "\$PANEL_URL/api/status" 'lambda d: d.get("runtime")'
  echo "--- diagnostics: fresh interpreter importing flask"
  "\$np_py" -c 'import flask; print("IMPORTABLE:", flask.__file__)' 2>&1 | tail -n 3
  echo "--- diagnostics: flask remnants in site-packages"; ls -d "\$site"/flask* 2>&1 | head -n 5
  echo "--- diagnostics: panel dir + processes"
  ls -la /opt/etc/naive/panel/ | head -n 12
  ps w | grep '[n]aivepanel.py' | cut -c1-120
  echo "--- diagnostics: forced sync probe (POST /api/runtime/check)"
  curl -s --max-time 60 \$H -X POST "\$PANEL_URL/api/runtime/check"; echo
  tail -n 40 /opt/var/log/naivepanel.log; exit 1
}
echo "broken runtime surfaced in /api/status: OK (after \$i polls)"
# рестарт в заведомо нерабочее состояние отклонён — синхронная перепроверка
code=\$(curl -s -o /tmp/rt-restart.json -w '%{http_code}' --max-time 60 \$H -X POST "\$PANEL_URL/api/panel/restart")
echo "restart while broken=\$code (expect 409)"
[ "\$code" = "409" ] || { cat /tmp/rt-restart.json; exit 1; }
# «Исправить и перезапустить» = переустановка текущей версии установщиком: его
# deps_check видит пропажу СВЕЖИМ интерпретатором, ставит flask через pip (в
# фидах Entware python3-flask нет) и только потом перезапускает панель
code=\$(curl -s -o /tmp/rt-repair.json -w '%{http_code}' \$H -X POST "\$PANEL_URL/api/update/repair")
echo "repair apply=\$code (expect 202)"
[ "\$code" = "202" ] || { cat /tmp/rt-repair.json; exit 1; }
started_after=""
for i in \$(seq 1 150); do
  started_after=\$(jfield "\$PANEL_URL/api/status" 'lambda d: d["panel"]["started"]')
  [ -n "\$started_after" ] && [ "\$started_after" != "\$started_before" ] && break
  sleep 1
done
{ [ -n "\$started_after" ] && [ "\$started_after" != "\$started_before" ]; } || {
  echo "FAIL: repair did not restart the panel"
  cat /opt/var/log/naivepanel-update.log; tail -n 20 /opt/var/log/naivepanel.log; exit 1
}
grep -q 'python/deps OK .*installed: flask' /opt/var/log/naivepanel-update.log \
  || { echo "FAIL: installer log has no repair line"; cat /opt/var/log/naivepanel-update.log; exit 1; }
"\$np_py" -c 'import flask' || { echo "FAIL: flask not importable after repair"; exit 1; }
runtime=\$(jfield "\$PANEL_URL/api/status" 'lambda d: d["runtime"]["state"]')
phase=\$(jfield "\$PANEL_URL/api/update/log" 'lambda d: d["state"]["phase"]')
{ [ "\$runtime" = "ok" ] && [ "\$phase" = "done" ]; } || {
  echo "FAIL: after repair runtime=\$runtime phase=\$phase (expect ok/done)"; exit 1
}
echo "runtime repair: OK (flask reinstalled by installer, panel restarted, state done)"

echo "==> runtime gate: unrepairable deps never restart a running panel"
# ломаем снова и отбираем у pip индекс: чинить нечем. Установщик обязан уйти
# ДО подмены файлов — панель остаётся тем же процессом с теми же файлами
mkdir -p /tmp/rt-deps-bak2
mv "\$site/flask" /tmp/rt-deps-bak2/
for d in "\$site"/flask-*.dist-info; do mv "\$d" /tmp/rt-deps-bak2/; done
sum_before=\$(sha256sum /opt/etc/naive/panel/naivepanel.py | cut -d' ' -f1)
started_before=\$(jfield "\$PANEL_URL/api/status" 'lambda d: d["panel"]["started"]')
curl -fsSL https://raw.githubusercontent.com/keenetic-tools/naivepanel/$NEXT_REF/install.sh > /tmp/rt-install.sh
if PIP_INDEX_URL=http://127.0.0.1:9/simple PIP_RETRIES=0 \
   sh /tmp/rt-install.sh --yes --from-update --ref $NEXT_REF > /tmp/rt-unrepairable.log 2>&1; then
  echo "FAIL: installer finished OK with unrepairable deps"; cat /tmp/rt-unrepairable.log; exit 1
fi
grep -q 'files were NOT replaced' /tmp/rt-unrepairable.log \
  && echo "installer gate: OK (died before touching panel files)" \
  || { echo "FAIL: no gate message in installer log"; cat /tmp/rt-unrepairable.log; exit 1; }
[ "\$(sha256sum /opt/etc/naive/panel/naivepanel.py | cut -d' ' -f1)" = "\$sum_before" ] \
  || { echo "FAIL: panel files changed by a refused installer"; exit 1; }
started_after=\$(jfield "\$PANEL_URL/api/status" 'lambda d: d["panel"]["started"]')
[ "\$started_after" = "\$started_before" ] \
  || { echo "FAIL: running panel was restarted with broken deps"; exit 1; }
echo "running panel untouched: OK"
# починили по SSH → «Перепроверить» сразу снимает баннер (без ожидания фона)
mv /tmp/rt-deps-bak2/flask "\$site/"
for d in /tmp/rt-deps-bak2/flask-*.dist-info; do mv "\$d" "\$site/"; done
code=\$(curl -s -o /tmp/rt-recheck.json -w '%{http_code}' --max-time 60 \$H -X POST "\$PANEL_URL/api/runtime/check")
[ "\$code" = "200" ] || { echo "FAIL: runtime check HTTP \$code"; cat /tmp/rt-recheck.json; exit 1; }
grep -q '"state": *"ok"' /tmp/rt-recheck.json \
  && echo "runtime recheck after manual fix: OK" \
  || { echo "FAIL: runtime still not ok after manual fix"; cat /tmp/rt-recheck.json; exit 1; }

echo "==> non-child zombie detection via procfs"
cat > /tmp/zombie-parent.py <<'PY'
import os
import time
from pathlib import Path

pid = os.fork()
if pid == 0:
    os._exit(0)
print(pid, flush=True)
release = Path("/tmp/naivepanel-e2e-zombie.release")
deadline = time.time() + 30
while not release.exists() and time.time() < deadline:
    time.sleep(0.1)
if release.exists():
    os.waitpid(pid, 0)
PY
"\$np_py" /tmp/zombie-parent.py > /tmp/zombie-child.pid &
zparent=\$!
zombie_ok=0
for i in \$(seq 1 50); do
  if [ -s /tmp/zombie-child.pid ]; then
    child=\$(cat /tmp/zombie-child.pid)
    if "\$np_py" -c 'import sys; sys.path.insert(0, "/opt/etc/naive/panel"); from panel.updates import _pid_alive; sys.exit(1 if _pid_alive(int(sys.argv[1])) else 0)' "\$child"; then
      zombie_ok=1
      break
    fi
  fi
  sleep 1
done
touch /tmp/naivepanel-e2e-zombie.release
wait "\$zparent"
[ "\$zombie_ok" = "1" ] || { echo "FAIL: non-child zombie still looks alive"; exit 1; }
echo "non-child zombie: OK"

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
