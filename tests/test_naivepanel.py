"""Unit-тесты NaivePanel: API-семантика через Flask test client, без сети.

Пути подменяются через env ДО импорта модуля — константы считываются при
import, поэтому фикстура делает importlib.reload на каждый тест.
"""
import base64
import importlib
import json
import os
import re
import sys
import time
import types
from pathlib import Path

import pytest

APP_DIR = Path(__file__).resolve().parents[1]

CSRF = {"X-Requested-With": "naivepanel"}


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("NAIVEPROXY_DIR", str(tmp_path / "proxy"))
    monkeypatch.setenv("NAIVEPANEL_PASS", str(tmp_path / "admin.pass"))
    monkeypatch.setenv("NAIVEPROXY_INIT", str(tmp_path / "absent-init.sh"))
    monkeypatch.setenv("NAIVEPANEL_INIT", str(tmp_path / "absent-init.sh"))
    monkeypatch.setenv("NAIVEPROXY_LOG", str(tmp_path / "naiveproxy.log"))
    monkeypatch.setenv("NAIVEPROXY_PID", str(tmp_path / "naiveproxy.pid"))
    monkeypatch.syspath_prepend(str(APP_DIR))
    return tmp_path


@pytest.fixture()
def app(env):
    import naivepanel
    importlib.reload(naivepanel)
    return naivepanel


@pytest.fixture()
def client(app):
    return app.app.test_client()


def _create(client, **overrides):
    payload = {
        "name": "home",
        "listen": "127.0.0.1:1080",
        "upstream": "proxy.example.com",
        "username": "user",
        "password": "p@ss:word",
    }
    payload.update(overrides)
    return client.post("/api/configs", json=payload, headers=CSRF), payload


# --- panel.conf: постоянные настройки ----------------------------------------

@pytest.fixture()
def conf_env(env, monkeypatch):
    """panel.conf-тесты применяют файл через os.environ.setdefault —
    сохраняем/восстанавливаем окружение целиком, чтобы не протекло."""
    saved = dict(os.environ)
    conf = env / "panel.conf"
    monkeypatch.setenv("NAIVEPANEL_CONF", str(conf))
    yield conf
    os.environ.clear()
    os.environ.update(saved)


def _reload():
    import naivepanel
    importlib.reload(naivepanel)
    return naivepanel


def test_conf_file_applies_bind_and_hosts(conf_env):
    conf_env.write_text(
        'NAIVEPANEL_BIND="192.168.1.1:8099"\n'
        'NAIVEPANEL_HOSTS="np.lan:8099,192.168.1.1:8099"\n'
    )
    m = _reload()
    assert m.PANEL_BIND == "192.168.1.1:8099"
    assert "np.lan:8099" in m.ALLOWED_HOSTS
    c = m.app.test_client()
    assert c.get("/api/status", headers={"Host": "np.lan:8099"}).status_code == 200
    assert c.get("/api/status", headers={"Host": "evil.com"}).status_code == 403


def test_conf_env_overrides_file(conf_env, monkeypatch):
    conf_env.write_text('NAIVEPANEL_BIND="10.0.0.1:9999"\n')
    monkeypatch.setenv("NAIVEPANEL_BIND", "127.0.0.1:8091")
    m = _reload()
    assert m.PANEL_BIND == "127.0.0.1:8091"  # env > panel.conf


def test_conf_ignores_comments_unknown_keys_and_typos(conf_env):
    conf_env.write_text(
        "# комментарий\n"
        "\n"
        "FOO=bar\n"
        "NIVEPANEL_BIND=x\n"  # опечатка не должна применять значение
        "NAIVEPANEL_HOSTS=\"a.lan:1\"\n"
    )
    m = _reload()
    assert "a.lan:1" in m.ALLOWED_HOSTS
    assert m.PANEL_BIND == "127.0.0.1:8089"  # дефолт — NIVEPANEL_* проигнорирован
    assert "FOO" in m._CONF_SKIPPED
    assert "NIVEPANEL_BIND" in m._CONF_SKIPPED


def test_conf_quotes_stripped(conf_env):
    conf_env.write_text("NAIVEPANEL_BIND='127.0.0.1:8095'\n")
    m = _reload()
    assert m.PANEL_BIND == "127.0.0.1:8095"


def test_conf_missing_file_uses_defaults(env, monkeypatch):
    monkeypatch.setenv("NAIVEPANEL_CONF", str(env / "absent.conf"))
    m = _reload()
    assert m.PANEL_BIND == "127.0.0.1:8089"


def _stub_init(env, marker_name="init-calls.txt"):
    """Исполняемый init-стаб: пишет аргумент (start|stop|restart) в marker."""
    marker = env / marker_name
    stub = env / "init-stub.sh"
    stub.write_text(f'#!/bin/sh\necho "$1" >> "{marker}"\nexit 0\n')
    stub.chmod(0o755)
    return stub, marker


# --- CSRF -------------------------------------------------------------------

def test_mutations_require_csrf_header(client):
    r = client.post("/api/service/restart")
    assert r.status_code == 403
    r = client.delete("/api/configs/home", json={}, content_type="application/json")
    assert r.status_code == 403


def test_mutations_pass_with_header(client):
    # init-скрипта нет — /api/service вернёт 503, но уже не 403
    r = client.post("/api/service/restart", headers=CSRF)
    assert r.status_code == 503


# --- create / get: пароль write-only ----------------------------------------

def test_create_requires_password_for_host_upstream(client):
    r, _ = _create(client, password="")
    assert r.status_code == 400


def test_create_full_url_upstream_needs_no_creds(client):
    r, _ = _create(client, upstream="quic://user:secret@host.example:443",
                   username="", password="")
    assert r.status_code == 201


def test_get_splits_fields_and_omits_password(client, app):
    r, payload = _create(client)  # password содержит и @, и :
    assert r.status_code == 201
    r = client.get("/api/configs/home")
    assert r.status_code == 200
    data = r.get_json()
    assert data["upstream"] == "proxy.example.com"
    assert data["username"] == "user"
    assert "password" not in data
    assert "proxy" not in data
    # на диске URI собран целиком; спецсимволы пароля percent-encoded
    stored = json.loads((app.CONF_D / "home.json").read_text())
    assert stored["proxy"] == "https://user:p%40ss%3Aword@proxy.example.com"


def test_list_masks_credentials_and_is_no_store(client):
    r, _ = _create(client)  # пароль p@ss:word (percent-encoded на диске)
    assert r.status_code == 201
    r = client.get("/api/configs")
    assert r.status_code == 200
    body = r.get_data(as_text=True)
    assert "p%40ss%3Aword" not in body   # ни percent-encoded, ни raw пароль
    assert "p@ss:word" not in body
    assert r.headers.get("Cache-Control") == "no-store"
    item = r.get_json()[0]
    assert item["proxy"] == "https://user:***@proxy.example.com"
    assert item["username"] == "user"


def test_put_reuses_password_when_omitted(client, app):
    _create(client)
    r = client.put("/api/configs/home", headers=CSRF, json={
        "name": "home",
        "listen": "127.0.0.1:1080",
        "upstream": "other.example.com",   # сменили хост, пароль не прислали
        "username": "user",
    })
    assert r.status_code == 200
    stored = json.loads((app.CONF_D / "home.json").read_text())
    assert stored["proxy"] == "https://user:p%40ss%3Aword@other.example.com"


def test_put_reuses_username_when_upstream_unchanged(client, app):
    _create(client)
    r = client.put("/api/configs/home", headers=CSRF, json={
        "name": "home",
        "listen": "socks://127.0.0.1:1080,http://127.0.0.1:8080",  # заодно массив
        "upstream": "proxy.example.com",
    })
    assert r.status_code == 200
    stored = json.loads((app.CONF_D / "home.json").read_text())
    assert stored["listen"] == ["socks://127.0.0.1:1080", "http://127.0.0.1:8080"]
    assert stored["proxy"] == "https://user:p%40ss%3Aword@proxy.example.com"


# --- auth -------------------------------------------------------------------

def test_status_includes_version(client, app):
    data = client.get("/api/status").get_json()
    assert data["version"] == app.APP_VERSION


def test_auth_401_without_credentials(client, env):
    (env / "admin.pass").write_text("admin:$2b$12$shortbrokenhash\n")
    r = client.get("/api/status")
    assert r.status_code == 401  # fail-closed, в т.ч. на битом хэше (не 500)


def test_auth_accepts_correct_password(client, env):
    bcrypt = pytest.importorskip("bcrypt")
    h = bcrypt.hashpw(b"s3cret", bcrypt.gensalt()).decode()
    (env / "admin.pass").write_text(f"admin:{h}\n")
    token = base64.b64encode(b"admin:s3cret").decode()
    assert client.get("/api/status").status_code == 401
    r = client.get("/api/status", headers={"Authorization": f"Basic {token}"})
    assert r.status_code == 200


def test_wrong_password_is_rejected(client, env):
    bcrypt = pytest.importorskip("bcrypt")
    h = bcrypt.hashpw(b"s3cret", bcrypt.gensalt()).decode()
    (env / "admin.pass").write_text(f"admin:{h}\n")
    token = base64.b64encode(b"admin:wrong").decode()
    r = client.get("/api/status", headers={"Authorization": f"Basic {token}"})
    assert r.status_code == 401


def test_auth_throttles_after_repeated_failures(client, env, app):
    bcrypt = pytest.importorskip("bcrypt")
    h = bcrypt.hashpw(b"s3cret", bcrypt.gensalt()).decode()
    (env / "admin.pass").write_text(f"admin:{h}\n")
    bad = base64.b64encode(b"admin:wrong").decode()
    for _ in range(app._AUTH_FAIL_LIMIT):
        assert client.get("/api/status", headers={"Authorization": f"Basic {bad}"}).status_code == 401
    assert client.get("/api/status", headers={"Authorization": f"Basic {bad}"}).status_code == 429


def test_auth_missing_header_does_not_throttle(client, env, app):
    # анонимные пробы (без Authorization) не считаются: за reverse-proxy
    # с общим remote_addr иначе блокировались бы все админы
    (env / "admin.pass").write_text("admin:$2b$12$shortbrokenhash\n")
    for _ in range(app._AUTH_FAIL_LIMIT + 3):
        assert client.get("/api/status").status_code == 401


def test_auth_success_clears_failure_counter(client, env, app):
    bcrypt = pytest.importorskip("bcrypt")
    h = bcrypt.hashpw(b"s3cret", bcrypt.gensalt()).decode()
    (env / "admin.pass").write_text(f"admin:{h}\n")
    bad = base64.b64encode(b"admin:wrong").decode()
    good = base64.b64encode(b"admin:s3cret").decode()
    # прогреваем кэш: следующий успех пойдёт по fast-path, минуя bcrypt
    assert client.get("/api/status", headers={"Authorization": f"Basic {good}"}).status_code == 200
    for _ in range(app._AUTH_FAIL_LIMIT - 1):
        client.get("/api/status", headers={"Authorization": f"Basic {bad}"})
    # успех по кэшу тоже должен сбросить счётчик неудач
    assert client.get("/api/status", headers={"Authorization": f"Basic {good}"}).status_code == 200
    # счётчик сброшен: полный лимит ошибок снова даёт 401, а не 429
    for _ in range(app._AUTH_FAIL_LIMIT):
        assert client.get("/api/status", headers={"Authorization": f"Basic {bad}"}).status_code == 401


# --- вспомогательные функции ------------------------------------------------

def test_split_proxy(app):
    assert app._split_proxy("https://user:p@ss:word@host.example") == \
        ("host.example", "user", "p@ss:word")
    assert app._split_proxy("quic://user:secret@host:443") == \
        ("quic://user:secret@host:443", "", None)
    # кредов нет — URI возвращается целиком (такое значение хранится,
    # только если upstream пришёл как полный URL без кредов)
    assert app._split_proxy("https://host.example") == \
        ("https://host.example", "", None)


def test_normalize_listen_variants(app):
    assert app._normalize_listen("127.0.0.1:1080") == "socks://127.0.0.1:1080"
    assert app._normalize_listen("http://127.0.0.1:8080") == "http://127.0.0.1:8080"
    assert app._normalize_listen("  ") is None


# --- Host allowlist (анти-DNS-rebinding) -------------------------------------

def test_host_allowlist_default_permits_local_only(client):
    # без NAIVEPANEL_HOSTS разрешён адрес bind + loopback-алиасы
    assert client.get("/api/status", headers={"Host": "localhost"}).status_code == 200
    assert client.get("/api/status", headers={"Host": "127.0.0.1:8089"}).status_code == 200
    assert client.get("/api/status", headers={"Host": "localhost:8089"}).status_code == 200
    # чужое имя — маркер DNS-rebinding → 403
    r = client.get("/api/status", headers={"Host": "evil.com:8089"})
    assert r.status_code == 403


def test_host_allowlist_explicit_is_exact(client, env, monkeypatch):
    monkeypatch.setenv("NAIVEPANEL_HOSTS", "router.lan:8089,192.168.1.1:8089")
    import naivepanel
    importlib.reload(naivepanel)
    c = naivepanel.app.test_client()
    assert c.get("/api/status", headers={"Host": "router.lan:8089"}).status_code == 200
    assert c.get("/api/status", headers={"Host": "192.168.1.1:8089"}).status_code == 200
    # задан allowlist → даже loopback без явного разрешения не проходит
    assert c.get("/api/status", headers={"Host": "127.0.0.1:8089"}).status_code == 403
    assert c.get("/api/status", headers={"Host": "evil.com:8089"}).status_code == 403


def test_parse_bind_variants(app):
    assert app._parse_bind("127.0.0.1:8089") == ("127.0.0.1", 8089)
    assert app._parse_bind("[::1]:8089") == ("::1", 8089)
    assert app._parse_bind("::1") == ("::1", 8089)      # голый IPv6 без порта
    assert app._parse_bind("::") == ("::", 8089)
    assert app._parse_bind("localhost") == ("localhost", 8089)
    assert app._parse_bind(":9000") == ("127.0.0.1", 9000)
    assert app._parse_bind("192.168.1.1:80") == ("192.168.1.1", 80)


# --- auth-кэш -----------------------------------------------------------------

def test_auth_cache_avoids_bcrypt_rehash(client, env, monkeypatch):
    bcrypt = pytest.importorskip("bcrypt")
    h = bcrypt.hashpw(b"s3cret", bcrypt.gensalt()).decode()
    (env / "admin.pass").write_text(f"admin:{h}\n")
    calls = {"n": 0}
    real = bcrypt.checkpw
    def counted(pw, hash_):
        calls["n"] += 1
        return real(pw, hash_)
    monkeypatch.setattr(bcrypt, "checkpw", counted)
    token = base64.b64encode(b"admin:s3cret").decode()
    for _ in range(3):  # поллинг UI шлёт одни и те же креды каждые 3с
        assert client.get("/api/status", headers={"Authorization": f"Basic {token}"}).status_code == 200
    assert calls["n"] == 1  # проверка выполнена один раз, дальше — кэш


def test_auth_cache_reset_on_admin_pass_change(client, env):
    bcrypt = pytest.importorskip("bcrypt")
    p = env / "admin.pass"
    p.write_text("admin:" + bcrypt.hashpw(b"s3cret", bcrypt.gensalt()).decode() + "\n")
    os.utime(p, ns=(1_000_000_000, 1_000_000_000))
    token = base64.b64encode(b"admin:s3cret").decode()
    assert client.get("/api/status", headers={"Authorization": f"Basic {token}"}).status_code == 200
    # пароль сменили — кэш сбрасывается (mtime/size), старые креды больше не годятся
    p.write_text("admin:" + bcrypt.hashpw(b"other", bcrypt.gensalt()).decode() + "\n")
    os.utime(p, ns=(2_000_000_000, 2_000_000_000))
    assert client.get("/api/status", headers={"Authorization": f"Basic {token}"}).status_code == 401


# --- PUT активного пресета / activate ----------------------------------------

def test_put_active_propagates_and_restarts(client, app, env):
    stub, marker = _stub_init(env)
    app.INIT_SCRIPT = stub
    _create(client)
    r = client.post("/api/configs/home/activate", headers=CSRF)
    assert r.status_code == 200
    assert marker.read_text().splitlines()[-1] == "restart"
    r = client.put("/api/configs/home", headers=CSRF, json={
        "name": "home",
        "listen": "127.0.0.1:1081",
        "upstream": "proxy.example.com",
        "username": "user",
    })
    assert r.status_code == 200
    assert r.get_json()["restart"]["rc"] == 0
    assert marker.read_text().splitlines()[-1] == "restart"  # PUT тоже применил
    active = json.loads(app.ACTIVE_CONFIG.read_text())
    assert active["listen"] == "socks://127.0.0.1:1081"
    assert app.ACTIVE_CONFIG.stat().st_mode & 0o777 == 0o600


def test_put_inactive_preset_has_no_restart(client, app):
    _create(client)
    r = client.put("/api/configs/home", headers=CSRF, json={
        "name": "home",
        "listen": "127.0.0.1:1080",
        "upstream": "proxy.example.com",
        "username": "user",
    })
    assert r.status_code == 200
    assert r.get_json()["restart"] is None


def test_panel_restart_spawns_init(client, app, env):
    marker = env / "panel-restart.txt"
    stub = env / "panel-init.sh"
    stub.write_text(f'#!/bin/sh\necho restart >> "{marker}"\n')
    stub.chmod(0o755)
    app.PANEL_INIT = stub
    r = client.post("/api/panel/restart", headers=CSRF)
    assert r.status_code == 202
    for _ in range(50):  # endpoint спавнит sh после sleep 1
        if marker.exists():
            break
        time.sleep(0.1)
    assert marker.read_text().strip() == "restart"


# --- percent-encoding креденшалов --------------------------------------------

def test_password_special_chars_encoded_roundtrip(client, app):
    r, _ = _create(client, password="p@ss/w:rd x")
    assert r.status_code == 201
    stored = json.loads((app.CONF_D / "home.json").read_text())
    assert stored["proxy"] == "https://user:p%40ss%2Fw%3Ard%20x@proxy.example.com"
    # PUT без пароля: старый извлекается (unquote) и кодируется заново
    r = client.put("/api/configs/home", headers=CSRF, json={
        "name": "home",
        "listen": "127.0.0.1:1080",
        "upstream": "other.example.com",
        "username": "user",
    })
    stored = json.loads((app.CONF_D / "home.json").read_text())
    assert stored["proxy"] == "https://user:p%40ss%2Fw%3Ard%20x@other.example.com"


def test_split_proxy_unquotes_and_keeps_legacy(app):
    assert app._split_proxy("https://user:p%40ss@host.example") == ("host.example", "user", "p@ss")
    # легаси-конфиги с raw @ в пароле не ломаются (unquote без % — no-op)
    assert app._split_proxy("https://user:p@ss@host.example") == ("host.example", "user", "p@ss")


# --- логи: tail + маскирование кредов ----------------------------------------

def test_logs_mask_credentials(client, env):
    (env / "naiveproxy.log").write_text(
        "2026-01-01 starting\n"
        "dial https://user:s3cret@proxy.example.com failed\n"
        "plain https://host/path ok\n"
        "socks://127.0.0.1:1080 listening\n"
    )
    content = client.get("/api/logs?lines=10").get_json()["content"]
    assert "s3cret" not in content
    assert "user:***@proxy.example.com" in content
    assert "https://host/path" in content      # URI без кредов не трогаем
    assert "socks://127.0.0.1:1080" in content


def test_logs_tail_reads_only_requested_lines(client, env):
    (env / "naiveproxy.log").write_text("".join(f"line{i}\n" for i in range(500)))
    content = client.get("/api/logs?lines=10").get_json()["content"]
    lines = content.splitlines()
    assert lines[0] == "line490"
    assert lines[-1] == "line499"
    assert len(lines) == 10


# --- JSON-ошибки для API ------------------------------------------------------

def test_api_errors_are_json(client):
    r = client.get("/api/configs/doesnotexist")
    assert r.status_code == 404
    assert r.get_json()["error"]  # не HTML-страница Flask
    r = client.post("/api/configs/doesnotexist/activate", headers=CSRF)
    assert r.status_code == 404
    assert r.get_json()["error"]
    # не-API пути получают обычную HTML-страницу ошибок
    r = client.get("/no-such-page")
    assert r.status_code == 404
    assert not r.is_json


# --- Security headers -----------------------------------------------------------

def test_security_headers_on_pages_and_api(client):
    for path in ("/", "/api/status"):
        r = client.get(path)
        csp = r.headers.get("Content-Security-Policy", "")
        assert "default-src 'none'" in csp
        assert "connect-src 'self'" in csp
        assert r.headers.get("X-Content-Type-Options") == "nosniff"
        assert r.headers.get("X-Frame-Options") == "DENY"
        assert r.headers.get("Referrer-Policy") == "no-referrer"


def test_csp_uses_nonce_and_drops_unsafe_inline_script(client):
    r = client.get("/")
    csp = r.headers["Content-Security-Policy"]
    assert "script-src 'nonce-" in csp
    assert "script-src 'unsafe-inline'" not in csp
    assert "style-src 'unsafe-inline'" in csp  # inline-стили и style="" остаются
    nonce = csp.split("script-src 'nonce-", 1)[1].split("'", 1)[0]
    assert f'nonce="{nonce}"' in r.get_data(as_text=True)


def test_ui_has_no_inline_event_handlers(app):
    html = (APP_DIR / "templates" / "index.html").read_text(encoding="utf-8")
    assert not re.search(r"\son[a-z]+\s*=", html), "inline-обработчики блокирует nonce-CSP"


def test_csp_has_no_external_origins(client):
    csp = client.get("/").headers["Content-Security-Policy"]
    for src in csp.split(";"):
        if "src" in src or "uri" in src:
            assert "://" not in src


def test_export_and_logs_are_no_store(client):
    _create(client)
    assert client.get("/api/configs/export").headers.get("Cache-Control") == "no-store"
    assert client.get("/api/logs").headers.get("Cache-Control") == "no-store"


def test_ui_uses_dialog_not_native_confirm(app):
    html = (APP_DIR / "templates" / "index.html").read_text(encoding="utf-8")
    assert "<dialog" in html
    assert "confirm(" not in html  # нативные confirm() убраны в пользу <dialog>


def test_ui_log_viewer_has_controls(app):
    html = (APP_DIR / "templates" / "index.html").read_text(encoding="utf-8")
    assert 'data-action="logFilter"' in html
    assert 'data-action="logDownload"' in html
    assert 'data-action="logCopy"' in html


def test_ui_has_skeleton_and_live_validation(app):
    html = (APP_DIR / "templates" / "index.html").read_text(encoding="utf-8")
    assert "skel" in html
    assert 'id="f_upstream"' in html and 'id="upHint"' in html


def test_ui_upstream_hint_accepts_credential_urls(app):
    html = (APP_DIR / "templates" / "index.html").read_text(encoding="utf-8")
    m = re.search(r"const UP_OK = /(.+)/;", html)
    assert m, "UP_OK не найден в index.html"
    # JS-экранирование \/ совместимо с Python re после раскрытия
    up_ok = re.compile(m.group(1).replace(r"\/", "/"))
    for url in ("https://user:pass@host:443/path?q=1#frag",
                "https://proxy.example.com",
                "quic://host:443",
                "proxy.example.com"):
        assert up_ok.match(url), f"должен приниматься: {url}"
    assert not up_ok.match("file://x"), "чужая схема не должна приниматься"


def test_ui_has_single_light_palette_definition(app):
    html = (APP_DIR / "templates" / "index.html").read_text(encoding="utf-8")
    assert html.count("--bg:#f4f5f7") == 1


# --- duplicate ------------------------------------------------------------------

def test_duplicate_copies_config_with_password(client, app):
    _create(client)
    r = client.post("/api/configs/home/duplicate", headers=CSRF)
    assert r.status_code == 201
    assert r.get_json()["name"] == "home-copy"
    src = json.loads((app.CONF_D / "home.json").read_text())
    copy = json.loads((app.CONF_D / "home-copy.json").read_text())
    assert copy == src  # включая proxy-URI с паролем
    assert copy["proxy"] == "https://user:p%40ss%3Aword@proxy.example.com"


def test_duplicate_counter_and_missing(client):
    _create(client)
    for _ in range(2):
        r = client.post("/api/configs/home/duplicate", headers=CSRF)
        assert r.status_code == 201
    assert r.get_json()["name"] == "home-copy2"
    assert client.post("/api/configs/nope/duplicate", headers=CSRF).status_code == 404
    # CSRF обязателен и для duplicate
    assert client.post("/api/configs/home/duplicate").status_code == 403


# --- валидация перед активацией --------------------------------------------------

def test_activate_rejects_broken_preset(client, app):
    # пресет, отредактированный руками до битого состояния
    app._ensure_dirs()
    (app.CONF_D / "broken.json").write_text('{"listen": "", "proxy": "https://h"}')
    r = client.post("/api/configs/broken/activate", headers=CSRF)
    assert r.status_code == 400
    assert "listen" in r.get_json()["error"]
    # активный конфиг не тронут: activate отклонён ДО перезаписи config.json
    assert not app.ACTIVE_CONFIG.exists()


def test_activate_rejects_proxy_without_scheme(client, app):
    app._ensure_dirs()
    (app.CONF_D / "noscheme.json").write_text(
        '{"listen": "socks://127.0.0.1:1080", "proxy": "justhost"}')
    r = client.post("/api/configs/noscheme/activate", headers=CSRF)
    assert r.status_code == 400
    assert "proxy" in r.get_json()["error"]


def test_validate_cfg_rejects_non_proxy_schemes(client, app):
    app._ensure_dirs()
    (app.CONF_D / "fileproto.json").write_text(
        '{"listen": "socks://127.0.0.1:1080", "proxy": "file:///etc/passwd"}')
    r = client.post("/api/configs/fileproto/activate", headers=CSRF)
    assert r.status_code == 400
    assert "proxy" in r.get_json()["error"]


def test_create_rejects_non_proxy_scheme(client, app):
    r, _ = _create(client, upstream="file://x@y", username="", password="")
    assert r.status_code == 400
    assert "proxy" in r.get_json()["error"]
    assert not (app.CONF_D / "home.json").exists()  # ничего не сохранили


def test_validate_cfg_ranges_and_types(app):
    good = {"listen": "socks://127.0.0.1:1080", "proxy": "https://h"}
    app._validate_cfg(good, "ok")  # не бросает
    app._validate_cfg({**good, "insecure-concurrency": 4}, "ok")
    # схема проверяется без учёта регистра и с обрезкой пробелов
    app._validate_cfg({**good, "proxy": "HTTPS://h"}, "ok")
    app._validate_cfg({**good, "proxy": "  https://h  "}, "ok")
    for bad in [{"insecure-concurrency": 5}, {"insecure-concurrency": True},
                {"log": 42}, {"extra-headers": []}]:
        with pytest.raises(Exception):
            app._validate_cfg({**good, **bad}, "bad")


# --- export / import --------------------------------------------------------------

def test_export_contains_all_presets_with_creds(client):
    _create(client)
    _create(client, name="work", upstream="other.example.com")
    r = client.get("/api/configs/export")
    assert r.status_code == 200
    assert "attachment" in r.headers["Content-Disposition"]
    data = r.get_json()
    assert set(data["presets"]) == {"home", "work"}
    # осознанное исключение из write-only: бэкап без паролей не был бы бэкапом
    assert data["presets"]["home"]["proxy"] == "https://user:p%40ss%3Aword@proxy.example.com"


def test_import_roundtrip_and_skip_existing(client, env):
    _create(client)
    export = client.get("/api/configs/export").get_json()
    export["presets"]["home"]["listen"] = "socks://127.0.0.1:1999"  # «другой роутер»
    r = client.post("/api/configs/import", headers=CSRF, json=export)
    assert r.status_code == 200
    d = r.get_json()
    assert d["imported"] == []  # home уже есть — не перезаписываем
    assert d["skipped"][0]["reason"] == "already exists"


def test_import_creates_presets_and_file_rights(client, app):
    body = {"format": 1, "presets": {
        "imported-one": {"listen": "socks://127.0.0.1:1080",
                         "proxy": "https://u:p@h.example"},
    }}
    r = client.post("/api/configs/import", headers=CSRF, json=body)
    d = r.get_json()
    assert d["imported"] == ["imported-one"] and d["skipped"] == []
    p = app.CONF_D / "imported-one.json"
    assert p.stat().st_mode & 0o777 == 0o600  # секреты → права как у пресетов


def test_import_rejects_invalid_entries(client):
    body = {"presets": {
        "bad name!": {"listen": "socks://127.0.0.1:1080", "proxy": "https://h"},
        "broken": {"listen": "", "proxy": ""},
        "good": {"listen": "127.0.0.1:1080", "proxy": "https://h"},
    }}
    d = client.post("/api/configs/import", headers=CSRF, json=body).get_json()
    assert d["imported"] == ["good"]
    reasons = {s["name"]: s["reason"] for s in d["skipped"]}
    assert "invalid name" in reasons["bad name!"]
    assert "listen" in reasons["broken"]
    assert client.post("/api/configs/import", headers=CSRF, json={}).status_code == 400


def test_reserved_names_rejected(client):
    # /api/configs/export и /api/configs/import — статические маршруты:
    # пресет с таким именем нельзя получить через GET
    for name in ("export", "import"):
        r, _ = _create(client, name=name)
        assert r.status_code == 400
        assert "reserved" in r.get_json()["error"]
    body = {"presets": {"export": {"listen": "127.0.0.1:1080", "proxy": "https://h"}}}
    d = client.post("/api/configs/import", headers=CSRF, json=body).get_json()
    assert d["skipped"][0]["reason"] == "reserved name"


# --- upstream probe ----------------------------------------------------------------

def test_upstream_endpoint_variants(app):
    f = app._upstream_endpoint
    assert f("proxy.example.com") == ("proxy.example.com", 443)
    assert f("https://proxy.example.com") == ("proxy.example.com", 443)
    assert f("https://user:p%40ss@h.example:8443/x") == ("h.example", 8443)
    assert f("[::1]:8443") == ("::1", 8443)
    assert f("https://[::1]/") == ("::1", 443)
    assert f("host:port") is None
    assert f("  ") is None


def test_probe_measures_real_tcp(client):
    # живой слушающий сокет на ephemeral-порту — без моков
    import socket as s
    srv = s.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    try:
        r = client.post("/api/probe", headers=CSRF,
                        json={"upstream": f"127.0.0.1:{port}"})
        assert r.status_code == 200
        d = r.get_json()
        assert d["port"] == port and isinstance(d["ms"], int) and d["ms"] >= 0
    finally:
        srv.close()
    # порт закрыт — это нормальный результат проверки, а не ошибка панели
    r = client.post("/api/probe", headers=CSRF, json={"upstream": "127.0.0.1:1"})
    d = r.get_json()
    assert r.status_code == 200 and "error" in d


def test_probe_requires_upstream(client):
    assert client.post("/api/probe", headers=CSRF, json={}).status_code == 400


def test_serve_prefers_waitress(app, monkeypatch):
    calls = {}
    fake = types.SimpleNamespace(serve=lambda application, **kw: calls.update(kw))
    monkeypatch.setitem(sys.modules, "waitress", fake)
    app._serve(app.app, "127.0.0.1", 8089)
    assert calls["host"] == "127.0.0.1" and calls["port"] == 8089
    assert calls["threads"] == app.WAITRESS_THREADS


def test_serve_falls_back_to_werkzeug(app, monkeypatch):
    monkeypatch.setitem(sys.modules, "waitress", None)  # import waitress → ImportError
    ran = {}
    monkeypatch.setattr(app.app, "run", lambda **kw: ran.update(kw))
    app._serve(app.app, "127.0.0.1", 8089)
    assert ran.get("threaded") is True


def test_invalid_threads_env_falls_back_to_default(env, monkeypatch):
    monkeypatch.setenv("NAIVEPANEL_THREADS", "abc")
    m = _reload()
    assert m.WAITRESS_THREADS == 4
