"""Unit-тесты NaivePanel: API-семантика через Flask test client, без сети.

Пути подменяются через env ДО импорта модуля — константы считываются при
import, поэтому фикстура делает importlib.reload на каждый тест.
"""
import base64
import importlib
import json
import os
import sys
import time
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


def test_wrong_password_is_slowed_and_rejected(client, env):
    bcrypt = pytest.importorskip("bcrypt")
    h = bcrypt.hashpw(b"s3cret", bcrypt.gensalt()).decode()
    (env / "admin.pass").write_text(f"admin:{h}\n")
    token = base64.b64encode(b"admin:wrong").decode()
    r = client.get("/api/status", headers={"Authorization": f"Basic {token}"})
    assert r.status_code == 401


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
