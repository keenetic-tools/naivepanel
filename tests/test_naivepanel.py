"""Unit-тесты NaivePanel: API-семантика через Flask test client, без сети.

Пути подменяются через env ДО импорта модуля — константы считываются при
import, поэтому фикстура делает importlib.reload на каждый тест.
"""
import base64
import importlib
import json
import sys
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
    # на диске URI собран целиком, спецсимволы пароля не портятся
    stored = json.loads((app.CONF_D / "home.json").read_text())
    assert stored["proxy"] == "https://user:p@ss:word@proxy.example.com"


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
    assert stored["proxy"] == "https://user:p@ss:word@other.example.com"


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
    assert stored["proxy"] == "https://user:p@ss:word@proxy.example.com"


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
