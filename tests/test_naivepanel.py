"""Unit-тесты NaivePanel: API-семантика через Flask test client, без сети.

Пути подменяются через env ДО импорта модуля — константы считываются при
import, поэтому фикстура делает importlib.reload на каждый тест.
"""
import base64
import importlib
import json
import os
import re
import shutil
import subprocess
import sys
import threading
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
    monkeypatch.setenv("NAIVEPANEL_LOG", str(tmp_path / "naivepanel.log"))
    monkeypatch.setenv("NAIVEPROXY_PID", str(tmp_path / "naiveproxy.pid"))
    # self-update пишет в каталог панели и свой лог — только в tmp
    monkeypatch.setenv("NAIVEPANEL_DIR", str(tmp_path / "panel"))
    monkeypatch.setenv("NAIVEPANEL_UPDATE_LOG", str(tmp_path / "update.log"))
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


def test_conf_file_applies_bind_and_hosts(conf_env, env):
    # LAN-bind без пароля с v0.17.2 fail-closed (SEC-01), поэтому Host-
    # allowlist проверяем при включённом auth — иначе первый же 403 был бы
    # неоднозначен (host? экспозиция?)
    bcrypt = pytest.importorskip("bcrypt")
    h = bcrypt.hashpw(b"s3cret", bcrypt.gensalt()).decode()
    (env / "admin.pass").write_text(f"admin:{h}\n")
    auth = {"Authorization": "Basic " + base64.b64encode(b"admin:s3cret").decode()}
    conf_env.write_text(
        'NAIVEPANEL_BIND="192.168.1.1:8099"\n'
        'NAIVEPANEL_HOSTS="np.lan:8099,192.168.1.1:8099"\n'
    )
    m = _reload()
    assert m.PANEL_BIND == "192.168.1.1:8099"
    assert "np.lan:8099" in m.ALLOWED_HOSTS
    c = m.app.test_client()
    assert c.get("/api/status", headers={"Host": "np.lan:8099", **auth}).status_code == 200
    assert c.get("/api/status", headers={"Host": "evil.com", **auth}).status_code == 403


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


# --- смена пароля из панели ---------------------------------------------------

def _basic(user, pw):
    return {"Authorization": "Basic " + base64.b64encode(
        f"{user}:{pw}".encode()).decode(), **CSRF}


def _pass_file(env, password, user="admin"):
    bcrypt = pytest.importorskip("bcrypt")
    return f"{user}:{bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()}\n"


def test_password_change_invalidates_old_credentials(client, env):
    p = env / "admin.pass"
    p.write_text(_pass_file(env, "oldpass1"))
    r = client.post("/api/password", json={"current": "oldpass1", "new": "newpass1"},
                    headers=_basic("admin", "oldpass1"))
    assert r.status_code == 200
    assert client.get("/api/status", headers=_basic("admin", "oldpass1")).status_code == 401
    assert client.get("/api/status", headers=_basic("admin", "newpass1")).status_code == 200


def test_password_change_rejects_wrong_current(client, env):
    (env / "admin.pass").write_text(_pass_file(env, "oldpass1"))
    r = client.post("/api/password", json={"current": "nope", "new": "newpass1"},
                    headers=_basic("admin", "oldpass1"))
    assert r.status_code == 400
    assert "current" in r.get_json()["error"]
    assert client.get("/api/status", headers=_basic("admin", "oldpass1")).status_code == 200


def test_password_change_rejects_short_new(client, env):
    (env / "admin.pass").write_text(_pass_file(env, "oldpass1"))
    r = client.post("/api/password", json={"current": "oldpass1", "new": "short"},
                    headers=_basic("admin", "oldpass1"))
    assert r.status_code == 400


def test_password_change_rejects_80_byte_new(client, env):
    # bcrypt не принимает пароли длиннее 72 байт (5.x — ValueError, 4.x молча
    # обрезает); отклоняем до записи, файл не трогаем
    p = env / "admin.pass"
    original = _pass_file(env, "oldpass1")
    p.write_text(original)
    r = client.post("/api/password", json={"current": "oldpass1", "new": "x" * 80},
                    headers=_basic("admin", "oldpass1"))
    assert r.status_code == 400
    assert "8–72 bytes" in r.get_json()["error"]
    assert p.read_text() == original


def test_password_change_rejects_non_string_new_object(client, env):
    # str() по объекту дал бы «пароль» из repr и 200 — UI-баг ставил бы
    # непригодные креды молча
    p = env / "admin.pass"
    original = _pass_file(env, "oldpass1")
    p.write_text(original)
    r = client.post("/api/password", json={"current": "oldpass1", "new": {"a": 1}},
                    headers=_basic("admin", "oldpass1"))
    assert r.status_code == 400
    assert p.read_text() == original


def test_password_change_rejects_non_string_new_number(client, env):
    (env / "admin.pass").write_text(_pass_file(env, "oldpass1"))
    r = client.post("/api/password", json={"current": "oldpass1", "new": 12345678},
                    headers=_basic("admin", "oldpass1"))
    assert r.status_code == 400


def test_password_change_rejects_non_string_current(client, env):
    (env / "admin.pass").write_text(_pass_file(env, "oldpass1"))
    r = client.post("/api/password", json={"current": ["oldpass1"], "new": "newpass1"},
                    headers=_basic("admin", "oldpass1"))
    assert r.status_code == 400


def test_password_change_preserves_other_users(client, env, app):
    bcrypt = pytest.importorskip("bcrypt")
    h = bcrypt.hashpw(b"alicepass", bcrypt.gensalt()).decode()
    p = env / "admin.pass"
    p.write_text(f"# keep\nalice:{h}\n" + _pass_file(env, "oldpass1"))
    r = client.post("/api/password", json={"current": "oldpass1", "new": "newpass1"},
                    headers=_basic("admin", "oldpass1"))
    assert r.status_code == 200
    stored = p.read_text()
    assert "# keep" in stored and f"alice:{h}" in stored
    assert client.get("/api/status", headers=_basic("alice", "alicepass")).status_code == 200


def test_password_change_write_failure_keeps_original(client, env, monkeypatch):
    p = env / "admin.pass"
    original = _pass_file(env, "oldpass1")
    p.write_text(original)
    monkeypatch.setattr(os, "replace", lambda *a, **k: (_ for _ in ()).throw(OSError("ro")))
    r = client.post("/api/password", json={"current": "oldpass1", "new": "newpass1"},
                    headers=_basic("admin", "oldpass1"))
    assert r.status_code == 500
    assert p.read_text() == original
    # временный файл не остаётся, тело ошибки — обычный JSON без путей
    assert list(env.glob(".admin.pass.*")) == []
    body = r.get_json()
    assert body == {"error": "cannot write admin.pass",
                    "description": "cannot write admin.pass"}


def test_password_change_without_auth_file(client, env):
    r = client.post("/api/password", json={"current": "x", "new": "newpass1"},
                    headers=CSRF)
    assert r.status_code == 409


def test_status_reports_auth_state(client, env):
    assert client.get("/api/status").get_json()["auth"] == {"enabled": False, "user": None}
    (env / "admin.pass").write_text(_pass_file(env, "s3cret"))
    d = client.get("/api/status", headers=_basic("admin", "s3cret")).get_json()
    assert d["auth"] == {"enabled": True, "user": "admin"}


def test_status_outside_request_context(app, env):
    # _status() зовут фоновые потоки (naive-update/rollback): без запроса
    # request.authorization бросил бы RuntimeError
    d = app._status()
    assert d["auth"] == {"enabled": env.joinpath("admin.pass").exists(), "user": None}
    assert d["auth"]["enabled"] is False


# --- вспомогательные функции ------------------------------------------------

def test_split_proxy(app):
    assert app._split_proxy("https://user:p@ss:word@host.example") == \
        ("host.example", "user", "p@ss:word")
    # все поддерживаемые схемы разбираются одинаково (SEC-02: раньше
    # http/quic возвращались целиком, с паролем внутри)
    assert app._split_proxy("quic://user:secret@host:443") == \
        ("host:443", "user", "secret")
    assert app._split_proxy("http://user:secret@host:8080") == \
        ("host:8080", "user", "secret")
    assert app._split_proxy("QUIC://user:secret@host:443") == \
        ("host:443", "user", "secret")
    # percent-encoded креды декодируются, IPv6-скобки сохраняются
    assert app._split_proxy("quic://user:p%40ss@[2001:db8::1]:443") == \
        ("[2001:db8::1]:443", "user", "p@ss")
    # кредов нет — URI возвращается целиком (такое значение хранится,
    # только если upstream пришёл как полный URL без кредов)
    assert app._split_proxy("https://host.example") == \
        ("https://host.example", "", None)
    assert app._split_proxy("quic://host:443") == \
        ("quic://host:443", "", None)


@pytest.mark.parametrize("scheme", ["https", "http", "quic", "QUIC"])
def test_get_never_returns_full_uri_password(client, scheme):
    # SEC-02: GET одного конфига не отдаёт пароль ни для одной схемы —
    # раньше http/quic уходили целиком; ответ ещё и no-store
    secret = "topsecret"
    r, _ = _create(client,
                   upstream=f"{scheme}://user:{secret}@proxy.example:443",
                   username="", password="")
    assert r.status_code == 201
    r = client.get("/api/configs/home")
    assert r.status_code == 200
    assert secret not in r.get_data(as_text=True)
    assert r.headers["Cache-Control"] == "no-store"
    d = r.get_json()
    assert d["upstream"] == "proxy.example:443"
    assert d["username"] == "user"


def test_for_edit_masks_unparsed_userinfo(app):
    # defense-in-depth: даже нераспознанная схема с кредами не должна
    # покидать _for_edit с userinfo внутри
    out = app._for_edit({"listen": "socks://127.0.0.1:1080",
                         "proxy": "weird://user:pw@host:1"})
    assert "pw" not in out["upstream"]


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


# --- LAN-bind без пароля: fail closed (SEC-01) --------------------------------

# панель без admin.pass, привязанная к не-loopback интерфейсу, не должна
# отвечать ни данными, ни мутациями: configs/export содержат пароли,
# service/panel restart и update меняют систему
_LAN_SENSITIVE = [
    ("get", "/"),
    ("get", "/api/status"),
    ("get", "/api/configs"),
    ("get", "/api/configs/export"),
    ("get", "/api/configs/home"),
    ("post", "/api/configs"),
    ("post", "/api/configs/import"),
    ("post", "/api/service/restart"),
    ("post", "/api/panel/restart"),
    ("post", "/api/password"),
    ("post", "/api/update/apply"),
    ("post", "/api/naive/update"),
]


def test_lan_without_auth_rejects_sensitive_routes(client, app, monkeypatch):
    monkeypatch.setattr(app.cfg, "_bind_is_loopback", lambda: False)
    for method, path in _LAN_SENSITIVE:
        r = getattr(client, method)(path, headers=CSRF, json={})
        assert r.status_code == 403, (method, path, r.status_code)


def test_lan_with_password_allows_requests(client, app, monkeypatch):
    # auth включён → LAN-bind легален, guard не должен переусердствовать
    bcrypt = pytest.importorskip("bcrypt")
    h = bcrypt.hashpw(b"s3cret", bcrypt.gensalt()).decode()
    app.PANEL_ADMIN_PASS.write_text(f"admin:{h}\n", encoding="utf-8")
    monkeypatch.setattr(app.cfg, "_bind_is_loopback", lambda: False)
    token = base64.b64encode(b"admin:s3cret").decode()
    r = client.get("/api/configs", headers={**CSRF, "Authorization": f"Basic {token}"})
    assert r.status_code == 200


def test_loopback_without_password_still_allows_dev_workflow(client, app):
    # дефолтный bind 127.0.0.1 — локальная работа без пароля остаётся легальной
    assert client.get("/api/status").status_code == 200


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


# --- замена строки в htpasswd -------------------------------------------------

def test_htpasswd_replace_keeps_comments_and_other_users(app):
    stored = "# admins\nalice:$2b$oldalice\nadmin:$2b$oldadmin\n"
    updated = app._htpasswd_replace(stored, "admin", "$2b$newadmin")
    assert updated == "# admins\nalice:$2b$oldalice\nadmin:$2b$newadmin\n"


def test_htpasswd_replace_missing_user(app):
    with pytest.raises(LookupError):
        app._htpasswd_replace("admin:$2b$x\n", "bob", "$2b$y")


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


# --- сериализация service-операций (REL-02) -----------------------------------

def _concurrency_probe(app, monkeypatch, rc=0):
    """Заглушка _service: считает одновременные входы (окно 50мс)."""
    guard = threading.Lock()
    state = {"depth": 0, "max": 0, "calls": []}

    def fake(action):
        with guard:
            state["depth"] += 1
            state["max"] = max(state["max"], state["depth"])
            state["calls"].append(action)
        time.sleep(0.05)  # даём второму звонящему шанс войти без лока
        with guard:
            state["depth"] -= 1
        return {"rc": rc}

    monkeypatch.setattr(app, "_service", fake)
    return state


def _run_concurrently(*targets):
    barrier = threading.Barrier(len(targets), timeout=10)
    errors = []

    def wrapped(fn):
        def run():
            try:
                barrier.wait()
                fn()
            except Exception as exc:  # noqa: BLE001 - любой сбой = провал теста
                errors.append(f"{type(exc).__name__}: {exc}")
        return run

    threads = [threading.Thread(target=wrapped(fn)) for fn in targets]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=15)
    assert not any(t.is_alive() for t in threads), "service op thread hung"
    assert errors == []


def test_put_active_and_activate_are_serialized(client, app, env, monkeypatch):
    # PUT активного пресета входил в _service без лока и мог перехлёстнуться
    # с activate другого пресета — оба писали config.json и крутили init
    stub, _ = _stub_init(env)
    app.INIT_SCRIPT = stub
    state = _concurrency_probe(app, monkeypatch)
    _create(client, name="home")
    _create(client, name="backup")
    client.post("/api/configs/home/activate", headers=CSRF)

    def put_home():
        app.app.test_client().put("/api/configs/home", headers=CSRF, json={
            "name": "home", "listen": "127.0.0.1:1081",
            "upstream": "proxy.example.com", "username": "user"})

    def activate_backup():
        app.app.test_client().post("/api/configs/backup/activate", headers=CSRF)

    _run_concurrently(put_home, activate_backup)
    assert state["max"] == 1, "service-операции выполнились параллельно"


def test_service_restart_and_activate_are_serialized(client, app, env, monkeypatch):
    stub, _ = _stub_init(env)
    app.INIT_SCRIPT = stub
    state = _concurrency_probe(app, monkeypatch)
    _create(client, name="home")
    _create(client, name="backup")

    def restart():
        app.app.test_client().post("/api/service/restart", headers=CSRF)

    def activate_backup():
        app.app.test_client().post("/api/configs/backup/activate", headers=CSRF)

    _run_concurrently(restart, activate_backup)
    assert state["max"] == 1, "service-операции выполнились параллельно"


def test_activate_failed_restart_restores_previous(client, app, env, monkeypatch):
    # рестарт с новым конфигом упал → файлы не должны врать, будто конфиг
    # применён: восстанавливаем прежний config.json/.active и пытаемся
    # вернуть сервис на старом конфиге
    stub, _ = _stub_init(env)
    app.INIT_SCRIPT = stub
    _create(client, name="home")
    assert client.post("/api/configs/home/activate", headers=CSRF).status_code == 200
    monkeypatch.setattr(app, "_service", lambda action: {"rc": 3, "stderr": "boom"})
    _create(client, name="backup")
    r = client.post("/api/configs/backup/activate", headers=CSRF)
    assert r.status_code == 200
    restart = r.get_json()["restart"]
    assert restart["rc"] == 3
    assert restart["degraded"] is True
    assert restart["rollback"]["rc"] == 3  # откат тоже не смог — не скрываем
    assert app._active_name() == "home"
    assert json.loads(app.ACTIVE_CONFIG.read_text())["listen"] == \
        "socks://127.0.0.1:1080"  # прежний конфиг возвращён


def test_put_active_failed_restart_restores_previous(client, app, env, monkeypatch):
    stub, _ = _stub_init(env)
    app.INIT_SCRIPT = stub
    _create(client, name="home")
    assert client.post("/api/configs/home/activate", headers=CSRF).status_code == 200
    monkeypatch.setattr(app, "_service", lambda action: {"rc": 3, "stderr": "boom"})
    r = client.put("/api/configs/home", headers=CSRF, json={
        "name": "home", "listen": "127.0.0.1:1082",
        "upstream": "proxy.example.com", "username": "user"})
    assert r.status_code == 200
    restart = r.get_json()["restart"]
    assert restart["rc"] == 3
    assert restart["degraded"] is True
    # сам пресет сохранён (правки юзера не теряем), но активный конфиг — прежний
    assert json.loads((app.CONF_D / "home.json").read_text())["listen"] == \
        "socks://127.0.0.1:1082"
    assert json.loads(app.ACTIVE_CONFIG.read_text())["listen"] == \
        "socks://127.0.0.1:1080"
    assert app._active_name() == "home"


def test_activate_failed_restart_first_activation_cleans_state(client, app, env,
                                                               monkeypatch):
    # до активации ничего не работало → после failed-рестарта не оставляем
    # config.json/.active, указывающих на неприменённый конфиг
    stub, _ = _stub_init(env)
    app.INIT_SCRIPT = stub
    monkeypatch.setattr(app, "_service", lambda action: {"rc": 3, "stderr": "boom"})
    _create(client, name="home")
    r = client.post("/api/configs/home/activate", headers=CSRF)
    assert r.status_code == 200
    assert r.get_json()["restart"]["degraded"] is True
    assert not app.ACTIVE_CONFIG.exists()
    assert app._active_name() is None


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


def test_spawns_do_not_rely_on_dash_c_positionals(client, app, env, monkeypatch):
    """busybox на Keenetic не передаёт позиционные аргументы после
    `sh -c 'строка'` (реальный кейс v0.9.0–v0.9.1: $1..$3 пусты →
    self-update умирал молча на `>>""`). Аргументы ходят через env —
    строки -c не должны содержать $1..$9 ни в одном спавне.
    macOS/bash и Debian/dash этот баг не ловят: расхождение только
    на целевой платформе — потому охраняем регрессией по форме команды.
    """
    captured = []

    class FakeProc:
        pid = 424242

        def wait(self):
            return 0

    def rec(cmd, **kwargs):
        captured.append((cmd, kwargs.get("env")))
        return FakeProc()

    monkeypatch.setattr(app.subprocess, "Popen", rec)
    _apply_stub(env, monkeypatch, app)
    app.PANEL_INIT.parent.mkdir(parents=True, exist_ok=True)
    app.PANEL_INIT.write_text("#!/bin/sh\n")
    assert client.post("/api/update/apply", headers=CSRF).status_code == 202
    assert client.post("/api/panel/restart", headers=CSRF).status_code == 202
    assert len(captured) == 2
    for cmd, cenv in captured:
        script = cmd[cmd.index("-c") + 1]
        assert not re.search(r"\$[0-9@*#]", script), \
            f"позиционные параметры в -c не работают на busybox Keenetic: {cmd}"
        assert cmd[-1] != "sh" or len(cmd) <= 3, \
            f"argv после -c не доходят на busybox Keenetic: {cmd}"
        assert cenv, "аргументы должны передаваться через env"
    envs = {k: v for _, e in captured if e for k, v in e.items()
            if k.startswith("NP_")}
    assert envs.get("NP_STAGE") and envs.get("NP_TAG") and envs.get("NP_LOG")
    assert envs.get("NP_INIT")


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


def test_logs_src_panel_tails_panel_log(client, env):
    (env / "naivepanel.log").write_text(
        "WARNING in naivepanel: rejected Host 'evil.com' from 203.0.113.7\n"
        "WARNING in naivepanel: self-update to v9.9.9 triggered by 192.168.1.5\n",
        encoding="utf-8",
    )
    (env / "naiveproxy.log").write_text("proxy line\n", encoding="utf-8")
    d = client.get("/api/logs?src=panel&lines=10").get_json()
    assert "rejected Host" in d["content"]
    assert "self-update to v9.9.9" in d["content"]
    assert "proxy line" not in d["content"]


def test_logs_src_defaults_and_unknown_to_proxy(client, env):
    (env / "naiveproxy.log").write_text("proxy line\n", encoding="utf-8")
    (env / "naivepanel.log").write_text("panel line\n", encoding="utf-8")
    # без src и с неизвестным src — прокси, а не 500
    assert "proxy line" in client.get("/api/logs").get_json()["content"]
    assert "proxy line" in client.get("/api/logs?src=bogus").get_json()["content"]


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


def test_ui_svc_message_reflects_rc(app):
    # REL-05: svc() показывал «Сервис перезапущен» даже при rc!=0
    html = (APP_DIR / "templates" / "index.html").read_text(encoding="utf-8")
    m = re.search(r"async function svc\(action\) \{.*?\n\}", html, re.S)
    assert m, "svc() не найден в index.html"
    body = m.group(0)
    assert "restartFailed" in body, "svc() обязан проверять rc ответа"
    assert "stderr" in body, "текст ошибки сервиса должен попадать в toast"


def test_ui_naive_update_distinguishes_restart_failure(app):
    # «бинарник заменён» и «рестарт удался» — разные события; UI обязан
    # различать их по restart_rc
    html = (APP_DIR / "templates" / "index.html").read_text(encoding="utf-8")
    assert "restart_rc" in html, "UI не различает failed restart после смены бинарника"


# --- UX: контраст, touch targets, доступность, гонки запросов (Tasks 11–13) ----

def _wcag_contrast(hex_fg: str, hex_bg: str = "ffffff") -> float:
    """Контраст WCAG 2.x по относительной яркости (контракт-тест токена)."""
    def lum(h: str) -> float:
        r, g, b = (int(h[i:i + 2], 16) / 255 for i in (0, 2, 4))
        lin = [c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4
               for c in (r, g, b)]
        return 0.2126 * lin[0] + 0.7152 * lin[1] + 0.0722 * lin[2]
    l1, l2 = sorted((lum(hex_fg), lum(hex_bg)), reverse=True)
    return (l1 + 0.05) / (l2 + 0.05)


def test_light_accent_meets_wcag_aa(app):
    # UX-01: светлый --acc #0e8a5f давал 4.36:1 на белом — текст на бейджах,
    # ссылки, галочки. Токен обязан держать AA для normal text
    html = (APP_DIR / "templates" / "index.html").read_text(encoding="utf-8")
    m = re.search(r'\[data-theme="light"\][^{]*\{[^}]*?--acc:#([0-9a-fA-F]{6})', html)
    assert m, "light --acc не найден"
    assert _wcag_contrast(m.group(1)) >= 4.5, _wcag_contrast(m.group(1))


def test_mobile_touch_targets_and_input_font(app):
    # UX-02: на ≤800px цели ≥44px; поля ≥16px, иначе iOS приближает страницу
    html = (APP_DIR / "templates" / "index.html").read_text(encoding="utf-8")
    blocks = re.findall(r"@media \(max-width:800px\) \{.*?\n  \}", html, re.S)
    assert blocks, "нет мобильного media-блока"
    mobile = "\n".join(blocks)
    assert "min-height:44px" in mobile, "нет touch-целей 44px"
    assert "font-size:16px" in mobile, "нет 16px у полей на mobile"


def test_toast_has_keyboard_close(app):
    # UX-03: toast закрывался только кликом по нему — недоступно с клавиатуры
    html = (APP_DIR / "templates" / "index.html").read_text(encoding="utf-8")
    m = re.search(r"function flash\(msg, ok, ms\) \{.*?\n\}", html, re.S)
    assert m, "flash() не найден"
    body = m.group(0)
    assert "createElement('button')" in body
    assert "Закрыть уведомление" in body


def test_log_focusable_and_labeled(app):
    # UX-03: прокручиваемый лог не получал фокус с клавиатуры
    html = (APP_DIR / "templates" / "index.html").read_text(encoding="utf-8")
    assert re.search(r'<pre class="log" id="log"[^>]*tabindex="0"', html), \
        "главный лог не фокусируется"
    assert re.search(r'<pre class="log" id="log"[^>]*aria-label="', html), \
        "у лога нет доступного имени"


def test_upstream_input_linked_to_hint(app):
    # UX-03: ошибка валидации upstream должна объявляться скринридером
    html = (APP_DIR / "templates" / "index.html").read_text(encoding="utf-8")
    assert 'aria-describedby="upHint"' in html, "f_upstream не связан с подсказкой"
    m = re.search(r"function validateUpstream\(\) \{.*?\n\}", html, re.S)
    assert m and "aria-invalid" in m.group(0), "валидация не ставит aria-invalid"


def test_sparkline_has_text_summary(app):
    # UX-03: спарклайн — только красно-зелёные полоски; текстовая сводка
    # обязана существовать для незрячих
    html = (APP_DIR / "templates" / "index.html").read_text(encoding="utf-8")
    m = re.search(r"function drawSpark\(d\) \{.*?\n\}", html, re.S)
    assert m and "sr-only" in m.group(0), "у спарклайна нет текстового эквивалента"


def test_theme_button_accessible_name_updates(app):
    # UX-03: имя кнопки темы должно отражать целевое состояние
    html = (APP_DIR / "templates" / "index.html").read_text(encoding="utf-8")
    m = re.search(r"function setThemeBtn\(theme\) \{.*?\n\}", html, re.S)
    assert m and "aria-label" in m.group(0), "setThemeBtn не ставит aria-label"
    t = re.search(r"function toggleTheme\(\) \{.*?\n\}", html, re.S)
    assert t and "setThemeBtn" in t.group(0), "toggleTheme не обновляет кнопку"


def test_no_double_escaping_in_textcontent(app):
    # UX-05: escapeHtml перед textContent показывал пользователю &amp; и т.п.
    html = (APP_DIR / "templates" / "index.html").read_text(encoding="utf-8")
    offenders = re.findall(r"textContent[^;\n]*=[^;\n]*escapeHtml\(", html)
    assert not offenders, offenders


def test_select_preset_guards_stale_response(app):
    # UX-05: быстрый выбор A→B — поздний ответ A не должен перезаписывать
    # форму B (out-of-order response)
    html = (APP_DIR / "templates" / "index.html").read_text(encoding="utf-8")
    m = re.search(r"async function selectPreset\(name\) \{.*?\n\}", html, re.S)
    assert m, "selectPreset не найден"
    body = m.group(0)
    assert "selectSeq" in body, "нет монотонного токена выбора"


def test_save_is_reentry_guarded(app):
    # UX-05: повторный Ctrl+S во время активного save не должен создавать
    # второй PUT
    html = (APP_DIR / "templates" / "index.html").read_text(encoding="utf-8")
    m = re.search(r"async function save\(ev\) \{.*?\n  \}", html, re.S)
    assert m, "save() не найден"
    assert "saving" in m.group(0), "нет guard'а от повторного входа"


# --- UX-04/06: информационная архитектура + дизайн-токены (Task 14) ------------

def test_ui_guidelines_doc_pins_structure(app):
    doc = (APP_DIR / "docs" / "UI-GUIDELINES.md").read_text(encoding="utf-8")
    for section in ("Обзор", "Диагностика", "Система", "Настройки"):
        assert section in doc, section
    assert "--sp-4" in doc and "inline-SVG" in doc


def test_design_tokens_defined(app):
    html = (APP_DIR / "templates" / "index.html").read_text(encoding="utf-8")
    for token in ("--sp-4:", "--fs-16:", "--font-mono:", "--r-l:",
                  "--z-toast:", "--focus-ring:", "--status-ok:"):
        assert token in html, token


def test_section_anchors_exist(app):
    html = (APP_DIR / "templates" / "index.html").read_text(encoding="utf-8")
    for anchor in ('id="sec-overview"', 'id="sec-diag"',
                   'id="sec-system"', 'id="sec-settings"'):
        assert anchor in html, anchor


def test_mobile_section_nav(app):
    # табы-якоря четырёх групп: скрыты на desktop, sticky на ≤800px
    html = (APP_DIR / "templates" / "index.html").read_text(encoding="utf-8")
    assert 'id="secNav"' in html
    for href in ("#sec-overview", "#sec-diag", "#sec-system", "#sec-settings"):
        assert f'href="{href}"' in html, href
    assert re.search(r"#secNav \{[^}]*display:none", html), "нет базового скрытия"
    mobile = re.findall(r"@media \(max-width:800px\) \{.*?\n  \}", html, re.S)
    assert mobile and any("#secNav" in b and "display:flex" in b for b in mobile), \
        "mobile-блок не показывает #secNav"


def test_icons_are_inline_svg_set(app):
    html = (APP_DIR / "templates" / "index.html").read_text(encoding="utf-8")
    assert 'class="ic"' in html, "нет статических inline-SVG"
    m = re.search(r"const IC = \{.*?\};", html, re.S)
    assert m and m.group(0).count("<svg") >= 6, "нет SVG-набора иконок (нужно ≥6)"
    for glyph in ("⧉", "⛓"):
        assert glyph not in html, f"Unicode-глиф {glyph} остался"


def test_theme_button_uses_icon_set(app):
    html = (APP_DIR / "templates" / "index.html").read_text(encoding="utf-8")
    m = re.search(r"function setThemeBtn\(theme\) \{.*?\n\}", html, re.S)
    assert m and "IC." in m.group(0), "setThemeBtn не использует SVG-набор"


def test_editor_state_chip(app):
    # UX-04: редактор различает «активен» / «изменено» / «сохранено»
    html = (APP_DIR / "templates" / "index.html").read_text(encoding="utf-8")
    assert 'id="editorState"' in html, "нет чипа состояния редактора"
    m = re.search(r"function setEditorState\(\w*\) \{.*?\n\}", html, re.S)
    assert m, "нет setEditorState()"
    body = m.group(0)
    for state in ("активен", "изменено", "сохранено"):
        assert state in body or state in html, state


def test_ops_card_renamed_to_system(app):
    html = (APP_DIR / "templates" / "index.html").read_text(encoding="utf-8")
    assert "<h2>Система</h2>" in html, "ops-карточка не названа «Система»"
    assert "<h2>Обслуживание</h2>" not in html, "старый заголовок остался"


def test_ui_scripts_parse(app, tmp_path):
    # регрессия Task 14: битая JS-строка рендера валилась только в браузере
    # (Invalid token) — статические тесты этого класса не ловят
    node = shutil.which("node")
    if not node:
        pytest.skip("node недоступен — JS-синтаксис не проверить")
    html = (APP_DIR / "templates" / "index.html").read_text(encoding="utf-8")
    blocks = re.findall(r"<script[^>]*>(.*?)</script>", html, re.S)
    assert blocks, "script-блоки не найдены"
    for n, block in enumerate(blocks):
        js = tmp_path / f"ui{n}.js"
        js.write_text(block, encoding="utf-8")
        r = subprocess.run([node, "--check", str(js)], capture_output=True, text=True)
        assert r.returncode == 0, f"script #{n} не парсится:\n{r.stderr}"


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


def test_ui_editor_closable_by_button_and_esc(app):
    # Редактор закрывается ✕ в заголовке и по Esc; Esc проверяет видимость
    # формы, а не current — работает и в режиме нового пресета (current === null)
    html = (APP_DIR / "templates" / "index.html").read_text(encoding="utf-8")
    for marker in ('data-action="closeEditor"', 'id="btnCloseEditor"',
                   'id="editorTitleText"', 'closeEditor: () => closeEditor(),',
                   "if ($('editor').style.display !== 'none'"):
        assert marker in html, marker
    assert "&& current &&" not in html  # Esc не привязан к выбранному пресету


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


# --- listen-валидация на write-путях (REL-04) ---------------------------------

@pytest.mark.parametrize("listen", [
    "file:///tmp/socket",             # схема вне socks/socks5/http
    "quic://127.0.0.1:1080",          # quic — схема upstream, не listen
    "socks://:1080",                  # пустой host
    "socks://127.0.0.1:0",            # порт 0
    "socks://127.0.0.1:65536",        # порт за пределами диапазона
    "http://user:pw@127.0.0.1:8080",  # userinfo в listen не имеет смысла
    "http://127.0.0.1:8080/path?q=1", # path/query в listen
    "socks://host:notaport",          # порт не число
    "socks://",                       # нет адреса после схемы
])
def test_create_rejects_invalid_listen(client, app, listen):
    r, _ = _create(client, listen=listen)
    assert r.status_code == 400, listen
    assert "listen" in r.get_json()["error"]
    assert not (app.CONF_D / "home.json").exists()  # ничего не сохранили


@pytest.mark.parametrize("listen", [
    "127.0.0.1:1080",             # голый host:port → нормализуется в socks://
    "socks://127.0.0.1:1080",
    "socks5://127.0.0.1:1080",
    "http://127.0.0.1:8080",
    "socks://[::1]:1080",
    "socks://127.0.0.1",          # порт не указан — умолчание бинарника 1080
])
def test_create_accepts_supported_listen(client, listen):
    r, _ = _create(client, listen=listen)
    assert r.status_code == 201, listen


def test_activate_and_import_reject_invalid_listen(client, app):
    # битой listen не пройти ни через активацию, ни через импорт
    app._ensure_dirs()
    (app.CONF_D / "badlisten.json").write_text(
        '{"listen": "file:///tmp/x", "proxy": "https://h"}')
    assert client.post("/api/configs/badlisten/activate",
                       headers=CSRF).status_code == 400
    body = {"presets": {
        "x": {"listen": "quic://1.2.3.4:1080", "proxy": "https://h"},
        "good": {"listen": "127.0.0.1:1080", "proxy": "https://h"},
    }}
    d = client.post("/api/configs/import", headers=CSRF, json=body).get_json()
    assert d["imported"] == ["good"]
    reasons = {s["name"]: s["reason"] for s in d["skipped"]}
    assert "listen" in reasons["x"]


def test_validate_cfg_listen_list_entries(app):
    good = {"listen": ["socks://127.0.0.1:1080", "http://127.0.0.1:8080"],
            "proxy": "https://h"}
    app._validate_cfg(good, "ok")
    with pytest.raises(Exception):
        app._validate_cfg(
            {**good, "listen": ["socks://127.0.0.1:1080", "file:///x"]}, "bad")


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


def test_export_includes_failover(client):
    _create(client, name="home")
    client.put("/api/failover", headers=CSRF,
               json={"enabled": True, "chain": ["home"], "auto_return": False})
    d = client.get("/api/configs/export").get_json()
    assert d["failover"] == {"enabled": True, "chain": ["home"],
                             "auto_return": False}


def test_export_chain_references_only_exported_presets(client, app):
    _create(client, name="home")
    # нечитаемый пресет пропускается экспортом, значит и из цепочки выпадает
    (app.CONF_D / "bad.json").write_text("{not json")
    app.FAILOVER_CONF.write_text(json.dumps(
        {"enabled": True, "chain": ["home", "bad"], "auto_return": True}))
    d = client.get("/api/configs/export").get_json()
    assert set(d["presets"]) == {"home"}
    assert d["failover"] == {"enabled": True, "chain": ["home"],
                             "auto_return": True}


def test_import_applies_failover_to_empty_chain(client):
    payload = {"format": 1,
               "presets": {"home": {"listen": "127.0.0.1:1080",
                                    "proxy": "https://u:p@example.com"}},
               "failover": {"enabled": True, "chain": ["home"],
                            "auto_return": False}}
    r = client.post("/api/configs/import", json=payload, headers=CSRF)
    assert r.status_code == 200 and r.get_json()["failover"]["applied"] is True
    assert client.get("/api/failover").get_json()["chain"] == ["home"]


def test_import_does_not_replace_existing_chain(client):
    _create(client, name="home")
    client.put("/api/failover", headers=CSRF,
               json={"enabled": True, "chain": ["home"]})
    payload = {"presets": {"backup": {"listen": "127.0.0.1:1081",
                                      "proxy": "https://u:p@example.org"}},
               "failover": {"enabled": True, "chain": ["backup"]}}
    d = client.post("/api/configs/import", json=payload, headers=CSRF).get_json()
    assert d["failover"]["applied"] is False
    assert client.get("/api/failover").get_json()["chain"] == ["home"]
    # блокирующая причина — существующая цепочка, а не разбор входящей
    bad = {"presets": {"home": {"listen": "127.0.0.1:1080",
                                "proxy": "https://u:p@example.com"}},
           "failover": {"enabled": True, "chain": ["ghost"]}}
    d = client.post("/api/configs/import", json=bad, headers=CSRF).get_json()
    assert d["failover"]["applied"] is False
    assert d["failover"]["reason"] == "target already has a failover chain"
    assert client.get("/api/failover").get_json()["chain"] == ["home"]


def test_import_does_not_replace_disabled_nonempty_chain(client):
    _create(client, name="home")
    client.put("/api/failover", headers=CSRF,
               json={"enabled": False, "chain": ["home"]})
    payload = {"presets": {"backup": {"listen": "127.0.0.1:1081",
                                      "proxy": "https://u:p@example.org"}},
               "failover": {"enabled": True, "chain": ["backup"]}}
    d = client.post("/api/configs/import", json=payload, headers=CSRF).get_json()
    assert d["failover"]["applied"] is False
    assert client.get("/api/failover").get_json()["chain"] == ["home"]


def test_import_without_failover_block_is_a_noop(client, app):
    payload = {"presets": {"home": {"listen": "127.0.0.1:1080",
                                    "proxy": "https://u:p@example.com"}}}
    d = client.post("/api/configs/import", json=payload, headers=CSRF).get_json()
    assert d["failover"] == {"applied": False, "reason": "no failover block"}
    assert not app.FAILOVER_CONF.exists()


def test_import_empty_failover_block_does_not_write(client, app):
    payload = {"presets": {"home": {"listen": "127.0.0.1:1080",
                                    "proxy": "https://u:p@example.com"}},
               "failover": {"enabled": False, "chain": []}}
    d = client.post("/api/configs/import", json=payload, headers=CSRF).get_json()
    assert d["failover"] == {"applied": False,
                             "reason": "empty failover block"}
    assert not app.FAILOVER_CONF.exists()


def test_import_rejects_non_bool_enabled(client):
    payload = {"presets": {"home": {"listen": "127.0.0.1:1080",
                                    "proxy": "https://u:p@example.com"}},
               "failover": {"enabled": "false", "chain": ["home"]}}
    d = client.post("/api/configs/import", json=payload, headers=CSRF).get_json()
    assert d["failover"]["applied"] is False
    assert "boolean" in d["failover"]["reason"]


def test_import_rejects_non_bool_auto_return(client):
    payload = {"presets": {"home": {"listen": "127.0.0.1:1080",
                                    "proxy": "https://u:p@example.com"}},
               "failover": {"enabled": True, "chain": ["home"],
                            "auto_return": "yes"}}
    d = client.post("/api/configs/import", json=payload, headers=CSRF).get_json()
    assert d["failover"] == {"applied": False,
                             "reason": "auto_return must be boolean"}


def test_import_rejects_auto_return_without_enabled(client, app):
    # зеркало PUT: авто-возврат без включённой цепочки — явная ошибка, а не
    # молчаливое понижение в auto_return:false
    payload = {"presets": {"home": {"listen": "127.0.0.1:1080",
                                    "proxy": "https://u:p@example.com"}},
               "failover": {"enabled": False, "chain": ["home"],
                            "auto_return": True}}
    d = client.post("/api/configs/import", json=payload, headers=CSRF).get_json()
    assert d["failover"] == {"applied": False,
                             "reason": "auto_return requires enabled chain"}
    assert not app.FAILOVER_CONF.exists()


def test_import_skips_failover_with_missing_names(client):
    payload = {"presets": {"home": {"listen": "127.0.0.1:1080",
                                    "proxy": "https://u:p@example.com"}},
               "failover": {"enabled": True, "chain": ["home", "ghost"]}}
    d = client.post("/api/configs/import", json=payload, headers=CSRF).get_json()
    assert d["failover"]["applied"] is False
    assert "ghost" in d["failover"]["reason"]


def test_import_skips_failover_with_duplicate_names(client):
    payload = {"presets": {"home": {"listen": "127.0.0.1:1080",
                                    "proxy": "https://u:p@example.com"}},
               "failover": {"enabled": True, "chain": ["home", "home"]}}
    d = client.post("/api/configs/import", json=payload, headers=CSRF).get_json()
    assert d["failover"]["applied"] is False
    assert "duplicates" in d["failover"]["reason"]
    assert client.get("/api/failover").get_json()["chain"] == []


def test_import_skips_failover_chain_too_long(client, app):
    names = [f"p{i}" for i in range(app.FAILOVER_CHAIN_MAX + 1)]
    presets = {n: {"listen": f"127.0.0.1:{1080 + i}",
                   "proxy": f"https://u:p@h{i}.example"}
               for i, n in enumerate(names)}
    payload = {"presets": presets,
               "failover": {"enabled": True, "chain": names}}
    d = client.post("/api/configs/import", json=payload, headers=CSRF).get_json()
    assert d["failover"]["applied"] is False
    assert "too long" in d["failover"]["reason"]


def test_import_rejects_non_object_failover(client):
    payload = {"presets": {"home": {"listen": "127.0.0.1:1080",
                                    "proxy": "https://u:p@example.com"}},
               "failover": ["home"]}
    d = client.post("/api/configs/import", json=payload, headers=CSRF).get_json()
    assert d["failover"]["applied"] is False
    assert "expected object" in d["failover"]["reason"]


def test_import_rejects_traversal_name_in_failover(client, app):
    payload = {"presets": {"home": {"listen": "127.0.0.1:1080",
                                    "proxy": "https://u:p@example.com"}},
               "failover": {"enabled": True, "chain": ["../etc/passwd"]}}
    d = client.post("/api/configs/import", json=payload, headers=CSRF).get_json()
    assert d["failover"]["applied"] is False
    assert client.get("/api/failover").get_json()["chain"] == []
    assert not app.FAILOVER_CONF.exists()


def test_import_rechecks_presets_inside_lock(client, app, monkeypatch):
    _create(client, name="home")
    real_load = app._load_failover_conf
    calls = {"n": 0}

    def load_and_vanish():
        calls["n"] += 1
        if calls["n"] == 2:  # второй вызов — уже под локом, перед re-glob
            (app.CONF_D / "home.json").unlink()
        return real_load()

    monkeypatch.setattr(app, "_load_failover_conf", load_and_vanish)
    payload = {"presets": {}, "failover": {"enabled": True, "chain": ["home"]}}
    d = client.post("/api/configs/import", json=payload, headers=CSRF).get_json()
    assert d["failover"]["applied"] is False
    assert "unknown presets: home" in d["failover"]["reason"]
    assert not app.FAILOVER_CONF.exists()


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


# --- self-update: сравнение версий и резолв тега ------------------------------

def test_ver_key_compares_numerically(app):
    assert app._ver_key("0.10.0") > app._ver_key("0.9.0")   # строкой было бы <
    assert app._ver_key("v0.6.1") == app._ver_key("0.6.1") == (0, 6, 1)
    assert app._ver_key("0.6") < app._ver_key("0.6.1")      # недостающие = 0
    assert app._ver_key("") == (0,)


def _github(monkeypatch, app, release=None, tags=()):
    """Подменяем сетевой слой: релиз и/или теги, как их отдаёт GitHub API."""
    def fake_get(url, timeout=6.0):
        if "/releases/latest" in url:
            if release is None:
                raise RuntimeError("404 no releases")
            return json.dumps(release)
        if "/tags" in url:
            return json.dumps([{"name": t} for t in tags])
        raise AssertionError(f"unexpected url: {url}")
    monkeypatch.setattr(app, "_http_get", fake_get)


def test_latest_release_prefers_newer_tag_over_release(app, monkeypatch):
    # реальный кейс репозитория: релиз-нота v0.6.0, но тег v0.6.1 уже существует
    _github(monkeypatch, app,
            release={"tag_name": "v0.6.0", "body": "notes", "html_url": "u"},
            tags=["v0.6.1", "v0.6.0"])
    rel = app._latest_release()
    assert rel["tag"] == "v0.6.1"
    assert rel["notes"] == ""  # у «голого» тега описания нет


def test_latest_release_keeps_notes_when_release_is_newest(app, monkeypatch):
    _github(monkeypatch, app,
            release={"tag_name": "v0.7.0", "body": "changelog", "html_url": "url"},
            tags=["v0.7.0", "v0.6.1"])
    rel = app._latest_release()
    assert rel["tag"] == "v0.7.0" and rel["notes"] == "changelog"


def test_latest_release_without_releases_uses_tags(app, monkeypatch):
    _github(monkeypatch, app, tags=["v0.5.1", "v0.6.1"])
    assert app._latest_release()["tag"] == "v0.6.1"


def test_latest_release_ignores_non_semver_tags(app, monkeypatch):
    # main/experimental-теги не должны предлагаться как «обновление»
    _github(monkeypatch, app, tags=["main", "v0.6.1-x", "nightly"])
    with pytest.raises(RuntimeError):
        app._latest_release()


def test_latest_release_no_network_raises(app, monkeypatch):
    def dead(url, timeout=6.0):
        raise RuntimeError("timeout")
    monkeypatch.setattr(app, "_http_get", dead)
    with pytest.raises(RuntimeError):
        app._latest_release()


def test_http_get_reports_missing_tools(app, monkeypatch):
    def no_tools(cmd, **kw):
        raise FileNotFoundError(cmd[0])
    monkeypatch.setattr(app.subprocess, "run", no_tools)
    with pytest.raises(RuntimeError) as ei:
        app._http_get("https://example.invalid/x")
    assert "not found" in str(ei.value)


# --- self-update: /api/update/check ---------------------------------------------

def test_check_reports_available_update(client, app, monkeypatch):
    monkeypatch.setattr(app, "_latest_release",
                        lambda: {"tag": "v9.9.9", "notes": "big release",
                                 "url": "https://x"})
    d = client.get("/api/update/check").get_json()
    assert d["available"] is True
    assert d["current"] == app.APP_VERSION and d["latest"] == "9.9.9"
    assert d["notes"] == "big release"


def test_check_cache_and_force(client, app, monkeypatch):
    calls = {"n": 0}
    def latest():
        calls["n"] += 1
        return {"tag": "v9.9.9", "notes": "", "url": ""}
    monkeypatch.setattr(app, "_latest_release", latest)
    assert client.get("/api/update/check").get_json().get("cached") is None
    d = client.get("/api/update/check").get_json()
    assert d["cached"] is True          # второй вызов — из кэша, без сети
    assert calls["n"] == 1
    d = client.get("/api/update/check?force=1").get_json()
    assert d.get("cached") is None and calls["n"] == 2


def test_check_failsoft_on_network_error(client, app, monkeypatch):
    def dead():
        raise RuntimeError("GitHub unreachable")
    monkeypatch.setattr(app, "_latest_release", dead)
    r = client.get("/api/update/check")
    assert r.status_code == 200         # недоступный GitHub — не ошибка панели
    d = r.get_json()
    assert d["available"] is False and d["latest"] is None and d["error"]
    # ошибки тоже кэшируются (коротким TTL), чтобы не долбить сеть
    assert client.get("/api/update/check").get_json()["cached"] is True


def test_check_same_version_is_not_available(client, app, monkeypatch):
    monkeypatch.setattr(app, "_latest_release",
                        lambda: {"tag": "v" + app.APP_VERSION, "notes": "", "url": ""})
    assert client.get("/api/update/check").get_json()["available"] is False


# --- self-update: /api/update/apply ----------------------------------------------

def _apply_stub(env, monkeypatch, app, tag="v9.9.9"):
    """Каталог панели с файлами + подменные _latest_release/install.sh."""
    panel = env / "panel"
    (panel / "templates").mkdir(parents=True, exist_ok=True)
    (panel / "naivepanel.py").write_text("# old panel code")
    marker = env / "update-ran.txt"
    monkeypatch.setattr(app, "_latest_release",
                        lambda: {"tag": tag, "notes": "", "url": ""})
    def fake_install(url, timeout=6.0):
        assert f"{tag}/install.sh" in url, f"install.sh должен качаться с тега: {url}"
        return f'#!/bin/sh\necho "ran $*" >> "{marker}"\n'
    monkeypatch.setattr(app, "_http_get", fake_install)
    return marker


def test_apply_spawns_installer_and_backs_up(client, app, env, monkeypatch):
    marker = _apply_stub(env, monkeypatch, app)
    r = client.post("/api/update/apply", headers=CSRF)
    assert r.status_code == 202
    body = r.get_json()
    assert body["target"] == "v9.9.9" and body["current"] == app.APP_VERSION
    # бэкап заменяемых файлов создан до запуска установщика
    backup = app.PANEL_DIR / "backup" / f"v{app.APP_VERSION}"
    assert (backup / "naivepanel.py").read_text() == "# old panel code"
    # state зафиксировал «running» с целью
    st = json.loads(app.UPDATE_STATE.read_text())
    assert st["phase"] == "running" and st["target"] == "v9.9.9"
    # пролог панелью: даже умерший до первой строки установщик оставит след
    assert app.UPDATE_LOG.read_text().startswith("== self-update")
    for _ in range(50):  # установщик spawn'ится отсоединённо — ждём маркер
        if marker.exists():
            break
        time.sleep(0.1)
    assert "--yes --from-update --ref v9.9.9" in marker.read_text()
    for _ in range(50):  # обёртка дожидается и дописывает exit-код в лог
        if "installer exit code" in app.UPDATE_LOG.read_text():
            break
        time.sleep(0.1)
    assert "installer exit code: 0" in app.UPDATE_LOG.read_text()


def test_apply_concurrent_returns_409(client, app, env, monkeypatch):
    _apply_stub(env, monkeypatch, app)
    # state «running» с ЖИВЫМ установщиком (свой pid в его роли): цель
    # v9.9.9 ≠ текущая версия — сам не закроется
    app._update_state_write({"phase": "running", "target": "v9.9.9",
                             "started": time.time(), "pid": os.getpid()})
    r = client.post("/api/update/apply", headers=CSRF)
    assert r.status_code == 409
    assert "in progress" in r.get_json()["error"]


def _dead_pid():
    """pid завершившегося процесса — гарантированно мёртвый."""
    proc = subprocess.Popen([sys.executable, "-c", "pass"])
    proc.wait()
    return proc.pid


def test_apply_retry_allowed_after_installer_dies(client, app, env, monkeypatch):
    _apply_stub(env, monkeypatch, app)
    # установщик умер, не обновив панель: retry разрешён сразу, без 15 минут
    app._update_state_write({"phase": "running", "target": "v9.9.9",
                             "started": time.time(), "pid": _dead_pid()})
    assert client.post("/api/update/apply", headers=CSRF).status_code == 202


def test_apply_spawn_failure_is_visible_and_leaves_no_state(client, app, env, monkeypatch):
    _apply_stub(env, monkeypatch, app)

    def boom(*args, **kwargs):
        raise OSError(12, "Cannot allocate memory")

    monkeypatch.setattr(app.subprocess, "Popen", boom)
    r = client.post("/api/update/apply", headers=CSRF)
    assert r.status_code == 500
    assert "cannot spawn installer" in r.get_json()["error"]
    # state не висит «running» без процесса (ловушка v0.7.0): с REL-03
    # фейл фиксируется явно — failed с причиной, а не пустотой
    st = json.loads(app.UPDATE_STATE.read_text())
    assert st["phase"] == "failed"
    assert "cannot spawn installer" in st["error"]


def test_apply_wrapper_records_installer_exit_code(client, app, env, monkeypatch):
    # тихая смерть установщика (OOM при exec, кейс v0.9.0) оставляла пустой
    # лог — обёртка спавна обязана дописать exit-код даже при ненулевом rc
    _apply_stub(env, monkeypatch, app)

    def failing_install(url, timeout=6.0):
        return '#!/bin/sh\nexit 3\n'

    monkeypatch.setattr(app, "_http_get", failing_install)
    r = client.post("/api/update/apply", headers=CSRF)
    assert r.status_code == 202
    for _ in range(50):
        log = app.UPDATE_LOG.read_text()
        if "installer exit code" in log:
            break
        time.sleep(0.1)
    assert "installer exit code: 3" in app.UPDATE_LOG.read_text()


def test_apply_refuses_exposed_panel_without_password(client, app, monkeypatch):
    app.cfg.PANEL_BIND = "192.168.1.1:8089"  # admin.pass не существует (fixture)
    monkeypatch.setattr(app, "_latest_release",
                        lambda: {"tag": "v9.9.9", "notes": "", "url": ""})
    r = client.post("/api/update/apply", headers=CSRF)
    assert r.status_code == 403
    assert "password" in r.get_json()["error"]


def test_apply_with_password_allowed_on_lan_bind(client, app, env, monkeypatch):
    bcrypt = pytest.importorskip("bcrypt")
    h = bcrypt.hashpw(b"s3cret", bcrypt.gensalt()).decode()
    app.PANEL_ADMIN_PASS.write_text(f"admin:{h}\n", encoding="utf-8")
    app.cfg.PANEL_BIND = "192.168.1.1:8089"  # не loopback, но auth включён — можно
    _apply_stub(env, monkeypatch, app)
    token = base64.b64encode(b"admin:s3cret").decode()
    r = client.post("/api/update/apply", headers={**CSRF, "Authorization": f"Basic {token}"})
    assert r.status_code == 202


def test_apply_502_when_release_unreachable(client, app, monkeypatch):
    def dead():
        raise RuntimeError("GitHub unreachable")
    monkeypatch.setattr(app, "_latest_release", dead)
    assert client.post("/api/update/apply", headers=CSRF).status_code == 502


def test_apply_502_when_install_sh_fails(client, app, env, monkeypatch):
    monkeypatch.setattr(app, "_latest_release",
                        lambda: {"tag": "v9.9.9", "notes": "", "url": ""})
    def no_install(url, timeout=6.0):
        if url.endswith("/install.sh"):
            raise RuntimeError("404")
        raise AssertionError(url)
    monkeypatch.setattr(app, "_http_get", no_install)
    assert client.post("/api/update/apply", headers=CSRF).status_code == 502


# --- сериализация запуска update workers (REL-03) ------------------------------

def test_apply_concurrent_single_installer(client, app, env, monkeypatch):
    # резолв релиза и скачивание install.sh длятся секунды: оба запроса
    # проходят гейт state до того, как первый запишет «running», → два
    # установщика. Замедляем сетевую фазу и сталкиваем запросы барьером.
    panel = env / "panel"
    (panel / "templates").mkdir(parents=True, exist_ok=True)
    (panel / "naivepanel.py").write_text("# old panel code")
    monkeypatch.setattr(app, "_latest_release",
                        lambda: {"tag": "v9.9.9", "notes": "", "url": ""})

    def slow_install(url, timeout=6.0):
        time.sleep(0.15)  # окно гонки: оба запроса в сети одновременно
        return "#!/bin/sh\nexit 0\n"

    monkeypatch.setattr(app, "_http_get", slow_install)
    popens = []

    class _Proc:
        pid = os.getpid()  # живой: reconciler не должен закрыть «running»

    def fake_popen(*a, **k):
        popens.append(1)
        return _Proc()

    monkeypatch.setattr(app.subprocess, "Popen", fake_popen)
    statuses = []

    def apply():
        c = app.app.test_client()
        statuses.append(c.post("/api/update/apply", headers=CSRF).status_code)

    _run_concurrently(apply, apply)
    assert statuses.count(202) == 1, statuses
    assert statuses.count(409) == 1, statuses
    assert len(popens) == 1


def test_naive_update_concurrent_single_worker(client, app, monkeypatch):
    def slow_release():
        time.sleep(0.15)  # окно гонки: оба запроса в резолве одновременно
        return {"tag": "v123.0.0", "assets": []}

    monkeypatch.setattr(app, "_naive_release", slow_release)
    workers = []
    monkeypatch.setattr(app, "_naive_update_worker",
                        lambda: workers.append(1))
    statuses = []

    def upd():
        c = app.app.test_client()
        statuses.append(c.post("/api/naive/update", headers=CSRF).status_code)

    _run_concurrently(upd, upd)
    assert statuses.count(202) == 1, statuses
    assert statuses.count(409) == 1, statuses
    assert len(workers) == 1


def _state_partial_read_case(app, write, read, first):
    write(first)
    stop = threading.Event()
    empty_reads = []

    def reader():
        while not stop.is_set():
            if read() == {}:
                empty_reads.append(True)
                return

    t = threading.Thread(target=reader)
    t.start()
    for i in range(400):
        write({"phase": "running", "i": i, "pad": "x" * 512})
    stop.set()
    t.join(timeout=5)
    assert not t.is_alive(), "state reader hung"
    assert empty_reads == [], "читатель увидел пустой/частичный state"


def test_update_state_concurrent_reads_never_see_partial(app):
    # write_text (truncate → write) оставлял читателю пустой файл; ридер
    # возвращал {} — панель сочла бы апдейт завершённым и запустила второй
    _state_partial_read_case(app, app._update_state_write,
                             app._update_state_read,
                             {"phase": "running", "i": 0})


def test_naive_state_concurrent_reads_never_see_partial(app):
    _state_partial_read_case(app, app._naive_state_write,
                             app._naive_state_read,
                             {"phase": "running", "i": 0})


# --- self-update: state и лог ------------------------------------------------------

def test_update_state_reconciles_after_restart(app):
    app._update_state_write({"phase": "running", "target": "v" + app.APP_VERSION,
                             "started": time.time() - 60})
    st = app._update_state()
    assert st["phase"] == "done"  # новый процесс видит себя равным цели
    assert json.loads(app.UPDATE_STATE.read_text())["phase"] == "done"


def test_update_state_marks_stale(app):
    old = time.time() - app._UPDATE_STALE_S - 1
    # живой (по pid) установщик без прогресса дольше 15 минут → stale
    app._update_state_write({"phase": "running", "target": "v0.0.1",
                             "started": old, "pid": os.getpid()})
    st = app._update_state()
    assert st.get("stale") is True  # зависший апдейт больше не блокирует apply


def test_update_state_marks_failed_when_installer_dead(app):
    app._update_state_write({"phase": "running", "target": "v0.0.1",
                             "started": time.time(), "pid": _dead_pid()})
    st = app._update_state()
    assert st["phase"] == "failed"
    assert json.loads(app.UPDATE_STATE.read_text())["phase"] == "failed"


def test_bind_is_loopback_variants(app):
    assert app._bind_is_loopback() is True            # дефолт 127.0.0.1:8089
    for bind in ("localhost:8089", "[::1]:8089", "127.0.0.1:8089"):
        app.cfg.PANEL_BIND = bind
        assert app._bind_is_loopback() is True, bind
    for bind in ("0.0.0.0:8089", "192.168.1.1:8089"):
        app.cfg.PANEL_BIND = bind
        assert app._bind_is_loopback() is False, bind


def test_update_log_tails_and_is_no_store(client, app, env):
    app.UPDATE_LOG.write_text("".join(f"u{i}\n" for i in range(50)),
                              encoding="utf-8")
    app.PANEL_LOG.write_text(
        "WARNING in naivepanel: self-update to v9.9.9 triggered by 192.168.1.5\n",
        encoding="utf-8",
    )
    r = client.get("/api/update/log?lines=5")
    assert r.headers.get("Cache-Control") == "no-store"
    d = r.get_json()
    assert d["content"].splitlines() == [f"u{i}" for i in range(45, 50)]
    assert "self-update to v9.9.9" in d["panel"]  # хвост лога панели
    assert d["state"] == {}  # state-файла нет — пусто, не ошибка


# --- self-update: UI -----------------------------------------------------------------

def test_ui_has_update_controls(app):
    html = (APP_DIR / "templates" / "index.html").read_text(encoding="utf-8")
    for marker in ('data-action="updateCheck"', 'data-action="updateApply"',
                   'data-action="updateNotes"', 'id="updDlg"', 'id="notesDlg"',
                   '/api/update/check', '/api/update/apply', '/api/update/log'):
        assert marker in html, marker


def test_ui_has_log_source_switch_and_panel_tail_in_update_dlg(app):
    html = (APP_DIR / "templates" / "index.html").read_text(encoding="utf-8")
    for marker in ('data-action="logSrc"', 'id="btnSrcPanel"', 'id="updPanelLog"',
                   'naivepanel-logsrc', "src='+logSrc"):
        assert marker in html, marker


def test_install_sh_repo_override_present(app):
    # self-update спавнит install.sh, наследуя окружение: зеркало задаётся
    # одним NAIVEPANEL_REPO и для панели, и для установщика
    text = (APP_DIR / "install.sh").read_text(encoding="utf-8")
    assert 'NAIVEPANEL_REPO:-keenetic-tools/naivepanel' in text


def test_install_sh_from_update_skips_python_checks(app):
    # self-update не должен форкать python ради проверок того, что уже
    # доказано работающей панелью (тесная память роутера, кейс v0.9.0)
    text = (APP_DIR / "install.sh").read_text(encoding="utf-8")
    assert '--from-update)    FROM_UPDATE=1 ;;' in text
    assert 'FROM_UPDATE" = 1' in text
    assert 'checks skipped (--from-update)' in text


# --- периодическая обрезка логов ------------------------------------------------------

def test_trim_oversized_log_keeps_tail_and_inode(env, monkeypatch):
    monkeypatch.setenv("NAIVEPANEL_LOG_MAX", "100")
    monkeypatch.setenv("NAIVEPANEL_LOG_KEEP", "30")
    m = _reload()
    log = m.LOG_FILE
    log.write_bytes(b"123456789\n" * 12)  # 120 байт (строки по 10) > лимита
    inode = log.stat().st_ino
    trimmed = m._trim_logs_once()
    # хвост 30 байт = 3 строки; первая срезана как обрубок → 2 полные строки
    assert [(p, was, now) for p, was, now in trimmed] == [(log, 120, 20)]
    assert log.read_bytes() == b"123456789\n123456789\n"
    # инод сохранён: пишущий процесс (naive с append-fd) не теряет файл
    assert log.stat().st_ino == inode


def test_trim_skips_small_and_missing_logs(env, monkeypatch):
    monkeypatch.setenv("NAIVEPANEL_LOG_MAX", "1000")
    m = _reload()
    m.LOG_FILE.write_bytes(b"short\n")
    # PANEL_LOG/UPDATE_LOG не существуют — не ошибка, просто пропускаем
    assert m._trim_logs_once() == []
    assert m.LOG_FILE.read_bytes() == b"short\n"


def test_trim_covers_log_file_from_active_config(env, monkeypatch):
    monkeypatch.setenv("NAIVEPANEL_LOG_MAX", "10")
    monkeypatch.setenv("NAIVEPANEL_LOG_KEEP", "4")
    m = _reload()
    extra = env / "naive-own.log"
    extra.write_text("".join(f"line{i:03d}\n" for i in range(20)),
                     encoding="utf-8")
    m.ACTIVE_CONFIG.parent.mkdir(parents=True, exist_ok=True)
    m.ACTIVE_CONFIG.write_text(
        json.dumps({"listen": "socks://127.0.0.1:1080", "log": str(extra)}),
        encoding="utf-8")
    trimmed = m._trim_logs_once()
    assert [p for p, _, _ in trimmed] == [extra]
    assert extra.stat().st_size <= 4


def test_trim_disabled_with_zero_max(env, monkeypatch):
    monkeypatch.setenv("NAIVEPANEL_LOG_MAX", "0")
    m = _reload()
    m.LOG_FILE.write_bytes(b"x" * 10000)
    assert m._trim_logs_once() == []
    assert m.LOG_FILE.stat().st_size == 10000


def test_trim_invalid_settings_fall_back_to_defaults(env, monkeypatch):
    monkeypatch.setenv("NAIVEPANEL_LOG_MAX", "5MB")
    monkeypatch.setenv("NAIVEPANEL_LOG_KEEP", "-")
    m = _reload()
    assert m._LOG_MAX_INVALID and m._LOG_KEEP_INVALID
    assert m.LOG_TRIM_MAX == 5242880
    assert m.LOG_TRIM_KEEP == 524288


# --- бинарник naive: версии, детект таргета, выбор ассета ----------------------

def test_naive_ver_key_counts_build_suffix(app):
    k = app._naive_ver_key
    assert k("v154.0.8037.49-2") == (154, 0, 8037, 49, 2)
    assert k("v154.0.8037.49-1") < k("v154.0.8037.49-2")
    # вывод `naive --version` без суффикса пересборки старше любого -N
    assert k("154.0.8037.49") < k("v154.0.8037.49-1")
    assert k("v113.0.5672.3-1") < k("v154.0.8037.49-2")
    assert k("") == (0, 0)


def test_naive_bin_version_parses_output(app, env):
    p = env / "naive"
    p.write_text('#!/bin/sh\necho "naive 154.0.8037.49"\n')
    p.chmod(0o755)
    app.NAIVE_BIN = p
    assert app._naive_bin_version() == "154.0.8037.49"


def test_naive_bin_version_missing_or_broken(app, env):
    assert app._naive_bin_version() is None  # файла нет
    p = env / "naive"
    p.write_text('#!/bin/sh\nexit 3\n')  # есть, но не работает
    p.chmod(0o755)
    app.NAIVE_BIN = p
    assert app._naive_bin_version() is None


def _cpuinfo(tmp_path, text):
    p = tmp_path / ("cpuinfo-" + str(abs(hash(text)))[:8])
    p.write_text(text, encoding="utf-8")
    return p


@pytest.mark.parametrize("machine,cputext,want", [
    # Keenetic Giga/Ultra/Peak 2021+ (IPQ8074A): 4x Cortex-A53
    ("aarch64", "CPU part\t: 0xd03\n", "aarch64_cortex-a53"),
    ("aarch64", "CPU part\t: 0xd08\n", "aarch64_cortex-a72"),
    ("aarch64", "CPU part\t: 0xd0e\n", "aarch64_cortex-a76"),
    # неизвестное ядро (напр. Apple/KNF) → безопасный generic
    ("aarch64", "CPU part\t: 0x612\n", "aarch64_generic"),
    ("arm64", "CPU part\t: 0xd03\n", "aarch64_cortex-a53"),
    # armv7: суффиксы FPU по Features (неон+vfpv4 → neon-vfpv4, есть -static)
    ("armv7l", "CPU part\t: 0xc07\nFeatures\t: half thumb fastmult vfp edsp neon vfpv3 vfpv4\n",
     "arm_cortex-a7_neon-vfpv4"),
    ("armv7l", "CPU part\t: 0xc07\nFeatures\t: half thumb fastmult vfp vfpv3 vfpv4\n",
     "arm_cortex-a7_vfpv4"),
    ("armv7l", "CPU part\t: 0xc07\nFeatures\t: half thumb fastmult vfp\n",
     "arm_cortex-a7"),
    ("armv7l", "CPU part\t: 0xc09\nFeatures\t: half thumb vfp neon\n", "arm_cortex-a9_neon"),
    ("armv7l", "CPU part\t: 0xc09\nFeatures\t: half thumb vfp\n", "arm_cortex-a9"),
    ("armv7l", "CPU part\t: 0xc0f\nFeatures\t: vfp neon vfpv4\n", "arm_cortex-a15_neon-vfpv4"),
    ("armv7l", "CPU part\t: 0xc05\nFeatures\t: vfp vfpv4\n", "arm_cortex-a5_vfpv4"),
    ("armv7l", "CPU part\t: 0xc08\nFeatures\t: vfp vfpv3\n", "arm_cortex-a8_vfpv3"),
    # неизвестный armv7 → самый массовый базовый таргет
    ("armv7l", "CPU part\t: 0xc0d\nFeatures\t: vfp\n", "arm_cortex-a7"),
    ("armv6l", "", "arm_arm1176jzf-s_vfp"),
    ("armv5tel", "", "arm_arm926ej-s"),
    ("x86_64", "", "x86_64"),
    ("i686", "", "x86"),
])
def test_naive_detect_target_variants(app, env, monkeypatch, machine, cputext, want):
    monkeypatch.setenv("NAIVEPROXY_UNAME_M", machine)
    monkeypatch.setenv("NAIVEPROXY_CPUINFO", str(_cpuinfo(env, cputext)))
    assert app._naive_detect_target() == want


def test_naive_detect_target_mips_uses_elf_endianness(app, env, monkeypatch):
    le = env / "elf-le"
    le.write_bytes(b"\x7fELF\x01\x01")
    be = env / "elf-be"
    be.write_bytes(b"\x7fELF\x01\x02")
    cpu = _cpuinfo(env, "cpu model\t\t: MIPS 1004Kc V2.15\n")
    monkeypatch.setenv("NAIVEPROXY_UNAME_M", "mips")
    monkeypatch.setenv("NAIVEPROXY_CPUINFO", str(cpu))
    # MT7621 (Keenetic на mips): 1004Kc — совместим с таргетом 24kc
    monkeypatch.setenv("NAIVEPROXY_ELF", str(le))
    assert app._naive_detect_target() == "mipsel_24kc"
    monkeypatch.setenv("NAIVEPROXY_ELF", str(be))
    assert app._naive_detect_target() is None  # big-endian: prebuilt нет


ASSETS = [
    ("naiveproxy-v154.0.8037.49-2-openwrt-aarch64_cortex-a53.tar.xz", "u-plain"),
    ("naiveproxy-v154.0.8037.49-2-openwrt-aarch64_cortex-a53-static.tar.xz", "u-static"),
    ("naiveproxy-v154.0.8037.49-2-openwrt-aarch64_generic.tar.xz", "u-gen"),
    ("naiveproxy-v154.0.8037.49-2-openwrt-aarch64_generic-static.tar.xz", "u-gen-static"),
    ("naiveproxy-v154.0.8037.49-2-openwrt-aarch64_cortex-a76.tar.xz", "u-a76"),
    ("naiveproxy-v154.0.8037.49-2-openwrt-mipsel_24kc-static.tar.xz", "u-mips"),
    ("naiveproxy-v154.0.8037.49-2-linux-arm64.tar.xz", "u-linux"),
]


def test_naive_pick_asset_prefers_static(app):
    pick = lambda t: app._naive_pick_asset(ASSETS, t)  # noqa: E731
    assert pick("aarch64_cortex-a53") == \
        ("naiveproxy-v154.0.8037.49-2-openwrt-aarch64_cortex-a53-static.tar.xz", "u-static")
    # у a76 нет -static — берётся обычный, а не фолбэк на generic
    assert pick("aarch64_cortex-a76")[1] == "u-a76"
    # неизвестный aarch64 → фолбэк на generic (-static)
    assert pick("aarch64_cortex-a34")[1] == "u-gen-static"
    # таргет с флейвором из маркера: -static отрезается до выбора
    assert app._naive_pick_asset(ASSETS, "aarch64_cortex-a53-static")[1] == "u-static"
    # linux-ассеты не матчатся под openwrt-таргет; пустой таргет — None
    assert app._naive_pick_asset(ASSETS, "x86_64") is None
    assert app._naive_pick_asset(ASSETS, None) is None


def test_naive_release_requires_tag_and_assets(app, monkeypatch):
    def fake_get(url, timeout=6.0):
        return json.dumps({"tag_name": "", "assets": []})
    monkeypatch.setattr(app, "_http_get", fake_get)
    with pytest.raises(RuntimeError):
        app._naive_release()


# --- /api/naive/check -----------------------------------------------------------

def _naive_env_reload(env, monkeypatch):
    monkeypatch.setenv("NAIVEPROXY_BIN", str(env / "naive"))
    monkeypatch.setenv("NAIVEPROXY_SRC_REPO", "test/naiveproxy")
    monkeypatch.setenv("NAIVEPROXY_UPDATE_LOG", str(env / "naive-upd.log"))
    m = _reload()
    m.NAIVEPROXY_DIR.mkdir(parents=True, exist_ok=True)  # маркеры/.state пишем тут
    return m


def _naive_rel(monkeypatch, app, tag="v154.0.8037.49-2",
               assets=(("naiveproxy-v154.0.8037.49-2-openwrt-x86_64.tar.xz", "u1"),)):
    monkeypatch.setattr(app, "_naive_release",
                        lambda: {"tag": tag, "notes": "", "url": "", "assets": list(assets)})


def test_naive_check_reports_available_for_older_tag(client, app, env, monkeypatch):
    m = _naive_env_reload(env, monkeypatch)
    c = m.app.test_client()
    p = env / "naive"
    p.write_text('#!/bin/sh\necho "naive 113.0.5672.3"\n')
    p.chmod(0o755)
    m.NAIVE_TAG.parent.mkdir(parents=True, exist_ok=True)
    m.NAIVE_TAG.write_text("v113.0.5672.3-1\n")
    _naive_rel(monkeypatch, m)
    d = c.get("/api/naive/check").get_json()
    assert d["version"] == "113.0.5672.3" and d["tag"] == "v113.0.5672.3-1"
    assert d["latest"] == "v154.0.8037.49-2" and d["available"] is True


def test_naive_check_same_tag_not_available(client, app, env, monkeypatch):
    m = _naive_env_reload(env, monkeypatch)
    c = m.app.test_client()
    p = env / "naive"
    p.write_text('#!/bin/sh\necho "naive 154.0.8037.49"\n')
    p.chmod(0o755)
    m.NAIVE_TAG.write_text("v154.0.8037.49-2\n")
    _naive_rel(monkeypatch, m)
    d = c.get("/api/naive/check").get_json()
    assert d["available"] is False


def test_naive_check_build_suffix_beats_plain_version(client, app, env, monkeypatch):
    # бинарник без маркера (ручная установка): --version теряет суффикс -2,
    # поэтому свежий релиз с пересборкой считается доступным
    m = _naive_env_reload(env, monkeypatch)
    c = m.app.test_client()
    p = env / "naive"
    p.write_text('#!/bin/sh\necho "naive 154.0.8037.49"\n')
    p.chmod(0o755)
    _naive_rel(monkeypatch, m)
    d = c.get("/api/naive/check").get_json()
    assert d["tag"] is None and d["available"] is True


def test_naive_check_no_binary_available_true(client, app, env, monkeypatch):
    m = _naive_env_reload(env, monkeypatch)
    c = m.app.test_client()
    _naive_rel(monkeypatch, m)
    d = c.get("/api/naive/check").get_json()
    assert d["version"] is None and d["available"] is True  # можно установить


def test_naive_check_failsoft_and_cache(client, app, env, monkeypatch):
    m = _naive_env_reload(env, monkeypatch)
    c = m.app.test_client()
    calls = {"n": 0}

    def dead():
        calls["n"] += 1
        raise RuntimeError("GitHub unreachable")

    monkeypatch.setattr(m, "_naive_release", dead)
    r = c.get("/api/naive/check")
    assert r.status_code == 200  # недоступный GitHub — не ошибка панели
    d = r.get_json()
    assert d["available"] is False and d["latest"] is None and d["error"]
    assert c.get("/api/naive/check").get_json()["cached"] is True
    assert c.get("/api/naive/check?force=1").get_json().get("cached") is None
    assert calls["n"] == 2


# --- /api/naive/update ----------------------------------------------------------

def test_naive_update_refuses_exposed_panel_without_password(client, app, env, monkeypatch):
    m = _naive_env_reload(env, monkeypatch)
    m.cfg.PANEL_BIND = "192.168.1.1:8089"
    _naive_rel(monkeypatch, m)
    r = m.app.test_client().post("/api/naive/update", headers=CSRF)
    assert r.status_code == 403
    assert "password" in r.get_json()["error"]


def test_naive_update_502_when_release_unreachable(client, app, env, monkeypatch):
    m = _naive_env_reload(env, monkeypatch)

    def dead():
        raise RuntimeError("GitHub unreachable")

    monkeypatch.setattr(m, "_naive_release", dead)
    assert m.app.test_client().post("/api/naive/update", headers=CSRF).status_code == 502


def test_naive_update_concurrent_returns_409(client, app, env, monkeypatch):
    m = _naive_env_reload(env, monkeypatch)
    _naive_rel(monkeypatch, m)
    m._naive_state_write({"phase": "running", "target": "v9.9.9",
                          "started": time.time()})
    r = m.app.test_client().post("/api/naive/update", headers=CSRF)
    assert r.status_code == 409
    assert "in progress" in r.get_json()["error"]


def test_naive_state_stale_allows_retry(app):
    old = time.time() - app._NAIVE_STALE_S - 1
    app._naive_state_write({"phase": "running", "target": "v1.0", "started": old})
    assert app._naive_state().get("stale") is True


def _serve_tarball(tarball: Path):
    """Локальный http-сервер, отдающий один файл; возвращает (url, stop)."""
    import http.server
    import threading

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            data = tarball.read_bytes()
            self.send_response(200)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *a):  # не шумим в вывод pytest
            pass

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()

    def stop():
        srv.shutdown()
        srv.server_close()

    return f"http://127.0.0.1:{srv.server_address[1]}/naive.tar.xz", stop


def _build_naive_tarball(path: Path, script: str, tag="v154.0.8037.49-2") -> None:
    import io
    import tarfile
    data = script.encode()
    with tarfile.open(path, "w:xz") as tf:
        info = tarfile.TarInfo(f"naiveproxy-{tag}-openwrt-x86_64/naive")
        info.mode = 0o755
        info.size = len(data)  # без size addfile пишет 0 байт
        tf.addfile(info, io.BytesIO(data))


def _naive_done(m, timeout=30.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        st = m._naive_state()
        if st.get("phase") in ("done", "failed"):
            return st
        time.sleep(0.1)
    return m._naive_state()


def test_naive_update_downloads_validates_and_replaces(client, app, env, monkeypatch):
    m = _naive_env_reload(env, monkeypatch)
    stub, marker = _stub_init(env, "naive-restarts.txt")
    m.INIT_SCRIPT = stub
    # «работающий» прокси: pid-файл с живым процессом → рестарт обязателен.
    # На Linux _pid_is_naive читает /proc/<pid>/comm и справедливо бракует
    # pytest-процесс (это не naive) — подменяем только анти-pid-reuse проверку:
    # тестируем логику воркера, а не классификатор имён процессов.
    m.PID_FILE.parent.mkdir(parents=True, exist_ok=True)
    m.PID_FILE.write_text(str(os.getpid()))
    monkeypatch.setattr(m, "_pid_is_naive", lambda pid: True)
    old = env / "naive"
    old.write_text('#!/bin/sh\necho "naive 113.0.5672.3"\n')
    old.chmod(0o755)
    m.NAIVE_TAG.write_text("v113.0.5672.3-1\n")
    m.NAIVE_BUILD.write_text("x86_64\n")

    tarball = env / "naive.tar.xz"
    _build_naive_tarball(tarball, '#!/bin/sh\necho "naive 154.0.8037.49"\n')
    url, stop = _serve_tarball(tarball)
    try:
        _naive_rel(monkeypatch, m,
                   assets=(("naiveproxy-v154.0.8037.49-2-openwrt-x86_64.tar.xz", url),))
        r = m.app.test_client().post("/api/naive/update", headers=CSRF)
        assert r.status_code == 202
        assert r.get_json()["target"] == "v154.0.8037.49-2"
        st = _naive_done(m)
    finally:
        stop()

    assert st["phase"] == "done", st
    assert st["version"] == "naive 154.0.8037.49"
    # бинарник заменён и валиден; маркеры обновлены точным тегом
    assert m._naive_bin_version() == "154.0.8037.49"
    assert m.NAIVE_TAG.read_text().strip() == "v154.0.8037.49-2"
    assert m.NAIVE_BUILD.read_text().strip() == "x86_64"
    # рабочий процесс был жив → сервис перезапущен; прежний образ — в бэкапе
    assert marker.read_text().splitlines()[-1] == "restart"
    assert (m.NAIVEPROXY_DIR / "backup" / "naive.previous").exists()
    assert not (m.NAIVEPROXY_DIR / ".naive-update").exists()  # stage убран


def test_naive_update_failed_check_keeps_old_binary(client, app, env, monkeypatch):
    # скачанный бинарник не проходит --version → рабочий не трогаем
    m = _naive_env_reload(env, monkeypatch)
    old = env / "naive"
    old.write_text('#!/bin/sh\necho "naive 113.0.5672.3"\n')
    old.chmod(0o755)
    m.NAIVE_TAG.write_text("v113.0.5672.3-1\n")
    m.NAIVE_BUILD.write_text("x86_64\n")

    tarball = env / "bad.tar.xz"
    _build_naive_tarball(tarball, '#!/bin/sh\nexit 7\n')
    url, stop = _serve_tarball(tarball)
    try:
        _naive_rel(monkeypatch, m,
                   assets=(("naiveproxy-v154.0.8037.49-2-openwrt-x86_64.tar.xz", url),))
        assert m.app.test_client().post("/api/naive/update", headers=CSRF).status_code == 202
        st = _naive_done(m)
    finally:
        stop()

    assert st["phase"] == "failed"
    assert "--version" in st["error"]
    assert m._naive_bin_version() == "113.0.5672.3"  # прежний на месте


def test_naive_update_no_asset_for_target_fails(client, app, env, monkeypatch):
    m = _naive_env_reload(env, monkeypatch)
    m.NAIVE_BUILD.write_text("aarch64_cortex-a9999\n")  # маркер с экзотикой
    _naive_rel(monkeypatch, m,
               assets=(("naiveproxy-v154.0.8037.49-2-openwrt-x86_64.tar.xz", "u1"),))
    assert m.app.test_client().post("/api/naive/update", headers=CSRF).status_code == 202
    st = _naive_done(m)
    assert st["phase"] == "failed"
    assert "no openwrt asset" in st["error"]


def test_naive_status_tails_log_and_no_store(client, app, env, monkeypatch):
    m = _naive_env_reload(env, monkeypatch)
    m.NAIVE_UPDATE_LOG.write_text("".join(f"n{i}\n" for i in range(50)),
                                  encoding="utf-8")
    m._naive_state_write({"phase": "done", "target": "v1"})
    r = m.app.test_client().get("/api/naive/status?lines=5")
    assert r.headers.get("Cache-Control") == "no-store"
    d = r.get_json()
    assert d["content"].splitlines() == [f"n{i}" for i in range(45, 50)]
    assert d["state"]["phase"] == "done"


# --- install.sh: установка бинарника -------------------------------------------

def test_install_sh_naive_source_overridable(app):
    # зеркало/локальный сервер для e2e задаётся одним env, как NAIVEPANEL_REPO
    text = (APP_DIR / "install.sh").read_text(encoding="utf-8")
    assert 'NAIVEPROXY_SRC_REPO:-klzgrad/naiveproxy' in text
    assert 'NAIVEPROXY_SRC_API:-https://api.github.com' in text
    for flag in ("--naive-target)", "--naive-ref)", "--skip-naive)", "--naive-force)"):
        assert flag in text, flag


def test_install_sh_from_update_skips_naive_step(app):
    # self-update панели не должен качать бинарник и трогать прокси
    text = (APP_DIR / "install.sh").read_text(encoding="utf-8")
    guard = 'if [ "$FROM_UPDATE" = 1 ]; then\n' \
            '    :  # см. комментарий выше — бинарник обновляется панелью отдельно\n' \
            'elif [ "$SKIP_NAIVE" = 1 ]; then'
    assert guard in text, "гейт --from-update вокруг установки naive сломан"


def test_install_sh_writes_naive_markers(app):
    # тег и таргет переживают установку — панель по ним считает available
    text = (APP_DIR / "install.sh").read_text(encoding="utf-8")
    assert 'echo "$tag"   > "$NAIVEPROXY_DIR/naive-version"' in text
    assert 'echo "$build" > "$NAIVEPROXY_DIR/naive-build"' in text


# --- UI: секция «Бинарник naive» ------------------------------------------------

def test_ui_has_naive_binary_controls(app):
    html = (APP_DIR / "templates" / "index.html").read_text(encoding="utf-8")
    for marker in ('data-action="naiveCheck"', 'data-action="naiveUpdate"',
                   'id="nvInfo"', 'id="btnNvUpd"', 'id="btnNvCheck"',
                   '/api/naive/check', '/api/naive/update', '/api/naive/status'):
        assert marker in html, marker


# --- UI: смена пароля администратора -------------------------------------------

def test_ui_has_password_change_controls(app):
    html = (APP_DIR / "templates" / "index.html").read_text(encoding="utf-8")
    for marker in ('id="pwDlg"', 'data-action="pwOpen"', 'id="pwCurrent"',
                   'id="pwNew"', 'id="pwRepeat"', 'autocomplete="new-password"',
                   'id="btnPwChange"', 'id="btnPwChange" hidden', 'role="status"',
                   'TextEncoder', 'authChanged) return'):
        assert marker in html, marker
    assert "confirm(" not in html
    assert 'minlength="8"' not in html


# --- E2E-проверка: реальный запрос через listen-прокси --------------------------

import socket


class _StubServer:
    """Одноразовый локальный сервер: на каждое соединение зовёт handler(conn).

    Живые сокеты на 127.0.0.1, без сети наружу: клиентская сторона панели
    ходит сюда как к «прокси», серверная часть скрипта играет роль и прокси,
    и echo-хоста за туннелем (для клиента они неразличимы).
    """

    def __init__(self, handler):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(4)
        self.port = self.sock.getsockname()[1]
        self.handler = handler
        self.errors = []
        threading.Thread(target=self._accept_loop, daemon=True).start()

    def _accept_loop(self):
        try:
            while True:
                conn, _ = self.sock.accept()
                threading.Thread(target=self._serve, args=(conn,), daemon=True).start()
        except OSError:
            pass

    def _serve(self, conn):
        try:
            self.handler(conn)
        except Exception as exc:  # диагностика стаба — не роняем тестовый поток
            self.errors.append(repr(exc))
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def close(self):
        self.sock.close()


def _http_proxy_ok(conn):
    req = conn.recv(4096)
    assert req.startswith(b"CONNECT "), req[:40]
    conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
    get = conn.recv(4096)
    assert get.startswith(b"GET "), get[:40]
    conn.sendall(b"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\n203.0.113.7")


def _socks5_proxy_ok(conn):
    greeting = conn.recv(3)
    assert greeting == b"\x05\x01\x00", greeting
    conn.sendall(b"\x05\x00")  # выбран NO-AUTH
    req = conn.recv(4096)
    assert req[:4] == b"\x05\x01\x00\x03", req[:10]
    conn.sendall(b"\x05\x00\x00\x01" + socket.inet_aton("0.0.0.0")
                 + (80).to_bytes(2, "big"))
    get = conn.recv(4096)
    assert get.startswith(b"GET "), get[:40]
    conn.sendall(b"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\n198.51.100.99")


def test_listen_endpoint_parsing(app):
    f = app._listen_endpoint
    assert f("socks://127.0.0.1:1080") == ("socks", "127.0.0.1", 1080)
    assert f("socks5://0.0.0.0:1080") == ("socks", "0.0.0.0", 1080)
    assert f("http://192.168.1.1:8080") == ("http", "192.168.1.1", 8080)
    assert f("127.0.0.1:1080") == ("socks", "127.0.0.1", 1080)  # без схемы — socks
    assert f("socks://127.0.0.1") == ("socks", "127.0.0.1", 1080)   # умолч. порт
    assert f("http://127.0.0.1") == ("http", "127.0.0.1", 8080)
    assert f("http://[::1]:8080") == ("http", "::1", 8080)
    assert f("quic://x:1") is None       # listen не бывает quic
    assert f("") is None
    assert f("host:port") is None


def test_extract_exit_ip(app):
    f = app._extract_exit_ip
    assert f("203.0.113.7") == "203.0.113.7"
    assert f('{"ip":"198.51.100.99"}') == "198.51.100.99"
    assert f("2001:db8::1") == "2001:db8::1"
    assert f("hello") is None


def test_e2e_http_listen_full_path(app, monkeypatch):
    # http-listen: CONNECT → 200 → GET → ответ с IP (echo-хост http, без TLS)
    stub = _StubServer(_http_proxy_ok)
    monkeypatch.setattr(app, "E2E_URL", "http://e2e.example/")
    try:
        d = app._proxy_e2e_check(f"http://127.0.0.1:{stub.port}")
        assert d["ok"] is True, d
        assert d["exit_ip"] == "203.0.113.7"
        assert d["ms"] >= 0
    finally:
        stub.close()
    assert not stub.errors, stub.errors


def test_e2e_socks_listen_full_path(app, monkeypatch):
    stub = _StubServer(_socks5_proxy_ok)
    monkeypatch.setattr(app, "E2E_URL", "http://e2e.example/")
    try:
        d = app._proxy_e2e_check(f"socks://127.0.0.1:{stub.port}")
        assert d["ok"] is True, d
        assert d["exit_ip"] == "198.51.100.99"
    finally:
        stub.close()
    assert not stub.errors, stub.errors


def test_e2e_refused_port(app):
    # порт точно закрыт: bind(0) → close, но без listen
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    d = app._proxy_e2e_check(f"socks://127.0.0.1:{port}")
    assert d["ok"] is False
    assert "не принимает" in d["error"]


def test_e2e_connect_rejected(app, monkeypatch):
    def handler(conn):
        conn.recv(4096)
        conn.sendall(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
    stub = _StubServer(handler)
    try:
        d = app._proxy_e2e_check(f"http://127.0.0.1:{stub.port}")
        assert d["ok"] is False
        assert "407" in d["error"]
    finally:
        stub.close()


def test_e2e_tunnel_ack_but_no_data_fails(app, monkeypatch):
    # туннель подтверждён (200 на CONNECT), но данные не пошли. Успех —
    # только полный ответ echo-хоста: это ok:False (инцидент v0.12.2 —
    # naive ACK-ает SOCKS/CONNECT при лежащем upstream, затем обрыв)
    def handler(conn):
        conn.recv(4096)
        conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
        time.sleep(0.3)  # клиент успеет отправить GET и упереться в закрытие
    stub = _StubServer(handler)
    monkeypatch.setattr(app, "E2E_URL", "http://e2e.example/")
    try:
        d = app._proxy_e2e_check(f"http://127.0.0.1:{stub.port}", timeout=3.0)
        assert d["ok"] is False, d
        assert d["error"]                       # причина в error, не в note
    finally:
        stub.close()


def test_e2e_socks_ack_then_close_is_failure(app):
    # точный кейс с реального роутера (v0.12.2): caddy на сервере отключили,
    # naive принимает SOCKS CONNECT и отвечает 0x00, затем TLS через
    # туннель получает EOF. До фикса это считалось успехом с note и
    # фейловер не срабатывал; теперь — неудача с текстом TLS-ошибки
    def handler(conn):
        greeting = conn.recv(3)
        assert greeting == b"\x05\x01\x00", greeting
        conn.sendall(b"\x05\x00")               # naive ACK-ает туннель…
        conn.recv(4096)                          # CONNECT-запрос
        conn.sendall(b"\x05\x00\x00\x01" + socket.inet_aton("0.0.0.0")
                     + (80).to_bytes(2, "big"))
        conn.recv(4096)                          # ClientHello уходит в никуда
        conn.close()                             # …и рвёт соединение
    stub = _StubServer(handler)
    try:
        d = app._proxy_e2e_check(f"socks://127.0.0.1:{stub.port}", timeout=5.0)
        assert d["ok"] is False, d
        assert "TLS" in d["error"] or "echo" in d["error"], d
    finally:
        stub.close()


def test_e2e_endpoint_uses_active_config(client, app, monkeypatch):
    # активного пресета нет → 400
    r = client.post("/api/e2e", json={}, headers=CSRF)
    assert r.status_code == 400
    # есть config.json с listen → проверка идёт по нему (порт закрыт → ok:false)
    app._save_json(app.ACTIVE_CONFIG,
                   {"listen": "socks://127.0.0.1:1", "proxy": "https://u:p@h"})
    r = client.post("/api/e2e", json={}, headers=CSRF)
    assert r.status_code == 200
    assert r.get_json()["ok"] is False
    # явный listen в теле перекрывает активный конфиг
    stub = _StubServer(_socks5_proxy_ok)
    monkeypatch.setattr(app, "E2E_URL", "http://e2e.example/")
    try:
        r = client.post("/api/e2e", json={"listen": f"socks://127.0.0.1:{stub.port}"},
                        headers=CSRF)
        d = r.get_json()
        assert r.status_code == 200 and d["ok"] is True, d
    finally:
        stub.close()


def test_e2e_requires_csrf_header(client):
    assert client.post("/api/e2e", json={}).status_code == 403


# --- Watchdog: авто-рестарт упавшего naive --------------------------------------

def _wd_seq(values):
    """_proxy_running → серия результатов; после исчерпания — «лежит»."""
    it = iter(values)

    def fake():
        return next(it, (False, None, None))
    return fake


def _wd_service(calls):
    def fake(action):
        calls.append(action)
        return {"rc": 0, "stdout": "", "stderr": ""}
    return fake


def _wd_arm(app):
    """Создаёт пустой init-скрипт: фикстура env указывает на отсутствующий,
    а без него watchdog честно отвечает no-init и не рестартит."""
    app.INIT_SCRIPT.parent.mkdir(parents=True, exist_ok=True)
    app.INIT_SCRIPT.write_text("#!/bin/sh\n")


def test_watchdog_silent_until_first_observation(app, monkeypatch):
    # первый тик только фиксирует состояние: «изначально лежит» — не сигнал
    wd = app._Watchdog()
    monkeypatch.setattr(app, "_proxy_running", _wd_seq([(True, 11, 5)]))
    assert wd.observe(recheck_delay=0.01) is None


def test_watchdog_restarts_on_crash(app, monkeypatch):
    wd = app._Watchdog()
    calls = []
    _wd_arm(app)
    monkeypatch.setattr(app, "_proxy_running",
                        _wd_seq([(True, 11, 5), (False, None, None), (False, None, None)]))
    monkeypatch.setattr(app, "_service", _wd_service(calls))
    assert wd.observe(recheck_delay=0.01) is None       # фиксируем running
    ev = wd.observe(recheck_delay=0.01)
    assert ev == {"event": "restarted", "rc": 0, "stderr": ""}
    assert calls == ["start"]
    assert wd.count == 1
    assert wd.snapshot() == {"enabled": True, "restarts": 1, "tripped": False}


def test_watchdog_respects_stop_marker(app, monkeypatch):
    wd = app._Watchdog()
    calls = []
    monkeypatch.setattr(app, "_proxy_running",
                        _wd_seq([(True, 11, 5), (False, None, None), (False, None, None)]))
    monkeypatch.setattr(app, "_service", _wd_service(calls))
    app.STOP_MARKER.parent.mkdir(parents=True, exist_ok=True)
    app.STOP_MARKER.write_text("")
    assert wd.observe(recheck_delay=0.01) is None
    ev = wd.observe(recheck_delay=0.01)
    assert ev == {"event": "stopped"}                    # штатный stop — стоим
    assert calls == []
    app.STOP_MARKER.unlink()


def test_watchdog_recheck_recovers_from_restart_race(app, monkeypatch):
    # up→down увиден посреди restart init-скрипта: перепроверка через паузу
    # видит, что сервис уже поднялся — рестартить не надо
    wd = app._Watchdog()
    calls = []
    monkeypatch.setattr(app, "_proxy_running",
                        _wd_seq([(True, 11, 5), (False, None, None), (True, 12, 0)]))
    monkeypatch.setattr(app, "_service", _wd_service(calls))
    assert wd.observe(recheck_delay=0.01) is None
    assert wd.observe(recheck_delay=0.01) is None
    assert calls == []


def test_watchdog_down_to_up_is_not_an_event(app, monkeypatch):
    wd = app._Watchdog()
    monkeypatch.setattr(app, "_proxy_running", _wd_seq([(False, None, None), (True, 9, 0)]))
    wd.observe(recheck_delay=0.01)
    assert wd.observe(recheck_delay=0.01) is None


def test_watchdog_flap_trips(app, monkeypatch):
    # 3 рестарта за окно → watchdog отключается; следующий crash уже не лечит
    wd = app._Watchdog()
    calls = []
    _wd_arm(app)
    monkeypatch.setattr(app, "_service", _wd_service(calls))

    def crash_cycle():
        monkeypatch.setattr(app, "_proxy_running",
                            _wd_seq([(True, 11, 5), (False, None, None),
                                     (False, None, None)]))
        wd.observe(recheck_delay=0.01)  # фиксируем running
        return wd.observe(recheck_delay=0.01)

    for _ in range(3):
        assert crash_cycle()["event"] == "restarted"
    assert wd.count == 3

    ev = crash_cycle()
    assert ev == {"event": "tripped"}
    assert wd.tripped is True
    assert len(calls) == 3            # четвёртый start не состоялся

    ev = crash_cycle()
    assert ev == {"event": "down-tripped"}
    assert len(calls) == 3


def test_watchdog_requires_init_script(app, monkeypatch):
    # init-скрипта нет (env-фикстура указывает на отсутствующий) — не падаем
    wd = app._Watchdog()
    calls = []
    monkeypatch.setattr(app, "_proxy_running",
                        _wd_seq([(True, 11, 5), (False, None, None), (False, None, None)]))
    monkeypatch.setattr(app, "_service", _wd_service(calls))
    wd.observe(recheck_delay=0.01)
    assert wd.observe(recheck_delay=0.01) == {"event": "no-init"}
    assert calls == []


def test_status_reports_watchdog(client):
    r = client.get("/api/status")
    d = r.get_json()
    assert r.status_code == 200
    assert d["watchdog"] == {"enabled": True, "restarts": 0, "tripped": False}


def test_watchdog_disabled_by_conf(conf_env):
    conf_env.write_text('NAIVEPANEL_WATCHDOG="0"\n')
    m = _reload()
    assert m.WATCHDOG_ENABLED is False
    c = m.app.test_client()
    assert c.get("/api/status").get_json()["watchdog"]["enabled"] is False


def test_watchdog_conf_interval_parsed(conf_env):
    conf_env.write_text('NAIVEPANEL_WATCHDOG_INTERVAL="30"\n')
    m = _reload()
    assert m.WATCHDOG_INTERVAL == 30


# --- UI: E2E и watchdog ---------------------------------------------------------

def test_ui_has_e2e_and_watchdog_controls(app):
    html = (APP_DIR / "templates" / "index.html").read_text(encoding="utf-8")
    for marker in ('data-action="e2e"', 'id="btnE2e"', 'id="e2eInfo"',
                   "/api/e2e", "checkProxy", "watchdog"):
        assert marker in html, marker


# --- Автофейловер: цепочка пресетов ---------------------------------------------

def _fo_setup(client, app, presets=("home", "backup"), chain=None, activate="home"):
    """Два живых пресета + активный home + цепочка (по умолчанию все пресеты)."""
    for name in presets:
        _create(client, name=name)
    if activate:
        assert client.post(f"/api/configs/{activate}/activate",
                           headers=CSRF).status_code == 200
    app._save_json(app.FAILOVER_CONF,
                   {"enabled": True, "chain": list(chain if chain is not None else presets)})
    return app._Failover(threshold=2)


def _fo_e2e(monkeypatch, app, ok, error=None):
    """Подмена E2E-проверки; возвращает список вызовов (listen-аргументы)."""
    calls = []
    result = {"ok": ok, "ms": 5}
    if error:
        result["error"] = error
    monkeypatch.setattr(app, "_proxy_e2e_check",
                        lambda listen: (calls.append(listen), result)[1])
    return calls


def test_failover_default_disabled(client):
    d = client.get("/api/failover").get_json()
    assert d["enabled"] is False and d["chain"] == []


def test_failover_put_validates_chain(client):
    _create(client, name="home")
    _create(client, name="backup")
    r = client.put("/api/failover", headers=CSRF,
                   json={"enabled": True, "chain": ["home", "backup"]})
    assert r.status_code == 200
    d = r.get_json()
    assert d["enabled"] is True and d["chain"] == ["home", "backup"]
    # несуществующий пресет — 404, битое имя — 400, дубль — 400
    assert client.put("/api/failover", headers=CSRF,
                      json={"enabled": True, "chain": ["home", "nope"]}).status_code == 404
    assert client.put("/api/failover", headers=CSRF,
                      json={"enabled": True, "chain": ["home", "BAD!"]}).status_code == 400
    assert client.put("/api/failover", headers=CSRF,
                      json={"enabled": True, "chain": ["home", "home"]}).status_code == 400
    assert client.put("/api/failover", headers=CSRF,
                      json={"enabled": True, "chain": []}).status_code == 400
    # выключенным можно сохранить пустую цепочку
    r = client.put("/api/failover", headers=CSRF, json={"enabled": False, "chain": []})
    assert r.status_code == 200 and r.get_json()["enabled"] is False


def test_failover_delete_takes_lock(app, monkeypatch):
    seen = []

    class FakeConf:
        def unlink(self):
            seen.append(app._FAILOVER_LOCK.locked())
            raise FileNotFoundError

        def read_text(self, encoding=None):
            raise FileNotFoundError

    monkeypatch.setattr(app, "FAILOVER_CONF", FakeConf())
    assert app.app.test_client().delete(
        "/api/failover", headers=CSRF).status_code == 200
    assert seen == [True]


def test_failover_delete_disables(client, app):
    _create(client, name="home")
    client.put("/api/failover", headers=CSRF,
               json={"enabled": True, "chain": ["home"]})
    assert app.FAILOVER_CONF.exists()
    assert client.delete("/api/failover", headers=CSRF).status_code == 200
    assert not app.FAILOVER_CONF.exists()
    assert client.get("/api/failover").get_json()["enabled"] is False


def test_failover_requires_csrf(client):
    assert client.put("/api/failover", json={"enabled": True, "chain": ["x"]}).status_code == 403
    assert client.delete("/api/failover").status_code == 403


def test_status_includes_failover(client):
    d = client.get("/api/status").get_json()
    assert "failover" in d and d["failover"]["enabled"] is False


def test_failover_cycle_idles_without_chain(app, monkeypatch):
    # нет цепочки И нет активного пресета — проверять нечего
    calls = _fo_e2e(monkeypatch, app, ok=False, error="down")
    fo = app._Failover(threshold=2)
    assert fo.cycle() is None
    assert calls == []
    assert fo.idle_reason == "нет активного пресета с listen"


def test_failover_cycle_respects_stop_marker(client, app, monkeypatch):
    fo = _fo_setup(client, app)
    app.STOP_MARKER.parent.mkdir(parents=True, exist_ok=True)
    app.STOP_MARKER.write_text("")
    calls = _fo_e2e(monkeypatch, app, ok=False, error="down")
    assert fo.cycle() is None
    assert calls == []                               # даже не проверяем
    assert fo.idle_reason == "прокси остановлен вручную"
    app.STOP_MARKER.unlink()


def test_failover_cycle_checks_but_never_switches_when_active_outside_chain(client, app, monkeypatch):
    fo = _fo_setup(client, app, presets=("home", "backup"), chain=("home", "backup"),
                   activate="home")
    # активный вне цепочки: монитор продолжает проверять (история для
    # спарклайна) и НЕ переключает даже после порога неудач
    _create(client, name="other")
    assert client.post("/api/configs/other/activate", headers=CSRF).status_code == 200
    calls = _fo_e2e(monkeypatch, app, ok=False, error="down")
    assert fo.cycle() is None
    assert fo.cycle() is None                       # порог даже не копится
    assert len(calls) == 2
    assert app._active_name() == "other"
    assert fo.idle_reason is None                   # проверки идут — не пауза
    assert fo.snapshot()["active_index"] is None


def test_monitor_records_history_when_failover_disabled(client, app, monkeypatch):
    # цепочка не задана, но активный пресет есть: монитор всё равно
    # проверяет и пишет историю — спарклайн живёт без фейловера
    fo = _fo_setup(client, app, presets=("home",), chain=None, activate="home")
    app.FAILOVER_CONF.unlink()
    _fo_e2e(monkeypatch, app, ok=False, error="down")
    assert fo.cycle() is None
    assert fo.idle_reason is None
    hist = app._e2e_history_load(10)
    assert len(hist) == 1 and hist[0]["ok"] is False and hist[0]["ms"] == 5


def test_failover_hysteresis_then_switch(client, app, monkeypatch):
    # порог 2: первая неудача — только счётчик, вторая — переключение
    fo = _fo_setup(client, app, presets=("home", "backup"))
    _fo_e2e(monkeypatch, app, ok=False, error="upstream down")
    assert fo.cycle() == {"event": "failing", "fails": 1}
    assert app._active_name() == "home"

    ev = fo.cycle()
    assert ev["event"] == "switched" and ev["to"] == "backup"
    assert app._active_name() == "backup"            # config.json/.active переписаны
    active = json.loads(app.ACTIVE_CONFIG.read_text())
    assert active["proxy"].startswith("https://")
    assert fo.switches == 1 and fo.snapshot()["active_index"] == 1


def test_failover_recovery_resets_counter(client, app, monkeypatch):
    fo = _fo_setup(client, app)
    _fo_e2e(monkeypatch, app, ok=False, error="x")
    assert fo.cycle() == {"event": "failing", "fails": 1}
    _fo_e2e(monkeypatch, app, ok=True)
    assert fo.cycle() is None
    _fo_e2e(monkeypatch, app, ok=False, error="x")
    assert fo.cycle() == {"event": "failing", "fails": 1}   # счётчик с нуля
    assert app._active_name() == "home"                     # переключения не было


def test_failover_exhausted_announced_once(client, app, monkeypatch):
    # цепочка из одного пресета: переключаться некуда — exhausted один раз
    fo = _fo_setup(client, app, presets=("home",), chain=("home",))
    _fo_e2e(monkeypatch, app, ok=False, error="x")
    assert fo.cycle() == {"event": "failing", "fails": 1}
    assert fo.cycle() == {"event": "exhausted", "active": "home"}
    # следующая волна: счётчик копится, но exhausted уже не анонсируется
    assert fo.cycle() == {"event": "failing", "fails": 1}
    assert fo.cycle() is None
    # восстановление снимает «уже кричали» — следующий провал снова анонсирует
    _fo_e2e(monkeypatch, app, ok=True)
    fo.cycle()
    _fo_e2e(monkeypatch, app, ok=False, error="x")
    fo.cycle()
    assert fo.cycle() == {"event": "exhausted", "active": "home"}


def test_failover_skips_missing_preset_in_chain(client, app, monkeypatch):
    # пресет удалили из conf.d — цепочка просто короче: home → backup
    fo = _fo_setup(client, app, presets=("home", "backup"),
                   chain=("home", "deleted", "backup"))
    (app.CONF_D / "deleted.json").unlink(missing_ok=True)
    _fo_e2e(monkeypatch, app, ok=False, error="x")
    fo.cycle()
    ev = fo.cycle()
    assert ev["event"] == "switched" and ev["to"] == "backup"


def test_failover_switch_restarts_service(client, app, monkeypatch, env):
    # полноценный switch: активация идёт тем же кодом, что ручной activate,
    # включая рестарт init-скрипта (здесь — заглушка с записью вызовов)
    stub = env / "stub-init"
    stub.write_text("#!/bin/sh\n")
    stub.chmod(0o755)
    app.INIT_SCRIPT = stub
    fo = _fo_setup(client, app)
    _fo_e2e(monkeypatch, app, ok=False, error="x")
    fo.cycle()
    ev = fo.cycle()
    assert ev["event"] == "switched"
    assert isinstance(ev["restart"]["rc"], int)


# --- UI: фейловер ---------------------------------------------------------------

def test_ui_failover_lives_with_presets(app):
    html = (APP_DIR / "templates" / "index.html").read_text(encoding="utf-8")
    for marker in ('id="foInfo"', 'id="foEnabled"', 'id="foAuto"',
                   'id="foCount"', 'data-action="foOrder"',
                   'data-action="foAll"', 'data-action="foToggle"',
                   'data-action="foUp"', 'data-action="foDown"',
                   "foOrderMode", "FO_CHAIN_MAX", "orderedPresets",
                   "captureFocus", "restoreFocus", 'aria-label="Добавить',
                   'id="foEnabled" aria-label="Автофейловер включён" disabled',
                   'id="foAuto" aria-label="Возвращать на основной" disabled',
                   "d.failover",
                   "/api/failover"):
        assert marker in html, marker
    assert html.count('id="foInfo"') == 1
    assert 'id="foChips"' not in html and 'id="foPick"' not in html
    assert 'id="btnFoSave"' not in html and 'id="btnFoOff"' not in html
    assert "saveFailover" not in html and "offFailover" not in html


def test_ui_checkboxes_do_not_stretch(app):
    html = (APP_DIR / "templates" / "index.html").read_text(encoding="utf-8")
    assert 'input[type="checkbox"] { width:auto' in html


# --- История E2E-проверок: буфер, API, спарклайн -----------------------------

def test_e2e_history_append_load_and_trim(app, monkeypatch):
    # обрезка ленивая (раз в _E2E_TRIM_EVERY аппендов) — здесь на каждом
    monkeypatch.setattr(app, "E2E_KEEP", 10)
    monkeypatch.setattr(app, "_E2E_TRIM_EVERY", 1)
    for i in range(12):
        app._e2e_history_append(i % 3 != 0, i)
    entries = app._e2e_history_load(100)
    assert len(entries) == 10                     # обрезка до E2E_KEEP
    assert entries[0]["ms"] == 2 and entries[-1]["ms"] == 11
    assert all(set(e) == {"t", "ok", "ms"} for e in entries)


def test_e2e_history_load_skips_broken_lines(app):
    app.E2E_HISTORY.parent.mkdir(parents=True, exist_ok=True)
    app.E2E_HISTORY.write_text(
        '{"t": 1, "ok": true, "ms": 10}\n'
        'обрыв записи без переноса\n'
        '{"t": 2, "ok": false}\n'                   # нет ok-bool — невалидно? ok есть; ms нет → 0
        'not json at all\n'
        '{"t": 3, "ok": true, "ms": 30}\n',
        encoding="utf-8",
    )
    entries = app._e2e_history_load(10)
    assert [e["t"] for e in entries] == [1, 2, 3]
    assert entries[1]["ms"] == 0                   # отсутствие ms не роняет загрузку


def test_e2e_history_api_empty_and_stats(client, app):
    r = client.get("/api/e2e/history")
    assert r.status_code == 200
    d = r.get_json()
    assert d["entries"] == [] and d["stats"]["availability"] is None
    for i, ok in enumerate([True, True, True, False]):
        app._e2e_history_append(ok, 100 + i)
    d = client.get("/api/e2e/history?last=4").get_json()
    assert len(d["entries"]) == 4
    assert d["stats"]["ok"] == 3 and d["stats"]["fail"] == 1
    assert d["stats"]["availability"] == 75.0
    assert d["stats"]["avg_ms"] == round((100 + 101 + 102 + 103) / 4)  # 102
    assert d["stats"]["window_s"] == d["entries"][3]["t"] - d["entries"][0]["t"]
    # last ограничен и снизу и сверху
    assert len(client.get("/api/e2e/history?last=1").get_json()["entries"]) == 1


def test_e2e_history_cycle_writes_entries(client, app, monkeypatch):
    # полный цикл: ok-проверка и fail-проверка пишутся в буфер как есть
    fo = _fo_setup(client, app, presets=("home",), chain=("home",))
    results = [{"ok": True, "ms": 30}, {"ok": False, "ms": 0, "error": "x"}]
    monkeypatch.setattr(app, "_proxy_e2e_check", lambda listen: results.pop(0))
    fo.cycle()
    fo.cycle()
    hist = app._e2e_history_load(10)
    assert [(e["ok"], e["ms"]) for e in hist] == [(True, 30), (False, 0)]


def test_ui_has_e2e_history_sparkline(app):
    html = (APP_DIR / "templates" / "index.html").read_text(encoding="utf-8")
    for marker in ('id="e2eSpark"', "/api/e2e/history", "drawSpark", "loadSpark",
                   'class="spark"'):
        assert marker in html, marker


# --- Двухскоростной монитор: частые проверки при сбое --------------------------

def test_failover_hot_flag_escalates_and_cools(client, app, monkeypatch):
    # неудача при вооружённом фейловере → hot=True (монитор спит FAST);
    # восстановление → hot=False. Без цепочки hot не включается
    fo = _fo_setup(client, app, presets=("home", "backup"))
    _fo_e2e(monkeypatch, app, ok=False, error="x")
    fo.cycle()
    assert fo.hot is True
    _fo_e2e(monkeypatch, app, ok=True)
    fo.cycle()
    assert fo.hot is False and fo._fails == 0


def test_failover_hot_off_without_chain(client, app, monkeypatch):
    # цепочки нет: порог не копится, эскалации нет — редкий ритм экономит echo
    fo = _fo_setup(client, app, presets=("home",), chain=None, activate="home")
    app.FAILOVER_CONF.unlink()
    _fo_e2e(monkeypatch, app, ok=False, error="x")
    fo.cycle()
    assert fo.hot is False


def test_failover_hot_cleared_by_stop_marker(client, app, monkeypatch):
    fo = _fo_setup(client, app)
    _fo_e2e(monkeypatch, app, ok=False, error="x")
    fo.cycle()
    assert fo.hot is True
    app.STOP_MARKER.parent.mkdir(parents=True, exist_ok=True)
    app.STOP_MARKER.write_text("")
    fo.cycle()                                   # пауза — частить незачем
    assert fo.hot is False and fo.idle_reason == "прокси остановлен вручную"
    app.STOP_MARKER.unlink()


def test_failover_fast_min_two_seconds(conf_env):
    conf_env.write_text('NAIVEPANEL_FAILOVER_INTERVAL="60"\n'
                        'NAIVEPANEL_FAILOVER_FAST="1"\n')
    m = _reload()
    assert m.FAILOVER_INTERVAL == 60
    assert m.FAILOVER_FAST == 2                  # минимум 2с


def test_failover_fast_not_longer_than_interval(conf_env):
    # отдельный тест: panel.conf применяется через setdefault, в рамках
    # одного теста второй reload не перезапишет уже установленную переменную
    conf_env.write_text('NAIVEPANEL_FAILOVER_INTERVAL="20"\n'
                        'NAIVEPANEL_FAILOVER_FAST="60"\n')
    m = _reload()
    assert m.FAILOVER_FAST == 20                 # не длиннее обычного интервала


def test_failover_snapshot_reports_probing_fast(client, app, monkeypatch):
    fo = _fo_setup(client, app)
    _fo_e2e(monkeypatch, app, ok=False, error="x")
    fo.cycle()
    snap = fo.snapshot()
    assert snap["probing_fast"] is True and snap["fast_interval"] >= 2


def test_failover_snapshot_rechecks_stale_idle(client, app):
    # idle_reason — итог последнего цикла монитора; состояние могло измениться
    # до следующего цикла. snapshot перепроверяет динамические причины,
    # чтобы не показывать «пауза» рядом со свежим active_index
    fo = _fo_setup(client, app, presets=("home",), chain=("home",))
    fo._idle("нет активного пресета с listen")     # было до появления пресета
    assert fo.snapshot()["idle"] is None           # listen уже есть — причина устарела
    app.STOP_MARKER.parent.mkdir(parents=True, exist_ok=True)
    app.STOP_MARKER.write_text("")
    fo._idle("прокси остановлен вручную")
    assert fo.snapshot()["idle"] == "прокси остановлен вручную"  # маркер реален
    app.STOP_MARKER.unlink()
    assert fo.snapshot()["idle"] is None           # маркер сняли — пауза устарела


# --- v0.14: авто-возврат, каскад с пробой, уведомления -------------------------

def _fo_setup2(client, app, presets=("home", "backup"), chain=None,
               activate="home", auto_return=False):
    """Как _fo_setup, но с auto_return и активацией любого пресета."""
    for name in presets:
        _create(client, name=name)
    if activate:
        assert client.post(f"/api/configs/{activate}/activate",
                           headers=CSRF).status_code == 200
    app._save_json(app.FAILOVER_CONF,
                   {"enabled": True,
                    "chain": list(chain if chain is not None else presets),
                    "auto_return": auto_return})
    return app._Failover(threshold=2)


def test_failover_conf_v2_auto_return(client, app):
    _create(client, name="home")
    _create(client, name="backup")
    r = client.put("/api/failover", headers=CSRF,
                   json={"enabled": True, "chain": ["home", "backup"],
                         "auto_return": True})
    assert r.status_code == 200
    d = r.get_json()
    assert d["auto_return"] is True and d["chain"] == ["home", "backup"]
    # валидация: не-bool и авто-возврат без цепочки
    assert client.put("/api/failover", headers=CSRF,
                      json={"enabled": True, "chain": ["home"],
                            "auto_return": "yes"}).status_code == 400
    assert client.put("/api/failover", headers=CSRF,
                      json={"enabled": False, "chain": [],
                            "auto_return": True}).status_code == 400


def test_failover_put_disabled_keeps_chain(client):
    _create(client, name="home")
    _create(client, name="backup")
    r = client.put("/api/failover", headers=CSRF,
                   json={"enabled": True, "chain": ["home", "backup"]})
    assert r.status_code == 200
    r = client.put("/api/failover", headers=CSRF,
                   json={"enabled": False, "chain": ["home", "backup"]})
    assert r.status_code == 200
    d = r.get_json()
    assert d["enabled"] is False
    assert d["chain"] == ["home", "backup"]
    assert d["auto_return"] is False


def test_failover_put_validates_chain_when_disabled(client):
    _create(client, name="home")
    assert client.put("/api/failover", headers=CSRF,
                      json={"enabled": False, "chain": ["nope"]}).status_code == 404
    assert client.put("/api/failover", headers=CSRF,
                      json={"enabled": False, "chain": ["home", "home"]}).status_code == 400


def test_failover_put_rejects_non_bool_enabled(client):
    _create(client, name="home")
    r = client.put("/api/failover", headers=CSRF,
                   json={"enabled": "false", "chain": ["home"]})
    assert r.status_code == 400


def test_failover_snapshot_filters_stale_names(client, app):
    _create(client, name="home")
    app.FAILOVER_CONF.write_text(json.dumps(
        {"enabled": True, "chain": ["home", "ghost"], "auto_return": True}))
    d = client.get("/api/failover").get_json()
    assert d["chain"] == ["home"]
    assert d["enabled"] is True and d["auto_return"] is True
    assert d["monitor"] is True
    assert d["chain_max"] == 8          # предел цепочки отдаём клиенту


def test_failover_snapshot_keeps_valid_entries_from_mixed_chain(client, app):
    _create(client, name="home")
    app.FAILOVER_CONF.write_text(json.dumps(
        {"enabled": True, "chain": ["home", 5, "../etc/passwd", "BAD!"],
         "auto_return": True}))
    d = client.get("/api/failover").get_json()
    assert d["chain"] == ["home"]


def test_failover_all_stale_chain_disables(client, app):
    _create(client, name="home")
    app.FAILOVER_CONF.write_text(json.dumps(
        {"enabled": True, "chain": ["ghost1", "ghost2"], "auto_return": True}))
    d = client.get("/api/failover").get_json()
    assert d["chain"] == [] and d["enabled"] is False
    assert d["auto_return"] is False


def test_failover_disable_without_chain_keeps_chain(client):
    _create(client, name="home")
    _create(client, name="backup")
    client.put("/api/failover", headers=CSRF,
               json={"enabled": True, "chain": ["home", "backup"]})
    r = client.put("/api/failover", headers=CSRF, json={"enabled": False})
    assert r.status_code == 200
    assert r.get_json()["chain"] == ["home", "backup"]


def test_failover_rejected_put_does_not_touch_conf(client, app):
    _create(client, name="home")
    client.put("/api/failover", headers=CSRF,
               json={"enabled": True, "chain": ["home"]})
    before = app.FAILOVER_CONF.read_text()
    r = client.put("/api/failover", headers=CSRF,
                   json={"enabled": True, "chain": ["home", "ghost"]})
    assert r.status_code == 404
    assert app.FAILOVER_CONF.read_text() == before


def test_delete_preset_removes_it_from_failover_chain(client):
    _create(client, name="home")
    _create(client, name="backup")
    client.put("/api/failover", headers=CSRF,
               json={"enabled": True, "chain": ["home", "backup"],
                     "auto_return": True})
    assert client.delete("/api/configs/backup", headers=CSRF).status_code == 200
    d = client.get("/api/failover").get_json()
    assert d["chain"] == ["home"]
    assert d["enabled"] is True and d["auto_return"] is True


def test_delete_last_chain_member_disables_failover(client, app):
    _create(client, name="home")
    client.put("/api/failover", headers=CSRF,
               json={"enabled": True, "chain": ["home"], "auto_return": True})
    assert client.delete("/api/configs/home", headers=CSRF).status_code == 200
    d = client.get("/api/failover").get_json()
    assert d["chain"] == [] and d["enabled"] is False
    assert d["auto_return"] is False
    assert json.loads(app.FAILOVER_CONF.read_text()) == {
        "enabled": False, "chain": [], "auto_return": False}


def test_delete_preset_with_undecodable_failover_conf(client, app):
    _create(client, name="home")
    app.FAILOVER_CONF.parent.mkdir(parents=True, exist_ok=True)
    app.FAILOVER_CONF.write_bytes(b"\xff\xfe{broken utf-8")
    assert client.delete("/api/configs/home", headers=CSRF).status_code == 200
    assert not (app.CONF_D / "home.json").exists()


def test_delete_preset_without_failover_conf_creates_none(client, app):
    _create(client, name="home")
    assert not app.FAILOVER_CONF.exists()
    assert client.delete("/api/configs/home", headers=CSRF).status_code == 200
    assert not app.FAILOVER_CONF.exists()


def test_delete_preset_with_malformed_failover_conf_keeps_file(client, app):
    _create(client, name="home")
    app.FAILOVER_CONF.parent.mkdir(parents=True, exist_ok=True)
    app.FAILOVER_CONF.write_text("{not json")
    assert client.delete("/api/configs/home", headers=CSRF).status_code == 200
    assert app.FAILOVER_CONF.read_text() == "{not json"


def test_delete_chain_member_logs_failover_write_failure(client, app,
                                                         monkeypatch, caplog):
    _create(client, name="home")
    _create(client, name="backup")
    client.put("/api/failover", headers=CSRF,
               json={"enabled": True, "chain": ["home", "backup"]})
    before = app.FAILOVER_CONF.read_bytes()

    def boom(path, data):
        raise OSError("disk full")

    monkeypatch.setattr(app, "_save_json", boom)
    with caplog.at_level("WARNING"):
        r = client.delete("/api/configs/backup", headers=CSRF)
    assert r.status_code == 200
    assert not (app.CONF_D / "backup.json").exists()
    assert app.FAILOVER_CONF.read_bytes() == before
    assert any("failover cleanup" in rec.getMessage()
               for rec in caplog.records)


def test_failover_concurrent_puts_are_serialized(app, monkeypatch):
    setup = app.app.test_client()
    for name in ("home", "backup"):
        _create(setup, name=name)
    states = [
        {"enabled": True, "chain": ["home"], "auto_return": False},
        {"enabled": True, "chain": ["backup"], "auto_return": True},
    ]
    real_save = app._save_json
    guard = threading.Lock()
    depth = 0
    max_depth = 0
    lock_missing = []
    barrier = threading.Barrier(2)
    errors = []

    def slow_save(path, data):
        nonlocal depth, max_depth
        if not app._FAILOVER_LOCK.locked():
            lock_missing.append(True)
        with guard:
            depth += 1
            max_depth = max(max_depth, depth)
        try:
            time.sleep(0.05)  # даём второму писателю шанс войти без лока
            real_save(path, data)
        finally:
            with guard:
                depth -= 1

    def put(payload):
        try:
            c = app.app.test_client()
            barrier.wait(timeout=10)
            r = c.put("/api/failover", headers=CSRF, json=payload)
            if r.status_code != 200:
                errors.append(f"status {r.status_code}")
        except Exception as exc:  # noqa: BLE001 - любой сбой = провал теста
            errors.append(f"{type(exc).__name__}: {exc}")

    monkeypatch.setattr(app, "_save_json", slow_save)
    threads = [threading.Thread(target=put, args=(s,)) for s in states]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=15)
    assert not any(t.is_alive() for t in threads), "writer thread hung"
    assert errors == []
    assert lock_missing == []
    assert max_depth == 1
    raw = json.loads(app.FAILOVER_CONF.read_text())
    assert raw in states
    assert set(raw) == {"enabled", "chain", "auto_return"}


# --- atomic writes: уникальные tmp под конкурентную запись (REL-01) ----------

def test_save_json_concurrent_same_target(app, env, monkeypatch):
    # общий <name>.tmp превращал две параллельные записи одного target в
    # гонку: replace первого потока удалял tmp из-под второго →
    # FileNotFoundError. Barrier перед replace сталкивает потоки в этом
    # окне детерминированно.
    target = env / "state" / "shared.json"
    real_replace = os.replace
    barrier = threading.Barrier(2, timeout=5)

    def replace_at_barrier(src, dst):
        barrier.wait()
        return real_replace(src, dst)

    monkeypatch.setattr(os, "replace", replace_at_barrier)
    errors = []

    def worker(value):
        try:
            app._save_json(target, {"value": value})
        except Exception as exc:  # noqa: BLE001 - любой сбой = провал теста
            errors.append(f"{type(exc).__name__}: {exc}")

    threads = [threading.Thread(target=worker, args=(v,)) for v in (1, 2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)
    assert not any(t.is_alive() for t in threads), "writer thread hung"
    assert errors == []
    assert json.loads(target.read_text())["value"] in (1, 2)
    # tmp-файлов не осталось, права — секретные 0600
    assert sorted(p.name for p in target.parent.iterdir()) == ["shared.json"]
    assert target.stat().st_mode & 0o777 == 0o600


def test_save_json_replace_failure_keeps_target_and_tmp_clean(app, env, monkeypatch):
    # ошибка до replace: прежний файл нетронут, мусорный tmp убран
    target = env / "state" / "cfg.json"
    app._save_json(target, {"value": "old"})
    monkeypatch.setattr(
        os, "replace", lambda *a: (_ for _ in ()).throw(OSError("ro fs")))
    with pytest.raises(OSError):
        app._save_json(target, {"value": "new"})
    assert json.loads(target.read_text())["value"] == "old"
    assert sorted(p.name for p in target.parent.iterdir()) == ["cfg.json"]


def test_delete_preset_rewrites_failover_chain_on_disk(client, app):
    _create(client, name="home")
    _create(client, name="backup")
    client.put("/api/failover", headers=CSRF,
               json={"enabled": True, "chain": ["home", "backup"],
                     "auto_return": True})
    assert client.delete("/api/configs/backup", headers=CSRF).status_code == 200
    raw = json.loads(app.FAILOVER_CONF.read_text())
    assert raw == {"enabled": True, "chain": ["home"], "auto_return": True}
    # пересоздание пресета с тем же именем не должно молча взвести цепочку
    _create(client, name="backup")
    assert client.get("/api/failover").get_json()["chain"] == ["home"]


def test_delete_preset_reaps_stale_chain_names(client, app):
    _create(client, name="home")
    _create(client, name="backup")
    app.FAILOVER_CONF.write_text(json.dumps(
        {"enabled": True, "chain": ["home", "backup", "ghost"],
         "auto_return": True}))
    assert client.delete("/api/configs/backup", headers=CSRF).status_code == 200
    stored = json.loads(app.FAILOVER_CONF.read_text())
    assert stored["chain"] == ["home"]
    assert stored["enabled"] is True and stored["auto_return"] is True
    # пересоздание stale-имени не должно взвести его обратно
    _create(client, name="ghost")
    assert client.get("/api/failover").get_json()["chain"] == ["home"]


def test_delete_preset_outside_chain_keeps_failover_conf(client, app):
    _create(client, name="home")
    _create(client, name="other")
    client.put("/api/failover", headers=CSRF,
               json={"enabled": True, "chain": ["home"], "auto_return": True})
    before = app.FAILOVER_CONF.read_bytes()
    assert client.delete("/api/configs/other", headers=CSRF).status_code == 200
    assert app.FAILOVER_CONF.read_bytes() == before


def test_failover_monitor_flag_from_env(conf_env, monkeypatch):
    monkeypatch.setenv("NAIVEPANEL_FAILOVER", "0")
    m = _reload()
    m.CONF_D.mkdir(parents=True, exist_ok=True)
    (m.CONF_D / "home.json").write_text(json.dumps(
        {"name": "home", "listen": "127.0.0.1:1080"}))
    m.FAILOVER_CONF.write_text(json.dumps(
        {"enabled": True, "chain": ["home"], "auto_return": True}))
    d = m.app.test_client().get("/api/failover").get_json()
    assert d["monitor"] is False and d["enabled"] is False
    assert d["auto_return"] is False


def test_auto_return_after_streak_and_probe(client, app, monkeypatch):
    # активен backup; upstream основного ожил: 3 ok-цикла копят стрик,
    # на третьем — проба живым naive и активация основного
    fo = _fo_setup2(client, app, presets=("home", "backup"),
                    activate="backup", auto_return=True)
    monkeypatch.setattr(app, "FAILOVER_RETURN_ALIVE", 3)
    _fo_e2e(monkeypatch, app, ok=True)
    monkeypatch.setattr(app, "_tcp_probe", lambda h, p, timeout=3.0: 5)
    monkeypatch.setattr(app, "_probe_preset",
                        lambda cfg, timeout=15.0: {"ok": True, "probe": True})
    assert fo.cycle() is None                    # стрик 1
    assert fo.cycle() is None                    # стрик 2
    ev = fo.cycle()
    assert ev["event"] == "returned" and ev["to"] == "home"
    assert app._active_name() == "home"
    assert fo.returns == 1
    snap = fo.snapshot()
    assert snap["auto_return"] is True and snap["returns"] == 1


def test_auto_return_probe_fail_sets_cooldown(client, app, monkeypatch):
    fo = _fo_setup2(client, app, presets=("home", "backup"),
                    activate="backup", auto_return=True)
    monkeypatch.setattr(app, "FAILOVER_RETURN_ALIVE", 1)
    monkeypatch.setattr(app, "_tcp_probe", lambda h, p, timeout=3.0: 5)
    probes = [{"ok": False, "error": "TLS через туннель не поднялся"},
              {"ok": True, "probe": True}]
    monkeypatch.setattr(app, "_probe_preset",
                        lambda cfg, timeout=15.0: probes.pop(0))
    _fo_e2e(monkeypatch, app, ok=True)
    ev = fo.cycle()
    assert ev["event"] == "return_probe_failed" and "TLS" in ev["error"]
    assert app._active_name() == "backup"       # не переключились
    assert fo.cycle() is None                   # cooldown: стрик готов, но ждём
    # cooldown истёк — вторая проба успешна
    fo._cooldown["home"] = 0.0
    ev = fo.cycle()
    assert ev["event"] == "returned" and ev["to"] == "home"


def test_auto_return_no_streak_no_probe(client, app, monkeypatch):
    # основной мёртв по TCP: стрик не копится, пробу не поднимаем
    fo = _fo_setup2(client, app, presets=("home", "backup"),
                    activate="backup", auto_return=True)
    monkeypatch.setattr(app, "FAILOVER_RETURN_ALIVE", 2)
    _fo_e2e(monkeypatch, app, ok=True)
    monkeypatch.setattr(app, "_tcp_probe", lambda h, p, timeout=3.0: None)
    called = []
    monkeypatch.setattr(app, "_probe_preset",
                        lambda cfg, timeout=15.0: called.append(1) or {"ok": True})
    for _ in range(4):
        assert fo.cycle() is None
    assert called == [] and app._active_name() == "backup"


def test_cascade_probes_first_alive(client, app, monkeypatch):
    # 3 пресета: home умер, dead — существующий, но не живой; переключаемся
    # на backup, минуя dead (проба живым naive перед активацией)
    for name in ("home", "dead", "backup"):
        _create(client, name=name, upstream=f"https://{name}.example.com")
    assert client.post("/api/configs/home/activate", headers=CSRF).status_code == 200
    app._save_json(app.FAILOVER_CONF,
                   {"enabled": True, "chain": ["home", "dead", "backup"],
                    "auto_return": False})
    fo = app._Failover(threshold=2)
    _fo_e2e(monkeypatch, app, ok=False, error="x")
    probed = []

    def fake_probe(cfg, timeout=10.0):
        name = "backup" if "backup" in cfg["proxy"] else "dead"
        probed.append(name)
        return {"ok": name == "backup", "probe": True}
    monkeypatch.setattr(app, "_probe_preset", fake_probe)
    fo.cycle()
    ev = fo.cycle()
    assert ev["event"] == "switched" and ev["to"] == "backup"
    assert probed == ["dead", "backup"]         # dead проверили и отвергли


def test_cascade_single_candidate_skips_probe(client, app, monkeypatch):
    # единственный запасной: скорость важнее — активируем без пробы,
    # E2E следующим тиком проверит (поведение v0.13 сохранено)
    fo = _fo_setup2(client, app, presets=("home", "backup"))
    _fo_e2e(monkeypatch, app, ok=False, error="x")
    called = []
    monkeypatch.setattr(app, "_probe_preset",
                        lambda cfg, timeout=10.0: called.append(1) or {"ok": True})
    fo.cycle()
    ev = fo.cycle()
    assert ev["event"] == "switched" and ev["to"] == "backup"
    assert called == []


class _FakeProc:
    def __init__(self, alive=True):
        self._alive = alive

    def poll(self):
        return None if self._alive else 1

    def terminate(self):
        self._alive = False

    def wait(self, timeout=None):
        return 0

    def kill(self):
        self._alive = False


def test_probe_preset_via_stub(app, monkeypatch):
    # проба поднимает naive на свободном порту — подменяем spawn, порт
    # указываем на живой socks-стаб: должен пройти полный E2E через него
    stub = _StubServer(_socks5_proxy_ok)
    monkeypatch.setattr(app, "NAIVE_BIN", Path("/bin/sh"))  # exists() ✓
    monkeypatch.setattr(app, "_free_port", lambda: stub.port)
    monkeypatch.setattr(app.subprocess, "Popen",
                        lambda *a, **kw: _FakeProc(alive=True))
    monkeypatch.setattr(app, "E2E_URL", "http://e2e.example/")
    try:
        d = app._probe_preset({"listen": "socks://127.0.0.1:1",
                               "proxy": "https://u:p@h.example"})
        assert d["ok"] is True, d
        assert d.get("probe") is True
        assert d["exit_ip"] == "198.51.100.99"
    finally:
        stub.close()


def test_probe_preset_binary_missing(app, monkeypatch):
    monkeypatch.setattr(app, "NAIVE_BIN", Path("/nonexistent/naive"))
    d = app._probe_preset({"proxy": "https://u:p@h"})
    assert d["ok"] is False and "не найден" in d["error"]


def _notify_webhook(app, url="https://example.com/hook"):
    app._notify_cfg.update({"token": "", "chat": "", "url": url})


def test_notify_dedupe_and_disabled(app):
    # без канала — тихо
    app._notify_cfg.update({"token": "", "chat": "", "url": ""})
    app._notify("e", "x")
    assert app._notify_queue.qsize() == 0
    _notify_webhook(app)
    app._notify("e1", "one")
    app._notify("e1", "spam")                    # дедуп в пределах окна
    assert list(app._notify_queue.queue) == [("e1", "one")]
    app._notify_last["e1"] = 0.0
    app._notify("e1", "two")
    assert app._notify_queue.qsize() == 2


def test_notify_send_webhook(app, monkeypatch):
    captured = {}

    def fake_run(cmd, timeout=10):
        captured["cmd"] = cmd
        captured["timeout"] = timeout
        return {"rc": 0, "stdout": "", "stderr": ""}

    _notify_webhook(app)
    monkeypatch.setattr(app, "_run", fake_run)
    app._notify_send("failover_switch", "home → backup")
    cmd = captured["cmd"]
    assert cmd[0] == "curl" and cmd[-1] == "https://example.com/hook"
    body = json.loads(cmd[cmd.index("-d") + 1])
    assert body["event"] == "failover_switch"
    assert body["text"] == "home → backup"


def test_notify_send_curl_failure_logged(app, monkeypatch):
    _notify_webhook(app)
    monkeypatch.setattr(app, "_run",
                        lambda cmd, timeout=10: {"rc": 7, "stdout": "",
                                                 "stderr": "refused"})
    app._notify_send("e", "x")   # rc!=0 → warning, не исключение


def test_notify_send_failure_does_not_raise(app):
    _notify_webhook(app, "https://127.0.0.1:1/hook")
    app._notify_send("e", "x")   # недоступный адрес → warning, не исключение


def test_notify_send_detail_success(app, monkeypatch):
    _notify_webhook(app)
    monkeypatch.setattr(app, "_run", lambda cmd, timeout=10:
                        {"rc": 0, "stdout": "", "stderr": ""})
    assert app._notify_send("e", "x", detail=True) == (True, "")


def test_notify_send_detail_disabled(app):
    app._notify_cfg.update({"token": "", "chat": "", "url": ""})
    assert app._notify_send("e", "x", detail=True) == (
        False, "уведомления не настроены")


def test_notify_send_detail_masks_webhook_url(app, monkeypatch):
    url = "https://hooks.example.com/services/T000/B000/SECRETVALUE"
    _notify_webhook(app, url)
    monkeypatch.setattr(app, "_run", lambda cmd, timeout=10:
                        {"rc": 7, "stdout": "", "stderr": f"curl: {url}"})
    ok, err = app._notify_send("e", "x", detail=True)
    assert ok is False
    assert "SECRETVALUE" not in err and "***" in err


def test_notify_send_detail_masks_telegram_token(app, monkeypatch):
    token = "123456:abcdefghijklmnopqrstuvwxyz"
    app._notify_cfg.update({"token": token, "chat": "42", "url": ""})
    monkeypatch.setattr(app, "_run", lambda cmd, timeout=10:
                        {"rc": 7, "stdout": "", "stderr": f"curl: {token}"})
    ok, err = app._notify_send("e", "x", detail=True)
    assert ok is False
    assert token not in err and "***" in err


def test_notify_channel_prefers_telegram(app):
    app._notify_cfg.update({"token": "123:abc", "chat": "42",
                            "url": "https://example.com/hook"})
    assert app._notify_channel() == "telegram"


def test_notify_disabled_is_noop(app):
    app._notify_cfg.update({"token": "", "chat": "", "url": ""})
    app._notify("e", "x")
    assert app._notify_queue.qsize() == 0


def test_notify_disabled_drops_queued_event(app):
    app._notify_cfg.update({"token": "", "chat": "", "url": ""})
    app._notify_queue.put(("e", "x"))
    app._notify_tick(timeout=0.01)
    assert app._notify_queue.qsize() == 0
    assert app._notify_pending_all() == []


def test_status_reports_notify_channel(conf_env):
    conf_env.write_text('NAIVEPANEL_NOTIFY_URL="https://example.com/hook"\n')
    m = _reload()
    assert m._notify_channel() == "webhook"
    d = m.app.test_client().get("/api/status").get_json()
    assert d["notify"] == {"enabled": True, "channel": "webhook", "pending": 0}


def test_ui_has_v014_controls(app):
    html = (APP_DIR / "templates" / "index.html").read_text(encoding="utf-8")
    for marker in ('id="foAuto"', 'id="ntInfo"', "auto_return",
                   "return_watch", "ждём возврата"):
        assert marker in html, marker


# --- Уведомления v0.14.1: через прокси → напрямую → pending -------------------

def _nt_run_capture(captured, results):
    """Фейковый _run: пишет команды; результаты по очереди."""
    def fake(cmd, timeout=10):
        captured.append(cmd)
        r = results.pop(0) if results else {"rc": 0, "stdout": "", "stderr": ""}
        return r
    return fake


def test_notify_send_via_alive_proxy(app, monkeypatch):
    # listen активного жив → первая попытка с -x socks5h (через naive)
    import socket as s
    srv = s.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(1)
    port = srv.getsockname()[1]
    app._save_json(app.ACTIVE_CONFIG,
                   {"listen": f"socks://127.0.0.1:{port}", "proxy": "https://u:p@h"})
    captured = []
    _notify_webhook(app)
    monkeypatch.setattr(app, "_run", _nt_run_capture(captured, []))
    try:
        assert app._notify_send("e", "x") is True
        assert captured[0][4] == "-x" and captured[0][5] == f"socks5h://127.0.0.1:{port}"
        assert captured[0][-1] == "https://example.com/hook"
    finally:
        srv.close()


def test_notify_send_proxy_dead_falls_back_direct(app, monkeypatch):
    # listen мёртв → сразу прямой путь, без -x
    app._save_json(app.ACTIVE_CONFIG,
                   {"listen": "socks://127.0.0.1:1", "proxy": "https://u:p@h"})
    captured = []
    _notify_webhook(app)
    monkeypatch.setattr(app, "_run", _nt_run_capture(captured, []))
    assert app._notify_send("e", "x") is True
    assert len(captured) == 1 and "-x" not in captured[0]


def test_notify_send_all_dead_returns_false(app, monkeypatch):
    app._save_json(app.ACTIVE_CONFIG,
                   {"listen": "socks://127.0.0.1:1", "proxy": "https://u:p@h"})
    captured = []
    _notify_webhook(app)
    monkeypatch.setattr(app, "_run",
                        _nt_run_capture(captured, [{"rc": 7, "stdout": "",
                                                    "stderr": "refused"}]))
    assert app._notify_send("e", "x") is False


def test_notify_pending_append_flush_and_status(app, monkeypatch):
    app._notify_pending_append("failover_switch", "дом без интернета")
    app._notify_pending_append("failover_exhausted", "всё лежит")
    items = app._notify_pending_all()
    assert [i["event"] for i in items] == ["failover_switch", "failover_exhausted"]
    # доставляем: первый успех, второй неудача → остаётся второй
    results = [{"rc": 0, "stdout": "", "stderr": ""},
               {"rc": 7, "stdout": "", "stderr": "refused"}]
    _notify_webhook(app)
    monkeypatch.setattr(app, "_run", lambda cmd, timeout=10: results.pop(0))
    app._save_json(app.ACTIVE_CONFIG,
                   {"listen": "socks://127.0.0.1:1", "proxy": "https://u:p@h"})
    assert app._notify_flush_pending() == 1
    left = app._notify_pending_all()
    assert [i["event"] for i in left] == ["failover_exhausted"]
    # статус показывает счётчик отложенных
    d = app.app.test_client().get("/api/status").get_json()
    assert d["notify"]["pending"] == 1
    # кап: 60 событий → в файле последние 50
    app.NOTIFY_PENDING.unlink()
    for i in range(60):
        app._notify_pending_append("e", f"t{i}")
    assert len(app._notify_pending_all()) == 50
    assert app._notify_pending_all()[-1]["text"] == "t59"


# --- Настройка Telegram из панели --------------------------------------------

def test_ui_has_telegram_controls(app):
    html = (APP_DIR / "templates" / "index.html").read_text(encoding="utf-8")
    for marker in (
            'id="tgForm"', 'id="tgToken"', 'id="tgChat"', 'id="tgMsg"',
            # токен именно замаскирован (type="password" есть и в других полях)
            'type="password" id="tgToken"',
            # и не подставляется автозаполнением браузера
            'id="tgToken" autocomplete="off"',
            # кнопки теста/отключения скрыты, пока канал не настроен
            'data-action="tgTest" hidden', 'data-action="tgOff" hidden',
            # проводка в ACTIONS (inline-обработчики запрещены CSP)
            'tgTest: () => testTelegram()', 'tgOff: () => offTelegram()',
            # поллинг статуса не затирает chat_id, пока его правят
            "document.activeElement !== $('tgChat')",
            # подсказка ntInfo ведёт в раздел, а не только в panel.conf
            'Уведомления: настраиваются ниже',
    ):
        assert marker in html, marker


def test_notify_telegram_save_and_get(conf_env, monkeypatch):
    conf_env.write_text('# keep me\nNAIVEPANEL_BIND="127.0.0.1:8089"\n')
    monkeypatch.setenv("NAIVEPANEL_CONF", str(conf_env))
    m = _reload()
    # настоящий _tg_bot_name кэширует сам; заглушка повторяет контракт
    def fake_bot(token):
        m._bot_cache[token] = ("@testbot", time.monotonic() + 3600)
        return "@testbot"

    monkeypatch.setattr(m, "_tg_bot_name", fake_bot)
    c = m.app.test_client()
    token = "123456:abcdefghijklmnopqrstuvwxyz"
    r = c.post("/api/notify/telegram", json={"token": token, "chat_id": "42"},
               headers=CSRF)
    assert r.status_code == 200
    stored = conf_env.read_text()
    assert "# keep me" in stored and 'NAIVEPANEL_BIND="127.0.0.1:8089"' in stored
    assert f'NAIVEPANEL_TG_TOKEN="{token}"' in stored
    assert 'NAIVEPANEL_TG_CHAT="42"' in stored
    assert m._notify_channel() == "telegram"

    d = c.get("/api/notify").get_json()
    assert token not in json.dumps(d)
    assert d["telegram"] == {"configured": True, "chat_id": "42",
                             "bot": "@testbot"}


def test_notify_telegram_empty_token_keeps_existing(conf_env, monkeypatch):
    monkeypatch.setenv("NAIVEPANEL_CONF", str(conf_env))
    m = _reload()
    monkeypatch.setattr(m, "_tg_bot_name", lambda token: None)
    token = "123:abcdefghijklmnopqrstuvwxyz"
    m._notify_cfg.update({"token": token, "chat": "42", "url": ""})
    c = m.app.test_client()
    assert c.post("/api/notify/telegram",
                  json={"token": "", "chat_id": "-100123456"},
                  headers=CSRF).status_code == 200
    assert m._notify_snapshot()["token"] == token
    assert m._notify_snapshot()["chat"] == "-100123456"


def test_notify_telegram_delete_disables_and_clears_pending(conf_env, monkeypatch):
    conf_env.write_text('NAIVEPANEL_TG_TOKEN="123:abcdefghijklmnopqrstuvwxyz"\n'
                        'NAIVEPANEL_TG_CHAT="42"\n')
    monkeypatch.setenv("NAIVEPANEL_CONF", str(conf_env))
    m = _reload()
    m._notify_pending_append("e", "stale")
    m._notify_queue.put(("e", "queued"))
    c = m.app.test_client()
    assert c.delete("/api/notify/telegram", headers=CSRF).status_code == 200
    assert "NAIVEPANEL_TG_TOKEN" not in conf_env.read_text()
    assert m._notify_channel() is None
    assert m._notify_pending_all() == []
    assert m._notify_queue.qsize() == 0


def test_notify_telegram_delete_keeps_webhook_pending(conf_env, monkeypatch):
    conf_env.write_text(
        'NAIVEPANEL_TG_TOKEN="123456:abcdefghijklmnopqrstuvwxyz"\n'
        'NAIVEPANEL_TG_CHAT="42"\n'
        'NAIVEPANEL_NOTIFY_URL="https://example.com/hook"\n')
    monkeypatch.setenv("NAIVEPANEL_CONF", str(conf_env))
    m = _reload()
    m._notify_pending_append("e", "keep")
    m._notify_queue.put(("e", "keep"))
    c = m.app.test_client()
    assert c.delete("/api/notify/telegram", headers=CSRF).status_code == 200
    assert m._notify_channel() == "webhook"
    assert m._notify_pending_all() != []
    assert m._notify_queue.qsize() == 1


def test_notify_telegram_save_reports_conf_write_failure(conf_env, monkeypatch):
    monkeypatch.setenv("NAIVEPANEL_CONF", str(conf_env))
    m = _reload()
    monkeypatch.setattr(m.tempfile, "mkstemp",
                        lambda *a, **k: (_ for _ in ()).throw(OSError("ro")))
    c = m.app.test_client()
    r = c.post("/api/notify/telegram",
               json={"token": "123456:abcdefghijklmnopqrstuvwxyz",
                     "chat_id": "42"}, headers=CSRF)
    assert r.status_code == 500
    assert "panel.conf" in r.get_json()["error"]
    assert m._notify_channel() is None


def test_notify_telegram_validation(conf_env, monkeypatch):
    monkeypatch.setenv("NAIVEPANEL_CONF", str(conf_env))
    m = _reload()
    monkeypatch.setattr(m, "_tg_bot_name", lambda token: None)
    c = m.app.test_client()
    good = "123456:abcdefghijklmnopqrstuvwxyz"
    assert c.post("/api/notify/telegram", json={"token": "bad", "chat_id": "42"},
                  headers=CSRF).status_code == 400
    assert c.post("/api/notify/telegram",
                  json={"token": good,
                        "chat_id": "not a chat"}, headers=CSRF).status_code == 400
    # арабо-индийские цифры не считаем числом: только ASCII [0-9]
    assert c.post("/api/notify/telegram",
                  json={"token": "١٢٣٤٥:abcdefghijklmnopqrstuvwxyz",
                        "chat_id": "42"}, headers=CSRF).status_code == 400
    # слишком длинный chat_id не пройдёт
    assert c.post("/api/notify/telegram",
                  json={"token": good, "chat_id": "1" * 30},
                  headers=CSRF).status_code == 400
    for chat in ("42", "-100123456", "@mychannel"):
        assert c.post("/api/notify/telegram",
                      json={"token": good, "chat_id": chat},
                      headers=CSRF).status_code == 200


def test_notify_mutations_blocked_without_auth_off_loopback(client, app, monkeypatch):
    monkeypatch.setattr(app.cfg, "_bind_is_loopback", lambda: False)
    r = client.post("/api/notify/telegram",
                    json={"token": "123:abcdefghijklmnopqrstuvwxyz",
                          "chat_id": "42"}, headers=CSRF)
    assert r.status_code == 403


def _notify_send_stub(calls, result=(True, "")):
    """Заглушка _notify_send: фиксирует вызов и требует detail=True."""
    def stub(event, text, detail=False):
        assert detail is True
        calls.append(event)
        return result
    return stub


def test_notify_test_sends_and_rate_limits(app, monkeypatch):
    app._notify_cfg.update({"token": "123456:abcdefghijklmnopqrstuvwxyz",
                            "chat": "42", "url": ""})
    app._notify_test_last = 0.0
    calls = []
    monkeypatch.setattr(app, "_notify_send", _notify_send_stub(calls))
    c = app.app.test_client()
    assert c.post("/api/notify/test", headers=CSRF).status_code == 200
    assert calls == ["test"]
    r = c.post("/api/notify/test", headers=CSRF)
    assert r.status_code == 429
    err = r.get_json()["error"]
    assert "не чаще" in err
    assert "уже отправлено" not in err


def test_notify_test_reports_telegram_error(app, monkeypatch):
    app._notify_cfg.update({"token": "123456:abcdefghijklmnopqrstuvwxyz",
                            "chat": "42", "url": ""})
    app._notify_test_last = 0.0
    monkeypatch.setattr(app, "_notify_send",
                        _notify_send_stub([], (False, "chat not found")))
    c = app.app.test_client()
    r = c.post("/api/notify/test", headers=CSRF)
    assert r.status_code == 502
    assert "chat not found" in r.get_json()["error"]
    # неудачная доставка тоже сжигает окно: сразу повторять нельзя
    assert c.post("/api/notify/test", headers=CSRF).status_code == 429


def test_notify_test_requires_channel(app):
    app._notify_cfg.update({"token": "", "chat": "", "url": ""})
    c = app.app.test_client()
    assert c.post("/api/notify/test", headers=CSRF).status_code == 409


def test_notify_test_blocked_without_auth_off_loopback(client, app, monkeypatch):
    monkeypatch.setattr(app.cfg, "_bind_is_loopback", lambda: False)
    r = client.post("/api/notify/test", headers=CSRF)
    assert r.status_code == 403


def test_notify_test_throttle_resets_on_reconfigure(conf_env, monkeypatch):
    token = "123456:abcdefghijklmnopqrstuvwxyz"
    monkeypatch.setenv("NAIVEPANEL_CONF", str(conf_env))
    m = _reload()
    monkeypatch.setattr(m, "_tg_bot_name", lambda token: None)
    m._notify_cfg.update({"token": token, "chat": "42", "url": ""})
    m._notify_test_last = 0.0
    calls = []
    monkeypatch.setattr(m, "_notify_send", _notify_send_stub(calls))
    c = m.app.test_client()
    assert c.post("/api/notify/test", headers=CSRF).status_code == 200
    assert c.post("/api/notify/test", headers=CSRF).status_code == 429
    # пересохранение конфига сбрасывает окно → тест сразу разрешён
    r = c.post("/api/notify/telegram", json={"token": token, "chat_id": "42"},
               headers=CSRF)
    assert r.status_code == 200
    assert c.post("/api/notify/test", headers=CSRF).status_code == 200
    assert c.post("/api/notify/test", headers=CSRF).status_code == 429
    # удаление тоже сбрасывает окно; канал возвращаем в runtime напрямую,
    # чтобы не проходить через save и проверить именно DELETE
    assert c.delete("/api/notify/telegram", headers=CSRF).status_code == 200
    m._notify_cfg.update({"token": token, "chat": "42", "url": ""})
    assert c.post("/api/notify/test", headers=CSRF).status_code == 200


def test_notify_save_warns_when_env_wins(conf_env, monkeypatch):
    monkeypatch.setenv("NAIVEPANEL_CONF", str(conf_env))
    monkeypatch.setenv("NAIVEPANEL_TG_TOKEN", "999:fromenvironment0000000000")
    m = _reload()
    monkeypatch.setattr(m, "_tg_bot_name", lambda token: None)
    c = m.app.test_client()
    r = c.post("/api/notify/telegram",
               json={"token": "123456:abcdefghijklmnopqrstuvwxyz",
                     "chat_id": "42"}, headers=CSRF)
    assert r.status_code == 200
    assert r.get_json()["warning"]


def test_notify_conf_upsert_removes_duplicate_keys(conf_env, monkeypatch):
    conf_env.write_text('NAIVEPANEL_TG_TOKEN="old1"\n'
                        'NAIVEPANEL_TG_TOKEN="old2"\n')
    monkeypatch.setenv("NAIVEPANEL_CONF", str(conf_env))
    m = _reload()
    token = "123456:abcdefghijklmnopqrstuvwxyz"
    r = m.app.test_client().post("/api/notify/telegram",
                                 json={"token": token, "chat_id": "42"},
                                 headers=CSRF)
    assert r.status_code == 200
    stored = conf_env.read_text()
    assert stored.count("NAIVEPANEL_TG_TOKEN") == 1
    assert token in stored and "old1" not in stored and "old2" not in stored


def test_notify_conf_upsert_delete_removes_duplicates(conf_env, monkeypatch):
    conf_env.write_text('NAIVEPANEL_TG_TOKEN="old1"\n'
                        'NAIVEPANEL_TG_TOKEN="old2"\n')
    monkeypatch.setenv("NAIVEPANEL_CONF", str(conf_env))
    m = _reload()
    m._conf_upsert({"NAIVEPANEL_TG_TOKEN": None})
    assert "NAIVEPANEL_TG_TOKEN" not in conf_env.read_text()


def test_notify_telegram_save_sets_0600(conf_env, monkeypatch):
    conf_env.write_text('NAIVEPANEL_BIND="127.0.0.1:8089"\n')
    conf_env.chmod(0o644)
    monkeypatch.setenv("NAIVEPANEL_CONF", str(conf_env))
    m = _reload()
    monkeypatch.setattr(m, "_tg_bot_name", lambda token: None)
    r = m.app.test_client().post(
        "/api/notify/telegram",
        json={"token": "123456:abcdefghijklmnopqrstuvwxyz", "chat_id": "42"},
        headers=CSRF)
    assert r.status_code == 200
    assert (conf_env.stat().st_mode & 0o777) == 0o600


def test_notify_telegram_delete_warns_when_env_wins(conf_env, monkeypatch):
    monkeypatch.setenv("NAIVEPANEL_CONF", str(conf_env))
    monkeypatch.setenv("NAIVEPANEL_TG_TOKEN", "999:fromenvironment0000000000")
    m = _reload()
    r = m.app.test_client().delete("/api/notify/telegram", headers=CSRF)
    assert r.status_code == 200
    assert r.get_json()["warning"]
    monkeypatch.delenv("NAIVEPANEL_TG_TOKEN")
    m = _reload()
    r = m.app.test_client().delete("/api/notify/telegram", headers=CSRF)
    assert r.get_json()["warning"] is None


def test_conf_upsert_concurrent_saves_use_unique_temps(conf_env, monkeypatch):
    conf_env.write_text('NAIVEPANEL_BIND="127.0.0.1:8089"\n')
    monkeypatch.setenv("NAIVEPANEL_CONF", str(conf_env))
    m = _reload()
    barrier = threading.Barrier(2, timeout=10)
    real_replace = os.replace

    def synced_replace(src, dst):
        barrier.wait()  # оба потока уже записали свой temp
        return real_replace(src, dst)

    monkeypatch.setattr(m.os, "replace", synced_replace)
    errors = []

    def save(key):
        try:
            m._conf_upsert({key: "1"})
        except Exception as exc:  # noqa: BLE001 — тест ловит любой сбой
            errors.append(exc)

    threads = [threading.Thread(target=save, args=(k,))
               for k in ("NAIVEPANEL_TG_TOKEN", "NAIVEPANEL_TG_CHAT")]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=15)
    assert errors == []
    assert not list(conf_env.parent.glob(".panel.conf.*"))


def test_tg_bot_name_non_dict_result(app, monkeypatch):
    for raw in ('{"result": []}', "[]", "null"):
        monkeypatch.setattr(app, "_http_get",
                            lambda url, timeout=5, _r=raw: _r)
        app._bot_cache.clear()
        assert app._tg_bot_name("123456:abcdefghijklmnopqrstuvwxyz") is None


# --- Rollback: откат панели и бинарника из бэкапов ----------------------------

def _rb_env_reload(env, monkeypatch):
    """Env для откатов панели: init-пути с РАЗНЫМИ именами (в базовой фикстуре
    оба absent-init.sh — имена бы склеились в бэкапе) + reload."""
    monkeypatch.setenv("NAIVEPANEL_INIT", str(env / "pinit.sh"))
    monkeypatch.setenv("NAIVEPROXY_INIT", str(env / "ninit.sh"))
    return _reload()


def _rb_make_backup(m, version, code="# old panel code", tmpl="old-tpl"):
    """Каталог backup/vX.Y.Z с файлами, как их пишет self-update."""
    backup = m.PANEL_DIR / "backup" / version
    backup.mkdir(parents=True, exist_ok=True)
    (backup / "naivepanel.py").write_text(code)
    (backup / "index.html").write_text(tmpl)
    (backup / m.PANEL_INIT.name).write_text("#!/bin/sh\n# panel init v old\n")
    return backup


def _rb_make_panel(m, code="# current panel code"):
    (m.PANEL_DIR / "templates").mkdir(parents=True, exist_ok=True)
    (m.PANEL_DIR / "naivepanel.py").write_text(code)
    (m.PANEL_DIR / "templates" / "index.html").write_text("cur-tpl")


def test_rollback_get_lists_versions_sorted_and_skips_junk(client, app):
    _rb_make_backup(app, "v0.9.0", code="a" * 10)
    _rb_make_backup(app, "v0.14.0", code="b" * 20)
    junk = app.PANEL_DIR / "backup" / "trash"
    junk.mkdir(parents=True)
    (app.PANEL_DIR / "backup" / "stray.file").write_text("x")
    d = client.get("/api/rollback").get_json()
    assert d["current"] == app.APP_VERSION
    assert [v["version"] for v in d["panel"]] == ["v0.14.0", "v0.9.0"]  # новые сверху
    assert d["panel"][0]["size"] > d["panel"][1]["size"]
    assert all(v["ts"] > 0 for v in d["panel"])
    assert d["binary"] == {"present": False, "tag": None, "size": 0}


def test_rollback_get_binary_with_and_without_tag(app):
    prev = app.NAIVEPROXY_DIR / "backup" / "naive.previous"
    prev.parent.mkdir(parents=True, exist_ok=True)
    prev.write_bytes(b"\x00binary")
    d = app.app.test_client().get("/api/rollback").get_json()
    assert d["binary"]["present"] is True
    assert d["binary"]["tag"] is None          # старый бэкап без тега
    assert d["binary"]["size"] == 7
    (app.NAIVEPROXY_DIR / "backup" / "naive.previous.tag").write_text(
        "v113.0.5672.3-1\n")
    d = app.app.test_client().get("/api/rollback").get_json()
    assert d["binary"]["tag"] == "v113.0.5672.3-1"


def test_rollback_panel_restores_files_backs_up_current_and_restarts(
        client, app, env, monkeypatch):
    m = _rb_env_reload(env, monkeypatch)
    c = m.app.test_client()
    _rb_make_panel(m, code="# current panel code")
    _rb_make_backup(m, "v0.9.0", code="# old panel code", tmpl="old-tpl")
    stub, marker = _stub_init(env, "rb-restarts.txt")
    monkeypatch.setattr(m, "PANEL_INIT", stub)
    # INIT_SCRIPT тоже возвращается: своё имя, свой файл
    ninit = env / "ninit.sh"
    (m.PANEL_DIR / "backup" / "v0.9.0" / "ninit.sh").write_text("# naive init old\n")

    r = c.post("/api/rollback", json={"panel": "v0.9.0"}, headers=CSRF)
    assert r.status_code == 202, r.get_json()
    body = r.get_json()
    assert body["target"] == "v0.9.0" and body["current"] == m.APP_VERSION
    assert sorted(body["restored"]) == ["index.html", "naivepanel.py",
                                        "ninit.sh", "pinit.sh"]
    # файлы вернулись старым содержимым
    assert (m.PANEL_DIR / "naivepanel.py").read_text() == "# old panel code"
    assert (m.PANEL_DIR / "templates" / "index.html").read_text() == "old-tpl"
    assert ninit.read_text() == "# naive init old\n"
    # откат обратим: текущая версия тоже ушла в бэкап
    cur = m.PANEL_DIR / "backup" / f"v{m.APP_VERSION}" / "naivepanel.py"
    assert cur.read_text() == "# current panel code"
    # state + лог — как у update: поднятая старая панель закроет «running»
    st = json.loads(m.UPDATE_STATE.read_text())
    assert st["phase"] == "running" and st["target"] == "v0.9.0"
    assert st["rollback"] is True and st["pid"] > 0
    assert m.UPDATE_LOG.read_text().startswith("== rollback")
    # рестартер отсоединён — ждём маркер, как existing-тесты установщика
    for _ in range(50):
        if marker.exists():
            break
        time.sleep(0.1)
    assert marker.read_text().strip() == "restart"


def test_rollback_panel_404_on_unknown_version(client, app):
    assert client.post("/api/rollback", json={"panel": "v9.9.9"},
                       headers=CSRF).status_code == 404


def test_rollback_panel_rejects_bad_names_and_current(client, app):
    for bad in ("../etc", "v0.9", "main", ""):
        r = client.post("/api/rollback", json={"panel": bad}, headers=CSRF)
        assert r.status_code == 400, bad
    # своя версия — не откат
    _rb_make_backup(app, f"v{app.APP_VERSION}")
    r = client.post("/api/rollback", json={"panel": f"v{app.APP_VERSION}"},
                    headers=CSRF)
    assert r.status_code == 400
    assert "already running" in r.get_json()["error"]


def test_rollback_panel_409_while_update_running(client, app, monkeypatch):
    _rb_make_backup(app, "v0.9.0")
    app._update_state_write({"phase": "running", "target": "v9.9.9",
                             "started": time.time(), "pid": os.getpid()})
    r = client.post("/api/rollback", json={"panel": "v0.9.0"}, headers=CSRF)
    assert r.status_code == 409
    assert "in progress" in r.get_json()["error"]


def test_rollback_panel_503_without_panel_init(client, app, monkeypatch):
    _rb_make_backup(app, "v0.9.0")
    # init-путь базовой фикстуры (absent-init.sh) не существует
    r = client.post("/api/rollback", json={"panel": "v0.9.0"}, headers=CSRF)
    assert r.status_code == 503


def test_rollback_refuses_exposed_panel_without_password(client, app, monkeypatch):
    _rb_make_backup(app, "v0.9.0")
    app.cfg.PANEL_BIND = "192.168.1.1:8089"  # admin.pass не существует (fixture)
    r = client.post("/api/rollback", json={"panel": "v0.9.0"}, headers=CSRF)
    assert r.status_code == 403
    assert "password" in r.get_json()["error"]
    # бинарник — тот же гейт
    r = client.post("/api/rollback", json={"binary": True}, headers=CSRF)
    assert r.status_code == 403


def _rb_naive_setup(env, monkeypatch, prev_tag=None):
    """Бинарник + naive.previous (+ опц. тег) в отдельном env."""
    m = _naive_env_reload(env, monkeypatch)
    cur = env / "naive"
    cur.write_text('#!/bin/sh\necho "naive 154.0.8037.49"\n')
    cur.chmod(0o755)
    m.NAIVE_TAG.write_text("v154.0.8037.49-2\n")
    prev = m.NAIVEPROXY_DIR / "backup" / "naive.previous"
    prev.parent.mkdir(parents=True, exist_ok=True)
    prev.write_text('#!/bin/sh\necho "naive 113.0.5672.3"\n')
    prev.chmod(0o755)
    if prev_tag is not None:
        (m.NAIVEPROXY_DIR / "backup" / "naive.previous.tag").write_text(
            prev_tag + "\n")
    return m


def test_rollback_binary_restores_previous(client, env, monkeypatch):
    m = _rb_naive_setup(env, monkeypatch, prev_tag="v113.0.5672.3-1")
    stub, marker = _stub_init(env, "rb-naive-restarts.txt")
    monkeypatch.setattr(m, "INIT_SCRIPT", stub)
    # «работающий» прокси — как в тестах воркера обновления
    m.PID_FILE.parent.mkdir(parents=True, exist_ok=True)
    m.PID_FILE.write_text(str(os.getpid()))
    monkeypatch.setattr(m, "_pid_is_naive", lambda pid: True)

    r = m.app.test_client().post("/api/rollback", json={"binary": True},
                                 headers=CSRF)
    assert r.status_code == 200, r.get_json()
    body = r.get_json()
    assert body["restored"] == "v113.0.5672.3-1"
    assert body["version"] == "naive 113.0.5672.3"
    assert body["restarted"] is True
    # бинарник реально заменён, тег вернулся, мусора .new нет
    assert m._naive_bin_version() == "113.0.5672.3"
    assert m.NAIVE_TAG.read_text().strip() == "v113.0.5672.3-1"
    assert not (env / "naive.new").exists()
    assert marker.read_text().strip() == "restart"
    st = m._naive_state_read()
    assert st["phase"] == "done" and st["rollback"] is True


def test_rollback_binary_failed_restart_not_reported_as_restarted(client, env,
                                                                  monkeypatch):
    # бинарник заменён, но рестарт упал: restarted=true врал бы, что всё ок
    m = _rb_naive_setup(env, monkeypatch, prev_tag="v113.0.5672.3-1")
    stub = env / "rb-fail-init.sh"
    stub.write_text('#!/bin/sh\necho "boom" >&2\nexit 7\n')
    stub.chmod(0o755)
    monkeypatch.setattr(m, "INIT_SCRIPT", stub)
    m.PID_FILE.parent.mkdir(parents=True, exist_ok=True)
    m.PID_FILE.write_text(str(os.getpid()))
    monkeypatch.setattr(m, "_pid_is_naive", lambda pid: True)

    r = m.app.test_client().post("/api/rollback", json={"binary": True},
                                 headers=CSRF)
    assert r.status_code == 200, r.get_json()
    body = r.get_json()
    assert body["restarted"] is False  # рестарт упал — не выдаём за успех
    assert body["restart_rc"] == 7     # бинарник-то заменён: rc виден явно
    assert m._naive_bin_version() == "113.0.5672.3"
    st = m._naive_state_read()
    assert st["phase"] == "done"       # замена бинарника состоялась
    assert st["restarted"] is False
    assert st["restart_rc"] == 7


# --- integrity обновлений: tar members + непропускаемый checksum (SEC-03) ------

def _evil_tarball(path: Path, evil) -> None:
    """Нормальный naive-тарболл + один вредоносный member."""
    import io
    import tarfile
    data = b"#!/bin/sh\necho 'naive 154.0.8037.49'\n"
    with tarfile.open(path, "w:xz") as tf:
        info = tarfile.TarInfo("naiveproxy-v154.0.8037.49-2-openwrt-x86_64/naive")
        info.mode = 0o755
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
        tf.addfile(evil)


def test_naive_update_rejects_unsafe_tar_members(client, app, env, monkeypatch):
    import tarfile
    escape = tarfile.TarInfo("../escaped")       # size 0 — для проверки пути хватит
    absolute = tarfile.TarInfo("/etc/absolute-pwn")
    symlink = tarfile.TarInfo("naiveproxy-v154/link")
    symlink.type = tarfile.SYMTYPE
    symlink.linkname = "/etc/passwd"
    cases = [
        (escape, "unsafe archive path"),
        (absolute, "unsafe archive path"),
        (symlink, "unsupported archive member"),
    ]
    for evil, want in cases:
        m = _naive_env_reload(env, monkeypatch)
        old = env / "naive"
        old.write_text('#!/bin/sh\necho "naive 113.0.5672.3"\n')
        old.chmod(0o755)
        m.NAIVE_TAG.write_text("v113.0.5672.3-1\n")
        m.NAIVE_BUILD.write_text("x86_64\n")
        _evil_tarball(env / "evil.tar.xz", evil)
        url, stop = _serve_tarball(env / "evil.tar.xz")
        try:
            _naive_rel(monkeypatch, m,
                       assets=(("naiveproxy-v154.0.8037.49-2-openwrt-x86_64.tar.xz",
                                url),))
            assert m.app.test_client().post("/api/naive/update",
                                            headers=CSRF).status_code == 202
            st = _naive_done(m)
        finally:
            stop()
        assert st["phase"] == "failed", st
        assert want in st["error"], st["error"]
        # вне stage ничего не создано, рабочий бинарник не тронут
        assert not (env / "escaped").exists()
        assert not (env / "etc").exists()
        assert m._naive_bin_version() == "113.0.5672.3"


def test_install_sh_checksum_cannot_be_skipped(app):
    # ветка «sha256sum not found — skipping» открывала установку без
    # integrity-проверки: обязана исчезнуть (fail-closed)
    src = (APP_DIR / "install.sh").read_text(encoding="utf-8")
    assert "skipping checksum verification" not in src
    assert "cannot verify SHA256SUMS" in src


# --- права panel.conf + PID identity в init-скриптах (SEC-04/05) ---------------

def test_install_sh_creates_private_panel_conf(app):
    # в panel.conf живут токены уведомлений: свежий файл не должен получать
    # group/other-readable 0644
    src = (APP_DIR / "install.sh").read_text(encoding="utf-8")
    assert 'chmod 0644 "$PANEL_CONF"' not in src
    m = re.search(r'chmod (\d+) "\$PANEL_CONF"', src)
    assert m, "chmod panel.conf не найден в install.sh"
    assert int(m.group(1), 8) & 0o077 == 0, "panel.conf: биты group/other должны быть сняты"


def test_notify_conf_upsert_keeps_private_mode(conf_env, monkeypatch):
    # Telegram save/delete не должен открывать panel.conf миру
    monkeypatch.setenv("NAIVEPANEL_CONF", str(conf_env))
    m = _reload()
    m._conf_upsert({"NAIVEPANEL_TG_TOKEN": "123456:abcdefghijklmnopqrstuvwxyz"})
    assert m.PANEL_CONF.stat().st_mode & 0o777 == 0o600
    m._conf_upsert({"NAIVEPANEL_TG_TOKEN": None})
    assert m.PANEL_CONF.stat().st_mode & 0o777 == 0o600


def _init_src(name: str) -> str:
    return (APP_DIR / name).read_text(encoding="utf-8")


def test_s99naiveproxy_checks_pid_identity(app):
    # kill -0 подтверждает лишь существование процесса: переиспользованный
    # pid нельзя TERM/KILL — сверяем comm через /proc
    src = _init_src("S99naiveproxy")
    assert "pid_is_ours" in src, "нет проверки identity pid"
    m = re.search(r"pid_is_ours\(\) \{(.*?)\n\}", src, re.S)
    assert m, "pid_is_ours() не найден"
    body = m.group(1)
    assert "/proc" in body and "naiveproxy" in body
    # running() обязан отвергать чужой pid
    m = re.search(r"running\(\) \{(.*?)\n\}", src, re.S)
    assert m and "pid_is_ours" in m.group(1), "running() не проверяет identity"


def test_s99naivepanel_checks_pid_identity(app):
    # comm у панели — python3: сверяем cmdline на naivepanel.py
    src = _init_src("S99naivepanel")
    assert "pid_is_ours" in src, "нет проверки identity pid"
    m = re.search(r"pid_is_ours\(\) \{(.*?)\n\}", src, re.S)
    assert m, "pid_is_ours() не найден"
    body = m.group(1)
    # в grep-паттерне точка экранирована: naivepanel\.py
    assert "cmdline" in body and "naivepanel\\.py" in body
    m = re.search(r"running\(\) \{(.*?)\n\}", src, re.S)
    assert m and "pid_is_ours" in m.group(1), "running() не проверяет identity"


def test_init_scripts_stop_does_not_hide_survivor(app):
    # процесс пережил TERM и KILL (D-state) — pidfile нельзя молча удалять,
    # будто всё остановлено
    for name in ("S99naiveproxy", "S99naivepanel"):
        src = _init_src(name)
        assert "survived" in src, f"{name}: stop не детектит выживший после KILL процесс"


# --- дорогие операции: одновременность и внешние ходы (SEC-06) ------------------

def test_expensive_limit_leaves_threads_for_cheap_routes(app):
    # семафор, равный пулу потоков waitress, ничего не защищает: дешёвые
    # роуты (статус/лог) обязаны всегда находить свободный поток
    assert app._EXPENSIVE_LIMIT <= app.WAITRESS_THREADS - 1


def test_probe_concurrency_limit_returns_429(client, app, monkeypatch):
    # залп probe держал по worker-потоку на каждый TCP-коннект (3с таймаут)
    # — waitress исчерпывался и /api/status отваливался. Сверх лимита — 429.
    monkeypatch.setattr(app, "_EXPENSIVE_SEM", threading.BoundedSemaphore(1))
    release = threading.Event()

    def slow_connect(ep, timeout=None):
        release.wait(timeout=5)
        raise OSError("blocked in test")

    monkeypatch.setattr(app.socket, "create_connection", slow_connect)
    results = []

    def probe():
        c = app.app.test_client()
        results.append(c.post("/api/probe", headers=CSRF,
                              json={"upstream": "p.example"}).status_code)

    t = threading.Thread(target=probe)
    t.start()
    time.sleep(0.15)  # первый запрос занял единственный слот
    c2 = app.app.test_client()
    r = c2.post("/api/probe", headers=CSRF, json={"upstream": "p.example"})
    assert r.status_code == 429
    release.set()
    t.join(timeout=5)
    assert not t.is_alive()
    assert results == [200]  # слот не потерян: первый отработал штатно


def test_e2e_concurrency_limit_returns_429(client, app, monkeypatch):
    monkeypatch.setattr(app, "_EXPENSIVE_SEM", threading.BoundedSemaphore(1))
    release = threading.Event()

    def slow_check(listen):
        release.wait(timeout=5)
        return {"ok": False, "error": "blocked in test"}

    monkeypatch.setattr(app, "_proxy_e2e_check", slow_check)
    _create(client)
    client.post("/api/configs/home/activate", headers=CSRF)
    t = threading.Thread(
        target=lambda: app.app.test_client().post("/api/e2e", headers=CSRF, json={}))
    t.start()
    time.sleep(0.15)
    r = app.app.test_client().post("/api/e2e", headers=CSRF, json={})
    assert r.status_code == 429
    release.set()
    t.join(timeout=5)
    assert not t.is_alive()


def test_update_check_force_storm_is_coalesced(client, app, monkeypatch):
    # параллельные force=1 не должны превращаться в залп внешних запросов
    app._update_check_cache.clear()
    calls = []
    release = threading.Event()

    def slow_release():
        release.wait(timeout=5)
        calls.append(1)
        return {"tag": "v9.9.9", "notes": "", "url": ""}

    monkeypatch.setattr(app, "_latest_release", slow_release)
    out = []

    def check():
        c = app.app.test_client()
        r = c.get("/api/update/check?force=1")
        out.append((r.status_code, r.get_json().get("cached")))

    t = threading.Thread(target=check)
    t.start()
    time.sleep(0.15)  # первый уже в фазе внешнего резолва
    check()           # второй force при живом первом
    release.set()
    t.join(timeout=5)
    assert not t.is_alive()
    assert len(out) == 2
    assert [s for s, _ in out] == [200, 200]
    # порядок возврата потоков не фиксирован: важно, что один сходил в сеть,
    # второй взял его результат из кэша
    assert sorted(f is True for _, f in out) == [False, True]
    assert len(calls) == 1


def test_update_check_429_when_saturated(client, app, monkeypatch):
    app._update_check_cache.clear()
    monkeypatch.setattr(app, "_EXPENSIVE_SEM", threading.BoundedSemaphore(0))
    monkeypatch.setattr(app, "_latest_release",
                        lambda: {"tag": "v9.9.9", "notes": "", "url": ""})
    r = client.get("/api/update/check?force=1")
    assert r.status_code == 429


def test_http_get_bounds_connect_time_and_size(app, monkeypatch):
    # без --connect-timeout зависший коннект съедал весь --max-time, без
    # --max-filesize безразмерный ответ оставался в памяти
    cmds = []

    class _R:
        returncode = 1
        stdout = ""

    def fake_run(cmd, **k):
        cmds.append(cmd)
        return _R()

    monkeypatch.setattr(app.subprocess, "run", fake_run)
    with pytest.raises(RuntimeError):
        app._http_get("https://example.invalid/x")
    assert any("--connect-timeout" in c and "--max-filesize" in c for c in cmds), cmds


def _no_waitress(monkeypatch):
    import builtins
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "waitress":
            raise ImportError(name)
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)


def test_serve_refuses_werkzeug_on_lan_without_waitress(app, monkeypatch):
    # Werkzeug dev-сервер в LAN — авария конфигурации, а не fallback
    _no_waitress(monkeypatch)
    monkeypatch.setattr(app.cfg, "_bind_is_loopback", lambda: False)
    monkeypatch.delenv("NAIVEPANEL_DEV_SERVER", raising=False)
    with pytest.raises(SystemExit):
        app._serve(app.app, "192.168.1.1", 8089)


def test_serve_werkzeug_fallback_allowed_on_loopback_and_override(app, monkeypatch):
    _no_waitress(monkeypatch)
    calls = []
    monkeypatch.setattr(app.app, "run", lambda **k: calls.append(k))
    # loopback — законный dev-режим
    monkeypatch.setattr(app.cfg, "_bind_is_loopback", lambda: True)
    app._serve(app.app, "127.0.0.1", 8089)
    assert calls, "loopback fallback не сработал"
    # явный override и в LAN
    calls.clear()
    monkeypatch.setattr(app.cfg, "_bind_is_loopback", lambda: False)
    monkeypatch.setenv("NAIVEPANEL_DEV_SERVER", "1")
    app._serve(app.app, "192.168.1.1", 8089)
    assert calls, "NAIVEPANEL_DEV_SERVER=1 override не сработал"


def test_install_sh_python_fallback_verifier(tmp_path):
    # извлечённый из install.sh python3-фолбэк: корректные суммы → rc 0,
    # подменённый файл → rc 1 (регрессионная защита самого текста скрипта)
    import hashlib
    src = (APP_DIR / "install.sh").read_text(encoding="utf-8")
    m = re.search(r"-c '\s*(import hashlib.*?)'", src, re.S)
    assert m, "python3 fallback verifier не найден в install.sh"
    code = m.group(1)
    (tmp_path / "f.txt").write_text("hello")
    digest = hashlib.sha256(b"hello").hexdigest()
    (tmp_path / "SHA256SUMS").write_text(f"{digest}  f.txt\n")
    r = subprocess.run([sys.executable, "-c", code], cwd=tmp_path,
                       capture_output=True)
    assert r.returncode == 0, r.stderr
    (tmp_path / "f.txt").write_text("tampered")
    r = subprocess.run([sys.executable, "-c", code], cwd=tmp_path,
                       capture_output=True)
    assert r.returncode == 1


def test_rollback_binary_without_tag_clears_naive_tag(client, env, monkeypatch):
    m = _rb_naive_setup(env, monkeypatch, prev_tag=None)  # старый бэкап без тега
    # прокси неактивен → без рестарта
    r = m.app.test_client().post("/api/rollback", json={"binary": True},
                                 headers=CSRF)
    assert r.status_code == 200
    assert r.get_json()["restarted"] is False
    # тег новой версии врать не должен — его нет, check возьмёт из бинарника
    assert not m.NAIVE_TAG.exists()
    assert r.get_json()["restored"] == "naive 113.0.5672.3"


def test_rollback_binary_404_and_broken_backup(client, env, monkeypatch):
    m = _naive_env_reload(env, monkeypatch)  # бэкапа нет
    r = m.app.test_client().post("/api/rollback", json={"binary": True},
                                 headers=CSRF)
    assert r.status_code == 404
    # битый бэкап: --version падает → текущий бинарник не трогаем
    prev = m.NAIVEPROXY_DIR / "backup" / "naive.previous"
    prev.parent.mkdir(parents=True, exist_ok=True)
    prev.write_text('#!/bin/sh\nexit 7\n')
    prev.chmod(0o755)
    (env / "naive").write_text('#!/bin/sh\necho "naive 154.0.8037.49"\n')
    (env / "naive").chmod(0o755)
    r = m.app.test_client().post("/api/rollback", json={"binary": True},
                                 headers=CSRF)
    assert r.status_code == 500
    assert "keeping the current" in r.get_json()["error"]
    assert m._naive_bin_version() == "154.0.8037.49"


def test_rollback_binary_409_while_naive_update_running(client, env, monkeypatch):
    m = _rb_naive_setup(env, monkeypatch)
    m._naive_state_write({"phase": "running", "target": "v1.0",
                          "started": time.time()})
    r = m.app.test_client().post("/api/rollback", json={"binary": True},
                                 headers=CSRF)
    assert r.status_code == 409


def test_naive_update_records_previous_tag(client, env, monkeypatch):
    m = _rb_naive_setup(env, monkeypatch, prev_tag=None)
    # тег текущего (v154) уже в NAIVE_TAG от _rb_naive_setup; воркер при
    # обновлении обязан записать его в naive.previous.tag
    m.NAIVE_BUILD.write_text("x86_64\n")  # таргет не должен зависеть от хоста
    tarball = env / "naive.tar.xz"
    _build_naive_tarball(tarball, '#!/bin/sh\necho "naive 200.0.0.1"\n',
                         tag="v200.0.0.1-1")
    _naive_rel(monkeypatch, m, tag="v200.0.0.1-1",
               assets=(("naiveproxy-v200.0.0.1-1-openwrt-x86_64.tar.xz", "u"),))
    monkeypatch.setattr(m, "_http_download",
                        lambda url, dst: shutil.copy(tarball, dst))
    m._naive_update_worker()
    st = m._naive_state_read()
    assert st["phase"] == "done", st
    tagfile = m.NAIVEPROXY_DIR / "backup" / "naive.previous.tag"
    assert tagfile.read_text().strip() == "v154.0.8037.49-2"


def test_rollback_delete_removes_single_version(client, app):
    _rb_make_backup(app, "v0.14.0")
    _rb_make_backup(app, "v0.9.0")
    junk = app.PANEL_DIR / "backup" / "trash"
    junk.mkdir(parents=True)
    r = client.delete("/api/rollback/v0.9.0", headers=CSRF)
    assert r.status_code == 200
    assert r.get_json()["left"] == ["v0.14.0"]
    assert not (app.PANEL_DIR / "backup" / "v0.9.0").exists()
    assert junk.exists()  # не-версии не трогаем


def test_rollback_delete_404_and_400(client, app):
    assert client.delete("/api/rollback/v0.9.0", headers=CSRF).status_code == 404
    assert client.delete("/api/rollback/main", headers=CSRF).status_code == 400


def test_rollback_cleanup_keeps_newest(client, app):
    for v in ("v0.9.0", "v0.13.0", "v0.14.0"):
        _rb_make_backup(app, v)
    r = client.post("/api/rollback/cleanup", json={"keep": 1}, headers=CSRF)
    assert r.status_code == 200
    body = r.get_json()
    assert body["left"] == ["v0.14.0"]
    assert sorted(body["removed"]) == ["v0.13.0", "v0.9.0"]
    # keep=0 вычищает всё
    r = client.post("/api/rollback/cleanup", json={"keep": 0}, headers=CSRF)
    assert r.get_json() == {"removed": ["v0.14.0"], "left": []}


def test_rollback_cleanup_rejects_bad_keep(client, app):
    for bad in ("all", -1, 1.5, True):
        r = client.post("/api/rollback/cleanup", json={"keep": bad}, headers=CSRF)
        assert r.status_code == 400, bad


# --- ARCH-01: поэтапное разделение backend (Task 15) ---------------------------

def test_panel_package_config_extraction(app, env, monkeypatch):
    # шаг 1: конфигурация — panel/config.py; naivepanel.py — compatibility-
    # модуль; reload(naivepanel) пересобирает конфиг (env перечитывается)
    import panel.config as cfg
    assert cfg is app.cfg, "cfg-модуль должен быть тем же объектом"
    assert cfg.APP_VERSION == app.APP_VERSION
    assert cfg.CONF_D == app.CONF_D
    monkeypatch.setenv("NAIVEPROXY_DIR", str(env / "proxy-reloaded"))
    m = _reload()
    assert m.NAIVEPROXY_DIR == env / "proxy-reloaded"
    assert cfg.NAIVEPROXY_DIR == m.NAIVEPROXY_DIR, "config не пересобрался"


def test_backup_and_restore_include_panel_package(app, env):
    # бэкап/откат обязаны знать о пакете: пропавший panel/config.py после
    # отката панели = нерабочая установка
    pkg = app.PANEL_DIR / "panel"
    pkg.mkdir(parents=True, exist_ok=True)
    (pkg / "config.py").write_text("# current config", encoding="utf-8")
    backup = app._backup_panel_files()
    assert (backup / "panel" / "config.py").read_text() == "# current config"
    # симулируем «обновление», затёршее пакет, и откат
    (pkg / "config.py").write_text("# new version", encoding="utf-8")
    src = backup / "panel" / "config.py"
    tmp = (pkg / "config.py").with_name("config.py.restore")
    import shutil as _sh
    _sh.copy2(src, tmp)
    os.replace(tmp, pkg / "config.py")
    assert (pkg / "config.py").read_text() == "# current config"


def test_install_sh_ships_panel_package(app):
    src = (APP_DIR / "install.sh").read_text(encoding="utf-8")
    assert 'PANEL_PKG="__init__.py config.py"' in src, "installer не качает пакет"
    assert '"$BASE/panel/$f"' in src, "нет загрузки файлов пакета"
    assert 'rm -rf "$PANEL_DIR/panel"' in src, "пакет не заменяется целиком"
