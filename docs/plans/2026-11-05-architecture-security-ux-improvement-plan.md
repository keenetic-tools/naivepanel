# NaivePanel Architecture, Security and UX Improvement Implementation Plan

> Выполнять поэтапно, задача за задачей, в порядке regression-first: сначала
> падающий тест, затем минимальная реализация, затем полный suite (правила —
> в §1). Между условными срезами (§8) — ревью.

**Goal:** Устранить подтверждённые дефекты безопасности и конкурентности, повысить надёжность обновлений и доступность UI, не меняя облегчённую offline-архитектуру NaivePanel.

**Architecture:** Сохраняем один Flask-процесс, vanilla HTML/CSS/JS, файловое хранилище и отсутствие обязательного build step. Сначала исправляем дефекты через regression-first изменения, затем поэтапно выделяем cohesive modules без микросервисов, SPA, внешней БД и big-bang rewrite.

**Tech Stack:** Python 3.10+, Flask, Waitress, vanilla HTML/CSS/JS, pytest, Ruff, Bandit, ShellCheck, Docker/Entware E2E, GitHub Actions.

**Статус (2026-11-05):** Tasks 1–13 + 17 (доки) реализованы; 1–10 в релизе
v0.18.0, 11–13 (UX/a11y) ожидают следующего релиза. Task 8 реализован с
уточнением: распаковка осталась системному `tar` (зависимость xz не
меняется), валидация members — stdlib `tarfile` с fallback на `tar -tf`
(только имена) для Entware-сборок без `python3-lzma`. Подпись релизов и
trust-модель для naive-assets выделены в Task 8b и отложены до отдельного
обсуждения. Остались: Task 14 (IA/дизайн-токены), 15 (ARCH-01 модули),
16 (CI gates), 8b; финальная release-validation из Task 17 — пререлизным
шагом следующего релиза.

---

## 1. Исходное состояние и правила выполнения

Аудит относится к `v0.17.1` (`a3586d9`); все строковые ссылки вида
`naivepanel.py:1234` — по этому коммиту (в рабочих ветках номера дрейфуют). На
момент аудита:

- `.venv/bin/python -m pytest -q` — **304 passed**;
- Ruff, Bandit, `ast.parse`, `sh -n` — успешно;
- `SHA256SUMS` соответствует рабочей копии;
- локально воспроизведены: unauthenticated LAN export с паролем, утечка пароля через `GET /api/configs/<name>` для `quic://`, принятие `file://` в `listen`, гонка `_save_json()`.

Ограничения аудита: не выполнялись реальный router test, Docker Entware E2E, browser visual test и активный penetration test. Поэтому задачи содержат обязательную проверку на соответствующих окружениях.

### Приоритеты

- **P1:** до ближайшего hotfix/release; подтверждённый дефект или существенный риск.
- **P2:** следующая итерация; надёжность, доступность и hardening.
- **P3:** последующая эволюция; сопровождаемость, CI, документация и visual polish.

### Правила реализации

1. Каждая задача начинается с failing regression test, кроме чисто документальных/design задач.
2. Не менять публичный API без необходимости. Если HTTP `200 {rc:N}` сохраняется для совместимости, frontend обязан корректно обрабатывать `rc`.
3. Не добавлять зависимости без явного одобрения. Сначала stdlib и существующие Flask/pytest.
4. Не менять секреты и файлы в `etc/`, `var/`, `tmp/` реальной установки. Тесты используют `tmp_path`.
5. Каждая задача завершается полным unit-test suite. Docker/browser проверки выполняются там, где указано.
6. Commit-команды ниже — будущие checkpoints в отдельной feature branch/worktree, а не разрешение на commit прямо в `main`.
7. Перед PR task commits squash'ятся согласно house style; после изменения release-файлов пересоздаётся `SHA256SUMS`.

### Зависимости

```text
SEC-01, SEC-02, REL-01, REL-04  → hotfix и остальные изменения
REL-01                          → REL-02, REL-03
REL-02                          → REL-05 и стабильные update/rollback flows
Task 8 integrity                → Task 8b release signing (отложено, отдельное обсуждение)
UX-01…UX-03                     → UX-04 information architecture
TEST-01 regression coverage     → ARCH-01 modular extraction
Все задачи                      → DOC-01 release validation
```

---

## 2. Реестр находок

| ID | Приоритет | Находка | Основные доказательства | Задача |
|---|---|---|---|---|
| SEC-01 | P1 | LAN-bind без `admin.pass` открывает configs/service/restart/export; export содержит пароли | `naivepanel.py:1949-1951,2377-2408,2821-2825`; `install.sh:655-670` | 1 |
| SEC-02 | P1 | Полный `http://`/`quic://` URI возвращается с паролем через GET; нет `no-store` | `naivepanel.py:388-419,2238-2243` | 2 |
| SEC-03 | P1 | Update supply chain: checksum может пропускаться, нет подписи издателя, binary запускается без digest verification, tar members не проверяются | `install.sh:475-491`; `naivepanel.py:3247-3259` | 8 (подпись → 8b, отложено) |
| SEC-04 | P2 | `panel.conf` с потенциальными секретами создаётся `0644` | `install.sh:625-634` | 9 |
| SEC-05 | P2 | PID reuse может привести к kill чужого процесса | `S99naiveproxy:43-48,88-110`; `S99naivepanel:30-35,75-90` | 9 |
| SEC-06 | P2 | Длительные probe/E2E/update-check могут занять все worker threads; Werkzeug fallback допустим на LAN | `naivepanel.py:2518-2564,2725-2765,3723-3739` | 10 |
| REL-01 | P1 | Общий `<name>.tmp` вызывает конкурентный `FileNotFoundError` | `naivepanel.py:358-368` | 4 |
| REL-02 | P1 | PUT активного пресета и service operations обходят единый lock; active config/pointer не образуют транзакцию | `naivepanel.py:371-375,2275-2281,2323-2342` | 5 |
| REL-03 | P1 | Check-and-start update workers не сериализован; state files неатомарны | `naivepanel.py:2836-2841,2936-3009,3193-3198,3347-3374` | 6 |
| REL-04 | P1 | `listen` валидируется только как непустая строка; принят `file://` | `naivepanel.py:463-474,549-577` | 3 |
| REL-05 | P2 | UI сообщает успех service action при `rc != 0` | `naivepanel.py:2541-2545`; `templates/index.html:1218-1221` | 7 |
| UX-01 | P2 | Light accent имеет контраст 4.36:1 вместо 4.5:1 | `templates/index.html:24-34` | 11 |
| UX-02 | P2 | Touch targets <44px; inputs 13px на mobile вызывают iOS zoom | `templates/index.html:41,127-170` | 11 |
| UX-03 | P2 | Toast нельзя закрыть клавиатурой; scrollable log недоступен с клавиатуры; sparkline не имеет данных для screen reader | `templates/index.html:178-191,345,510-520,968-988` | 12 |
| UX-04 | P2 | Все функции перегружают одну страницу; system/settings workflows смешаны | `templates/index.html:231-465` | 14 |
| UX-05 | P3 | `escapeHtml()` используется перед `textContent`; возможны видимые entities | `templates/index.html:936,1273,1380` | 13 |
| UX-06 | P3 | Визуальные tokens не покрывают все состояния; Unicode-иконки не образуют единый icon set | `templates/index.html:9-212` | 14 |
| ARCH-01 | P3 | Backend 3827 строк и global state затрудняют безопасные изменения | `naivepanel.py` целиком | 15 |
| TEST-01 | P3 | 304 unit tests не покрыли найденные scheme/race/LAN cases; UI проверяется преимущественно строковыми assertions | `tests/test_naivepanel.py`; `docker-e2e.sh:106-138` | 1–7,16 |
| TEST-02 | P3 | Нет reproducible dependency manifest, blocking audit, version matrix, ShellCheck и регулярного Docker/browser E2E | `.github/workflows/ci.yml:8-25` | 16 |
| DOC-01 | P3 | Roadmap противоречит E2E semantics; README имеет повторный heading | `docs/ROADMAP.md:15`; `README.md:516-518` | 17 |

---

## 3. Задачи hotfix: безопасность и целостность данных

### Task 1: SEC-01 — fail closed для незащищённого LAN-bind

**Files:**
- Modify: `naivepanel.py` (`_require_auth`, `_require_local_or_auth`, registration of `before_request`)
- Modify: `install.sh` (bind/auth preflight)
- Test: `tests/test_naivepanel.py`
- Docs: `README.md` («Доступ из LAN без reverse proxy», «Безопасность»)

**Step 1: Write the failing test**

Добавить fixture с `NAIVEPANEL_BIND=192.168.1.1:8089`, отсутствующим `admin.pass` и `Host: 192.168.1.1:8089`. Проверить каждый sensitive route, а не только update:

```python
def test_lan_without_auth_rejects_sensitive_routes(client, app, monkeypatch):
    monkeypatch.setenv("NAIVEPANEL_BIND", "192.168.1.1:8089")
    m = _reload()
    c = m.app.test_client()
    headers = {"Host": "192.168.1.1:8089", **CSRF}
    for method, path in [
        ("get", "/api/configs"),
        ("get", "/api/configs/export"),
        ("post", "/api/configs"),
        ("post", "/api/service/restart"),
        ("post", "/api/panel/restart"),
        ("post", "/api/password"),
        ("post", "/api/update/apply"),
    ]:
        response = getattr(c, method)(path, headers=headers, json={})
        assert response.status_code == 403, (method, path, response.status_code)
```

Добавить противоположный test: loopback без auth по-прежнему допускает development workflow, а LAN + валидный bcrypt пропускает запрос после auth.

**Step 2: Run test to verify it fails**

Run:

```bash
.venv/bin/python -m pytest -q tests/test_naivepanel.py::test_lan_without_auth_rejects_sensitive_routes
```

Expected before fix: FAIL; configs/export/service routes возвращают не `403`.

**Step 3: Implement minimal centralized guard**

Сделать один guard для всех routes, а не копировать проверку по handlers:

```python
def _panel_is_exposed_without_auth() -> bool:
    return not PANEL_ADMIN_PASS.exists() and not _bind_is_loopback()

@app.before_request
def _reject_unauthenticated_exposure():
    if _panel_is_exposed_without_auth():
        abort(403, description=(
            "panel is exposed without a password — "
            "set one (install.sh --with-auth) first"
        ))
```

Зарегистрировать guard до CSRF/auth handlers. Сохранить `_require_local_or_auth()` как явную дополнительную защиту code/secrets-changing routes.

В `install.sh` отклонять не-loopback `--bind` без `admin.pass`/`--with-auth`, кроме отдельного явного emergency override. Не вводить override, если достаточно fail-fast preflight.

**Step 4: Verify**

Run:

```bash
.venv/bin/python -m pytest -q tests/test_naivepanel.py
```

Expected: PASS. Дополнительно повторить ручной repro: LAN без auth больше не создаёт пресет и не отдаёт export.

**Step 5: Commit checkpoint**

```bash
git add naivepanel.py install.sh tests/test_naivepanel.py README.md
git commit -m "fix: reject unauthenticated LAN panel access"
```

---

### Task 2: SEC-02 — write-only passwords для всех разрешённых proxy-схем

**Files:**
- Modify: `naivepanel.py:388-419,2238-2243`
- Test: `tests/test_naivepanel.py`
- Test: `docker-e2e.sh:106-138`

**Step 1: Write parametrized failing tests**

```python
@pytest.mark.parametrize("scheme", ["https", "http", "quic"])
def test_get_never_returns_full_uri_password(client, scheme):
    secret = "topsecret"
    response, _ = _create(
        client,
        upstream=f"{scheme}://user:{secret}@proxy.example:443",
        username="",
        password="",
    )
    assert response.status_code == 201
    response = client.get("/api/configs/home")
    assert response.status_code == 200
    assert secret not in response.get_data(as_text=True)
    assert response.headers["Cache-Control"] == "no-store"
    assert response.get_json()["upstream"] == "proxy.example:443"
    assert response.get_json()["username"] == "user"
```

Добавить uppercase scheme и legacy raw-`@` password cases, чтобы не сломать существующее `_split_proxy()` поведение.

**Step 2: Run tests to verify failure**

Run:

```bash
.venv/bin/python -m pytest -q tests/test_naivepanel.py -k "never_returns_full_uri_password"
```

Expected before fix: FAIL для `http` и `quic`; также отсутствует `Cache-Control`.

**Step 3: Implement**

Обобщить `_split_proxy()` через `urlsplit()`:

- scheme сравнивать в lower case;
- поддерживать `https/http/quic`;
- возвращать `(host_with_optional_port, username, password)`;
- сохранять IPv6 brackets/port;
- для legacy HTTPS с raw `@` использовать последний `@`, как сейчас;
- не возвращать исходный URI с userinfo из `_for_edit()` даже в fallback.

Добавить `no-store` в `api_configs_get()`:

```python
resp = jsonify(_for_edit(cfg))
resp.headers["Cache-Control"] = "no-store"
return resp
```

В `docker-e2e.sh` проверять отсутствие самого секрета во всём теле ответа. Текущая проверка только ключа `"password"` недостаточна.

**Step 4: Verify**

Run:

```bash
.venv/bin/python -m pytest -q tests/test_naivepanel.py -k "split_proxy or password or masks_credentials or never_returns_full_uri_password"
.venv/bin/python -m pytest -q
```

Expected: PASS.

**Step 5: Commit checkpoint**

```bash
git add naivepanel.py tests/test_naivepanel.py docker-e2e.sh
git commit -m "fix: keep proxy passwords write-only for every scheme"
```

---

### Task 3: REL-04 — полная валидация listen/proxy endpoints

**Files:**
- Modify: `naivepanel.py:463-577`
- Modify: `templates/index.html:284-300` (если hint расходится с фактическими схемами)
- Test: `tests/test_naivepanel.py`
- Docs: `README.md` («Поля конфига»)

**Step 1: Write failing validation tests**

```python
@pytest.mark.parametrize("listen", [
    "file:///tmp/socket",
    "quic://127.0.0.1:1080",
    "socks://:1080",
    "socks://127.0.0.1:0",
    "socks://127.0.0.1:65536",
    "http://user:pw@127.0.0.1:8080",
    "http://127.0.0.1:8080/path?q=1",
])
def test_create_rejects_invalid_listen(client, listen):
    response, _ = _create(client, listen=listen)
    assert response.status_code == 400

@pytest.mark.parametrize("listen", [
    "127.0.0.1:1080",
    "socks://127.0.0.1:1080",
    "http://127.0.0.1:8080",
    "socks://[::1]:1080",
])
def test_create_accepts_supported_listen(client, listen):
    response, _ = _create(client, listen=listen)
    assert response.status_code == 201
```

Повторить негативные cases через activate и import, не только create.

**Step 2: Run tests to verify failure**

Run:

```bash
.venv/bin/python -m pytest -q tests/test_naivepanel.py -k "invalid_listen or supported_listen"
```

Expected before fix: `file://` и другие malformed values принимаются.

**Step 3: Implement**

Ввести единый parser, который проверяет:

- listen schemes: `socks`, `socks5`, `http`;
- proxy schemes: `https`, `http`, `quic`;
- обязательный host;
- numeric port `1..65535`;
- отсутствие userinfo у listen;
- отсутствие path/query/fragment у listen;
- строковые типы, конечное число listen addresses и разумный max length.

Не полагаться на HTML `pattern` или live hint: сервер валидирует независимо.

Исправить UI hint: `quic://` относится к upstream proxy, а не к listen, если naive это подтверждает.

**Step 4: Verify**

Run:

```bash
.venv/bin/python -m pytest -q tests/test_naivepanel.py -k "listen or validate_cfg or non_proxy_scheme"
.venv/bin/python -m pytest -q
```

Expected: PASS.

**Step 5: Commit checkpoint**

```bash
git add naivepanel.py templates/index.html tests/test_naivepanel.py README.md
git commit -m "fix: validate listen and proxy endpoints before saving"
```

---

### Task 4: REL-01 — уникальные atomic writes для JSON

**Files:**
- Modify: `naivepanel.py:358-368`
- Test: `tests/test_naivepanel.py`

**Step 1: Write the deterministic concurrency regression test**

Использовать `threading.Barrier(2)` вокруг `Path.replace()` для одного target и запустить два `_save_json()` параллельно. Ожидаемый инвариант:

```python
assert errors == []
assert json.loads(target.read_text())["value"] in {1, 2}
```

Дополнительно проверить:

- temp files не остаются после success/failure;
- итоговый mode `0600`;
- JSON не бывает частично записан при injected `os.replace` failure;
- прежний target сохраняется при ошибке до replace.

**Step 2: Run test to verify it fails**

Run:

```bash
.venv/bin/python -m pytest -q tests/test_naivepanel.py -k "save_json_concurrent"
```

Expected before fix: один поток получает `FileNotFoundError`.

**Step 3: Implement minimal atomic writer**

Использовать тот же проверенный pattern, что `_write_admin_pass()`:

```python
fd, tmp_name = tempfile.mkstemp(
    dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp"
)
tmp = Path(tmp_name)
try:
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        os.fchmod(fh.fileno(), 0o600)
        json.dump(data, fh, indent=2, sort_keys=False)
        fh.write("\n")
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)
finally:
    tmp.unlink(missing_ok=True)
```

`path.parent.mkdir()` выполнить до `mkstemp`. Не использовать общий `.tmp`. Уникальные temp names устраняют техническую гонку, но не решают last-writer-wins — это закрывает Task 5.

**Step 4: Verify**

Run:

```bash
.venv/bin/python -m pytest -q tests/test_naivepanel.py -k "save_json or file_rights"
.venv/bin/python -m pytest -q
```

Expected: PASS.

**Step 5: Commit checkpoint**

```bash
git add naivepanel.py tests/test_naivepanel.py
git commit -m "fix: make JSON writes atomic under concurrency"
```

---

## 4. Надёжность service/update operations

### Task 5: REL-02 — единый service-operation lock и согласованная активация

**Files:**
- Modify: `naivepanel.py` (`_write_active`, `api_configs_update`, `_activate_preset`, `api_service`, naive update/rollback)
- Test: `tests/test_naivepanel.py`

**Step 1: Write failing tests**

Добавить deterministic tests:

- PUT активного A не может пересечься с activate B;
- `/api/service/restart` не выполняется параллельно с activate;
- restart failure не оставляет UI/FS в ложном состоянии «успешно применено»;
- при rollback active config восстанавливается прежний config и `.active`.

Использовать barriers/events в fake `_service()`, не реальный init process.

**Step 2: Run tests to verify current race/failure**

Run:

```bash
.venv/bin/python -m pytest -q tests/test_naivepanel.py -k "service_operation or activate_concurrent or restart_failure"
```

Expected before fix: PUT и service restart входят в fake одновременно; failed restart не восстанавливает прежнее состояние.

**Step 3: Implement**

- Переименовать `_ACTIVATE_LOCK` в `_SERVICE_LOCK` либо ввести новый общий lock.
- Все stop/start/restart/activate/active-PUT/binary update/rollback проходят через него.
- Внутри lock сохранять прежние `config.json` и `.active`, записывать новые через atomic writer, pointer писать последним.
- При `rc != 0` восстанавливать прежние files и возвращать структурированный `degraded` результат.
- Если rollback restart тоже failed, возвращать обе ошибки; не скрывать degraded state.

Не обещать двухфайловую crash-transaction, которую FS не даёт. Задокументировать recovery при power loss; при необходимости добавить маленький journal и восстановление при startup отдельным test.

**Step 4: Verify**

Run:

```bash
.venv/bin/python -m pytest -q tests/test_naivepanel.py -k "activate or service or restart or rollback"
.venv/bin/python -m pytest -q
```

Expected: PASS; fake calls строго сериализованы.

**Step 5: Commit checkpoint**

```bash
git add naivepanel.py tests/test_naivepanel.py
git commit -m "fix: serialize service mutations and activation"
```

---

### Task 6: REL-03 — атомарный launch/state обновлений

**Files:**
- Modify: `naivepanel.py:2828-2880,2936-3012,3185-3212,3347-3377`
- Test: `tests/test_naivepanel.py`

**Step 1: Write failing concurrent launch tests**

Синхронизировать два вызова `POST /api/update/apply` и два `POST /api/naive/update` до check-and-set. Инварианты:

```python
assert statuses.count(202) == 1
assert statuses.count(409) == 1
assert popen_calls == 1       # panel update
assert worker_threads == 1    # naive update
```

Проверить valid JSON state после конкурентных status/read/write и отсутствие частично записанного файла.

**Step 2: Run tests to verify race**

Expected before fix: возможны два installers/workers либо invalid/interleaved state.

**Step 3: Implement**

- `_UPDATE_LAUNCH_LOCK` и `_NAIVE_UPDATE_LAUNCH_LOCK` (или одна job registry lock).
- Полный check-running → reserve state → spawn/start выполнять по корректно выбранной lock strategy. Не держать lock во время сетевого release resolution; сначала resolve, затем атомарно reserve.
- Если spawn failed, вернуть state в `failed`/empty в том же critical section.
- State files писать через atomic writer с сохранением fail-soft logging semantics.
- Отдельно покрыть PID reuse installer state, если `_pid_alive()` продолжает использоваться без process identity.

**Step 4: Verify**

Run:

```bash
.venv/bin/python -m pytest -q tests/test_naivepanel.py -k "update_concurrent or update_state or naive_state"
.venv/bin/python -m pytest -q
```

Expected: PASS, ровно один worker.

**Step 5: Commit checkpoint**

```bash
git add naivepanel.py tests/test_naivepanel.py
git commit -m "fix: serialize update worker launch and state writes"
```

---

### Task 7: REL-05 — достоверный service feedback в UI

**Files:**
- Modify: `templates/index.html:1218-1222`
- Modify: `naivepanel.py:3288-3295,3484-3496` (если update/rollback restart failure не возвращается явно)
- Test: `tests/test_naivepanel.py`
- Test: browser E2E (Task 16)

**Step 1: Write tests**

Backend fixture возвращает `rc=1, stderr="boom"`. Browser test ожидает error toast с `boom`, отсутствие success toast и повторный status refresh. Unit/static test не должен заменять browser assertion.

**Step 2: Verify current wrong behavior**

Expected before fix: `svc()` игнорирует `d.rc` и показывает success.

**Step 3: Implement**

Переиспользовать существующие helpers:

```javascript
async function svc(action) {
  const buttons = document.querySelectorAll('[data-action="svc"]');
  buttons.forEach(b => { b.disabled = true; });
  try {
    const d = await jpost('/api/service/' + action, null);
    flash(applyMsg('Сервис ' + (SVC_VERBS[action] || action), d), !restartFailed(d));
    await refreshAll();
  } catch (e) {
    flash(e.message, false);
  } finally {
    buttons.forEach(b => { b.disabled = false; });
  }
}
```

Для update/rollback binary возвращать `restart` result; `restarted:true` без успешного `rc` недопустимо. Различать «binary заменён, но restart failed» и полный failure.

**Step 4: Verify**

Run unit suite и browser scenario. Expected: PASS; failure виден пользователю.

**Step 5: Commit checkpoint**

```bash
git add naivepanel.py templates/index.html tests/test_naivepanel.py
git commit -m "fix: report failed service commands in the UI"
```

---

## 5. Supply chain и системный hardening

### Task 8: SEC-03 — непропускаемая integrity-проверка обновлений

> **Решение (2026-11-05):** задача сужена до обязательного checksum и
> безопасной распаковки. Подпись издателя и trust-модель для naive-assets
> (upstream не публикует их checksum) выделены в Task 8b и отложены до
> отдельного обсуждения — без готового ответа «кому верить» подпись
> добавляет key management, но не защиту.

**Files:**
- Modify: `install.sh` (checksum fail-closed + python3-fallback verifier)
- Modify: `naivepanel.py` (`_naive_update_worker`: валидация members до распаковки)
- Test: `tests/test_naivepanel.py`
- Test: `docker-e2e.sh`

**Step 1: Write failing security tests**

Fixtures:

- `sha256sum` в системе отсутствует → верификация всё равно выполняется
  (fallback через `python3 -c` hashlib; python3 и так обязателен для панели),
  ветка «warn + продолжаем без проверки» удалена;
- изменённый файл из пары SHA256SUMS → install умирает ДО копирования;
- archive с member `../outside`, absolute path, symlink/hardlink или спец-типом
  → отклонён до распаковки; вне stage ничего не создано;
- happy-path naive update/rollback не сломан.

**Step 2: Run tests before implementation**

Expected before fix: `warn "sha256sum not found — skipping checksum verification"`
пропускает проверку; `tar -xJf` распаковывает архив без анализа members.

**Step 3: Implement**

Panel-files (`install.sh`):

- checksum обязателен: есть `sha256sum` → им; нет → верификация через
  `python3` (hashlib, тот же формат SHA256SUMS); невозможность проверить →
  `die`, не `warn`.

Naive-binary (`naivepanel.py`):

- распаковка остаётся системному `tar` (не добавляем зависимость от
  `python3-lzma`, которая есть не во всех Entware-сборках python3);
  перед распаковкой — валидация всех members: основной путь stdlib
  `tarfile` (Python 3.10: без `filter="data"` — появился позже), fallback
  без lzma — имена из `tar -tf` (path traversal отсекается, типы — нет):

```python
for member in archive.getmembers():
    member_path = Path(member.name)
    if member_path.is_absolute() or ".." in member_path.parts:
        raise RuntimeError("unsafe archive path")
    if member.issym() or member.islnk() or not (member.isfile() or member.isdir()):
        raise RuntimeError("unsupported archive member")
```

- порядок сохраняется: download → validate members → extract → `--version`
  gate → atomic rename (rename-семантика уже верная).

**Step 4: Verify**

Run:

```bash
.venv/bin/python -m pytest -q tests/test_naivepanel.py -k "checksum or archive or naive_update"
./docker-e2e.sh
```

Expected: все negative fixtures отклонены до install/execute; happy path сохранён.

**Step 5: Commit checkpoint**

```bash
git add install.sh naivepanel.py tests docker-e2e.sh
git commit -m "fix: enforce update integrity before install"
```

---

### Task 8b (отложено): SEC-03 — подпись релизов и trust-модель naive-assets

Выделено из Task 8 решением 2026-11-05. Открытые вопросы, без ответов на
которые реализацию не начинать:

- naive-бинарники публикует upstream (klzgrad/naiveproxy), их release не
  содержит publisher-checksum — манифест checksum придётся собирать и
  пиннить самим (перепубликация verified-манифеста или TOFU-пин первого
  install);
- доступность `minisign`/verifier на Entware (проверить заранее;
  самодельную криптографию не изобретать);
- key management для single-maintainer проекта: где хранится приватный ключ,
  что считается компрометацией, процедура ротации;
- bootstrap `curl | sh` — отдельный trust boundary (GitHub + TLS);
- компрометации GitHub не должно быть достаточно для подмены manifest и
  подписи одновременно;
- `docs/RELEASE-SIGNING.md` фиксирует ответы до начала кода.

---

### Task 9: SEC-04/SEC-05 — права конфигурации и PID identity

**Files:**
- Modify: `install.sh:634`
- Modify: `S99naiveproxy`, `S99naivepanel`
- Test: `tests/test_naivepanel.py` (static contract при необходимости)
- Test: `docker-e2e.sh`

**Step 1: Write failing checks**

- После fresh install `stat -c %a panel.conf` → `600`.
- После Telegram save/delete mode остаётся `600`.
- Fake PID file указывает на процесс с другим `comm/cmdline`; `stop` не посылает ему signal и возвращает ошибку/stale-pid result.
- Нормальный naive/panel PID продолжает останавливаться корректно.

**Step 2: Run checks before fix**

Expected before fix: fresh `panel.conf` = `0644`; init `running()` проверяет только `kill -0`.

**Step 3: Implement**

- Изменить fresh `panel.conf` на `0600`; задокументировать, почему это важно при ручном добавлении token.
- Для naive проверять `/proc/$pid/comm` ∈ `naive|naiveproxy`.
- Для panel проверять `/proc/$pid/cmdline` на ожидаемый `naivepanel.py`, а не только `python3`.
- Если `/proc` недоступен, применить явно документированный conservative fallback; не убивать процесс с доказанно чужой identity.
- После TERM/KILL проверять фактическое завершение, не удалять PID file молча при живом процессе.

**Step 4: Verify**

Run shell syntax, unit suite и Docker E2E. Expected: PASS; новые stale-PID scenarios безопасны.

**Step 5: Commit checkpoint**

```bash
git add install.sh S99naiveproxy S99naivepanel tests/test_naivepanel.py docker-e2e.sh README.md
git commit -m "fix: harden config permissions and service PID checks"
```

---

### Task 10: SEC-06 — ограничение дорогих запросов и production server policy

**Files:**
- Modify: `naivepanel.py:2518-2564,2725-2765,2900-2933,3307-3344,3723-3739`
- Modify: `install.sh` (Waitress dependency/fallback policy)
- Test: `tests/test_naivepanel.py`
- Docs: `README.md`

**Step 1: Write tests**

- Более N параллельных E2E/probe → немедленный `429`, без исчерпания Waitress threads.
- `?force=1` не создаёт неограниченный внешний request storm.
- Non-loopback без Waitress → fail-fast, если нет явного development override.
- Loopback development fallback продолжает работать с warning.

**Step 2: Run tests before fix**

Expected before fix: все запросы принимаются; Werkzeug fallback доступен на любом bind.

**Step 3: Implement**

- Использовать `threading.BoundedSemaphore` для E2E/probe/update-check с non-blocking acquire и `429`.
- Кэшировать update-check и коалесцировать параллельные identical checks в одну внешнюю операцию.
- Добавить curl `--connect-timeout` и общий `--max-time`; ограничивать размер скачиваемых metadata.
- На non-loopback требовать Waitress. Werkzeug оставить только для explicit development mode.
- Проверить доступные Waitress timeout/request limits для целевой версии; не копировать параметры без проверки документации.

**Step 4: Verify**

Run unit suite и controlled slow-server test. Expected: worker threads остаются доступны для `/api/status`.

**Step 5: Commit checkpoint**

```bash
git add naivepanel.py install.sh tests/test_naivepanel.py README.md
git commit -m "fix: bound expensive panel operations"
```

---

## 6. UI/UX и accessibility

### Task 11: UX-01/UX-02 — контраст, touch targets и mobile typography

**Files:**
- Modify: `templates/index.html:24-34,127-170`
- Test: `tests/test_naivepanel.py` (token contract)
- Test: browser visual/accessibility checks (Task 16)

**Step 1: Define failing acceptance checks**

- Light accent и white-on-accent ≥4.5:1.
- Все primary/icon actions на mobile имеют target ≥44×44px.
- Mobile form controls имеют font-size ≥16px.
- Нет horizontal overflow на 375px, включая presets в failover-order mode.

**Step 2: Reproduce**

Browser screenshots на 375/768/1024/1440px + axe scan. Зафиксировать текущие overflow/focus/target issues до CSS.

**Step 3: Implement minimal CSS**

- Заменить light `--acc` на проверенный `#0b7a53` (5.35:1 на белом) либо другой token с повторным расчётом.
- В `@media (max-width:800px)` задать inputs `font-size:16px`, action buttons `min-height:44px`, icon buttons `min-width:44px`.
- Для `.acts` предусмотреть wrap/overflow strategy; не обрезать действия.
- Проверить hover/focus/disabled в обеих темах и `prefers-reduced-motion`.

**Step 4: Verify**

Повторить screenshots и axe. Expected: contrast ≥4.5, targets ≥44, no horizontal scroll, видимый keyboard focus.

**Step 5: Commit checkpoint**

```bash
git add templates/index.html tests/test_naivepanel.py
git commit -m "fix: improve mobile controls and light theme contrast"
```

---

### Task 12: UX-03 — доступные toast/log/sparkline/forms

**Files:**
- Modify: `templates/index.html` (HTML controls, toast renderer, dialogs, sparkline)
- Test: `tests/test_naivepanel.py`
- Test: browser keyboard/screen-reader-oriented checks (Task 16)

**Step 1: Write acceptance checks**

- Theme button имеет динамическое accessible name.
- Лог фокусируется клавиатурой и прокручивается.
- Toast содержит настоящую close button с accessible name.
- Ошибка upstream связана с input через `aria-describedby`; invalid выставляется.
- Sparkline имеет текстовую сводку последних проверок, не полагающуюся только на red/green.
- Все icon-only actions имеют accessible names; focus не теряется после rerender.

**Step 2: Reproduce keyboard-only flow**

Expected before fix: scrollable `<pre>` не получает focus; toast закрывается только click; sparkline SVG `aria-hidden` без эквивалента.

**Step 3: Implement**

- `pre.log`: `tabindex="0"` и accessible label.
- Toast: `<div class="toast">…<button type="button" aria-label="Закрыть уведомление">…</button></div>`.
- `f_upstream`: `aria-describedby="upHint"` и `aria-invalid` из validation.
- `drawSpark()`: обновлять visually-hidden текстовую сводку; при необходимости details с таблицей последних результатов.
- Не включать автоматические live announcements для 3-секундного лога — это создало бы шум.
- Сохранить существующие native `<dialog>` и focus restoration.

**Step 4: Verify**

Keyboard-only: создать пресет, открыть/закрыть dialogs, закрыть toast, прочитать лог, переключить failover. Axe без serious/critical violations; ручная проверка screen reader при наличии окружения.

**Step 5: Commit checkpoint**

```bash
git add templates/index.html tests/test_naivepanel.py
git commit -m "fix: make panel feedback keyboard accessible"
```

---

### Task 13: UX-05 — убрать двойное экранирование и request races

**Files:**
- Modify: `templates/index.html:854-880,929-940,1265-1284,1372-1400`
- Test: browser/unit JS checks в рамках Task 16

**Step 1: Write failing checks**

- Update error с `A&B` отображается как `A&B`, не `A&amp;B`.
- Быстрый выбор preset A → B не позволяет позднему response A перезаписать форму B.
- Повторный Ctrl+S во время активного save не создаёт второй PUT.

**Step 2: Reproduce**

Expected before fix: `escapeHtml()` перед `textContent`; async selection/save не имеет cancellation/guard.

**Step 3: Implement**

- Убрать `escapeHtml()` из всех `textContent` assignments; оставить в `innerHTML`.
- Добавить `AbortController` или monotonically increasing selection token.
- В `save()` сразу выходить, если save уже выполняется; keyboard shortcut использует тот же guard.
- Не отменять серверную mutation на клиенте и не считать abort признаком отката; после завершения перечитывать состояние.

**Step 4: Verify**

Run browser tests и complete unit suite. Expected: PASS, out-of-order responses не меняют текущий editor.

**Step 5: Commit checkpoint**

```bash
git add templates/index.html tests
git commit -m "fix: prevent stale UI updates and double escaping"
```

---

### Task 14: UX-04/UX-06 — информационная архитектура и visual system без SPA

**Files:**
- Modify: `templates/index.html`
- Optionally create: `templates/partials/` (Jinja includes; один итоговый offline HTML response)
- Create: `docs/UI-GUIDELINES.md`
- Test: browser workflows/screenshots (Task 16)

**Step 1: Зафиксировать дизайн перед перемещением DOM**

В `docs/UI-GUIDELINES.md` описать:

- «Обзор» — service, active preset, presets/failover, E2E;
- «Диагностика» — logs/probe/history;
- «Система» — panel/binary updates и rollback;
- «Настройки» — password и notifications;
- desktop сохраняет 2–3 column dashboard;
- mobile использует tabs/section navigation без потери primary workflow;
- editor явно различает «сохранено», «активно», «есть несохранённые изменения».

**Step 2: Создать tokens без внешних зависимостей**

Добавить semantic tokens для spacing, font sizes, radius, shadows, z-index, focus и status colors. Сохранить system font stack и offline CSP. Иконки — маленький согласованный inline-SVG set, без emoji-font dependency.

**Step 3: Поэтапно менять структуру**

Сначала группировка существующих cards, затем mobile navigation, затем editor presentation. Не переписывать JS одновременно с перемещением всего DOM. После каждого шага прогонять create/activate/failover/log/update workflows.

**Step 4: Verify**

- 375/768/1024/1440 screenshots в light/dark.
- Нет hidden primary actions, horizontal overflow или focus loss.
- Create → save → activate → check → update/rollback flows не стали длиннее без причины.
- Итог остаётся offline, без CDN и обязательного JS bundler.

**Step 5: Commit checkpoint**

```bash
git add templates docs/UI-GUIDELINES.md tests
git commit -m "feat: clarify dashboard navigation and design tokens"
```

---

## 7. Архитектура, тестирование и выпуск

### Task 15: ARCH-01 — поэтапное разделение backend без big-bang rewrite

**Files:**
- Create gradually: `naivepanel/` package или согласованный `panel/` package
- Modify: `naivepanel.py` как compatibility entrypoint на переходный период
- Modify: `install.sh`, `S99naivepanel`, `SHA256SUMS`
- Test: `tests/test_naivepanel.py`

**Step 1: Зафиксировать границы и порядок extraction**

Рекомендуемые модули:

```text
config.py      env/panel.conf parsing, paths, constants
security.py    auth, CSRF, Host allowlist, CSP/security headers
presets.py     schemas, proxy parsing, atomic preset storage
service.py     PID/process/init operations, service lock
monitor.py     watchdog, failover, E2E history, notifications
updates.py     release resolution, signed updates, rollback, workers
app.py         app factory, routes, error handling
```

Не создавать классы ради классов и не переносить всё одним commit. Compatibility entrypoint сохраняет текущий запуск до обновления installer.

**Step 2: Переносить по одному модулю**

Для каждого move:

1. Скопировать поведение без refactor logic.
2. Обновить imports и только необходимые test imports.
3. Прогнать полный suite.
4. Отдельный commit.

Порядок: `config` → `security` → `presets` → `service` → `monitor` → `updates` → app factory/routes.

**Step 3: Проверить deployment**

- Fresh install содержит все package files.
- Self-update создаёт полный backup и умеет rollback.
- Init запускает правильный entrypoint.
- Нет смешения старого single-file и нового package после interrupted update.

**Step 4: Verify**

```bash
.venv/bin/python -m pytest -q
.venv/bin/ruff check naivepanel.py naivepanel tests
./docker-e2e.sh
```

Expected: PASS; fresh install/upgrade/rollback работают.

**Step 5: Commit checkpoint**

```bash
git add naivepanel.py naivepanel install.sh S99naivepanel tests SHA256SUMS
git commit -m "refactor: split panel into cohesive modules"
```

---

### Task 16: TEST-01/TEST-02 — воспроизводимые проверки и CI gates

**Files:**
- Modify: `.github/workflows/ci.yml`
- Optionally create: `.github/workflows/e2e.yml`, `.github/workflows/release.yml`
- Create: `requirements-dev.txt` и/или constraints с проверенными версиями
- Create: `tests/browser/` (Playwright/axe только после одобрения зависимости)
- Modify: `docker-e2e.sh`

**Step 1: Закрыть пробелы regression coverage**

Обязательные cases:

- LAN без auth по всем sensitive routes;
- все proxy schemes и secret absence anywhere in response;
- invalid listen через create/update/activate/import;
- concurrent JSON writes и service/update operations;
- failed service `rc` в browser UI;
- keyboard-only и mobile viewport workflows.

**Step 2: Сделать зависимости и проверки воспроизводимыми**

- Зафиксировать reviewed dependency versions, включая Waitress.
- Python matrix включает минимальный 3.10 и актуальные supported versions.
- `pip-audit` становится blocking; исключения оформляются с причиной и expiry, не глобальным `continue-on-error: true`.
- Добавить ShellCheck для `install.sh`, `S99naiveproxy`, `S99naivepanel`, `docker-e2e.sh`.
- GitHub Actions закрепить по reviewed commit SHA, не только major tag.

**Step 3: Добавить E2E в нужном ритме**

- Unit/Ruff/Bandit/ShellCheck — каждый PR.
- Browser critical workflows + axe — каждый PR, если инфраструктура стабильна.
- Docker Entware E2E — nightly и обязательно перед release; можно включить для PR с caching.
- Release workflow проверяет подпись manifest, checksum и clean source tree.

**Step 4: Verify CI itself**

Запустить workflow на тестовой ветке. Убедиться, что новые gates действительно падают на намеренно broken fixtures, а не только отображаются.

**Step 5: Commit checkpoint**

```bash
git add .github requirements-dev.txt tests docker-e2e.sh
git commit -m "ci: add reproducible security and E2E gates"
```

---

### Task 17: DOC-01 и финальная release validation

**Files:**
- Modify: `docs/ROADMAP.md`
- Modify: `README.md`
- Modify: `SHA256SUMS`
- Optionally create: `CHANGELOG.md`

**Step 1: Исправить документацию**

- В `docs/ROADMAP.md:15` убрать устаревшее «недоступный echo-хост неудачей не считается». Актуальная семантика: полный HTTP response обязателен; ACK туннеля без данных — failure.
- Удалить повторный `### Установка бинарника naive` в `README.md:516-518`.
- Обновить security sections после SEC-01/02/03.
- Задокументировать новые permissions, update trust model, production Waitress policy и browser recovery flows.
- Убрать устаревшие гарантии, если поведение сознательно изменилось.

**Step 2: Пересоздать checksums**

```bash
shasum -a 256 S99naivepanel S99naiveproxy naivepanel.py templates/index.html > SHA256SUMS
```

Если появился package, обновить команду/manifest так, чтобы все release files были включены. Не оставлять старый single-file-only список.

**Step 3: Полная validation matrix**

```bash
.venv/bin/python -m pytest -q
.venv/bin/ruff check naivepanel.py tests/
.venv/bin/bandit -q -ll -r naivepanel.py
sh -n S99naiveproxy && sh -n S99naivepanel && sh -n install.sh
sha256sum -c SHA256SUMS  # macOS fallback: shasum -a 256 -c SHA256SUMS
./docker-e2e.sh
```

Дополнительно:

- browser workflows 375/768/1024/1440, light/dark, keyboard-only;
- LAN without auth, LAN with auth, reverse proxy with allowed Host;
- self-update, failed update, rollback panel/binary;
- interrupted update/restart recovery;
- clean install и upgrade от предыдущего release на реальном Entware или эквивалентном Docker.

**Step 4: Зафиксировать остаточные риски**

- HTTP Basic без TLS остаётся риском в недоверенной LAN; рекомендация — Caddy TLS или SSH tunnel.
- До внедрения signed bootstrap первоначальный `curl | sh` продолжает зависеть от TLS/GitHub trust.
- FS active config/pointer не является полноценной БД-транзакцией; recovery и его ограничения должны быть описаны.
- Router watchdog работает только пока работает панель; cron/procd fallback остаётся отдельной roadmap-задачей.

**Step 5: Commit checkpoint**

```bash
git add README.md docs SHA256SUMS CHANGELOG.md
git commit -m "docs: align release guidance with hardened behavior"
```

---

## 8. Предлагаемые release slices

### Hotfix 0.17.2

Tasks **1–4**: SEC-01, SEC-02, REL-04, REL-01. Это минимальный самостоятельный пакет с regression tests, без UI redesign и module extraction.

### Следующий reliability release

Tasks **5–10**: service/update serialization, truthful feedback, непропускаемая integrity-проверка обновлений (8; подпись — 8b, отложено), permissions/PID/resource controls.

### UX release

Tasks **11–14**: accessibility, mobile layout, feedback, information architecture. Не смешивать с ARCH-01, чтобы visual regressions не маскировали backend regressions.

### Maintenance/CI evolution

Tasks **15–17**: modular extraction, CI gates, documentation и release hardening.

Порядок может меняться по риску, но ARCH-01 не начинать до появления regression coverage из Tasks 1–7.

---

## 9. Definition of Done для всего плана

План считается завершённым только когда:

- [ ] LAN без пароля не отдаёт и не изменяет sensitive state; loopback development сохраняется.
- [ ] Ни один config GET не возвращает upstream password для поддерживаемых URI formats; sensitive responses `no-store`.
- [ ] Неподдерживаемые listen/proxy values отклоняются до записи/активации.
- [ ] Параллельные JSON/service/update operations не создают corrupted state или duplicate workers.
- [ ] Failed service/restart виден как failure/degraded, а не success.
- [ ] Checksum обновлений панели непропускаем (нет `sha256sum` → python3-верификация, сбой проверки = остановка установки); archive extraction ограничена безопасными members до запуска бинарника; подпись издателя — Task 8b (отложено).
- [ ] `panel.conf` и secrets имеют корректные permissions; stale PID не приводит к kill чужого процесса.
- [ ] Light/dark contrast соответствует WCAG AA для normal text; mobile targets ≥44px; inputs ≥16px.
- [ ] Primary workflows доступны клавиатурой; toast/log/forms/sparkline имеют доступные эквиваленты.
- [ ] UI остаётся offline и без обязательного framework/build step.
- [ ] Unit, lint, security, browser и Entware E2E checks проходят; negative tests подтверждают, что gates способны падать.
- [ ] Fresh install, upgrade, failed update и rollback проверены на целевом окружении.
- [ ] README, ROADMAP, release-signing docs и SHA256SUMS соответствуют фактическому поведению.

## 10. Осознанные non-goals

- Микросервисы, Kubernetes, внешняя БД и RBAC/multi-user.
- SPA/React/Vue и обязательный frontend bundler.
- HTTPS termination внутри панели; TLS остаётся задачей reverse proxy или SSH tunnel.
- Полный Prometheus-compatible monitoring stack.
- Big-bang rewrite ради модульности или современного внешнего вида.
