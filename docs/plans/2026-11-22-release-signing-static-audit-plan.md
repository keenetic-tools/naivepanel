# NaivePanel Round 2: подпись релизов, статика, аудит и бэклог

> Продолжение [плана 2026-11-05](2026-11-05-architecture-security-ux-improvement-plan.md)
> (все его задачи выполнены). Правила выполнения те же: regression-first
> (сначала падающий тест, затем минимальная реализация, затем полный suite),
> без новых зависимостей без явного одобрения, без мягких gate'ов.

**Goal:** Закрыть оставшийся supply-chain риск self-update, снизить трафик и
время загрузки UI, дать админу журнал действий для разбора инцидентов —
не меняя облегчённую offline-архитектуру (один Flask-процесс, файловое
хранилище, vanilla JS, нет build step).

**Architecture:** Все ограничения Round 1 сохраняются: один процесс, waitress,
JSON-файлы, vanilla HTML/CSS/JS, pytest/Ruff/Bandit/ShellCheck/Docker E2E.

**Статус (2026-11-22):** план создан по итогам повторного аудита v0.26.2.
Task 20 (аудит) — ГОТОВО. Task 19 (статика) — ГОТОВО: panel/static/{app.js,
styles.css}, кэш immutable + ?v=APP_VERSION, CSP 'self', цепочка
install.sh → docker-e2e.sh → backup/rollback → SHA256SUMS обновлена,
smoke-тест пройден. Task 18 (подпись) — ГОТОВО: схема A
(minisign-совместимая Ed25519), tools/release_sign.py (keygen/sign/verify,
stdlib-only RFC 8032), ключ зашит в install.sh (keyid
c1f50218985a4272), подпись SHA256SUMS обязательна (fail-closed), копия
верификатора встроена в install.sh между маркерами #@np-verify-begin/end
(позитив+негатив в docker-e2e.sh, крипто-круговорот в
tests/test_release_sign.py). Продовый секрет: naivepanel-release.sec
(gitignored) — maintainer'у убрать офлайн. Следующие: средний приоритет
(Task 21 ARCH-02 notify, Task 22 session-auth, Task 23 hardening, Task 24
поллинг, Task 28 mypy/coverage).

## Реестр находок

| ID | Приоритет | Находка | Задача |
|---|---|---|---|
| SEC-07 | P1 | SHA256SUMS сверяет файлы, но качается с того же origin — компрометация репозитория подменяет файлы и суммы молча; подпись релизов отложена (8b Round 1) | 18 |
| ARCH-03 | P1 | Вся статика inline в index.html (2751 строка), отдаётся с no-cache — каждая загрузка UI качает ~100 КБ заново через роутер; JS/CSS не кэшируются между визитами | 19 |
| SEC-08 | P1 | Нет единого журнала действий: CRUD пресетов, activate, import/export, failover, обновления не логируются как аудит; auth-фейлы есть, действий — нет | 20 |
| ARCH-02 | P2 | panel/monitor.py (1563 строк) совмещает 4 домена: E2E/история/аптайм, watchdog, failover, уведомления (~400 строк) | 21 |
| SEC-09 | P2 | Basic-auth: креды с каждым запросом, logout — хак с навигацией на logout@host; нет session-альтернативы | 22 |
| SEC-10 | P2 | Мелкий hardening: нет Permissions-Policy/COOP; /api/password не троттлится по неудачным current; креды пробного naive ~15с в argv (видно через ps); маскирование кредов в логах regex'ом не ловит пароли с пробелами/переносами | 23 |
| UX-07 | P2 | Поллинг /api/status каждые 3с идёт и при скрытой вкладке — зря жгёт CPU роутера | 24 |
| UX-08 | P3 | Лог без follow-режима (автоскролл/пауза) и поиска; /api/probe возвращает ms, UI их не показывает | 25 |
| UX-09 | P3 | Импорт только через скрытый file input — нет drag&drop на список пресетов | 26 |
| i18n | P3 | UI только русский (roadmap 4.2) | 27 |
| TEST-03 | P2 | Нет type checking (mypy) и coverage gate; 426 тестов в одном файле на 6157 строк | 28 |
| UX-10 | P3 | Нет PWA-манифеста (установка на домашний экран) | 29 |

## Зависимости

```text
Task 18 (подпись)     — только после выбора схемы maintainer'ом
Task 19 (статика)     → обновляет install.sh, docker-e2e.sh, SHA256SUMS, тесты
Task 20 (аудит)       → UI-тогл источника лога зависит от текста index.html (до Task 19)
Task 21 (notify)      — после 19/20, чтобы не конфликтовать за monitor.py
Task 28 (mypy/cov)    — независим, удобен после 19/20/21 (файлы стабильны)
```

---

## Task 18: SEC-07 — подпись релизов и верификация в install.sh

**Files:**
- Modify: `install.sh` (верификация подписи перед установкой)
- Add: `SHA256SUMS.sig` (в релизном теге; формат зависит от схемы)
- Modify: `panel/updates.py` (`/api/update/apply` — тот же контракт: установщик сам верифицирует)
- Modify: `README.md` (trust-модель, ротация ключа)
- Test: `tests/test_naivepanel.py` (контракт verify-функции), meta-тест SHA256SUMS
- CI: `e2e.yml`/`docker-e2e.sh` — негативный кейс «подпись не сошлась → установка отклонена»

**Решение по схеме (фиксируется перед реализацией):**

- **Вариант A (рекомендуемый):** minisign-совместимая Ed25519-подпись файла
  `SHA256SUMS`. Публичный ключ зашит в install.sh (trust anchor, как сегодня
  SHA256SUMS, но приватный ключ живёт офлайн у maintainer'а и его кража
  требует отдельного доступа). Верификация: `openssl pkeyutl`/`openssl dgst`
  при наличии openssl в Entware, fallback — компактный pure-python Ed25519
  verify (stdlib-only, ~100 строк, без новых зависимостей). Подпись
  прикладывается к релизу как файл `SHA256SUMS.sig` в том же теге.
- **Вариант B:** Sigstore/cosign + GitHub artifact attestations. Современно,
  но верификация на роутере требует сторонних инструментов (sigstore/gHa
  bundle) — противоречит «без новых зависимостей».
- **Вариант C:** только подписанные git-теги (`git tag -s`). Минимум, но не
  покрывает путь установки через raw.githubusercontent (содержимое тега
  отдаётся независимо от подписи).

**Критерии приёмки:** install.sh и self-update отклоняют релиз с битой/
чужой подписью (e2e-негатив в docker-e2e.sh); отсутствие подписи — жёсткий
fail (как с sha256sum сегодня, install.sh:512-541); публичный ключ вынесен
в отдельную очевидную константу с комментарием о ротации.

---

## Task 19: ARCH-03 — разделение статики: panel/static + кэширование

**Files:**
- Add: `panel/static/app.js`, `panel/static/styles.css` (содержимое вырезается
  из `templates/index.html`)
- Modify: `templates/index.html` (тонкий inline bootstrap темы с nonce +
  `<link>`/`<script src>` через `url_for('static', ..., v=app_version)`)
- Modify: `panel/app.py` (`static_folder`, context_processor с версией,
  Cache-Control для /static)
- Modify: `panel/security.py` (`script-src 'self' 'nonce-…'`, `style-src 'self' 'unsafe-inline'`)
- Modify: `panel/updates.py` (`_backup_panel_files` — бэкап `panel/static/*`),
  `panel/app.py` rollback restore — та же схема
- Modify: `install.sh` (fetch/putfile `panel/static/*`), `docker-e2e.sh`
  (копирование static в $WWW), `SHA256SUMS` (перегенерация)
- Test: `tests/test_naivepanel.py` (~75 строковых assert'ов читают
  index.html — переносим читающие JS/CSS на `panel/static/app.js|styles.css`,
  HTML-assert'ы остаются), новые: кэш-заголовки /static, `?v=` busting
- Docs: `README.md` (структура релиза), `docs/UI-GUIDELINES.md` (куда
  добавлять стили/скрипты)

**Шаги:**

1. Падающие тесты: `/static/app.js` и `/static/styles.css` отдаются 200 с
   `Cache-Control: public, max-age=31536000, immutable`; CSP содержит
   `script-src 'self'`; HTML `/` содержит `<script src="/static/app.js?v=…">`.
2. Реализация: вырезать блоки, Flask(`static_folder=panel/static`,
   `static_url_path="/static"`), `SEND_FILE_MAX_AGE` не полагаться — свой
   after_request для `/static`; bootstrap-темы остаётся inline под nonce.
3. Проверить, что в JS/CSS нет Jinja-подстановок (grep `{{`/`{%`), иначе
   переносить нельзя — сначала параметризовать.
4. Обновить цепочку доставки: install.sh → SHA256SUMS → docker-e2e.sh →
   backup/rollback → test_sha256sums_matches_every_shipped_file.
5. Полный suite; ручной smoke: `naivepanel.py` на dev-bind, / и /static 200,
   тема не мигает (bootstrap до first paint).

**Критерии приёмки:** после первой загрузки повторный визит качает только
HTML (~10 КБ); self-update меняет `?v=` → новый JS/CSS подхватывается без
ручного сброса кэша; откат восстанавливает и static.

---

## Task 20: SEC-08 — журнал аудита действий

**Files:**
- Modify: `panel/config.py` (`PANEL_AUDIT = PANEL_DIR / "audit.jsonl"`)
- Modify: `panel/security.py` (`_audit(event, **fields)` — append JSONL,
  actor из request-context, маскирование не требуется: только структурированные
  поля, никаких URI с кредами)
- Modify: `panel/app.py` — `_audit` в: configs create/update/delete/
  duplicate/activate/import/export, failover PUT/DELETE, notify save/delete/
  test, password change, panel restart, update apply, naive update, rollback
  post/delete/cleanup, service start/stop/restart
- Modify: `panel/monitor.py` — авто-события (watchdog restarted/tripped,
  failover switched/returned/exhausted) с actor="monitor"
- Modify: `naivepanel.py` — `PANEL_AUDIT` в целях `_trim_logs_once`
- Modify: `templates/index.html` — третий тогл источника «аудит» рядом с
  «прокси»/«панель»; `_tail_path` уже маскирует креды
- Test: `tests/test_naivepanel.py` — create preset пишет запись; `GET
  /api/logs?src=audit` отдаёт её; в записях нет кредов; trim покрывает audit

**Критерии приёмки:** каждое мутационное действие из UI/API имеет запись
{ts, event, actor, detail}; журнал читается из UI; файл переживает рестарт,
обрезается триммером; ни одна запись не содержит паролей/токенов.

---

## Task 21: ARCH-02 — выделение panel/notify.py из monitor.py

**Files:** Add `panel/notify.py` (конфиг, очередь, sender, pending, getMe,
webhook), modify `panel/monitor.py` (удалить ~400 строк), `panel/app.py`
(импорты), `naivepanel.py` (шим: `_reload_or_import("panel.notify")`),
тесты — патчи `mon._notify_*` → `ntf._notify_*`.

**Критерии приёмки:** поведение не меняется (полный suite зелёный), monitor
<1200 строк, публичные имена re-export'ятся шимом для совместимости тестов.

## Task 22: SEC-09 — опциональная session-аутентификация

Cookie-сессия (SameSite=Strict, httpOnly, сервер хранит sha256 токена с
TTL) как альтернатива Basic: login-эндпоинт, logout реальный, Basic
оставить для обратной совместимости и PAC. Env-флаг `NAIVEPANEL_AUTH=
basic|session`. Троттлинг login как у auth. CSRF-токен для session-режима
(double-submit). Только после Task 20 (аудит логирует login/logout).

## Task 23: SEC-10 — hardening-мелочи

Добавить `Permissions-Policy` и `Cross-Origin-Opener-Policy` в
`_security_headers`; считать неудачи current-пароля `/api/password` в
`_auth_fails`; `_probe_preset` передавать `--proxy` через временный
config-файл 0600, а не argv (проверить поддержку `--config` у naive);
маскирование кредов в логах — по разобранному userinfo, не regex'ом.

## Task 24: UX-07 — пауза поллинга при скрытой вкладке

`document.visibilityState`: скрыта → clearInterval, видна → немедленный
тик + интервал. Тест: строковый assert на обработчик в app.js. Также
пауза для лог-поллинга.

## Task 25: UX-08 — follow-режим лога, поиск, latency пинга

Follow: автоскролл при новых строках, отключение при ручном скролле вверх,
кнопка «вниз». Поиск: фильтрация строк по подстроке. Пинг: показ «доступен,
N мс» из поля `ms` ответа /api/probe.

## Task 26: UX-09 — drag&drop импорта пресетов

drop-зона на списке пресетов: файл .json → тот же flow, что у importFile;
визуальная подсветка dragover; отклонение не-JSON понятным toast'ом.

## Task 27: i18n / английская локаль

Словарь строк в одном объекте app.js + переключатель в шапке, выбор в
localStorage; lang-атрибут html. Объём large — отдельная оценка перед стартом.

## Task 28: TEST-03 — mypy, coverage gate, разбиение тестов

`mypy panel/ naivepanel.py` (начать с non-strict, фиксировать конфиг);
`pytest --cov=panel --cov-fail-under=<текущий>` в CI; разбить
test_naivepanel.py на test_security/test_presets/test_monitor/test_updates/
test_app по владельцам.

## Task 29: UX-10 — PWA-манифест

`manifest.webmanifest` + иконки 192/512, display: standalone. Service
worker не добавляем (auth-кэширование рискованно) — только installability.
