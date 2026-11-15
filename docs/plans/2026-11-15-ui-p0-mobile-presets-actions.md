# NaivePanel UI P0: мобильные профили, безопасные действия, первый запуск и offline

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

> Выполнять задачу за задачей подряд. Для каждой задачи: сначала failing-тест,
> затем минимальная реализация, полный `pytest`, live-скриншоты, коммит.
> Правила скриншотов — `docs/UI-GUIDELINES.md` §2. Не переписывать JS и DOM
> одновременно с изменением дизайна: в этом плане они специально разведены по
> задачам.

**Goal:** Убрать P0-дефекты UI/UX из ревью 2026-11-15: нечитаемый мобильный
список профилей, редактор вне экрана, действия без подтверждения и состояния,
сломанный первый запуск, отсутствие offline-состояния и английские ошибки —
не ломая offline-архитектуру «один HTML без CDN».

**Architecture:** Всё остаётся в одном шаблоне `templates/index.html`
(vanilla CSS/JS, nonce-CSP, без сборки). Меняем слой представления: строка
профиля становится двухуровневой с одним меню действий, порядок цепочки
переезжает из строк в отдельный `<dialog>`, редактор получает явный
block/empty-state и scroll/focus при открытии, сервисные кнопки — состояние и
подтверждения. Backend-контракты не меняются; английские `abort(...)` тексты
локализуются на клиенте в `ruError()`.

**Tech Stack:** Python 3.10+, Flask, Waitress, vanilla HTML/CSS/JS, pytest,
Ruff, Bandit, Node (`node --check` только если есть в PATH).

---

## 1. Scope, ограничения и исходное состояние

**В scope (P0):**

1. Локализация ошибок API/сети (`ruError`, `humanError`) и 409 активного профиля.
2. Строка профиля v2: две строки, `host:port` вместо маскированного URI,
   одно меню `⋯` с текстовыми действиями; активный — первым.
3. Порядок цепочки — отдельный диалог; удалить `foOrderMode` и стрелки из строк.
4. Открытие редактора: `editorBlock`/`editorEmpty`, scroll + focus заголовка;
   корректный возврат фокуса при закрытии.
5. Сервисные действия: скрытие/дизейбл по состоянию, подтверждения stop/restart,
   запрет no-op save активного, скрытие «Удалить»/«Сделать активным» у активного.
6. Первый запуск: исправленный empty-state, CTA, скрытие фейловера (<2 профилей)
   и экспорта (0 профилей), скрытие пустого редактора.
7. Offline: баннер «нет связи», время последнего успеха, retry, error-state
   вместо вечного skeleton.
8. Гигиена рядом с затронутыми строками: контраст бейджей, тап-цели 44px,
   `aria-live` без мутаций каждые 3с, динамическая подпись лога, горячие клавиши
   по `e.code`, высота шапки через CSS-переменную.
9. Docs (UI-GUIDELINES, README) + финальная матрица скриншотов.

**Out of scope (отдельный P1/P2-план):**

- смена интервала поллинга, gzip/precompress, ETag, lazy-load GitHub-проверок;
- event feed (переключения/возвраты/watchdog) и «Подключить устройство» с QR;
- планшетная IA 801–1239px, scrollspy в навигации, i18n/английская локаль;
- TLS-баннер, logout/session для Basic auth, PWA-манифест/favicon;
- переименование «пресет → профиль» во всём UI (в этом плане все
  пользовательские тексты остаются с «пресетом»; глобальный copy/i18n-проход —
  отдельно).

**Принятые решения (не блокируют старт):**

1. Одна строка = два уровня + `⋯`. Активация — из меню или из редактора
   (2 тапа). Если one-click activation окажется продуктовым требованием,
   добавить отдельную текстовую кнопку только на desktop, не возвращая столбик
   иконок.
2. `Save` активного пресета не спрашивает подтверждение, но показывает
   inline-предупреждение и запрещён при `!dirty` (нельзя случайно перезапустить
   сервис, открыв пресет и нажав «Сохранить»).
3. Удаление активного пресета недоступно в UI (backend 409 остаётся как
   defense-in-depth и локализуется на клиенте).
4. Новых зависимостей и browser-автоматизации в CI нет. Поведение проверяется
   source-contract тестами + обязательными live-скриншотами; это ограничение
   проекта, а не плана.

**Baseline (проверено 2026-11-15):**

```bash
.venv/bin/python -m pytest -q
# 443 passed, 1 skipped
```

**Контракты, которые придётся обновить вместе с кодом (важно):**

- `tests/test_naivepanel.py::test_ui_editor_closable_by_button_and_esc` —
  сейчас требует строку `if ($('editor').style.display !== 'none'`; после
  задачи 4 будет `if (isEditorOpen()`.
- `tests/test_naivepanel.py::test_ui_failover_lives_with_presets` — Task 2
  убирает из него `foUp`/`foDown`/`foOrderMode`/`aria-label="Добавить`, Task 3
  добавляет `id="foOrderDlg"`, `renderFoOrder`, `Добавить в цепочку` и
  возвращает `foUp`/`foDown` уже для диалога.
- Оба теста обновляются в тех же коммитах, что и код; это не «подгонка под
  реализацию», а смена зафиксированного контракта.

**Правила:**

1. Один task = один commit (если не сказано иное). Ветка/worktree, не `main`.
2. После каждого шага — полный `pytest`; для UI-задач — скриншоты
   375/390/768/1024/1440 в обеих темах (минимум затронутые состояния).
3. Внешние origin'ы, inline-обработчики, `innerHTML` с неэкранированными
   данными — запрещены (CSP/nonce и текущие правила).
4. Тексты ошибок наружу — только через `ruError()`/`humanError()`.
5. Не менять `panel/app.py` в этом плане, кроме случая, если тест покажет, что
   клиентской локализации недостаточно.
6. `APP_VERSION` и релизные заметки — отдельным release-шагом. **`SHA256SUMS`
   — манифест поставляемых файлов, а не только release-артефакт:** meta-тест
   `test_sha256sums_matches_every_shipped_file` падает при любом изменении
   `templates/index.html`/`panel/*.py`/скриптов. Поэтому каждый task-коммит,
   меняющий поставляемый файл, обязан обновить и закоммитить `SHA256SUMS`:
   ```bash
   shasum -a 256 naivepanel.py templates/index.html S99naivepanel \
     S99naiveproxy panel/*.py > SHA256SUMS
   ```
   На release-шаге манифест пересоздаётся ещё раз после bump `APP_VERSION`.

**Live-стенд для скриншотов:** панель на роутере или локальный запуск с
`NAIVEPANEL_*`/`NAIVEPROXY_*` на временные пути; 4–6 пресетов, цепочка из 3,
логи, история E2E. Ровно те состояния, которые проверяет ревью:
running/stopped, first-run, row menu, order dialog, editor active/dirty,
offline.

Снимки «до» из ревью (локальный стенд 2026-11-15, `tmp/` в gitignore):
`tmp/shots/mobile-active-row.png`, `tmp/shots/first-run-mobile.png`,
`tmp/shots/desktop-light.png`, `tmp/shots/desktop-order.png`.

---

## 2. Сводка задач

| # | Задача | Основные файлы | Зависит от |
|---|---|---|---|
| 1 | Русские ошибки API и сети | `templates/index.html`, `tests/test_naivepanel.py` | — |
| 2 | Строка профиля v2 + меню действий | `templates/index.html`, тесты | 1 |
| 3 | Диалог порядка цепочки, удаление `foOrderMode` | `templates/index.html`, тесты | 2 |
| 4 | Редактор: block/empty, scroll/focus, возврат фокуса | `templates/index.html`, тесты | — |
| 5 | Сервисные действия: состояние, подтверждения, save-guard | `templates/index.html`, тесты | 2, 4 |
| 6 | Первый запуск: empty-state, CTA, скрытие лишнего | `templates/index.html`, тесты | 2, 4, 5 |
| 7 | Offline-баннер и error-state | `templates/index.html`, тесты | 1, 4, 5 |
| 8 | Гигиена: контраст, тап-цели, aria-live, шапка, shortcuts | `templates/index.html`, тесты | 2–7 |
| 9 | Docs, README, финальная матрица скриншотов | `docs/UI-GUIDELINES.md`, `README.md` | все |

---

### Task 1: Локализация ошибок API и сети (`ruError`, `humanError`)

> **Статус: реализовано** (commit `3c26ac8`) с уточнениями code-quality review:
> тест расширен проверками русских строк/401/403/429/humanError/httpStatus;
> `invalid name` приведён к `^[a-zA-Z0-9_\-.]{1,64}$`; 429-fallback
> duration-neutral; `humanError()` сохраняет префикс составного сообщения.

**Files:**
- Modify: `templates/index.html` — `handle()`, `flash()`, новый `ruError()`/`humanError()`.
- Test: `tests/test_naivepanel.py` — новый раздел в конце файла.

**Step 1: Write the failing tests**

Добавить в конец `tests/test_naivepanel.py`:

```python
# --- UI P0 (2026-11-15): строки профилей, действия, первый запуск, offline ----

def _ui_html() -> str:
    return (APP_DIR / "templates" / "index.html").read_text(encoding="utf-8")


def _ui_fn(html: str, name: str) -> str:
    m = re.search(rf"(?:async )?function {re.escape(name)}\(.*?\n\}}", html, re.S)
    assert m, f"{name}() не найден в index.html"
    return m.group(0)


def test_p0_api_errors_are_localized(app):
    html = _ui_html()
    assert "function ruError(" in html
    for phrase in ("cannot delete active preset",
                   "invalid name",
                   "too many concurrent checks, try later"):
        assert phrase in html, phrase
    handle = _ui_fn(html, "handle")
    assert "ruError(" in handle
    assert "humanError(" in _ui_fn(html, "flash")
```

**Step 2: Run tests to verify they fail**

```bash
.venv/bin/python -m pytest -q tests/test_naivepanel.py::test_p0_api_errors_are_localized
```

Expected: FAIL — `ruError()`/`humanError()` отсутствуют.

**Step 3: Implement**

Заменить `handle()` и добавить перед ним:

```js
// Сервер отдаёт технические английские abort(description). Наружу — понятная
// причина; незнакомое оставляем как есть, чтобы не терять детали для поддержки.
const ERROR_RU = {
  'cannot delete active preset': 'Активный пресет нельзя удалить — сначала переключитесь на другой.',
  'invalid name': 'Недопустимое имя пресета: только a-z, 0-9, _ - .',
  'name in body must match URL': 'Имя в форме не совпадает с именем пресета.',
  'too many concurrent checks, try later': 'Слишком много одновременных проверок. Подождите минуту.',
  'too many failed auth attempts, try later': 'Слишком много неудачных попыток входа. Подождите минуту.',
  'panel is exposed without a password — set one (install.sh --with-auth) first':
    'Панель открыта в сеть без пароля. Сначала задайте пароль (install.sh --with-auth).',
  'host not allowed (see NAIVEPANEL_HOSTS)': 'Адрес панели не разрешён. Проверьте NAIVEPANEL_HOSTS.',
};

function ruError(msg, status) {
  if (msg && ERROR_RU[msg]) return ERROR_RU[msg];
  if (typeof msg === 'string' && /^preset .+ not found$/.test(msg))
    return 'Пресет не найден — обновите список.';
  if (status === 401) return 'Неверный пароль. Войдите заново.';
  if (status === 403) return 'Доступ запрещён.';
  if (status === 429) return 'Слишком много запросов. Подождите минуту.';
  return msg || ('HTTP ' + status);
}

// fetch() бросает «Failed to fetch»/«Load failed» без HTTP-статуса — это
// сетевой обрыв, а не текст сервера.
function humanError(err) {
  const msg = String((err && err.message) || err || '');
  if (/Failed to fetch|NetworkError|Load failed|Network request failed/i.test(msg))
    return 'Нет связи с панелью';
  return msg;
}

async function handle(r) {
  const txt = await r.text();
  let data; try { data = JSON.parse(txt); } catch { data = {raw:txt}; }
  if (!r.ok) {
    const raw = data.error || data.description || data.message || data.raw || ('HTTP ' + r.status);
    const err = new Error(ruError(raw, r.status));
    err.httpStatus = r.status;
    throw err;
  }
  return data;
}
```

В начале `flash()` (до `$('msg').textContent = msg;`) добавить:

```js
  msg = humanError(msg);
```

**Step 4: Verify**

```bash
.venv/bin/python -m pytest -q tests/test_naivepanel.py::test_p0_api_errors_are_localized
.venv/bin/python -m pytest -q
```

Expected: PASS, 444 passed (было 443 + 1 новый), 1 skipped.

**Step 5: Manual check**

На живом стенде удалить активный пресет через API (в обход скрытого UI) и
убедиться, что тост русский:

```bash
curl -i -u admin:... -X DELETE -H 'X-Requested-With: naivepanel' \
  http://127.0.0.1:8089/api/configs/<active>
```

В UI вызвать действие, читающее 409 (например, через консоль
`fetch('/api/configs/<active>', {method:'DELETE', headers:{'X-Requested-With':'naivepanel'}})`),
и проверить тост: «Активный пресет нельзя удалить — сначала переключитесь…».

**Step 6: Commit**

```bash
git add templates/index.html tests/test_naivepanel.py
git commit -m "feat(ui): localize API and network errors"
```

---

### Task 2: Строка профиля v2 и меню действий

**Files:**
- Modify: `templates/index.html` — CSS `ul.presets`, новый `renderPresets`,
  `openPresetMenu`, `IC.more/empty/search`, диалог `#presetMenuDlg`, ACTIONS.
- Test: `tests/test_naivepanel.py` — новые тесты.

**Целевая строка (anatomy):**

```text
[ nl-main  активен ]                 [⋯]
[ lex · nl1.keenetic.pro:443   осн. ×2 ]
```

Высота ≤72px на 390px; имя не сжимается бейджами до нуля; `host:port` читается
без схемы и маски; действия — только в меню, не столбиком иконок.

**Step 1: Write the failing tests**

```python
def test_p0_preset_row_two_lines_and_menu(app):
    html = _ui_html()
    body = _ui_fn(html, "renderPresets")
    assert 'class="ptop"' in body
    assert 'class="pmeta"' in body
    assert 'class="kebab"' in body
    assert 'data-action="presetMenu"' in body
    assert 'data-action="foUp"' not in body, "стрелки порядка должны жить в диалоге"
    assert 'class="acts"' not in body, "старый столбик иконок остался"
    assert "isActivePreset" in body
    assert "orderedPresets" in body

    css = re.search(r"ul\.presets li \{[^}]*\}", html, re.S)
    assert css and "display:grid" in css.group(0)
    assert "grid-template-columns:minmax(0,1fr) auto" in css.group(0)
    for cls in (r"\.ptop", r"\.pmeta", r"\.kebab"):
        assert re.search(cls + r" \{[^}]*\}", html), cls


def test_p0_preset_menu_has_labelled_actions(app):
    html = _ui_html()
    assert 'id="presetMenuDlg"' in html
    assert 'id="pmActions"' in html
    menu = _ui_fn(html, "openPresetMenu")
    for label in ("Сделать активным", "Дублировать",
                  "Добавить в цепочку", "Убрать из цепочки", "Удалить"):
        assert label in menu, label
    assert "isActivePreset" in menu
    assert "presetMenuDlg" in menu or "showModal" in menu


def test_p0_empty_state_layout(app):
    html = _ui_html()
    css = re.search(r"ul\.presets \.empty \{[^}]*\}", html, re.S)
    assert css and "flex-direction:column" in css.group(0)
    body = _ui_fn(html, "renderPresets")
    assert "IC.empty" in body and "IC.search" in body
    assert "Вставьте строку подключения" in body
    assert "focusQuick" in body
```

Обновить существующий `test_ui_failover_lives_with_presets`: убрать из списка
маркеры `'data-action="foUp"'`, `'data-action="foDown"'`, `"foOrderMode"`,
`'aria-label="Добавить'` — после Task 2 строки больше не содержат стрелок и
режима порядка. Task 3 вернёт `foUp`/`foDown` в диалог и добавит
`renderFoOrder`/`foOrderDlg` к этому же тесту.

**Step 2: Run tests to verify they fail**

```bash
.venv/bin/python -m pytest -q \
  tests/test_naivepanel.py::test_p0_preset_row_two_lines_and_menu \
  tests/test_naivepanel.py::test_p0_preset_menu_has_labelled_actions \
  tests/test_naivepanel.py::test_p0_empty_state_layout
```

Expected: FAIL — новых классов/меню нет.

**Step 3: Implement CSS**

Удалить/заменить блок от `ul.presets li` до `ul.presets .del:hover` (строки
~126–153) на:

```css
  ul.presets li { border:1px solid var(--border); border-radius:var(--r-m); margin-bottom:6px;
                  display:grid; grid-template-columns:minmax(0,1fr) auto; align-items:center;
                  background:var(--input-bg); min-width:0;
                  transition:border-color .14s ease, transform .14s ease, box-shadow .14s ease; }
  ul.presets li:hover { border-color:var(--acc); transform:translateY(-1px); box-shadow:var(--shadow-1); }
  ul.presets li.selected { border-color:var(--border-sel); background:var(--sel-bg); }
  ul.presets li.active { border-color:var(--acc); background:var(--acc-tint); }
  ul.presets .sel { display:flex; flex-direction:column; align-items:flex-start; gap:2px;
                    min-width:0; padding:9px 6px 9px 12px; background:none; border:none;
                    color:inherit; font:inherit; text-align:left; cursor:pointer;
                    border-radius:9px; width:100%; box-shadow:none; }
  ul.presets .sel:hover { background:var(--hov); filter:none; box-shadow:none; }
  ul.presets .ptop { display:flex; align-items:center; gap:6px; min-width:0; width:100%; }
  ul.presets .name { font-weight:600; min-width:0; flex:0 1 auto;
                     overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
  ul.presets .pmeta { display:flex; align-items:center; gap:6px; min-width:0; width:100%;
                      color:var(--mut); font-size:12px; }
  ul.presets .proxy { min-width:0; flex:1 1 auto; overflow:hidden;
                      text-overflow:ellipsis; white-space:nowrap; }
  ul.presets .pbadges { display:flex; align-items:center; gap:4px; flex:none; margin-left:auto; }
  ul.presets .badge { font-size:11px; font-weight:600; padding:2px 7px; border-radius:999px;
                      background:var(--badge-bg); color:var(--acc); white-space:nowrap; }
  ul.presets .badge.listen { background:var(--mut-tint); color:var(--mut); }
  ul.presets .kebab { width:36px; height:36px; padding:0; margin-right:4px;
                      display:inline-flex; align-items:center; justify-content:center;
                      background:none; border:none; border-radius:8px; color:var(--mut);
                      box-shadow:none; cursor:pointer; }
  ul.presets .kebab:hover { background:var(--hov); color:var(--fg); filter:none; }
  ul.presets .empty { display:flex; flex-direction:column; align-items:center; gap:6px;
                      text-align:center; padding:26px 12px; border-style:dashed; }
  ul.presets li.empty:hover { border-color:var(--border); transform:none; box-shadow:none; }
  ul.presets .empty .ic { width:22px; height:22px; opacity:.55; }
  ul.presets .empty b { font-weight:600; color:var(--fg); }
  ul.presets .empty .hint { display:block; font-size:12px; opacity:.85; margin:0; }
  ul.presets .empty button { margin-top:6px; }
```

Удалить старые правила `.empty`, `.act`, `.del` (они больше не используются в
списке); `.rbrow .del` остаётся отдельно.

В мобильный блок (≤800px) добавить:

```css
    ul.presets .kebab { width:44px; height:44px; min-width:44px; min-height:44px; margin-right:0; }
```

Добавить глобальное правило рядом с `* { box-sizing:border-box; }`:

```css
  [hidden] { display:none !important; }
```

**Step 4: Implement icons and JS**

В `IC` добавить три иконки:

```js
  more: '<svg class="ic" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" aria-hidden="true"><path d="M8 3.2h.01M8 8h.01M8 12.8h.01"/></svg>',
  empty: '<svg class="ic" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="2.2" y="3.2" width="11.6" height="9.6" rx="2"/><path d="M5 8h6M8 5v6"/></svg>',
  search: '<svg class="ic" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><circle cx="7" cy="7" r="4.5"/><path d="M10.5 10.5L14 14"/></svg>',
```

Добавить рядом с `orderedPresets` (и заменить `orderedPresets`):

```js
function proxyHost(proxy) {
  const s = String(proxy || '');
  const at = s.lastIndexOf('@');
  const tail = at >= 0 ? s.slice(at + 1) : s.replace(/^[a-z]+:\/\//i, '');
  return tail.replace(/\/+$/, '') || s;
}

function presetMeta(p) {
  const m = String(p.proxy || '').match(/^([a-z]+):\/\//i);
  const scheme = m ? m[1].toLowerCase() : '';
  const host = proxyHost(p.proxy);
  const proto = scheme && scheme !== 'https' ? scheme + ' · ' : '';
  return proto + (p.username ? p.username + ' · ' : '') + host;
}

function isActivePreset(p) {
  return activeName ? p.name === activeName : !!p.active;
}

function orderedPresets(presets) {
  // Активный — первым: он не должен тонуть в алфавитном списке conf.d.
  return presets.filter(isActivePreset).concat(presets.filter(p => !isActivePreset(p)));
}
```

Заменить `renderPresets()` целиком:

```js
function renderPresets(presets) {
  lastPresets = presets;
  setEditorState(); // activeName приходит из статуса — чип должен поспевать
  const ordered = orderedPresets(presets);
  const q = ($('search').value || '').trim().toLowerCase();
  const shown = q ? ordered.filter(p =>
    (p.name + ' ' + (p.proxy || '')).toLowerCase().includes(q)) : ordered;
  const ul = $('presets'); ul.setAttribute('aria-busy','false'); ul.innerHTML = '';

  if (!presets.length) {
    ul.innerHTML = '<li class="empty" aria-live="polite">' + IC.empty + '<b>Пресетов пока нет</b>'
      + '<span class="hint">Вставьте строку подключения выше или нажмите «+ Новый»</span>'
      + '<button type="button" class="ghost" data-action="focusQuick">Вставить ссылку</button></li>';
    return;
  }
  if (!shown.length) {
    ul.innerHTML = '<li class="empty" aria-live="polite">' + IC.search + '<b>Ничего не найдено</b>'
      + '<span class="hint">Попробуйте другое слово или очистите поиск</span></li>';
    return;
  }

  for (const p of shown) {
    const li = document.createElement('li');
    const isActive = isActivePreset(p);
    li.className = (isActive ? 'active' : '') + (p.name === current ? ' selected' : '');
    const masked = p.proxy.replace(/:\/\/[^@]+@/, '://***@');
    const idx = foChainArr.indexOf(p.name);
    const role = idx === 0
      ? '<span class="badge" title="Основной в цепочке">осн.</span>'
      : (idx > 0 ? '<span class="badge" title="Резерв ' + (idx + 1) + '">№' + (idx + 1) + '</span>' : '');
    const listen = p.listen_count > 1
      ? '<span class="badge listen" title="Слушает ' + p.listen_count + ' адреса">×' + p.listen_count + '</span>'
      : '';
    const name = escapeHtml(p.name);
    li.innerHTML = '<button class="sel" data-action="select" data-arg="' + name + '"'
      + (p.name === current ? ' aria-current="true"' : '') + '>'
      + '<span class="ptop"><span class="name" title="' + name + '">' + name + '</span>'
      + (isActive ? '<span class="badge">активен</span>' : '') + '</span>'
      + '<span class="pmeta"><span class="proxy" title="' + escapeHtml(masked) + '">'
      + escapeHtml(presetMeta(p)) + '</span>'
      + '<span class="pbadges">' + role + listen + '</span></span>'
      + '</button>'
      + '<button class="kebab" type="button" data-action="presetMenu" data-arg="' + name + '"'
      + ' aria-label="Действия с ' + name + '" aria-haspopup="dialog">' + IC.more + '</button>';
    ul.appendChild(li);
  }
}
```

Добавить диалог после `#confirmDlg`:

```html
<dialog id="presetMenuDlg" aria-labelledby="pmTitle">
  <p id="pmTitle" class="dlgtitle"></p>
  <p id="pmMeta" class="dlgsub"></p>
  <div class="pmenu" id="pmActions"></div>
  <form method="dialog" class="dlg-actions">
    <button class="ghost" value="close">Отмена</button>
  </form>
</dialog>
```

CSS рядом с `dialog`:

```css
  .dlgtitle { margin:0; font-weight:600; }
  .dlgsub { margin:4px 0 0; font-size:12px; color:var(--mut); }
  .pmenu { display:flex; flex-direction:column; gap:8px; margin-top:14px; }
  .pmenu button { width:100%; text-align:left; }
```

Добавить JS после `renderPresets`:

```js
function openPresetMenu(name) {
  const p = lastPresets.find(x => x.name === name);
  if (!p) return;
  const isActive = isActivePreset(p);
  const inChain = foChainArr.includes(name);
  const full = !inChain && foChainArr.length >= FO_CHAIN_MAX;
  const n = escapeHtml(name);
  const acts = [];
  $('pmTitle').textContent = name;
  $('pmMeta').textContent = presetMeta(p) + (isActive ? ' · активен' : '');
  if (!isActive)
    acts.push('<button type="button" class="ghost" data-action="activate" data-arg="' + n + '">Сделать активным</button>');
  if (inChain)
    acts.push('<button type="button" class="ghost" data-action="foToggle" data-arg="' + n + '">Убрать из цепочки</button>');
  else
    acts.push('<button type="button" class="ghost" data-action="foToggle" data-arg="' + n + '"'
      + (full ? ' disabled title="Цепочка заполнена"' : '') + '>Добавить в цепочку</button>');
  acts.push('<button type="button" class="ghost" data-action="duplicate" data-arg="' + n + '">Дублировать</button>');
  if (!isActive)
    acts.push('<button type="button" class="danger" data-action="del" data-arg="' + n + '">Удалить</button>');
  $('pmActions').innerHTML = acts.join('');
  $('presetMenuDlg').showModal();
}
```

В `ACTIONS` добавить:

```js
  presetMenu: (arg) => openPresetMenu(arg),
  focusQuick: () => { $('quickUri').scrollIntoView({block:'center'}); $('quickUri').focus(); },
```

В делегированном обработчике кликов закрывать меню до действия:

```js
document.addEventListener('click', (e) => {
  const el = e.target.closest('[data-action]');
  if (!el) return;
  const fn = ACTIONS[el.dataset.action];
  if (!fn) return;
  e.preventDefault();
  const menu = $('presetMenuDlg');
  if (menu.open && el.closest('#presetMenuDlg')) menu.close();
  fn(el.dataset.arg);
});
```

**Временная совместимость с Task 3:** в этом коммите `renderPresets` больше
не рисует стрелки порядка, а старый `foOrderMode` ещё существует до Task 3.
Чтобы не показывать неработающий режим, добавить `hidden` к `#btnFoOrder`;
Task 3 снимает `hidden` и заменяет режим диалогом. Не деплоить промежуточный
коммит между Task 2 и Task 3.

**Step 5: Verify**

```bash
.venv/bin/python -m pytest -q \
  tests/test_naivepanel.py::test_p0_preset_row_two_lines_and_menu \
  tests/test_naivepanel.py::test_p0_preset_menu_has_labelled_actions \
  tests/test_naivepanel.py::test_p0_empty_state_layout
.venv/bin/python -m pytest -q
```

Expected: PASS, 447 passed, 1 skipped.

Manual: 390px — строка active `nl-main` ≤72px, имя читается, `lex ·
nl1.keenetic.pro:443` во второй строке, `⋯` 44×44; меню открывается, фокус на
первом пункте, Esc закрывает, «Отмена» возвращает фокус на `⋯`; при активном
пресете в меню нет «Сделать активным» и «Удалить». На desktop — строка не
выше 64px, активная строка не теряет имя; длинные имена обрезаются с ellipsis,
а не исчезают в «f…».

**Step 6: Commit**

```bash
git add templates/index.html tests/test_naivepanel.py
git commit -m "feat(ui): two-line preset rows with action menu"
```

---

### Task 3: Диалог порядка цепочки, удаление `foOrderMode`

**Files:**
- Modify: `templates/index.html` — `renderFoOrder`, `openFoOrder`, диалог
  `#foOrderDlg`, `renderFailover`, `foSaveState`, `foMove`, ACTIONS, HTML кнопки
  «Порядок».
- Test: `tests/test_naivepanel.py` — новый тест + обновление
  `test_ui_failover_lives_with_presets`.

**Step 1: Return the contract markers and add the failing test**

В `test_ui_failover_lives_with_presets` (из Task 2) добавить обратно/добавить
маркеры:

```python
                   'data-action="foUp"', 'data-action="foDown"',
                   "renderFoOrder", 'id="foOrderDlg"',
                   "Добавить в цепочку",
```

`"foOrderMode"` не возвращать: режим удалён. Остальные маркеры
(`FO_CHAIN_MAX`, `orderedPresets`, `captureFocus`, `restoreFocus`, `foInfo`,
`foEnabled`, `foAuto`, `foCount`, `foOrder`, `foAll`, `foToggle`,
`/api/failover`) остаются как были.

Добавить:

```python
def test_p0_failover_order_is_a_dialog(app):
    html = _ui_html()
    assert 'id="foOrderDlg"' in html
    assert 'id="foOrderList"' in html
    assert "foOrderMode" not in html, "режим порядка в строках должен быть удалён"
    assert "renderFoOrder" in _ui_fn(html, "foSaveState")
    order = _ui_fn(html, "renderFoOrder")
    assert "foUp" in order and "foDown" in order
    assert "order-item" in order
    assert "foOrder: () => openFoOrder()" in html
```

**Step 2: Run tests to verify they fail**

```bash
.venv/bin/python -m pytest -q \
  tests/test_naivepanel.py::test_p0_failover_order_is_a_dialog \
  tests/test_naivepanel.py::test_ui_failover_lives_with_presets
```

Expected: FAIL — `foOrderMode` ещё в HTML, диалога нет.

**Step 3: Implement HTML/CSS**

Кнопку «Порядок» заменить (убрать `hidden` из Task 2, убрать
`aria-pressed`, добавить `aria-haspopup`):

```html
      <button class="ghost" data-action="foOrder" id="btnFoOrder"
              aria-haspopup="dialog"
              title="Изменить порядок пресетов в цепочке">Порядок</button>
```

Добавить диалог рядом с `#presetMenuDlg`:

```html
<dialog id="foOrderDlg" aria-labelledby="foOrderTitle">
  <p id="foOrderTitle" class="dlgtitle">Порядок цепочки</p>
  <p class="dlgsub">При сбое панель переключается на следующий пресет сверху вниз.</p>
  <ol id="foOrderList" class="order-list"></ol>
  <form method="dialog" class="dlg-actions">
    <button class="ghost" value="close">Готово</button>
  </form>
</dialog>
```

CSS:

```css
  .order-list { list-style:none; margin:12px 0 0; padding:0; display:flex;
                flex-direction:column; gap:6px; max-height:320px; overflow:auto; }
  .order-item { display:grid; grid-template-columns:20px minmax(0,1fr) 44px 44px;
                align-items:center; gap:6px; padding:4px 0;
                border-bottom:1px solid var(--border); }
  .order-item .onum { color:var(--mut); font-size:12px; text-align:right; }
  .order-item .oname { min-width:0; overflow:hidden; text-overflow:ellipsis;
                       white-space:nowrap; }
```

**Step 4: Implement JS**

Удалить `foToggleOrder()` и `let foOrderMode = ...`. В `orderedPresets`/
`renderPresets` уже нет режима (Task 2). В `renderFailover` удалить строки,
меняющие `order.textContent`/`aria-pressed`, оставить:

```js
  const order = $('btnFoOrder');
  order.disabled = foBusy || !chain.length;
  $('btnFoAll').disabled = foBusy
    || chain.length >= FO_CHAIN_MAX
    || !lastPresets.some(p => !chain.includes(p.name));
```

Добавить:

```js
function renderFoOrder() {
  const list = $('foOrderList');
  if (!foChainArr.length) {
    list.innerHTML = '<li class="empty">Цепочка пуста</li>';
    return;
  }
  list.innerHTML = foChainArr.map((name, i) => '<li class="order-item">'
    + '<span class="onum">' + (i + 1) + '</span>'
    + '<span class="oname" title="' + escapeHtml(name) + '">' + escapeHtml(name) + '</span>'
    + '<button type="button" class="ghost iconbtn" data-action="foUp" data-arg="' + escapeHtml(name) + '"'
    + ' aria-label="Выше ' + escapeHtml(name) + '" title="Выше"'
    + (i === 0 || foBusy ? ' disabled' : '') + '>' + IC.up + '</button>'
    + '<button type="button" class="ghost iconbtn" data-action="foDown" data-arg="' + escapeHtml(name) + '"'
    + ' aria-label="Ниже ' + escapeHtml(name) + '" title="Ниже"'
    + (i === foChainArr.length - 1 || foBusy ? ' disabled' : '') + '>' + IC.down + '</button>'
    + '</li>').join('');
}

function openFoOrder() {
  if (!foChainArr.length) return;
  renderFoOrder();
  $('foOrderDlg').showModal();
}
```

В `foSaveState().finally` перед `restoreFocus(focus)` добавить:

```js
    if ($('foOrderDlg').open) renderFoOrder();
```

В `ACTIONS` заменить `foOrder: () => foToggleOrder(),` на:

```js
  foOrder: () => openFoOrder(),
```

**Step 5: Verify**

```bash
.venv/bin/python -m pytest -q \
  tests/test_naivepanel.py::test_p0_failover_order_is_a_dialog \
  tests/test_naivepanel.py::test_ui_failover_lives_with_presets
.venv/bin/python -m pytest -q
```

Expected: PASS, 448 passed, 1 skipped.

Manual: «Порядок» открывает диалог; полные имена, номера, ↑/↓ 44px; на краях
кнопки disabled; после ↑ фокус остаётся на той же стрелке (не падает на body);
Esc/«Готово» закрывает; список пресетов больше не меняет разметку.

**Step 6: Commit**

```bash
git add templates/index.html tests/test_naivepanel.py
git commit -m "feat(ui): move failover ordering into a dialog"
```

### Task 4: Редактор — block/empty-state, scroll/focus, возврат фокуса

**Files:**
- Modify: `templates/index.html` — обёртка `#editorBlock`, `#editorEmpty`,
  `#mainCard.no-editor`, `isEditorOpen`, `focusPresetRow`, `syncEditorChrome`,
  `selectPreset`, `newPreset`, `hideEditor`, `closeEditor`, `del`, shortcuts.
- Test: `tests/test_naivepanel.py` — 2 новых теста + обновление
  `test_ui_editor_closable_by_button_and_esc`.

**Step 1: Write failing tests and update the old contract**

В `test_ui_editor_closable_by_button_and_esc` заменить маркер
`"if ($('editor').style.display !== 'none'"` на `"if (isEditorOpen()"`.

Добавить:

```python
def test_p0_editor_opens_visible_and_focuses_title(app):
    html = _ui_html()
    assert 'id="editorBlock" hidden' in html
    assert 'id="editorEmpty"' in html
    assert re.search(r'<h2 id="editorTitle"[^>]*tabindex="-1"', html), \
        "заголовок редактора должен принимать программный фокус"
    sel = _ui_fn(html, "selectPreset")
    assert "editorBlock" in sel
    assert "scrollIntoView" in sel
    assert ".focus(" in sel
    assert "function isEditorOpen(" in html


def test_p0_editor_close_returns_focus(app):
    html = _ui_html()
    close = _ui_fn(html, "closeEditor")
    assert "hideEditor" in close and "focusPresetRow" in close
    hide = _ui_fn(html, "hideEditor")
    assert "editorBlock" in hide
```

**Step 2: Run to verify failure**

```bash
.venv/bin/python -m pytest -q \
  tests/test_naivepanel.py::test_p0_editor_opens_visible_and_focuses_title \
  tests/test_naivepanel.py::test_p0_editor_close_returns_focus \
  tests/test_naivepanel.py::test_ui_editor_closable_by_button_and_esc
```

Expected: FAIL — `#editorBlock`/`isEditorOpen` отсутствуют.

**Step 3: HTML**

Обернуть заголовок и форму. Начало центральной карточки:

```html
  <section class="card no-editor" id="mainCard" style="grid-area:main">
    <div id="editorEmpty" class="edempty" hidden>
      <span>Пресет не выбран — выберите в списке.</span>
      <button type="button" class="ghost" data-action="newPreset">Создать пресет</button>
    </div>
    <div id="editorBlock" hidden>
      <h2 id="editorTitle" tabindex="-1"><span id="editorTitleText">Редактор</span>…</h2>
      <form id="editor">
        …
      </form>
    </div>
    <div id="msg" class="sr-only" aria-live="polite"></div>
```

У `#editor` убрать `style="display:none"` — видимостью управляет только
`#editorBlock`. Закрывающий `</div>` для `#editorBlock` — сразу после `</form>`.

CSS:

```css
  .edempty { display:flex; align-items:center; flex-wrap:wrap; gap:10px;
             font-size:13px; color:var(--mut); padding:2px 0 14px;
             border-bottom:1px solid var(--border); margin-bottom:14px; }
  #mainCard.no-editor #sec-diag { margin-top:0; padding-top:0; border-top:0; }
  #editorTitle { scroll-margin-top:64px; }
  @media (max-width:800px) { #editorTitle { scroll-margin-top:118px; } }
```

**Step 4: JS**

Добавить перед `selectPreset`:

```js
function isEditorOpen() { return !$('editorBlock').hidden; }

function focusPresetRow(name) {
  if (!name) return false;
  const row = [...document.querySelectorAll('ul.presets .sel')]
    .find(b => b.dataset.arg === name);
  if (!row) return false;
  row.scrollIntoView({block:'center'});
  row.focus();
  return true;
}

function syncEditorChrome() {
  const noPresets = !lastPresets.length;
  $('editorEmpty').hidden = noPresets || isEditorOpen();
  $('mainCard').classList.toggle('no-editor', !isEditorOpen());
}
```

В `renderPresets` сразу после `lastPresets = presets;` добавить
`syncEditorChrome();` (Task 6 расширит эту функцию).

В `selectPreset` заменить `$('editor').style.display = 'block';` на:

```js
    $('editorBlock').hidden = false;
    syncEditorChrome();
```

и в конце, после `$('msg').textContent = '';`, добавить:

```js
    const title = $('editorTitle');
    title.scrollIntoView({block:'start', behavior:'instant'});
    title.focus({preventScroll:true});
```

В `newPreset` заменить `$('editor').style.display = 'block';` на:

```js
  $('editorBlock').hidden = false;
  syncEditorChrome();
```

(фокус `f_name` уже есть и прокрутит поле).

Заменить `hideEditor` и `closeEditor`:

```js
function hideEditor(focusBack = true) {
  const name = current;
  current = null;
  dirty = false;
  $('editorBlock').hidden = true;
  setHash(null);
  setEditorState();
  syncEditorChrome();
  if (focusBack && !focusPresetRow(name)) $('search').focus();
}

async function closeEditor() {
  if (!(await maybeDiscard())) return;
  const name = current;
  hideEditor(false);
  renderPresets(lastPresets);
  if (!focusPresetRow(name)) $('search').focus();
}
```

В `del()` вызов `hideEditor()` заменить на `hideEditor(false)` (строки уже
удаляется, фокус вернёт `refreshAll`).

В горячих клавишах заменить проверки видимости формы:

```js
    if (isEditorOpen()) { e.preventDefault(); save(null); }
```

```js
  if (isEditorOpen() && e.target.tagName !== 'SUMMARY') closeEditor();
```

**Step 5: Verify**

```bash
.venv/bin/python -m pytest -q \
  tests/test_naivepanel.py::test_p0_editor_opens_visible_and_focuses_title \
  tests/test_naivepanel.py::test_p0_editor_close_returns_focus \
  tests/test_naivepanel.py::test_ui_editor_closable_by_button_and_esc
.venv/bin/python -m pytest -q
```

Expected: PASS, 450 passed, 1 skipped.

Manual: 390px, список прокручен к 4-му пресету, тап — страница сразу
переходит к редактору, заголовок «Редактор — …» в фокусе, форма видна; Esc →
список, фокус на той же строке; «Создать» → форма открыта. Закрытый редактор
не оставляет пустой заголовок с линией: видна одна строка «Пресет не выбран»
(или ничего на пустой установке).

**Step 6: Commit**

```bash
git add templates/index.html tests/test_naivepanel.py
git commit -m "feat(ui): open editor on preset select and manage focus"
```

---

### Task 5: Сервисные действия — состояние, подтверждения, save-guard

**Files:**
- Modify: `templates/index.html` — `renderServiceButtons`, `renderEditorChrome`,
  `renderStatus`, `svc`, `activate`, `del`, `save`, `setEditorState`; ID кнопок,
  `#editorApplyHint`.
- Test: `tests/test_naivepanel.py` — 3 новых теста.

**Step 1: Write failing tests**

```python
def test_p0_service_buttons_state(app):
    html = _ui_html()
    for bid in ("btnStart", "btnStop", "btnRestart", "btnE2e"):
        assert f'id="{bid}"' in html
    fn = _ui_fn(html, "renderServiceButtons")
    assert "$('btnStart').hidden" in fn
    assert "$('btnStop').hidden" in fn
    assert "$('btnStart').disabled" in fn
    assert "st.current" in fn and "st.active" in fn
    assert "init_present" in fn
    assert "focused.hidden" in fn, "фокус не должен теряться при скрытии кнопки"


def test_p0_stop_confirm_and_activate_guard(app):
    html = _ui_html()
    svc = _ui_fn(html, "svc")
    assert "askConfirm" in svc
    assert "Остановить прокси" in svc
    assert "соединений" in svc
    act = _ui_fn(html, "activate")
    assert "n === activeName" in act
    assert "askConfirm" in act


def test_p0_save_pristine_and_active_guards(app):
    html = _ui_html()
    chrome = _ui_fn(html, "renderEditorChrome")
    assert "btnActivate" in chrome and "btnDelete" in chrome
    assert "btnSave" in chrome and "dirty" in chrome
    assert "editorApplyHint" in html
    save = _ui_fn(html, "save")
    assert "current && !dirty" in save
    assert "renderEditorChrome()" in save, "finally обязан пересчитать disabled"
    assert "btn.disabled = false" not in save
    delete = _ui_fn(html, "del")
    assert "foChainArr.includes" in delete
    assert "Активный пресет" in delete
```

**Step 2: Run to verify failure**

```bash
.venv/bin/python -m pytest -q \
  tests/test_naivepanel.py::test_p0_service_buttons_state \
  tests/test_naivepanel.py::test_p0_stop_confirm_and_activate_guard \
  tests/test_naivepanel.py::test_p0_save_pristine_and_active_guards
```

Expected: FAIL — IDs/функций нет.

**Step 3: HTML/CSS**

Кнопки сервиса:

```html
      <button data-action="svc" data-arg="start" id="btnStart">Запуск</button>
      <button class="ghost" data-action="svc" data-arg="stop" id="btnStop">Стоп</button>
      <button class="ghost" data-action="svc" data-arg="restart" id="btnRestart">Рестарт</button>
```

Кнопки редактора:

```html
      <p id="editorApplyHint" class="apply-hint" hidden>
        Изменения активного пресета применятся сразу: прокси перезапустится,
        соединения оборвутся.
      </p>
      <div class="row">
        <button type="submit" id="btnSave" title="Ctrl+S">Сохранить</button>
        <button type="button" class="ghost" id="btnActivate"
                data-action="activate">Сделать активным</button>
        <button type="button" class="danger" id="btnDelete"
                data-action="del">Удалить</button>
      </div>
```

CSS:

```css
  .apply-hint { margin-top:12px; color:var(--warn); font-size:12px; }
  .row #btnDelete { margin-left:auto; }
```

**Step 4: JS**

Добавить глобал и рендер кнопок (рядом с `renderStatus`):

```js
let lastStatus = null;
let svcKey = '';

function renderServiceButtons(st, force) {
  const has = !!st.current;
  const init = st.init_present !== false;
  const running = !!st.active;
  const key = [running, has, init].join('|');
  if (!force && key === svcKey) return;
  svcKey = key;

  // Если фокус стоял на кнопке, которую сейчас скроем (Start после старта,
  // Stop после остановки), уводим его на следующее доступное действие, а не
  // на body.
  const focused = document.activeElement;
  const keepFocus = !!(focused && focused.matches('[data-action="svc"]'));

  // Кнопки не «мертвые»: в каждом состоянии видно только применимое действие.
  $('btnStart').hidden = running || !has;
  $('btnStop').hidden = !running;
  $('btnRestart').hidden = !running;
  $('btnStart').disabled = !init;
  $('btnStop').disabled = !init;
  $('btnRestart').disabled = !init;
  $('btnE2e').disabled = !has;

  if (keepFocus && focused.hidden) {
    const next = [$('btnStop'), $('btnRestart'), $('btnStart'), $('btnE2e')]
      .find(b => b && !b.hidden && !b.disabled);
    if (next) next.focus();
  }

  const why = init ? '' : 'init-скрипт не найден';
  for (const b of [$('btnStart'), $('btnStop'), $('btnRestart')]) b.title = why;
}
```

В начале `renderStatus` добавить `lastStatus = st; renderServiceButtons(st);`;
в конце — `renderEditorChrome();`.

Заменить `svc()`:

```js
async function svc(action) {
  if (action === 'start' && lastStatus && lastStatus.active) return;
  if (action !== 'start' && lastStatus && lastStatus.active) {
    const n = lastStatus.connections ? lastStatus.connections.established : null;
    const head = action === 'stop'
      ? 'Остановить прокси? Интернет через прокси пропадёт у всех устройств, которые им пользуются.'
      : 'Перезапустить прокси? Соединения через прокси оборвутся на несколько секунд.';
    const tail = n == null ? '' : '\nСейчас соединений через прокси: ' + n + '.';
    const ok = await askConfirm(head + tail, {
      ok: action === 'stop' ? 'Остановить' : 'Перезапустить',
      danger: action === 'stop',
    });
    if (!ok) return;
  }
  const buttons = Array.from(document.querySelectorAll('[data-action="svc"]'));
  buttons.forEach(b => { b.disabled = true; });
  try {
    const d = await jpost('/api/service/' + action, null);
    const failed = restartFailed(d);
    flash('Сервис ' + (SVC_VERBS[action] || action)
          + (failed ? ' — НЕ удался: ' + (d.stderr || d.stdout || ('rc=' + d.rc)) : ''),
          !failed);
    await refreshAll();
  } catch (e) { flash(e.message, false); }
  finally { renderServiceButtons(lastStatus || {}, true); }
}
```

Заменить `activate()`:

```js
async function activate(name) {
  const n = name || current;
  if (!n) return;
  const p = lastPresets.find(x => x.name === n);
  if (n === activeName || (p && p.active)) {
    flash('Пресет уже активен', true);
    return;
  }
  let msg = '';
  if (dirty) msg += 'В форме есть несохранённые правки — активируется последняя сохранённая версия пресета.\n';
  if (lastStatus && lastStatus.active)
    msg += 'Прокси перезапустится, соединения оборвутся на несколько секунд.';
  if (msg && !(await askConfirm(msg, {ok: 'Активировать'}))) return;
  try {
    const d = await jpost('/api/configs/' + encodeURIComponent(n) + '/activate', null);
    flash(applyMsg('Активирован: ' + n, d.restart), !restartFailed(d.restart));
    await refreshAll();
  } catch (e) { flash(e.message, false); }
}
```

Заменить `del()`:

```js
async function del(name) {
  const n = name || current;
  if (!n) return;
  const p = lastPresets.find(x => x.name === n);
  if (n === activeName || (p && p.active)) {
    flash('Активный пресет нельзя удалить — сначала переключитесь на другой.', false);
    return;
  }
  let msg = 'Удалить пресет ' + n + '?';
  if (foChainArr.includes(n)) msg += '\nОн также будет убран из цепочки фейловера.';
  if (!(await askConfirm(msg, {ok: 'Удалить', danger: true}))) return;
  try {
    await jdel('/api/configs/' + encodeURIComponent(n));
    if (current === n) hideEditor(false);
    flash('Удалён: ' + n, true);
    await refreshAll();
  } catch (e) { flash(e.message, false); }
}
```

В `save()` после `if (saving) return;` добавить:

```js
  if (current && !dirty) return; // нечего сохранять: не дёргаем restart активного
```

Заменить `setEditorState` на версию с chrome:

```js
function setEditorState() {
  const el = $('editorState');
  if (!current) {
    el.textContent = '';
    el.className = 'edstate';
  } else if (dirty) {
    el.textContent = 'изменено';
    el.className = 'edstate dirty';
  } else if (activeName && current === activeName) {
    el.textContent = 'активен';
    el.className = 'edstate active';
  } else {
    el.textContent = 'сохранено';
    el.className = 'edstate';
  }
  renderEditorChrome();
}
```

Добавить `renderEditorChrome`:

```js
function renderEditorChrome() {
  const has = !!current;
  const row = lastPresets.find(p => p.name === current);
  const isActive = has && (current === activeName || !!(row && row.active));
  $('btnActivate').hidden = !has || isActive;
  $('btnDelete').hidden = !has || isActive;
  $('btnSave').disabled = saving || (has && !dirty);
  $('editorApplyHint').hidden = !(isActive && dirty);
}
```

В `save()` в `finally` заменить `btn.disabled = false;` на
`renderEditorChrome();` (после `saving = false`) — иначе chrome-логика снова
включит Save после успешного сохранения, хотя изменений уже нет.

В `quickImport` после `dirty = true;` добавить `setEditorState();` — иначе
черновик, заполненный программно, оставит Save disabled до первого ручного
ввода в поле.

**Step 5: Verify**

```bash
.venv/bin/python -m pytest -q \
  tests/test_naivepanel.py::test_p0_service_buttons_state \
  tests/test_naivepanel.py::test_p0_stop_confirm_and_activate_guard \
  tests/test_naivepanel.py::test_p0_save_pristine_and_active_guards
.venv/bin/python -m pytest -q
```

Expected: PASS, 453 passed, 1 skipped.

Manual:
- running: «Запуск» скрыт, «Стоп»/«Рестарт» видны; «Стоп» → диалог с числом
  соединений; «Отмена» ничего не меняет.
- stopped: «Стоп»/«Рестарт» скрыты, «Запуск» виден.
- нет пресетов: «Запуск» скрыт, «Проверить прокси» disabled.
- активный пресет: «Сделать активным» и «Удалить» скрыты; pristine Save
  disabled; после правки — Save enabled + жёлтая плашка; сохранение
  перезапускает сервис и плашка исчезает.
- удаление пресета из цепочки — в подтверждении есть строка про цепочку.

**Step 6: Commit**

```bash
git add templates/index.html tests/test_naivepanel.py
git commit -m "feat(ui): state-aware service actions and safe save"
```

---

### Task 6: Первый запуск — empty-state, CTA, скрытие лишнего

**Files:**
- Modify: `templates/index.html` — `#foSection`, `#btnExport`,
  `syncEditorChrome`; тексты empty-state уже из Task 2.
- Test: `tests/test_naivepanel.py` — 1 новый тест (+ empty-state в Task 2).

**Step 1: Write failing test**

```python
def test_p0_first_run_hides_failover_and_export(app):
    html = _ui_html()
    assert 'id="foSection"' in html
    assert 'id="btnExport"' in html
    sync = _ui_fn(html, "syncEditorChrome")
    assert "foSection" in sync and "btnExport" in sync
    assert "lastPresets.length < 2" in sync
    assert "noPresets" in sync
```

**Step 2: Run to verify failure**

```bash
.venv/bin/python -m pytest -q tests/test_naivepanel.py::test_p0_first_run_hides_failover_and_export
```

Expected: FAIL.

**Step 3: HTML**

Обернуть весь блок фейловера (`<h2 class="sect">Фейловер…` до второго
`label.chk`) в:

```html
    <div id="foSection" hidden>
      …
    </div>
```

Добавить id экспорту:

```html
      <a class="btn" id="btnExport" href="/api/configs/export" …>Экспорт</a>
```

**Step 4: JS**

Расширить `syncEditorChrome` (из Task 4):

```js
function syncEditorChrome() {
  const noPresets = !lastPresets.length;
  $('foSection').hidden = lastPresets.length < 2;
  $('btnExport').hidden = noPresets;
  $('editorEmpty').hidden = noPresets || isEditorOpen();
  $('mainCard').classList.toggle('no-editor', !isEditorOpen());
}
```

**Step 5: Verify**

```bash
.venv/bin/python -m pytest -q tests/test_naivepanel.py::test_p0_first_run_hides_failover_and_export
.venv/bin/python -m pytest -q
```

Expected: PASS, 454 passed, 1 skipped.

Manual (пустая установка): empty-state по центру (иконка сверху, заголовок,
подсказка, кнопка «Вставить ссылку»), нет «Фейловер», нет «Экспорт», нет
пустого «Редактор»; «Запуск»/«Проверить прокси» недоступны. После импорта
двух пресетов фейловер появляется.

**Step 6: Commit**

```bash
git add templates/index.html tests/test_naivepanel.py
git commit -m "feat(ui): first-run guidance and hide inapplicable sections"
```

---

### Task 7: Offline-баннер и error-state

**Files:**
- Modify: `templates/index.html` — `#connBanner`, `setOffline`, `noteOk`,
  `noteFail`, `pollStatus`, `refreshAll`, `renderPresetsError`, `retryAll`, CSS.
- Test: `tests/test_naivepanel.py` — 1 новый тест.

**Step 1: Write failing test**

```python
def test_p0_offline_banner_and_error_state(app):
    html = _ui_html()
    assert 'id="connBanner"' in html
    assert 'id="connText"' in html
    assert "function setOffline(" in html
    poll = _ui_fn(html, "pollStatus")
    assert "noteOk" in poll and "noteFail" in poll
    refresh = _ui_fn(html, "refreshAll")
    assert "renderPresetsError" in refresh
    assert "retryAll" in html
    assert "Повторить" in html
```

**Step 2: Run to verify failure**

```bash
.venv/bin/python -m pytest -q tests/test_naivepanel.py::test_p0_offline_banner_and_error_state
```

Expected: FAIL.

**Step 3: HTML/CSS**

Перед `<div id="toasts"></div>`:

```html
<div id="connBanner" hidden>
  <span class="dot off" aria-hidden="true"></span>
  <span id="connText" role="status">Нет связи с панелью</span>
  <button type="button" class="ghost" id="btnRetry" data-action="retry">Повторить</button>
</div>
```

CSS:

```css
  #connBanner { position:fixed; left:var(--sp-4); right:var(--sp-4); bottom:var(--sp-4);
                z-index:9; display:flex; align-items:center; gap:10px;
                padding:10px 12px; border:1px solid var(--err); border-radius:var(--r-m);
                background:var(--card); box-shadow:var(--shadow-2); font-size:13px; }
  #connBanner .dot { margin-right:0; flex:none; }
  #connBanner button { margin-left:auto; }
  body.has-conn-banner { padding-bottom:64px; }
  body.has-conn-banner #toasts { bottom:80px; }
  @media (max-width:800px) {
    #connBanner { left:12px; right:12px; bottom:calc(12px + env(safe-area-inset-bottom)); }
  }
```

**Step 4: JS**

Добавить рядом с `lastStatus`:

```js
let lastOkAt = 0;
let pollFails = 0;
let offline = false;
let lastStatusHtml = '';

function setOffline(on) {
  if (on === offline) return;
  offline = on;
  $('connBanner').hidden = !on;
  document.body.classList.toggle('has-conn-banner', on);
  if (on) {
    const at = lastOkAt
      ? new Date(lastOkAt).toLocaleTimeString('ru-RU', {hour:'2-digit', minute:'2-digit'})
      : '';
    $('connText').textContent = 'Нет связи с панелью' + (at ? ' · последнее обновление ' + at : '');
    $('status').innerHTML = '<span class="off"><span class="dot off" aria-hidden="true"></span>нет связи</span>';
    lastStatusHtml = '';
    for (const id of ['btnStart', 'btnStop', 'btnRestart', 'btnE2e']) {
      const b = $(id);
      if (b) b.disabled = true;
    }
  }
}

function noteOk() {
  const wasOffline = offline;
  lastOkAt = Date.now();
  pollFails = 0;
  setOffline(false);
  // force: ключ состояния мог не измениться, а кнопки были выключены offline'ом
  renderServiceButtons(lastStatus || {}, true);
  if (wasOffline) flash('Связь с панелью восстановлена', true);
}

function noteFail(immediate) {
  pollFails++;
  if (immediate || pollFails >= 2) setOffline(true);
}

function renderPresetsError(msg) {
  const ul = $('presets');
  ul.setAttribute('aria-busy', 'false');
  ul.innerHTML = '<li class="empty" aria-live="polite">' + IC.empty
    + '<b>Не удалось загрузить пресеты</b>'
    + '<span class="hint">' + escapeHtml(msg || 'нет связи с панелью') + '</span>'
    + '<button type="button" class="ghost" data-action="retry">Повторить</button></li>';
}

async function retryAll() {
  const b = $('btnRetry');
  if (b) b.disabled = true;
  await refreshAll();
  if (b) b.disabled = false;
}
```

Заменить `pollStatus`:

```js
async function pollStatus() {
  try {
    const st = await jget('/api/status');
    lastStatus = st;
    noteOk();
    renderStatus(st);
  } catch (e) {
    if (!e.httpStatus) noteFail(false); // 401/500 — не «нет сети»
  }
}
```

В `refreshAll` успех пометить до рендера, а ошибку — как offline:

```js
async function refreshAll() {
  try {
    const [st, ps] = await Promise.all([jget('/api/status'), jget('/api/configs')]);
    lastStatus = st;
    noteOk();
    renderStatus(st);
    renderPresets(ps);
    loadFailover();
    loadSpark();
    loadLog();
  } catch (e) {
    if (!e.httpStatus) noteFail(true);
    if (!lastPresets.length) renderPresetsError(humanError(e));
    flash(e.message, false);
  }
}
```

В `ACTIONS` добавить `retry: () => retryAll(),`.

**Step 5: Verify**

```bash
.venv/bin/python -m pytest -q tests/test_naivepanel.py::test_p0_offline_banner_and_error_state
.venv/bin/python -m pytest -q
```

Expected: PASS, 455 passed, 1 skipped.

Manual: остановить панель (не прокси) — через ~6–8с баннер «Нет связи с
панелью · последнее обновление HH:MM», шапка «нет связи»; поднять панель —
баннер исчезает, тост «Связь восстановлена», статус снова зелёный. Первый
запуск при недоступной панели — error-state с «Повторить», а не вечный
skeleton.

**Step 6: Commit**

```bash
git add templates/index.html tests/test_naivepanel.py
git commit -m "feat(ui): show offline state and allow retry"
```

---

### Task 8: Гигиена — контраст, тап-цели, aria-live, шапка, shortcuts

**Files:**
- Modify: `templates/index.html` — токены, mobile CSS, `renderStatus`,
  `renderLogSrc`, `#updMsg`, shortcuts, `--hdr-h`.
- Test: `tests/test_naivepanel.py` — 4 новых теста.

**Step 1: Write failing tests**

```python
def _composite_hex(fg: str, alpha: float, bg: str = "ffffff") -> str:
    out = []
    for i in (0, 2, 4):
        c = round(int(fg[i:i + 2], 16) * alpha + int(bg[i:i + 2], 16) * (1 - alpha))
        out.append(f"{c:02x}")
    return "".join(out)


def test_p0_badge_contrast(app):
    html = _ui_html()
    light = re.search(r'\[data-theme="light"\]\s*\{([^}]*)\}', html, re.S).group(1)
    def tok(name):
        m = re.search(rf"--{name}:#([0-9a-fA-F]{{6}})", light)
        assert m, name
        return m.group(1)
    assert _wcag_contrast(tok("acc"), tok("badge-bg")) >= 4.5
    assert _wcag_contrast(tok("badge-mut"), tok("mut-tint")) >= 4.5
    m = re.search(r"--acc-tint:rgba\(11,122,83,([0-9.]+)\)", light)
    assert m, "light --acc-tint"
    bg = _composite_hex(tok("acc"), float(m.group(1)))
    assert _wcag_contrast(tok("mut"), bg) >= 4.5


def test_p0_mobile_targets_and_radio(app):
    html = _ui_html()
    mobile = "\n".join(re.findall(r"@media \(max-width:800px\) \{.*?\n  \}", html, re.S))
    for rule in ("#btnCloseEditor", "#btnQuickUri"):
        assert re.search(re.escape(rule) + r" \{[^}]*min-width:44px", mobile), rule
    assert re.search(r"#secNav a \{[^}]*min-height:44px", mobile)
    assert re.search(
        r"input:not\(\[type=\"checkbox\"\]\):not\(\[type=\"radio\"\]\)[^{]*\{[^}]*min-height:44px",
        mobile)
    assert re.search(r"\.rbrow input\[type=\"radio\"\][^{]*\{[^}]*flex:none", html)


def test_p0_aria_live_and_log_labels(app):
    html = _ui_html()
    rs = _ui_fn(html, "renderStatus")
    assert "lastStatusHtml" in rs and "lastSvcHtml" in rs
    assert "const ver" not in rs
    src = _ui_fn(html, "renderLogSrc")
    assert "aria-label" in src
    assert "Лог прокси" in html and "Лог панели" in html
    assert re.search(r'<p id="updMsg"[^>]*role="status"', html)


def test_p0_shortcuts_header_and_hidden(app):
    html = _ui_html()
    assert "e.code === 'KeyS'" in html
    assert "e.code === 'Slash'" in html
    assert "--hdr-h" in html
    assert "ResizeObserver" in html
    assert re.search(r"\[hidden\] \{[^}]*display:none", html)
```

**Step 2: Run to verify failure**

```bash
.venv/bin/python -m pytest -q \
  tests/test_naivepanel.py::test_p0_badge_contrast \
  tests/test_naivepanel.py::test_p0_mobile_targets_and_radio \
  tests/test_naivepanel.py::test_p0_aria_live_and_log_labels \
  tests/test_naivepanel.py::test_p0_shortcuts_header_and_hidden
```

Expected: FAIL.

**Step 3: Tokens and CSS**

В светлой теме заменить токены:

```css
    --acc-tint:rgba(11,122,83,.04); --badge-bg:#e8f5ef; --mut-tint:#eef0f2;
    --badge-mut:#4f5762;
```

В тёмной добавить `--badge-mut:#aab3bf;` (остальные можно оставить rgba).
В `.badge.listen` заменить `color:var(--mut)` на `color:var(--badge-mut)`.

В `:root` добавить `--hdr-h:53px; --nav-h:0px;`.

Базовая шапка:

```css
  #status { color:var(--mut); margin-left:auto; min-width:0; max-width:52%;
            overflow:hidden; text-overflow:ellipsis; white-space:nowrap;
            font-variant-numeric:tabular-nums; }
```

Мобильный блок навигации/отступов (внутри `@media (max-width:800px)`):

```css
    :root { --nav-h:53px; }
    #status { font-size:12px; }
    #secNav { top:var(--hdr-h); }
    #secNav a { display:flex; align-items:center; min-height:44px; padding:8px 10px; }
    section[id], #editorTitle { scroll-margin-top:calc(var(--hdr-h) + var(--nav-h) + 8px); }
    #btnCloseEditor { min-width:44px; }
    #btnQuickUri { min-width:44px; }
    input:not([type="checkbox"]):not([type="radio"]), textarea, select { min-height:44px; }
```

Отдельно (без media):

```css
  .rbrow input[type="radio"] { flex:none; width:18px; height:18px; margin:0;
                               accent-color:var(--acc); }
```

Убрать жёсткие `#secNav { top:53px; }` и `section[id] { scroll-margin-top:118px; }`
из старых mobile-блоков — их заменяют переменные.

**Step 4: Header height and shortcuts**

В JS после настройки темы добавить:

```js
const HEADER = document.querySelector('header');
function syncHeaderHeight() {
  document.documentElement.style.setProperty('--hdr-h', HEADER.offsetHeight + 'px');
}
syncHeaderHeight();
if (window.ResizeObserver) new ResizeObserver(syncHeaderHeight).observe(HEADER);
else window.addEventListener('resize', syncHeaderHeight);
```

В `keydown`:

```js
  if ((e.ctrlKey || e.metaKey) && (e.code === 'KeyS' || e.key.toLowerCase() === 's')) {
    if (isEditorOpen()) { e.preventDefault(); save(null); }
    return;
  }
  if ((e.code === 'Slash' || e.key === '/') && !e.ctrlKey && !e.metaKey
      && !/^(INPUT|TEXTAREA)$/.test(e.target.tagName)) {
    e.preventDefault(); $('search').focus();
    return;
  }
```

**Step 5: renderStatus guards and compact header**

Заменить формирование шапки (без версии и без «пресет:»):

```js
  const statusHtml = st.active
    ? '<span class="on">' + dotOn + ' работает</span>'
      + (st.current ? ' · ' + escapeHtml(st.current) : '')
    : '<span class="off">' + dotOff + ' остановлен</span>'
      + (st.current ? ' · ' + escapeHtml(st.current) : '');
  if (statusHtml !== lastStatusHtml) {
    $('status').innerHTML = statusHtml;
    lastStatusHtml = statusHtml;
  }
```

Для `#svcinfo` собрать строку и обновлять только при изменении:

```js
  const svcHtml = rows.map(([k, v], i) =>
    '<div class="kv'+(i === 0 ? ' wide' : '')+'"><span>'+k+'</span><b>'+v+'</b></div>').join('');
  if (svcHtml !== lastSvcHtml) {
    $('svcinfo').innerHTML = svcHtml;
    $('svcinfo').title = 'обновлено ' + new Date().toLocaleTimeString();
    lastSvcHtml = svcHtml;
  }
```

Объявить `let lastSvcHtml = '';` рядом с `lastStatusHtml`.

`renderLogSrc` дополняется:

```js
  $('log').setAttribute('aria-label',
    logSrc === 'panel'
      ? 'Лог панели (naivepanel.log), последние записи'
      : 'Лог прокси (naiveproxy.log), последние записи');
```

Статический `aria-label` у `<pre id="log">` заменить на
`aria-label="Лог (последние записи)"` — JS уточнит источник.

`<p id="updMsg">` получает `role="status"` (не `aria-live` на весь лог).

**Step 6: Verify**

```bash
.venv/bin/python -m pytest -q \
  tests/test_naivepanel.py::test_p0_badge_contrast \
  tests/test_naivepanel.py::test_p0_mobile_targets_and_radio \
  tests/test_naivepanel.py::test_p0_aria_live_and_log_labels \
  tests/test_naivepanel.py::test_p0_shortcuts_header_and_hidden
.venv/bin/python -m pytest -q
```

Expected: PASS, 459 passed, 1 skipped.

Manual: обе темы — бейджи читаемы; 375/390 — шапка в одну строку, nav не
наезжает на шапку, все табы видны или скроллятся; `Cmd+S` работает на русской
раскладке; `#status` не мигает каждые 3с; скринридер не получает повторный
текст статуса без изменения; подпись лога соответствует источнику.

**Step 7: Commit**

```bash
git add templates/index.html tests/test_naivepanel.py
git commit -m "fix(ui): mobile targets, badge contrast and live-region churn"
```

---

### Task 9: Docs, README, финальная матрица скриншотов

**Files:**
- Modify: `docs/UI-GUIDELINES.md` — новые паттерны строки/действий/offline.
- Modify: `README.md` — «Возможности UI» (строки, меню, первый запуск, offline).
- No code.

**Step 1: Update UI-GUIDELINES**

Добавить разделы:

```markdown
### Строка пресета (v0.24)

Два уровня: имя + статус/роль; ниже — `host:port` (креды не показываем).
Действия — в меню `⋯`, не столбиком иконок. Активный пресет — первым в списке.
На тач-устройстве у строки нет icon-only кнопок, кроме `⋯` (44×44).

### Действия, прерывающие сервис

`Стоп`/`Рестарт` — подтверждение с числом соединений. `Сохранить` активного
пресета перезапускает naive: Save disabled при отсутствии изменений, перед
кнопками — предупреждение. Удаление активного недоступно (backend 409 —
defense-in-depth), удаление из цепочки предупреждает об этом.

### Offline

Если два полла подряд не прошли, показываем фиксированный баннер «Нет связи с
панелью» с временем последнего успеха и «Повторить»; шапка не врёт «работает».
Первый запуск при недоступной панели — error-state, не вечный skeleton.

### Первый запуск

Пустой список — центрированный empty-state с CTA; пустой редактор не
рендерится; фейловер скрыт при <2 пресетах; экспорт скрыт при 0.
```

Проверить, что существующие правила (44px, AA, SVG) не противоречат новым.

**Step 2: Update README**

В «Возможности UI» заменить/добавить:

- строки пресетов в два уровня и меню действий (вместо столбика иконок);
- дублирование — теперь `⋯ → «Дублировать»` (убрать устаревший глиф `⧉`);
- управление фейловером — меню строки + отдельный диалог «Порядок»;
- предупреждение и подтверждения для stop/restart/save активного;
- первый запуск с CTA и скрытием неприменимых секций;
- offline-баннер и русские сообщения об ошибках.

**Step 3: Screenshot matrix**

Снять и приложить к PR (в репозиторий не коммитить; `tmp/` в gitignore):

| Состояние | 375 | 390 | 768 | 1024 | 1440 |
|---|---|---|---|---|---|
| running, 6 пресетов | ✓ | ✓ | ✓ | ✓ | ✓ |
| stopped | ✓ | ✓ | — | ✓ | ✓ |
| first-run (0) | ✓ | ✓ | — | ✓ | ✓ |
| row menu open | ✓ | ✓ | — | — | ✓ |
| order dialog | ✓ | ✓ | — | — | ✓ |
| editor active (pristine) | ✓ | ✓ | — | ✓ | ✓ |
| editor active dirty (hint) | ✓ | ✓ | — | ✓ | ✓ |
| offline banner | ✓ | ✓ | — | — | ✓ |

Каждая ячейка — обе темы (dark/light); 375 — без горизонтального скролла;
строка профиля ≤72px; nav не перекрывает шапку.

**Step 4: Final verification**

```bash
.venv/bin/python -m pytest -q
ruff check .
bandit -q -ll -r naivepanel.py panel
.venv/bin/python -m pytest -q tests/test_naivepanel.py::test_ui_scripts_parse
git diff --check
```

Ожидаемо: **459 passed, 1 skipped**; Ruff/Bandit чисто; JS парсится (если node
есть).

**Step 5: Commit**

```bash
git add docs/UI-GUIDELINES.md README.md
git commit -m "docs: describe mobile rows, safe actions and offline state"
```

---

## 3. Definition of Done

- [ ] 459 passed, 1 skipped; Ruff/Bandit без новых замечаний.
- [ ] На 375/390 нет горизонтального скролла; строка профиля ≤72px; имя
      читается; `⋯` ≥44×44.
- [ ] Тап по профилю → редактор на экране, заголовок в фокусе; Esc возвращает
      фокус на строку.
- [ ] «Стоп»/«Рестарт» — подтверждение; «Запуск» скрыт, когда работает;
      «Запуск» скрыт без профиля; Save активного заблокирован без изменений,
      с изменениями — предупреждение.
- [ ] Активный пресет нельзя удалить/повторно активировать из UI; удаление из
      цепочки предупреждает.
- [ ] Первый запуск: empty-state по центру + CTA; нет пустого редактора,
      фейловера и экспорта; Start/E2E недоступны.
- [ ] Offline-баннер через ≤2 неудачных полла, с временем и retry; первый
      запуск без панели — error-state.
- [ ] Ошибки 409/400/429 и сетевые — по-русски.
- [ ] Бейджи ≥4.5:1, тап-цели 44px, `#status` не мутирует без изменения,
      подпись лога соответствует источнику.
- [ ] `docs/UI-GUIDELINES.md` и README обновлены; скриншоты приложены.

## 4. Риски и откат

1. **`renderPresets` — самая большая правка.** Делать Task 2 отдельным
   коммитом; при регрессе откатить только его. После правки обязательно
   прогнать `test_ui_scripts_parse` (если node) и вручную проверить меню/Esc.
2. **Два старых контракта меняются осознанно** (editor visibility,
   `foOrderMode`). Обновить тесты в тех же коммитах, не оставлять «мёртвые»
   маркеры.
3. **`[hidden] { display:none !important }`** может скрыть элемент, который
   раньше показывали через CSS. Проверить все `hidden` в шаблоне (`grep`) и
   прогнать UI.
4. **Scroll/focus на iOS.** `behavior:'instant'` поддерживается современными
   Safari; если на целевом устройстве нет — останется плавный скролл, это
   допустимо. Проверить на реальном телефоне.
5. **Offline-баннер** не должен принимать HTTP 401/500 за обрыв сети: поэтому
   `handle()` помечает `err.httpStatus`, а `noteFail` вызывается только для
   сетевых ошибок.
6. **Focus после reorder.** `foSaveState` перерисовывает диалог до
   `restoreFocus`; если фокус всё же падает на body — воспроизвести и
   поправить порядок вызовов.
7. **Нет browser-тестов в CI.** Контрактные тесты ловят структуру, но не
   пиксели; live-скриншоты обязательны, иначе задача не считается принятой.

## 5. Открытые вопросы (не блокируют)

1. Оставить one-click активацию на desktop отдельной кнопкой или ограничиться
   меню/редактором? По умолчанию — меню.
2. Нужен ли отдельный confirm на Save активного поверх inline-предупреждения?
   По умолчанию — нет (предупреждение + disabled pristine).
3. Глобальный переименование «пресет → профиль» — отдельный copy/i18n-проход;
   в этом плане везде остаётся «пресет», новые тексты не смешивают термины.

