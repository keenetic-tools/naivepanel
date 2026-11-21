
const $ = (id) => document.getElementById(id);
let current = null; // выбранный пресет (имя) или null
let dirty = false;  // есть несохранённые правки в редакторе
let selectSeq = 0;  // монотонный токен выбора: поздний ответ A не пишет форму, когда выбран B
let saving = false; // guard от повторного входа (Ctrl+S во время активного PUT)
let activating = false; // guard от повторного activate, пока летит POST
let authChanged = false; // пароль сменён: поллинг старыми кредами не шлём

const CSRF = {'X-Requested-With': 'naivepanel'}; // мутации без него сервер отбивает 403

async function jget(url, tries = 2) {
  // GET идемпотентен: при сетевом сбое (не HTTP-ошибке) — одна повторная
  // попытка через 800мс. Сглаживает transient-гонки сразу после рестарта панели.
  for (let i = 0; ; i++) {
    let r;
    try { r = await fetch(url); }
    catch (e) {
      if (i + 1 >= tries) throw e;
      await new Promise(res => setTimeout(res, 800));
      continue;
    }
    return handle(r);
  }
}
async function jpost(url, body) {
  const r = await fetch(url, {method:'POST',
    headers: {...CSRF, 'Content-Type':'application/json'},
    body: body ? JSON.stringify(body) : null});
  return handle(r);
}
async function jput(url, body) {
  const r = await fetch(url, {method:'PUT', headers:{...CSRF, 'Content-Type':'application/json'}, body:JSON.stringify(body)});
  return handle(r);
}
async function jdel(url) { const r = await fetch(url, {method:'DELETE', headers:CSRF}); return handle(r); }

// Сервер отдаёт технические английские abort(description). Наружу — понятная
// причина; незнакомое оставляем как есть, кроме общих подсказок по 401/403/429.
const ERROR_RU = {
  'cannot delete active preset': 'Активный пресет нельзя удалить — сначала переключитесь на другой.',
  'invalid name': 'Недопустимое имя пресета: латиница, цифры, _ - . (до 64 символов).',
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
  if (status === 429) return 'Слишком много запросов. Попробуйте позже.';
  return msg || ('HTTP ' + status);
}

// fetch() бросает «Failed to fetch»/«Load failed» без HTTP-статуса — это
// сетевой обрыв, а не текст сервера.
function humanError(err) {
  // Нормализуем только сетевой фрагмент: префикс действия («Не удалось
  // отправить команду: …») сохраняется и остаётся понятным пользователю.
  const NET_ERROR_RE = /(Failed to fetch|NetworkError(?: when attempting to fetch resource\.?)?|Load failed|Network request failed)/i;
  const msg = String((err && err.message) || err || '').trim();
  if (!NET_ERROR_RE.test(msg)) return msg;
  const cleaned = msg.replace(NET_ERROR_RE, 'нет связи с панелью');
  return /^нет связи с панелью$/i.test(cleaned) ? 'Нет связи с панелью' : cleaned;
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

// Единый SVG-набор иконок (UX-06): 16×16, stroke=currentColor, w2.
// Разнородные Unicode-глифы (кресты, стрелки, цепочка, солнце/луна)
// заменены этим набором.
const IC = {
  x: '<svg class="ic" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><path d="M4 4l8 8M12 4l-8 8"/></svg>',
  arrow: '<svg class="ic" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3 8h10M9 4l4 4-4 4"/></svg>',
  copy: '<svg class="ic" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round" aria-hidden="true"><rect x="5.5" y="5.5" width="7.5" height="7.5" rx="1.5"/><path d="M10.5 3H4.5A1.5 1.5 0 0 0 3 4.5v6"/></svg>',
  up: '<svg class="ic" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M8 13V3M4 7l4-4 4 4"/></svg>',
  down: '<svg class="ic" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M8 3v10M4 9l4 4 4-4"/></svg>',
  link: '<svg class="ic" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M6.5 9.5l3-3"/><path d="M5.5 7L4 5.5a2.6 2.6 0 0 1 3.7-3.7L9.2 3.3"/><path d="M10.5 9l1.5 1.5a2.6 2.6 0 0 1-3.7 3.7L6.8 12.7"/></svg>',
  sun: '<svg class="ic" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><circle cx="8" cy="8" r="3"/><path d="M8 1.2v1.6M8 13.2v1.6M1.2 8h1.6M13.2 8h1.6M3.2 3.2l1.1 1.1M11.7 11.7l1.1 1.1M12.8 3.2l-1.1 1.1M4.3 11.7l-1.1 1.1"/></svg>',
  moon: '<svg class="ic" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round" aria-hidden="true"><path d="M13.5 9.8A6.2 6.2 0 0 1 6.2 2.5a6.2 6.2 0 1 0 7.3 7.3z"/></svg>',
  more: '<svg class="ic" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" aria-hidden="true"><path d="M8 3.2h.01M8 8h.01M8 12.8h.01"/></svg>',
  empty: '<svg class="ic" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="2.2" y="3.2" width="11.6" height="9.6" rx="2"/><path d="M5 8h6M8 5v6"/></svg>',
  search: '<svg class="ic" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><circle cx="7" cy="7" r="4.5"/><path d="M10.5 10.5L14 14"/></svg>',
};

// Сообщение видно toast'ом (клик — закрыть), а #msg — visually-hidden
// aria-live для скринридера. Ошибки держим дольше: их успевают прочитать.
function flash(msg, ok, ms) {
  msg = humanError(msg);
  $('msg').textContent = msg;
  if (!msg) return;
  const box = $('toasts');
  const t = document.createElement('div');
  t.className = 'toast ' + (ok ? 'ok' : 'err');
  t.textContent = msg;
  // закрывается и с клавиатуры: настоящая кнопка, а не только клик по тосту
  const x = document.createElement('button');
  x.className = 'toast-x';
  x.type = 'button';
  x.setAttribute('aria-label', 'Закрыть уведомление');
  x.innerHTML = IC.x;
  t.appendChild(x);
  t.onclick = (e) => { if (e.target === t) t.remove(); };  // клик по тексту тоже закрывает
  x.onclick = () => t.remove();
  box.appendChild(t);
  while (box.children.length > 4) box.firstChild.remove();
  setTimeout(() => t.remove(), ms || (ok ? 5000 : 9000));
}

// --- Тема: data-theme выставлен bootstrap-скриптом (localStorage или
// системная), клик фиксирует выбор в localStorage. ---------------------
const THEME_KEY = 'naivepanel-theme';
function effTheme() {
  const t = document.documentElement.dataset.theme;
  if (t) return t;
  return matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
}
function setThemeBtn(theme) {
  const b = $('themeToggle');
  b.innerHTML = theme === 'light' ? IC.moon : IC.sun;
  // доступное имя отражает целевое состояние, а не текущее (UX-03)
  b.setAttribute('aria-label',
    theme === 'light' ? 'Переключить на тёмную тему' : 'Переключить на светлую тему');
}
function toggleTheme() {
  const next = effTheme() === 'light' ? 'dark' : 'light';
  document.documentElement.dataset.theme = next;
  try { localStorage.setItem(THEME_KEY, next); } catch (e) { /* private mode */ }
  setThemeBtn(next);
}
setThemeBtn(effTheme());

// Следим за системной темой, пока пользователь не зафиксировал выбор.
matchMedia('(prefers-color-scheme: light)').addEventListener('change', (e) => {
  let stored = null;
  try { stored = localStorage.getItem(THEME_KEY); } catch (err) { /* private mode */ }
  if (!stored) {
    document.documentElement.dataset.theme = e.matches ? 'light' : 'dark';
    setThemeBtn(effTheme());
  }
});

// Высота шапки: sticky-табы и scroll-margin считаются от реальной высоты, а
// не от захардкоженных 53px — шрифт/перенос/зум меняют её. ResizeObserver —
// основной путь, resize — fallback для старых браузеров.
const HEADER = document.querySelector('header');
function syncHeaderHeight() {
  document.documentElement.style.setProperty('--hdr-h', HEADER.offsetHeight + 'px');
}
syncHeaderHeight();
if (window.ResizeObserver) new ResizeObserver(syncHeaderHeight).observe(HEADER);
else window.addEventListener('resize', syncHeaderHeight);

function setHash(name) {
  history.replaceState(null, '', name ? '#preset='+encodeURIComponent(name) : location.pathname);
}

function askConfirm(message, opts = {}) {
  const dlg = $('confirmDlg');
  if (dlg.open) return Promise.resolve(false); // повторный Escape — не переоткрываем
  $('confirmMsg').textContent = message;
  const ok = $('confirmOk');
  ok.textContent = opts.ok || 'OK';
  ok.className = opts.danger ? 'danger' : '';
  return new Promise(resolve => {
    dlg.addEventListener('close', () => resolve(dlg.returnValue === 'ok'), {once:true});
    dlg.returnValue = '';
    dlg.showModal();
  });
}

async function doLogout() {
  const ok = await askConfirm(
    'Выйти из панели?\nБраузер забудет пароль и попросит его при следующем входе.',
    {ok: 'Выйти'});
  if (!ok) return;
  // Basic-креды кэширует сам браузер и шлёт их молча с каждым запросом —
  // «отмена» нативного промпта их не снимает. Единственный рабочий выход:
  // навигация с заведомо неверной парой в URL (logout@) — браузер затирает
  // кэш кредов, сервер отвечает 401 и появляется нативный промпт.
  // (fetch с фейковым Authorization кэш в актуальном Chromium НЕ меняет —
  // проверено живым прогоном; навигация меняет.)
  location.href = location.protocol + '//logout@' + location.host + '/';
}

function openPassword() {
  $('pwForm').reset();
  $('pwMsg').textContent = '';
  $('btnPwSave').disabled = false;
  $('pwDlg').showModal();
  $('pwCurrent').focus();
}

async function changePassword(e) {
  e.preventDefault();
  const cur = $('pwCurrent').value, nw = $('pwNew').value;
  const msg = $('pwMsg');
  const bytes = new TextEncoder().encode(nw).length; // сервер считает байты
  if (!cur) { msg.textContent = 'введите текущий пароль'; return; }
  if (bytes < 8 || bytes > 72) { msg.textContent = 'длина — 8–72 байта'; return; }
  if (nw !== $('pwRepeat').value) { msg.textContent = 'пароли не совпадают'; return; }
  const btn = $('btnPwSave');
  btn.disabled = true;
  msg.textContent = 'меняю…';
  try {
    await jpost('/api/password', {current: cur, new: nw});
    authChanged = true; // остановить поллинг: старые креды не должны жечь throttle
    msg.textContent = 'Пароль изменён. Войдите заново.';
    setTimeout(() => location.reload(), 1500);
  } catch (err) {
    msg.textContent = err.message;
    btn.disabled = false;
  }
}
$('pwForm').addEventListener('submit', changePassword);

async function maybeDiscard() {
  return !dirty || await askConfirm('Есть несохранённые изменения. Отбросить?',
                                     {ok:'Отбросить', danger:true});
}

async function refreshAll() {
  let st;
  try { st = await jget('/api/status'); }
  catch (e) {
    if (isConnError(e)) noteFail(true);
    if (!lastPresets.length) renderPresetsError(humanError(e));
    flash(e.message, false);
    return;
  }
  lastStatus = st;
  noteOk();
  // Шаблонный/render-сбой не должен ни поднимать offline, ни всплывать
  // unhandled rejection'ом: connectivity решает только запрос статуса.
  try {
    renderStatus(st);
    try { renderPresets(await jget('/api/configs')); }
    catch (e) {
      flash(e.message, false);
      if (!lastPresets.length) {
        renderPresetsError(humanError(e));
        // До загрузки фейловера не доходим: она перерисует пресеты и затрёт
        // error-state обычным «Пресетов пока нет» без retry.
        return;
      }
    }
    // Ждём фейловер: он перерисовывает пресеты. Без await его поздний
    // renderPresets стирал бы фокус, который del ставит после refreshAll.
    await loadFailover();
    loadSpark();
    loadLog();   // оставшиеся сами гасят свои сетевые ошибки
  } catch (e) { flash(e.message, false); }
}

function fmtUptime(s) {
  if (s == null) return '—';
  const d = Math.floor(s/86400), h = Math.floor(s%86400/3600), m = Math.floor(s%3600/60);
  if (d) return d+'д '+h+'ч';
  if (h) return h+'ч '+m+'м';
  if (m) return m+'м '+(s%60)+'с';
  return s+'с';
}

let lastStatus = null;
let lastOkAt = 0;
let pollFails = 0;
let offline = false;
let retrying = false;
let lastStatusHtml = '';
let lastSvcHtml = '';
let lastSysHtml = '';
let svcKey = '';
let svcBusy = false; // идёт POST /api/service — не перерисовывать кнопки включёнными
let e2eBusy = false; // идёт POST /api/e2e

// 502/503/504 — прокси/шлюз не достучался до панели: для пользователя это
// такой же обрыв, как Failed to fetch. 401/500 — «панель ответила», баннер не
// поднимаем: это ошибка доступа/сервера, а не отсутствие связи.
const CONN_ERROR_STATUSES = [502, 503, 504];
function isConnError(e) {
  return !e || !e.httpStatus || CONN_ERROR_STATUSES.includes(e.httpStatus);
}

// Высоту баннера меряем, а не хардкодим: на 320/360/375px текст переносится
// и фиксированные 64px накрывали контент/тосты.
function syncBannerHeight() {
  if (!offline) return;
  document.documentElement.style.setProperty(
    '--conn-banner-h', $('connBanner').offsetHeight + 'px');
}

// Offline-состояние: баннер появляется после двух сетевых сбоев подряд (или
// сразу, если упал refreshAll), прячется первым успешным ответом. Last data
// (lastStatus) не сбрасываем — кнопки и цифры должны пережить обрыв.
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
    // offline уже true: предикат в renderServiceButtons выключит кнопки и
    // заодно уведёт фокус с кнопки, которую сейчас скроет.
    renderServiceButtons(lastStatus || {}, true);
    syncBannerHeight();
  }
}

function noteOk() {
  const wasOffline = offline;
  lastOkAt = Date.now();
  pollFails = 0;
  setOffline(false);
  // force только при восстановлении: ключ состояния мог не измениться, а
  // кнопки были выключены offline'ом.
  if (wasOffline) renderServiceButtons(lastStatus || {}, true);
  if (wasOffline) flash('Связь с панелью восстановлена', true);
  return wasOffline;
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
  // Кэш пресетов пуст: экспорт и фейловер без данных не показываем.
  syncEditorChrome();
}

async function retryAll() {
  if (retrying) return;
  retrying = true;
  const btns = [...document.querySelectorAll('[data-action="retry"]')];
  btns.forEach(b => { b.disabled = true; });
  try { await refreshAll(); }
  finally {
    retrying = false;
    btns.forEach(b => { if (b.isConnected) b.disabled = false; });
  }
}

// Догрузка только пресетов: статус уже получен, поэтому сетевой сбой здесь —
// не повод поднимать offline-баннер (иначе configs-only обрыв зацикливал бы
// recovery: poll → refreshAll → noteFail → баннер → poll ...).
async function refreshPresets() {
  try { renderPresets(await jget('/api/configs')); }
  catch (e) {
    flash(e.message, false);
    if (!lastPresets.length) {
      renderPresetsError(humanError(e));
      return;
    }
  }
}

// Состояние приходит из /api/status; 3-секундный поллинг не должен трогать
// кнопки без изменений (это сбрасывало бы фокус). init-скрипта может не быть —
// тогда действия остаются видимыми, но выключенными (title объясняет почему).
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
  // offline входит в disabled: пока баннер висит, in-flight svc/e2e finally
  // не должен вернуть кнопки в строй до реального восстановления связи.
  $('btnStart').hidden = running || !has;
  $('btnStop').hidden = !running;
  $('btnRestart').hidden = !running;
  $('btnStart').disabled = !init || svcBusy || offline;
  $('btnStop').disabled = !init || svcBusy || offline;
  $('btnRestart').disabled = !init || svcBusy || offline;
  $('btnE2e').disabled = !has || e2eBusy || offline;

  if (keepFocus && focused.hidden) {
    const next = [$('btnStop'), $('btnRestart'), $('btnStart'), $('btnE2e')]
      .find(b => b && !b.hidden && !b.disabled);
    if (next) next.focus();
  }

  const why = init ? '' : 'init-скрипт не найден';
  for (const b of [$('btnStart'), $('btnStop'), $('btnRestart')]) b.title = why;
}

function renderStatus(st) {
  lastStatus = st;
  renderServiceButtons(st);
  // смена активного пресета (в т.ч. автофейловером) отражается в списке пресетов
  if (st.current !== activeName) { activeName = st.current; foRerender(); }
  // а свежие цифры фейловера приходят в каждом статусе — обновляем строку,
  // не дожидаясь GET /api/failover (баг v0.13.0: «актив 1/3» висел после
  // автопереключения до перезагрузки страницы)
  if (st.failover) {
    const f = st.failover;
    const changed = !foEq(f.chain || [], foChainArr)
      || !!f.enabled !== foEnabled || !!f.auto_return !== foAutoReturn;
    if (!foBusy && changed) applyFailover(f);
    else {
      foLast = f;
      const line = foInfoLine(f);
      $('foInfo').textContent = line.text;
      $('foInfo').title = line.title;
    }
  }
  if (st.notify) {
    $('ntInfo').textContent = 'уведомления: '+
      (st.notify.channel ? (st.notify.channel === 'telegram' ? 'Telegram' : 'webhook')
       : 'выкл')
      + (st.notify.pending ? ' · отложено: '+st.notify.pending : '');
  }
  if (st.auth) {
    $('btnPwChange').hidden = !st.auth.enabled;
    // «Выйти» осмысленен только при включённом auth
    $('btnLogout').hidden = !st.auth.enabled;
  }
  const dotOn = '<span class="dot on" aria-hidden="true"></span>', dotOff = '<span class="dot off" aria-hidden="true"></span>';
  // Шапка без версии и без «пресет:» — на телефоне она уходила в ellipsis.
  // innerHTML трогаем только при изменении: 3-секундный поллинг с одинаковой
  // строкой дёргал aria-live="polite" и скринридер перечитывал статус.
  const statusHtml = st.active
    ? '<span class="on">' + dotOn + ' работает</span>'
      + (st.current ? ' · ' + escapeHtml(st.current) : '')
    : '<span class="off">' + dotOff + ' остановлен</span>'
      + (st.current ? ' · ' + escapeHtml(st.current) : '');
  if (statusHtml !== lastStatusHtml) {
    $('status').innerHTML = statusHtml;
    lastStatusHtml = statusHtml;
  }
  const conn = st.connections;
  const connTip = 'ESTABLISHED на listen-портах активного пресета, включая локальный форвардер';
  // аптайм: серия текущего запуска + доступность 24ч/7д из журнала переходов;
  // (Nч) — если наблюдений меньше окна
  const us = st.uptime_stats;
  const fmtUpPct = (w) => w == null ? '—'
    : w.pct + '%' + (w.observed_s < 0.95*86400 ? ' ('+fmtSpan(w.observed_s)+')' : '');
  const upTip = 'текущий запуск процесса · доступность за 24ч/7д из журнала переходов'
    + (us && us.restarts_day ? '; рестартов за сутки: '+us.restarts_day : '');
  const upStreak = st.active ? fmtUptime(st.uptime) : '—';
  const upVal = '<span title="'+upTip+'">'+upStreak
    + (us == null ? '' : ' · '+fmtUpPct(us.day)+' / '+fmtUpPct(us.week))+'</span>';
  // «Обзор» — только рантайм прокси; панель-уровень (версия, watchdog)
  // живёт в карточке «Система»
  const rows = [
    ['состояние', st.active ? '<span class="on">'+dotOn+' работает</span>' : '<span class="off">'+dotOff+' остановлен</span>'],
    ['пресет', st.current ? escapeHtml(st.current) : '—'],
    ['аптайм', upVal],
    ['pid', st.active && st.pid != null ? String(st.pid) : '—'],
    ['соединений', conn ? '<span title="'+connTip+'">'+conn.established+'</span>' : '—'],
  ];
  // длинные значения — во всю ширину колонки, коротышы (pid, соединений) — пара
  const wideRow = new Set(['состояние', 'пресет', 'аптайм']);
  const svcHtml = rows.map(([k, v]) =>
    '<div class="kv'+(wideRow.has(k) ? ' wide' : '')+'"><span>'+k+'</span><b>'+v+'</b></div>').join('');
  if (svcHtml !== lastSvcHtml) {
    $('svcinfo').innerHTML = svcHtml;
    $('svcinfo').title = 'обновлено ' + new Date().toLocaleTimeString();
    lastSvcHtml = svcHtml;
  }
  const wdTip = 'панель сама поднимает прокси при падении; ↻N — рестартов с запуска панели';
  const wdVal = st.watchdog
    ? (st.watchdog.tripped ? 'выкл (флаппинг)'
       : st.watchdog.enabled ? 'вкл' + (st.watchdog.restarts ? ' · ↻'+st.watchdog.restarts : '')
       : 'выкл')
    : '—';
  const sysRows = [
    ['версия', 'v'+escapeHtml(st.version || '?')],
    ['watchdog', '<span title="'+wdTip+'">'+wdVal+'</span>'],
  ];
  const sysHtml = sysRows.map(([k, v]) =>
    '<div class="kv"><span>'+k+'</span><b>'+v+'</b></div>').join('');
  if (sysHtml !== lastSysHtml) {
    $('sysinfo').innerHTML = sysHtml;
    lastSysHtml = sysHtml;
  }
  renderEditorChrome();
}

let tgConfigured = false;

async function loadNotify() {
  try {
    const d = await jget('/api/notify');
    tgConfigured = !!(d.telegram && d.telegram.configured);
    $('tgInfo').textContent = tgConfigured
      ? 'Telegram: ' + (d.telegram.bot || 'настроен')
        + (d.telegram.chat_id ? ', chat ' + d.telegram.chat_id : '')
      : 'Telegram не настроен'
        + (d.channel === 'webhook' ? ' (активен webhook из panel.conf)' : '');
    $('tgToken').placeholder = tgConfigured
      ? 'оставьте пустым, чтобы не менять' : '123456:ABC-DEF…';
    if (document.activeElement !== $('tgChat')) {
      $('tgChat').value = (d.telegram && d.telegram.chat_id) || '';
    }
    $('btnTgTest').hidden = !tgConfigured;
    $('btnTgOff').hidden = !tgConfigured;
  } catch (e) { /* transient */ }
}

async function saveTelegram(e) {
  e.preventDefault();
  const token = $('tgToken').value.trim();
  const chat = $('tgChat').value.trim();
  if (!chat) { $('tgMsg').textContent = 'укажите chat_id'; return; }
  if (!token && !tgConfigured) { $('tgMsg').textContent = 'вставьте токен бота'; return; }
  const btn = $('btnTgSave');
  btn.disabled = true;
  $('tgMsg').textContent = 'сохраняю…';
  try {
    const d = await jpost('/api/notify/telegram', {token, chat_id: chat});
    $('tgToken').value = '';
    $('tgMsg').textContent = d.warning || 'Сохранено';
    await loadNotify();
  } catch (err) {
    $('tgMsg').textContent = err.message;
  } finally {
    btn.disabled = false;
  }
}

async function testTelegram() {
  const btn = $('btnTgTest');
  btn.disabled = true;
  $('tgMsg').textContent = 'отправляю тест…';
  try {
    await jpost('/api/notify/test');
    $('tgMsg').textContent = 'Тест отправлен';
  } catch (err) {
    $('tgMsg').textContent = 'Ошибка: ' + err.message;
  } finally {
    setTimeout(() => { btn.disabled = false; }, 5000);
  }
}

async function offTelegram() {
  if (!await askConfirm('Отключить Telegram-уведомления?',
                        {ok: 'Отключить', danger: true})) return;
  try {
    const d = await jdel('/api/notify/telegram');
    $('tgMsg').textContent = d.warning || 'Отключено';
    await loadNotify();
  } catch (err) { $('tgMsg').textContent = err.message; }
}
$('tgForm').addEventListener('submit', saveTelegram);

// Лёгкий поллинг: лог и статус сами показывают, что naive упал, без кликов.
// Пресеты не трогаем — перерисовка списка каждые 3с мешает наведению/клику.
async function pollStatus() {
  try {
    const st = await jget('/api/status');
    lastStatus = st;
    const recovered = noteOk();
    renderStatus(st);
    // Только восстановление после initial-сбоя: кэш строк не трогаем, чтобы
    // не сбрасывать фокус/наведение на каждом обычном recovery.
    if (recovered && !lastPresets.length) await refreshPresets();
  } catch (e) {
    if (isConnError(e)) noteFail(false); // 401/500 — не «нет сети»
  }
}

let lastPresets = []; // кэш для перерисовки при смене selected/поиска без запроса

// host:port без схемы и кредов: в строке пресета он должен читаться, а не
// прятаться за https:// и маской пароля (сам URI остаётся в title).
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

function captureFocus() {
  const el = document.activeElement;
  if (!el) return null;
  // чекбоксы (и прочие элементы с id) переживают перерисовку списка: их
  // disabled на время PUT снимает фокус, поэтому запоминаем именно id
  if (el.id) return {id: el.id};
  return el.dataset && el.dataset.action
    ? {action: el.dataset.action, arg: el.dataset.arg || ''} : null;
}

function restoreFocus(f) {
  if (!f) return;
  const byAction = (action) => [...document.querySelectorAll('[data-action]')]
    .find(e => e.dataset.action === action && (e.dataset.arg || '') === f.arg);
  let el = f.id ? document.getElementById(f.id) : byAction(f.action);
  if (!el) return;
  // id-captured кнопка могла сама выключиться после PUT (например «Вся
  // цепочка» при заполнении): без этого фокус падал бы на <body>. Уводим
  // на «Порядок», он доступен при непустой цепочке.
  if (el.disabled && f.id) {
    const order = document.getElementById('btnFoOrder');
    if (order && !order.disabled && !order.hidden) el = order;
  }
  // на краях цепочки стрелка disabled — фокус уводим на соседнюю стрелку,
  // иначе на кнопку цепочки: иначе после PUT фокус падал бы на <body>
  if (el.disabled && (f.action === 'foUp' || f.action === 'foDown')) {
    const other = byAction(f.action === 'foUp' ? 'foDown' : 'foUp');
    el = (other && !other.disabled) ? other : (byAction('foToggle') || el);
  }
  if (el && !el.disabled && !el.hidden) el.focus();
}

function renderPresets(presets) {
  lastPresets = presets;
  syncEditorChrome();
  // Счётчик цепочки зависит и от списка: после восстановления связи
  // refreshPresets не трогает renderFailover, и «N из 0» залипал бы.
  $('foCount').textContent = foChainArr.length + ' из ' + presets.length;
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
    // маска пароля — только для title: вторая строка показывает host:port
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

// Меню действий строки: единственное место, где живут активация, цепочка,
// дублирование и удаление. Активному пресету не предлагаем активировать его
// ещё раз или удалить — сервер такие операции всё равно отклонит.
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

function escapeHtml(s) { return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }

// Редактор открыт/закрыт: единственный признак — видимость обёртки.
// У формы #editor своего display нет, иначе два источника истины разъедутся.
function isEditorOpen() { return !$('editorBlock').hidden; }

// Мгновенный переход без smooth-анимации. behavior:'instant' поддерживают не
// все движки: неизвестное значение enum бросает TypeError. Без фолбэка это
// исключение попадало бы в catch selectPreset и показывало сырой текст ошибки.
function scrollInstant(el, block) {
  try { el.scrollIntoView({block, behavior:'instant'}); }
  catch (e) { el.scrollIntoView({block}); }
}

// Возврат фокуса на строку пресета (после Esc/✕): без этого фокус падал бы
// на <body>, и клавиатурный пользователь терял место в списке.
function focusPresetRow(name) {
  if (!name) return false;
  const row = [...document.querySelectorAll('ul.presets .sel')]
    .find(b => b.dataset.arg === name);
  if (!row) return false;
  scrollInstant(row, 'center');
  row.focus({preventScroll:true});
  return true;
}

// После удаления выбранного пресета строки с этим именем уже нет: фокус
// возвращаем на первую строку списка, иначе он упал бы на <body>.
function focusFirstPresetRow() {
  const row = document.querySelector('ul.presets .sel');
  if (!row) return false;
  scrollInstant(row, 'center');
  row.focus({preventScroll:true});
  return true;
}

// Оболочка по состоянию пресетов: фейловер нужен только при 2+ пресетах,
// экспорт — при хотя бы одном; пустая установка — без пустого редактора,
// открытый редактор — без пустого состояния, закрытый при наличии пресетов —
// одна строка «Пресет не выбран» вместо пустого заголовка.
function syncEditorChrome() {
  const noPresets = !lastPresets.length;
  $('foSection').hidden = lastPresets.length < 2;
  $('btnExport').hidden = noPresets;
  $('editorEmpty').hidden = noPresets || isEditorOpen();
  $('mainCard').classList.toggle('no-editor', !isEditorOpen());
}

async function selectPreset(name) {
  if (name !== current && !(await maybeDiscard())) return;
  const seq = ++selectSeq;
  try {
    const cfg = await jget('/api/configs/'+encodeURIComponent(name));
    if (seq !== selectSeq) return; // выбрали другой пресет, пока шли данные
    // current — только после успешного ответа: упавший GET не должен
    // оставлять current на пресете, чья форма не загружена (от current
    // зависят закрытие, удаление и возврат фокуса).
    current = name;
    const listen = Array.isArray(cfg.listen) ? cfg.listen.join('\n') : (cfg.listen || '');
    $('editorTitleText').textContent = 'Редактор — '+name;
    $('editorBlock').hidden = false;
    syncEditorChrome();
    $('btnCloseEditor').hidden = false;
    $('f_name').value = name;
    $('f_name').disabled = true;
    $('f_listen').value = listen.replace(/^socks:\/\//gm, '');
    // upstream/username приходят с сервера уже разобранными (без пароля),
    // так что регэксп-парсинг proxy-URI на клиенте не нужен
    $('f_upstream').value = cfg.upstream || '';
    $('f_username').value = cfg.username || '';
    $('f_password').value = '';
    $('f_log').value = cfg.log || '';
    $('f_host_resolver_rules').value = cfg['host-resolver-rules'] || '';
    $('f_extra_headers').value = cfg['extra-headers'] || '';
    $('f_insecure_concurrency').value = cfg['insecure-concurrency'] || '';
    dirty = false;
    setHash(name);
    setEditorState();
    renderPresets(lastPresets); // подсветить выбранный
    $('msg').textContent = '';
    // Телефон: строка списка далеко внизу — сразу переходим к редактору
    // и отдаём фокус заголовку (tabindex="-1"), а не оставляем его на <body>.
    const title = $('editorTitle');
    scrollInstant(title, 'start');
    title.focus({preventScroll:true});
  } catch (e) { flash(e.message, false); }
}

async function newPreset() {
  if (!(await maybeDiscard())) return;
  current = null;
  $('editorTitleText').textContent = 'Редактор — новый';
  $('editorBlock').hidden = false;
  syncEditorChrome();
  $('btnCloseEditor').hidden = false;
  $('f_name').disabled = false;
  ['f_name','f_listen','f_upstream','f_username','f_password','f_log','f_host_resolver_rules','f_extra_headers','f_insecure_concurrency']
    .forEach(id => $(id).value = '');
  dirty = false;
  setHash(null);
  setEditorState();
  renderPresets(lastPresets); // снять подсветку выбора
  $('f_name').focus();
}

// Импорт пресета одной строкой (3.2): вставил https://user:pass@host —
// сервер разложил URI по полям (парсер один, см. /api/configs/parse),
// редактор открыт и помечен «изменено». Имя — предложение из хоста;
// занятое получает суффикс -2/-3 (как duplicate).
async function quickImport() {
  const raw = $('quickUri').value.trim();
  if (!raw) { $('quickUri').focus(); return; }
  let d;
  try { d = await jpost('/api/configs/parse', {uri: raw}); }
  catch (e) { flash(e.message, false); return; }
  await newPreset();
  let name = d.name || 'preset';
  const taken = new Set((lastPresets || []).map(p => p.name));
  for (let n = 2; taken.has(name); n++) name = (d.name || 'preset') + n;
  $('f_name').value = name;
  $('f_upstream').value = d.upstream || '';
  $('f_username').value = d.username || '';
  $('f_password').value = d.password || '';
  dirty = true; // заполненный черновик: maybeDiscard спросит при уходе с редактора
  setEditorState();
  $('quickUri').value = '';
  if (!d.decomposed)
    flash('URI не разложен по полям: схема '+d.scheme+':// осталась в upstream целиком — проверьте форму', false);
  else if (!d.creds)
    flash('Разложено, но кредов в строке не было — заполните username и пароль', false);
  else flash('Разложено в редактор — проверьте имя и listen', true);
  $('f_listen').focus();
}

// Единственная точка фактического закрытия редактора: closeEditor/del
// переиспользуют. Фокус не трогаем — его возвращает вызывающий: closeEditor
// после перерисовки списка, del — на первую строку после refreshAll.
function hideEditor() {
  current = null;
  dirty = false;
  $('editorBlock').hidden = true;
  setHash(null);
  setEditorState();
  syncEditorChrome();
}

// Чип состояния редактора (UX-04): ровно три состояния — «активен»
// (открытый пресет сейчас работает), «изменено» (несохранённые правки),
// «сохранено». Пустой = черновик нового пресета без правок.
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

// Кнопки редактора по состоянию: активный пресет нельзя ни активировать
// повторно, ни удалить (сервер такие операции всё равно отклонит), а
// «Сохранить» без правок не дёргает restart активного пресета.
function renderEditorChrome() {
  const has = !!current;
  const row = lastPresets.find(p => p.name === current);
  // Свежий activeName важнее поля active в кэше списка: после автофейловера
  // пресеты приходят с сервера со старым active, и OR с ним заблокировал бы
  // ручной возврат на основной.
  const isActive = has && (current === activeName || !!(row && isActivePreset(row)));
  // Перед переключением запоминаем фокус: скрытая/выключенная кнопка уронила
  // бы его на <body> — уводим на заголовок редактора (tabindex="-1").
  const focused = document.activeElement;
  const chromeFocused = !!(focused
    && focused.matches('#btnActivate, #btnDelete, #btnSave'));
  $('btnActivate').hidden = !has || isActive;
  $('btnDelete').hidden = !has || isActive;
  $('btnSave').disabled = saving || (has && !dirty);
  // Единственное место, где выключается Activate: activate() включает флаг
  // ДО вызова chrome, чтобы capture/rescue ниже успели увести фокус.
  $('btnActivate').disabled = activating;
  $('editorApplyHint').hidden = !(isActive && dirty);
  if (chromeFocused && isEditorOpen() && (focused.hidden || focused.disabled))
    $('editorTitle').focus({preventScroll:true});
}

async function closeEditor() {
  if (!(await maybeDiscard())) return;
  const name = current;
  hideEditor();
  renderPresets(lastPresets);
  if (!focusPresetRow(name)) $('search').focus();
}

async function dupPreset(name) {
  try {
    const d = await jpost('/api/configs/'+encodeURIComponent(name)+'/duplicate', null);
    flash('Скопирован: '+d.name+' (пароль перенесён)', true);
    await refreshAll();
    selectPreset(d.name);
  } catch (e) { flash(e.message, false); }
}

function togglePw() {
  const i = $('f_password'), b = $('btnPw');
  const show = i.type === 'password';
  i.type = show ? 'text' : 'password';
  b.textContent = show ? 'скрыть' : 'показать';
}

// TCP-пинг upstream с роутера: отличает «прокси лежит» от «сеть недоступна».
async function probeUpstream() {
  const b = $('btnProbe');
  b.disabled = true; b.textContent = '…';
  try {
    const d = await jpost('/api/probe', {upstream: $('f_upstream').value.trim()});
    flash(d.ms != null
      ? 'upstream доступен: '+d.ms+'мс ('+escapeHtml(d.host)+':'+d.port+')'
      : 'upstream НЕ доступен: '+(d.error || '?'), d.ms != null);
  } catch (e) { flash(e.message, false); }
  finally { b.disabled = false; b.textContent = 'пинг'; }
}

// E2E-проверка: реальный запрос ЧЕРЕЗ listen активного пресета (туннель до
// echo-сервера + exit-IP). probe выше — «до upstream есть TCP», это —
// «прокси действительно проксирует»: креды, форвардинг, remote-DNS.
async function checkProxy() {
  const b = $('btnE2e'), info = $('e2eInfo');
  e2eBusy = true;
  b.disabled = true; b.textContent = 'Проверяю…';
  info.textContent = 'проверка: запрос через прокси…';
  try {
    const d = await jpost('/api/e2e', {});
    const short = d.ok
      ? 'через прокси' + (d.exit_ip ? ' · exit '+d.exit_ip : '') + ' · '+d.ms+'мс'
        + (d.note ? ' · '+d.note : '')
      : 'НЕ работает — '+(d.error || '?');
    info.textContent = 'проверка: '+short;
    flash(d.ok ? 'Прокси работает: '+short : 'Прокси '+short, !!d.ok);
  } catch (e) { info.textContent = 'проверка: '+e.message; flash(e.message, false); }
  finally {
    e2eBusy = false;
    b.textContent = 'Проверить прокси';
    renderServiceButtons(lastStatus || {}, true);
  }
}

// Спарклайн истории E2E: полоска зелёный/красный по проверкам монитора +
// подпись с доступностью и средней задержкой. Данные меняются раз в
// интервал монитора — обновляем раз в 30с, не в 3-секундном полле.
async function loadSpark() {
  try { drawSpark(await jget('/api/e2e/history?last=120')); }
  catch (e) { /* тихо: спарклайн некритичен */ }
}
function drawSpark(d) {
  const box = $('e2eSpark');
  const es = d.entries || [];
  if (!es.length) { box.hidden = true; return; }
  box.hidden = false;
  const n = es.length, w = 100 / n;
  let bars = '';
  for (let i = 0; i < n; i++) {
    const e = es[i];
    bars += '<rect x="'+(i * w).toFixed(2)+'" y="'+(e.ok ? 4 : 0)
      +'" width="'+Math.max(w - 0.4, 0.3).toFixed(2)+'" height="'+(e.ok ? 12 : 16)
      +'" style="fill:'+(e.ok ? 'var(--acc)' : 'var(--err)')+'"/>';
  }
  const st = d.stats || {};
  const win = st.window_s ? fmtSpan(st.window_s) : '';
  const last = es[n - 1];
  // текстовый эквивалент полосок для скринридера (UX-03): не только цвет
  const summary = 'E2E-история: '+n+' проверок'
    + (st.availability != null ? ', успешных '+st.availability+'%' : '')
    + (st.avg_ms != null ? ', в среднем '+st.avg_ms+'мс' : '')
    + ', последняя — '+(last.ok ? 'успешна' : 'сбой');
  box.innerHTML = '<svg viewBox="0 0 100 16" preserveAspectRatio="none" aria-hidden="true">'+bars+'</svg>'
    + '<span class="cap">E2E '+(st.availability != null ? st.availability+'%' : '')
    + (st.avg_ms != null ? ' · в среднем '+st.avg_ms+'мс' : '')
    + (win ? ' · '+win : '')+'</span>'
    + '<span class="sr-only">'+summary+'</span>';
  box.title = 'последние '+n+' проверок монитора: зелёный — прокси работает, красный — сбой (подробности — лог панели)';
}
function fmtSpan(s) {
  const h = Math.floor(s/3600), m = Math.round(s%3600/60);
  if (h) return m ? h+'ч '+m+'м' : h+'ч';
  return m ? m+'м' : '<1м';
}

// Фейловер: цепочка «основной → запасные» — состав из меню «⋯» строки
// пресета, порядок — диалогом «Порядок». Каждое изменение сразу уходит PUT
// /api/failover: без черновиков и кнопки «Сохранить». Монитор панели делает
// E2E-проверку активного пресета и после порога неудач подряд переключает
// на следующий; назад, на основной — только вручную или авто-возвратом.
let foChainArr = [];       // эффективная цепочка с сервера
let foEnabled = false;     // фейловер включён
let foAutoReturn = false;  // авто-возврат
let foBusy = false;        // идёт PUT — контролы заблокированы
let foLast = null;         // последний ответ /api/failover (для перерисовки)
let activeName = null;     // активный пресет (из /api/status)

let FO_CHAIN_MAX = 8; // дефолт; реальный предел приходит с сервера (chain_max)

const foEq = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);

function applyFailover(d) {
  foLast = d;
  if (d.chain_max) FO_CHAIN_MAX = d.chain_max;
  foChainArr = Array.isArray(d.chain) ? d.chain.slice() : [];
  foEnabled = !!d.enabled;
  foAutoReturn = !!d.auto_return;
  renderFailover(d);
  renderPresets(lastPresets);
}

async function loadFailover() {
  if (foBusy) return;  // не затирать состояние, пока летит PUT
  try { applyFailover(await jget('/api/failover')); }
  catch (e) { /* transient */ }
}

// Строкa статуса фейловера как чистая функция: её же дёргает 3-секундный
// поллинг из renderStatus — после АВТОпереключения цифры (актив N/M, fails,
// ok, переключений) должны оживать без перезагрузки страницы.
function foInfoLine(d) {
  const chain = d.chain || [];
  let t;
  if (!d.monitor) t = 'монитор выключен в panel.conf';
  else if (!chain.length) t = 'выкл, цепочка пуста';
  else if (!d.enabled) t = 'выкл, цепочка: ' + chain.join(' → ');
  else {
    t = 'вкл, цепочка: ' + chain.join(' → ');
    if (d.idle) t += ' · пауза: ' + d.idle;
    else {
      if (d.active_index != null) t += ' · актив ' + (d.active_index + 1) + '/' + chain.length;
      if (d.last_ok != null) t += d.last_ok ? ' · ok' : ' · НЕ проходит (' + d.fails + '/' + d.threshold + ')';
    }
    if (d.probing_fast && d.last_ok === false) t += ' · частые проверки';
    if (d.switches) t += ' · переключений: ' + d.switches;
    if (d.auto_return) {
      if (d.return_watch) t += ' · ждём возврата: ' + d.return_watch.name + ' ' + d.return_watch.streak + '/' + d.return_watch.need;
      if (d.returns) t += ' · возвратов: ' + d.returns;
    }
    if (activeName && !chain.includes(activeName))
      t += ' · активный вне цепочки';
  }
  return {text: 'фейловер: ' + t,
          title: d.last_error ? String(d.last_error) : ''};
}

function renderFailover(d) {
  d = d || {chain: [], enabled: false, auto_return: false, monitor: true};
  const chain = d.chain || [];
  $('foCount').textContent = chain.length + ' из ' + lastPresets.length;
  const line = foInfoLine(d);
  $('foInfo').textContent = line.text;
  $('foInfo').title = line.title;
  $('foEnabled').disabled = !d.monitor || foBusy || !chain.length;
  if (!foBusy) $('foEnabled').checked = !!d.enabled;
  $('foAuto').disabled = !d.enabled || !chain.length || foBusy;
  if (!foBusy) $('foAuto').checked = !!d.auto_return;
  const order = $('btnFoOrder');
  order.disabled = foBusy || !chain.length;
  $('btnFoAll').disabled = foBusy
    || chain.length >= FO_CHAIN_MAX
    || !lastPresets.some(p => !chain.includes(p.name));
}

async function foSaveState(enabled, chain, auto) {
  if (foBusy) return;
  const focus = captureFocus();
  foBusy = true;
  renderFailover(foLast);
  renderPresets(lastPresets);
  try {
    applyFailover(await jput('/api/failover',
      {enabled: enabled, chain: chain, auto_return: auto}));
  } catch (e) {
    flash(e.message, false);
    foBusy = false;  // иначе loadFailover() ниже выйдет по своему guard'у
    await loadFailover();
  } finally {
    foBusy = false;
    renderFailover(foLast);
    renderPresets(lastPresets);
    if ($('foOrderDlg').open) renderFoOrder();
    restoreFocus(focus);
  }
}

async function foToggle(name) {
  if (foBusy) return;
  const inChain = foChainArr.includes(name);
  if (!inChain && foChainArr.length >= FO_CHAIN_MAX) {
    flash('В цепочке уже ' + FO_CHAIN_MAX + ' пресетов', false);
    return;
  }
  if (inChain && name === activeName) {
    const ok = await askConfirm(
      'Активный пресет выйдет из цепочки — автофейловер не будет его защищать. Продолжить?',
      {ok: 'Убрать', danger: true});
    if (!ok) return;
  }
  const chain = inChain
    ? foChainArr.filter(n => n !== name) : foChainArr.concat(name);
  const enabled = foEnabled && chain.length > 0;
  await foSaveState(enabled, chain, enabled ? foAutoReturn : false);
}

async function foMove(name, dir) {
  if (foBusy) return;
  const i = foChainArr.indexOf(name), j = i + dir;
  if (i < 0 || j < 0 || j >= foChainArr.length) return;
  const chain = foChainArr.slice();
  [chain[i], chain[j]] = [chain[j], chain[i]];
  await foSaveState(foEnabled, chain, foEnabled ? foAutoReturn : false);
}

async function foAll() {
  if (foBusy) return;
  const add = lastPresets.map(p => p.name)
    .filter(n => !foChainArr.includes(n));
  let chain = foChainArr.concat(add);
  if (chain.length > FO_CHAIN_MAX) {
    chain = chain.slice(0, FO_CHAIN_MAX);
    flash('В цепочку влезли первые ' + FO_CHAIN_MAX + ' пресетов', false);
  }
  await foSaveState(foEnabled, chain, foEnabled ? foAutoReturn : false);
}

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

function foRerender() {
  renderFailover(foLast);
  renderPresets(lastPresets);
}

// Правдивые сообщения о применении: restart.rc отдаёт PUT активного пресета
// и activate; rc===null — init-скрипта нет (рестарт пропущен), rc!==0 — сбой.
function restartFailed(rst) { return !!rst && typeof rst.rc === 'number' && rst.rc !== 0; }
function applyMsg(base, rst) {
  if (!rst) return base;                                  // не активный пресет
  if (typeof rst.rc !== 'number') return base + ' (init-скрипта нет — рестарт пропущен)';
  if (rst.rc !== 0) return base + ' — рестарт НЕ удался: ' + (rst.stderr || rst.stdout || ('rc=' + rst.rc));
  return base + ', сервис перезапущен';
}

async function save(ev) {
  if (ev) ev.preventDefault();
  if (saving) return; // Ctrl+S во время активного PUT не создаёт второй запрос
  if (current && !dirty) return; // нечего сохранять: не дёргаем restart активного
  saving = true;
  const btn = $('btnSave');
  const payload = formPayload();
  btn.textContent = 'Сохранение…';
  // Выключаем Save через chrome, пока он ещё видит фокус: иначе Chromium
  // сбросит его на <body>, а renderEditorChrome уведёт на заголовок.
  renderEditorChrome();
  try {
    if (current) {
      const d = await jput('/api/configs/'+encodeURIComponent(current), payload);
      flash(applyMsg('Сохранено: '+current, d.restart), !restartFailed(d.restart));
    } else {
      await jpost('/api/configs', payload);
      current = payload.name;
      $('f_name').disabled = true;
      setHash(current);
      flash('Создан: '+current+' (не активен — нажмите «Сделать активным»)', true);
    }
    dirty = false;
    setEditorState();
    await refreshAll();
  } catch (e) { flash(e.message, false); }
  finally { saving = false; renderEditorChrome(); btn.textContent = 'Сохранить'; }
}

function formPayload() {
  return {
    name: $('f_name').value.trim(),
    listen: $('f_listen').value.split(/[\n,]+/).map(s => s.trim()).filter(Boolean),
    upstream: $('f_upstream').value.trim(),
    username: $('f_username').value,
    password: $('f_password').value,
    log: $('f_log').value.trim(),
    host_resolver_rules: $('f_host_resolver_rules').value.trim(),
    extra_headers: $('f_extra_headers').value,
    insecure_concurrency: $('f_insecure_concurrency').value.trim(),
  };
}

async function activate(name) {
  const n = name || current;
  if (!n) return;
  const p = lastPresets.find(x => x.name === n);
  if (n === activeName || (p && isActivePreset(p))) {
    flash('Пресет уже активен', true);
    return;
  }
  let msg = '';
  if (dirty) msg += 'В форме есть несохранённые правки — активируется последняя сохранённая версия пресета.\n';
  if (lastStatus && lastStatus.active)
    msg += 'Прокси перезапустится, соединения оборвутся на несколько секунд.';
  if (msg && !(await askConfirm(msg, {ok: 'Активировать'}))) return;
  // Пока диалог был открыт, автофейловер мог уже сделать пресет активным:
  // повторный activate дал бы лишний restart.
  if (n === activeName || (p && isActivePreset(p))) {
    flash('Пресет уже активен', true);
    return;
  }
  if (activating) return;
  activating = true;
  renderEditorChrome(); // capture фокуса и disable — до запроса, одной точкой
  try {
    const d = await jpost('/api/configs/'+encodeURIComponent(n)+'/activate', null);
    flash(applyMsg('Активирован: '+n, d.restart), !restartFailed(d.restart));
    await refreshAll();
  } catch (e) { flash(e.message, false); }
  finally {
    activating = false;
    renderEditorChrome();
  }
}

async function del(name) {
  const n = name || current;
  if (!n) return;
  const p = lastPresets.find(x => x.name === n);
  if (n === activeName || (p && isActivePreset(p))) {
    flash('Активный пресет нельзя удалить — сначала переключитесь на другой.', false);
    return;
  }
  let msg = 'Удалить пресет ' + n + '?';
  if (foChainArr.includes(n)) msg += '\nОн также будет убран из цепочки фейловера.';
  if (!(await askConfirm(msg, {ok: 'Удалить', danger: true}))) return;
  try {
    await jdel('/api/configs/'+encodeURIComponent(n));
    // current читаем после ответа, а не до: пока DELETE летел, могли открыть
    // другой пресет или новый черновик — такой редактор не закрываем.
    const wasCurrent = current === n;
    if (wasCurrent) hideEditor();
    flash('Удалён: '+n, true);
    await refreshAll();
    // Список перерисован без удалённой строки: фокус — на первую строку,
    // иначе он падал бы на <body>; пустой список уводит в поиск. Редактор,
    // открытый во время refreshAll, фокус не отбираем.
    if (wasCurrent && !isEditorOpen() && !focusFirstPresetRow()) $('search').focus();
  } catch (e) { flash(e.message, false); }
}

const SVC_VERBS = {start:'запущен', stop:'остановлен', restart:'перезапущен'};
async function svc(action) {
  // Фокус запоминаем до confirm/disabled: клик по действию мог уронить его на
  // <body>, когда все кнопки выключатся на время запроса.
  const focusStart = document.activeElement;
  const wasSvcFocus = !!(focusStart && focusStart.matches('[data-action="svc"]'));
  // Статус ещё не загружен: не знаем, запущен ли сервис, — destructive
  // действие вслепую не отправляем (кнопки до первого статуса disabled).
  if (!lastStatus) { flash('Статус сервиса ещё не загружен', false); return; }
  // Повторный старт уже работающего сервиса — не ошибка пользователя, а
  // недоступное действие: кнопка Start в этом состоянии скрыта, вызов тихо
  // игнорируем.
  if (action === 'start' && lastStatus.active) return;
  if (action !== 'start' && lastStatus.active) {
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
  svcBusy = true;
  buttons.forEach(b => { b.disabled = true; });
  try {
    const d = await jpost('/api/service/' + action, null);
    const failed = restartFailed(d);
    flash('Сервис ' + (SVC_VERBS[action] || action)
          + (failed ? ' — НЕ удался: ' + (d.stderr || d.stdout || ('rc=' + d.rc)) : ''),
          !failed);
    await refreshAll();
  } catch (e) { flash(e.message, false); }
  finally {
    svcBusy = false;
    renderServiceButtons(lastStatus || {}, true);
    // Фокус мог упасть на body, пока все кнопки были disabled; возвращаем
    // его, только если пользователь не ушёл сам и не открыт диалог.
    const ae = document.activeElement;
    const focusLost = !ae || ae === document.body || ae === focusStart;
    if (wasSvcFocus && focusLost && !document.querySelector('dialog[open]')) {
      const next = (focusStart && !focusStart.hidden && !focusStart.disabled)
        ? focusStart
        : [$('btnStart'), $('btnRestart'), $('btnStop'), $('btnE2e')]
            .find(b => b && !b.hidden && !b.disabled);
      if (next) next.focus();
    }
  }
}

async function panelRestart() {
  if (!(await askConfirm('Перезапустить саму панель? Страница перезагрузится, когда сервер поднимется.', {ok:'Перезапустить'}))) return;
  try {
    const r = await fetch('/api/panel/restart', {method:'POST', headers:CSRF});
    if (!(r.ok || r.status === 202)) { flash(await r.text(), false); return; }
  } catch (e) {
    flash('Не удалось отправить команду: '+e.message, false); return;
  }
  flash('Панель перезапускается…', true);
  // Ждём перехода «сервер упал → поднялся» (а не фиксированную паузу),
  // затем перезагружаем страницу, чтобы подхватить новые HTML/JS.
  let wentDown = false;
  const deadline = Date.now() + 30000;
  while (Date.now() < deadline) {
    await new Promise(res => setTimeout(res, 700));
    let up = false;
    try { up = (await fetch('/api/status', {cache:'no-store'})).ok; }
    catch (e) { /* сервер ещё лежит */ }
    if (!up) wentDown = true;
    else if (wentDown) { location.reload(); return; }
  }
  flash('Сервер не поднялся за 30с — обновите страницу вручную', false);
}

// --- Обновление панели из UI ------------------------------------------------
let upd = null; // ответ /api/update/check: {current, latest, available, notes, url}

async function checkUpdate(manual) {
  const btn = document.querySelector('[data-action="updateCheck"]');
  btn.disabled = true;
  try {
    upd = await jget('/api/update/check' + (manual ? '?force=1' : ''));
    renderUpdate();
    if (manual && !upd.error && !upd.available) flash('Обновлений нет — v'+upd.current+' свежая', true);
  } catch (e) {
    upd = null;
    renderUpdate(e.message);
    if (manual) flash('Не удалось проверить обновления: '+e.message, false);
  } finally { btn.disabled = false; }
}

function renderUpdate(err) {
  const info = $('updInfo'), btn = $('btnUpdCheck'), notes = $('btnUpdNotes');
  notes.hidden = true;
  btn.classList.add('solo');
  btn.classList.add('ghost');
  btn.textContent = 'Проверить обновления';
  btn.title = 'Сверить версию панели с последним релизом GitHub';
  if (!upd) {
    info.textContent = 'обновления: не проверены' + (err ? ' — '+err : '');
    return;
  }
  if (upd.error) { // GitHub недоступен с роутера — штатный случай, тихая строка
    info.textContent = 'обновления: не удалось проверить ('+upd.error+')';
    return;
  }
  if (upd.available) {
    info.innerHTML = 'доступна <b style="color:var(--acc)">v'+escapeHtml(upd.latest)+'</b>'
      + ' · установлена v'+escapeHtml(upd.current);
    notes.hidden = false;
    btn.classList.remove('solo');
    btn.classList.remove('ghost');
    btn.textContent = 'Обновить до v'+upd.latest;
    btn.title = 'Обновить панель — веб-панель перезапустится на несколько секунд, прокси не прервётся';
  } else {
    info.textContent = 'обновления: установлена последняя версия (v'+upd.current+')';
  }
}

function showNotes() {
  if (!upd) return;
  $('notesTitle').textContent = 'NaivePanel v'+upd.latest;
  $('notesBody').textContent = upd.notes || 'Описание релиза не заполнено — см. страницу релиза.';
  $('notesUrl').innerHTML = upd.url
    ? 'Полная заметка: <a style="color:var(--acc)" href="'+escapeHtml(upd.url)+'" target="_blank" rel="noopener">'+escapeHtml(upd.url)+'</a>'
    : '';
  $('notesDlg').showModal();
}

async function applyUpdate() {
  if (!upd || !upd.available) return;
  const ok = await askConfirm(
    'Обновить панель до v'+upd.latest+'?\nВеб-панель перезапустится на несколько секунд; прокси (naive) продолжит работать без прерывания.',
    {ok:'Обновить'});
  if (!ok) return;
  let d;
  try { d = await jpost('/api/update/apply', null); }
  catch (e) { flash('Обновление не запущено: '+e.message, false); return; }
  const want = String(d.target || ('v'+upd.latest)).replace(/^v/, '');
  $('updMsg').textContent = 'Обновление до v'+want+'…';
  $('updLog').textContent = '';
  $('updPanelLog').textContent = '';
  // диалог переиспользуется обновлением бинарника naive, которое прячет хвост
  // лога панели — возвращаем перед апдейтом самой панели
  $('updPanelLogTitle').style.display = '';
  $('updPanelLog').style.display = '';
  $('updDlg').showModal();
  flash('Обновление до v'+want+' запущено', true);
  // Детект завершения — на клиенте (state на сервере не переживает рестарт):
  // панель должна «упасть и подняться» с новой версией в /api/status.
  const t0 = Date.now(), deadline = t0 + 180000;
  let wentDown = false;
  for (;;) {
    await new Promise(res => setTimeout(res, 1000));
    try { renderUpdLog(await jget('/api/update/log?lines=30')); } catch (e) { /* рестарт панели */ }
    let st = null;
    try { st = await (await fetch('/api/status', {cache:'no-store'})).json(); }
    catch (e) { wentDown = true; }
    // 15с-страховка от «рестарт проскочил между поллами»: смена версии и без
    // наблюдённого падения — успех; без смены версии ждём именно падения
    const changed = st && st.version !== upd.current;
    if (st && st.version === want && (wentDown || (changed && Date.now() - t0 > 15000))) {
      $('updMsg').textContent = 'Обновлено до v'+want+' — перезагружаю страницу…';
      setTimeout(() => location.reload(), 900);
      return;
    }
    if (Date.now() > deadline) {
      $('updMsg').textContent = 'v'+want+' не поднялась за 3 мин — лог ниже; подробности в '
        + String(d.log || '/opt/var/log/naivepanel-update.log');
      flash('Обновление не завершилось вовремя — см. лог обновления', false);
      return;
    }
  }
}

function renderUpdLog(d) {
  const pre = $('updLog');
  const txt = d.content || '(лог пока пуст)';
  if (pre.textContent !== txt) pre.textContent = txt;
  pre.scrollTop = pre.scrollHeight;
  // Хвост лога панели: при зависшем/умершем установщике причина — здесь
  const pp = $('updPanelLog');
  const ptxt = d.panel || '(пока пусто)';
  if (pp.textContent !== ptxt) pp.textContent = ptxt;
  pp.scrollTop = pp.scrollHeight;
}

// --- Бинарник naive: версия и обновление из UI -------------------------------
let nv = null; // ответ /api/naive/check: {version, tag, latest, available, target…}

async function checkNaive(manual) {
  const btn = $('btnNvCheck');
  btn.disabled = true;
  try {
    nv = await jget('/api/naive/check' + (manual ? '?force=1' : ''));
    renderNaive();
    if (manual && !nv.error && !nv.available)
      flash('Бинарник актуален: ' + (nv.tag || nv.version || '?'), true);
  } catch (e) {
    nv = null;
    renderNaive(e.message);
    if (manual) flash('Не удалось проверить бинарник: ' + e.message, false);
  } finally { btn.disabled = false; }
}

function renderNaive(err) {
  const info = $('nvInfo'), btn = $('btnNvCheck');
  btn.classList.add('solo');
  btn.classList.add('ghost');
  btn.textContent = 'Проверить обновления';
  btn.title = 'Сверить версию бинарника с последним релизом klzgrad/naiveproxy';
  if (!nv) {
    info.textContent = 'бинарник: не проверен' + (err ? ' — ' + err : '');
    return;
  }
  if (nv.error) { // GitHub недоступен — тихая строка, как у обновлений панели
    info.textContent = 'бинарник: не удалось проверить (' + nv.error + ')';
    return;
  }
  const tgt = nv.target ? ' · ' + escapeHtml(nv.target) : '';
  const cur = nv.tag || nv.version;
  if (!cur) { // бинарника нет — та же кнопка его устанавливает
    info.innerHTML = 'не установлен · доступен <b style="color:var(--acc)">'
      + escapeHtml(nv.latest || '?') + '</b>' + tgt;
    btn.classList.remove('ghost');
    btn.textContent = 'Установить';
    btn.title = 'Скачать и установить бинарник naive — прокси, если запущен, будет перезапущен';
    return;
  }
  if (nv.available) {
    info.innerHTML = escapeHtml(cur) + ' → доступен <b style="color:var(--acc)">'
      + escapeHtml(nv.latest) + '</b>' + tgt;
    btn.classList.remove('ghost');
    btn.textContent = 'Обновить';
    btn.title = 'Обновить бинарник naive — прокси перезапустится, соединения оборвутся на секунду';
  } else {
    info.textContent = 'бинарник: ' + cur + ' — актуален' + tgt;
  }
}

async function updateNaive() {
  if (!nv || !nv.latest) return;
  const missing = !nv.tag && !nv.version;
  const ok = await askConfirm(missing
    ? 'Установить бинарник naive ' + nv.latest + '?\nПрокси, если запущен, будет перезапущен.'
    : 'Обновить бинарник naive до ' + nv.latest + '?\nПрокси перезапустится — соединения оборвутся на секунду.',
    {ok: missing ? 'Установить' : 'Обновить'});
  if (!ok) return;
  const btn = $('btnNvCheck');
  btn.disabled = true;
  let d;
  try { d = await jpost('/api/naive/update', null); }
  catch (e) { flash('Обновление бинарника не запущено: ' + e.message, false); btn.disabled = false; return; }
  // тот же диалог, что у обновления панели; хвост лога панели не нужен
  $('updPanelLogTitle').style.display = 'none';
  $('updPanelLog').style.display = 'none';
  $('updMsg').textContent = 'Бинарник naive → ' + d.target + '…';
  $('updLog').textContent = '';
  $('updDlg').showModal();
  flash('Обновление бинарника до ' + d.target + ' запущено', true);
  // Панель при этом живёт: завершение видно в state, падений сервера ждать не надо
  const deadline = Date.now() + 600000; // 3.5МБ на медленном линке
  for (;;) {
    await new Promise(res => setTimeout(res, 2000));
    let st = null;
    try { st = await jget('/api/naive/status?lines=40'); } catch (e) { /* сеть мигнула */ }
    if (st) {
      const txt = st.content || '(лог пока пуст)';
      if ($('updLog').textContent !== txt) $('updLog').textContent = txt;
      $('updLog').scrollTop = $('updLog').scrollHeight;
      const phase = st.state && st.state.phase;
      if (phase === 'done') {
        $('updMsg').textContent = 'Бинарник обновлён: ' + (st.state.version || st.state.target || '');
        // бинарник заменён, но рестарт мог упасть — это не успех (REL-05)
        const rrc = st.state.restart_rc;
        if (typeof rrc === 'number' && rrc !== 0) {
          flash('Бинарник обновлён, но рестарт НЕ удался (rc=' + rrc + ') — проверьте статус сервиса', false);
        } else {
          flash('Бинарник naive обновлён' + (st.state.restarted ? ' — сервис перезапущен' : ''), true);
        }
        $('updDlg').close();
        await checkNaive(true);
        await refreshAll();
        btn.disabled = false;
        return;
      }
      if (phase === 'failed') {
        $('updMsg').textContent = 'Ошибка: ' + (st.state.error || 'см. лог ниже');
        flash('Обновление бинарника не удалось — см. лог', false);
        btn.disabled = false;
        return;
      }
    }
    if (Date.now() > deadline) {
      $('updMsg').textContent = 'Не завершилось за 10 мин — лог ниже; подробности в '
        + String(d.log || '/opt/var/log/naivepanel-naive.log');
      flash('Обновление бинарника не завершилось вовремя', false);
      btn.disabled = false;
      return;
    }
  }
}

// --- Откат версий: панель и бинарник из бэкапов -------------------------------
let rb = null; // ответ /api/rollback: {current, panel:[{version,size,ts}], binary}

function fmtBytes(n) {
  if (!n) return '0 Б';
  const units = ['Б', 'КБ', 'МБ', 'ГБ'];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  return (i === 0 ? String(n) : n.toFixed(1).replace('.', ',')) + ' ' + units[i];
}

async function loadRollback() {
  try { rb = await jget('/api/rollback'); }
  catch (e) { rb = null; }
  renderRollback();
}

function renderRollback() {
  const info = $('rbInfo');
  if (!rb) { info.textContent = 'откат: список версий недоступен'; return; }
  const total = (rb.panel || []).reduce((s, v) => s + v.size, 0);
  info.textContent = (rb.panel || []).length
    ? 'откат: бэкапов ' + rb.panel.length + ' (' + fmtBytes(total) + ')'
    : 'откат: бэкапов панели пока нет';
  $('rbCur').textContent = 'текущая версия панели: v' + (rb.current || '?');
  const b = rb.binary || {};
  $('rbBinInfo').textContent = b.present
    ? 'Бинарник naive: ' + (b.tag || 'версия неизвестна') + ' · ' + fmtBytes(b.size)
    : 'Бинарник naive: бэкапа нет';
  $('btnRbBin').hidden = !b.present;
  const curName = 'v' + (rb.current || '');
  const firstOk = (rb.panel || []).find(v => v.version !== curName);
  $('btnRbDo').disabled = !firstOk;  // выбирать нечего — и кнопки жать незачем
  $('rbList').innerHTML = (rb.panel || []).map(v => {
    // бэкап текущей версии (остаётся после отката как «путь назад») — откат
    // на неё бессмыслен, сервер ответит 400: строку показываем, но глушим
    const isCur = v.version === curName;
    const checked = !isCur && firstOk !== undefined && v.version === firstOk.version;
    return '<label class="rbrow"' + (isCur ? ' style="opacity:.5;cursor:default"' : '') + '>'
      + '<input type="radio" name="rbVer" value="' + escapeHtml(v.version) + '"'
      + (isCur ? ' disabled' : (checked ? ' checked' : '')) + '>'
      + '<span class="rbname">' + escapeHtml(v.version)
      + (isCur ? ' <span style="color:var(--mut);font-size:11px">— текущая</span>' : '') + '</span>'
      + '<span class="rbmeta">' + fmtBytes(v.size) + '</span>'
      + '<button type="button" class="del" aria-label="Удалить бэкап '
      + escapeHtml(v.version) + '" title="Удалить бэкап ' + escapeHtml(v.version)
      + '" data-action="rbDel" data-arg="' + escapeHtml(v.version) + '">✕</button></label>';
  }).join('') || '<p style="margin:4px 0;font-size:12px;color:var(--mut)">'
    + 'бэкапов панели нет — появятся после первого обновления</p>';
}

async function openRollback() {
  await loadRollback();
  $('rbDlg').showModal();
}

function rbSelected() {
  const el = document.querySelector('input[name="rbVer"]:checked');
  return el ? el.value : null;
}

async function rollbackPanel() {
  const ver = rbSelected();
  if (!ver || !rb) return;
  const ok = await askConfirm(
    'Откатить панель на ' + ver + '?\nВеб-панель перезапустится; прокси продолжит '
    + 'работать. Текущая версия v' + rb.current + ' тоже сохранится в бэкап — откат обратим.',
    {ok: 'Откатить', danger: true});
  if (!ok) return;
  let d;
  try { d = await jpost('/api/rollback', {panel: ver}); }
  catch (e) { flash('Откат не запущен: ' + e.message, false); return; }
  $('rbDlg').close();
  // тот же диалог и цикл ожидания, что у обновления: панель должна упасть и
  // подняться уже старым кодом — ловим смену версии в /api/status
  const want = String(d.target || ver).replace(/^v/, '');
  $('updMsg').textContent = 'Откат панели на v' + want + '…';
  $('updLog').textContent = '';
  $('updPanelLog').textContent = '';
  $('updPanelLogTitle').style.display = '';
  $('updPanelLog').style.display = '';
  $('updDlg').showModal();
  flash('Откат до v' + want + ' запущен', true);
  const t0 = Date.now(), deadline = t0 + 120000; // файлы локальные — 2 мин за глаза
  let wentDown = false;
  for (;;) {
    await new Promise(res => setTimeout(res, 1000));
    try { renderUpdLog(await jget('/api/update/log?lines=30')); } catch (e) { /* рестарт панели */ }
    let st = null;
    try { st = await (await fetch('/api/status', {cache:'no-store'})).json(); }
    catch (e) { wentDown = true; }
    if (st && st.version === want && (wentDown || Date.now() - t0 > 15000)) {
      $('updMsg').textContent = 'Откачено на v' + want + ' — перезагружаю страницу…';
      setTimeout(() => location.reload(), 900);
      return;
    }
    if (Date.now() > deadline) {
      $('updMsg').textContent = 'v' + want + ' не поднялась за 2 мин — лог ниже; подробности в '
        + String(d.log || '/opt/var/log/naivepanel-update.log');
      flash('Откат не завершился вовремя — см. лог обновления', false);
      return;
    }
  }
}

async function rollbackBinary() {
  if (!rb || !rb.binary || !rb.binary.present) return;
  const ok = await askConfirm(
    'Откатить бинарник naive на ' + (rb.binary.tag || 'предыдущую версию') + '?\n'
    + 'Прокси перезапустится — соединения оборвутся на секунду.',
    {ok: 'Откатить', danger: true});
  if (!ok) return;
  let d;
  try { d = await jpost('/api/rollback', {binary: true}); }
  catch (e) { flash('Откат бинарника не удался: ' + e.message, false); return; }
  // рестарт после отката мог упасть — не выдаём за успех (REL-05)
  const rrc = d.restart_rc;
  if (typeof rrc === 'number' && rrc !== 0) {
    flash('Бинарник откачен на ' + (d.restored || '?')
          + ', но рестарт НЕ удался (rc=' + rrc + ') — проверьте сервис', false);
  } else {
    flash('Бинарник откачен на ' + (d.restored || '?')
          + (d.restarted ? ' — сервис перезапущен' : ''), true);
  }
  await loadRollback();
  await checkNaive(true);
  await refreshAll();
}

async function rbDelete(ver) {
  if (!ver) return;
  const ok = await askConfirm('Удалить бэкап ' + ver + '? Вернуть его будет нельзя.',
                              {ok: 'Удалить', danger: true});
  if (!ok) return;
  try { await jdel('/api/rollback/' + encodeURIComponent(ver)); }
  catch (e) { flash('Не удалено: ' + e.message, false); return; }
  flash('Бэкап ' + ver + ' удалён', true);
  await loadRollback();
}

async function rbCleanup() {
  if (!rb) return;
  if ((rb.panel || []).length <= 1) { flash('Других бэкапов нет', true); return; }
  const keep = rb.panel[0].version, n = rb.panel.length - 1;
  const ok = await askConfirm('Оставить только ' + keep + ' и удалить остальные бэкапы (' + n + ')?',
                              {ok: 'Удалить', danger: true});
  if (!ok) return;
  let d;
  try { d = await jpost('/api/rollback/cleanup', {keep: 1}); }
  catch (e) { flash('Не получилось: ' + e.message, false); return; }
  flash('Удалено бэкапов: ' + (d.removed || []).length, true);
  await loadRollback();
}

let lastLog = null;   // кэш — не трогаем DOM, если контент не изменился
let logStuck = true;  // «прилип» к низу лога — автоскролл только когда true
let logErrOnly = false; // показывать только ошибки/предупреждения

// Источник лога: 'proxy' (naiveproxy.log) | 'panel' (naivepanel.log) |
// 'audit' (audit.jsonl — журнал действий, SEC-08). Выбор переживает
// перезагрузку страницы, как и тема.
const LOG_SRC_KEY = 'naivepanel-logsrc';
const LOG_SRC_LABEL = {
  proxy: 'Лог прокси (naiveproxy.log), последние записи',
  panel: 'Лог панели (naivepanel.log), последние записи',
  audit: 'Журнал аудита (audit.jsonl), последние записи',
};
const LOG_SRC_FILE = {proxy: 'naiveproxy.log', panel: 'naivepanel.log',
                      audit: 'audit.jsonl'};
let logSrc = 'proxy';
try {
  if (['panel', 'audit'].includes(localStorage.getItem(LOG_SRC_KEY)))
    logSrc = localStorage.getItem(LOG_SRC_KEY);
} catch (e) { /* приватный режим — остаёмся на дефолте */ }

function renderLogSrc() {
  for (const [id, src] of [['btnSrcProxy','proxy'], ['btnSrcPanel','panel'],
                           ['btnSrcAudit','audit']]) {
    const b = $(id), on = src === logSrc;
    b.setAttribute('aria-pressed', String(on));
    b.classList.toggle('on', on);
  }
  // Источник меняется без перезагрузки: статическая подпись «Лог» уточняется
  // здесь, иначе скринридер считает оба лога одним и тем же.
  $('log').setAttribute('aria-label', LOG_SRC_LABEL[logSrc]);
}

function setLogSrc(src) {
  // Без связи новый источник не загрузится, а старый контент остался бы
  // под новой подписью — источник не переключаем.
  if (offline) { flash('Нет связи с панелью — источник лога недоступен', false); return; }
  if (src === logSrc) return;
  logSrc = src;
  try { localStorage.setItem(LOG_SRC_KEY, src); } catch (e) { /* приватный режим */ }
  lastLog = null;   // форсируем перерисовку другим контентом
  logStuck = true;  // новый источник — снова прилипаем к низу
  renderLogSrc();
  loadLog();
}

// naive/Chromium пишет уровни в формате [pid:ERROR:…]; подсветим их.
const LOG_ERR = /\b(ERROR|FATAL|PANIC)\b/, LOG_WARN = /\b(WARNING|WARN)\b/;
function renderLog(content) {
  // сервер уже замаскировал креды; здесь — экранирование и подсветка уровней
  const lines = content.split('\n');
  const shown = logErrOnly ? lines.filter(l => LOG_ERR.test(l) || LOG_WARN.test(l)) : lines;
  $('log').innerHTML = shown.map(l => {
    const cls = LOG_ERR.test(l) ? ' class="lvl-err"' : (LOG_WARN.test(l) ? ' class="lvl-warn"' : '');
    return '<span'+cls+'>'+escapeHtml(l)+'</span>';
  }).join('\n');
}

function toggleLogFilter() {
  logErrOnly = !logErrOnly;
  const b = $('btnLogFilter');
  b.setAttribute('aria-pressed', String(logErrOnly));
  b.classList.toggle('on', logErrOnly);
  lastLog = null;           // форсируем перерисовку
  loadLog();
}

function downloadLog() {
  const blob = new Blob([lastLog || ''], {type:'text/plain'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = LOG_SRC_FILE[logSrc];
  a.click();
  // отложенный revoke: синхронный может оборвать загрузку в Safari/Firefox
  setTimeout(() => URL.revokeObjectURL(a.href), 0);
}

async function copyText(text) {
  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(text);
  } else {
    // http-LAN: Clipboard API недоступен вне secure context — fallback
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    const ok = document.execCommand('copy');
    ta.remove();
    if (!ok) throw new Error('execCommand copy failed');
  }
}

async function copyLog() {
  try {
    await copyText(lastLog || '');
    flash('Лог скопирован', true);
  } catch (e) { flash('Не удалось скопировать: ' + e.message, false); }
}

// Адрес PAC для настроек устройства: панели достаточно знать свой origin —
// путь фиксированный. URL показываем во flash: если панель открыта по
// 127.0.0.1, для чужих устройств он бесполезен (нужен адрес роутера).
async function copyPac() {
  const url = location.origin + '/proxy.pac';
  try {
    await copyText(url);
    flash('Скопировано: ' + url + ' — вставьте в настройки автопрокси устройства', true);
  } catch (e) { flash('Не удалось скопировать: ' + e.message, false); }
}

async function loadLog() {
  if (offline) return; // связь уже помечена offline — прошлый лог не трогаем
  let content;
  try {
    const r = await jget('/api/logs?lines=100&src='+logSrc);
    content = r.content || '(пусто)';
  } catch (e) {
    // transient-сбой не затирает прочитанный лог; без кэша показываем
    // по-русски, без внутреннего «log error» и браузерного Failed to fetch
    if (lastLog) return;
    content = isConnError(e) ? 'Нет связи с панелью' : 'log error: '+e.message;
  }
  if (content !== lastLog) {
    lastLog = content;
    renderLog(content);
  }
  if (logStuck) $('log').scrollTop = $('log').scrollHeight;
}

// Импорт: файл экспорта содержит proxy-URI с паролями — креды переносятся.
$('importFile').addEventListener('change', async () => {
  const f = $('importFile').files[0];
  $('importFile').value = ''; // повторный выбор того же файла тоже срабатывает
  if (!f) return;
  try {
    const d = await jpost('/api/configs/import', JSON.parse(await f.text()));
    const parts = ['импортировано: ' + (d.imported.join(', ') || '—')];
    for (const s of d.skipped) parts.push('пропущен ' + s.name + ' — ' + s.reason);
    // блок фейловера в файле — часть импорта: показываем, применился ли он
    let tail = '';
    if (d.failover && d.failover.applied) tail = ' · фейловер: применён';
    else if (d.failover && d.failover.reason
             && d.failover.reason !== 'no failover block')
      tail = ' · фейловер: ' + d.failover.reason;
    const foApplied = !!(d.failover && d.failover.applied);
    flash(parts.join('\n') + tail, d.imported.length > 0 || foApplied, 12000);
    // failover-only импорт тоже должен появиться сразу, не ждём поллинг
    if (d.imported.length || foApplied) await refreshAll();
  } catch (e) { flash('Импорт не удался: ' + e.message, false); }
});

$('search').addEventListener('input', () => renderPresets(lastPresets));
$('editor').addEventListener('input', () => { dirty = true; setEditorState(); });
// Известная схема + URL-безопасные символы (креды/путь/query) либо голый host.
const UP_OK = /^(https?:\/\/|quic:\/\/)[A-Za-z0-9._~%!$&'()*+,;=:@\/?#\-\[\]]+$|^[A-Za-z0-9.\-\[\]:]+$/;
function validateUpstream() {
  const v = $('f_upstream').value.trim();
  const bad = v.length > 0 && !UP_OK.test(v);
  $('upHint').classList.toggle('show', bad);
  $('f_upstream').setAttribute('aria-invalid', bad ? 'true' : 'false');
}
$('f_upstream').addEventListener('input', validateUpstream);
window.addEventListener('beforeunload', (e) => { if (dirty) { e.preventDefault(); e.returnValue = ''; } });

// Горячие клавиши: Ctrl/Cmd+S — сохранить, «/» — поиск, Esc — закрыть редактор.
// e.code — физическая клавиша: Ctrl+S работает и в русской раскладке («ы»),
// e.key остаётся fallback для браузеров без KeyboardEvent.code.
let escSawDialog = false;
document.addEventListener('keydown', (e) => {
  if ((e.ctrlKey || e.metaKey) && (e.code === 'KeyS' || e.key.toLowerCase() === 's')) {
    if (isEditorOpen()) { e.preventDefault(); save(null); }
    return;
  }
  if ((e.code === 'Slash' || e.key === '/') && !e.ctrlKey && !e.metaKey
      && !/^(INPUT|TEXTAREA)$/.test(e.target.tagName)) {
    e.preventDefault(); $('search').focus();
    return;
  }
  // Esc на keydown только запоминает, был ли открыт dialog: тот закроется сам,
  // и keyup не должен переоткрыть confirm поверх только что закрытого
  if (e.key === 'Escape') escSawDialog = !!document.querySelector('dialog[open]');
});
// Esc закрываем редактор по keyup: close-watcher того же Esc успевает отменить
// confirm, открытый при dirty-форме из keydown (замер: cancel через +0.3мс)
document.addEventListener('keyup', (e) => {
  if (e.key !== 'Escape' || escSawDialog || document.querySelector('dialog[open]')) return;
  // Условие — видимость редактора, а не current: Esc работает и в режиме
  // нового пресета (current === null); SUMMARY — Esc там закрыл <details>
  if (isEditorOpen() && e.target.tagName !== 'SUMMARY') closeEditor();
});

// Следим за «прилипанием»: пользователь у самого низа → автоскролл включён,
// проскроллил вверх читать → выключен, пока не вернётся вниз.
$('log').addEventListener('scroll', () => {
  const pre = $('log');
  logStuck = pre.scrollTop + pre.clientHeight >= pre.scrollHeight - 20;
});

// Автообновление лога и статуса: раз в 3с, только на видимой вкладке.
setInterval(() => { if (!authChanged && !document.hidden) { loadLog(); pollStatus(); } }, 3000);
// Высота offline-баннера зависит от переноса текста — пересчитываем при ресайзе.
addEventListener('resize', () => { if (offline) syncBannerHeight(); });
document.addEventListener('visibilitychange', () => {
  if (authChanged) return; // пароль уже сменён — старыми кредами не поллим
  if (!document.hidden) { loadLog(); pollStatus(); loadSpark(); }
});
// История E2E меняется раз в интервал монитора — свой медленный таймер
setInterval(() => { if (!authChanged && !document.hidden) loadSpark(); }, 30000);

// Делегирование кликов: inline-обработчики запрещены nonce-CSP.
const ACTIONS = {
  theme: () => toggleTheme(),
  svc: (arg) => svc(arg),
  newPreset: () => newPreset(),
  closeEditor: () => closeEditor(),
  quickImport: () => quickImport(),
  copyPac: () => copyPac(),
  import: () => $('importFile').click(),
  foOrder: () => openFoOrder(),
  foToggle: (arg) => foToggle(arg),
  foAll: () => foAll(),
  foUp: (arg) => foMove(arg, -1),
  foDown: (arg) => foMove(arg, 1),
  panelRestart: () => panelRestart(),
  // одна кнопка на поток: есть обновление → применить, нет → перепроверить
  updateCheck: () => (upd && upd.available) ? applyUpdate() : checkUpdate(true),
  updateNotes: () => showNotes(),
  naiveCheck: () => (nv && nv.latest && (nv.available || !(nv.tag || nv.version)))
    ? updateNaive() : checkNaive(true),
  rollbackOpen: () => openRollback(),
  rbBin: () => rollbackBinary(),
  rbDo: () => rollbackPanel(),
  rbDel: (arg) => rbDelete(arg),
  rbKeep: () => rbCleanup(),
  rbClose: () => $('rbDlg').close(),
  pwOpen: () => openPassword(),
  pwClose: () => $('pwDlg').close(),
  logout: () => doLogout(),
  tgTest: () => testTelegram(),
  tgOff: () => offTelegram(),
  select: (arg) => selectPreset(arg),
  presetMenu: (arg) => openPresetMenu(arg),
  focusQuick: () => { $('quickUri').scrollIntoView({block:'center'}); $('quickUri').focus(); },
  activate: (arg) => activate(arg),
  duplicate: (arg) => dupPreset(arg),
  del: (arg) => del(arg),
  probe: () => probeUpstream(),
  e2e: () => checkProxy(),
  togglePw: () => togglePw(),
  loadLog: () => loadLog(),
  logFilter: () => toggleLogFilter(),
  logSrc: (arg) => setLogSrc(arg),
  logDownload: () => downloadLog(),
  logCopy: () => copyLog(),
  retry: () => retryAll(),
};

document.addEventListener('click', (e) => {
  const el = e.target.closest('[data-action]');
  if (!el) return;
  const fn = ACTIONS[el.dataset.action];
  if (!fn) return;
  e.preventDefault();
  // Меню — модальный dialog: закрываем его до действия, иначе следующий
  // диалог (confirm при удалении/цепочке) откроется поверх него.
  const menu = $('presetMenuDlg');
  if (menu.open && el.closest('#presetMenuDlg')) menu.close();
  fn(el.dataset.arg);
});

$('editor').addEventListener('submit', save);
// Enter в строке подключения — тот же «→ пресет» (paste → Enter → редактор)
$('quickUri').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') { e.preventDefault(); quickImport(); }
});
$('foEnabled').addEventListener('change', (e) => {
  if (!foChainArr.length) { e.target.checked = false; return; }
  foSaveState(e.target.checked, foChainArr,
              e.target.checked ? foAutoReturn : false);
});
$('foAuto').addEventListener('change', (e) => {
  foSaveState(foEnabled, foChainArr, e.target.checked);
});

renderLogSrc();
refreshAll();
// Тихий авто-check после первичной загрузки: если есть обновление — бейдж,
// нет или сеть недоступна — тихая строка в секции «Панель», без тостов.
setTimeout(() => checkUpdate(false), 1500);
// Бинарник naive проверяем следом — тем же паттерном, без тостов
setTimeout(() => checkNaive(false), 2500);
// Сводка бэкапов для строки «откат: …» — тоже тихо
setTimeout(() => loadRollback(), 3500);
setTimeout(loadNotify, 1000);
const hashMatch = location.hash.match(/^#preset=(.+)$/);
if (hashMatch) selectPreset(decodeURIComponent(hashMatch[1]));
