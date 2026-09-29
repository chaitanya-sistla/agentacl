// AgentFence local UI. Security: all dynamic text is inserted with
// textContent / createTextNode (never innerHTML); icons are built with
// createElementNS from constant path data. The bearer token lives only in
// this closure's memory.
'use strict';

let TOKEN = null;
const S = {
  overview: null,
  scope: 'user', project: '', agent: 'claude-code',
  loaded: null, doc: null, yaml: '', mode: 'structured', dirty: false,
  lastRow: 0, events: [], filter: 'all', search: '',
  fsPath: '', fsParent: null, tab: 'sessions',
  testKind: 'path', testAction: 'read', sessions: [],
};

// ---------------------------------------------------------------- helpers
const ICONS = {
  shield: 'M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z',
  activity: 'M22 12h-4l-3 9L9 3l-3 9H2',
  sliders: 'M4 21v-7M4 10V3M12 21v-9M12 8V3M20 21v-5M20 12V3M1 14h6M9 8h6M17 16h6',
  folder: 'M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z',
  file: 'M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8zM14 2v6h6',
  flask: 'M9 3h6M10 3v6L4 20a1 1 0 0 0 .9 1.5h14.2A1 1 0 0 0 20 20l-6-11V3',
  lock: 'M5 11h14v10H5zM8 11V7a4 4 0 0 1 8 0v4',
  refresh: 'M21 12a9 9 0 1 1-2.64-6.36L21 8M21 3v5h-5',
  plus: 'M12 5v14M5 12h14',
  x: 'M18 6 6 18M6 6l12 12',
  check: 'M20 6 9 17l-5-5',
  alert: 'M12 9v4M12 17h.01M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z',
  link: 'M10 13a5 5 0 0 0 7.5.5l3-3a5 5 0 0 0-7-7l-1.7 1.7M14 11a5 5 0 0 0-7.5-.5l-3 3a5 5 0 0 0 7 7l1.7-1.7',
  terminal: 'M4 17l6-6-6-6M12 19h8',
  globe: 'M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20zM2 12h20M12 2a15 15 0 0 1 0 20M12 2a15 15 0 0 0 0 20',
  eye: 'M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12zM12 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6z',
  bot: 'M12 8V4H8M4 8h16v12H4zM2 14h2M20 14h2M15 13v2M9 13v2',
  save: 'M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2zM17 21v-8H7v8M7 3v5h8',
  arrowUp: 'M12 19V5M5 12l7-7 7 7',
  arrowRight: 'M5 12h14M12 5l7 7-7 7',
  play: 'M6 4l14 8-14 8z',
  user: 'M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2M12 3a4 4 0 1 0 0 8 4 4 0 0 0 0-8z',
  ban: 'M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20zM4.9 4.9l14.2 14.2',
  chevron: 'M9 18l6-6-6-6',
  sparkles: 'M12 3l1.9 5.1L19 10l-5.1 1.9L12 17l-1.9-5.1L5 10l5.1-1.9z',
};
function icon(name, cls = 'h-4 w-4') {
  const ns = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(ns, 'svg');
  svg.setAttribute('viewBox', '0 0 24 24'); svg.setAttribute('fill', 'none'); svg.setAttribute('stroke', 'currentColor');
  svg.setAttribute('stroke-width', '2'); svg.setAttribute('stroke-linecap', 'round'); svg.setAttribute('stroke-linejoin', 'round');
  svg.setAttribute('class', cls + ' shrink-0'); svg.setAttribute('aria-hidden', 'true');
  const p = document.createElementNS(ns, 'path'); p.setAttribute('d', ICONS[name] || ''); svg.appendChild(p);
  return svg;
}
function el(tag, attrs, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k === 'class') e.className = v;
    else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
    else if (v === true) e.setAttribute(k, '');
    else if (v !== false && v != null) e.setAttribute(k, v);
  }
  for (const k of kids.flat()) {
    if (k == null || k === false) continue;
    e.appendChild(typeof k === 'string' || typeof k === 'number' ? document.createTextNode(String(k)) : k);
  }
  return e;
}
const $ = (id) => document.getElementById(id);
const clear = (n) => { while (n.firstChild) n.removeChild(n.firstChild); };
const show = (n, on, disp = 'block') => { n.classList.toggle('hidden', !on); if (on && disp !== 'block') n.classList.add(disp); };
const tilde = (p) => (S.overview && p && p.startsWith(S.overview.home)) ? '~' + p.slice(S.overview.home.length) : (p || '');

function toast(msg, kind = 'ok') {
  const tone = { ok: 'border-emerald-500/30 text-emerald-700 dark:text-emerald-300', err: 'border-rose-500/30 text-rose-700 dark:text-rose-300', info: 'border-brand-500/30 text-brand-600 dark:text-brand-400' }[kind];
  const t = el('div', { class: 'pointer-events-auto flex items-start gap-3 rounded-xl border bg-white/95 p-3.5 text-sm shadow-xl backdrop-blur transition dark:bg-zinc-900/95 ' + tone },
    icon(kind === 'err' ? 'alert' : kind === 'info' ? 'sparkles' : 'check', 'h-4 w-4 mt-0.5'), el('div', { class: 'text-zinc-700 dark:text-zinc-200' }, msg));
  $('toasts').appendChild(t);
  setTimeout(() => { t.style.opacity = '0'; setTimeout(() => t.remove(), 300); }, kind === 'err' ? 8000 : 4500);
}
function dialog({ title, body, okText = 'Continue', danger = false, input = null }) {
  return new Promise((resolve) => {
    const d = $('dialog'); $('dlg-title').textContent = title;
    const b = $('dlg-body'); clear(b); (Array.isArray(body) ? body : [body]).forEach(x => b.appendChild(typeof x === 'string' ? el('p', { class: 'mt-1' }, x) : x));
    const inp = $('dlg-input'); inp.classList.toggle('hidden', input == null); if (input != null) inp.value = input;
    const ok = $('dlg-ok'); ok.textContent = okText; ok.className = danger ? 'btn-danger' : 'btn-primary';
    d.classList.remove('hidden'); d.classList.add('flex');
    const done = (v) => { d.classList.add('hidden'); d.classList.remove('flex'); ok.onclick = null; $('dlg-cancel').onclick = null; resolve(v); };
    ok.onclick = () => done(input != null ? inp.value : true);
    $('dlg-cancel').onclick = () => done(input != null ? null : false);
    (input != null ? inp : ok).focus();
  });
}
function decisionBadge(effect, enforcement) {
  if (!effect) return el('span', { class: 'text-zinc-400' }, '—');
  if (enforcement === 'observed' && effect !== 'allow') return el('span', { class: 'badge-observed' }, icon('eye', 'h-3 w-3'), 'Observed · not blocked');
  if (effect === 'allow') return el('span', { class: 'badge-allow' }, icon('check', 'h-3 w-3'), enforcement === 'enforced' ? 'Allowed' : 'Allow');
  if (effect === 'ask') return el('span', { class: 'badge-ask' }, icon('alert', 'h-3 w-3'), enforcement === 'enforced' ? 'Blocked · approval' : 'Ask');
  return el('span', { class: 'badge-deny' }, icon('ban', 'h-3 w-3'), enforcement === 'enforced' ? 'Blocked' : 'Deny');
}
const agentName = (id) => (S.overview?.agents.find(a => a.id === id)?.name) || id;
function relTime(ts) {
  const d = (Date.now() - Date.parse(ts)) / 1000;
  if (!isFinite(d)) return '';
  if (d < 5) return 'just now'; if (d < 60) return Math.floor(d) + 's ago';
  if (d < 3600) return Math.floor(d / 60) + 'm ago'; if (d < 86400) return Math.floor(d / 3600) + 'h ago';
  return new Date(ts).toLocaleDateString();
}

async function api(method, path, body) {
  const opts = { method, headers: { 'Authorization': 'Bearer ' + TOKEN } };
  if (body !== undefined) { opts.headers['Content-Type'] = 'application/json'; opts.body = JSON.stringify(body); }
  const r = await fetch(path, opts);
  let data; try { data = await r.json(); } catch (_) { data = { error: 'bad response' }; }
  if (r.status === 401) { lock('Your session ended. Press Enter in the `agentfence ui` terminal for a fresh link.'); throw new Error('unauthorized'); }
  return { status: r.status, data };
}
function lock(msg) { if (msg) $('locked-msg').textContent = msg; const l = $('locked'); l.classList.remove('hidden'); l.classList.add('grid'); }

// ---------------------------------------------------------------- bootstrap
async function bootstrap() {
  document.querySelectorAll('[data-icon]').forEach(n => n.appendChild(icon(n.dataset.icon, n.classList.contains('grid') ? 'h-5 w-5' : 'h-4 w-4')));
  const m = /code=([0-9a-f]+)/.exec(location.hash);
  const tabm = /tab=(sessions|policy|files|test)/.exec(location.hash);
  history.replaceState(null, '', '/');
  if (!m) return lock();
  const r = await fetch('/api/session', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ code: m[1] }) });
  const d = await r.json().catch(() => ({}));
  if (!r.ok || !d.token) return lock(d.error || 'This link has expired or was already used. Press Enter in the `agentfence ui` terminal for a fresh one.');
  TOKEN = d.token;
  const ov = (await api('GET', '/api/overview')).data;
  S.overview = ov;
  $('who').textContent = ov.human;
  const proj = $('project'); clear(proj);
  for (const p of ov.projects) proj.appendChild(el('option', { value: p }, tilde(p)));
  proj.appendChild(el('option', { value: '__other__' }, 'Other project…'));
  S.project = ov.projects[0] || '';
  const ag = $('agent'); clear(ag);
  for (const a of ov.agents) ag.appendChild(el('option', { value: a.id }, a.name));
  wire();
  await loadPolicy();
  await Promise.all([refreshSessions(), pollEvents()]);
  go(tabm ? tabm[1] : 'sessions');
  setInterval(refreshSessions, 3000); setInterval(pollEvents, 1500);
}

const TITLES = {
  sessions: ['Overview', 'Supervised agents and what they tried to do'],
  policy: ['Policy', 'What agents may read, write, run and reach'],
  files: ['Files', 'Browse your disk and decide what agents can touch'],
  test: ['Test a request', 'Check a path, command or host against your draft'],
};
function go(tab) {
  S.tab = tab;
  document.querySelectorAll('#nav .nav-item').forEach(b => b.classList.toggle('active', b.dataset.tab === tab));
  for (const t of Object.keys(TITLES)) $('tab-' + t).classList.toggle('hidden', t !== tab);
  $('page-title').textContent = TITLES[tab][0]; $('page-sub').textContent = TITLES[tab][1];
  $('mobile-nav').value = tab;
  if (tab === 'files') listDir(S.fsPath || S.project);
  updateSavebar();
}

function wire() {
  document.querySelectorAll('#nav .nav-item').forEach(b => b.addEventListener('click', () => go(b.dataset.tab)));
  $('mobile-nav').addEventListener('change', (e) => go(e.target.value));
  document.querySelectorAll('#mode-seg .seg-btn').forEach(b => b.addEventListener('click', () => switchMode(b.dataset.mode)));
  document.querySelectorAll('#scope-seg .seg-btn').forEach(b => b.addEventListener('click', async () => {
    if (b.dataset.scope === S.scope || !(await confirmDiscard())) return;
    S.scope = b.dataset.scope; segOn('scope-seg', 'scope', S.scope); loadPolicy();
  }));
  document.querySelectorAll('#event-filter .seg-btn').forEach(b => b.addEventListener('click', () => { S.filter = b.dataset.f; segOn('event-filter', 'f', S.filter); renderEvents(); }));
  $('event-search').addEventListener('input', (e) => { S.search = e.target.value.toLowerCase(); renderEvents(); });
  $('agent').addEventListener('change', (e) => { S.agent = e.target.value; loadPolicy(false); });
  $('project').addEventListener('change', async (e) => {
    let v = e.target.value;
    if (v === '__other__') v = await dialog({ title: 'Choose a project', body: 'Absolute path to a project directory (its git root is used).', input: S.project, okText: 'Open' }) || S.project;
    if (await confirmDiscard()) { S.project = v; S.fsPath = ''; loadPolicy(); } else e.target.value = S.project;
  });
  $('reload').addEventListener('click', async () => { if (await confirmDiscard()) loadPolicy(); });
  $('yaml').addEventListener('input', () => { S.yaml = $('yaml').value; markDirty(); });
  $('preview').addEventListener('click', preview);
  $('discard').addEventListener('click', async () => { if (await confirmDiscard()) loadPolicy(); });
  document.querySelectorAll('#drawer [data-close]').forEach(b => b.addEventListener('click', closeDrawer));
  $('save').addEventListener('click', save);
  $('up').addEventListener('click', () => { if (S.fsParent) listDir(S.fsParent); });
  $('fs-go').addEventListener('click', () => listDir($('fs-path').value));
  $('fs-path').addEventListener('keydown', (e) => { if (e.key === 'Enter') listDir($('fs-path').value); });
  document.querySelectorAll('#t-kind .seg-btn').forEach(b => b.addEventListener('click', () => {
    S.testKind = b.dataset.k; segOn('t-kind', 'k', S.testKind);
    $('t-action').classList.toggle('hidden', S.testKind !== 'path');
    $('t-value').placeholder = { path: '~/src/app/.env', exec: 'git push origin main', host: 'api.example.com:443' }[S.testKind];
  }));
  document.querySelectorAll('#t-action .seg-btn').forEach(b => b.addEventListener('click', () => { S.testAction = b.dataset.a; segOn('t-action', 'a', S.testAction); }));
  $('t-go').addEventListener('click', testRequest);
  $('t-value').addEventListener('keydown', (e) => { if (e.key === 'Enter') testRequest(); });
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeDrawer(); });
}
function segOn(id, key, val) { document.querySelectorAll('#' + id + ' .seg-btn').forEach(b => b.classList.toggle('on', b.dataset[key] === val)); }
async function confirmDiscard() {
  return !S.dirty || dialog({ title: 'Discard unsaved changes?', body: 'Your policy draft has changes that are not saved.', okText: 'Discard', danger: true });
}
function markDirty() { S.dirty = true; updateSavebar(); }
function updateSavebar() {
  const sb = $('savebar'); const on = S.dirty && !readonly();
  sb.classList.toggle('hidden', !on); sb.classList.toggle('flex', on);
}

// ---------------------------------------------------------------- overview
function stat(label, value, sub, tone, ic) {
  const tones = { brand: 'from-brand-500/15 text-brand-600 dark:text-brand-400', rose: 'from-rose-500/15 text-rose-600 dark:text-rose-400', violet: 'from-violet-500/15 text-violet-600 dark:text-violet-400', amber: 'from-amber-500/15 text-amber-600 dark:text-amber-400' }[tone];
  return el('div', { class: 'card relative overflow-hidden p-5' },
    el('div', { class: 'absolute inset-0 bg-gradient-to-br to-transparent opacity-60 ' + tones.split(' ')[0] }),
    el('div', { class: 'relative flex items-start justify-between' },
      el('div', {}, el('div', { class: 'text-xs font-medium uppercase tracking-wide text-zinc-500 dark:text-zinc-400' }, label),
        el('div', { class: 'mt-2 text-3xl font-semibold tabular-nums tracking-tight' }, String(value)),
        el('div', { class: 'mt-1 text-xs text-zinc-500 dark:text-zinc-400' }, sub)),
      el('div', { class: 'grid h-9 w-9 place-items-center rounded-xl bg-white/70 shadow-sm dark:bg-white/5 ' + tones.split(' ').slice(1).join(' ') }, icon(ic))));
}
function renderStats() {
  const since = Date.now() - 24 * 3600 * 1000;
  const recent = S.events.filter(e => Date.parse(e.timestamp) >= since);
  const blocked = recent.filter(e => e.enforcement === 'enforced' && (e.decision === 'deny' || e.decision === 'ask'));
  const secrets = blocked.filter(e => e.policy === 'protect-secrets').length;
  const observed = recent.filter(e => e.enforcement === 'observed').length;
  const stale = S.sessions.filter(s => s.stale === true).length;
  const box = $('stats'); clear(box);
  box.append(
    stat('Active agents', S.sessions.length, stale ? stale + ' need a relaunch' : 'all on current policy', 'brand', 'bot'),
    stat('Blocked · 24h', blocked.length, 'kernel or proxy refused', 'rose', 'ban'),
    stat('Secrets protected', secrets, 'reads/writes of credentials stopped', 'amber', 'lock'),
    stat('Observed only', observed, 'rules the sandbox can’t enforce yet', 'violet', 'eye'));
}

async function refreshSessions() {
  if (!TOKEN) return;
  const { data } = await api('GET', '/api/sessions');
  S.sessions = data.sessions;
  const box = $('sessions'); clear(box);
  if (!data.sessions.length) {
    box.appendChild(el('div', { class: 'flex flex-col items-center px-6 py-12 text-center' },
      el('div', { class: 'grid h-12 w-12 place-items-center rounded-2xl bg-zinc-100 text-zinc-400 dark:bg-white/5' }, icon('bot', 'h-6 w-6')),
      el('div', { class: 'mt-3 font-medium' }, 'No supervised agents running'),
      el('div', { class: 'mt-1 text-sm text-zinc-500 dark:text-zinc-400' }, 'Start one from a project directory:'),
      el('code', { class: 'mt-3 rounded-lg bg-zinc-100 px-3 py-1.5 dark:bg-white/5' }, 'agentfence run -- claude')));
  }
  for (const s of data.sessions) {
    const status = s.stale === true ? el('span', { class: 'badge-ask' }, icon('alert', 'h-3 w-3'), 'Policy changed · relaunch to apply')
      : s.stale === 'unknown' ? el('span', { class: 'badge-neutral' }, 'Status unknown') : el('span', { class: 'badge-allow' }, icon('check', 'h-3 w-3'), 'On current policy');
    const btn = el('button', { class: s.stale === true ? 'btn-primary' : 'btn-outline', disabled: !s.restartable, title: s.restartable ? '' : 'Started by an older agentfence — restart it from its terminal', onclick: async () => {
      const ok = await dialog({ title: 'Relaunch ' + (s.agent_name || s.agent) + '?', body: ['The agent restarts under the current policy. Claude Code resumes its conversation.', 'If the new policy is invalid, the agent keeps running and you’ll see a “restart refused” event.'], okText: 'Relaunch' });
      if (!ok) return;
      const { data } = await api('POST', '/api/sessions/restart', { session: s.session });
      data.ok ? toast('Relaunch requested for ' + (s.agent_name || s.agent) + '.', 'info') : toast(data.error || 'Relaunch failed', 'err');
    } }, icon('refresh'), 'Relaunch');
    box.appendChild(el('div', { class: 'flex flex-wrap items-center gap-4 px-5 py-4' },
      el('div', { class: 'grid h-10 w-10 place-items-center rounded-xl bg-gradient-to-br from-orange-400/20 to-rose-500/20 text-orange-600 dark:text-orange-300' }, icon('bot', 'h-5 w-5')),
      el('div', { class: 'min-w-0 flex-1' },
        el('div', { class: 'flex flex-wrap items-center gap-2' }, el('span', { class: 'font-semibold' }, s.agent_name || s.agent), el('span', { class: 'badge-neutral font-mono' }, 'pid ' + (s.pid || '?')), status),
        el('div', { class: 'mt-1 truncate font-mono text-xs text-zinc-500 dark:text-zinc-400' }, tilde(s.project) + '  ·  policy ' + (s.policy || '') + '  ·  started ' + relTime(s.started_at))),
      btn));
  }
  renderStats();
}

async function pollEvents() {
  if (!TOKEN) return;
  const { data } = await api('GET', '/api/events?limit=300&after=' + S.lastRow);
  if (!data.events.length && S.events.length) return;
  for (const e of data.events) { S.lastRow = Math.max(S.lastRow, e.rowid); S.events.unshift(e); }
  S.events.sort((a, b) => b.rowid - a.rowid);
  S.events.length = Math.min(S.events.length, 500);
  renderEvents(); renderStats();
}
function renderEvents() {
  const body = $('events'); clear(body);
  const list = S.events.filter(e => {
    const f = S.filter;
    if (f === 'blocked' && !(e.enforcement === 'enforced' && e.decision !== 'allow')) return false;
    if (f === 'observed' && e.enforcement !== 'observed') return false;
    if (f === 'system' && e.decision) return false;
    if (S.search && !(e.resource_display + ' ' + e.action + ' ' + (e.rule_id || '') + ' ' + e.agent).toLowerCase().includes(S.search)) return false;
    return true;
  }).slice(0, 200);
  if (!list.length) body.appendChild(el('tr', {}, el('td', { class: 'td py-10 text-center text-zinc-400', colspan: 6 }, S.events.length ? 'No events match this filter.' : 'No activity yet.')));
  for (const e of list) {
    const blocked = e.enforcement === 'enforced' && e.decision && e.decision !== 'allow';
    body.appendChild(el('tr', { class: 'transition hover:bg-zinc-50 dark:hover:bg-white/[0.02] ' + (blocked ? 'bg-rose-500/[0.03]' : ''), title: e.reason_display || '' },
      el('td', { class: 'td whitespace-nowrap text-xs text-zinc-500 dark:text-zinc-400' }, relTime(e.timestamp)),
      el('td', { class: 'td whitespace-nowrap' }, agentName(e.agent)),
      el('td', { class: 'td whitespace-nowrap font-mono text-xs' }, e.action),
      el('td', { class: 'td' }, el('div', { class: 'mono' }, tilde(e.resource_display)), e.chain_display ? el('div', { class: 'mt-0.5 text-[11px] text-zinc-400' }, e.chain_display) : null),
      el('td', { class: 'td' }, decisionBadge(e.decision, e.enforcement)),
      el('td', { class: 'td font-mono text-xs text-zinc-500 dark:text-zinc-400' }, e.rule_id ? (e.policy + ' / ' + e.rule_id) : '')));
  }
}

// ---------------------------------------------------------------- policy
const readonly = () => !!(S.loaded && S.loaded.trusted);
async function loadPolicy(resetDraft = true) {
  const q = new URLSearchParams({ scope: S.scope, project: S.project, agent: S.agent });
  const { data } = await api('GET', '/api/policy?' + q);
  if (data.error && !data.yaml) { toast(data.error, 'err'); return; }
  S.project = data.project || S.project; $('project').value = S.project;
  S.loaded = data;
  if (resetDraft) { S.doc = data.doc; S.yaml = data.yaml; S.dirty = false; }
  const meta = $('policy-meta'); clear(meta);
  meta.append(el('span', { class: data.exists ? 'badge-allow' : 'badge-neutral' }, data.exists ? 'Saved' : 'Not created yet'), el('code', { class: 'text-xs' }, tilde(data.file)));
  if (data.sha256) meta.appendChild(el('span', { class: 'font-mono text-[11px] text-zinc-400' }, 'sha256 ' + data.sha256.slice(0, 12) + '…'));
  if (!data.exists && S.scope === 'user') meta.appendChild(el('div', { class: 'w-full rounded-xl border border-brand-500/20 bg-brand-500/5 p-3 text-xs text-zinc-600 dark:text-zinc-300' }, 'Starting from the built-in default. Saving a user policy replaces that default for every project — keep the project read/write rules unless you mean to remove them.'));
  $('policy-readonly').classList.toggle('hidden', !readonly());
  $('yaml').readOnly = readonly();
  if (data.error) toast(data.error, 'err');
  renderEffective(data.effective);
  renderStructured(); $('yaml').value = S.yaml; updateSavebar();
}

function renderEffective(eff) {
  const w = $('warnings'); clear(w);
  const body = $('rules'); clear(body);
  if (!eff) return;
  for (const x of eff.warnings || []) w.appendChild(el('div', { class: 'badge-ask max-w-xl whitespace-normal text-left' }, icon('alert', 'h-3 w-3'), x));
  $('rules-count').textContent = eff.rules.length + ' rules';
  for (const r of eff.rules) {
    const enf = r.enforceability === 'observed' ? el('span', { class: 'badge-observed' }, 'observed only') : r.enforceability === 'enforced-coarse' ? el('span', { class: 'badge-neutral' }, 'enforced · by executable') : el('span', { class: 'badge-neutral' }, icon('shield', 'h-3 w-3'), 'enforced');
    body.appendChild(el('tr', {},
      el('td', { class: 'td text-xs text-zinc-500 dark:text-zinc-400' }, r.policy),
      el('td', { class: 'td font-mono text-xs' }, r.id),
      el('td', { class: 'td' }, decisionBadge(r.effect), el('div', { class: 'mt-1 text-[11px] text-zinc-400' }, r.section)),
      el('td', { class: 'td' }, el('div', { class: 'mono' }, r.pattern), r.excepts.length ? el('div', { class: 'mt-0.5 text-[11px] text-zinc-400' }, 'except ' + r.excepts.length + ' pattern(s)') : null),
      el('td', { class: 'td' }, enf)));
  }
}

const SECTIONS = [
  ['filesystem', 'allow_read', 'Can read', 'Paths agents may read.', 'path', true, 'allow', '${PROJECT}/**'],
  ['filesystem', 'allow_write', 'Can write', 'Paths agents may create or modify.', 'path', true, 'allow', '${PROJECT}/**'],
  ['filesystem', 'deny_read', 'Never read', 'Always blocked — explicit deny wins over any allow.', 'path', false, 'deny', '${PROJECT}/secrets/**'],
  ['filesystem', 'deny_write', 'Never write', 'Always blocked, including rename and delete.', 'path', false, 'deny', '${HOME}/.config/**'],
  ['network', 'allow', 'Reachable hosts', 'Everything else is blocked by the proxy.', 'host', true, 'allow', 'api.github.com'],
  ['network', 'deny', 'Blocked hosts', 'Refused even if another rule allows them.', 'host', false, 'deny', 'evil.example.com'],
  ['network', 'listen', 'Local dev-server ports', 'Loopback only, e.g. localhost:3000.', 'host', true, 'allow', 'localhost:3000'],
  ['process', 'deny', 'Never run', 'Blocked by executable name (arguments are observed).', 'command', false, 'deny', 'terraform destroy *'],
  ['process', 'require_approval', 'Needs approval', 'Observed and flagged today; enforced with Endpoint Security.', 'command', false, 'ask', 'git push *'],
  ['process', 'allow', 'Allowed commands', 'Only matters when the process default is deny.', 'command', true, 'allow', 'npm test'],
];
function ensureDoc() {
  if (!S.doc) S.doc = { name: S.scope, layer: S.scope, match_: null, defaults: {}, filesystem: {}, process: {}, network: {}, builtin: null };
  for (const k of ['filesystem', 'process', 'network']) S.doc[k] = S.doc[k] || {};
  S.doc.defaults = S.doc.defaults || {};
}
const SECTION_ICON = { filesystem: 'folder', network: 'globe', process: 'terminal' };

function renderStructured() {
  const root = $('sub-structured'); clear(root);
  if (!S.doc) { root.appendChild(el('div', { class: 'card p-6 text-sm text-rose-600 xl:col-span-2' }, 'This YAML has errors, so it can’t be shown as rules. Fix it in the YAML tab.')); return; }
  ensureDoc(); const ro = readonly();
  // Defaults
  const defs = el('div', { class: 'card p-5 xl:col-span-2' },
    el('div', { class: 'flex items-center gap-2' }, icon('shield', 'h-4 w-4 text-brand-500'), el('h3', { class: 'font-semibold' }, 'When no rule matches')),
    el('p', { class: 'mt-1 text-xs text-zinc-500 dark:text-zinc-400' }, 'Built-in protections (secrets, git config, AgentFence itself) always apply on top.'));
  const row = el('div', { class: 'mt-4 grid gap-4 sm:grid-cols-3' });
  for (const cat of ['filesystem', 'network', 'process']) {
    const seg = el('div', { class: 'seg' });
    for (const v of ['', 'allow', 'ask', 'deny']) {
      if (S.scope === 'project' && v === 'allow') continue;
      seg.appendChild(el('button', { class: 'seg-btn' + ((S.doc.defaults[cat] || '') === v ? ' on' : ''), disabled: ro, onclick: () => { S.doc.defaults[cat] = v || null; markDirty(); renderStructured(); } }, v || 'inherit'));
    }
    row.appendChild(el('div', {}, el('div', { class: 'label flex items-center gap-1.5' }, icon(SECTION_ICON[cat], 'h-3.5 w-3.5'), cat), seg));
  }
  defs.appendChild(row); root.appendChild(defs);

  for (const [grp, key, title, help, kind, isAllow, tone, ph] of SECTIONS) {
    if (S.scope === 'project' && isAllow) continue;
    const list = (S.doc[grp][key] = S.doc[grp][key] || []);
    const toneCls = { allow: 'bg-emerald-500', deny: 'bg-rose-500', ask: 'bg-amber-500' }[tone];
    const card = el('div', { class: 'card flex flex-col p-5' },
      el('div', { class: 'flex items-start justify-between gap-3' },
        el('div', {}, el('div', { class: 'flex items-center gap-2' }, el('span', { class: 'h-2 w-2 rounded-full ' + toneCls }), el('h3', { class: 'font-semibold' }, title), el('span', { class: 'badge-neutral' }, String(list.length))),
          el('p', { class: 'mt-1 text-xs text-zinc-500 dark:text-zinc-400' }, help)),
        el('span', { class: 'font-mono text-[11px] text-zinc-400' }, grp + '.' + key)));
    const chips = el('div', { class: 'mt-4 flex flex-wrap gap-2' });
    if (!list.length) chips.appendChild(el('span', { class: 'text-xs italic text-zinc-400' }, 'No rules'));
    list.forEach((r, i) => {
      const extra = [r.id ? '#' + r.id : null, r.except && r.except.length ? 'except ' + r.except.length : null].filter(Boolean).join(' · ');
      chips.appendChild(el('span', { class: 'chip', title: r.reason || '' }, el('span', { class: 'truncate' }, r.pattern),
        extra ? el('span', { class: 'text-[10px] text-zinc-400' }, extra) : null,
        ro ? null : el('button', { class: 'rounded p-0.5 text-zinc-400 hover:bg-rose-500/10 hover:text-rose-600', title: 'Remove', onclick: () => { list.splice(i, 1); markDirty(); renderStructured(); } }, icon('x', 'h-3.5 w-3.5'))));
    });
    card.appendChild(chips);
    if (!ro) {
      const add = el('input', { class: 'input font-mono', placeholder: ph });
      const doAdd = () => { const v = add.value.trim(); if (!v) return; list.push({ kind, pattern: v, except: [], id: null, reason: null }); markDirty(); renderStructured(); };
      add.addEventListener('keydown', (e) => { if (e.key === 'Enter') doAdd(); });
      card.appendChild(el('div', { class: 'mt-4 flex gap-2' }, add, el('button', { class: 'btn-outline shrink-0', onclick: doAdd }, icon('plus'), 'Add')));
    }
    root.appendChild(card);
  }
}

async function switchMode(mode) {
  if (mode === S.mode) return;
  const body = { scope: S.scope, project: S.project, agent: S.agent };
  if (S.mode === 'structured') body.doc = S.doc; else body.yaml = S.yaml;
  const { data } = await api('POST', '/api/policy/preview', body);
  if (mode === 'structured' && !data.doc) { toast('The YAML has errors — fix them before switching to Rules. ' + (data.error || ''), 'err'); return; }
  if (data.yaml) S.yaml = data.yaml;
  if (data.doc) S.doc = data.doc;
  S.mode = mode; segOn('mode-seg', 'mode', mode);
  $('sub-structured').classList.toggle('hidden', mode !== 'structured'); $('sub-yaml').classList.toggle('hidden', mode !== 'yaml');
  $('yaml').value = S.yaml; renderStructured();
}
function draftBody() {
  const b = { scope: S.scope, project: S.project, agent: S.agent };
  if (S.mode === 'structured') b.doc = S.doc; else b.yaml = S.yaml;
  return b;
}

function openDrawer() { const d = $('drawer'); d.classList.remove('hidden'); }
function closeDrawer() { $('drawer').classList.add('hidden'); }
async function preview() {
  const { data } = await api('POST', '/api/policy/preview', draftBody());
  $('drawer-file').textContent = tilde(S.loaded.file);
  const errs = $('d-errors'); clear(errs);
  if (!data.ok) errs.appendChild(el('div', { class: 'rounded-xl border border-rose-500/30 bg-rose-500/10 p-4 text-sm' },
    el('div', { class: 'flex items-center gap-2 font-semibold text-rose-700 dark:text-rose-300' }, icon('alert'), 'This policy can’t be saved'),
    el('div', { class: 'mt-2 whitespace-pre-wrap font-mono text-xs text-rose-700 dark:text-rose-200' }, data.error || 'Invalid policy')));
  $('save').disabled = !data.ok;
  const w = $('d-warnings'); clear(w);
  if (data.comments_lost) w.appendChild(el('div', { class: 'badge-ask whitespace-normal' }, 'Comments in the existing file won’t be kept (a .bak backup is written).'));
  for (const x of (data.effective && data.effective.warnings) || []) w.appendChild(el('div', { class: 'badge-ask whitespace-normal' }, x));
  const unread = !!(data.effective && data.effective.project_unreadable);
  const cw = $('d-confirm-wrap'); cw.classList.toggle('hidden', !unread); cw.classList.toggle('flex', unread); $('d-confirm').checked = false;
  const ed = $('d-effective'); clear(ed);
  if (data.effective_diff) {
    const rowOf = (txt, add) => el('div', { class: 'flex items-start gap-2 rounded-lg px-3 py-2 font-mono text-xs ' + (add ? 'bg-emerald-500/10 text-emerald-800 dark:text-emerald-200' : 'bg-rose-500/10 text-rose-800 dark:text-rose-200') }, el('span', { class: 'font-bold' }, add ? '+' : '−'), el('span', { class: 'break-all' }, txt));
    data.effective_diff.added.forEach(a => ed.appendChild(rowOf(a, true)));
    data.effective_diff.removed.forEach(r => ed.appendChild(rowOf(r, false)));
    if (!data.effective_diff.added.length && !data.effective_diff.removed.length) ed.appendChild(el('div', { class: 'text-sm text-zinc-500' }, 'No change in what agents can do.'));
  }
  const fd = $('d-diff'); clear(fd);
  for (const l of data.file_diff || []) fd.appendChild(el('div', { class: l.op === '+' ? 'bg-emerald-500/15 text-emerald-300' : l.op === '-' ? 'bg-rose-500/15 text-rose-300' : '' }, (l.op === ' ' ? '  ' : l.op + ' ') + l.line));
  if (data.effective) renderEffective(data.effective);
  openDrawer();
}
async function save() {
  const body = draftBody();
  body.base_sha256 = S.loaded.sha256;
  if ($('d-confirm').checked) body.confirm = ['project-unreadable'];
  $('save').disabled = true;
  const { status, data } = await api('POST', '/api/policy/save', body);
  $('save').disabled = false;
  if (data.ok) {
    closeDrawer();
    const n = (data.affected_sessions || []).length;
    toast(n ? 'Policy saved. ' + n + ' running session(s) use it — relaunch them on the Overview to apply.' : 'Policy saved. It applies to agents launched from now on.');
    await loadPolicy(); refreshSessions();
    if (n) go('sessions');
  } else if (data.needs_confirm) {
    const cw = $('d-confirm-wrap'); cw.classList.remove('hidden'); cw.classList.add('flex');
    toast(data.error, 'err');
  } else if (data.conflict) {
    toast(data.error, 'err');
    const fd = $('d-diff'); clear(fd);
    fd.appendChild(el('div', { class: 'text-amber-300' }, '# Current file on disk (changed since you loaded it):'));
    fd.appendChild(el('div', {}, data.current_yaml || '(deleted)'));
    S.loaded.sha256 = data.current_sha256;
  } else {
    toast(data.error || ('Save failed (' + status + ')'), 'err');
  }
}

// ---------------------------------------------------------------- files
async function listDir(path, force) {
  const body = draftBody(); body.path = path; body.force = !!force;
  const { data } = await api('POST', '/api/fs/list', body);
  if (data.error) { toast(data.error, 'err'); return; }
  S.fsPath = data.path; S.fsParent = data.parent; $('fs-path').value = data.path;
  $('fs-agent').textContent = agentName(S.agent);
  const cr = $('crumbs'); clear(cr);
  const parts = data.path.split('/').filter(Boolean); let acc = '';
  cr.appendChild(el('button', { class: 'rounded px-1.5 py-0.5 text-zinc-500 hover:bg-zinc-100 dark:hover:bg-white/5', onclick: () => listDir('/') }, '/'));
  parts.forEach((p, i) => {
    acc += '/' + p; const target = acc;
    if (i) cr.appendChild(icon('chevron', 'h-3 w-3 text-zinc-400'));
    cr.appendChild(el('button', { class: 'rounded px-1.5 py-0.5 font-mono text-xs hover:bg-zinc-100 dark:hover:bg-white/5 ' + (i === parts.length - 1 ? 'font-semibold' : 'text-zinc-500'), onclick: () => listDir(target) }, p));
  });
  const note = $('fs-note'); clear(note); note.classList.add('hidden');
  if (data.needs_force) {
    note.classList.remove('hidden');
    note.appendChild(el('div', { class: 'card flex items-center justify-between gap-4 p-4 text-sm' }, el('span', {}, 'macOS may ask for permission to list this folder.'), el('button', { class: 'btn-outline', onclick: () => listDir(path, true) }, 'List anyway')));
  } else if (data.truncated) { note.classList.remove('hidden'); note.appendChild(el('div', { class: 'text-xs text-zinc-500' }, 'Showing the first 2000 entries.')); }
  const tb = $('fs'); clear(tb);
  if (!data.entries.length && !data.needs_force) tb.appendChild(el('tr', {}, el('td', { class: 'td py-10 text-center text-zinc-400', colspan: 4 }, 'Empty folder')));
  for (const e of data.entries) {
    const ic = e.kind === 'symlink' ? 'link' : e.is_dir ? 'folder' : 'file';
    const nameEl = e.is_dir && e.kind !== 'symlink'
      ? el('button', { class: 'group flex items-center gap-2 text-left font-medium hover:text-brand-600 dark:hover:text-brand-400', onclick: () => listDir(e.path) }, icon(ic, 'h-4 w-4 text-brand-500'), el('span', { class: 'font-mono text-[13px]' }, e.display))
      : el('div', { class: 'flex items-center gap-2' }, icon(ic, 'h-4 w-4 text-zinc-400'), el('span', { class: 'font-mono text-[13px]' }, e.display));
    const nameTd = el('td', { class: 'td' }, nameEl);
    if (e.link_target) nameTd.appendChild(el('div', { class: 'ml-6 mt-0.5 font-mono text-[11px] text-zinc-400' }, '→ ' + e.link_target));
    if (e.builtin_lock) nameTd.appendChild(el('div', { class: 'ml-6 mt-1 inline-flex items-center gap-1 text-[11px] text-amber-600 dark:text-amber-400' }, icon('lock', 'h-3 w-3'), 'Protected by a built-in rule'));
    const dec = (d) => el('div', { title: d.policy + ' / ' + d.rule_id + ' — ' + d.reason }, decisionBadge(d.effect));
    const acts = el('div', { class: 'flex flex-wrap justify-end gap-1.5' });
    for (const [k, label, cls] of [['allow_read', 'Read', 'emerald'], ['allow_write', 'Write', 'emerald'], ['deny_read', 'Read', 'rose'], ['deny_write', 'Write', 'rose']]) {
      const a = e.actions[k];
      const allow = k.startsWith('allow');
      acts.appendChild(el('button', {
        class: 'inline-flex items-center gap-1 rounded-md border px-2 py-1 text-[11px] font-semibold transition disabled:cursor-not-allowed disabled:opacity-30 ' + (cls === 'emerald' ? 'border-emerald-500/30 text-emerald-700 hover:bg-emerald-500/10 dark:text-emerald-300' : 'border-rose-500/30 text-rose-700 hover:bg-rose-500/10 dark:text-rose-300'),
        disabled: !!a.unavailable || readonly(), title: a.unavailable || ('Adds ' + a.section + ': ' + a.display), onclick: () => addRule(a),
      }, icon(allow ? 'check' : 'ban', 'h-3 w-3'), (allow ? 'Allow ' : 'Deny ') + label));
    }
    tb.appendChild(el('tr', { class: 'transition hover:bg-zinc-50 dark:hover:bg-white/[0.02]' }, nameTd, el('td', { class: 'td' }, dec(e.read)), el('td', { class: 'td' }, dec(e.write)), el('td', { class: 'td' }, acts)));
  }
}
async function addRule(a) {
  const ok = await dialog({ title: 'Add rule to your draft?', body: [el('div', { class: 'label mt-2' }, a.section), el('code', { class: 'block rounded-lg bg-zinc-100 px-3 py-2 dark:bg-white/5' }, a.display), 'Nothing is saved until you review and save the policy.'], okText: 'Add to draft' });
  if (!ok) return;
  if (S.mode !== 'structured') await switchMode('structured');
  ensureDoc();
  const [grp, key] = a.section.split('.');
  const list = (S.doc[grp][key] = S.doc[grp][key] || []);
  if (!list.some(r => r.pattern === a.rule)) list.push({ kind: 'path', pattern: a.rule, except: [], id: null, reason: null });
  markDirty(); renderStructured();
  toast('Added to draft. Review & save when ready.', 'info');
  listDir(S.fsPath);
}

// ---------------------------------------------------------------- test
async function testRequest() {
  const v = $('t-value').value.trim();
  if (!v) return;
  const kind = S.testKind;
  const home = S.overview.home;
  const val = kind === 'path' && v.startsWith('~') ? home + v.slice(1) : v;
  const req = kind === 'path' ? { kind, path: val, action: S.testAction } : kind === 'exec' ? { kind, command: val } : { kind, host: val };
  const body = draftBody(); body.request = req;
  const { data } = await api('POST', '/api/evaluate', body);
  const out = $('t-result'); clear(out);
  if (data.error) { out.appendChild(el('div', { class: 'card border-rose-500/30 p-5 text-sm text-rose-600' }, data.error)); return; }
  const allowed = data.effect === 'allow';
  const tone = allowed ? 'from-emerald-500/20 text-emerald-600 dark:text-emerald-400' : data.effect === 'ask' ? 'from-amber-500/20 text-amber-600 dark:text-amber-400' : 'from-rose-500/20 text-rose-600 dark:text-rose-400';
  out.appendChild(el('div', { class: 'card relative overflow-hidden p-6' },
    el('div', { class: 'absolute inset-0 bg-gradient-to-br to-transparent ' + tone.split(' ')[0] }),
    el('div', { class: 'relative flex items-start gap-4' },
      el('div', { class: 'grid h-12 w-12 place-items-center rounded-2xl bg-white/70 shadow-sm dark:bg-white/5 ' + tone.split(' ').slice(1).join(' ') }, icon(allowed ? 'check' : data.effect === 'ask' ? 'alert' : 'ban', 'h-6 w-6')),
      el('div', { class: 'min-w-0' },
        el('div', { class: 'text-2xl font-semibold tracking-tight ' + tone.split(' ').slice(1).join(' ') }, allowed ? 'Allowed' : data.effect === 'ask' ? 'Needs approval' : 'Blocked'),
        el('div', { class: 'mt-1 text-sm text-zinc-600 dark:text-zinc-300' }, data.reason),
        el('div', { class: 'mt-3 flex flex-wrap items-center gap-2' }, el('span', { class: 'badge-neutral font-mono' }, data.policy + ' / ' + data.rule_id)),
        data.trace.length ? el('div', { class: 'mt-3 space-y-1' }, el('div', { class: 'label' }, 'Matched rules'), ...data.trace.map(t => el('div', { class: 'font-mono text-xs text-zinc-500 dark:text-zinc-400' }, t))) : null))));
}

bootstrap().catch(e => { if (String(e) !== 'Error: unauthorized') toast('Error: ' + e, 'err'); });
