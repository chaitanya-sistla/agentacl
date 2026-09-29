// AgentFence local UI. Security: dynamic text is inserted with textContent /
// createTextNode only (never innerHTML); icons are built with createElementNS
// from constant path data; the bearer token lives only in memory.
'use strict';

let TOKEN = null;
const S = {
  overview: null,
  scope: 'user', project: '', agent: 'claude-code',
  loaded: null, doc: null, yaml: '', mode: 'structured', dirty: false,
  ev: { page: 1, size: 25, kind: 'all', q: '', total: 0, pages: 1, counts: null },
  rulesPage: 1, effective: null,
  sessions: [], tab: 'sessions',
  map: { nodes: new Map(), roots: [], selected: null, loadedFor: '' },
};

// ------------------------------------------------------------------ helpers
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
  arrowRight: 'M5 12h14M12 5l7 7-7 7',
  play: 'M6 4l14 8-14 8z',
  user: 'M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2M12 3a4 4 0 1 0 0 8 4 4 0 0 0 0-8z',
  ban: 'M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20zM4.9 4.9l14.2 14.2',
  chevron: 'M9 18l6-6-6-6',
  chevronDown: 'M6 9l6 6 6-6',
  chevronLeft: 'M15 18l-6-6 6-6',
  map: 'M1 6v16l7-4 8 4 7-4V2l-7 4-8-4-7 4zM8 2v16M16 6v16',
  key: 'M21 2l-2 2m-7.6 7.6a5.5 5.5 0 1 1-7.8 7.8 5.5 5.5 0 0 1 7.8-7.8zm0 0L15.5 7.5m0 0 3 3L22 7l-3-3m-3.5 3.5L19 4',
  cpu: 'M4 4h16v16H4zM9 9h6v6H9zM9 1v3M15 1v3M9 20v3M15 20v3M20 9h3M20 14h3M1 9h3M1 14h3',
  home: 'M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2zM9 22V12h6v10',
  sparkles: 'M12 3l1.9 5.1L19 10l-5.1 1.9L12 17l-1.9-5.1L5 10l5.1-1.9z',
};
function icon(name, cls = 'h-4 w-4') {
  const ns = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(ns, 'svg');
  for (const [k, v] of Object.entries({ viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', 'stroke-width': '2', 'stroke-linecap': 'round', 'stroke-linejoin': 'round', class: cls + ' shrink-0', 'aria-hidden': 'true' })) svg.setAttribute(k, v);
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
const tilde = (p) => (S.overview && p && p.startsWith(S.overview.home)) ? '~' + p.slice(S.overview.home.length) : (p || '');
const baseName = (p) => (p || '').replace(/\/+$/, '').split('/').pop() || p;
const agentName = (id) => (S.overview?.agents.find(a => a.id === id)?.name) || id;
function debounce(fn, ms) { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; }

function toast(msg, kind = 'ok') {
  const tone = { ok: 'border-emerald-500/40', err: 'border-rose-500/40', info: 'border-brand-500/40' }[kind];
  const ic = { ok: ['check', 'text-emerald-500'], err: ['alert', 'text-rose-500'], info: ['sparkles', 'text-brand-500'] }[kind];
  const t = el('div', { class: 'pointer-events-auto flex items-start gap-3 rounded-xl border bg-white p-3.5 text-sm shadow-xl transition-opacity dark:bg-zinc-900 ' + tone },
    icon(ic[0], 'mt-0.5 h-4 w-4 ' + ic[1]), el('div', { class: 'text-zinc-700 dark:text-zinc-200' }, msg));
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

// Plain-language access status.
const STATUS = {
  full: { label: 'Can read & write', short: 'Full access', dot: 'bg-emerald-500', ring: 'border-emerald-500/40', text: 'text-emerald-700 dark:text-emerald-300', stroke: '#10b981' },
  'read-only': { label: 'Can read, not write', short: 'Read-only', dot: 'bg-sky-500', ring: 'border-sky-500/40', text: 'text-sky-700 dark:text-sky-300', stroke: '#0ea5e9' },
  blocked: { label: 'Blocked', short: 'Blocked', dot: 'bg-rose-500', ring: 'border-rose-500/50', text: 'text-rose-700 dark:text-rose-300', stroke: '#f43f5e' },
  ask: { label: 'Needs approval', short: 'Approval', dot: 'bg-amber-500', ring: 'border-amber-500/50', text: 'text-amber-700 dark:text-amber-300', stroke: '#f59e0b' },
  partial: { label: 'Blocked, some things inside allowed', short: 'Partly allowed', dot: 'bg-violet-500', ring: 'border-violet-500/50', text: 'text-violet-700 dark:text-violet-300', stroke: '#8b5cf6' },
};
function statusBadge(st) {
  const s = STATUS[st]; if (!s) return el('span', { class: 'badge-neutral' }, st);
  return el('span', { class: 'badge-neutral ' + s.text }, el('span', { class: 'h-1.5 w-1.5 rounded-full ' + s.dot }), s.short);
}
function resultBadge(effect, enforcement) {
  if (!effect) return el('span', { class: 'text-zinc-400' }, '—');
  if (enforcement === 'observed' && effect !== 'allow') return el('span', { class: 'badge-observed' }, icon('eye', 'h-3 w-3'), 'Seen, not blocked');
  if (effect === 'allow') return el('span', { class: 'badge-allow' }, icon('check', 'h-3 w-3'), 'Allowed');
  if (effect === 'ask') return el('span', { class: 'badge-ask' }, icon('alert', 'h-3 w-3'), 'Needs approval');
  return el('span', { class: 'badge-deny' }, icon('ban', 'h-3 w-3'), 'Blocked');
}
const ACTION_WORDS = {
  'filesystem.read': 'Read a file', 'filesystem.write': 'Change a file', 'process.exec': 'Run a command', 'network.connect': 'Connect to',
  'network.listen': 'Open a port', 'ipc.mach-lookup': 'Talk to a system service', session_start: 'Session started', session_end: 'Session ended',
  backend_warning: 'Note', 'policy.inputs': 'Loaded rules', 'policy.saved': 'Rules saved', 'session.restart_requested': 'Relaunch requested', 'restart.refused': 'Relaunch refused',
};
const actionWord = (a) => ACTION_WORDS[a] || a;
// Who a decision comes from, in plain words.
const POLICY_WORDS = {
  'protect-secrets': 'the built-in secret protection', 'exec-persistence': 'the built-in protection for config that runs code later',
  'agentfence-self': 'the built-in protection for AgentFence itself', 'seatbelt-baseline': 'the sandbox (no rule allows it)',
  default: 'the starting rules (the project is open, everything else closed)', runtime: 'the basics every program needs to run',
  user: 'your rules', project: 'this project\u2019s rules', builtin: 'AgentFence', fallback: 'the default setting', session: 'the agent\u2019s own install folder', proxy: 'the network proxy',
};
function whyText(e) {
  if (!e.policy) return '';
  if (e.policy.startsWith('provider:')) {
    const eff = e.effect || e.decision;
    return eff === 'allow' ? agentName(e.policy.slice(9)) + ' needs this to work' : 'Protected: ' + agentName(e.policy.slice(9)) + '\u2019s own settings (they could run code later)';
  }
  if (e.rule_id === 'default') return e.effect === 'allow' || e.decision === 'allow' ? 'the default setting allows it' : 'nothing allows it, so it\u2019s blocked by default';
  const who = POLICY_WORDS[e.policy] || e.policy;
  return who.charAt(0).toUpperCase() + who.slice(1) + (e.rule_id && !e.rule_id.includes('/') && !['default', 'runtime-requirement', 'protected-config'].includes(e.rule_id) ? ' (' + e.rule_id + ')' : '');
}
const RULE_WORDS = POLICY_WORDS;
function relTime(ts) {
  const d = (Date.now() - Date.parse(ts)) / 1000;
  if (!isFinite(d)) return '';
  if (d < 5) return 'just now'; if (d < 60) return Math.floor(d) + 's ago';
  if (d < 3600) return Math.floor(d / 60) + ' min ago'; if (d < 86400) return Math.floor(d / 3600) + ' h ago';
  return new Date(ts).toLocaleString();
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

// ------------------------------------------------------------------ bootstrap
async function bootstrap() {
  document.querySelectorAll('[data-icon]').forEach(n => n.appendChild(icon(n.dataset.icon, n.classList.contains('grid') ? 'h-5 w-5' : 'h-4 w-4')));
  const m = /code=([0-9a-f]+)/.exec(location.hash);
  const tabm = /tab=(sessions|map|policy|test)/.exec(location.hash);
  history.replaceState(null, '', '/');
  if (!m) return lock();
  const r = await fetch('/api/session', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ code: m[1] }) });
  const d = await r.json().catch(() => ({}));
  if (!r.ok || !d.token) return lock(d.error || 'This link has expired or was already used. Press Enter in the `agentfence ui` terminal for a fresh one.');
  TOKEN = d.token;
  S.overview = (await api('GET', '/api/overview')).data;
  $('who').textContent = S.overview.human;
  fillProjects(S.overview.projects, S.overview.projects[0]);
  const ag = $('agent'); clear(ag);
  for (const a of S.overview.agents) ag.appendChild(el('option', { value: a.id }, a.name));
  renderLegend();
  wire();
  await loadPolicy();
  await Promise.all([refreshSessions(), loadEvents()]);
  go(tabm ? tabm[1] : 'sessions');
  setInterval(refreshSessions, 4000);
  setInterval(() => { if (S.tab === 'sessions') loadEvents(true); }, 3000);
}
function fillProjects(list, selected) {
  const sel = $('project'); clear(sel);
  const seen = new Set();
  for (const p of list) {
    if (seen.has(p)) continue; seen.add(p);
    sel.appendChild(el('option', { value: p }, baseName(p) + '  —  ' + tilde(p)));
  }
  S.project = selected || list[0] || '';
  sel.value = S.project;
}

const TITLES = {
  sessions: ['Overview', 'Which agents are running and what they tried to do'],
  map: ['Access map', 'Every folder, colored by what the agent can do there'],
  policy: ['Rules', 'Decide what agents may read, change, run and connect to'],
  test: ['Check access', 'Ask whether the agent could do something — before it tries'],
};
function go(tab) {
  S.tab = tab;
  document.querySelectorAll('#nav .nav-item').forEach(b => b.classList.toggle('active', b.dataset.tab === tab));
  for (const t of Object.keys(TITLES)) $('tab-' + t).classList.toggle('hidden', t !== tab);
  $('page-title').textContent = TITLES[tab][0]; $('page-sub').textContent = TITLES[tab][1];
  $('mobile-nav').value = tab;
  if (tab === 'map') loadMap();
  if (tab === 'sessions') loadEvents();
  updateSavebar();
}

function wire() {
  document.querySelectorAll('#nav .nav-item').forEach(b => b.addEventListener('click', () => go(b.dataset.tab)));
  $('mobile-nav').addEventListener('change', (e) => go(e.target.value));
  document.querySelectorAll('#mode-seg .seg-btn').forEach(b => b.addEventListener('click', () => switchMode(b.dataset.mode)));
  $('scope').addEventListener('change', async (e) => {
    if (!(await confirmDiscard())) { e.target.value = S.scope; return; }
    S.scope = e.target.value; S.map.loadedFor = ''; loadPolicy();
  });
  $('agent').addEventListener('change', (e) => { S.agent = e.target.value; S.map.loadedFor = ''; loadPolicy(false); if (S.tab === 'map') loadMap(); });
  $('project').addEventListener('change', async (e) => {
    if (!(await confirmDiscard())) { e.target.value = S.project; return; }
    S.project = e.target.value; S.map.loadedFor = ''; await loadPolicy(); if (S.tab === 'map') loadMap();
  });
  $('pick-folder').addEventListener('click', pickFolder);
  $('reload').addEventListener('click', async () => { if (await confirmDiscard()) loadPolicy(); });
  $('yaml').addEventListener('input', () => { S.yaml = $('yaml').value; markDirty(); });
  $('preview').addEventListener('click', preview);
  $('discard').addEventListener('click', async () => { if (await confirmDiscard()) { await loadPolicy(); S.map.loadedFor = ''; if (S.tab === 'map') loadMap(); } });
  document.querySelectorAll('#drawer [data-close]').forEach(b => b.addEventListener('click', closeDrawer));
  $('save').addEventListener('click', save);
  $('event-kind').addEventListener('change', (e) => { S.ev.kind = e.target.value; S.ev.page = 1; loadEvents(); });
  $('event-search').addEventListener('input', debounce((e) => { S.ev.q = e.target.value; S.ev.page = 1; loadEvents(); }, 250));
  $('map-reload').addEventListener('click', () => { S.map.loadedFor = ''; loadMap(); });
  $('t-kind').addEventListener('change', (e) => { $('t-value').placeholder = { read: '~/src/app/.env', write: '~/src/app/src/main.rs', rename: '~/.aws', exec: 'git push origin main', host: 'api.example.com:443' }[e.target.value]; });
  $('t-go').addEventListener('click', testRequest);
  $('t-value').addEventListener('keydown', (e) => { if (e.key === 'Enter') testRequest(); });
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeDrawer(); });
}
async function confirmDiscard() {
  return !S.dirty || dialog({ title: 'Discard unsaved changes?', body: 'Your rule changes have not been saved.', okText: 'Discard', danger: true });
}
function markDirty() { S.dirty = true; updateSavebar(); S.map.loadedFor = ''; }
function updateSavebar() {
  const sb = $('savebar'); const on = S.dirty && !readonly();
  sb.classList.toggle('hidden', !on); sb.classList.toggle('flex', on);
}

async function pickFolder() {
  toast('A Finder window is open — choose your project folder.', 'info');
  const { data } = await api('POST', '/api/pick-folder', {});
  if (data.cancelled) return;
  if (data.error) { toast(data.error, 'err'); return; }
  if (!(await confirmDiscard())) return;
  const list = [data.path, ...Array.from($('project').options).map(o => o.value)];
  fillProjects(list, data.path);
  S.map.loadedFor = '';
  await loadPolicy(); if (S.tab === 'map') loadMap();
  toast('Project set to ' + tilde(data.path));
}

// ------------------------------------------------------------------ overview
function stat(label, value, sub, tone, ic) {
  const t = { brand: ['from-brand-500/15', 'text-brand-600 dark:text-brand-400'], rose: ['from-rose-500/15', 'text-rose-600 dark:text-rose-400'], violet: ['from-violet-500/15', 'text-violet-600 dark:text-violet-400'], amber: ['from-amber-500/15', 'text-amber-600 dark:text-amber-400'] }[tone];
  return el('div', { class: 'card relative overflow-hidden p-5' },
    el('div', { class: 'absolute inset-0 bg-gradient-to-br to-transparent opacity-70 ' + t[0] }),
    el('div', { class: 'relative flex items-start justify-between' },
      el('div', {}, el('div', { class: 'text-xs font-medium text-zinc-500 dark:text-zinc-400' }, label),
        el('div', { class: 'mt-2 text-3xl font-semibold tabular-nums tracking-tight' }, String(value)),
        el('div', { class: 'mt-1 text-xs text-zinc-500 dark:text-zinc-400' }, sub)),
      el('div', { class: 'grid h-9 w-9 place-items-center rounded-xl bg-white/80 shadow-sm dark:bg-white/5 ' + t[1] }, icon(ic))));
}
function renderStats() {
  const c = S.ev.counts || { blocked: 0, secrets: 0, observed: 0 };
  const stale = S.sessions.filter(s => s.stale === true).length;
  const box = $('stats'); clear(box);
  box.append(
    stat('Agents running', S.sessions.length, stale ? stale + ' need a relaunch' : 'all using current rules', 'brand', 'bot'),
    stat('Blocked (last 24 h)', c.blocked, 'attempts macOS refused', 'rose', 'ban'),
    stat('Secrets protected (24 h)', c.secrets, 'reads of keys and credentials stopped', 'amber', 'key'),
    stat('Seen but not blocked (24 h)', c.observed, 'rules only logged for now', 'violet', 'eye'));
}

async function refreshSessions() {
  if (!TOKEN) return;
  const { data } = await api('GET', '/api/sessions');
  S.sessions = data.sessions;
  const box = $('sessions'); clear(box);
  if (!data.sessions.length) {
    box.appendChild(el('div', { class: 'flex flex-col items-center px-6 py-10 text-center' },
      el('div', { class: 'grid h-12 w-12 place-items-center rounded-2xl bg-zinc-100 text-zinc-400 dark:bg-white/5' }, icon('bot', 'h-6 w-6')),
      el('div', { class: 'mt-3 font-medium' }, 'No agents are running through AgentFence'),
      el('div', { class: 'mt-1 text-sm text-zinc-500 dark:text-zinc-400' }, 'In your project folder, start your agent like this:'),
      el('code', { class: 'mt-3 rounded-lg bg-zinc-100 px-3 py-1.5 dark:bg-white/5' }, 'agentfence run -- claude')));
  }
  for (const s of data.sessions) {
    const status = s.stale === true ? el('span', { class: 'badge-ask' }, icon('alert', 'h-3 w-3'), 'Rules changed — relaunch to apply')
      : s.stale === 'unknown' ? el('span', { class: 'badge-neutral' }, 'Started by an older version') : el('span', { class: 'badge-allow' }, icon('check', 'h-3 w-3'), 'Using current rules');
    const btn = el('button', { class: s.stale === true ? 'btn-primary' : 'btn-outline', disabled: !s.restartable, title: s.restartable ? '' : 'Started by an older agentfence — restart it from its terminal', onclick: async () => {
      const ok = await dialog({ title: 'Relaunch ' + (s.agent_name || s.agent) + '?', body: ['It restarts with the current rules. Claude Code continues the same conversation.', 'If the rules have a mistake, the agent keeps running and you’ll see why.'], okText: 'Relaunch' });
      if (!ok) return;
      const { data } = await api('POST', '/api/sessions/restart', { session: s.session });
      data.ok ? toast('Relaunching ' + (s.agent_name || s.agent) + '…', 'info') : toast(data.error || 'Relaunch failed', 'err');
    } }, icon('refresh'), 'Relaunch');
    box.appendChild(el('div', { class: 'flex flex-wrap items-center gap-4 px-5 py-4' },
      el('div', { class: 'grid h-10 w-10 place-items-center rounded-xl bg-gradient-to-br from-orange-400/20 to-rose-500/20 text-orange-600 dark:text-orange-300' }, icon('bot', 'h-5 w-5')),
      el('div', { class: 'min-w-0 flex-1' },
        el('div', { class: 'flex flex-wrap items-center gap-2' }, el('span', { class: 'font-semibold' }, s.agent_name || s.agent), status),
        el('div', { class: 'mt-1 truncate text-xs text-zinc-500 dark:text-zinc-400' }, 'In ' + tilde(s.project) + '  ·  started ' + relTime(s.started_at) + '  ·  process ' + (s.pid || '?'))),
      btn));
  }
  renderStats();
}

async function loadEvents(silent) {
  if (!TOKEN) return;
  const q = new URLSearchParams({ page: S.ev.page, size: S.ev.size, kind: S.ev.kind, q: S.ev.q });
  const { data } = await api('GET', '/api/events?' + q);
  if (silent && S.ev.page !== 1 && data.total === S.ev.total) return;
  Object.assign(S.ev, { total: data.total, pages: data.pages, counts: data.counts_24h });
  renderEvents(data.events); renderPager(); renderStats();
}
function renderEvents(list) {
  const body = $('events'); clear(body);
  if (!list.length) body.appendChild(el('tr', {}, el('td', { class: 'td py-10 text-center text-zinc-400', colspan: 6 }, S.ev.total || S.ev.q || S.ev.kind !== 'all' ? 'Nothing matches this filter.' : 'No activity yet — start an agent with agentfence run.')));
  for (const e of list) {
    const blocked = e.enforcement === 'enforced' && e.decision && e.decision !== 'allow';
    body.appendChild(el('tr', { class: 'transition hover:bg-zinc-50 dark:hover:bg-white/[0.02]' + (blocked ? ' bg-rose-500/[0.04]' : ''), title: e.reason_display || '' },
      el('td', { class: 'td whitespace-nowrap text-xs text-zinc-500 dark:text-zinc-400', title: e.timestamp }, relTime(e.timestamp)),
      el('td', { class: 'td whitespace-nowrap' }, agentName(e.agent)),
      el('td', { class: 'td whitespace-nowrap' }, actionWord(e.action)),
      el('td', { class: 'td' }, el('div', { class: 'mono' }, tilde(e.resource_display)), e.chain_display && e.chain_display.includes('→') ? el('div', { class: 'mt-0.5 text-[11px] text-zinc-400' }, 'via ' + e.chain_display) : null),
      el('td', { class: 'td' }, resultBadge(e.decision, e.enforcement)),
      el('td', { class: 'td text-xs text-zinc-500 dark:text-zinc-400' }, whyText(e))));
  }
}
function pagerInto(box, page, pages, total, size, onGo, onSize) {
  clear(box);
  const from = total ? (page - 1) * size + 1 : 0, to = Math.min(page * size, total);
  box.appendChild(el('div', { class: 'text-zinc-500 dark:text-zinc-400' }, total ? `Showing ${from.toLocaleString()}–${to.toLocaleString()} of ${total.toLocaleString()}` : 'No results'));
  const nav = el('div', { class: 'flex items-center gap-1' });
  const btn = (label, p, on, dis) => el('button', { class: 'min-w-8 rounded-lg px-2.5 py-1 text-sm font-medium ' + (on ? 'bg-brand-600 text-white' : 'text-zinc-600 hover:bg-zinc-100 dark:text-zinc-300 dark:hover:bg-white/5'), disabled: dis, onclick: () => onGo(p) }, label);
  nav.appendChild(el('button', { class: 'btn-ghost', disabled: page <= 1, onclick: () => onGo(page - 1) }, icon('chevronLeft'), 'Previous'));
  const pagesToShow = new Set([1, pages, page - 1, page, page + 1].filter(p => p >= 1 && p <= pages));
  let last = 0;
  for (const p of [...pagesToShow].sort((a, b) => a - b)) {
    if (p - last > 1) nav.appendChild(el('span', { class: 'px-1 text-zinc-400' }, '…'));
    nav.appendChild(btn(String(p), p, p === page, false)); last = p;
  }
  nav.appendChild(el('button', { class: 'btn-ghost', disabled: page >= pages, onclick: () => onGo(page + 1) }, 'Next', icon('chevron')));
  box.appendChild(nav);
  if (onSize) {
    const sel = el('select', { class: 'select w-32', onchange: (e) => onSize(+e.target.value) }, ...[10, 25, 50, 100].map(n => el('option', { value: n }, n + ' per page')));
    sel.value = String(size);
    box.appendChild(sel);
  }
}
function renderPager() {
  pagerInto($('pager'), S.ev.page, S.ev.pages, S.ev.total, S.ev.size, (p) => { S.ev.page = Math.min(Math.max(1, p), S.ev.pages); loadEvents(); }, (n) => { S.ev.size = n; S.ev.page = 1; loadEvents(); });
}

// ------------------------------------------------------------------ access map
const NODE_W = 250, NODE_H = 44, COL_W = 300, ROW_H = 56, PAGE = 25;
function renderLegend() {
  const lg = $('legend'); clear(lg);
  for (const k of ['full', 'read-only', 'partial', 'blocked', 'ask']) {
    const s = STATUS[k];
    lg.appendChild(el('span', { class: 'inline-flex items-center gap-1.5 rounded-full border border-zinc-200 bg-white px-2.5 py-1 font-medium dark:border-white/10 dark:bg-white/5' }, el('span', { class: 'h-2 w-2 rounded-full ' + s.dot }), s.label));
  }
  lg.appendChild(el('span', { class: 'inline-flex items-center gap-1.5 rounded-full border border-dashed border-zinc-300 px-2.5 py-1 font-medium text-zinc-500 dark:border-white/20' }, 'Dashed = has exceptions inside'));
  lg.appendChild(el('span', { class: 'inline-flex items-center gap-1.5 px-1 text-zinc-500' }, icon('lock', 'h-3 w-3'), 'Built-in protection'));
}
async function mapCall(path, extra) {
  const body = draftBody(); Object.assign(body, extra || {}); if (path) body.path = path;
  return (await api('POST', path ? '/api/fs/list' : '/api/map', body)).data;
}
async function loadMap() {
  $('map-agent').textContent = agentName(S.agent) + (S.dirty ? ' · with unsaved changes' : '');
  const key = [S.scope, S.project, S.agent].join('|');
  if (S.map.loadedFor === key) { renderMap(); return; }
  const data = await mapCall(null);
  if (data.error) { toast(data.error, 'err'); return; }
  const M = S.map; M.nodes = new Map(); M.roots = [];
  const expanded = M.expanded || new Set();
  for (const g of data.roots) {
    const gid = g.id;
    M.nodes.set(gid, { data: g, children: [], expanded: true, depth: 0 });
    M.roots.push(gid);
    for (const c of g.children) addNode(c, gid, 1);
    M.nodes.get(gid).children = g.children.map(c => c.id);
  }
  M.loadedFor = key;
  // Re-open folders that were open before (e.g. after adding a rule).
  for (const id of expanded) if (M.nodes.has(id) && M.nodes.get(id).data.expandable) await expand(id, true);
  if (!M.selected || !M.nodes.has(M.selected)) M.selected = M.nodes.get('group:project')?.children[0] || null;
  renderMap();
}
function addNode(d, parent, depth) {
  S.map.nodes.set(d.id, { data: d, children: [], expanded: false, depth, parent, total: 0, loaded: 0 });
}
async function expand(id, silent) {
  const n = S.map.nodes.get(id); if (!n || !n.data.expandable) return;
  if (n.loaded === 0 || n.forceNext) {
    const data = await mapCall(n.data.path, { offset: n.loaded, limit: PAGE, force: !!n.forceNext });
    if (data.needs_force) { n.needsForce = true; n.expanded = true; if (!silent) renderMap(); return; }
    n.needsForce = false; n.forceNext = false;
    for (const c of data.entries) { addNode(c, id, n.depth + 1); n.children.push(c.id); }
    n.loaded += data.entries.length; n.total = data.total;
  }
  n.expanded = true;
  (S.map.expanded = S.map.expanded || new Set()).add(id);
  if (!silent) renderMap();
}
async function more(id) {
  const n = S.map.nodes.get(id);
  const data = await mapCall(n.data.path, { offset: n.loaded, limit: PAGE });
  for (const c of data.entries) { addNode(c, id, n.depth + 1); n.children.push(c.id); }
  n.loaded += data.entries.length; renderMap();
}
function visible() {
  const out = [];
  const walk = (id) => {
    const n = S.map.nodes.get(id); out.push({ id, n });
    if (n.expanded) {
      for (const c of n.children) walk(c);
      if (n.needsForce) out.push({ id: id + '::force', n: { depth: n.depth + 1, special: 'force', parent: id } });
      else if (n.loaded < n.total) out.push({ id: id + '::more', n: { depth: n.depth + 1, special: 'more', parent: id, remaining: n.total - n.loaded } });
    }
  };
  S.map.roots.forEach(walk);
  return out;
}
function renderMap() {
  const canvas = $('map-canvas'); clear(canvas);
  const rows = visible();
  const pos = new Map();
  rows.forEach((r, i) => pos.set(r.id, { x: 24 + r.n.depth * COL_W, y: 20 + i * ROW_H }));
  const width = 24 + Math.max(...rows.map(r => r.n.depth)) * COL_W + NODE_W + 40;
  const height = 20 + rows.length * ROW_H + 20;
  canvas.style.width = width + 'px'; canvas.style.height = height + 'px';
  // connectors
  const ns = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(ns, 'svg');
  svg.setAttribute('width', width); svg.setAttribute('height', height); svg.setAttribute('class', 'absolute inset-0');
  for (const r of rows) {
    const parent = r.n.parent; if (!parent || !pos.has(parent)) continue;
    const a = pos.get(parent), b = pos.get(r.id);
    const x1 = a.x + NODE_W, y1 = a.y + NODE_H / 2, x2 = b.x, y2 = b.y + NODE_H / 2, mx = (x1 + x2) / 2;
    const p = document.createElementNS(ns, 'path');
    p.setAttribute('d', `M${x1} ${y1} C${mx} ${y1}, ${mx} ${y2}, ${x2} ${y2}`);
    p.setAttribute('fill', 'none');
    p.setAttribute('stroke', r.n.data ? (STATUS[r.n.data.status]?.stroke || '#71717a') : '#a1a1aa');
    p.setAttribute('stroke-width', '1.75'); p.setAttribute('stroke-opacity', '0.55');
    if (!r.n.data) p.setAttribute('stroke-dasharray', '4 4');
    svg.appendChild(p);
  }
  canvas.appendChild(svg);
  for (const r of rows) {
    const { x, y } = pos.get(r.id);
    const box = r.n.special ? specialNode(r) : mapNode(r.id, r.n);
    box.style.left = x + 'px'; box.style.top = y + 'px'; box.style.width = NODE_W + 'px'; box.style.height = NODE_H + 'px';
    canvas.appendChild(box);
  }
  renderDetail();
}
function specialNode(r) {
  if (r.n.special === 'force') {
    return el('button', { class: 'absolute flex items-center gap-2 rounded-xl border border-dashed border-amber-500/50 bg-amber-500/5 px-3 text-left text-xs text-amber-700 dark:text-amber-300', onclick: () => { const p = S.map.nodes.get(r.n.parent); p.forceNext = true; p.loaded = 0; p.children = []; expand(r.n.parent); } }, icon('alert', 'h-3.5 w-3.5'), 'macOS may ask permission — click to list');
  }
  return el('button', { class: 'absolute flex items-center gap-2 rounded-xl border border-dashed border-zinc-300 px-3 text-left text-xs font-medium text-zinc-500 hover:border-brand-500 hover:text-brand-600 dark:border-white/15', onclick: () => more(r.n.parent) }, icon('plus', 'h-3.5 w-3.5'), `Show ${Math.min(PAGE, r.n.remaining)} more (${r.n.remaining} left)`);
}
function mapNode(id, n) {
  const d = n.data;
  if (d.kind === 'group') {
    const ic = { 'group:project': 'folder', 'group:home': 'home', 'group:secrets': 'key', 'group:system': 'cpu' }[id] || 'folder';
    return el('div', { class: 'absolute flex items-center gap-2.5 rounded-xl bg-zinc-900 px-3 text-white shadow-md dark:bg-white dark:text-zinc-900', title: d.description },
      icon(ic, 'h-4 w-4'), el('div', { class: 'min-w-0' }, el('div', { class: 'truncate text-sm font-semibold' }, d.display), el('div', { class: 'truncate text-[10px] opacity-60' }, d.description)));
  }
  const s = STATUS[d.status] || STATUS.blocked;
  const sel = S.map.selected === id;
  const dashed = d.inner_rules > 0 ? ' border-dashed' : '';
  const ic = d.kind === 'symlink' ? 'link' : d.is_dir ? 'folder' : 'file';
  const node = el('div', { class: 'absolute flex cursor-pointer items-center gap-2 rounded-xl border-2 bg-white pl-2.5 pr-1.5 shadow-sm transition hover:shadow-md dark:bg-zinc-900 ' + s.ring + dashed + (sel ? ' ring-2 ring-brand-500 ring-offset-2 ring-offset-white dark:ring-offset-zinc-950' : ''), title: tilde(d.path) + ' — ' + s.label, onclick: () => { S.map.selected = id; renderMap(); } },
    el('span', { class: 'h-2.5 w-2.5 shrink-0 rounded-full ' + s.dot }),
    icon(ic, 'h-4 w-4 text-zinc-400'),
    el('div', { class: 'min-w-0 flex-1' },
      el('div', { class: 'truncate font-mono text-[12.5px] font-medium' }, d.display),
      el('div', { class: 'truncate text-[10.5px] ' + s.text }, s.short + (d.inner_rules && d.status !== 'partial' ? ' · exceptions inside' : ''))),
    d.builtin_lock ? el('span', { title: 'Built-in protection' }, icon('lock', 'h-3.5 w-3.5 text-amber-500')) : null,
    d.expandable ? el('button', { class: 'grid h-7 w-7 place-items-center rounded-lg text-zinc-400 hover:bg-zinc-100 hover:text-zinc-700 dark:hover:bg-white/10', title: n.expanded ? 'Collapse' : 'Show what’s inside', onclick: (e) => { e.stopPropagation(); if (n.expanded) { n.expanded = false; S.map.expanded?.delete(id); renderMap(); } else expand(id); } }, icon(n.expanded ? 'chevronDown' : 'chevron', 'h-4 w-4')) : null);
  return node;
}
function explain(label, d) {
  const allowed = d.effect === 'allow';
  const w = whyText(d);
  const who = w.charAt(0).toLowerCase() + w.slice(1);
  return el('div', { class: 'flex items-start gap-3 rounded-xl p-3 ' + (allowed ? 'bg-emerald-500/10' : d.effect === 'ask' ? 'bg-amber-500/10' : 'bg-rose-500/10') },
    el('div', { class: 'mt-0.5 ' + (allowed ? 'text-emerald-600 dark:text-emerald-400' : d.effect === 'ask' ? 'text-amber-600' : 'text-rose-600 dark:text-rose-400') }, icon(allowed ? 'check' : d.effect === 'ask' ? 'alert' : 'ban', 'h-5 w-5')),
    el('div', {}, el('div', { class: 'font-medium' }, label + (allowed ? ': allowed' : d.effect === 'ask' ? ': needs approval' : ': blocked')),
      el('div', { class: 'mt-0.5 text-xs text-zinc-600 dark:text-zinc-300' }, 'Because ' + who + '.'),
      d.reason ? el('div', { class: 'mt-1 text-[11px] text-zinc-500 dark:text-zinc-400' }, d.reason) : null));
}
function renderDetail() {
  const box = $('map-detail'); clear(box);
  const n = S.map.selected && S.map.nodes.get(S.map.selected);
  if (!n || !n.data || n.data.kind === 'group') {
    box.append(el('div', { class: 'text-sm font-semibold' }, 'Click any file or folder'), el('p', { class: 'mt-1 text-sm text-zinc-500 dark:text-zinc-400' }, 'You’ll see what the agent can do there, why, and buttons to change it.'));
    return;
  }
  const d = n.data; const s = STATUS[d.status] || STATUS.blocked;
  const parts = [
    el('div', { class: 'flex items-center gap-2' }, icon(d.kind === 'symlink' ? 'link' : d.is_dir ? 'folder' : 'file', 'h-5 w-5 text-zinc-400'), el('div', { class: 'min-w-0 truncate font-mono text-sm font-semibold' }, d.display)),
    el('div', { class: 'mt-1 break-all font-mono text-[11px] text-zinc-500 dark:text-zinc-400' }, tilde(d.path)),
    d.link_target ? el('div', { class: 'mt-1 font-mono text-[11px] text-zinc-500' }, 'Points to ' + tilde(d.link_target)) : null,
    el('div', { class: 'mt-4 flex items-center gap-2 rounded-xl border-2 px-3 py-2 ' + s.ring }, el('span', { class: 'h-3 w-3 rounded-full ' + s.dot }), el('span', { class: 'font-semibold ' + s.text }, s.label)),
    el('div', { class: 'mt-4 space-y-2' }, explain('Reading', d.read), explain('Changing', d.write)),
    d.inner_rules ? el('p', { class: 'mt-3 rounded-lg bg-zinc-100 p-2.5 text-xs text-zinc-600 dark:bg-white/5 dark:text-zinc-300' }, [d.inner_allow ? d.inner_allow + ' rule(s) allow things inside' : null, d.inner_deny ? d.inner_deny + ' rule(s) block things inside' : null].filter(Boolean).join(', ') + ' — open the folder to see them.') : null,
    d.builtin_lock ? el('p', { class: 'mt-3 flex items-start gap-2 rounded-lg bg-amber-500/10 p-2.5 text-xs text-amber-800 dark:text-amber-200' }, icon('lock', 'mt-0.5 h-3.5 w-3.5'), 'AgentFence protects this by default. You can add rules, but a built-in block always wins.') : null];
  box.append(...parts.filter(Boolean));
  const acts = el('div', { class: 'mt-5 grid grid-cols-2 gap-2' });
  const A = [['allow_read', 'Let it read', 'check', 'border-emerald-500/40 text-emerald-700 hover:bg-emerald-500/10 dark:text-emerald-300'], ['allow_write', 'Let it change', 'check', 'border-emerald-500/40 text-emerald-700 hover:bg-emerald-500/10 dark:text-emerald-300'],
    ['deny_read', 'Block reading', 'ban', 'border-rose-500/40 text-rose-700 hover:bg-rose-500/10 dark:text-rose-300'], ['deny_write', 'Block changes', 'ban', 'border-rose-500/40 text-rose-700 hover:bg-rose-500/10 dark:text-rose-300']];
  for (const [k, label, ic, cls] of A) {
    const a = d.actions[k];
    acts.appendChild(el('button', { class: 'inline-flex items-center justify-center gap-1.5 rounded-lg border px-3 py-2 text-sm font-medium transition disabled:cursor-not-allowed disabled:opacity-30 ' + cls, disabled: !!a.unavailable || readonly(), title: a.unavailable || ('Adds: ' + a.display), onclick: () => addRule(a) }, icon(ic, 'h-4 w-4'), label));
  }
  box.append(el('div', { class: 'label mt-6' }, 'Change access'), acts,
    el('p', { class: 'mt-2 text-[11px] text-zinc-500 dark:text-zinc-400' }, S.scope === 'project' ? 'Editing this project’s rules (they can only take access away).' : 'Editing your rules (all projects). Nothing is saved until you review.'));
}
async function addRule(a) {
  const ok = await dialog({ title: 'Add this rule?', body: [el('code', { class: 'mt-2 block rounded-lg bg-zinc-100 px-3 py-2 dark:bg-white/5' }, a.display), 'It’s added to your unsaved changes. Review & save when you’re ready.'], okText: 'Add rule' });
  if (!ok) return;
  if (S.mode !== 'structured') await switchMode('structured');
  ensureDoc();
  const [grp, key] = a.section.split('.');
  const list = (S.doc[grp][key] = S.doc[grp][key] || []);
  if (!list.some(r => r.pattern === a.rule)) list.push({ kind: 'path', pattern: a.rule, except: [], id: null, reason: null });
  markDirty(); renderStructured();
  toast('Rule added to your changes — the map now shows the result.', 'info');
  if (S.tab === 'map') loadMap();
}

// ------------------------------------------------------------------ rules
const readonly = () => !!(S.loaded && S.loaded.trusted);
async function loadPolicy(resetDraft = true) {
  const q = new URLSearchParams({ scope: S.scope, project: S.project, agent: S.agent });
  const { data } = await api('GET', '/api/policy?' + q);
  if (data.error && !data.yaml) { toast(data.error, 'err'); return; }
  S.loaded = data;
  if (resetDraft) { S.doc = data.doc; S.yaml = data.yaml; S.dirty = false; }
  const meta = $('policy-meta'); clear(meta);
  meta.append(el('span', { class: data.exists ? 'badge-allow' : 'badge-neutral' }, data.exists ? 'Saved file' : 'No file yet'), el('code', { class: 'text-xs' }, tilde(data.file)));
  if (!data.exists && S.scope === 'user') meta.appendChild(el('div', { class: 'w-full rounded-xl border border-brand-500/20 bg-brand-500/5 p-3 text-xs text-zinc-600 dark:text-zinc-300' }, 'You’re starting from the built-in defaults (the project is readable and writable; everything else is blocked). Saving creates your own rules file, which then replaces those defaults.'));
  $('policy-readonly').classList.toggle('hidden', !readonly());
  $('yaml').readOnly = readonly();
  if (data.error) toast(data.error, 'err');
  S.effective = data.effective; S.rulesPage = 1; renderEffective();
  renderStructured(); $('yaml').value = S.yaml; updateSavebar();
}
function renderEffective() {
  const eff = S.effective;
  const w = $('warnings'); clear(w);
  const body = $('rules'); clear(body);
  if (!eff) return;
  for (const x of eff.warnings || []) w.appendChild(el('div', { class: 'badge-ask max-w-xl whitespace-normal text-left' }, icon('alert', 'h-3 w-3'), x));
  $('rules-count').textContent = eff.rules.length + ' rules';
  const size = 25, pages = Math.max(1, Math.ceil(eff.rules.length / size));
  S.rulesPage = Math.min(S.rulesPage, pages);
  for (const r of eff.rules.slice((S.rulesPage - 1) * size, S.rulesPage * size)) {
    const enf = r.enforceability === 'observed' ? el('span', { class: 'badge-observed' }, 'Logged only') : r.enforceability === 'enforced-coarse' ? el('span', { class: 'badge-neutral' }, 'Enforced (by program name)') : el('span', { class: 'badge-neutral' }, icon('shield', 'h-3 w-3'), 'Enforced by macOS');
    body.appendChild(el('tr', {},
      el('td', { class: 'td text-xs text-zinc-500 dark:text-zinc-400' }, r.policy.startsWith('provider:') ? agentName(r.policy.slice(9)) + ' needs' : (RULE_WORDS[r.policy] || r.policy)),
      el('td', { class: 'td font-mono text-xs' }, r.id),
      el('td', { class: 'td' }, resultBadge(r.effect), el('div', { class: 'mt-1 text-[11px] text-zinc-400' }, r.section)),
      el('td', { class: 'td' }, el('div', { class: 'mono' }, r.pattern), r.excepts.length ? el('div', { class: 'mt-0.5 text-[11px] text-zinc-400' }, 'except ' + r.excepts.length + ' pattern(s)') : null),
      el('td', { class: 'td' }, enf)));
  }
  const pg = $('rules-pager');
  pagerInto(pg, S.rulesPage, pages, eff.rules.length, size, (p) => { S.rulesPage = Math.min(Math.max(1, p), pages); renderEffective(); }, null);
  pg.className = 'flex flex-wrap items-center justify-between gap-3 border-t border-zinc-200 px-5 py-3 text-sm dark:border-white/10';
}

const SECTIONS = [
  ['filesystem', 'allow_read', 'Folders & files it can read', 'Add paths the agent may look at.', 'path', true, 'allow', '${PROJECT}/**'],
  ['filesystem', 'allow_write', 'Folders & files it can change', 'Add paths the agent may create, edit or delete in.', 'path', true, 'allow', '${PROJECT}/**'],
  ['filesystem', 'deny_read', 'Never let it read', 'Always blocked — even if another rule allows it.', 'path', false, 'deny', '${PROJECT}/secrets/**'],
  ['filesystem', 'deny_write', 'Never let it change', 'Always blocked, including moving and deleting.', 'path', false, 'deny', '${HOME}/.config/**'],
  ['network', 'allow', 'Websites & servers it can reach', 'Everything not listed here is blocked.', 'host', true, 'allow', 'api.github.com'],
  ['network', 'deny', 'Never let it connect to', 'Blocked even if another rule allows it.', 'host', false, 'deny', 'evil.example.com'],
  ['network', 'listen', 'Local ports it can open (dev servers)', 'Only on this Mac, e.g. localhost:3000.', 'host', true, 'allow', 'localhost:3000'],
  ['process', 'deny', 'Programs it can never run', 'Blocked by program name.', 'command', false, 'deny', 'terraform'],
  ['process', 'require_approval', 'Commands to flag for approval', 'Logged and highlighted today; not blocked yet.', 'command', false, 'ask', 'git push *'],
];
function ensureDoc() {
  if (!S.doc) S.doc = { name: S.scope, layer: S.scope, match_: null, defaults: {}, filesystem: {}, process: {}, network: {}, builtin: null };
  for (const k of ['filesystem', 'process', 'network']) S.doc[k] = S.doc[k] || {};
  S.doc.defaults = S.doc.defaults || {};
}
function renderStructured() {
  const root = $('sub-structured'); clear(root);
  if (!S.doc) { root.appendChild(el('div', { class: 'card p-6 text-sm text-rose-600 xl:col-span-2' }, 'The YAML file has a mistake, so it can’t be shown here. Fix it in the YAML tab.')); return; }
  ensureDoc(); const ro = readonly();
  const defs = el('div', { class: 'card p-5 xl:col-span-2' },
    el('h3', { class: 'font-semibold' }, 'When nothing below matches'),
    el('p', { class: 'mt-1 text-xs text-zinc-500 dark:text-zinc-400' }, 'Secrets, git settings and AgentFence itself stay protected no matter what you pick.'));
  const row = el('div', { class: 'mt-4 grid gap-4 sm:grid-cols-3' });
  const DEF_LABELS = { filesystem: 'Other files', network: 'Other websites', process: 'Other programs' };
  for (const cat of ['filesystem', 'network', 'process']) {
    const sel = el('select', { class: 'select', disabled: ro, onchange: (e) => { S.doc.defaults[cat] = e.target.value || null; markDirty(); } },
      el('option', { value: '' }, 'Use the built-in default'),
      S.scope === 'project' ? null : el('option', { value: 'allow' }, 'Allow'),
      el('option', { value: 'ask' }, 'Needs approval'),
      el('option', { value: 'deny' }, 'Block'));
    sel.value = S.doc.defaults[cat] || '';
    row.appendChild(el('label', {}, el('span', { class: 'label' }, DEF_LABELS[cat]), sel));
  }
  defs.appendChild(row); root.appendChild(defs);
  for (const [grp, key, title, help, kind, isAllow, tone, ph] of SECTIONS) {
    if (S.scope === 'project' && isAllow) continue;
    const list = (S.doc[grp][key] = S.doc[grp][key] || []);
    const dot = { allow: 'bg-emerald-500', deny: 'bg-rose-500', ask: 'bg-amber-500' }[tone];
    const card = el('div', { class: 'card flex flex-col p-5' },
      el('div', { class: 'flex items-center gap-2' }, el('span', { class: 'h-2 w-2 rounded-full ' + dot }), el('h3', { class: 'font-semibold' }, title), el('span', { class: 'badge-neutral' }, String(list.length))),
      el('p', { class: 'mt-1 text-xs text-zinc-500 dark:text-zinc-400' }, help));
    const chips = el('div', { class: 'mt-4 flex flex-wrap gap-2' });
    if (!list.length) chips.appendChild(el('span', { class: 'text-xs italic text-zinc-400' }, 'Nothing yet'));
    list.forEach((r, i) => {
      chips.appendChild(el('span', { class: 'chip', title: r.reason || '' }, el('span', { class: 'truncate' }, r.pattern),
        ro ? null : el('button', { class: 'rounded p-0.5 text-zinc-400 hover:bg-rose-500/10 hover:text-rose-600', title: 'Remove', onclick: () => { list.splice(i, 1); markDirty(); renderStructured(); } }, icon('x', 'h-3.5 w-3.5'))));
    });
    card.appendChild(chips);
    if (!ro) {
      const add = el('input', { class: 'input font-mono', placeholder: 'e.g. ' + ph });
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
  if (mode === 'structured' && !data.doc) { toast('The YAML has a mistake — fix it before switching. ' + (data.error || ''), 'err'); return; }
  if (data.yaml) S.yaml = data.yaml;
  if (data.doc) S.doc = data.doc;
  S.mode = mode;
  document.querySelectorAll('#mode-seg .seg-btn').forEach(b => b.classList.toggle('on', b.dataset.mode === mode));
  $('sub-structured').classList.toggle('hidden', mode !== 'structured'); $('sub-yaml').classList.toggle('hidden', mode !== 'yaml');
  $('yaml').value = S.yaml; renderStructured();
}
function draftBody() {
  const b = { scope: S.scope, project: S.project, agent: S.agent };
  if (S.dirty) { if (S.mode === 'structured') b.doc = S.doc; else b.yaml = S.yaml; }
  return b;
}

function closeDrawer() { $('drawer').classList.add('hidden'); }
async function preview() {
  const body = { scope: S.scope, project: S.project, agent: S.agent };
  if (S.mode === 'structured') body.doc = S.doc; else body.yaml = S.yaml;
  const { data } = await api('POST', '/api/policy/preview', body);
  $('drawer-file').textContent = 'Saves to ' + tilde(S.loaded.file);
  const errs = $('d-errors'); clear(errs);
  if (!data.ok) errs.appendChild(el('div', { class: 'rounded-xl border border-rose-500/30 bg-rose-500/10 p-4 text-sm' },
    el('div', { class: 'flex items-center gap-2 font-semibold text-rose-700 dark:text-rose-300' }, icon('alert'), 'These rules can’t be saved yet'),
    el('div', { class: 'mt-2 whitespace-pre-wrap font-mono text-xs text-rose-700 dark:text-rose-200' }, data.error || 'Invalid rules')));
  $('save').disabled = !data.ok;
  const w = $('d-warnings'); clear(w);
  if (data.comments_lost) w.appendChild(el('div', { class: 'badge-ask whitespace-normal' }, 'Comments in the current file won’t be kept (a backup copy is saved).'));
  for (const x of (data.effective && data.effective.warnings) || []) w.appendChild(el('div', { class: 'badge-ask whitespace-normal' }, x));
  const unread = !!(data.effective && data.effective.project_unreadable);
  const cw = $('d-confirm-wrap'); cw.classList.toggle('hidden', !unread); cw.classList.toggle('flex', unread); $('d-confirm').checked = false;
  const ed = $('d-effective'); clear(ed);
  if (data.effective_diff) {
    const rowOf = (txt, add) => el('div', { class: 'flex items-start gap-2 rounded-lg px-3 py-2 font-mono text-xs ' + (add ? 'bg-emerald-500/10 text-emerald-800 dark:text-emerald-200' : 'bg-rose-500/10 text-rose-800 dark:text-rose-200') }, el('span', { class: 'font-bold' }, add ? '+' : '−'), el('span', { class: 'break-all' }, txt));
    data.effective_diff.added.forEach(a => ed.appendChild(rowOf(a, true)));
    data.effective_diff.removed.forEach(r => ed.appendChild(rowOf(r, false)));
    if (!data.effective_diff.added.length && !data.effective_diff.removed.length) ed.appendChild(el('div', { class: 'text-sm text-zinc-500' }, 'Nothing changes for agents.'));
  }
  const fd = $('d-diff'); clear(fd);
  for (const l of data.file_diff || []) fd.appendChild(el('div', { class: l.op === '+' ? 'bg-emerald-500/15 text-emerald-300' : l.op === '-' ? 'bg-rose-500/15 text-rose-300' : '' }, (l.op === ' ' ? '  ' : l.op + ' ') + l.line));
  $('drawer').classList.remove('hidden');
}
async function save() {
  const body = { scope: S.scope, project: S.project, agent: S.agent };
  if (S.mode === 'structured') body.doc = S.doc; else body.yaml = S.yaml;
  body.base_sha256 = S.loaded.sha256;
  if ($('d-confirm').checked) body.confirm = ['project-unreadable'];
  $('save').disabled = true;
  const { status, data } = await api('POST', '/api/policy/save', body);
  $('save').disabled = false;
  if (data.ok) {
    closeDrawer();
    const n = (data.affected_sessions || []).length;
    toast(n ? 'Saved. ' + n + ' running agent(s) use these rules — relaunch them on the Overview to apply.' : 'Saved. Agents started from now on use these rules.');
    await loadPolicy(); refreshSessions(); S.map.loadedFor = '';
    if (n) go('sessions'); else if (S.tab === 'map') loadMap();
  } else if (data.needs_confirm) {
    const cw = $('d-confirm-wrap'); cw.classList.remove('hidden'); cw.classList.add('flex');
    toast(data.error, 'err');
  } else if (data.conflict) {
    toast(data.error, 'err');
    const fd = $('d-diff'); clear(fd);
    fd.appendChild(el('div', { class: 'text-amber-300' }, '# The file changed on disk since you opened it. Current version:'));
    fd.appendChild(el('div', {}, data.current_yaml || '(deleted)'));
    S.loaded.sha256 = data.current_sha256;
  } else {
    toast(data.error || ('Save failed (' + status + ')'), 'err');
  }
}

// ------------------------------------------------------------------ check access
async function testRequest() {
  const v = $('t-value').value.trim();
  if (!v) return;
  const kind = $('t-kind').value;
  const val = v.startsWith('~') ? S.overview.home + v.slice(1) : v;
  const req = ['read', 'write', 'rename'].includes(kind) ? { kind: 'path', path: val, action: kind } : kind === 'exec' ? { kind, command: val } : { kind, host: val };
  const body = draftBody(); body.request = req;
  const { data } = await api('POST', '/api/evaluate', body);
  const out = $('t-result'); clear(out);
  if (data.error) { out.appendChild(el('div', { class: 'card border-rose-500/30 p-5 text-sm text-rose-600' }, data.error)); return; }
  const allowed = data.effect === 'allow';
  const tone = allowed ? ['from-emerald-500/20', 'text-emerald-600 dark:text-emerald-400'] : data.effect === 'ask' ? ['from-amber-500/20', 'text-amber-600 dark:text-amber-400'] : ['from-rose-500/20', 'text-rose-600 dark:text-rose-400'];
  out.appendChild(el('div', { class: 'card relative overflow-hidden p-6' },
    el('div', { class: 'absolute inset-0 bg-gradient-to-br to-transparent ' + tone[0] }),
    el('div', { class: 'relative flex items-start gap-4' },
      el('div', { class: 'grid h-12 w-12 place-items-center rounded-2xl bg-white/80 shadow-sm dark:bg-white/5 ' + tone[1] }, icon(allowed ? 'check' : data.effect === 'ask' ? 'alert' : 'ban', 'h-6 w-6')),
      el('div', { class: 'min-w-0' },
        el('div', { class: 'text-2xl font-semibold tracking-tight ' + tone[1] }, allowed ? 'Yes, allowed' : data.effect === 'ask' ? 'Needs approval' : 'No, blocked'),
        el('div', { class: 'mt-1 text-sm text-zinc-600 dark:text-zinc-300' }, data.reason),
        el('div', { class: 'mt-3 text-xs text-zinc-500 dark:text-zinc-400' }, 'Decided by: ' + whyText(data))))));
}

bootstrap().catch(e => { if (String(e) !== 'Error: unauthorized') toast('Error: ' + e, 'err'); });
