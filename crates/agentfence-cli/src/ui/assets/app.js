// AgentFence local UI. All dynamic text goes through textContent (never
// innerHTML). The bearer token lives only in this variable.
'use strict';

let TOKEN = null;
const S = {
  overview: null,
  scope: 'user', project: '', agent: 'claude-code',
  loaded: null,          // server's GET /api/policy
  doc: null,             // structured draft (RawDoc JSON)
  yaml: '',              // YAML draft
  mode: 'structured',    // which editor is the source of truth
  dirty: false,
  lastRow: 0,
  fsPath: '',
};

// ---------- helpers ----------
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
function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }
function banner(msg, ok) {
  const b = $('banner'); b.textContent = msg; b.className = 'banner' + (ok ? ' ok' : ''); b.hidden = !msg;
  if (ok) setTimeout(() => { if (b.textContent === msg) b.hidden = true; }, 5000);
}
function pill(effect, enforcement) {
  if (!effect) return el('span', { class: 'muted' }, '—');
  if (enforcement === 'observed' && effect !== 'allow') return el('span', { class: 'pill observed' }, 'OBSERVED — not blocked');
  const label = { deny: enforcement === 'enforced' ? 'BLOCKED' : 'DENY', allow: 'ALLOW', ask: enforcement === 'enforced' ? 'BLOCKED (approval)' : 'ASK' }[effect] || effect;
  return el('span', { class: 'pill ' + effect }, label);
}

async function api(method, path, body) {
  const opts = { method, headers: { 'Authorization': 'Bearer ' + TOKEN } };
  if (body !== undefined) { opts.headers['Content-Type'] = 'application/json'; opts.body = JSON.stringify(body); }
  const r = await fetch(path, opts);
  let data = null;
  try { data = await r.json(); } catch (_) { data = { error: 'bad response' }; }
  if (r.status === 401) { banner('Session expired. Press Enter in the `agentfence ui` terminal for a new link.'); throw new Error('unauthorized'); }
  return { status: r.status, data };
}

// ---------- bootstrap ----------
async function bootstrap() {
  const m = /code=([0-9a-f]+)/.exec(location.hash);
  history.replaceState(null, '', '/');
  if (!m) { banner('Open the UI with the link printed by `agentfence ui` (press Enter there for a new one).'); return; }
  const r = await fetch('/api/session', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ code: m[1] }) });
  const d = await r.json().catch(() => ({}));
  if (!r.ok || !d.token) { banner(d.error || 'Could not start the session.'); return; }
  TOKEN = d.token;
  const ov = await api('GET', '/api/overview');
  S.overview = ov.data;
  $('who').textContent = '· ' + ov.data.human;
  const proj = $('project'); clear(proj);
  for (const p of ov.data.projects) proj.appendChild(el('option', { value: p }, p.replace(ov.data.home, '~')));
  proj.appendChild(el('option', { value: '__other__' }, 'Other…'));
  S.project = ov.data.projects[0] || '';
  const ag = $('agent'); clear(ag);
  for (const a of ov.data.agents) ag.appendChild(el('option', { value: a.id }, a.name));
  wire();
  await loadPolicy();
  refreshSessions(); pollEvents();
  setInterval(refreshSessions, 3000); setInterval(pollEvents, 1500);
}

// ---------- tabs ----------
function wire() {
  document.querySelectorAll('nav .tab').forEach(b => b.addEventListener('click', () => {
    document.querySelectorAll('nav .tab').forEach(x => x.classList.toggle('active', x === b));
    for (const t of ['sessions', 'policy', 'files', 'test']) $('tab-' + t).hidden = (b.dataset.tab !== t);
    if (b.dataset.tab === 'files') listDir(S.fsPath || S.project);
  }));
  document.querySelectorAll('.subtab').forEach(b => b.addEventListener('click', () => switchMode(b.dataset.sub)));
  $('scope').addEventListener('change', async (e) => { if (await confirmDiscard()) { S.scope = e.target.value; loadPolicy(); } else e.target.value = S.scope; });
  $('agent').addEventListener('change', (e) => { S.agent = e.target.value; loadPolicy(false); });
  $('project').addEventListener('change', async (e) => {
    let v = e.target.value;
    if (v === '__other__') { v = window.prompt('Project directory (absolute path):', S.project) || S.project; }
    if (await confirmDiscard()) { S.project = v; S.fsPath = ''; loadPolicy(); }
  });
  $('reload').addEventListener('click', async () => { if (await confirmDiscard()) loadPolicy(); });
  $('yaml').addEventListener('input', () => { S.yaml = $('yaml').value; markDirty(); });
  $('preview').addEventListener('click', preview);
  $('cancel-preview').addEventListener('click', () => { $('preview-pane').hidden = true; });
  $('save').addEventListener('click', save);
  $('up').addEventListener('click', () => { if (S.fsParent) listDir(S.fsParent); });
  $('fs-go').addEventListener('click', () => listDir($('fs-path').value));
  $('t-go').addEventListener('click', testRequest);
}
async function confirmDiscard() { return !S.dirty || window.confirm('Discard unsaved policy changes?'); }
function markDirty() { S.dirty = true; $('dirty').textContent = 'Unsaved changes'; }

// ---------- policy ----------
function readonly() { return S.loaded && S.loaded.trusted; }
async function loadPolicy(resetDraft = true) {
  const q = new URLSearchParams({ scope: S.scope, project: S.project, agent: S.agent });
  const { data } = await api('GET', '/api/policy?' + q);
  if (data.error && !data.yaml) { banner(data.error); return; }
  S.project = data.project || S.project;
  S.loaded = data;
  if (resetDraft) { S.doc = data.doc; S.yaml = data.yaml; S.dirty = false; $('dirty').textContent = ''; }
  const meta = $('policy-meta'); clear(meta);
  meta.appendChild(el('span', {}, (data.exists ? 'Editing ' : 'Not created yet — will create ') , el('code', {}, data.file)));
  if (!data.exists && S.scope === 'user') meta.appendChild(el('div', { class: 'warn' }, 'Starting from the built-in default. Saving a user policy replaces the default, so keep the project read/write rules unless you mean to remove them.'));
  $('policy-readonly').hidden = !readonly();
  $('preview').disabled = readonly();
  $('yaml').readOnly = readonly();
  if (data.error) banner(data.error); else banner('');
  renderEffective(data.effective);
  renderStructured(); $('yaml').value = S.yaml;
}

function renderEffective(eff) {
  const w = $('warnings'); clear(w);
  const body = $('rules-body'); clear(body);
  if (!eff) return;
  for (const x of eff.warnings || []) w.appendChild(el('div', { class: 'warn' }, '⚠ ' + x));
  for (const r of eff.rules) {
    body.appendChild(el('tr', {}, el('td', {}, r.policy), el('td', {}, r.id), el('td', {}, r.section),
      el('td', {}, pill(r.effect)), el('td', { class: 'path' }, r.pattern + (r.excepts.length ? '  (except ' + r.excepts.length + ')' : '')),
      el('td', {}, r.enforceability === 'observed' ? el('span', { class: 'pill observed' }, 'observed only') : r.enforceability)));
  }
}

const SECTIONS = [
  ['filesystem', 'allow_read', 'Agents may read', 'path', true],
  ['filesystem', 'allow_write', 'Agents may write', 'path', true],
  ['filesystem', 'deny_read', 'Agents may never read', 'path', false],
  ['filesystem', 'deny_write', 'Agents may never write', 'path', false],
  ['process', 'deny', 'Never run (command pattern)', 'command', false],
  ['process', 'require_approval', 'Needs approval (observed only today)', 'command', false],
  ['process', 'allow', 'Allowed commands', 'command', true],
  ['network', 'allow', 'Hosts agents may reach', 'host', true],
  ['network', 'deny', 'Hosts never reachable', 'host', false],
  ['network', 'listen', 'Local ports agents may listen on (localhost:PORT)', 'host', true],
];

function ensureDoc() {
  if (!S.doc) S.doc = { name: S.scope, layer: S.scope, match_: null, defaults: {}, filesystem: {}, process: {}, network: {}, builtin: null };
  for (const k of ['filesystem', 'process', 'network']) S.doc[k] = S.doc[k] || {};
  S.doc.defaults = S.doc.defaults || {};
}

function renderStructured() {
  const root = $('sub-structured'); clear(root);
  if (!S.doc) { root.appendChild(el('div', { class: 'error' }, 'This YAML cannot be shown as rules (it has errors). Fix it in the YAML tab.')); return; }
  ensureDoc();
  const ro = readonly();
  const defs = el('div', { class: 'section' }, el('h4', {}, 'Defaults (when no rule matches)'));
  const row = el('div', { class: 'defaults' });
  for (const cat of ['filesystem', 'network', 'process']) {
    const sel = el('select', { disabled: ro, onchange: (e) => { S.doc.defaults[cat] = e.target.value || null; markDirty(); } },
      el('option', { value: '' }, '(not set)'), ...['allow', 'ask', 'deny'].map(v => el('option', { value: v }, v)));
    sel.value = S.doc.defaults[cat] || '';
    row.appendChild(el('label', {}, cat + ' ', sel));
  }
  defs.appendChild(row); root.appendChild(defs);
  for (const [grp, key, title, kind, isAllow] of SECTIONS) {
    if (S.scope === 'project' && isAllow) continue; // restrict-only
    const list = (S.doc[grp][key] = S.doc[grp][key] || []);
    const sec = el('div', { class: 'section' }, el('h4', {}, title + '  ', el('span', { class: 'muted' }, grp + '.' + key)));
    list.forEach((r, i) => {
      const inp = el('input', { class: 'pat', value: r.pattern, disabled: ro, oninput: (e) => { r.pattern = e.target.value; markDirty(); } });
      const extra = [r.id ? 'id ' + r.id : null, r.except && r.except.length ? r.except.length + ' exceptions' : null].filter(Boolean).join(', ');
      sec.appendChild(el('div', { class: 'rule-row' }, inp, extra ? el('span', { class: 'muted' }, extra) : null,
        el('button', { class: 'small', disabled: ro, onclick: () => { list.splice(i, 1); markDirty(); renderStructured(); } }, 'Remove')));
    });
    if (!ro) {
      const add = el('input', { class: 'pat', placeholder: kind === 'path' ? '${PROJECT}/docs/**' : kind === 'command' ? 'terraform apply *' : 'api.example.com' });
      sec.appendChild(el('div', { class: 'rule-row' }, add, el('button', { class: 'small', onclick: () => {
        if (!add.value.trim()) return;
        list.push({ kind, pattern: add.value.trim(), except: [], id: null, reason: null }); markDirty(); renderStructured();
      } }, 'Add')));
    }
    root.appendChild(sec);
  }
}

async function switchMode(mode) {
  if (mode === S.mode) return;
  // Convert through the server so both views reflect the same bytes.
  const body = { scope: S.scope, project: S.project, agent: S.agent };
  if (S.mode === 'structured') body.doc = S.doc; else body.yaml = S.yaml;
  const { data } = await api('POST', '/api/policy/preview', body);
  if (mode === 'structured' && !data.doc) { banner('The YAML has errors; fix them before switching to Rules. ' + (data.error || '')); return; }
  if (data.yaml) S.yaml = data.yaml;
  if (data.doc) S.doc = data.doc;
  S.mode = mode;
  document.querySelectorAll('.subtab').forEach(x => x.classList.toggle('active', x.dataset.sub === mode));
  $('sub-structured').hidden = mode !== 'structured'; $('sub-yaml').hidden = mode !== 'yaml';
  $('yaml').value = S.yaml; renderStructured();
}

function draftBody() {
  const b = { scope: S.scope, project: S.project, agent: S.agent };
  if (S.mode === 'structured') b.doc = S.doc; else b.yaml = S.yaml;
  return b;
}

async function preview() {
  const { data } = await api('POST', '/api/policy/preview', draftBody());
  const pane = $('preview-pane'); pane.hidden = false;
  const errs = $('preview-errors'); errs.textContent = data.ok ? '' : (data.error || 'Invalid policy');
  $('save').disabled = !data.ok;
  const w = $('preview-warnings'); clear(w);
  if (data.comments_lost) w.appendChild(el('div', { class: 'warn' }, '⚠ Comments in the existing file will not be kept (a .bak backup is written).'));
  for (const x of (data.effective && data.effective.warnings) || []) w.appendChild(el('div', { class: 'warn' }, '⚠ ' + x));
  const unread = data.effective && data.effective.project_unreadable;
  $('confirm-unreadable-wrap').hidden = !unread; $('confirm-unreadable').checked = false;
  const ed = $('effective-diff'); clear(ed);
  if (data.effective_diff) {
    for (const a of data.effective_diff.added) ed.appendChild(el('div', { class: 'diff add' }, '+ ' + a));
    for (const r of data.effective_diff.removed) ed.appendChild(el('div', { class: 'diff del' }, '− ' + r));
    if (!data.effective_diff.added.length && !data.effective_diff.removed.length) ed.appendChild(el('div', { class: 'muted' }, 'No change in effective rules.'));
  }
  const fd = $('file-diff'); clear(fd);
  for (const l of data.file_diff || []) fd.appendChild(el('div', { class: l.op === '+' ? 'add' : l.op === '-' ? 'del' : '' }, l.op + ' ' + l.line));
  if (data.effective) renderEffective(data.effective);
  pane.scrollIntoView({ behavior: 'smooth' });
}

async function save() {
  const body = draftBody();
  body.base_sha256 = S.loaded.sha256;
  if ($('confirm-unreadable').checked) body.confirm = ['project-unreadable'];
  const { status, data } = await api('POST', '/api/policy/save', body);
  if (data.ok) {
    $('preview-pane').hidden = true;
    const n = (data.affected_sessions || []).length;
    banner('Saved. ' + (n ? n + ' running session(s) use this policy — relaunch them from Sessions to apply it.' : 'It applies to agents launched from now on.'), true);
    await loadPolicy(); refreshSessions();
  } else if (data.needs_confirm) {
    $('confirm-unreadable-wrap').hidden = false; $('preview-errors').textContent = data.error;
  } else if (data.conflict) {
    $('preview-errors').textContent = data.error;
    const fd = $('file-diff'); clear(fd);
    fd.appendChild(el('div', { class: 'muted' }, '— current file on disk —'));
    fd.appendChild(el('div', {}, data.current_yaml || '(deleted)'));
    S.loaded.sha256 = data.current_sha256; // saving again overwrites that version, deliberately
  } else {
    $('preview-errors').textContent = data.error || ('Save failed (' + status + ')');
  }
}

// ---------- sessions & events ----------
async function refreshSessions() {
  if (!TOKEN) return;
  const { data } = await api('GET', '/api/sessions');
  const body = $('sessions-body'); clear(body);
  if (!data.sessions.length) body.appendChild(el('tr', {}, el('td', { colspan: 6, class: 'muted' }, 'No supervised agents. Start one with `agentfence run -- claude`.')));
  const home = S.overview.home;
  for (const s of data.sessions) {
    const status = s.stale === true ? el('span', { class: 'pill stale' }, 'policy changed — relaunch to apply') : s.stale === 'unknown' ? el('span', { class: 'muted' }, 'unknown') : el('span', { class: 'pill allow' }, 'current');
    const btn = el('button', { class: 'small', disabled: !s.restartable, title: s.restartable ? '' : 'Started by an older agentfence; restart it manually', onclick: async () => {
      if (!window.confirm('Relaunch ' + s.agent_name + ' under the current policy? Claude Code resumes its conversation.')) return;
      const { data } = await api('POST', '/api/sessions/restart', { session: s.session });
      banner(data.ok ? 'Relaunch requested. ' + data.note : data.error, !!data.ok);
    } }, 'Relaunch');
    body.appendChild(el('tr', {}, el('td', {}, s.agent_name || s.agent), el('td', {}, String(s.pid || '')),
      el('td', { class: 'path' }, (s.project || '').replace(home, '~')), el('td', {}, s.policy || ''), el('td', {}, status), el('td', {}, btn)));
  }
}

async function pollEvents() {
  if (!TOKEN) return;
  const { data } = await api('GET', '/api/events?limit=200&after=' + S.lastRow);
  const body = $('events-body');
  for (const e of data.events) {
    S.lastRow = Math.max(S.lastRow, e.rowid);
    const rule = e.policy ? e.policy + '/' + e.rule_id : '';
    const tr = el('tr', { title: e.reason_display || '' }, el('td', {}, (e.timestamp || '').slice(11, 19)), el('td', {}, e.agent),
      el('td', {}, e.action), el('td', { class: 'path' }, e.resource_display), el('td', {}, pill(e.decision, e.enforcement)), el('td', {}, rule));
    body.insertBefore(tr, body.firstChild);
  }
  while (body.children.length > 300) body.removeChild(body.lastChild);
}

// ---------- files ----------
async function listDir(path, force) {
  const body = draftBody(); body.path = path; body.force = !!force;
  const { data } = await api('POST', '/api/fs/list', body);
  if (data.error) { banner(data.error); return; }
  S.fsPath = data.path; S.fsParent = data.parent; $('fs-path').value = data.path;
  const note = $('fs-note');
  note.hidden = !data.needs_force && !data.truncated;
  clear(note);
  if (data.needs_force) note.appendChild(el('span', {}, 'macOS may ask for permission to list this folder. ', el('button', { class: 'small', onclick: () => listDir(path, true) }, 'List anyway')));
  else if (data.truncated) note.appendChild(el('span', {}, 'Showing the first 2000 entries.'));
  const tb = $('fs-body'); clear(tb);
  for (const e of data.entries) {
    const name = el('td', { class: 'path' });
    if (e.is_dir && e.kind !== 'symlink') name.appendChild(el('a', { href: '#', onclick: (ev) => { ev.preventDefault(); listDir(e.path); } }, '📁 ' + e.display));
    else name.appendChild(document.createTextNode((e.kind === 'symlink' ? '↪ ' : '📄 ') + e.display));
    if (e.link_target) name.appendChild(el('div', { class: 'muted' }, '→ ' + e.link_target));
    if (e.builtin_lock) name.appendChild(el('div', { class: 'lock' }, '🔒 protected by a built-in rule'));
    const acts = el('td', {});
    for (const [k, label] of [['allow_read', 'Allow read'], ['allow_write', 'Allow write'], ['deny_read', 'Deny read'], ['deny_write', 'Deny write']]) {
      const a = e.actions[k];
      acts.appendChild(el('button', { class: 'small', disabled: !!a.unavailable || readonly(), title: a.unavailable || ('Adds: ' + a.display), onclick: () => addRule(a) }, label));
      acts.appendChild(document.createTextNode(' '));
    }
    const dec = (d) => el('span', { title: d.policy + '/' + d.rule_id + ': ' + d.reason }, pill(d.effect));
    tb.appendChild(el('tr', {}, name, el('td', {}, dec(e.read)), el('td', {}, dec(e.write)), acts));
  }
}

async function addRule(a) {
  if (!window.confirm('Add this rule to your draft?\n\n' + a.section + ':  ' + a.display)) return;
  if (S.mode !== 'structured') await switchMode('structured');
  ensureDoc();
  const [grp, key] = a.section.split('.');
  const list = (S.doc[grp][key] = S.doc[grp][key] || []);
  if (!list.some(r => r.pattern === a.rule)) list.push({ kind: 'path', pattern: a.rule, except: [], id: null, reason: null });
  markDirty(); renderStructured();
  banner('Added to draft: ' + a.display + ' — review and save in the Policy tab.', true);
  listDir(S.fsPath);
}

// ---------- test ----------
async function testRequest() {
  const kind = $('t-kind').value, v = $('t-value').value.trim();
  if (!v) return;
  const req = kind === 'path' ? { kind, path: v, action: $('t-action').value } : kind === 'exec' ? { kind, command: v } : { kind, host: v };
  const body = draftBody(); body.request = req;
  const { data } = await api('POST', '/api/evaluate', body);
  const out = $('t-result'); clear(out);
  if (data.error) { out.appendChild(el('div', { class: 'error' }, data.error)); return; }
  out.appendChild(el('div', { class: 'result' }, el('div', { class: 'big' }, pill(data.effect)),
    el('div', {}, 'Rule: ', el('code', {}, data.policy + '/' + data.rule_id)), el('div', {}, data.reason),
    data.trace.length ? el('div', { class: 'muted' }, 'Matched: ' + data.trace.join('; ')) : null));
}

bootstrap().catch(e => { if (String(e) !== 'Error: unauthorized') banner('Error: ' + e); });
