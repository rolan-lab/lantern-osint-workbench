'use strict';
/* Lantern OSINT Workbench — core: utilities, UI primitives, state & storage, router. */

// ---------------------------------------------------------------- utilities
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const uid = () => Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
const nowISO = () => new Date().toISOString();
const plural = (n, w, p) => `${n} ${n === 1 ? w : (p || w + 's')}`;
const clamp = (v, a, b) => Math.max(a, Math.min(b, v));
const trunc = (s, n) => { s = String(s ?? ''); return s.length > n ? s.slice(0, n - 1) + '…' : s; };

function fmtUTC(iso, withSeconds = true) {
  if (!iso) return '';
  const d = new Date(iso);
  if (isNaN(d)) return String(iso);
  const s = d.toISOString().replace('T', ' ').replace(/\.\d{3}Z$/, 'Z');
  return withSeconds ? s : s.replace(/:\d\dZ$/, 'Z');
}
function fmtBytes(n) {
  if (!Number.isFinite(n)) return '';
  const u = ['B', 'KB', 'MB', 'GB']; let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(i ? 1 : 0)} ${u[i]}`;
}
function relTime(iso) {
  const d = (Date.now() - new Date(iso)) / 1000;
  if (!Number.isFinite(d)) return '';
  if (d < 60) return 'just now';
  if (d < 3600) return `${Math.floor(d / 60)}m ago`;
  if (d < 86400) return `${Math.floor(d / 3600)}h ago`;
  if (d < 86400 * 30) return `${Math.floor(d / 86400)}d ago`;
  return fmtUTC(iso).slice(0, 10);
}
function safeUrl(u) {
  try { const x = new URL(String(u).trim()); return (x.protocol === 'http:' || x.protocol === 'https:') ? x.href : null; }
  catch { return null; }
}
function debounce(fn, ms) { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; }
function download(filename, content, mime = 'text/plain') {
  const blob = content instanceof Blob ? content : new Blob([content], { type: mime + ';charset=utf-8' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob); a.download = filename;
  document.body.appendChild(a); a.click();
  setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 1500);
}
function slug(s) { return String(s || 'case').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 50) || 'case'; }
function csvCell(v) { const s = String(v ?? ''); return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s; }
function toCSV(rows) { return rows.map((r) => r.map(csvCell).join(',')).join('\r\n'); }
function readFileAs(file, how = 'text') {
  return new Promise((res, rej) => {
    const r = new FileReader();
    r.onload = () => res(r.result); r.onerror = () => rej(r.error);
    how === 'buffer' ? r.readAsArrayBuffer(file) : r.readAsText(file);
  });
}

async function copyText(t, quiet) {
  try { await navigator.clipboard.writeText(t); if (!quiet) toast('Copied to clipboard'); return true; }
  catch {
    const ta = document.createElement('textarea'); ta.value = t; ta.style.cssText = 'position:fixed;opacity:0';
    document.body.appendChild(ta); ta.select(); let ok = false;
    try { ok = document.execCommand('copy'); } catch { /* ignore */ }
    ta.remove(); if (!quiet) toast(ok ? 'Copied to clipboard' : 'Copy failed', ok ? '' : 'error'); return ok;
  }
}
function toast(msg, kind = '') {
  const el = document.createElement('div');
  el.className = 'toast ' + kind; el.textContent = msg;
  $('#toasts').appendChild(el);
  setTimeout(() => el.classList.add('out'), 2800);
  setTimeout(() => el.remove(), 3200);
}
function openUrl(u) {
  const s = safeUrl(u);
  if (!s) { toast('Blocked a non-http(s) link', 'error'); return false; }
  window.open(s, '_blank', 'noopener,noreferrer');
  return true;
}

// Drag-and-drop / click file picker on an element.
function fileDrop(el, onFiles, { multiple = true, accept = '' } = {}) {
  const input = document.createElement('input');
  input.type = 'file'; input.multiple = multiple; if (accept) input.accept = accept; input.hidden = true;
  el.appendChild(input);
  el.addEventListener('click', (e) => { if (e.target === input) return; input.click(); });
  input.addEventListener('change', () => { if (input.files.length) onFiles([...input.files]); input.value = ''; });
  el.addEventListener('dragover', (e) => { e.preventDefault(); el.classList.add('over'); });
  el.addEventListener('dragleave', () => el.classList.remove('over'));
  el.addEventListener('drop', (e) => { e.preventDefault(); el.classList.remove('over'); if (e.dataTransfer.files.length) onFiles([...e.dataTransfer.files]); });
}

// ---------------------------------------------------------------- icons
const ICONS = {
  dashboard: '<rect x="3" y="3" width="7" height="9" rx="1.5"/><rect x="14" y="3" width="7" height="5" rx="1.5"/><rect x="14" y="12" width="7" height="9" rx="1.5"/><rect x="3" y="16" width="7" height="5" rx="1.5"/>',
  entities: '<path d="M8 6h13M8 12h13M8 18h13"/><circle cx="4" cy="6" r="1"/><circle cx="4" cy="12" r="1"/><circle cx="4" cy="18" r="1"/>',
  graph: '<circle cx="6" cy="6" r="2.5"/><circle cx="18" cy="8" r="2.5"/><circle cx="9" cy="18" r="2.5"/><path d="M8.4 6.4l7.2 1.2M6.7 8.4l1.6 7.2M16.5 10.1l-5.8 6"/>',
  timeline: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
  evidence: '<path d="M12 3l8 3v6c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6z"/><path d="M9 12l2 2 4-4"/>',
  notes: '<path d="M4 20h4L19 9l-4-4L4 16z"/><path d="M13.5 6.5l4 4"/>',
  report: '<path d="M7 3h7l5 5v13H7z"/><path d="M14 3v5h5M10 13h6M10 17h6"/>',
  extractor: '<path d="M3 5h18l-7 8v6l-4 2v-8z"/>',
  pivot: '<circle cx="12" cy="12" r="9"/><path d="M15.5 8.5l-2 5-5 2 2-5z"/>',
  dorks: '<circle cx="11" cy="11" r="7"/><path d="M20 20l-4-4"/>',
  recon: '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="4.5"/><path d="M12 12l6.4-6.4"/>',
  metadata: '<rect x="3" y="4" width="18" height="16" rx="2"/><circle cx="9" cy="10" r="2"/><path d="M21 16l-5-5-9 9"/>',
  toolbox: '<path d="M14.7 6.3a4 4 0 0 0-5.4 5.4L3 18l3 3 6.3-6.3a4 4 0 0 0 5.4-5.4l-2.5 2.5-2.4-.6-.6-2.4z"/>',
  opsec: '<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>',
  settings: '<ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M4 5v14c0 1.7 3.6 3 8 3s8-1.3 8-3V5M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3"/>',
};
const icon = (name) => `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${ICONS[name] || ''}</svg>`;

// ---------------------------------------------------------------- modal & dialogs
function modal({ title, body, actions = [], wide = false, onClose, onMount }) {
  const wrap = document.createElement('div');
  wrap.className = 'modal-backdrop';
  wrap.innerHTML = `<div class="modal ${wide ? 'wide' : ''}" role="dialog" aria-modal="true" aria-label="${esc(title)}">
    <div class="modal-head"><h3>${esc(title)}</h3><button class="icon-btn" data-x aria-label="Close">✕</button></div>
    <div class="modal-body"></div><div class="modal-foot"></div></div>`;
  const bodyEl = $('.modal-body', wrap);
  if (typeof body === 'string') bodyEl.innerHTML = body; else if (body) bodyEl.appendChild(body);
  let closed = false;
  const close = () => {
    if (closed) return; closed = true;
    wrap.remove(); document.removeEventListener('keydown', onKey, true);
    onClose && onClose();
  };
  const onKey = (e) => { if (e.key === 'Escape') { e.stopPropagation(); close(); } };
  document.addEventListener('keydown', onKey, true);
  wrap.addEventListener('mousedown', (e) => { if (e.target === wrap) close(); });
  $('[data-x]', wrap).onclick = close;
  const foot = $('.modal-foot', wrap);
  actions.forEach((a) => {
    const b = document.createElement('button');
    b.className = 'btn ' + (a.kind || ''); b.textContent = a.label;
    b.onclick = async () => { const r = a.onClick ? await a.onClick(wrap) : undefined; if (r !== false) close(); };
    foot.appendChild(b);
  });
  if (!actions.length) foot.remove();
  $('#modalRoot').appendChild(wrap);
  onMount && onMount(wrap, close);
  const first = $('input:not([type=checkbox]),textarea,select', bodyEl);
  if (first) first.focus(); else $('.btn.primary', foot)?.focus();
  return { el: wrap, close };
}

function confirmDlg(message, { title = 'Confirm', ok = 'Confirm', danger = false } = {}) {
  return new Promise((res) => {
    let v = false;
    modal({
      title, body: `<p>${esc(message)}</p>`, onClose: () => res(v),
      actions: [{ label: 'Cancel', kind: 'ghost' }, { label: ok, kind: danger ? 'danger' : 'primary', onClick: () => { v = true; } }],
    });
  });
}

function fieldHtml(f) {
  const id = 'f_' + f.name + '_' + Math.random().toString(36).slice(2, 6);
  const v = f.value ?? '';
  let input;
  if (f.type === 'textarea') input = `<textarea id="${id}" name="${f.name}" rows="${f.rows || 4}" placeholder="${esc(f.placeholder || '')}">${esc(v)}</textarea>`;
  else if (f.type === 'select' || f.type === 'multiselect') {
    const multi = f.type === 'multiselect';
    const sel = multi ? new Set(v || []) : null;
    input = `<select id="${id}" name="${f.name}" ${multi ? `multiple size="${Math.min(8, Math.max(3, f.options.length))}"` : ''}>${f.options.map((o) => {
      const [val, lab] = Array.isArray(o) ? o : [o, o];
      const on = multi ? sel.has(val) : String(val) === String(v);
      return `<option value="${esc(val)}" ${on ? 'selected' : ''}>${esc(lab)}</option>`;
    }).join('')}</select>`;
  } else if (f.type === 'checkbox') {
    return `<label class="check field"><input type="checkbox" name="${f.name}" ${v ? 'checked' : ''}> ${esc(f.label)}</label>`;
  } else input = `<input id="${id}" name="${f.name}" type="${f.type || 'text'}" value="${esc(v)}" placeholder="${esc(f.placeholder || '')}" ${f.step ? `step="${f.step}"` : ''} spellcheck="false">`;
  return `<label class="field" for="${id}"><span>${esc(f.label)}${f.required ? ' *' : ''}</span>${input}${f.hint ? `<small>${esc(f.hint)}</small>` : ''}</label>`;
}
function readForm(root, fields) {
  const out = {};
  for (const f of fields) {
    const el = $(`[name="${f.name}"]`, root);
    if (!el) continue;
    if (f.type === 'multiselect') out[f.name] = Array.from(el.selectedOptions).map((o) => o.value);
    else if (f.type === 'checkbox') out[f.name] = el.checked;
    else out[f.name] = typeof el.value === 'string' ? el.value.trim() : el.value;
    if (f.required && !out[f.name]) { el.classList.add('invalid'); el.focus(); toast(`${f.label} is required`, 'error'); return null; }
  }
  return out;
}
function formDlg(title, fields, { ok = 'Save', wide = false, intro = '' } = {}) {
  return new Promise((res) => {
    let out = null;
    const m = modal({
      title, wide, onClose: () => res(out),
      body: `${intro ? `<p class="ink2 small">${intro}</p>` : ''}<form class="form" onsubmit="return false">${fields.map(fieldHtml).join('')}</form>`,
      actions: [
        { label: 'Cancel', kind: 'ghost' },
        { label: ok, kind: 'primary', onClick: (w) => { const r = readForm(w, fields); if (!r) return false; out = r; } },
      ],
    });
    m.el.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' && e.target.tagName === 'INPUT' && e.target.type !== 'checkbox') { e.preventDefault(); $('.modal-foot .btn.primary', m.el).click(); }
    });
  });
}

// ---------------------------------------------------------------- state
const STORE_KEY = 'lantern-osint-v1';

function newCase(name = 'Untitled investigation', description = '') {
  const t = nowISO();
  return { id: uid(), name, description, status: 'open', created: t, updated: t, entities: [], links: [], events: [], evidence: [], notes: '', checklist: {}, log: [] };
}
function defaultState() {
  const c = newCase('My first investigation', 'Scope, objective and legal basis go here.');
  return { version: 1, activeCaseId: c.id, settings: { activeLookups: false, theme: 'system', logPivots: true, autoLink: true }, cases: { [c.id]: c } };
}
function migrate(s) {
  if (!s || typeof s !== 'object' || !s.cases) return defaultState();
  s.settings = Object.assign({ activeLookups: false, theme: 'system', logPivots: true, autoLink: true }, s.settings || {});
  for (const c of Object.values(s.cases)) {
    for (const k of ['entities', 'links', 'events', 'evidence', 'log']) if (!Array.isArray(c[k])) c[k] = [];
    c.checklist = c.checklist || {}; c.notes = c.notes || '';
  }
  if (!s.cases[s.activeCaseId]) s.activeCaseId = Object.keys(s.cases)[0];
  if (!s.activeCaseId) { const c = newCase(); s.cases[c.id] = c; s.activeCaseId = c.id; }
  return s;
}

const App = {
  state: null,
  views: {},
  current: null,
  params: {},
  _cleanup: null,

  load() {
    try { const raw = localStorage.getItem(STORE_KEY); this.state = raw ? migrate(JSON.parse(raw)) : defaultState(); }
    catch (e) { console.error(e); this.state = defaultState(); setTimeout(() => toast('Saved data was unreadable — started fresh', 'error'), 300); }
  },
  saveNow() {
    try { localStorage.setItem(STORE_KEY, JSON.stringify(this.state)); return true; }
    catch (e) { console.error(e); toast('Save failed — browser storage may be full. Export your cases.', 'error'); return false; }
  },
  save: null,
  get case() { return this.state.cases[this.state.activeCaseId]; },
  get settings() { return this.state.settings; },

  /** Mark the active case changed, optionally appending to its activity log. */
  touch(msg) {
    const c = this.case;
    c.updated = nowISO();
    if (msg) { c.log.unshift({ t: c.updated, msg }); if (c.log.length > 500) c.log.length = 500; }
    this.save();
    this.renderChrome();
  },
  log(msg) { this.touch(msg); },

  // ---- entities
  entity(id) { return this.case.entities.find((e) => e.id === id); },
  findEntity(type, value) {
    const key = entityKey(type, value);
    return this.case.entities.find((e) => entityKey(e.type, e.value) === key);
  },
  addEntity(type, value, extra = {}) {
    value = cleanValue(type, value);
    if (!value) return { entity: null, created: false };
    const existing = this.findEntity(type, value);
    if (existing) {
      if (extra.source && !existing.source) existing.source = extra.source;
      return { entity: existing, created: false };
    }
    const e = Object.assign({ id: uid(), type, value, label: '', tags: [], notes: '', reliability: '', credibility: '', source: '', created: nowISO() }, extra, { type, value });
    this.case.entities.push(e);
    if (this.settings.autoLink) this.autoLink();
    return { entity: e, created: true };
  },
  updateEntity(id, patch) { const e = this.entity(id); if (e) Object.assign(e, patch); return e; },
  removeEntity(id) {
    const c = this.case;
    c.entities = c.entities.filter((e) => e.id !== id);
    c.links = c.links.filter((l) => l.from !== id && l.to !== id);
    for (const ev of c.events) ev.entityIds = (ev.entityIds || []).filter((x) => x !== id);
  },
  addLink(from, to, label = '') {
    if (!from || !to || from === to) return null;
    const c = this.case;
    const ex = c.links.find((l) => (l.from === from && l.to === to) || (l.from === to && l.to === from));
    if (ex) { if (label && !ex.label) ex.label = label; return ex; }
    const l = { id: uid(), from, to, label, created: nowISO() };
    c.links.push(l);
    return l;
  },
  /** Create links implied by the data (email→domain, url→domain, subdomain→parent). Only between existing entities. */
  autoLink() {
    const c = this.case;
    const domains = new Map(c.entities.filter((e) => e.type === 'domain').map((e) => [e.value, e]));
    let n = 0;
    const link = (a, b, label) => { if (a && b && !c.links.some((l) => (l.from === a.id && l.to === b.id) || (l.from === b.id && l.to === a.id))) { this.addLink(a.id, b.id, label); n++; } };
    const parentOf = (host) => { const parts = host.split('.'); for (let i = 1; i < parts.length - 1; i++) { const p = parts.slice(i).join('.'); if (domains.has(p)) return domains.get(p); } return null; };
    for (const e of c.entities) {
      if (e.type === 'email') { const d = e.value.split('@')[1]; link(e, domains.get(d) || (d && parentOf(d)), 'address at'); }
      else if (e.type === 'url') { const h = hostOf(e.value); if (h) link(e, domains.get(h) || parentOf(h), 'hosted on'); }
      else if (e.type === 'domain') { const p = parentOf(e.value); if (p) link(e, p, 'subdomain of'); }
    }
    return n;
  },

  // ---- cases
  switchCase(id) {
    if (!this.state.cases[id]) return;
    this.state.activeCaseId = id; this.saveNow(); this.renderChrome(); this.render();
  },
  async createCase() {
    const r = await formDlg('New case', [
      { name: 'name', label: 'Case name', required: true, placeholder: 'e.g. Phishing campaign targeting ACME' },
      { name: 'description', label: 'Scope / objective', type: 'textarea', rows: 3, placeholder: 'What question are you answering? Under what authority?' },
    ], { ok: 'Create case' });
    if (!r) return;
    const c = newCase(r.name, r.description);
    c.log.unshift({ t: c.created, msg: 'Case created' });
    this.state.cases[c.id] = c; this.state.activeCaseId = c.id;
    this.saveNow(); this.renderChrome(); this.go('dashboard');
    toast(`Case “${r.name}” created`);
  },

  // ---- router
  register(view) { this.views[view.id] = view; },
  go(id, params = {}) {
    this.params = params;
    const h = '#/' + id;
    if (location.hash === h) this.render(); else location.hash = h;
  },
  onHash() {
    const id = (location.hash.match(/^#\/([\w-]+)/) || [])[1];
    this.current = this.views[id] ? id : 'dashboard';
    this.render();
  },
  render() {
    const v = this.views[this.current];
    const el = $('#view');
    if (this._cleanup) { try { this._cleanup(); } catch (e) { console.error(e); } this._cleanup = null; }
    el.innerHTML = '';
    el.scrollTop = 0;
    // Fresh host per render so listeners attached by a view die with it.
    const host = document.createElement('div');
    host.className = 'view-host';
    el.appendChild(host);
    try { const r = v.render(host, this.params || {}); if (typeof r === 'function') this._cleanup = r; }
    catch (e) { console.error(e); host.innerHTML = `<div class="banner warn">Something went wrong rendering this view: ${esc(e.message)}</div>`; }
    this.params = {};
    document.title = `${v.label} · Lantern`;
    this.renderNav();
    $('#sidebar').classList.remove('open'); $('#scrim').classList.remove('open');
  },
  /** Re-render the current view keeping the scroll position. */
  refresh() {
    const el = $('#view'); const y = el.scrollTop;
    const p = this.params; this.params = p;
    this.render(); el.scrollTop = y;
  },

  // ---- chrome
  NAV: [
    { group: 'Case', items: ['dashboard', 'entities', 'graph', 'timeline', 'evidence', 'notes', 'report'] },
    { group: 'Collect', items: ['extractor', 'pivot', 'dorks', 'recon'] },
    { group: 'Analyze', items: ['metadata', 'toolbox'] },
    { group: 'Operate', items: ['opsec', 'settings'] },
  ],
  renderNav() {
    const c = this.case;
    const counts = { entities: c.entities.length, graph: c.links.length, timeline: c.events.length, evidence: c.evidence.length };
    $('#nav').innerHTML = this.NAV.map((g) => `<div class="nav-group"><h6>${esc(g.group)}</h6>${g.items.filter((id) => this.views[id]).map((id) => {
      const v = this.views[id];
      const n = counts[id];
      return `<a href="#/${id}" class="nav-item ${this.current === id ? 'active' : ''}" ${this.current === id ? 'aria-current="page"' : ''}>${icon(v.icon || id)}<span>${esc(v.label)}</span>${n ? `<span class="count">${n}</span>` : ''}</a>`;
    }).join('')}</div>`).join('');
  },
  renderChrome() {
    const sel = $('#caseSelect');
    const cases = Object.values(this.state.cases).sort((a, b) => b.updated.localeCompare(a.updated));
    sel.innerHTML = cases.map((c) => `<option value="${esc(c.id)}" ${c.id === this.state.activeCaseId ? 'selected' : ''}>${esc(trunc(c.name, 40))}${c.status === 'closed' ? ' (closed)' : ''}</option>`).join('');
    const on = this.settings.activeLookups;
    const b = $('#modeBadge');
    b.className = 'badge' + (on ? ' active' : '');
    b.innerHTML = `<span class="dot" style="background:${on ? 'var(--warn)' : 'var(--good)'}"></span>${on ? 'Active lookups' : 'Passive'}`;
    b.title = on ? 'Active lookups ON — Recon tools may query third-party APIs from your IP. Click to disable.' : 'Passive mode — the app makes no network requests. Click to enable active lookups.';
    this.renderNav();
  },
  async toggleActive() {
    if (!this.settings.activeLookups) {
      const ok = await confirmDlg('Active lookups let the Recon tools call public APIs (Cloudflare DNS-over-HTTPS, rdap.org, certspotter / crt.sh, ipinfo.io, archive.org) directly from this browser. Those services will see your IP address and what you queried. The target’s own servers are never contacted directly. Enable?', { title: 'Enable active lookups?', ok: 'Enable' });
      if (!ok) return;
    }
    this.settings.activeLookups = !this.settings.activeLookups;
    this.saveNow(); this.renderChrome();
    if (this.current === 'recon' || this.current === 'settings' || this.current === 'toolbox') this.refresh();
    toast(this.settings.activeLookups ? 'Active lookups enabled' : 'Passive mode — no network requests');
  },
  applyTheme() {
    const t = this.settings.theme;
    if (t === 'light' || t === 'dark') document.documentElement.setAttribute('data-theme', t);
    else document.documentElement.removeAttribute('data-theme');
    window.dispatchEvent(new Event('lantern-theme'));
  },
  cycleTheme() {
    const order = ['system', 'dark', 'light'];
    this.settings.theme = order[(order.indexOf(this.settings.theme) + 1) % order.length];
    this.applyTheme(); this.saveNow();
    toast(`Theme: ${this.settings.theme}`);
  },
};
App.save = debounce(() => App.saveNow(), 250);

/** Standard view header. */
function viewHead(title, sub = '', actionsHtml = '') {
  return `<div class="view-head"><div><h1>${esc(title)}</h1>${sub ? `<p>${sub}</p>` : ''}</div>${actionsHtml ? `<div class="row">${actionsHtml}</div>` : ''}</div>`;
}
/** Read a CSS custom property (for canvas drawing). */
function cssVar(name) { return getComputedStyle(document.documentElement).getPropertyValue(name).trim(); }
