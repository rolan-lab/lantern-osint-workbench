'use strict';
/* Lantern — timeline of events and evidence / chain-of-custody log. */

const EVENT_CATS = ['Account created', 'Post / publication', 'Domain / infra', 'Communication', 'Transaction', 'Location / travel', 'Media captured', 'Legal / corporate', 'Breach / leak', 'Other'];

/** Parse a user-entered time. No zone given → UTC. Returns {iso, precision} or null. */
function parseWhen(s) {
  s = String(s || '').trim();
  if (!s) return null;
  const m = s.match(/^(\d{4})-(\d\d)(?:-(\d\d))?(?:[ T](\d\d):(\d\d)(?::(\d\d)(?:\.\d+)?)?)?\s*(Z|UTC|[+-]\d\d:?\d\d)?$/i);
  if (m) {
    const [, y, mo, d = '01', h, mi, se = '00', z] = m;
    let zone = 'Z';
    if (z && !/^(z|utc)$/i.test(z)) zone = z.includes(':') ? z : `${z.slice(0, 3)}:${z.slice(3)}`;
    const dt = new Date(`${y}-${mo}-${d}T${h || '00'}:${mi || '00'}:${se}${zone}`);
    return isNaN(dt) ? null : { iso: dt.toISOString(), precision: h ? 'time' : m[3] ? 'day' : 'month' };
  }
  if (/^\d{10}(\d{3})?$/.test(s)) return { iso: new Date(s.length === 10 ? +s * 1000 : +s).toISOString(), precision: 'time' };
  const dt = new Date(s);
  return isNaN(dt) ? null : { iso: dt.toISOString(), precision: 'time' };
}
function fmtWhen(ev) {
  const s = fmtUTC(ev.when, true);
  if (ev.precision === 'day') return s.slice(0, 10);
  if (ev.precision === 'month') return s.slice(0, 7);
  return s.endsWith(':00Z') ? s.replace(/:00Z$/, 'Z') : s;
}

async function addEventDlg(prefill = {}, existing = null) {
  const c = App.case;
  const src = existing || prefill;
  const opts = c.entities.map((e) => [e.id, `${typeLabel(e.type)} · ${trunc(e.label || e.value, 60)}`]);
  const fields = [
    { name: 'when', label: 'When (UTC unless you add an offset)', required: true, value: src.when ? fmtWhen({ when: src.when, precision: src.precision }) : fmtUTC(nowISO(), false).replace('Z', ''), placeholder: '2024-03-01 14:22  ·  2024-03-01T14:22+02:00  ·  2024-03  ·  unix seconds', hint: 'Partial dates are fine: 2023-07 or 2023-07-14.' },
    { name: 'title', label: 'What happened', required: true, value: src.title || '' },
    { name: 'category', label: 'Category', type: 'select', options: EVENT_CATS, value: src.category || 'Other' },
    { name: 'details', label: 'Details', type: 'textarea', rows: 3, value: src.details || '' },
    { name: 'source', label: 'Source (URL or reference)', value: src.source || '' },
  ];
  if (opts.length) fields.push({ name: 'entityIds', label: 'Related entities (Ctrl/Cmd-click for several)', type: 'multiselect', options: opts, value: src.entityIds || [] });
  const r = await formDlg(existing ? 'Edit event' : 'Add timeline event', fields, { ok: existing ? 'Save' : 'Add event', wide: true });
  if (!r) return null;
  const w = parseWhen(r.when);
  if (!w) { toast('Could not understand that date/time', 'error'); return null; }
  const data = { when: w.iso, precision: w.precision, title: r.title, category: r.category, details: r.details, source: r.source, entityIds: r.entityIds || [] };
  if (existing) { Object.assign(existing, data); App.touch(`Edited event: ${r.title}`); return existing; }
  const ev = { id: uid(), created: nowISO(), ...data };
  c.events.push(ev);
  App.touch(`Timeline: ${r.title}`);
  toast('Event added to timeline');
  return ev;
}
/** Prefilled event dialog from other tools. entityValue: [type, value] — added to the case if needed. */
async function addEventQuick({ when, title, details = '', source = '', category = 'Other', entityValue = null, precision = 'time' }) {
  const ids = [];
  if (entityValue) { const r = App.addEntity(entityValue[0], entityValue[1], { source }); if (r.entity) ids.push(r.entity.id); }
  return addEventDlg({ when, title, details, source, category, entityIds: ids, precision });
}

// ---------------------------------------------------------------- Timeline view
const tlState = { q: '', desc: false };
App.register({
  id: 'timeline', label: 'Timeline', icon: 'timeline',
  render(el) {
    const c = App.case;
    el.innerHTML = `
      ${viewHead('Timeline', 'Chronology of the case in UTC. Add events by hand, or send them here from Metadata (photo capture times), Recon (domain registration) and the ID decoder.',
        `<button class="btn" id="tcsv">Export CSV</button><button class="btn primary" id="tadd">+ Add event</button>`)}
      <div class="row mb"><input id="tq" placeholder="Filter events…" value="${esc(tlState.q)}" style="width:280px"><button class="btn ghost" id="tsort">${tlState.desc ? 'Newest first' : 'Oldest first'} ⇅</button><span class="spacer"></span><span class="muted small" id="tcount"></span></div>
      <div id="tlist"></div>`;
    const draw = () => {
      const q = tlState.q.toLowerCase();
      const evs = c.events.filter((e) => !q || [e.title, e.details, e.source, e.category, ...(e.entityIds || []).map((id) => App.entity(id)?.value || '')].join(' ').toLowerCase().includes(q))
        .sort((a, b) => (tlState.desc ? b.when.localeCompare(a.when) : a.when.localeCompare(b.when)));
      $('#tcount', el).textContent = `${evs.length} of ${c.events.length} events`;
      if (!c.events.length) { $('#tlist', el).innerHTML = '<div class="empty"><b>No events yet</b>Timelines expose patterns: account creation clusters, activity hours, gaps.</div>'; return; }
      let html = '<div class="tl">', lastDay = null, lastT = null;
      for (const ev of evs) {
        const day = ev.when.slice(0, 10);
        if (day !== lastDay) {
          const gap = lastT ? Math.abs(new Date(ev.when) - new Date(lastT)) / 86400000 : 0;
          html += `<div class="tl-day">${ev.precision === 'month' ? ev.when.slice(0, 7) : day}${gap >= 2 ? ` <span class="muted" style="font-weight:400">· ${Math.round(gap)} days ${tlState.desc ? 'earlier' : 'later'}</span>` : ''}</div>`;
          lastDay = day;
        }
        lastT = ev.when;
        const src = safeUrl(ev.source);
        html += `<div class="tl-item"><div class="card">
          <div class="row"><span class="tl-time">${esc(fmtWhen(ev).slice(ev.precision === 'time' ? 11 : 0) || fmtWhen(ev))}</span><b class="break" style="flex:1 1 160px">${esc(ev.title)}</b>${ev.category && ev.category !== 'Other' ? `<span class="chip">${esc(ev.category)}</span>` : ''}
            <button class="btn sm ghost" data-ed="${esc(ev.id)}">Edit</button><button class="btn sm ghost" data-del="${esc(ev.id)}" aria-label="Delete event">✕</button></div>
          ${ev.details ? `<div class="small ink2" style="white-space:pre-wrap;margin-top:4px">${esc(ev.details)}</div>` : ''}
          ${(ev.entityIds || []).length || ev.source ? `<div class="row small" style="margin-top:6px">${(ev.entityIds || []).map((id) => entityChip(App.entity(id))).join('')}${ev.source ? (src ? `<a href="${esc(src)}" target="_blank" rel="noopener noreferrer" class="break">${esc(trunc(ev.source, 70))}</a>` : `<span class="muted">${esc(ev.source)}</span>`) : ''}</div>` : ''}
        </div></div>`;
      }
      $('#tlist', el).innerHTML = html + '</div>';
    };
    draw();
    bindEntityChips(el);
    $('#tq', el).addEventListener('input', debounce((e) => { tlState.q = e.target.value; draw(); }, 120));
    $('#tsort', el).onclick = (e) => { tlState.desc = !tlState.desc; e.target.textContent = `${tlState.desc ? 'Newest first' : 'Oldest first'} ⇅`; draw(); };
    $('#tadd', el).onclick = async () => { if (await addEventDlg()) draw(); };
    $('#tcsv', el).onclick = () => download(`${slug(c.name)}-timeline.csv`, toCSV([['when_utc', 'precision', 'title', 'category', 'details', 'source', 'entities'], ...[...c.events].sort((a, b) => a.when.localeCompare(b.when)).map((e) => [e.when, e.precision, e.title, e.category, e.details, e.source, (e.entityIds || []).map((id) => App.entity(id)?.value).filter(Boolean).join('; ')])]), 'text/csv');
    el.addEventListener('click', async (e) => {
      const b = e.target.closest('button'); if (!b) return;
      if (b.dataset.ed) { const ev = c.events.find((x) => x.id === b.dataset.ed); if (ev && await addEventDlg({}, ev)) draw(); }
      if (b.dataset.del) { const ev = c.events.find((x) => x.id === b.dataset.del); if (ev && await confirmDlg(`Delete event “${ev.title}”?`, { title: 'Delete event', ok: 'Delete', danger: true })) { c.events = c.events.filter((x) => x !== ev); App.touch(`Deleted event: ${ev.title}`); draw(); } }
    });
  },
});

// ---------------------------------------------------------------- Evidence / chain of custody
function nextEvidenceId() { const n = Math.max(0, ...App.case.evidence.map((x) => +(String(x.ref).match(/\d+/) || [0])[0])); return `EV-${String(n + 1).padStart(3, '0')}`; }
async function logUrlCapture(prefill = {}) {
  const r = await formDlg('Log a web capture', [
    { name: 'url', label: 'URL', required: true, value: prefill.url || '' },
    { name: 'title', label: 'Title / description', value: prefill.title || '' },
    { name: 'archiveUrl', label: 'Archive URL (Wayback / archive.today), if you made one', value: '' },
    { name: 'notes', label: 'Notes', type: 'textarea', rows: 3, placeholder: 'What does this page show? Screenshot filename?' },
  ], { ok: 'Log capture', intro: 'Records the URL with a UTC timestamp. Archive it too — pages change and disappear.' });
  if (!r) return null;
  if (!safeUrl(r.url)) { toast('That is not an http(s) URL', 'error'); return null; }
  const item = { id: uid(), ref: nextEvidenceId(), kind: 'url', title: r.title || r.url, url: r.url, archiveUrl: r.archiveUrl, notes: r.notes, capturedAt: nowISO() };
  App.case.evidence.push(item);
  App.addEntity('url', r.url, { source: `Evidence ${item.ref}` });
  App.touch(`Evidence ${item.ref}: logged ${r.url}`);
  return item;
}
async function logFiles(files, extra = {}) {
  const added = [];
  for (const f of files) {
    toast(`Hashing ${f.name}…`);
    const h = await hashBuffer(await readFileAs(f, 'buffer'));
    const item = { id: uid(), ref: nextEvidenceId(), kind: 'file', title: f.name, filename: f.name, size: f.size, mime: f.type, md5: h.md5, sha1: h.sha1, sha256: h.sha256, fileModified: f.lastModified ? new Date(f.lastModified).toISOString() : '', capturedAt: nowISO(), url: extra.url || '', notes: extra.notes || '' };
    App.case.evidence.push(item);
    App.touch(`Evidence ${item.ref}: hashed ${f.name} (SHA-256 ${h.sha256.slice(0, 16)}…)`);
    added.push(item);
  }
  return added;
}

App.register({
  id: 'evidence', label: 'Evidence', icon: 'evidence',
  render(el) {
    const c = App.case;
    el.innerHTML = `
      ${viewHead('Evidence & chain of custody', 'Fingerprint every file you collect (MD5 / SHA-1 / SHA-256) and log every page you rely on, with UTC timestamps. Files are hashed locally and are <b>not stored</b> — keep the originals; the hashes prove they are unchanged.',
        `<button class="btn" id="ecsv">Export custody log (CSV)</button><button class="btn primary" id="eurl">+ Log web capture</button>`)}
      <div class="grid g2">
        <div class="drop" id="edrop"><b>Drop files to hash &amp; log</b><br><span class="small">Screenshots, downloads, exports, PDFs — any size, any type</span></div>
        <div class="drop" id="ever"><b>Verify a file</b><br><span class="small">Drop a file to check it against the log (integrity / duplicate check)</span></div>
      </div>
      <div id="everres" class="mt"></div>
      <div id="elist" class="mt"></div>`;
    const draw = () => {
      if (!c.evidence.length) { $('#elist', el).innerHTML = '<div class="empty"><b>No evidence logged</b>Hash files and log captures as you go — reconstructing provenance later is painful.</div>'; return; }
      $('#elist', el).innerHTML = `<div class="tbl-wrap"><table class="tbl"><thead><tr><th>Ref</th><th>Captured (UTC)</th><th>Item</th><th>Fingerprint</th><th>Notes</th><th></th></tr></thead><tbody>
        ${[...c.evidence].reverse().map((x) => `<tr>
          <td class="mono nowrap">${esc(x.ref)}</td>
          <td class="mono small nowrap">${esc(fmtUTC(x.capturedAt))}</td>
          <td style="max-width:340px"><div class="break"><b>${esc(x.title)}</b></div>
            ${x.kind === 'file' ? `<div class="small muted">${esc(fmtBytes(x.size))}${x.mime ? ' · ' + esc(x.mime) : ''}</div>` : ''}
            ${x.url ? `<div class="small break"><a href="${esc(safeUrl(x.url) || '#')}" target="_blank" rel="noopener noreferrer">${esc(trunc(x.url, 80))}</a></div>` : ''}
            ${x.archiveUrl ? `<div class="small break">Archive: <a href="${esc(safeUrl(x.archiveUrl) || '#')}" target="_blank" rel="noopener noreferrer">${esc(trunc(x.archiveUrl, 60))}</a></div>` : x.kind === 'url' ? `<div class="row small" style="margin-top:4px"><a class="lnk" data-arch="wb" data-u="${esc(x.url)}">Save to Wayback</a><a class="lnk" data-arch="at" data-u="${esc(x.url)}">archive.today</a></div>` : ''}</td>
          <td class="mono small">${x.sha256 ? `<div title="SHA-256 — click to copy" data-copy="${esc(x.sha256)}" style="cursor:copy">SHA256 ${esc(x.sha256.slice(0, 20))}…</div><div title="MD5 — click to copy" data-copy="${esc(x.md5)}" style="cursor:copy" class="muted">MD5 ${esc(x.md5)}</div>` : '<span class="muted">—</span>'}</td>
          <td class="small" style="max-width:260px;white-space:pre-wrap">${esc(x.notes || '')}</td>
          <td class="actions"><button class="btn sm ghost" data-eed="${esc(x.id)}">Edit</button><button class="btn sm ghost" data-edel="${esc(x.id)}" aria-label="Delete">✕</button></td>
        </tr>`).join('')}</tbody></table></div>`;
    };
    draw();
    fileDrop($('#edrop', el), async (files) => { await logFiles(files); draw(); toast(`${plural(files.length, 'file')} hashed and logged`); });
    fileDrop($('#ever', el), async (files) => {
      const out = [];
      for (const f of files) {
        const h = await hashBuffer(await readFileAs(f, 'buffer'));
        const m = c.evidence.find((x) => x.sha256 === h.sha256);
        const sameName = c.evidence.find((x) => x.filename === f.name && x.sha256 !== h.sha256);
        out.push(m ? `<div class="banner" style="margin-bottom:8px"><span class="status good">Match</span><div class="grow small"><b>${esc(f.name)}</b> is identical to <b>${esc(m.ref)}</b> (${esc(m.title)}), logged ${esc(fmtUTC(m.capturedAt))}.</div></div>`
          : `<div class="banner warn" style="margin-bottom:8px"><span class="status ${sameName ? 'crit' : 'warn'}">${sameName ? 'Altered?' : 'Not logged'}</span><div class="grow small"><b>${esc(f.name)}</b> — SHA-256 <span class="mono">${esc(h.sha256)}</span>${sameName ? `<br>A file with the same name (${esc(sameName.ref)}) was logged with a <b>different</b> hash — the content has changed since.` : ''}</div></div>`);
      }
      $('#everres', el).innerHTML = out.join('');
    }, {});
    $('#eurl', el).onclick = async () => { if (await logUrlCapture()) draw(); };
    $('#ecsv', el).onclick = () => download(`${slug(c.name)}-chain-of-custody.csv`, toCSV([['ref', 'captured_utc', 'kind', 'title', 'filename', 'size_bytes', 'mime', 'md5', 'sha1', 'sha256', 'url', 'archive_url', 'file_last_modified', 'notes'], ...c.evidence.map((x) => [x.ref, x.capturedAt, x.kind, x.title, x.filename, x.size, x.mime, x.md5, x.sha1, x.sha256, x.url, x.archiveUrl, x.fileModified, x.notes])]), 'text/csv');
    el.addEventListener('click', async (e) => {
      const t = e.target.closest('[data-copy],[data-arch],button'); if (!t) return;
      if (t.dataset.copy) return copyText(t.dataset.copy);
      if (t.dataset.arch) { e.preventDefault(); openUrl(t.dataset.arch === 'wb' ? `https://web.archive.org/save/${t.dataset.u}` : `https://archive.ph/?run=1&url=${encodeURIComponent(t.dataset.u)}`); return; }
      if (t.dataset.eed) {
        const x = c.evidence.find((v) => v.id === t.dataset.eed); if (!x) return;
        const r = await formDlg(`Edit ${x.ref}`, [{ name: 'title', label: 'Title', value: x.title }, { name: 'url', label: 'Source URL', value: x.url || '' }, { name: 'archiveUrl', label: 'Archive URL', value: x.archiveUrl || '' }, { name: 'notes', label: 'Notes', type: 'textarea', rows: 4, value: x.notes || '' }]);
        if (r) { Object.assign(x, r); App.touch(`Evidence ${x.ref}: edited`); draw(); }
      }
      if (t.dataset.edel) {
        const x = c.evidence.find((v) => v.id === t.dataset.edel);
        if (x && await confirmDlg(`Remove ${x.ref} (${x.title}) from the custody log? The deletion itself is recorded in the activity log.`, { title: 'Remove evidence record', ok: 'Remove', danger: true })) {
          c.evidence = c.evidence.filter((v) => v !== x); App.touch(`Evidence ${x.ref} removed (${x.title}${x.sha256 ? `, SHA-256 ${x.sha256}` : ''})`); draw();
        }
      }
    });
  },
});
