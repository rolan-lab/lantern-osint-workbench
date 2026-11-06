'use strict';
/* Lantern — case views: dashboard, entities, notes + shared entity dialogs. */

const RELIABILITY = [['', '—'], ['A', 'A · Completely reliable'], ['B', 'B · Usually reliable'], ['C', 'C · Fairly reliable'], ['D', 'D · Not usually reliable'], ['E', 'E · Unreliable'], ['F', 'F · Reliability cannot be judged']];
const CREDIBILITY = [['', '—'], ['1', '1 · Confirmed by other sources'], ['2', '2 · Probably true'], ['3', '3 · Possibly true'], ['4', '4 · Doubtful'], ['5', '5 · Improbable'], ['6', '6 · Truth cannot be judged']];
const grade = (e) => (e.reliability || e.credibility ? `${e.reliability || '?'}${e.credibility || '?'}` : '');

function entityChip(e, { clickable = true } = {}) {
  if (!e) return '';
  return `<span class="chip ${clickable ? 'clickable' : ''}" ${clickable ? `data-entity="${esc(e.id)}"` : ''} title="${esc(typeLabel(e.type))}: ${esc(e.value)}"><span class="dot" style="background:${typeColorVar(e.type)}"></span><span class="break">${esc(trunc(e.label || e.value, 48))}</span></span>`;
}
/** Wire up [data-entity] chips inside root to open the entity sheet. */
function bindEntityChips(root) {
  root.addEventListener('click', (ev) => { const c = ev.target.closest('[data-entity]'); if (c && root.contains(c)) { ev.preventDefault(); entitySheet(c.dataset.entity); } });
}

const ENTITY_FIELDS = (e = {}) => [
  { name: 'type', label: 'Type', type: 'select', options: TYPE_OPTIONS, value: e.type || 'keyword' },
  { name: 'value', label: 'Value (the selector)', required: true, value: e.value || '', placeholder: 'e.g. jdoe@example.com' },
  { name: 'label', label: 'Display label (optional)', value: e.label || '', placeholder: 'e.g. “Suspected operator — main inbox”' },
  { name: 'tags', label: 'Tags (comma-separated)', value: (e.tags || []).join(', '), placeholder: 'suspect, infra, confirmed' },
  { name: 'reliability', label: 'Source reliability (Admiralty)', type: 'select', options: RELIABILITY, value: e.reliability || '' },
  { name: 'credibility', label: 'Information credibility (Admiralty)', type: 'select', options: CREDIBILITY, value: e.credibility || '' },
  { name: 'source', label: 'Source (where you found it)', value: e.source || '', placeholder: 'URL, document, or tool' },
  { name: 'notes', label: 'Notes', type: 'textarea', rows: 3, value: e.notes || '' },
];
function normTags(s) { return [...new Set(String(s || '').split(',').map((t) => t.trim()).filter(Boolean))]; }

async function addEntityDlg(prefill = {}) {
  if (prefill.value && !prefill.type) prefill.type = detectType(prefill.value);
  const r = await formDlg('Add entity', ENTITY_FIELDS(prefill), { ok: 'Add to case' });
  if (!r) return null;
  const { entity, created } = App.addEntity(r.type, r.value, { label: r.label, tags: normTags(r.tags), reliability: r.reliability, credibility: r.credibility, source: r.source, notes: r.notes });
  if (!entity) { toast('Nothing to add', 'error'); return null; }
  App.touch(created ? `Added ${typeLabel(entity.type)} ${entity.value}` : null);
  toast(created ? 'Entity added' : 'Already in case');
  return entity;
}
async function editEntityDlg(id) {
  const e = App.entity(id); if (!e) return null;
  const r = await formDlg('Edit entity', ENTITY_FIELDS(e));
  if (!r) return null;
  const value = cleanValue(r.type, r.value);
  const dup = App.findEntity(r.type, value);
  if (dup && dup.id !== id) { toast('Another entity already has that type and value', 'error'); return null; }
  App.updateEntity(id, { type: r.type, value, label: r.label, tags: normTags(r.tags), reliability: r.reliability, credibility: r.credibility, source: r.source, notes: r.notes });
  App.touch(`Edited ${typeLabel(r.type)} ${value}`);
  return e;
}
async function deleteEntity(id) {
  const e = App.entity(id); if (!e) return false;
  if (!(await confirmDlg(`Delete “${trunc(e.value, 80)}” and its ${plural(App.case.links.filter((l) => l.from === id || l.to === id).length, 'link')}?`, { title: 'Delete entity', ok: 'Delete', danger: true }))) return false;
  App.removeEntity(id); App.touch(`Deleted ${typeLabel(e.type)} ${e.value}`);
  return true;
}
async function linkDlg(fromId, toId) {
  const ents = App.case.entities;
  const opts = ents.map((e) => [e.id, `${typeLabel(e.type)} · ${trunc(e.label || e.value, 60)}`]);
  if (ents.length < 2) { toast('Add at least two entities first', 'error'); return null; }
  const r = await formDlg('Link entities', [
    { name: 'from', label: 'From', type: 'select', options: opts, value: fromId || ents[0].id },
    { name: 'label', label: 'Relationship', placeholder: 'e.g. registered by, uses, resolves to, same person as' },
    { name: 'to', label: 'To', type: 'select', options: opts, value: toId || ents[1].id },
  ], { ok: 'Create link' });
  if (!r) return null;
  if (r.from === r.to) { toast('Pick two different entities', 'error'); return null; }
  const l = App.addLink(r.from, r.to, r.label);
  App.touch(`Linked ${App.entity(r.from).value} → ${App.entity(r.to).value}${r.label ? ` (${r.label})` : ''}`);
  return l;
}

/** Entity detail sheet: everything about one selector in one place. */
function entitySheet(id) {
  const e = App.entity(id); if (!e) return;
  const c = App.case;
  const links = c.links.filter((l) => l.from === id || l.to === id);
  const events = c.events.filter((ev) => (ev.entityIds || []).includes(id));
  const groups = pivotsFor(e.type, e.value).slice(0, 2);
  const body = `
    <div class="row mb">${typeChip(e.type)} ${e.tags?.map((t) => `<span class="tag">${esc(t)}</span>`).join('') || ''} ${grade(e) ? `<span class="chip" title="Admiralty grade">Grade ${esc(grade(e))}</span>` : ''}</div>
    <div class="mono break" style="font-size:15px;margin-bottom:10px">${esc(e.value)}</div>
    <dl class="kv">
      ${e.label ? `<dt>Label</dt><dd>${esc(e.label)}</dd>` : ''}
      ${e.source ? `<dt>Source</dt><dd class="break">${safeUrl(e.source) ? `<a href="${esc(safeUrl(e.source))}" target="_blank" rel="noopener noreferrer">${esc(e.source)}</a>` : esc(e.source)}</dd>` : ''}
      <dt>Added</dt><dd>${esc(fmtUTC(e.created))}</dd>
      ${e.notes ? `<dt>Notes</dt><dd style="white-space:pre-wrap">${esc(e.notes)}</dd>` : ''}
    </dl>
    <h4 style="margin:16px 0 6px">Links (${links.length})</h4>
    ${links.length ? `<div class="stack" style="--gap:6px">${links.map((l) => { const o = App.entity(l.from === id ? l.to : l.from); return `<div class="row">${l.from === id ? '→' : '←'} <span class="muted small">${esc(l.label || 'linked')}</span> ${entityChip(o)}<span class="spacer"></span><button class="btn sm ghost" data-unlink="${esc(l.id)}">Remove</button></div>`; }).join('')}</div>` : '<p class="muted small">No links yet.</p>'}
    ${events.length ? `<h4 style="margin:16px 0 6px">Timeline (${events.length})</h4>${events.map((ev) => `<div class="small"><span class="mono">${esc(fmtUTC(ev.when, false))}</span> · ${esc(ev.title)}</div>`).join('')}` : ''}
    <h4 style="margin:16px 0 6px">Quick pivots</h4>
    ${groups.map((g) => `<div class="small muted" style="margin:6px 0 4px">${esc(g.group)}</div><div class="links">${g.items.map((it) => `<a class="lnk ${it.paste ? 'paste' : ''}" data-url="${esc(it.url)}" data-paste="${it.paste ? 1 : ''}">${esc(it.name)}</a>`).join('')}</div>`).join('')}`;
  const m = modal({
    title: `${typeLabel(e.type)} details`, wide: true, body,
    actions: [
      { label: 'Delete', kind: 'danger', onClick: async () => { if (await deleteEntity(id)) { App.refresh(); } else return false; } },
      { label: 'Link to…', kind: 'ghost', onClick: async () => { await linkDlg(id); App.refresh(); } },
      { label: 'Edit', kind: 'ghost', onClick: async () => { await editEntityDlg(id); App.refresh(); } },
      { label: 'All pivots', kind: 'primary', onClick: () => { App.go('pivot', { q: e.value, type: e.type }); } },
    ],
  });
  m.el.addEventListener('click', (ev) => {
    const u = ev.target.closest('[data-unlink]');
    if (u) { App.case.links = App.case.links.filter((l) => l.id !== u.dataset.unlink); App.touch('Removed a link'); u.closest('.row').remove(); App.refresh(); return; }
    const a = ev.target.closest('[data-url]');
    if (a) { ev.preventDefault(); launchPivot(a.dataset.url, !!a.dataset.paste, e.value, a.textContent); return; }
    const chip = ev.target.closest('[data-entity]');
    if (chip) { m.close(); entitySheet(chip.dataset.entity); }
  });
}

/** Open a pivot link (copying the value first for paste-only sites) and record it in the case log. */
function launchPivot(url, paste, value, name) {
  if (paste) copyText(value, true).then(() => toast('Value copied — paste it into the site'));
  if (openUrl(url) && App.settings.logPivots) App.touch(`Pivot: ${name} ← ${trunc(value, 80)}`);
}

// ---------------------------------------------------------------- Dashboard
App.register({
  id: 'dashboard', label: 'Dashboard', icon: 'dashboard',
  render(el) {
    const c = App.case;
    const famCounts = Object.keys(FAMILIES).map((f) => [f, c.entities.filter((e) => famOf(e.type) === f).length]).filter(([, n]) => n);
    const max = Math.max(1, ...famCounts.map(([, n]) => n));
    const checklistDone = OPSEC_ITEMS.filter((i) => c.checklist[i.id]).length;
    const nextSteps = OPSEC_ITEMS.filter((i) => !c.checklist[i.id]).slice(0, 4);
    const stat = (v, l, go) => `<a class="card stat" href="#/${go}" style="text-decoration:none;color:inherit"><div class="v">${v}</div><div class="l">${l}</div></a>`;
    el.innerHTML = `
      ${viewHead(c.name, `${c.description ? esc(c.description) + ' · ' : ''}<span class="muted">Opened ${esc(fmtUTC(c.created).slice(0, 10))} · updated ${esc(relTime(c.updated))}</span>`,
        `<span class="status ${c.status === 'closed' ? 'warn' : 'good'}">${c.status === 'closed' ? 'Closed' : 'Open'}</span><button class="btn" id="editCase">Edit case</button>`)}
      <div class="grid g4">
        ${stat(c.entities.length, 'Entities', 'entities')}${stat(c.links.length, 'Links', 'graph')}${stat(c.events.length, 'Timeline events', 'timeline')}${stat(c.evidence.length, 'Evidence items', 'evidence')}
      </div>
      <div class="grid g2 mt">
        <div class="card">
          <h3>Quick capture</h3>
          <p class="card-sub">Paste anything — an email, page source, a chat log, an incident report. Lantern pulls out every selector.</p>
          <textarea id="qc" rows="6" placeholder="Paste text here…"></textarea>
          <div class="row mt"><button class="btn primary" id="qcGo">Extract selectors</button><span class="muted small">Defanged indicators (hxxp, [.]) are handled.</span></div>
        </div>
        <div class="card">
          <h3>Entities by category<span class="spacer"></span><a class="btn sm ghost" href="#/entities">View table</a></h3>
          ${famCounts.length ? `<div class="bars">${famCounts.map(([f, n]) => `<div class="bar-row" title="${esc(FAMILIES[f].label)}: ${n}"><span class="lab"><span class="dot" style="background:var(--c${FAMILIES[f].slot})"></span>${esc(FAMILIES[f].label)}</span><div class="bar-track"><div class="bar-fill" style="width:${(n / max) * 100}%;background:var(--c${FAMILIES[f].slot})"></div></div><span class="n">${n}</span></div>`).join('')}</div>`
            : `<div class="empty"><b>No entities yet</b>Paste text into Quick capture, or use the Quick pivot bar above.</div>`}
        </div>
      </div>
      <div class="grid g2 mt">
        <div class="card">
          <h3>Activity log<span class="spacer"></span><span class="muted small">UTC</span></h3>
          ${c.log.length ? `<div style="max-height:320px;overflow:auto">${c.log.slice(0, 40).map((l) => `<div class="row nowrap small" style="padding:4px 0;border-bottom:1px solid var(--line)"><span class="mono muted nowrap">${esc(fmtUTC(l.t, false).slice(5))}</span><span class="break">${esc(l.msg)}</span></div>`).join('')}</div>` : '<p class="muted small">Every pivot, addition and edit is recorded here so you can reconstruct your research path.</p>'}
        </div>
        <div class="card">
          <h3>Methodology<span class="spacer"></span><a class="btn sm ghost" href="#/opsec">Open checklist</a></h3>
          <div class="row small mb"><div class="progress" style="flex:1"><div style="width:${(checklistDone / OPSEC_ITEMS.length) * 100}%"></div></div><span class="ink2">${checklistDone}/${OPSEC_ITEMS.length}</span></div>
          ${nextSteps.length ? `<ul class="checklist">${nextSteps.map((i) => `<li><input type="checkbox" data-check="${i.id}"><span>${esc(i.text)}</span></li>`).join('')}</ul>` : '<p class="small">All methodology steps checked. Nice discipline.</p>'}
        </div>
      </div>`;
    $('#qcGo', el).onclick = () => { const t = $('#qc', el).value; if (!t.trim()) return toast('Paste some text first', 'error'); App.go('extractor', { text: t }); };
    $('#editCase', el).onclick = async () => {
      const r = await formDlg('Edit case', [
        { name: 'name', label: 'Case name', required: true, value: c.name },
        { name: 'description', label: 'Scope / objective', type: 'textarea', rows: 4, value: c.description },
        { name: 'status', label: 'Status', type: 'select', options: [['open', 'Open'], ['closed', 'Closed']], value: c.status },
      ]);
      if (r) { Object.assign(c, r); App.touch('Edited case details'); App.refresh(); }
    };
    el.addEventListener('change', (e) => { const k = e.target.dataset.check; if (k) { c.checklist[k] = e.target.checked; App.touch(); setTimeout(() => App.refresh(), 250); } });
  },
});

// ---------------------------------------------------------------- Entities
const entState = { q: '', type: '', sort: 'added', selected: new Set() };
App.register({
  id: 'entities', label: 'Entities', icon: 'entities',
  render(el) {
    const c = App.case;
    const typesPresent = [...new Set(c.entities.map((e) => e.type))];
    el.innerHTML = `
      ${viewHead('Entities', 'Every selector in this case. Click a value for details, links and pivots. Grades use the Admiralty system (source reliability A–F × information credibility 1–6).',
        `<button class="btn" id="bulk">Bulk import</button><button class="btn" id="derive" title="Create domain entities from emails/URLs and link related items">Derive &amp; auto-link</button><button class="btn" id="csv">Export CSV</button><button class="btn primary" id="add">+ Add entity</button>`)}
      <div class="row mb">
        <input id="fq" class="grow" placeholder="Filter by value, label, tag, notes…" value="${esc(entState.q)}" style="max-width:420px">
        <select id="ft"><option value="">All types</option>${typesPresent.map((t) => `<option value="${t}" ${entState.type === t ? 'selected' : ''}>${esc(typeLabel(t))}</option>`).join('')}</select>
        <select id="fs">${[['added', 'Newest first'], ['type', 'By type'], ['value', 'A → Z'], ['links', 'Most linked']].map(([v, l]) => `<option value="${v}" ${entState.sort === v ? 'selected' : ''}>${l}</option>`).join('')}</select>
        <span class="spacer"></span>
        <span id="selbar" class="row"></span>
      </div>
      <div id="tbl"></div>`;
    const draw = () => {
      const q = entState.q.toLowerCase();
      const deg = new Map(); c.links.forEach((l) => { deg.set(l.from, (deg.get(l.from) || 0) + 1); deg.set(l.to, (deg.get(l.to) || 0) + 1); });
      let rows = c.entities.filter((e) => (!entState.type || e.type === entState.type) && (!q || [e.value, e.label, e.notes, e.source, ...(e.tags || [])].join(' ').toLowerCase().includes(q)));
      const order = Object.keys(TYPES);
      rows.sort(entState.sort === 'type' ? (a, b) => order.indexOf(a.type) - order.indexOf(b.type) || a.value.localeCompare(b.value)
        : entState.sort === 'value' ? (a, b) => a.value.localeCompare(b.value)
          : entState.sort === 'links' ? (a, b) => (deg.get(b.id) || 0) - (deg.get(a.id) || 0)
            : (a, b) => b.created.localeCompare(a.created));
      for (const id of [...entState.selected]) if (!c.entities.some((e) => e.id === id)) entState.selected.delete(id);
      $('#tbl', el).innerHTML = !c.entities.length
        ? `<div class="empty"><b>No entities yet</b>Add one, paste text into the Extractor, or bulk-import a list.</div>`
        : `<div class="tbl-wrap"><table class="tbl"><thead><tr><th style="width:28px"><input type="checkbox" id="selAll" aria-label="Select all"></th><th>Type</th><th>Value</th><th>Label · notes</th><th>Tags</th><th title="Admiralty grade">Grade</th><th class="num">Links</th><th>Added (UTC)</th><th></th></tr></thead><tbody>
          ${rows.map((e) => `<tr>
            <td><input type="checkbox" data-sel="${esc(e.id)}" ${entState.selected.has(e.id) ? 'checked' : ''} aria-label="Select"></td>
            <td class="nowrap">${typeChip(e.type)}</td>
            <td><a href="#" class="mono break" data-entity="${esc(e.id)}">${esc(e.value)}</a></td>
            <td class="small">${e.label ? `<div>${esc(e.label)}</div>` : ''}${e.notes ? `<div class="muted">${esc(trunc(e.notes, 90))}</div>` : ''}</td>
            <td>${(e.tags || []).map((t) => `<span class="tag">${esc(t)}</span>`).join('')}</td>
            <td class="mono">${esc(grade(e))}</td>
            <td class="num">${deg.get(e.id) || ''}</td>
            <td class="mono small nowrap muted">${esc(fmtUTC(e.created, false).slice(0, 16))}</td>
            <td class="actions"><button class="btn sm" data-pivot="${esc(e.id)}">Pivot</button> <button class="btn sm ghost" data-edit="${esc(e.id)}">Edit</button></td>
          </tr>`).join('')}
          ${rows.length ? '' : '<tr><td colspan="9" class="muted" style="text-align:center;padding:20px">No matches</td></tr>'}
        </tbody></table></div><p class="muted small">${rows.length} of ${c.entities.length} shown</p>`;
      const n = entState.selected.size;
      $('#selbar', el).innerHTML = n ? `<span class="small ink2">${n} selected</span><button class="btn sm" id="tagSel">Tag</button><button class="btn sm" id="linkSel" title="Link every selected entity to the first one selected">Link to first</button><button class="btn sm danger" id="delSel">Delete</button>` : '';
    };
    draw();
    bindEntityChips(el);
    $('#fq', el).addEventListener('input', debounce((e) => { entState.q = e.target.value; draw(); }, 120));
    $('#ft', el).onchange = (e) => { entState.type = e.target.value; draw(); };
    $('#fs', el).onchange = (e) => { entState.sort = e.target.value; draw(); };
    $('#add', el).onclick = async () => { if (await addEntityDlg()) App.refresh(); };
    $('#csv', el).onclick = () => {
      const rows = [['type', 'value', 'label', 'tags', 'reliability', 'credibility', 'source', 'notes', 'added_utc']].concat(c.entities.map((e) => [e.type, e.value, e.label, (e.tags || []).join('; '), e.reliability, e.credibility, e.source, e.notes, e.created]));
      download(`${slug(c.name)}-entities.csv`, toCSV(rows), 'text/csv');
    };
    $('#derive', el).onclick = () => {
      let added = 0;
      for (const e of [...c.entities]) {
        let d = null;
        if (e.type === 'email') d = e.value.split('@')[1];
        else if (e.type === 'url' || e.type === 'image') d = hostOf(e.value);
        if (d && isDomain(d)) { const r = App.addEntity('domain', d, { source: `derived from ${e.value}` }); if (r.created) added++; }
      }
      const linked = App.autoLink();
      App.touch(`Derived ${added} domain(s), created ${linked} link(s)`); toast(`Derived ${added} domain(s), ${linked} new link(s)`); App.refresh();
    };
    $('#bulk', el).onclick = async () => {
      const r = await formDlg('Bulk import', [
        { name: 'text', label: 'One selector per line', type: 'textarea', rows: 10, placeholder: 'jdoe@example.com\n203.0.113.7\nevil-domain.xyz\n@handle' },
        { name: 'type', label: 'Type', type: 'select', options: [['auto', 'Auto-detect per line'], ...TYPE_OPTIONS] },
        { name: 'tags', label: 'Tags to apply', placeholder: 'optional' },
        { name: 'source', label: 'Source', placeholder: 'optional' },
      ], { ok: 'Import', wide: true });
      if (!r) return;
      let n = 0, dup = 0;
      for (const line of r.text.split(/\r?\n/).map((s) => refang(s.trim())).filter(Boolean)) {
        const t = r.type === 'auto' ? detectType(line) : r.type;
        const res = App.addEntity(t, line, { tags: normTags(r.tags), source: r.source });
        res.created ? n++ : dup++;
      }
      App.touch(`Bulk-imported ${n} entities`); toast(`Imported ${n}${dup ? `, ${dup} already present` : ''}`); App.refresh();
    };
    el.addEventListener('click', async (ev) => {
      const t = ev.target;
      if (t.dataset.pivot) { const e = App.entity(t.dataset.pivot); App.go('pivot', { q: e.value, type: e.type }); }
      else if (t.dataset.edit) { if (await editEntityDlg(t.dataset.edit)) draw(); }
      else if (t.id === 'delSel') {
        const ids = [...entState.selected];
        if (await confirmDlg(`Delete ${plural(ids.length, 'entity', 'entities')} and their links?`, { title: 'Delete entities', ok: 'Delete', danger: true })) {
          ids.forEach((id) => App.removeEntity(id)); entState.selected.clear(); App.touch(`Deleted ${ids.length} entities`); App.refresh();
        }
      } else if (t.id === 'tagSel') {
        const r = await formDlg('Tag selected', [{ name: 'tags', label: 'Tags to add (comma-separated)', required: true }]);
        if (r) { const add = normTags(r.tags); entState.selected.forEach((id) => { const e = App.entity(id); if (e) e.tags = [...new Set([...(e.tags || []), ...add])]; }); App.touch(`Tagged ${entState.selected.size} entities`); draw(); }
      } else if (t.id === 'linkSel') {
        const [first, ...rest] = [...entState.selected];
        const r = await formDlg('Link to first selected', [{ name: 'label', label: 'Relationship', placeholder: 'e.g. associated with' }]);
        if (r) { rest.forEach((id) => App.addLink(id, first, r.label)); App.touch(`Linked ${rest.length} entities to ${App.entity(first)?.value}`); toast(`${rest.length} link(s) created`); draw(); }
      }
    });
    el.addEventListener('change', (ev) => {
      const t = ev.target;
      if (t.dataset.sel) { t.checked ? entState.selected.add(t.dataset.sel) : entState.selected.delete(t.dataset.sel); draw(); }
      else if (t.id === 'selAll') { $$('[data-sel]', el).forEach((cb) => (t.checked ? entState.selected.add(cb.dataset.sel) : entState.selected.delete(cb.dataset.sel))); draw(); }
    });
  },
});

// ---------------------------------------------------------------- Notes
App.register({
  id: 'notes', label: 'Notes', icon: 'notes',
  render(el) {
    const c = App.case;
    el.innerHTML = `
      ${viewHead('Case notes', 'Free-form working notes (Markdown friendly). Saved automatically, included in the report.',
        `<button class="btn" id="ts" title="Insert the current UTC time at the cursor">Insert UTC timestamp</button><button class="btn" id="ext">Extract selectors</button><button class="btn" id="dl">Download .md</button>`)}
      <textarea id="notes" style="min-height:calc(100vh - 230px);font-size:13.5px" placeholder="## Hypotheses\n- …\n\n## Findings\n- …\n\n## Open questions\n- …">${esc(c.notes)}</textarea>
      <div class="row mt small muted"><span id="saved">Saved</span><span class="spacer"></span><span id="wc"></span></div>`;
    const ta = $('#notes', el);
    const wc = () => { $('#wc', el).textContent = `${(ta.value.match(/\S+/g) || []).length} words`; };
    wc();
    const persist = debounce(() => { c.notes = ta.value; App.touch(); $('#saved', el).textContent = `Saved ${fmtUTC(nowISO()).slice(11)}`; }, 400);
    ta.addEventListener('input', () => { $('#saved', el).textContent = 'Saving…'; wc(); persist(); });
    $('#ts', el).onclick = () => {
      const s = `[${fmtUTC(nowISO())}] `; const p = ta.selectionStart;
      ta.setRangeText(s, p, ta.selectionEnd, 'end'); ta.focus(); ta.dispatchEvent(new Event('input'));
    };
    $('#ext', el).onclick = () => App.go('extractor', { text: ta.value });
    $('#dl', el).onclick = () => download(`${slug(c.name)}-notes.md`, ta.value, 'text/markdown');
    return () => { if (ta.value !== c.notes) { c.notes = ta.value; App.touch(); } };
  },
});
