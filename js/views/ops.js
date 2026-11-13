'use strict';
/* Lantern — reporting, OPSEC/methodology, settings & data management. */

const OPSEC_ITEMS = [
  { id: 'scope', phase: 'Plan', text: 'Define the question, scope and legal basis (authorization, terms of service, privacy law).' },
  { id: 'minimize', phase: 'Plan', text: 'Decide what personal data you will not collect (data minimization).' },
  { id: 'isolate', phase: 'Environment', text: 'Work in an isolated browser profile or research VM.' },
  { id: 'network', phase: 'Environment', text: 'Mask your network origin (VPN / Tor) where attribution matters.' },
  { id: 'puppet', phase: 'Environment', text: 'Use research accounts — never personal ones — and keep them separated.' },
  { id: 'passive', phase: 'Environment', text: 'Stay passive: no follows, likes, friend requests or messages to subjects.' },
  { id: 'archive', phase: 'Collect', text: 'Archive key pages (Wayback / archive.today) before relying on them.' },
  { id: 'hash', phase: 'Collect', text: 'Hash every downloaded file and log it in Evidence.' },
  { id: 'utc', phase: 'Collect', text: 'Record times in UTC and note the original time zone.' },
  { id: 'logkeep', phase: 'Collect', text: 'Keep the activity log on so searches and pivots are reproducible.' },
  { id: 'corroborate', phase: 'Analyze', text: 'Corroborate key findings with at least two independent sources.' },
  { id: 'grade', phase: 'Analyze', text: 'Grade source reliability and information credibility on key entities.' },
  { id: 'alternatives', phase: 'Analyze', text: 'Test alternative explanations (competing hypotheses) before concluding.' },
  { id: 'misattribution', phase: 'Analyze', text: 'Rule out misattribution: shared usernames, recycled photos, spoofed metadata.' },
  { id: 'confidence', phase: 'Report', text: 'State confidence levels, gaps and limitations explicitly.' },
  { id: 'redact', phase: 'Report', text: 'Redact personal data of uninvolved third parties.' },
  { id: 'retention', phase: 'Report', text: 'Store exports securely and delete case data when retention ends.' },
];

// ---------------------------------------------------------------- report
const rpState = { sections: { summary: true, hypotheses: true, entities: true, links: true, timeline: true, evidence: true, notes: true, log: false }, defang: false };
const DEFANG_TYPES = new Set(['url', 'domain', 'email', 'ipv4', 'ipv6']);
const mdCell = (s) => String(s ?? '').replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');

function buildReport(c, opt) {
  const v = (e) => (opt.defang && DEFANG_TYPES.has(e.type) ? defang(e.value) : e.value);
  const ent = (id) => c.entities.find((e) => e.id === id);
  const L = [];
  L.push(`# ${c.name}`, '');
  L.push(`**Status:** ${c.status} · **Case opened:** ${fmtUTC(c.created)} · **Report generated:** ${fmtUTC(nowISO())}`, '');
  if (c.description) L.push('## Scope & objective', '', c.description, '');
  if (opt.sections.summary) {
    const byType = {}; c.entities.forEach((e) => (byType[e.type] = (byType[e.type] || 0) + 1));
    L.push('## Summary', '', `- **${c.entities.length}** entities (${Object.entries(byType).map(([t, n]) => `${n} ${typeLabel(t).toLowerCase()}`).join(', ') || 'none'})`, `- **${c.links.length}** relationships`, `- **${c.events.length}** timeline events`, `- **${c.evidence.length}** evidence items`, '');
    const done = OPSEC_ITEMS.filter((i) => c.checklist[i.id]).length;
    L.push(`- Methodology checklist: ${done}/${OPSEC_ITEMS.length} steps completed`, '');
  }
  if (opt.sections.hypotheses) L.push(...achMarkdown(c));
  if (opt.sections.entities && c.entities.length) {
    L.push('## Entities', '');
    const order = Object.keys(TYPES);
    const groups = {}; c.entities.forEach((e) => (groups[e.type] = groups[e.type] || []).push(e));
    for (const t of Object.keys(groups).sort((a, b) => order.indexOf(a) - order.indexOf(b))) {
      L.push(`### ${typeLabel(t)} (${groups[t].length})`, '', '| Value | Label | Grade | Tags | Source | Notes |', '|---|---|---|---|---|---|');
      groups[t].forEach((e) => L.push(`| \`${mdCell(v(e))}\` | ${mdCell(e.label)} | ${mdCell(grade(e))} | ${mdCell((e.tags || []).join(', '))} | ${mdCell(e.source)} | ${mdCell(e.notes)} |`));
      L.push('');
    }
  }
  if (opt.sections.links && c.links.length) {
    L.push('## Relationships', '');
    c.links.forEach((l) => { const a = ent(l.from), b = ent(l.to); if (a && b) L.push(`- \`${v(a)}\` —${l.label ? ` *${l.label}* ` : ''}→ \`${v(b)}\``); });
    L.push('');
  }
  if (opt.sections.timeline && c.events.length) {
    L.push('## Timeline (UTC)', '', '| When | Event | Category | Entities | Source |', '|---|---|---|---|---|');
    [...c.events].sort((a, b) => a.when.localeCompare(b.when)).forEach((e) => L.push(`| ${fmtWhen(e)} | ${mdCell(e.title)}${e.details ? ` — ${mdCell(e.details)}` : ''} | ${mdCell(e.category)} | ${mdCell((e.entityIds || []).map((id) => ent(id) && v(ent(id))).filter(Boolean).join(', '))} | ${mdCell(e.source)} |`));
    L.push('');
  }
  if (opt.sections.evidence && c.evidence.length) {
    L.push('## Evidence & chain of custody', '', '| Ref | Captured (UTC) | Item | SHA-256 | Source / archive |', '|---|---|---|---|---|');
    c.evidence.forEach((x) => L.push(`| ${x.ref} | ${fmtUTC(x.capturedAt)} | ${mdCell(x.title)}${x.size ? ` (${fmtBytes(x.size)})` : ''} | ${x.sha256 ? `\`${x.sha256}\`` : '—'} | ${mdCell([opt.defang && x.url ? defang(x.url) : x.url, x.archiveUrl].filter(Boolean).join(' · '))} |`));
    L.push('');
  }
  // Notes headings are demoted one level so they nest under “Analyst notes”.
  if (opt.sections.notes && c.notes.trim()) L.push('## Analyst notes', '', c.notes.trim().replace(/^(#{1,5})\s/gm, '#$1 '), '');
  if (opt.sections.log && c.log.length) { L.push('## Research activity log', ''); [...c.log].reverse().forEach((l) => L.push(`- ${fmtUTC(l.t)} — ${opt.defang ? defang(l.msg) : l.msg}`)); L.push(''); }
  L.push('---', `*Generated with Lantern OSINT Workbench.${opt.defang ? ' Indicators are defanged.' : ''} Source grades use the Admiralty system (reliability A–F, credibility 1–6).*`);
  return L.join('\n');
}

/** STIX 2.1 bundle: one report plus cyber-observables for the technical selectors, and relationships between them. */
function buildStix(c) {
  const uuid = () => (crypto.randomUUID ? crypto.randomUUID() : 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (ch) => { const r = (Math.random() * 16) | 0; return (ch === 'x' ? r : (r & 3) | 8).toString(16); }));
  const SCO = {
    domain: (v) => ({ type: 'domain-name', value: v }), ipv4: (v) => ({ type: 'ipv4-addr', value: v }), ipv6: (v) => ({ type: 'ipv6-addr', value: v }),
    url: (v) => ({ type: 'url', value: v }), email: (v) => ({ type: 'email-addr', value: v }), mac: (v) => ({ type: 'mac-addr', value: v.replace(/-/g, ':') }),
    asn: (v) => ({ type: 'autonomous-system', number: +v.replace(/^AS/i, '') }), username: (v) => ({ type: 'user-account', account_login: v }),
    hash: (v) => { const a = { 32: 'MD5', 40: 'SHA-1', 64: 'SHA-256', 128: 'SHA-512' }[v.length]; return a && /^[a-f0-9]+$/.test(v) ? { type: 'file', hashes: { [a]: v } } : null; },
    btc: (v) => ({ type: 'x-crypto-wallet', value: v, chain: 'bitcoin' }), eth: (v) => ({ type: 'x-crypto-wallet', value: v, chain: 'evm' }),
    cve: (v) => ({ type: 'vulnerability', name: v, external_references: [{ source_name: 'cve', external_id: v }] }),
    person: (v) => ({ type: 'identity', name: v, identity_class: 'individual' }), org: (v) => ({ type: 'identity', name: v, identity_class: 'organization' }),
  };
  const now = nowISO(), ids = new Map(), objects = [];
  for (const e of c.entities) {
    const o = SCO[e.type]?.(e.value); if (!o) continue;
    o.spec_version = '2.1'; o.id = `${o.type}--${uuid()}`;
    if (o.type === 'vulnerability' || o.type === 'identity') { o.created = e.created || now; o.modified = now; if (e.notes) o.description = e.notes; if (e.tags?.length) o.labels = e.tags; }
    ids.set(e.id, o.id); objects.push(o);
  }
  for (const l of c.links) { const a = ids.get(l.from), b = ids.get(l.to); if (a && b) objects.push({ type: 'relationship', spec_version: '2.1', id: `relationship--${uuid()}`, created: l.created || now, modified: now, relationship_type: (l.label || 'related-to').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'related-to', source_ref: a, target_ref: b }); }
  const report = { type: 'report', spec_version: '2.1', id: `report--${uuid()}`, created: c.created, modified: now, name: c.name, description: c.description || '', published: now, report_types: ['threat-report'], object_refs: objects.map((o) => o.id) };
  return { type: 'bundle', id: `bundle--${uuid()}`, objects: objects.length ? [report, ...objects] : [] };
}

/** Minimal Markdown → HTML for the subset the report uses (and typical notes). Input is escaped first. */
function mdToHtml(md) {
  const inline = (s) => esc(s).replace(/`([^`]+)`/g, '<code>$1</code>').replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>').replace(/(^|[^*])\*([^*]+)\*/g, '$1<em>$2</em>');
  const lines = md.split('\n'); const out = []; let i = 0;
  while (i < lines.length) {
    const l = lines[i];
    if (/^\|.*\|$/.test(l) && /^\|[-| :]+\|$/.test(lines[i + 1] || '')) {
      const cells = (r) => r.slice(1, -1).split(/(?<!\\)\|/).map((c) => c.trim().replace(/\\\|/g, '|'));
      const head = cells(l); i += 2; const rows = [];
      while (i < lines.length && /^\|.*\|$/.test(lines[i])) rows.push(cells(lines[i++]));
      out.push(`<table><thead><tr>${head.map((h) => `<th>${inline(h)}</th>`).join('')}</tr></thead><tbody>${rows.map((r) => `<tr>${r.map((c) => `<td>${inline(c)}</td>`).join('')}</tr>`).join('')}</tbody></table>`);
      continue;
    }
    const h = l.match(/^(#{1,4})\s+(.*)/);
    if (h) { out.push(`<h${h[1].length}>${inline(h[2])}</h${h[1].length}>`); i++; continue; }
    if (/^---+$/.test(l)) { out.push('<hr>'); i++; continue; }
    if (/^\s*[-*]\s+/.test(l)) { const items = []; while (i < lines.length && /^\s*[-*]\s+/.test(lines[i])) items.push(`<li>${inline(lines[i++].replace(/^\s*[-*]\s+/, ''))}</li>`); out.push(`<ul>${items.join('')}</ul>`); continue; }
    if (!l.trim()) { i++; continue; }
    const para = []; while (i < lines.length && lines[i].trim() && !/^(#{1,4}\s|\||---|\s*[-*]\s)/.test(lines[i])) para.push(inline(lines[i++]));
    out.push(`<p>${para.join('<br>')}</p>`);
  }
  return out.join('\n');
}
function reportHtml(title, md) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)}</title>
<style>body{font:14px/1.55 system-ui,-apple-system,"Segoe UI",sans-serif;color:#0b0b0b;background:#fff;max-width:1000px;margin:32px auto;padding:0 20px}h1{font-size:26px;margin-bottom:4px}h2{margin-top:32px;border-bottom:1px solid #e1e0d9;padding-bottom:4px}h3{margin-top:20px}table{border-collapse:collapse;width:100%;font-size:12.5px;margin:8px 0 16px}th,td{border:1px solid #e1e0d9;padding:5px 8px;text-align:left;vertical-align:top}th{background:#f2f1ed}code{font:12px ui-monospace,Consolas,monospace;background:#f2f1ed;padding:1px 4px;border-radius:3px;word-break:break-all}hr{border:0;border-top:1px solid #e1e0d9;margin:28px 0}em{color:#52514e}@media print{body{margin:0}h2{break-after:avoid}tr{break-inside:avoid}}</style></head><body>${mdToHtml(md)}</body></html>`;
}

App.register({
  id: 'report', label: 'Report', icon: 'report',
  render(el) {
    const c = App.case;
    const S = [['summary', 'Summary'], ['hypotheses', 'Hypotheses'], ['entities', 'Entities'], ['links', 'Relationships'], ['timeline', 'Timeline'], ['evidence', 'Evidence'], ['notes', 'Notes'], ['log', 'Activity log']];
    el.innerHTML = `
      ${viewHead('Report', 'Generate a structured case report. Markdown for wikis and tickets, a printable HTML page (print → PDF), or a full JSON export for hand-off.',
        `<button class="btn" id="rstix" title="Indicators as a STIX 2.1 bundle for threat-intel platforms (MISP, OpenCTI…)">STIX 2.1</button><button class="btn" id="rjson">Export case JSON</button><button class="btn" id="rhtml">Download HTML</button><button class="btn" id="rmd">Download .md</button><button class="btn primary" id="rcopy">Copy Markdown</button>`)}
      <div class="card row">${S.map(([k, l]) => `<label class="check"><input type="checkbox" data-sec="${k}" ${rpState.sections[k] ? 'checked' : ''}> ${l}</label>`).join('')}<span class="spacer"></span><label class="check"><input type="checkbox" id="rdef" ${rpState.defang ? 'checked' : ''}> Defang indicators</label><button class="btn ghost" id="rprint">Print / PDF</button></div>
      <div class="grid g2 mt"><div class="card"><h3>Markdown</h3><pre class="out" id="rmdout" style="max-height:70vh"></pre></div><div class="card"><h3>Preview</h3><iframe id="rprev" title="Report preview" sandbox="allow-same-origin allow-modals" style="width:100%;height:70vh;border:1px solid var(--line);border-radius:8px;background:#fff"></iframe></div></div>`;
    let md = '';
    const draw = () => { md = buildReport(c, rpState); $('#rmdout', el).textContent = md; $('#rprev', el).srcdoc = reportHtml(c.name, md); };
    el.addEventListener('change', (e) => { if (e.target.dataset.sec) rpState.sections[e.target.dataset.sec] = e.target.checked; if (e.target.id === 'rdef') rpState.defang = e.target.checked; draw(); });
    $('#rcopy', el).onclick = () => copyText(md);
    $('#rmd', el).onclick = () => download(`${slug(c.name)}-report.md`, md, 'text/markdown');
    $('#rhtml', el).onclick = () => download(`${slug(c.name)}-report.html`, reportHtml(c.name, md), 'text/html');
    $('#rjson', el).onclick = () => exportCase(c);
    $('#rstix', el).onclick = () => { const b = buildStix(c); if (b.objects.length < 2) return toast('No indicator-type entities to export', 'error'); download(`${slug(c.name)}-stix.json`, JSON.stringify(b, null, 2), 'application/json'); App.touch(`Exported STIX bundle (${b.objects.length - 1} objects)`); };
    $('#rprint', el).onclick = () => { const f = $('#rprev', el); try { f.contentWindow.focus(); f.contentWindow.print(); } catch { toast('Download the HTML and print it from your browser', 'error'); } };
    draw();
  },
});

// ---------------------------------------------------------------- OPSEC & methodology
App.register({
  id: 'opsec', label: 'OPSEC & method', icon: 'opsec',
  render(el) {
    const c = App.case;
    const phases = [...new Set(OPSEC_ITEMS.map((i) => i.phase))];
    const done = OPSEC_ITEMS.filter((i) => c.checklist[i.id]).length;
    el.innerHTML = `
      ${viewHead('OPSEC & methodology', 'A per-case checklist for disciplined, defensible open-source research. Progress is saved with the case and summarized in the report.')}
      <div class="row mb"><div class="progress" style="flex:1;max-width:480px"><div style="width:${(done / OPSEC_ITEMS.length) * 100}%"></div></div><span class="ink2 small">${done} of ${OPSEC_ITEMS.length} complete</span></div>
      <div class="grid g2">
        <div class="stack">${phases.map((p) => `<div class="card"><h3>${esc(p)}</h3><ul class="checklist">${OPSEC_ITEMS.filter((i) => i.phase === p).map((i) => `<li class="${c.checklist[i.id] ? 'done' : ''}"><input type="checkbox" id="ck_${i.id}" data-check="${i.id}" ${c.checklist[i.id] ? 'checked' : ''}><label for="ck_${i.id}"><span>${esc(i.text)}</span></label></li>`).join('')}</ul></div>`).join('')}</div>
        <div class="stack">
          <div class="card"><h3>Admiralty grading</h3><p class="card-sub">Grade the <b>source</b> and the <b>information</b> independently. “B2” = usually reliable source, probably true.</p>
            <table class="tbl"><thead><tr><th>Source reliability</th><th>Information credibility</th></tr></thead><tbody>${RELIABILITY.slice(1).map(([, r], i) => `<tr><td>${esc(r)}</td><td>${esc(CREDIBILITY[i + 1][1])}</td></tr>`).join('')}</tbody></table></div>
          <div class="card"><h3>Ground rules</h3><ul class="small ink2" style="padding-left:18px;margin:0">
            <li>Only collect what answers your question. Public ≠ fair game for everything.</li>
            <li>Never use leaked credentials, bypass logins or access controls, or impersonate real people.</li>
            <li>Viewing some profiles notifies the owner (e.g. LinkedIn) — use logged-out or research accounts.</li>
            <li>Platform-stripped photos carry no EXIF; absence of metadata proves nothing.</li>
            <li>Screenshots aren’t enough: archive the URL, hash the file, note the UTC time.</li>
            <li>Usernames are not unique identities. Corroborate with independent selectors before linking accounts.</li>
            <li>When you find something alarming (threats, exploitation, imminent harm), stop and escalate to the appropriate authority.</li></ul></div>
          <div class="card"><h3>This tool’s footprint</h3><ul class="small ink2" style="padding-left:18px;margin:0">
            <li>No analytics, fonts, CDNs or third-party scripts. Data lives in this browser’s local storage only.</li>
            <li>In <b>Passive</b> mode the app makes no network requests at all.</li>
            <li>Pivot links open in new tabs with no referrer. The sites you open <b>do</b> see your IP and query.</li>
            <li><b>Active lookups</b> (Recon, lookalike checks) call public APIs, never the target directly: <span class="small">${esc(ACTIVE_SERVICES)}.</span></li></ul></div>
        </div>
      </div>`;
    el.addEventListener('change', (e) => { const k = e.target.dataset.check; if (k) { c.checklist[k] = e.target.checked; App.touch(e.target.checked ? `Checklist: ${OPSEC_ITEMS.find((i) => i.id === k).text}` : null); App.refresh(); } });
  },
});

// ---------------------------------------------------------------- settings & data
function exportCase(c) {
  download(`${slug(c.name)}-${fmtUTC(nowISO()).slice(0, 10)}.lantern.json`, JSON.stringify({ format: 'lantern-case', version: 1, exported: nowISO(), case: c }, null, 2), 'application/json');
  App.touch('Exported case JSON');
}
function importData(obj) {
  const cases = obj?.format === 'lantern-case' ? [obj.case] : obj?.format === 'lantern-backup' ? Object.values(obj.state?.cases || {}) : obj?.cases ? Object.values(obj.cases) : obj?.entities ? [obj] : [];
  let n = 0;
  for (const raw of cases) {
    if (!raw || typeof raw !== 'object' || !Array.isArray(raw.entities)) continue;
    const c = migrate({ cases: { x: JSON.parse(JSON.stringify(raw)) }, activeCaseId: 'x' }).cases.x;
    if (App.state.cases[c.id]) { c.id = uid(); c.name += ' (imported)'; }
    c.log.unshift({ t: nowISO(), msg: 'Imported into this workbench' });
    App.state.cases[c.id] = c; App.state.activeCaseId = c.id; n++;
  }
  App.saveNow(); App.renderChrome();
  return n;
}

App.register({
  id: 'settings', label: 'Settings & data', icon: 'settings',
  render(el) {
    const s = App.settings;
    const bytes = new Blob([JSON.stringify(App.state)]).size;
    const cases = Object.values(App.state.cases).sort((a, b) => b.updated.localeCompare(a.updated));
    el.innerHTML = `
      ${viewHead('Settings & data', 'Everything is stored locally in this browser. Export regularly — clearing site data deletes your cases.')}
      <div class="grid g2">
        <div class="card"><h3>Preferences</h3>
          <label class="check field"><input type="checkbox" data-set="activeLookups" ${s.activeLookups ? 'checked' : ''}> Active lookups (Recon & lookalike DNS checks call public APIs)</label>
          <label class="check field"><input type="checkbox" data-set="logPivots" ${s.logPivots ? 'checked' : ''}> Record every pivot, dork and recon run in the case activity log</label>
          <label class="check field"><input type="checkbox" data-set="autoLink" ${s.autoLink ? 'checked' : ''}> Auto-link implied relationships when entities are added (email → domain, URL → domain, subdomain → parent)</label>
          <label class="field" style="max-width:240px"><span>Theme</span><select id="stheme">${['system', 'dark', 'light'].map((t) => `<option ${s.theme === t ? 'selected' : ''}>${t}</option>`).join('')}</select></label>
        </div>
        <div class="card"><h3>Backup &amp; restore</h3>
          <p class="card-sub">Stored: <b>${fmtBytes(bytes)}</b> across ${plural(cases.length, 'case')} (browser limit is ~5 MB).</p>
          ${bytes > 4e6 ? '<div class="banner warn mb"><span>⚠</span><div class="grow small">Approaching the browser storage limit. Export and archive closed cases.</div></div>' : ''}
          <div class="row"><button class="btn primary" id="sbackup">Export full backup</button><button class="btn" id="simport">Import case / backup…</button></div>
          <div class="row mt"><button class="btn danger" id="swipe">Erase all data</button></div>
        </div>
      </div>
      <div class="card mt"><h3>Cases</h3>
        <div class="tbl-wrap"><table class="tbl"><thead><tr><th>Case</th><th>Status</th><th class="num">Entities</th><th class="num">Events</th><th class="num">Evidence</th><th>Updated</th><th></th></tr></thead><tbody>
        ${cases.map((c) => `<tr><td><b>${esc(c.name)}</b>${c.id === App.state.activeCaseId ? ' <span class="chip">active</span>' : ''}<div class="small muted">${esc(trunc(c.description, 100))}</div></td><td><span class="status ${c.status === 'closed' ? 'warn' : 'good'}">${c.status}</span></td><td class="num">${c.entities.length}</td><td class="num">${c.events.length}</td><td class="num">${c.evidence.length}</td><td class="small mono nowrap">${esc(fmtUTC(c.updated, false))}</td>
          <td class="actions">${c.id !== App.state.activeCaseId ? `<button class="btn sm" data-open="${esc(c.id)}">Open</button>` : ''} <button class="btn sm ghost" data-exp="${esc(c.id)}">Export</button> <button class="btn sm ghost" data-dup="${esc(c.id)}">Duplicate</button> <button class="btn sm ghost danger" data-del="${esc(c.id)}">Delete</button></td></tr>`).join('')}
        </tbody></table></div></div>`;
    el.addEventListener('change', (e) => {
      const k = e.target.dataset.set;
      if (k === 'activeLookups') { e.target.checked = s.activeLookups; App.toggleActive(); return; }
      if (k) { s[k] = e.target.checked; App.saveNow(); toast('Saved'); }
      if (e.target.id === 'stheme') { s.theme = e.target.value; App.applyTheme(); App.saveNow(); }
    });
    $('#sbackup', el).onclick = () => download(`lantern-backup-${fmtUTC(nowISO()).slice(0, 10)}.json`, JSON.stringify({ format: 'lantern-backup', version: 1, exported: nowISO(), state: App.state }, null, 2), 'application/json');
    $('#simport', el).onclick = () => {
      const i = document.createElement('input'); i.type = 'file'; i.accept = '.json,application/json';
      i.onchange = async () => {
        try { const n = importData(JSON.parse(await readFileAs(i.files[0], 'text'))); toast(n ? `Imported ${plural(n, 'case')}` : 'No cases found in that file', n ? '' : 'error'); App.refresh(); }
        catch (err) { toast('Import failed: ' + err.message, 'error'); }
      };
      i.click();
    };
    $('#swipe', el).onclick = async () => {
      if (!(await confirmDlg('Permanently erase every case, entity, note and setting stored by Lantern in this browser? Export a backup first if you might need it.', { title: 'Erase all data', ok: 'Erase everything', danger: true }))) return;
      localStorage.removeItem(STORE_KEY); App.state = defaultState(); App.saveNow(); App.applyTheme(); App.renderChrome(); App.go('dashboard'); toast('All data erased');
    };
    el.addEventListener('click', async (e) => {
      const b = e.target.closest('button'); if (!b) return;
      const c = App.state.cases[b.dataset.open || b.dataset.exp || b.dataset.dup || b.dataset.del];
      if (!c) return;
      if (b.dataset.open) { App.switchCase(c.id); App.go('dashboard'); }
      if (b.dataset.exp) exportCase(c);
      if (b.dataset.dup) { const d = JSON.parse(JSON.stringify(c)); d.id = uid(); d.name += ' (copy)'; d.created = d.updated = nowISO(); App.state.cases[d.id] = d; App.saveNow(); App.renderChrome(); App.refresh(); toast('Case duplicated'); }
      if (b.dataset.del) {
        if (!(await confirmDlg(`Delete case “${c.name}” with ${plural(c.entities.length, 'entity', 'entities')}? This cannot be undone.`, { title: 'Delete case', ok: 'Delete case', danger: true }))) return;
        delete App.state.cases[c.id];
        if (!Object.keys(App.state.cases).length) { const n = newCase(); App.state.cases[n.id] = n; }
        if (!App.state.cases[App.state.activeCaseId]) App.state.activeCaseId = Object.keys(App.state.cases)[0];
        App.saveNow(); App.renderChrome(); App.refresh(); toast('Case deleted');
      }
    });
  },
});
