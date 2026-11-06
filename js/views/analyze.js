'use strict';
/* Lantern — Metadata analyzer view. Everything is parsed locally; files never leave the browser. */

const mdState = { results: [] };
const FLAG_CLASS = { crit: 'crit', warn: 'warn', info: 'good' };
const FLAG_LABEL = { crit: 'Critical', warn: 'Notable', info: 'Info' };
/** Zone-less timestamps (camera local time) are treated as UTC, as the UI states. */
const toUTCiso = (s) => { const t = /T\d\d:\d\d(:\d\d(\.\d+)?)?$/.test(s) ? s + 'Z' : s; const d = new Date(t); return isNaN(d) ? null : d.toISOString(); };

App.register({
  id: 'metadata', label: 'Metadata', icon: 'metadata',
  render(el) {
    el.innerHTML = `
      ${viewHead('File metadata analyzer', 'Drop photos, PDFs, Office documents or executables. Extracts EXIF & GPS, camera serials, authors and editors, edit history, hidden sheets, AI-generation markers and C2PA manifests — entirely in your browser.',
        mdState.results.length ? '<button class="btn ghost" id="mclear">Clear results</button>' : '')}
      <div class="drop" id="mdrop"><b>Drop files here</b> or click to choose<br><span class="small">JPEG · PNG · WebP · TIFF/RAW · GIF · PDF · DOCX/XLSX/PPTX · ODF · ZIP · EXE/DLL</span></div>
      <div id="mres" class="stack mt"></div>`;
    const box = $('#mres', el);
    const drawOne = (r, i) => {
      const groups = {}; r.fields.forEach((f) => (groups[f.group] = groups[f.group] || []).push(f));
      const g = r.gps;
      return `<div class="card" data-i="${i}">
        <h3 class="break">${esc(r.name)}<span class="spacer"></span><span class="chip">${esc(r.kind)}</span><span class="chip">${esc(fmtBytes(r.size))}</span></h3>
        <div class="row mb">
          <button class="btn sm primary" data-a="evidence">Log as evidence</button>
          ${g ? `<button class="btn sm" data-a="loc">+ Add GPS location to case</button>` : ''}
          ${r.dates.length ? `<button class="btn sm" data-a="dates">Send ${plural(r.dates.length, 'date')} to timeline</button>` : ''}
          <button class="btn sm ghost" data-a="ext">Extract selectors from fields</button>
          <button class="btn sm ghost" data-a="json">Copy JSON</button>
        </div>
        <div class="grid" style="grid-template-columns:${r.preview ? 'minmax(0,1fr) 220px' : 'minmax(0,1fr)'}">
          <div>
            ${r.flags.length ? `<div class="stack" style="margin-bottom:14px">${r.flags.map((f) => `<div class="row nowrap small" style="margin-top:4px;align-items:flex-start"><span class="status ${FLAG_CLASS[f.level]} nowrap" style="min-width:74px">${FLAG_LABEL[f.level]}</span><span>${esc(f.text)}</span></div>`).join('')}</div>` : ''}
            ${g ? `<div class="banner" style="margin-bottom:14px"><span>📍</span><div class="grow small"><b class="mono">${g.lat}, ${g.lon}</b>${g.alt !== null ? ` · alt ${g.alt.toFixed(0)} m` : ''}${g.dir !== null ? ` · facing ${g.dir.toFixed(0)}°` : ''}${g.utc ? ` · ${esc(fmtUTC(g.utc))}` : ''}
              <div class="row" style="margin-top:6px">${[['Google Maps', `https://www.google.com/maps/search/?api=1&query=${g.lat},${g.lon}`], ['Street View', `https://www.google.com/maps/@?api=1&map_action=pano&viewpoint=${g.lat},${g.lon}${g.dir !== null ? `&heading=${Math.round(g.dir)}` : ''}`], ['OpenStreetMap', `https://www.openstreetmap.org/?mlat=${g.lat}&mlon=${g.lon}#map=17/${g.lat}/${g.lon}`], ['SunCalc', `https://www.suncalc.org/#/${g.lat},${g.lon},17/null/null/null/null`]].map(([n, u]) => `<a class="lnk" href="${esc(u)}" target="_blank" rel="noopener noreferrer">${n}</a>`).join('')}<a class="lnk" data-a="pivotloc">All location pivots</a></div></div></div>` : ''}
            ${Object.entries(groups).map(([grp, fs]) => `<div style="margin-bottom:12px"><div class="small muted" style="font-weight:650;text-transform:uppercase;letter-spacing:.06em;font-size:10.5px;margin-bottom:4px">${esc(grp)}</div><dl class="kv">${fs.map((f) => `<dt>${esc(f.key)}</dt><dd class="${/serial|ID|hash|Coordinates/i.test(f.key) ? 'mono' : ''}" style="white-space:pre-wrap">${esc(f.value)}</dd>`).join('')}</dl></div>`).join('')}
            ${r.dates.length ? `<div style="margin-bottom:12px"><div class="small muted" style="font-weight:650;text-transform:uppercase;letter-spacing:.06em;font-size:10.5px;margin-bottom:4px">Timestamps found</div>${r.dates.map((d, di) => `<div class="row small"><span class="mono">${esc(d.iso)}</span><span class="ink2">${esc(d.label)}${d.note ? ` (${esc(d.note)})` : ''}</span><a href="#" data-a="date" data-d="${di}">→ timeline</a></div>`).join('')}</div>` : ''}
            <div class="small muted" style="font-weight:650;text-transform:uppercase;letter-spacing:.06em;font-size:10.5px;margin-bottom:4px">Fingerprints</div>
            <dl class="kv">${['md5', 'sha1', 'sha256'].filter((k) => r.hashes[k]).map((k) => `<dt>${k.toUpperCase()}</dt><dd class="mono break" data-copy="${r.hashes[k]}" style="cursor:copy" title="Click to copy">${r.hashes[k]}</dd>`).join('')}
              ${r.lastModified ? `<dt>File system mtime</dt><dd class="mono">${esc(fmtUTC(r.lastModified))} <span class="muted small">(from your disk — not evidential)</span></dd>` : ''}</dl>
            <div class="row mt"><a class="lnk" href="https://www.virustotal.com/gui/file/${r.hashes.sha256}" target="_blank" rel="noopener noreferrer">VirusTotal by hash</a>${r.preview ? '<span class="muted small">For reverse image search, upload the file to Google Lens, Yandex, Bing or TinEye.</span>' : ''}</div>
            ${r.xmp ? `<details class="mt"><summary class="small ink2" style="cursor:pointer">Raw XMP packet (${fmtBytes(r.xmp.length)})</summary><pre class="out mt">${esc(r.xmp.slice(0, 50000))}</pre></details>` : ''}
          </div>
          ${r.preview ? `<div><img src="${r.preview}" alt="Preview of ${esc(r.name)}" style="width:100%;border-radius:8px;border:1px solid var(--line)"></div>` : ''}
        </div>
      </div>`;
    };
    const draw = () => { box.innerHTML = mdState.results.map(drawOne).join(''); };
    draw();
    fileDrop($('#mdrop', el), async (files) => {
      for (const f of files) {
        try {
          const r = await analyzeFile(f);
          if (/^image\/(jpeg|png|gif|webp|bmp|avif)/.test(f.type) && f.size < 60e6) r.preview = URL.createObjectURL(f);
          r._file = f;
          mdState.results.unshift(r);
          App.touch(`Metadata: analyzed ${f.name} (${r.kind})`);
        } catch (e) { console.error(e); toast(`${f.name}: ${e.message}`, 'error'); }
      }
      App.refresh();
    });
    $('#mclear', el)?.addEventListener('click', () => { mdState.results.forEach((r) => r.preview && URL.revokeObjectURL(r.preview)); mdState.results = []; App.refresh(); });
    box.addEventListener('click', async (e) => {
      const cp = e.target.closest('[data-copy]'); if (cp) return copyText(cp.dataset.copy);
      const a = e.target.closest('[data-a]'); if (!a) return;
      const r = mdState.results[+a.closest('[data-i]').dataset.i]; if (!r) return;
      const act = a.dataset.a;
      if (act === 'evidence') {
        if (App.case.evidence.some((x) => x.sha256 === r.hashes.sha256)) return toast('Already in the evidence log');
        await logFiles([r._file], { notes: `${r.kind}. ${r.flags.map((f) => f.text).join(' ')}`.slice(0, 1000) }); toast('Logged as evidence');
      } else if (act === 'loc' || act === 'pivotloc') {
        const v = `${r.gps.lat}, ${r.gps.lon}`;
        if (act === 'pivotloc') { e.preventDefault(); return App.go('pivot', { q: v, type: 'location' }); }
        const loc = App.addEntity('location', v, { label: `Photo GPS: ${r.name}`, source: r.name, notes: r.gps.utc ? `GPS fix ${r.gps.utc}` : '' });
        App.touch(loc.created ? `Added location from ${r.name}` : null); toast(loc.created ? 'Location added to case' : 'Location already in case');
      } else if (act === 'dates') {
        for (const d of r.dates) { const when = toUTCiso(d.iso); if (!when) continue; App.case.events.push({ id: uid(), created: nowISO(), when, precision: 'time', title: `${d.label}: ${r.name}`, category: 'Media captured', details: d.note ? `Note: ${d.note}. ` + (d.note.includes('local') ? 'Treated as UTC — adjust if the camera timezone is known.' : '') : '', source: r.name, entityIds: [] }); }
        App.touch(`Timeline: added ${r.dates.length} timestamps from ${r.name}`); toast(`${plural(r.dates.length, 'event')} added to timeline`);
      } else if (act === 'date') {
        e.preventDefault(); const d = r.dates[+a.dataset.d];
        addEventQuick({ when: toUTCiso(d.iso) || nowISO(), title: `${d.label}: ${r.name}`, category: 'Media captured', source: r.name, details: d.note || '' });
      } else if (act === 'ext') App.go('extractor', { text: r.fields.map((f) => `${f.key}: ${f.value}`).join('\n') + (r.xmp ? '\n' + r.xmp : '') });
      else if (act === 'json') { const { preview, _file, ...rest } = r; void preview; void _file; copyText(JSON.stringify(rest, null, 2)); }
    });
  },
});
