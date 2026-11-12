'use strict';
/* Lantern — Geo: coordinate converter, distance & bearing, and sun / shadow calculator for chronolocation.
   All maths is local (js/geo.js); map links are ordinary pivots. */

const geoState = { q: '', a: '', b: '', sunAt: '', date: '', time: '12:00', offset: '', by: 'bearing', val: '' };
const fmtKm = (m) => (m < 1000 ? `${m.toFixed(0)} m` : `${(m / 1000).toLocaleString(undefined, { maximumFractionDigits: m < 100000 ? 2 : 0 })} km`);
const hhmm = (ms, offMin = 0) => { const d = new Date(ms + offMin * 60000); return `${String(d.getUTCHours()).padStart(2, '0')}:${String(d.getUTCMinutes()).padStart(2, '0')}`; };
function parseOffset(s) {
  const m = String(s || '').trim().match(/^(?:UTC|GMT)?\s*([+\-−])?\s*(\d{1,2})(?::?(\d{2}))?$/i);
  if (!m) return null;
  const min = +m[2] * 60 + +(m[3] || 0);
  return Math.abs(min) <= 14 * 60 ? (m[1] === '-' || m[1] === '−' ? -min : min) : null;
}

App.register({
  id: 'geo', label: 'Geo & sun', icon: 'geo',
  render(el, params) {
    if (params.q) { geoState.q = params.q; geoState.sunAt = params.q; }
    if (!geoState.date) geoState.date = nowISO().slice(0, 10);
    const locs = App.case.entities.filter((e) => e.type === 'location' && parseCoords(e.value));
    el.innerHTML = `
      ${viewHead('Geo & sun', 'Convert coordinates between every notation, measure distance and bearing, and use the sun to test <b>when</b> or <b>where</b> an image was taken (chronolocation). Runs offline.')}
      <div class="grid g2">
        <div class="card"><h3>Coordinate converter</h3>
          <input id="gq" class="mono" style="width:100%" spellcheck="false" value="${esc(geoState.q)}" placeholder="48.8584, 2.2945 · 48°51′30″N 2°17′40″E · 31U DQ 48251 11932 · 8FW4V75V+8Q · Google/OSM map URL">
          ${locs.length ? `<div class="row mt small"><span class="muted">From case:</span>${locs.slice(0, 8).map((e) => `<a class="lnk" data-loc="${esc(e.value)}">${esc(trunc(e.label || e.value, 28))}</a>`).join('')}</div>` : ''}
          <div id="gout" class="mt"></div>
        </div>
        <div class="card"><h3>Distance &amp; bearing</h3>
          <div class="field-row"><label class="field"><span>Point A</span><input id="ga" class="mono" spellcheck="false" value="${esc(geoState.a)}" placeholder="lat, lon (any notation)"></label>
            <label class="field"><span>Point B</span><input id="gb" class="mono" spellcheck="false" value="${esc(geoState.b)}" placeholder="lat, lon (any notation)"></label></div>
          <div id="gdout"></div>
          <p class="muted small" style="margin-bottom:0">Great-circle distance on a spherical Earth (error ≤ 0.5%). Use it to test whether travel between two sightings was physically possible in the time available.</p>
        </div>
      </div>
      <div class="card mt"><h3>Sun &amp; shadows</h3>
        <p class="card-sub">Shadows point directly away from the sun, and their length depends on its height. Given a place and date, a measured shadow narrows down the time — or, given a claimed time, shows whether the shadows in an image are consistent with it.</p>
        <div class="field-row">
          <label class="field"><span>Location</span><input id="gs" class="mono" spellcheck="false" value="${esc(geoState.sunAt)}" placeholder="lat, lon"></label>
          <label class="field"><span>Date (UTC)</span><input id="gdate" type="date" value="${esc(geoState.date)}"></label>
          <label class="field"><span>Time (UTC)</span><input id="gtime" type="time" value="${esc(geoState.time)}"></label>
          <label class="field"><span>Local UTC offset (optional)</span><input id="goff" class="mono" value="${esc(geoState.offset)}" placeholder="+02:00"></label>
        </div>
        <div id="gsout"></div>
      </div>`;

    const kv = (rows) => `<dl class="kv">${rows.map(([k, v]) => `<dt>${esc(k)}</dt><dd class="mono break" data-copy="${esc(v)}" style="cursor:copy" title="Click to copy">${esc(v)}</dd>`).join('')}</dl>`;
    const drawConv = () => {
      geoState.q = $('#gq', el).value; const o = $('#gout', el);
      if (!geoState.q.trim()) { o.innerHTML = '<p class="muted small">Accepts decimal degrees, DMS, degrees + decimal minutes, MGRS, UTM, Plus Codes, geohashes and map URLs.</p>'; return; }
      const p = parseAnyCoords(geoState.q);
      if (!p) { o.innerHTML = '<span class="status crit">Unrecognised</span> <span class="small">Could not read that as a coordinate.</span>'; return; }
      const dd = `${+p.lat.toFixed(6)}, ${+p.lon.toFixed(6)}`;
      const inCase = App.findEntity('location', dd);
      o.innerHTML = `<div class="small muted mb">Read as ${esc(p.format)}</div>${kv(coordFormats(p.lat, p.lon))}
        <div class="row mt"><button class="btn sm primary" data-act="maps" data-v="${esc(dd)}">Maps &amp; imagery</button>${inCase ? '<span class="chip">✓ in case</span>' : `<button class="btn sm" data-act="add" data-v="${esc(dd)}">+ Add to case</button>`}<button class="btn sm ghost" data-act="sun" data-v="${esc(dd)}">Use for sun</button><button class="btn sm ghost" data-act="a" data-v="${esc(dd)}">→ A</button><button class="btn sm ghost" data-act="b" data-v="${esc(dd)}">→ B</button></div>`;
    };
    const drawDist = () => {
      geoState.a = $('#ga', el).value; geoState.b = $('#gb', el).value; const o = $('#gdout', el);
      const a = parseAnyCoords(geoState.a), b = parseAnyCoords(geoState.b);
      if (!a || !b) { o.innerHTML = geoState.a.trim() && geoState.b.trim() ? '<span class="status crit">Unrecognised</span> <span class="small">Check both points.</span>' : ''; return; }
      const d = haversine(a, b), brg = bearing(a, b), back = bearing(b, a), mid = midpoint(a, b);
      o.innerHTML = kv([['Distance', `${fmtKm(d)} · ${(d / 1609.344).toFixed(d < 16093 ? 2 : 0)} mi · ${(d / 1852).toFixed(d < 18520 ? 2 : 0)} nmi`], ['Bearing A → B', `${brg.toFixed(1)}° (${compass(brg)})`], ['Bearing B → A', `${back.toFixed(1)}° (${compass(back)})`], ['Midpoint', `${mid.lat.toFixed(6)}, ${mid.lon.toFixed(6)}`],
        ['Fastest plausible travel', `${fmtDuration((d / 1000 / 900) * 3600)} by airliner · ${fmtDuration((d / 1000 / 100) * 3600)} by road (100 km/h)`]]);
    };
    const drawSun = () => {
      geoState.sunAt = $('#gs', el).value; geoState.date = $('#gdate', el).value; geoState.time = $('#gtime', el).value || '12:00'; geoState.offset = $('#goff', el).value;
      const o = $('#gsout', el), p = parseAnyCoords(geoState.sunAt);
      if (!p || !/^\d{4}-\d\d-\d\d$/.test(geoState.date)) { o.innerHTML = geoState.sunAt.trim() ? '<span class="status crit">Unrecognised</span> <span class="small">Enter a location and a date.</span>' : '<p class="muted small">Enter a location to begin.</p>'; return; }
      const [Y, M, D] = geoState.date.split('-').map(Number), [h, mi] = geoState.time.split(':').map(Number);
      const ms = Date.UTC(Y, M - 1, D, h, mi), sp = sunPosition(ms, p.lat, p.lon), t = sunTimes(Date.UTC(Y, M - 1, D, 12), p.lat, p.lon);
      const off = parseOffset(geoState.offset), solarOff = Math.round(p.lon * 4);
      const loc = (x) => (x === null ? '—' : `${hhmm(x)} UTC${off !== null ? ` · ${hhmm(x, off)} local` : ''}`);
      const rows = [];
      const from = t.rise ?? t.noon - 12 * 3600000, to = t.set ?? t.noon + 12 * 3600000;
      for (let x = Math.ceil(from / 1800000) * 1800000; x <= to; x += 1800000) { const q = sunPosition(x, p.lat, p.lon); if (q.altitude > 0) rows.push([x, q]); }
      const up = sp.altitude > 0;
      o.innerHTML = `
        <div class="grid g2">
          <div>
            <h4 style="margin:0 0 6px">At ${esc(geoState.date)} ${esc(geoState.time)} UTC${off !== null ? ` (${hhmm(ms, off)} local)` : ''}</h4>
            ${up ? kv([['Sun azimuth', `${sp.azimuth.toFixed(1)}° (${compass(sp.azimuth)})`], ['Sun elevation', `${sp.altitude.toFixed(1)}°`], ['Shadows point toward', `${sp.shadowBearing.toFixed(1)}° (${compass(sp.shadowBearing)})`], ['Shadow length', Number.isFinite(sp.shadowRatio) ? `${sp.shadowRatio.toFixed(2)} × object height` : 'very long (sun on the horizon)']])
              : `<p><span class="status warn">Night</span> The sun is ${Math.abs(sp.altitude).toFixed(1)}° below the horizon — daylight in an image rules this time out.</p>`}
            <div style="height:10px"></div>${kv([['Sunrise', t.polar ? `none (polar ${t.polar})` : loc(t.rise)], ['Solar noon', loc(t.noon)], ['Sunset', t.polar ? `none (polar ${t.polar})` : loc(t.set)], ['Day length', t.rise ? fmtDuration((t.set - t.rise) / 1000) : t.polar === 'day' ? '24h' : '0h'], ['Mean solar time', `UTC${solarOff >= 0 ? '+' : '−'}${String(Math.floor(Math.abs(solarOff) / 60)).padStart(2, '0')}:${String(Math.abs(solarOff) % 60).padStart(2, '0')} (from longitude)`]])}
            <h4 style="margin:16px 0 6px">Solve from a measured shadow</h4>
            <div class="row"><select id="gby"><option value="bearing" ${geoState.by === 'bearing' ? 'selected' : ''}>Shadow direction (° from north)</option><option value="ratio" ${geoState.by === 'ratio' ? 'selected' : ''}>Shadow length ÷ object height</option></select><input id="gval" class="mono" style="width:110px" value="${esc(geoState.val)}" placeholder="${geoState.by === 'bearing' ? '45' : '1.4'}"><button class="btn sm" id="gsolve">Find times</button></div>
            <div id="gsolved" class="mt"></div>
            <p class="muted small">Measure the direction on satellite imagery with north up; measure length against an object of known height (a person, a lamp post, a storey ≈ 3 m). Accuracy ≈ 0.3° of sun position — your measurement error dominates.</p>
          </div>
          <div><h4 style="margin:0 0 6px">Through the day</h4>
            <div style="max-height:440px;overflow:auto"><table class="tbl"><thead><tr><th>UTC</th>${off !== null ? '<th>Local</th>' : ''}<th class="num">Azimuth</th><th class="num">Elevation</th><th class="num">Shadow →</th><th class="num">Length ×</th></tr></thead><tbody>
            ${rows.map(([x, q]) => `<tr><td class="mono">${hhmm(x)}</td>${off !== null ? `<td class="mono">${hhmm(x, off)}</td>` : ''}<td class="num mono">${q.azimuth.toFixed(0)}° ${compass(q.azimuth)}</td><td class="num mono">${q.altitude.toFixed(1)}°</td><td class="num mono">${q.shadowBearing.toFixed(0)}° ${compass(q.shadowBearing)}</td><td class="num mono">${Number.isFinite(q.shadowRatio) && q.shadowRatio < 99 ? q.shadowRatio.toFixed(2) : '∞'}</td></tr>`).join('') || `<tr><td colspan="6" class="muted">The sun does not rise on this date.</td></tr>`}
            </tbody></table></div></div>
        </div>`;
      const solve = () => {
        geoState.by = $('#gby', o).value; geoState.val = $('#gval', o).value;
        const v = parseFloat(geoState.val), box = $('#gsolved', o);
        if (!Number.isFinite(v) || (geoState.by === 'ratio' && v <= 0)) { box.innerHTML = ''; return; }
        const hits = solveShadow(Date.UTC(Y, M - 1, D, 12), p.lat, p.lon, geoState.by, geoState.by === 'bearing' ? norm360(v) : v, geoState.by === 'bearing' ? 1 : 0.03);
        box.innerHTML = hits.length ? `<table class="tbl"><thead><tr><th>Time</th><th class="num">Sun az / el</th><th></th></tr></thead><tbody>${hits.map((x) => `<tr><td class="mono">${loc(x.ms)}</td><td class="num mono">${x.pos.azimuth.toFixed(0)}° / ${x.pos.altitude.toFixed(0)}°</td><td class="actions"><button class="btn sm ghost" data-tl="${x.ms}">→ timeline</button></td></tr>`).join('')}</tbody></table>${geoState.by === 'ratio' && hits.length > 1 ? '<p class="muted small">A length alone matches a morning and an afternoon time — the shadow’s direction tells them apart.</p>' : ''}`
          : `<p class="small"><span class="status warn">No match</span> The sun never produces that shadow here on this date — the claimed place or date is wrong, or the measurement is off.</p>`;
      };
      $('#gsolve', o).onclick = solve; $('#gby', o).onchange = () => { geoState.by = $('#gby', o).value; };
      $('#gval', o).addEventListener('keydown', (e) => { if (e.key === 'Enter') solve(); });
      if (geoState.val) solve();
    };

    el.addEventListener('click', (e) => {
      const c = e.target.closest('[data-copy]'); if (c) { copyText(c.dataset.copy); return; }
      const l = e.target.closest('[data-loc]'); if (l) { $('#gq', el).value = l.dataset.loc; drawConv(); return; }
      const tl = e.target.closest('[data-tl]'); if (tl) { addEventQuick({ when: new Date(+tl.dataset.tl).toISOString(), title: 'Estimated capture time (shadow analysis)', category: 'Media captured', details: `Sun/shadow solution for ${geoState.sunAt} on ${geoState.date}. Estimate — depends on the measured shadow.`, entityValue: parseAnyCoords(geoState.sunAt) ? ['location', `${+parseAnyCoords(geoState.sunAt).lat.toFixed(6)}, ${+parseAnyCoords(geoState.sunAt).lon.toFixed(6)}`] : null }); return; }
      const b = e.target.closest('[data-act]'); if (!b) return;
      const v = b.dataset.v;
      if (b.dataset.act === 'maps') App.go('pivot', { q: v, type: 'location' });
      else if (b.dataset.act === 'add') { const r = App.addEntity('location', v, { source: 'Geo tools' }); App.touch(r.created ? `Added location ${v}` : null); toast('Location added to case'); drawConv(); }
      else if (b.dataset.act === 'sun') { $('#gs', el).value = v; drawSun(); $('#gs', el).scrollIntoView({ behavior: 'smooth', block: 'center' }); }
      else if (b.dataset.act === 'a') { $('#ga', el).value = v; drawDist(); }
      else if (b.dataset.act === 'b') { $('#gb', el).value = v; drawDist(); }
    });
    $('#gq', el).addEventListener('input', debounce(drawConv, 150));
    $('#ga', el).addEventListener('input', debounce(drawDist, 150)); $('#gb', el).addEventListener('input', debounce(drawDist, 150));
    for (const id of ['gs', 'gdate', 'gtime', 'goff']) $('#' + id, el).addEventListener('input', debounce(drawSun, 200));
    drawConv(); drawDist(); drawSun();
  },
});
