'use strict';
/* Lantern — link-analysis graph (canvas, force-directed, no dependencies). */

const gState = { hidden: new Set(), q: '', selected: null };

App.register({
  id: 'graph', label: 'Link graph', icon: 'graph',
  render(el) {
    const c = App.case;
    el.innerHTML = `
      ${viewHead('Link analysis', 'Entities as nodes, relationships as edges. Colour = category, the 2-letter glyph = type. Select a node to focus its neighbourhood.',
        `<button class="btn" id="gAuto" title="Link emails/URLs to their domains and subdomains to parents">Auto-link</button><button class="btn" id="gLink">Link…</button><button class="btn" id="gRelayout">Re-layout</button><button class="btn" id="gFit">Fit</button><button class="btn" id="gPng">PNG</button>`)}
      <div class="row mb"><div class="legend" id="gLegend"></div><span class="spacer"></span><input id="gQ" placeholder="Highlight…" value="${esc(gState.q)}" style="width:200px"></div>
      <div class="graph-wrap" id="gWrap">
        <canvas class="graph" id="gCanvas" aria-label="Entity link graph"></canvas>
        <div class="graph-tip hidden" id="gTip"></div>
        <div class="graph-panel hidden" id="gPanel"></div>
        <div class="graph-hint" id="gHint">Drag nodes to pin · scroll to zoom · drag background to pan · Shift-click a second node to link · double-click for details</div>
      </div>`;
    if (!c.entities.length) {
      $('#gWrap', el).innerHTML = '<div class="empty" style="margin:40px"><b>Nothing to graph yet</b>Add entities (Extractor, Pivot, Recon) and link them — or press Auto-link.</div>';
      ['gAuto', 'gLink', 'gRelayout', 'gFit', 'gPng'].forEach((id) => ($('#' + id, el).disabled = true));
      return;
    }
    const wrap = $('#gWrap', el), cv = $('#gCanvas', el), ctx = cv.getContext('2d'), tip = $('#gTip', el), panel = $('#gPanel', el);
    let W = 0, H = 0, dpr = 1, scale = 1, tx = 0, ty = 0, alpha = 1, raf = 0, linkFrom = null;
    let drag = null, hover = null, pan = null;
    let colors = {};
    const readColors = () => {
      colors = { surface: cssVar('--surface'), ink: cssVar('--ink'), ink2: cssVar('--ink-2'), muted: cssVar('--muted'), line: cssVar('--line-2'), accent: cssVar('--accent') };
      for (let i = 0; i <= 8; i++) colors['c' + i] = cssVar('--c' + i);
    };
    readColors();

    // ---- model
    let nodes = [], links = [], byId = new Map(), deg = new Map();
    const build = () => {
      const prev = byId;
      const vis = c.entities.filter((e) => !gState.hidden.has(famOf(e.type)));
      byId = new Map();
      nodes = vis.map((e, i) => {
        const p = prev.get(e.id);
        const a = (i / Math.max(1, vis.length)) * Math.PI * 2, r = 60 + Math.sqrt(vis.length) * 25;
        const n = p || { e, x: e.pos?.x ?? Math.cos(a) * r + (Math.random() - 0.5) * 20, y: e.pos?.y ?? Math.sin(a) * r + (Math.random() - 0.5) * 20, vx: 0, vy: 0 };
        n.e = e; byId.set(e.id, n); return n;
      });
      links = c.links.filter((l) => byId.has(l.from) && byId.has(l.to)).map((l) => ({ l, a: byId.get(l.from), b: byId.get(l.to) }));
      deg = new Map(); links.forEach(({ a, b }) => { deg.set(a, (deg.get(a) || 0) + 1); deg.set(b, (deg.get(b) || 0) + 1); });
      if (gState.selected && !byId.has(gState.selected)) gState.selected = null;
    };
    build();
    const radius = (n) => 12 + Math.min(8, (deg.get(n) || 0) * 1.2);
    const neighbors = (id) => { const s = new Set([id]); links.forEach(({ a, b }) => { if (a.e.id === id) s.add(b.e.id); if (b.e.id === id) s.add(a.e.id); }); return s; };

    // ---- physics
    const tick = () => {
      const N = nodes.length;
      for (let i = 0; i < N; i++) {
        const a = nodes[i];
        for (let j = i + 1; j < N; j++) {
          const b = nodes[j];
          let dx = a.x - b.x, dy = a.y - b.y, d2 = dx * dx + dy * dy;
          if (d2 < 0.01) { dx = Math.random() - 0.5; dy = Math.random() - 0.5; d2 = 0.5; }
          if (d2 > 250000) continue;
          const f = (2600 / d2) * alpha, d = Math.sqrt(d2);
          const fx = (dx / d) * f, fy = (dy / d) * f;
          a.vx += fx; a.vy += fy; b.vx -= fx; b.vy -= fy;
        }
      }
      for (const { a, b } of links) {
        const dx = b.x - a.x, dy = b.y - a.y, d = Math.sqrt(dx * dx + dy * dy) || 1;
        const f = (d - 110) * 0.03 * alpha, fx = (dx / d) * f, fy = (dy / d) * f;
        a.vx += fx; a.vy += fy; b.vx -= fx; b.vy -= fy;
      }
      for (const n of nodes) {
        n.vx -= n.x * 0.006 * alpha; n.vy -= n.y * 0.006 * alpha;
        if (n.e.pinned || n === drag?.node) { n.vx = n.vy = 0; continue; }
        n.vx *= 0.82; n.vy *= 0.82;
        n.x += clamp(n.vx, -30, 30); n.y += clamp(n.vy, -30, 30);
      }
      alpha *= 0.985;
    };
    const persist = () => { nodes.forEach((n) => { n.e.pos = { x: Math.round(n.x), y: Math.round(n.y) }; }); App.save(); };

    // ---- drawing
    const toScreen = (x, y) => [x * scale + tx, y * scale + ty];
    const toWorld = (sx, sy) => [(sx - tx) / scale, (sy - ty) / scale];
    const draw = () => {
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.fillStyle = colors.surface; ctx.fillRect(0, 0, W, H);
      const q = gState.q.trim().toLowerCase();
      const focus = gState.selected ? neighbors(gState.selected) : null;
      const match = (n) => !q || (n.e.value + ' ' + (n.e.label || '') + ' ' + (n.e.tags || []).join(' ')).toLowerCase().includes(q);
      const dim = (n) => (focus && !focus.has(n.e.id)) || !match(n);
      // edges
      ctx.lineCap = 'round';
      for (const { l, a, b } of links) {
        const hot = focus && (a.e.id === gState.selected || b.e.id === gState.selected);
        ctx.globalAlpha = (dim(a) || dim(b)) && !hot ? 0.15 : 1;
        ctx.strokeStyle = hot ? colors.accent : colors.line; ctx.lineWidth = hot ? 2 : 1.5;
        const [x1, y1] = toScreen(a.x, a.y), [x2, y2] = toScreen(b.x, b.y);
        ctx.beginPath(); ctx.moveTo(x1, y1); ctx.lineTo(x2, y2); ctx.stroke();
        if (l.label && (scale > 0.85 || hot)) {
          ctx.font = '10px system-ui, sans-serif'; ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
          const mx = (x1 + x2) / 2, my = (y1 + y2) / 2;
          ctx.lineWidth = 3; ctx.strokeStyle = colors.surface; ctx.strokeText(trunc(l.label, 26), mx, my);
          ctx.fillStyle = colors.muted; ctx.fillText(trunc(l.label, 26), mx, my);
        }
      }
      // nodes
      for (const n of nodes) {
        const [x, y] = toScreen(n.x, n.y), r = radius(n) * Math.max(0.6, Math.min(1.3, scale));
        const slot = FAMILIES[famOf(n.e.type)].slot;
        ctx.globalAlpha = dim(n) ? 0.2 : 1;
        if (n.e.id === gState.selected || n.e.id === linkFrom) { ctx.beginPath(); ctx.arc(x, y, r + 5, 0, Math.PI * 2); ctx.strokeStyle = colors.accent; ctx.lineWidth = 2.5; ctx.stroke(); }
        ctx.beginPath(); ctx.arc(x, y, r, 0, Math.PI * 2);
        ctx.fillStyle = colors['c' + slot]; ctx.fill();
        ctx.lineWidth = 2; ctx.strokeStyle = colors.surface; ctx.stroke();
        if (n.e.pinned) { ctx.beginPath(); ctx.arc(x + r * 0.75, y - r * 0.75, 3, 0, Math.PI * 2); ctx.fillStyle = colors.ink; ctx.fill(); }
        ctx.font = `600 ${Math.round(r * 0.72)}px system-ui, sans-serif`; ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
        ctx.fillStyle = slot === 4 ? '#0b0b0b' : '#ffffff';
        ctx.fillText((TYPES[n.e.type] || TYPES.other).glyph, x, y + 0.5);
        if (scale > 0.55 || n === hover || n.e.id === gState.selected) {
          const label = trunc(n.e.label || n.e.value, 30);
          ctx.font = '11px system-ui, sans-serif'; ctx.textBaseline = 'top';
          ctx.lineWidth = 3; ctx.strokeStyle = colors.surface; ctx.strokeText(label, x, y + r + 4);
          ctx.fillStyle = colors.ink2; ctx.fillText(label, x, y + r + 4);
        }
      }
      ctx.globalAlpha = 1;
    };
    const loop = () => {
      if (alpha > 0.004) { tick(); if (alpha <= 0.004) persist(); }
      draw();
      raf = requestAnimationFrame(loop);
    };
    const reheat = (a = 0.5) => { alpha = Math.max(alpha, a); };

    const fit = () => {
      if (!nodes.length) return;
      let x0 = Infinity, y0 = Infinity, x1 = -Infinity, y1 = -Infinity;
      nodes.forEach((n) => { x0 = Math.min(x0, n.x); y0 = Math.min(y0, n.y); x1 = Math.max(x1, n.x); y1 = Math.max(y1, n.y); });
      const pad = 70, bw = Math.max(1, x1 - x0), bh = Math.max(1, y1 - y0);
      scale = clamp(Math.min((W - pad * 2) / bw, (H - pad * 2) / bh), 0.2, 2);
      tx = W / 2 - ((x0 + x1) / 2) * scale; ty = H / 2 - ((y0 + y1) / 2) * scale;
    };
    const resize = () => {
      dpr = window.devicePixelRatio || 1; W = wrap.clientWidth; H = wrap.clientHeight;
      cv.width = Math.round(W * dpr); cv.height = Math.round(H * dpr);
      if (!tx && !ty) { tx = W / 2; ty = H / 2; }
    };
    const ro = new ResizeObserver(() => { resize(); }); ro.observe(wrap);
    resize();
    const hadLayout = c.entities.every((e) => e.pos);
    alpha = hadLayout ? 0.05 : 1;
    if (hadLayout) fit(); else { for (let i = 0; i < 120; i++) tick(); fit(); }

    // ---- legend
    const drawLegend = () => {
      const counts = {}; c.entities.forEach((e) => { const f = famOf(e.type); counts[f] = (counts[f] || 0) + 1; });
      $('#gLegend', el).innerHTML = Object.keys(FAMILIES).filter((f) => counts[f]).map((f) => `<span class="chip clickable ${gState.hidden.has(f) ? 'off' : ''}" data-fam="${f}" title="Click to show/hide"><span class="dot" style="background:var(--c${FAMILIES[f].slot})"></span>${esc(FAMILIES[f].label)} <span class="muted">${counts[f]}</span></span>`).join('');
    };
    drawLegend();

    // ---- panel
    const showPanel = () => {
      const id = gState.selected; const e = id && App.entity(id);
      if (!e) { panel.classList.add('hidden'); return; }
      const nb = [...neighbors(id)].filter((x) => x !== id).map((x) => App.entity(x)).filter(Boolean);
      panel.classList.remove('hidden');
      panel.innerHTML = `<div class="row nowrap">${typeChip(e.type)}<span class="spacer"></span><button class="icon-btn" data-p="close" aria-label="Close">✕</button></div>
        <div class="mono break" style="margin:6px 0">${esc(e.value)}</div>${e.label ? `<div class="small ink2">${esc(e.label)}</div>` : ''}
        <div class="row mt"><button class="btn sm primary" data-p="details">Details</button><button class="btn sm" data-p="pivot">Pivot</button><button class="btn sm" data-p="link">Link to…</button><button class="btn sm ghost" data-p="pin">${e.pinned ? 'Unpin' : 'Pin'}</button></div>
        <div class="small muted mt">${plural(nb.length, 'neighbour')}</div><div class="row" style="margin-top:4px">${nb.slice(0, 30).map((n) => entityChip(n)).join('')}</div>`;
    };
    panel.addEventListener('click', (ev) => {
      const b = ev.target.closest('[data-p],[data-entity]'); if (!b) return;
      const e = App.entity(gState.selected);
      if (b.dataset.entity) { gState.selected = b.dataset.entity; showPanel(); return; }
      const p = b.dataset.p;
      if (p === 'close') { gState.selected = null; showPanel(); }
      else if (p === 'details') entitySheet(e.id);
      else if (p === 'pivot') App.go('pivot', { q: e.value, type: e.type });
      else if (p === 'link') { linkFrom = e.id; $('#gHint', el).textContent = 'Click the node to link to (Esc to cancel)'; }
      else if (p === 'pin') { e.pinned = !e.pinned; App.save(); showPanel(); reheat(0.2); }
    });

    // ---- interaction
    const hit = (sx, sy) => { const [x, y] = toWorld(sx, sy); let best = null, bd = Infinity; for (const n of nodes) { const d = Math.hypot(n.x - x, n.y - y), r = (radius(n) + 6) / Math.min(1, scale); if (d < r && d < bd) { best = n; bd = d; } } return best; };
    const pos = (ev) => { const r = cv.getBoundingClientRect(); return [ev.clientX - r.left, ev.clientY - r.top]; };
    const makeLink = async (from, to) => {
      const r = await formDlg('Link entities', [{ name: 'label', label: `${trunc(App.entity(from).value, 40)} → ${trunc(App.entity(to).value, 40)}`, placeholder: 'Relationship, e.g. owns, uses, same person as' }], { ok: 'Link' });
      if (r) { App.addLink(from, to, r.label); App.touch(`Linked ${App.entity(from).value} → ${App.entity(to).value}`); build(); reheat(0.3); }
    };
    cv.addEventListener('pointerdown', (ev) => {
      const [sx, sy] = pos(ev); const n = hit(sx, sy);
      cv.setPointerCapture(ev.pointerId);
      if (n) { drag = { node: n, sx, sy, moved: false, shift: ev.shiftKey }; }
      else { pan = { sx, sy, tx, ty, moved: false }; cv.classList.add('dragging'); }
    });
    cv.addEventListener('pointermove', (ev) => {
      const [sx, sy] = pos(ev);
      if (drag) {
        if (Math.hypot(sx - drag.sx, sy - drag.sy) > 3) drag.moved = true;
        if (drag.moved) { const [x, y] = toWorld(sx, sy); drag.node.x = x; drag.node.y = y; reheat(0.15); }
        return;
      }
      if (pan) { if (Math.hypot(sx - pan.sx, sy - pan.sy) > 3) pan.moved = true; tx = pan.tx + sx - pan.sx; ty = pan.ty + sy - pan.sy; return; }
      const n = hit(sx, sy);
      if (n !== hover) { hover = n; cv.style.cursor = n ? 'pointer' : ''; }
      if (n) { tip.classList.remove('hidden'); tip.innerHTML = `<b>${esc(typeLabel(n.e.type))}</b> · <span class="mono">${esc(trunc(n.e.value, 70))}</span>${n.e.label ? `<br>${esc(n.e.label)}` : ''}<br><span class="muted">${plural(deg.get(n) || 0, 'link')}</span>`; tip.style.left = Math.min(sx + 14, W - 330) + 'px'; tip.style.top = (sy + 14) + 'px'; }
      else tip.classList.add('hidden');
    });
    cv.addEventListener('pointerup', (ev) => {
      if (drag) {
        const n = drag.node;
        if (drag.moved) { n.e.pinned = true; persist(); showPanel(); }
        else if (linkFrom && linkFrom !== n.e.id) { const f = linkFrom; linkFrom = null; $('#gHint', el).textContent = 'Linked.'; makeLink(f, n.e.id); }
        else if (drag.shift && gState.selected && gState.selected !== n.e.id) makeLink(gState.selected, n.e.id);
        else { gState.selected = gState.selected === n.e.id ? null : n.e.id; showPanel(); }
        drag = null;
      } else if (pan) { if (!pan.moved) { gState.selected = null; linkFrom = null; showPanel(); } pan = null; cv.classList.remove('dragging'); }
      try { cv.releasePointerCapture(ev.pointerId); } catch { /* ignore */ }
    });
    cv.addEventListener('pointerleave', () => { tip.classList.add('hidden'); hover = null; });
    cv.addEventListener('dblclick', (ev) => { const [sx, sy] = pos(ev); const n = hit(sx, sy); if (n) entitySheet(n.e.id); });
    cv.addEventListener('wheel', (ev) => {
      ev.preventDefault();
      const [sx, sy] = pos(ev); const [wx, wy] = toWorld(sx, sy);
      scale = clamp(scale * Math.exp(-ev.deltaY * 0.0015), 0.15, 4);
      tx = sx - wx * scale; ty = sy - wy * scale;
    }, { passive: false });
    const onKey = (ev) => { if (ev.key === 'Escape' && linkFrom) { linkFrom = null; $('#gHint', el).textContent = 'Link cancelled.'; } };
    document.addEventListener('keydown', onKey);
    const onTheme = () => readColors();
    window.addEventListener('lantern-theme', onTheme);
    const mq = matchMedia('(prefers-color-scheme: dark)'); mq.addEventListener('change', onTheme);

    // ---- toolbar
    $('#gLegend', el).addEventListener('click', (ev) => { const f = ev.target.closest('[data-fam]')?.dataset.fam; if (!f) return; gState.hidden.has(f) ? gState.hidden.delete(f) : gState.hidden.add(f); drawLegend(); build(); reheat(0.3); });
    $('#gQ', el).addEventListener('input', (ev) => { gState.q = ev.target.value; });
    $('#gFit', el).onclick = fit;
    $('#gRelayout', el).onclick = () => { nodes.forEach((n) => { n.x = (Math.random() - 0.5) * 400; n.y = (Math.random() - 0.5) * 400; n.vx = n.vy = 0; n.e.pinned = false; }); alpha = 1; for (let i = 0; i < 150; i++) tick(); fit(); };
    $('#gAuto', el).onclick = () => { const n = App.autoLink(); App.touch(n ? `Auto-linked ${n} relationship(s)` : null); toast(n ? `${plural(n, 'link')} created` : 'No new implied links'); build(); reheat(0.4); };
    $('#gLink', el).onclick = async () => { if (await linkDlg(gState.selected)) { build(); reheat(0.4); } };
    $('#gPng', el).onclick = () => { draw(); cv.toBlob((b) => download(`${slug(c.name)}-graph.png`, b), 'image/png'); };

    showPanel();
    raf = requestAnimationFrame(loop);
    return () => { cancelAnimationFrame(raf); ro.disconnect(); document.removeEventListener('keydown', onKey); window.removeEventListener('lantern-theme', onTheme); mq.removeEventListener('change', onTheme); persist(); };
  },
});
