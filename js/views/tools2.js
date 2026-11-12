'use strict';
/* Lantern — extra toolbox tabs: favicon hash (MurmurHash3, as indexed by Shodan & co.) and name → email / username permutations. */

/** MurmurHash3 x86 32-bit. Returns a signed 32-bit integer, like Python's mmh3.hash(). */
function mmh3(bytes, seed = 0) {
  const c1 = 0xcc9e2d51, c2 = 0x1b873593; let h = seed | 0; const n = bytes.length, blocks = n >> 2;
  for (let i = 0; i < blocks; i++) {
    let k = bytes[i * 4] | (bytes[i * 4 + 1] << 8) | (bytes[i * 4 + 2] << 16) | (bytes[i * 4 + 3] << 24);
    k = Math.imul(k, c1); k = (k << 15) | (k >>> 17); k = Math.imul(k, c2);
    h ^= k; h = (h << 13) | (h >>> 19); h = (Math.imul(h, 5) + 0xe6546b64) | 0;
  }
  let k = 0; const t = blocks * 4;
  switch (n & 3) { case 3: k ^= bytes[t + 2] << 16; /* falls through */ case 2: k ^= bytes[t + 1] << 8; /* falls through */ case 1: k ^= bytes[t]; k = Math.imul(k, c1); k = (k << 15) | (k >>> 17); k = Math.imul(k, c2); h ^= k; /* no default */ }
  h ^= n; h ^= h >>> 16; h = Math.imul(h, 0x85ebca6b); h ^= h >>> 13; h = Math.imul(h, 0xc2b2ae35); h ^= h >>> 16;
  return h | 0;
}
/** Shodan-style favicon hash: mmh3 of the file's base64 text wrapped at 76 columns with a trailing newline. */
function faviconHash(u8) {
  let bin = ''; for (let i = 0; i < u8.length; i += 0x8000) bin += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000));
  const b64 = btoa(bin).replace(/.{76}/g, '$&\n');
  return mmh3(utf8(b64.endsWith('\n') ? b64 : b64 + '\n'));
}

function renderFavicon(root) {
  root.innerHTML = `<div class="grid g2">
    <div class="card"><h3>Favicon hash</h3>
      <p class="card-sub">Internet scanners index every site’s favicon by hash. Servers that share an unusual icon — a phishing kit, a C2 panel, an organization’s internal apps — can be found even when they sit behind unrelated IPs and domains.</p>
      <div class="drop" id="fdrop"><b>Drop a favicon file here</b><span class="small muted">.ico / .png / .svg — hashed locally, never uploaded</span></div>
      <div id="fout" class="mt"></div></div>
    <div class="card"><h3>How to get the icon safely</h3><ul class="small ink2" style="padding-left:18px;margin:0">
      <li>Prefer a copy from a scanner or archive: open the site’s result on urlscan.io or the Wayback Machine and save <span class="mono">/favicon.ico</span> from there.</li>
      <li>Fetching it yourself contacts the target. If you must, do it from your research environment: <span class="mono">curl -s https://site/favicon.ico -o favicon.ico</span></li>
      <li>The icon may live elsewhere — look for <span class="mono">&lt;link rel="icon" href="…"&gt;</span> in the page source.</li>
      <li>Default icons (frameworks, hosting panels) match thousands of unrelated hosts. A hash is only meaningful when the icon is distinctive.</li></ul></div></div>`;
  const out = $('#fout', root);
  fileDrop($('#fdrop', root), async ([f]) => {
    if (f.size > 5e6) return toast('That is too large to be a favicon (5 MB max)', 'error');
    const u8 = new Uint8Array(await readFileAs(f, 'buffer')), h = faviconHash(u8), md = (await hashBuffer(u8.buffer));
    tbState.favicon = { name: f.name, size: f.size, h, md5: md.md5, sha256: md.sha256 };
    draw(); App.touch(`Favicon hash computed for ${f.name}: ${h}`);
  }, { multiple: false });
  const draw = () => {
    const F = tbState.favicon; if (!F) { out.innerHTML = ''; return; }
    const b64 = (q) => encodeURIComponent(b64encode(q));
    const links = [['Shodan', `https://www.shodan.io/search?query=${encodeURIComponent(`http.favicon.hash:${F.h}`)}`], ['FOFA', `https://en.fofa.info/result?qbase64=${b64(`icon_hash="${F.h}"`)}`], ['Censys', `https://search.censys.io/search?resource=hosts&q=${encodeURIComponent(`services.http.response.favicons.md5_hash:${F.md5}`)}`], ['ZoomEye', `https://www.zoomeye.ai/searchResult?q=${encodeURIComponent(`iconhash:"${F.h}"`)}`], ['Criminal IP', `https://www.criminalip.io/asset/search?query=${encodeURIComponent(`favicon: ${(F.h >>> 0).toString(16)}`)}`], ['VirusTotal (file)', `https://www.virustotal.com/gui/file/${F.sha256}`]];
    out.innerHTML = `<dl class="kv"><dt>File</dt><dd>${esc(F.name)} <span class="muted">(${esc(fmtBytes(F.size))})</span></dd><dt>MurmurHash3</dt><dd class="mono" data-copy="${F.h}" style="cursor:copy" title="Click to copy">${F.h}</dd><dt>MD5</dt><dd class="mono break" data-copy="${F.md5}" style="cursor:copy">${F.md5}</dd><dt>SHA-256</dt><dd class="mono break" data-copy="${F.sha256}" style="cursor:copy">${F.sha256}</dd></dl>
      <div class="small muted" style="margin:12px 0 4px">Find hosts serving this icon</div><div class="links">${links.map(([n, u]) => `<a class="lnk" data-url="${esc(u)}" data-name="${esc(n)}">${esc(n)}</a>`).join('')}</div>
      <div class="row mt"><button class="btn sm" id="fadd">+ Add hash to case</button></div>`;
  };
  out.addEventListener('click', (e) => {
    const c = e.target.closest('[data-copy]'); if (c) return void copyText(c.dataset.copy);
    const a = e.target.closest('[data-url]'); if (a) return void launchPivot(a.dataset.url, false, `favicon ${tbState.favicon.h}`, `${a.dataset.name} favicon search`);
    if (e.target.id === 'fadd') { const F = tbState.favicon; const r = App.addEntity('hash', F.sha256, { label: `Favicon ${F.name}`, notes: `Favicon MurmurHash3 (Shodan http.favicon.hash): ${F.h}\nMD5: ${F.md5}`, source: 'Favicon hash tool', tags: ['favicon'] }); App.touch(r.created ? `Added favicon hash ${F.h}` : null); toast(r.created ? 'Added to case' : 'Already in case'); }
  });
  draw();
}

// ---------------------------------------------------------------- name permutations
const asciiName = (s) => String(s || '').normalize('NFKD').replace(/[̀-ͯ]/g, '').replace(/ß/g, 'ss').replace(/[øØ]/g, 'o').replace(/[łŁ]/g, 'l').replace(/[đĐ]/g, 'd').replace(/[æÆ]/g, 'ae').toLowerCase().replace(/[^a-z0-9]/g, '');
/** Common corporate mailbox / handle patterns for a person's name, most likely first. */
function namePermutations({ first, middle = '', last, nick = '', year = '' }) {
  const f = asciiName(first), m = asciiName(middle), l = asciiName(last), n = asciiName(nick);
  const out = [], add = (v, why) => { if (v && v.length > 1 && !out.some((x) => x.v === v)) out.push({ v, why }); };
  if (f && l) {
    add(`${f}.${l}`, 'first.last'); add(`${f[0]}${l}`, 'flast'); add(`${f}${l}`, 'firstlast'); add(`${f}`, 'first'); add(`${f}${l[0]}`, 'firstl'); add(`${f}_${l}`, 'first_last'); add(`${f}-${l}`, 'first-last');
    add(`${l}.${f}`, 'last.first'); add(`${l}${f[0]}`, 'lastf'); add(`${l}${f}`, 'lastfirst'); add(`${f[0]}.${l}`, 'f.last'); add(`${f}.${l[0]}`, 'first.l'); add(`${l}`, 'last'); add(`${l}_${f}`, 'last_first'); add(`${f[0]}${l[0]}`, 'initials'); add(`${l}.${f[0]}`, 'last.f');
    if (m) { add(`${f}.${m[0]}.${l}`, 'first.m.last'); add(`${f[0]}${m[0]}${l}`, 'fmlast'); add(`${f}${m[0]}${l}`, 'firstmlast'); add(`${f}.${m}.${l}`, 'first.middle.last'); add(`${f[0]}${m[0]}${l[0]}`, 'initials'); }
    if (year) { const yy = String(year).slice(-2); add(`${f}${l}${year}`, 'firstlast + year'); add(`${f}.${l}${yy}`, 'first.last + yy'); add(`${f}${l}${yy}`, 'firstlast + yy'); add(`${f[0]}${l}${yy}`, 'flast + yy'); add(`${f}${yy}`, 'first + yy'); }
  } else if (f || l) add(f || l, 'single name');
  if (n) { add(n, 'nickname'); if (l) { add(`${n}.${l}`, 'nick.last'); add(`${n}${l}`, 'nicklast'); } if (year) add(`${n}${String(year).slice(-2)}`, 'nick + yy'); }
  return out;
}
function renderPermute(root) {
  const S = (tbState.perm = tbState.perm || { first: '', middle: '', last: '', nick: '', year: '', domains: '' });
  root.innerHTML = `<div class="grid g2">
    <div class="card"><h3>Name → email &amp; username candidates</h3>
      <p class="card-sub">Organizations use a handful of mailbox patterns. Generate the candidates, then confirm one address from a public source — a press release, a commit, a document author field — to learn the pattern for everyone else.</p>
      <div class="field-row">${[['first', 'First name', 'Jane'], ['middle', 'Middle (optional)', 'Q'], ['last', 'Last name', 'Doe'], ['nick', 'Nickname / known handle (optional)', 'jd'], ['year', 'Year (optional)', '1990']].map(([k, l, ph]) => `<label class="field"><span>${l}</span><input data-pm="${k}" value="${esc(S[k])}" placeholder="${ph}" spellcheck="false"></label>`).join('')}</div>
      <label class="field"><span>Email domains (comma-separated — leave empty for usernames only)</span><input data-pm="domains" class="mono" value="${esc(S.domains)}" placeholder="example.com, gmail.com" spellcheck="false"></label>
      <p class="muted small" style="margin-bottom:0">Candidates are guesses, not findings. Never send mail to test an address — that contacts the subject. Verification by SMTP probing is unreliable and intrusive.</p></div>
    <div class="card"><h3>Candidates<span class="spacer"></span><button class="btn sm ghost" id="pmcopy">Copy</button><button class="btn sm ghost" id="pmdork">Dork</button></h3><div id="pmout"></div></div></div>`;
  let list = [];
  const draw = () => {
    $$('[data-pm]', root).forEach((i) => { S[i.dataset.pm] = i.value; });
    const locals = namePermutations(S), doms = S.domains.split(/[,\s]+/).map((d) => d.trim().toLowerCase().replace(/^@/, '')).filter(isDomain);
    list = doms.length ? doms.flatMap((d) => locals.map((x) => ({ v: `${x.v}@${d}`, why: x.why, t: 'email' }))) : locals.map((x) => ({ ...x, t: 'username' }));
    $('#pmout', root).innerHTML = list.length ? `<div class="small muted mb">${plural(list.length, 'candidate')} · ordered by how common the pattern is</div><div style="max-height:56vh;overflow:auto"><table class="tbl"><tbody>${list.map((x) => `<tr><td class="mono break">${esc(x.v)}</td><td class="small muted">${esc(x.why)}</td><td class="actions"><button class="btn sm ghost" data-pmpv="${esc(x.v)}" data-t="${x.t}">Pivot</button></td></tr>`).join('')}</tbody></table></div>` : '<p class="muted small">Enter at least a first or last name.</p>';
  };
  root.addEventListener('input', debounce(draw, 150));
  root.addEventListener('click', (e) => { const b = e.target.closest('[data-pmpv]'); if (b) App.go('pivot', { q: b.dataset.pmpv, type: b.dataset.t }); });
  $('#pmcopy', root).onclick = () => list.length && copyText(list.map((x) => x.v).join('\n'));
  $('#pmdork', root).onclick = () => { if (!list.length) return; dkState.any = ''; dkState.exact = ''; dkState.all = `(${list.slice(0, 12).map((x) => `"${x.v}"`).join(' OR ')})`; App.go('dorks'); };
  draw();
}
