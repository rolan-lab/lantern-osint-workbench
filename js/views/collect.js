'use strict';
/* Lantern — collection views: selector extractor, pivot launcher, dork builder. */

// ---------------------------------------------------------------- Extractor
const extState = { text: '', results: [], selected: new Set(), refang: true, profiles: true, source: '', tags: '', linkTo: '' };
App.register({
  id: 'extractor', label: 'Extractor', icon: 'extractor',
  render(el, params) {
    if (params.text !== undefined) { extState.text = params.text; extState.results = []; }
    const c = App.case;
    el.innerHTML = `
      ${viewHead('Selector extractor', 'Paste raw text, HTML source, headers, logs or a threat report. Emails, domains, URLs, IPs, phones, handles, wallets, hashes, CVEs, MACs and coordinates are pulled out, de-duplicated and validated (BTC checksums, TLD sanity, IPv6 structure).')}
      <div class="card">
        <textarea id="xt" rows="10" placeholder="Paste here, or drop a .txt / .html / .eml / .csv / .json / .log file onto this box">${esc(extState.text)}</textarea>
        <div class="row mt">
          <button class="btn primary" id="xgo">Extract</button>
          <button class="btn" id="xfile">Load file…</button>
          <button class="btn ghost" id="xclear">Clear</button>
          <span class="spacer"></span>
          <label class="check"><input type="checkbox" id="xref" ${extState.refang ? 'checked' : ''}> Refang (hxxp, [.], [at])</label>
          <label class="check"><input type="checkbox" id="xprof" ${extState.profiles ? 'checked' : ''}> Usernames from profile URLs</label>
        </div>
      </div>
      <div id="xres" class="mt"></div>`;
    const ta = $('#xt', el);
    ta.addEventListener('input', () => { extState.text = ta.value; });
    const run = () => {
      extState.text = ta.value; extState.refang = $('#xref', el).checked; extState.profiles = $('#xprof', el).checked;
      extState.results = extractSelectors(extState.text, { refangFirst: extState.refang, profiles: extState.profiles });
      extState.selected = new Set(extState.results.filter((r) => !r.noise && !App.findEntity(r.type, r.value)).map((r) => entityKey(r.type, r.value)));
      draw();
    };
    const loadFiles = async (files) => {
      const parts = [];
      for (const f of files) { if (f.size > 25e6) { toast(`${f.name} is too large (25 MB max)`, 'error'); continue; } parts.push(await readFileAs(f, 'text')); }
      ta.value = parts.join('\n\n'); run();
    };
    ta.addEventListener('dragover', (e) => e.preventDefault());
    ta.addEventListener('drop', (e) => { e.preventDefault(); if (e.dataTransfer.files.length) loadFiles([...e.dataTransfer.files]); });
    $('#xfile', el).onclick = () => { const i = document.createElement('input'); i.type = 'file'; i.multiple = true; i.onchange = () => loadFiles([...i.files]); i.click(); };
    $('#xgo', el).onclick = run;
    $('#xclear', el).onclick = () => { ta.value = ''; extState.text = ''; extState.results = []; draw(); ta.focus(); };

    const draw = () => {
      const R = extState.results, box = $('#xres', el);
      if (!R.length) { box.innerHTML = extState.text.trim() ? '<div class="empty"><b>Nothing extracted yet</b>Press Extract — or the text may contain no recognizable selectors.</div>' : ''; return; }
      const byType = {}; R.forEach((r) => (byType[r.type] = byType[r.type] || []).push(r));
      const ents = c.entities.map((e) => [e.id, `${typeLabel(e.type)} · ${trunc(e.label || e.value, 50)}`]);
      box.innerHTML = `
        <div class="card">
          <h3>${plural(R.length, 'selector')} found <span class="spacer"></span>
            <button class="btn sm ghost" id="xall">Select all</button><button class="btn sm ghost" id="xnone">Select none</button>
            <button class="btn sm" id="xcopy">Copy</button><button class="btn sm" id="xdef">Copy defanged</button><button class="btn sm" id="xcsv">CSV</button></h3>
          <div class="grid g2">
            ${Object.entries(byType).map(([t, items]) => `
              <div><div class="row mb" style="margin-bottom:6px">${typeChip(t)}<span class="muted small">${items.length}</span></div>
              ${items.map((r) => { const k = entityKey(r.type, r.value); const inCase = App.findEntity(r.type, r.value); return `
                <label class="row nowrap small" style="padding:3px 0;align-items:flex-start;cursor:pointer">
                  <input type="checkbox" data-k="${esc(k)}" ${extState.selected.has(k) ? 'checked' : ''} style="margin-top:2px">
                  <span class="mono break" style="flex:1">${esc(r.value)}</span>
                  ${r.count > 1 ? `<span class="muted nowrap">×${r.count}</span>` : ''}
                  ${r.note ? `<span class="muted nowrap">${esc(r.note)}</span>` : ''}
                  ${inCase ? '<span class="chip">in case</span>' : ''}
                  <a href="#" class="small nowrap" data-pv="${esc(k)}">pivot</a>
                </label>`; }).join('')}</div>`).join('')}
          </div>
        </div>
        <div class="card mt">
          <h3>Add to case</h3>
          <div class="field-row">
            <label class="field"><span>Source / where this text came from</span><input id="xsrc" value="${esc(extState.source)}" placeholder="URL, filename, report title…"></label>
            <label class="field"><span>Tags</span><input id="xtags" value="${esc(extState.tags)}" placeholder="optional, comma-separated"></label>
            <label class="field"><span>Link each to an existing entity</span><select id="xlink"><option value="">— none —</option>${ents.map(([id, l]) => `<option value="${esc(id)}" ${extState.linkTo === id ? 'selected' : ''}>${esc(l)}</option>`).join('')}</select></label>
          </div>
          <div class="row"><button class="btn primary" id="xadd">Add ${extState.selected.size} selected</button><span class="muted small">Already-present selectors are skipped (their source is kept).</span></div>
        </div>`;
    };
    el.addEventListener('change', (e) => {
      const k = e.target.dataset.k;
      if (k) { e.target.checked ? extState.selected.add(k) : extState.selected.delete(k); const b = $('#xadd', el); if (b) b.textContent = `Add ${extState.selected.size} selected`; }
      if (e.target.id === 'xsrc') extState.source = e.target.value;
      if (e.target.id === 'xtags') extState.tags = e.target.value;
      if (e.target.id === 'xlink') extState.linkTo = e.target.value;
    });
    el.addEventListener('click', (e) => {
      const t = e.target, R = extState.results;
      const chosen = () => R.filter((r) => extState.selected.has(entityKey(r.type, r.value)));
      if (t.dataset.pv) { e.preventDefault(); const r = R.find((x) => entityKey(x.type, x.value) === t.dataset.pv); if (r) App.go('pivot', { q: r.value, type: r.type }); }
      else if (t.id === 'xall') { R.forEach((r) => extState.selected.add(entityKey(r.type, r.value))); draw(); }
      else if (t.id === 'xnone') { extState.selected.clear(); draw(); }
      else if (t.id === 'xcopy') copyText((chosen().length ? chosen() : R).map((r) => r.value).join('\n'));
      else if (t.id === 'xdef') copyText((chosen().length ? chosen() : R).map((r) => defang(r.value)).join('\n'));
      else if (t.id === 'xcsv') download('selectors.csv', toCSV([['type', 'value', 'count', 'note'], ...(chosen().length ? chosen() : R).map((r) => [r.type, r.value, r.count, r.note])]), 'text/csv');
      else if (t.id === 'xadd') {
        const src = $('#xsrc', el).value.trim(), tags = normTags($('#xtags', el).value), linkTo = $('#xlink', el).value;
        let n = 0;
        for (const r of chosen()) {
          const res = App.addEntity(r.type, r.value, { source: src, tags, notes: r.note && r.note !== 'handle' ? r.note : '' });
          if (res.created) n++;
          if (linkTo && res.entity && res.entity.id !== linkTo) App.addLink(res.entity.id, linkTo, 'mentioned in');
        }
        App.touch(`Extractor: added ${n} entities${src ? ` from ${trunc(src, 60)}` : ''}`);
        toast(`${plural(n, 'entity', 'entities')} added`);
        extState.selected.clear(); draw();
      }
    });
    if (params.text !== undefined && params.text.trim()) run(); else draw();
  },
});

// ---------------------------------------------------------------- Pivot launcher
const pvState = { q: '', type: '' };
function selectorInsights(type, v) {
  const out = [];
  if (type === 'phone') { const p = phoneCountry(v); out.push(['Digits', phoneDigits(v)]); if (p) out.push(['Calling code', `${p.cc} · ${p.country}`], ['National number', p.national]); else out.push(['Note', 'No international prefix — country unknown. Try adding +CC.']); }
  if (type === 'hash') out.push(['Algorithm (by format)', hashAlgo(v) || 'unknown']);
  if (type === 'ipv4') { const i = ipv4Info(v); out.push(['Class', i.cls], ['Reverse DNS name', i.ptr], ['Integer', i.int]); }
  if (type === 'domain') { const u = domainToUnicode(v); if (u !== v) out.push(['Unicode (IDN)', u]); const sc = scriptMix(u); if (sc.mixed) out.push(['⚠ Mixed scripts', sc.scripts.join(' + ') + ' — possible homograph']); else if (wholeScriptSpoof(u)) out.push(['⚠ Homograph', `renders like ${skeleton(u)}`]); out.push(['Registrable domain (guess)', registrable(v)]); }
  if (type === 'email') { const [local, d] = v.split('@'); out.push(['Local part', local], ['Domain', d]); if (/\+/.test(local)) out.push(['Sub-address', `${local.split('+')[0]}@${d} (plus-addressing)`]); if (FREEMAIL.has(d)) out.push(['Provider', 'Free webmail — domain pivots won’t reveal the owner']); }
  if (type === 'location') { const c = parseCoords(v); if (c) out.push(['Decimal', `${c.lat}, ${c.lon}`], ['DMS', `${toDMS(c.lat, 'NS')} ${toDMS(c.lon, 'EW')}`]); }
  if (type === 'btc') out.push(['Checksum', btcValid(v) ? 'Valid' : 'Invalid'], ['Format', /^bc1p/i.test(v) ? 'Taproot (bech32m)' : /^bc1/i.test(v) ? 'SegWit (bech32)' : v[0] === '3' ? 'P2SH' : 'Legacy P2PKH']);
  if (type === 'url') { try { const u = new URL(v); out.push(['Host', u.hostname], ['Path', u.pathname]); if (u.search) out.push(['Query params', [...u.searchParams.keys()].join(', ')]); const tr = [...u.searchParams.keys()].filter((k) => /^(utm_|fbclid|gclid|igsh|si$|mc_eid|ref)/i.test(k)); if (tr.length) out.push(['Tracking params', tr.join(', ') + ' — can reveal the sharer/campaign']); } catch { /* ignore */ } }
  if (type === 'cve') { const y = +v.split('-')[1]; out.push(['Year assigned', y]); }
  if (type === 'asn') out.push(['AS number', v.replace(/^AS/i, '')], ['Kind', +v.slice(2) >= 64512 && +v.slice(2) <= 65534 || +v.slice(2) >= 4200000000 ? 'Private-use ASN (RFC 6996) — not routed on the internet' : 'Public ASN']);
  if (type === 'tracker') out.push(['Kind', trackerKind(v)], ['Why it matters', 'Sites that embed the same ID are usually run by the same account holder']);
  if (type === 'wallet') out.push(['Chain', altWallet(v) || 'unrecognised format']);
  if (type === 'iban') out.push(['Checksum', ibanValid(v) ? 'Valid (mod-97)' : 'Invalid'], ['Country', v.slice(0, 2)], ['Bank / account part (BBAN)', v.slice(4)], ['Grouped', v.replace(/(.{4})/g, '$1 ').trim()]);
  if (type === 'eth') out.push(['Note', 'The same 0x address exists on every EVM chain (Ethereum, BSC, Polygon, Arbitrum, Base…) — check each']);
  if (type === 'domain' && /\.onion$/.test(v)) out.push(['Tor onion service', /^[a-z2-7]{56}\.onion$/.test(v) ? 'v3 address — only reachable through Tor' : 'Not a valid v3 onion address (v2 was retired in 2021)']);
  return out;
}
const FREEMAIL = new Set(['gmail.com', 'googlemail.com', 'outlook.com', 'hotmail.com', 'live.com', 'msn.com', 'yahoo.com', 'ymail.com', 'icloud.com', 'me.com', 'mac.com', 'aol.com', 'proton.me', 'protonmail.com', 'pm.me', 'gmx.com', 'gmx.de', 'gmx.net', 'web.de', 'mail.com', 'yandex.ru', 'yandex.com', 'mail.ru', 'qq.com', '163.com', '126.com', 'tutanota.com', 'tuta.io', 'zoho.com', 'fastmail.com', 'hey.com', 'duck.com', 'mailfence.com', 'inbox.ru', 'bk.ru', 'list.ru', 'rambler.ru', 'naver.com', 'daum.net', 'libero.it', 'orange.fr', 'free.fr', 'laposte.net', 't-online.de', 'seznam.cz', 'wp.pl', 'o2.pl', 'interia.pl', 'rediffmail.com', 'cock.li', 'onionmail.org', 'skiff.com', 'guerrillamail.com', 'mailinator.com', 'temp-mail.org', '10minutemail.com']);
function toDMS(d, hemi) { const a = Math.abs(d), deg = Math.floor(a), m = Math.floor((a - deg) * 60), s = ((a - deg - m / 60) * 3600).toFixed(1); return `${deg}°${m}′${s}″${d < 0 ? hemi[1] : hemi[0]}`; }

App.register({
  id: 'pivot', label: 'Pivot', icon: 'pivot',
  render(el, params) {
    if (params.q !== undefined) { pvState.q = refang(String(params.q).trim()); pvState.type = params.type || ''; }
    el.innerHTML = `
      ${viewHead('Pivot launcher', 'Turn one selector into every useful public lookup. Links open in new tabs with no referrer; nothing is sent until you click. Each click is written to the case activity log.')}
      <form class="card row" id="pvf" autocomplete="off">
        <input id="pvq" class="grow mono" placeholder="email · domain · IP · ASN · URL · username · phone · hash · wallet · IBAN · tracker ID · CVE · lat,lon · name" value="${esc(pvState.q)}" spellcheck="false" style="min-width:240px">
        <select id="pvt"><option value="">Auto-detect</option>${TYPE_OPTIONS.map(([k, l]) => `<option value="${k}" ${pvState.type === k ? 'selected' : ''}>${esc(l)}</option>`).join('')}</select>
        <button class="btn primary">Pivot</button>
      </form>
      <div id="pvout" class="mt"></div>`;
    const draw = () => {
      const box = $('#pvout', el);
      const raw = pvState.q;
      if (!raw) {
        const ex = [['email', 'jane.doe@example.com'], ['domain', 'example.com'], ['ipv4', '8.8.8.8'], ['username', 'torvalds'], ['phone', '+44 20 7946 0958'], ['hash', '44d88612fea8a8f36de82e1278abb02f'], ['btc', '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa'], ['location', '48.8584, 2.2945'], ['cve', 'CVE-2021-44228'], ['asn', 'AS15169'], ['tracker', 'UA-12345678-1'], ['org', 'Example Corp']];
        box.innerHTML = `<div class="card"><h3>Try an example</h3><div class="links">${ex.map(([t, v]) => `<a class="lnk" data-ex="${esc(v)}" data-t="${t}"><span class="dot" style="background:${typeColorVar(t)}"></span>${esc(typeLabel(t))}: <span class="mono">${esc(v)}</span></a>`).join('')}</div>
          <p class="muted small" style="margin-bottom:0">Tip: press <span class="kbd">/</span> anywhere to jump to the quick-pivot bar.</p></div>`;
        return;
      }
      const type = pvState.type || detectType(raw);
      const v = cleanValue(type, raw);
      const inCase = App.findEntity(type, v);
      const groups = pivotsFor(type, v);
      const insights = selectorInsights(type, v);
      const related = relatedSelectors(type, v);
      box.innerHTML = `
        <div class="card">
          <div class="row">${typeChip(type)}<span class="mono break" style="font-size:15px;flex:1">${esc(v)}</span>
            ${inCase ? `<a href="#" class="chip clickable" data-entity="${esc(inCase.id)}">✓ in case — details</a>` : `<button class="btn" id="pvadd">+ Add to case</button>`}
            <button class="btn ghost" id="pvcopy">Copy</button></div>
          ${insights.length ? `<dl class="kv mt">${insights.map(([k, val]) => `<dt>${esc(k)}</dt><dd class="mono">${esc(val)}</dd>`).join('')}</dl>` : ''}
          ${related.length ? `<div class="row mt small"><span class="muted">Pivot further:</span>${related.map(([t, x]) => `<a class="lnk" data-ex="${esc(x)}" data-t="${t}"><span class="dot" style="background:${typeColorVar(t)}"></span>${esc(typeLabel(t))}: <span class="mono">${esc(x)}</span></a>`).join('')}</div>` : ''}
          ${RECON_TYPES.includes(type) ? `<div class="row mt small"><span class="muted">Live data:</span><a class="lnk" data-recon="${esc(v)}">Open in Recon (${{ domain: 'DNS, RDAP, certificates, mail posture', ipv4: 'owner, routing, exposed services', ipv6: 'owner, routing, exposed services', asn: 'holder, announced prefixes', username: 'GitHub, GitLab, Bluesky, Hacker News, Keybase', email: 'mail domain, GitHub commits', btc: 'balance, transactions, counterparties', cve: 'CVSS, KEV, EPSS' }[type]})</a></div>` : ''}
          ${type === 'location' ? `<div class="row mt small"><span class="muted">Analysis:</span><a class="lnk" data-geo="${esc(v)}">Open in Geo &amp; sun (formats, distance, shadows)</a></div>` : ''}
          ${['url', 'domain'].includes(type) ? `<div class="row mt small"><span class="muted">Dorks:</span><a class="lnk" data-dork="${esc(type === 'url' ? hostOf(v) : v)}">Build search dorks for this domain</a></div>` : ''}
        </div>
        <div class="pivot-grid mt">
          ${groups.map((g, gi) => `<div class="card"><h3 style="font-size:13.5px">${esc(g.group)}<span class="spacer"></span><button class="btn sm ghost" data-all="${gi}" title="Open every link in this group (allow pop-ups for this page)">Open all</button></h3>
            <div class="links">${g.items.map((it, ii) => `<a class="lnk ${it.paste ? 'paste' : ''}" href="${esc(it.url)}" data-g="${gi}" data-i="${ii}" title="${it.paste ? 'Copies the value, then opens the site — paste it there' : esc(it.url)}" rel="noopener noreferrer" target="_blank">${esc(it.name)}</a>`).join('')}</div></div>`).join('')}
        </div>
        <p class="muted small mt">⧉ = site has no direct query URL: the value is copied, then the site opens. “Open all” needs pop-ups allowed for this page.</p>`;
      box.onclick = async (e) => {
        const a = e.target.closest('a,button'); if (!a) return;
        if (a.dataset.ex) { e.preventDefault(); pvState.q = a.dataset.ex; pvState.type = a.dataset.t || ''; $('#pvq', el).value = pvState.q; $('#pvt', el).value = pvState.type; draw(); return; }
        if (a.dataset.recon) { e.preventDefault(); App.go('recon', { q: a.dataset.recon, type }); return; }
        if (a.dataset.geo) { e.preventDefault(); App.go('geo', { q: a.dataset.geo }); return; }
        if (a.dataset.dork) { e.preventDefault(); App.go('dorks', { target: a.dataset.dork }); return; }
        if (a.dataset.entity) { e.preventDefault(); entitySheet(a.dataset.entity); return; }
        if (a.id === 'pvcopy') { copyText(v); return; }
        if (a.id === 'pvadd') { const r = App.addEntity(type, v, { source: 'Pivot launcher' }); if (r.entity) { App.touch(`Added ${typeLabel(type)} ${v}`); toast('Added to case'); draw(); } return; }
        if (a.dataset.all !== undefined) { const g = groups[+a.dataset.all]; g.items.filter((it) => !it.paste).forEach((it) => window.open(it.url, '_blank', 'noopener,noreferrer')); if (App.settings.logPivots) App.touch(`Pivot: opened ${g.group} (${g.items.length}) ← ${trunc(v, 80)}`); return; }
        if (a.dataset.g !== undefined) { e.preventDefault(); const it = groups[+a.dataset.g].items[+a.dataset.i]; launchPivot(it.url, it.paste, v, it.name); }
      };
    };
    $('#pvf', el).onsubmit = (e) => { e.preventDefault(); pvState.q = refang($('#pvq', el).value.trim()); pvState.type = $('#pvt', el).value; draw(); };
    $('#pvt', el).onchange = () => { pvState.type = $('#pvt', el).value; draw(); };
    draw();
  },
});

// ---------------------------------------------------------------- Dork builder
const dkState = { exact: '', all: '', any: '', none: '', site: '', filetype: '', intitle: '', inurl: '', intext: '', after: '', before: '', target: '' };
const ENGINES = {
  google: ['Google', 'https://www.google.com/search?q='],
  bing: ['Bing', 'https://www.bing.com/search?q='],
  ddg: ['DuckDuckGo', 'https://duckduckgo.com/?q='],
  yandex: ['Yandex', 'https://yandex.com/search/?text='],
  brave: ['Brave', 'https://search.brave.com/search?q='],
};
const DORKS = [
  { cat: 'Domain footprint', items: [
    ['Everything indexed', 'site:{t}'],
    ['Subdomains', 'site:*.{t} -site:www.{t}'],
    ['Office & PDF documents', 'site:{t} (filetype:pdf OR filetype:docx OR filetype:doc OR filetype:xlsx OR filetype:xls OR filetype:pptx)'],
    ['Open directory listings', 'site:{t} intitle:"index of"'],
    ['Login & admin portals', 'site:{t} (inurl:login OR inurl:signin OR inurl:admin OR intitle:"log in")'],
    ['Mentions elsewhere', '"{t}" -site:{t}'],
    ['Code repositories', '(site:github.com OR site:gitlab.com OR site:bitbucket.org) "{t}"'],
    ['Paste sites', '(site:pastebin.com OR site:rentry.co OR site:ghostbin.site OR site:justpaste.it) "{t}"'],
    ['Public docs & boards', '(site:docs.google.com OR site:trello.com OR site:notion.site OR site:airtable.com) "{t}"'],
    ['Cloud storage buckets', '(site:s3.amazonaws.com OR site:blob.core.windows.net OR site:storage.googleapis.com) "{t}"'],
  ] },
  { cat: 'Person / handle', items: [
    ['Social profiles', '"{t}" (site:linkedin.com OR site:x.com OR site:instagram.com OR site:facebook.com OR site:tiktok.com OR site:reddit.com)'],
    ['CVs & résumés', '"{t}" (intitle:resume OR intitle:cv OR inurl:resume) (filetype:pdf OR filetype:docx)'],
    ['Documents mentioning', '"{t}" (filetype:pdf OR filetype:docx OR filetype:xlsx OR filetype:pptx)'],
    ['Forums & threads', '"{t}" (inurl:forum OR inurl:thread OR inurl:topic OR inurl:viewtopic)'],
    ['Telegram channels & posts', 'site:t.me "{t}"'],
    ['Usernames in URLs', 'inurl:"{t}" -site:{t}.com'],
  ] },
  { cat: 'Organization', items: [
    ['Employees (LinkedIn)', 'site:linkedin.com/in "{t}"'],
    ['Job posts (tech stack clues)', '"{t}" (site:greenhouse.io OR site:lever.co OR site:myworkdayjobs.com OR site:linkedin.com/jobs)'],
    ['Press releases & filings', '"{t}" (site:sec.gov OR site:prnewswire.com OR site:businesswire.com OR site:globenewswire.com)'],
    ['Presentations', '"{t}" (filetype:pptx OR filetype:ppt OR site:slideshare.net OR site:speakerdeck.com)'],
    ['Org charts & staff lists', '"{t}" ("org chart" OR "staff directory" OR "phone list" OR "team") (filetype:pdf OR filetype:xlsx)'],
    ['Tenders & contracts', '"{t}" (tender OR procurement OR "contract award" OR RFP) filetype:pdf'],
  ] },
  { cat: 'Exposure of your own domain (defensive)', items: [
    ['Config & environment files', 'site:{t} (ext:env OR ext:ini OR ext:conf OR ext:cfg OR ext:yml OR ext:yaml OR ext:toml)'],
    ['Database dumps & backups', 'site:{t} (ext:sql OR ext:bak OR ext:dump OR ext:old OR ext:backup OR ext:tar OR ext:gz OR ext:zip)'],
    ['Log files', 'site:{t} (ext:log OR intitle:"index of" "access.log" OR "error.log")'],
    ['Error messages & stack traces', 'site:{t} ("Fatal error" OR "Stack trace" OR "Warning: mysql" OR "SQL syntax" OR "Traceback (most recent call last)")'],
    ['API docs & test endpoints', 'site:{t} (inurl:swagger OR inurl:api-docs OR inurl:graphql OR inurl:phpinfo OR intitle:"Swagger UI")'],
    ['Dev / staging hosts', 'site:{t} (inurl:dev OR inurl:staging OR inurl:test OR inurl:uat OR inurl:beta) -inurl:developer'],
    ['Secrets in public code', '"{t}" (password OR secret OR api_key OR apikey OR token OR "BEGIN PRIVATE KEY") (site:github.com OR site:gitlab.com OR site:gist.github.com)'],
    ['Shared documents', '"{t}" (site:docs.google.com OR site:drive.google.com OR site:1drv.ms OR site:dropbox.com OR site:box.com)'],
    ['Confidential-marked documents', 'site:{t} ("confidential" OR "internal use only" OR "not for distribution") (filetype:pdf OR filetype:docx OR filetype:xlsx OR filetype:pptx)'],
  ] },
  { cat: 'Email address / phone', items: [
    ['Exact mentions', '"{t}"'],
    ['In documents', '"{t}" (filetype:pdf OR filetype:xlsx OR filetype:csv OR filetype:docx OR filetype:txt)'],
    ['Classifieds & marketplaces', '"{t}" (site:craigslist.org OR site:gumtree.com OR site:olx.com OR site:ebay.com OR site:facebook.com/marketplace)'],
    ['Paste & leak mentions', '"{t}" (site:pastebin.com OR site:rentry.co OR site:justpaste.it OR site:controlc.com)'],
    ['Social profiles', '"{t}" (site:facebook.com OR site:instagram.com OR site:linkedin.com OR site:x.com OR site:vk.com)'],
  ] },
  { cat: 'Location / event', items: [
    ['Photos & posts mentioning', '"{t}" (site:flickr.com OR site:instagram.com OR site:x.com OR site:reddit.com OR site:tiktok.com)'],
    ['Video', '"{t}" (site:youtube.com OR site:vimeo.com OR site:rumble.com OR site:t.me)'],
    ['Local news', '"{t}" (news OR police OR incident OR witness)'],
    ['Webcams', '"{t}" (webcam OR "live cam" OR "live stream")'],
  ] },
];
function buildDork(s) {
  const q = [];
  const words = (x) => x.trim().split(/\s+/).filter(Boolean);
  if (s.exact.trim()) q.push(`"${s.exact.trim().replace(/"/g, '')}"`);
  if (s.all.trim()) q.push(...words(s.all));
  if (s.any.trim()) { const w = words(s.any); q.push(w.length > 1 ? `(${w.join(' OR ')})` : w[0]); }
  if (s.none.trim()) q.push(...words(s.none).map((w) => `-${w.replace(/^-/, '')}`));
  for (const op of ['site', 'filetype', 'intitle', 'inurl', 'intext']) {
    const v = s[op].trim(); if (!v) continue;
    const vals = v.split(/\s*,\s*/).filter(Boolean).map((x) => (/\s/.test(x) ? `"${x}"` : x));
    q.push(vals.length > 1 ? `(${vals.map((x) => `${op}:${x}`).join(' OR ')})` : `${op}:${vals[0]}`);
  }
  if (s.after) q.push(`after:${s.after}`);
  if (s.before) q.push(`before:${s.before}`);
  return q.join(' ');
}
App.register({
  id: 'dorks', label: 'Dorks', icon: 'dorks',
  render(el, params) {
    if (params.target) dkState.target = params.target;
    const F = [['exact', 'Exact phrase', 'John Q. Example'], ['all', 'All of these words', 'invoice leaked'], ['any', 'Any of these words', 'password credentials'], ['none', 'None of these words', 'jobs careers'],
      ['site', 'site: (comma = OR)', 'example.com, example.org'], ['filetype', 'filetype: (comma = OR)', 'pdf, xlsx'], ['intitle', 'intitle:', 'index of'], ['inurl', 'inurl:', 'admin'], ['intext', 'intext:', 'confidential']];
    el.innerHTML = `
      ${viewHead('Search dork builder', 'Compose advanced search-engine queries, or start from a template. Operators use Google syntax; most also work on Bing, DuckDuckGo and Brave.')}
      <div class="grid g2">
        <div class="card">
          <h3>Builder</h3>
          <div class="field-row">${F.map(([k, l, ph]) => `<label class="field"><span>${esc(l)}</span><input data-dk="${k}" value="${esc(dkState[k])}" placeholder="${esc(ph)}" spellcheck="false"></label>`).join('')}
            <label class="field"><span>after: (date)</span><input type="date" data-dk="after" value="${esc(dkState.after)}"></label>
            <label class="field"><span>before: (date)</span><input type="date" data-dk="before" value="${esc(dkState.before)}"></label></div>
          <pre class="out" id="dq"></pre>
          <div class="row mt" id="deng">${Object.entries(ENGINES).map(([k, [n]]) => `<button class="btn ${k === 'google' ? 'primary' : ''}" data-eng="${k}">${n}</button>`).join('')}<span class="spacer"></span><button class="btn ghost" id="dcopy">Copy</button><button class="btn ghost" id="dnote">Save to notes</button><button class="btn ghost" id="dreset">Reset</button></div>
        </div>
        <div class="card">
          <h3>Templates</h3>
          <label class="field"><span>Target (domain, name, handle or organization)</span><input id="dtarget" class="mono" value="${esc(dkState.target)}" placeholder="example.com" spellcheck="false"></label>
          <div id="dtpl" style="max-height:62vh;overflow:auto"></div>
        </div>
      </div>`;
    const upd = () => { $('#dq', el).textContent = buildDork(dkState) || '(fill in some fields)'; };
    const drawTpl = () => {
      const t = dkState.target.trim();
      $('#dtpl', el).innerHTML = DORKS.map((g) => `<div class="small muted" style="margin:10px 0 4px;font-weight:600">${esc(g.cat)}</div>${g.items.map(([n, tpl]) => {
        const q = tpl.replace(/\{t\}/g, t || '…');
        return `<div style="padding:6px 0;border-bottom:1px solid var(--line)"><div class="row nowrap"><b class="small">${esc(n)}</b><span class="spacer"></span>${['google', 'bing', 'ddg'].map((k) => `<button class="btn sm ghost" data-tq="${esc(q)}" data-te="${k}" ${t ? '' : 'disabled'}>${ENGINES[k][0][0]}</button>`).join('')}<button class="btn sm ghost" data-tc="${esc(q)}" ${t ? '' : 'disabled'}>Copy</button></div><div class="mono small ink2 break">${esc(q)}</div></div>`;
      }).join('')}`).join('');
    };
    const go = (q, engine) => { if (!q) return toast('Query is empty', 'error'); if (openUrl(ENGINES[engine][1] + encodeURIComponent(q)) && App.settings.logPivots) App.touch(`Dork (${ENGINES[engine][0]}): ${trunc(q, 120)}`); };
    el.addEventListener('input', (e) => {
      if (e.target.dataset.dk) { dkState[e.target.dataset.dk] = e.target.value; upd(); }
      if (e.target.id === 'dtarget') { dkState.target = e.target.value; drawTpl(); }
    });
    el.addEventListener('click', (e) => {
      const b = e.target.closest('button'); if (!b) return;
      if (b.dataset.eng) go(buildDork(dkState), b.dataset.eng);
      else if (b.dataset.tq) go(b.dataset.tq, b.dataset.te);
      else if (b.dataset.tc) copyText(b.dataset.tc);
      else if (b.id === 'dcopy') copyText(buildDork(dkState));
      else if (b.id === 'dnote') { const q = buildDork(dkState); if (!q) return; App.case.notes += `${App.case.notes ? '\n' : ''}[${fmtUTC(nowISO())}] Dork: ${q}`; App.touch('Saved a dork to notes'); toast('Appended to case notes'); }
      else if (b.id === 'dreset') { Object.keys(dkState).forEach((k) => { if (k !== 'target') dkState[k] = ''; }); App.refresh(); }
    });
    upd(); drawTpl();
  },
});
