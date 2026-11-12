'use strict';
/* Lantern — Recon: live, opt-in lookups against public APIs (never the target's own servers).
   Domain: DNS-over-HTTPS (Cloudflare, Google fallback), mail posture, DKIM/MTA-STS/DNSSEC, RDAP, certificate
   transparency, Wayback. IP: ipinfo.io, PTR, RDAP, Shodan InternetDB, RIPEstat routing. ASN: RIPEstat + RDAP.
   Username: GitHub, GitLab, Bluesky (+ PLC handle history), Hacker News, Keybase. Email: mail domain + GitHub commits.
   Bitcoin: Blockstream / mempool.space. CVE: MITRE CVE record + FIRST EPSS. Every card degrades to a manual link. */

const RR = { A: 1, NS: 2, CNAME: 5, SOA: 6, PTR: 12, MX: 15, TXT: 16, AAAA: 28, DNSKEY: 48, CAA: 257 };
const RR_NAME = Object.fromEntries(Object.entries(RR).map(([k, v]) => [v, k]));

async function fetchJSON(url, opts = {}, timeout = 15000) {
  if (!App.settings.activeLookups) throw new Error('Active lookups are disabled');
  const ctl = new AbortController(); const t = setTimeout(() => ctl.abort(), timeout);
  try {
    const r = await fetch(url, { ...opts, signal: ctl.signal, referrerPolicy: 'no-referrer', credentials: 'omit' });
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return await r.json();
  } catch (e) { throw new Error(e.name === 'AbortError' ? 'Timed out' : e.message === 'Failed to fetch' ? 'Request blocked (network, CORS or ad-blocker)' : e.message); }
  finally { clearTimeout(t); }
}
async function doh(name, type) {
  const q = `name=${encodeURIComponent(name)}&type=${type}`;
  try { return await fetchJSON(`https://cloudflare-dns.com/dns-query?${q}`, { headers: { accept: 'application/dns-json' } }); }
  catch { return fetchJSON(`https://dns.google/resolve?${q}`); }
}
const answers = (j, type) => (j.Answer || []).filter((a) => !type || a.type === RR[type]).map((a) => ({ ...a, data: String(a.data).replace(/^"|"$/g, '').replace(/"\s*"/g, '') }));
function ptrName(ip) {
  if (isIPv4(ip)) return ip.split('.').reverse().join('.') + '.in-addr.arpa';
  const parts = ip.split('::'); const l = parts[0] ? parts[0].split(':') : [], r = parts[1] ? parts[1].split(':') : [];
  const full = [...l, ...Array(8 - l.length - r.length).fill('0'), ...r].map((g) => g.padStart(4, '0')).join('');
  return full.split('').reverse().join('.') + '.ip6.arpa';
}
/** Strip tags and decode entities without ever attaching the markup to the document. */
function htmlToText(html) { const d = new DOMParser().parseFromString(String(html || '').replace(/<p>/gi, '\n'), 'text/html'); return (d.body.textContent || '').trim(); }
function vcardName(ent) { const fn = ent?.vcardArray?.[1]?.find((x) => x[0] === 'fn'); return fn ? fn[3] : ''; }
function rdapEvents(j) { const o = {}; (j.events || []).forEach((e) => (o[e.eventAction] = e.eventDate)); return o; }

const rcState = { q: '', type: '', results: {} };
const RECON_TYPES = ['domain', 'ipv4', 'ipv6', 'asn', 'username', 'email', 'btc', 'cve'];
// DKIM selectors that identify the sending platform when present.
const DKIM_SELECTORS = [['google', 'Google Workspace'], ['selector1', 'Microsoft 365'], ['selector2', 'Microsoft 365'], ['k1', 'Mailchimp / Mandrill'], ['k2', 'Mailchimp'], ['s1', 'SendGrid'], ['s2', 'SendGrid'], ['mandrill', 'Mandrill'], ['protonmail', 'Proton Mail'], ['fm1', 'Fastmail'], ['zoho', 'Zoho Mail'], ['mxvault', 'Mailgun / other'], ['pm', 'Postmark'], ['default', ''], ['dkim', ''], ['mail', ''], ['smtp', ''], ['key1', ''], ['amazonses', 'Amazon SES']];
const kvRows = (rows, cls = 'mono') => `<dl class="kv">${rows.filter(([, v]) => v !== '' && v !== null && v !== undefined && v !== false).map(([k, v, raw]) => `<dt>${esc(k)}</dt><dd class="${cls} break">${raw ? v : esc(v)}</dd>`).join('')}</dl>`;
const extLink = (url, text) => (safeUrl(url) ? `<a href="${esc(safeUrl(url))}" target="_blank" rel="noopener noreferrer">${esc(text || url)} ↗</a>` : esc(text || url));

App.register({
  id: 'recon', label: 'Recon', icon: 'recon',
  render(el, params) {
    if (params.q) { rcState.q = params.q; rcState.type = params.type || ''; rcState.results = {}; }
    const on = App.settings.activeLookups;
    el.innerHTML = `
      ${viewHead('Recon', 'Live lookups for a <b>domain</b>, <b>IP</b>, <b>ASN</b>, <b>username</b>, <b>email</b>, <b>Bitcoin address</b> or <b>CVE</b>. DNS and mail posture, registration, certificates, exposed services, routing, public developer profiles, on-chain activity and exploit likelihood — pulled from public APIs, never from the target.')}
      ${on ? `<div class="banner warn"><span>⚠</span><div class="grow">Active lookups are <b>on</b>. Queries go from your IP to ${ACTIVE_SERVICES} — never directly to the target. Use a VPN or research VM if attribution matters.</div><button class="btn sm" id="rcoff">Turn off</button></div>`
        : `<div class="banner info"><span>ℹ</span><div class="grow">Passive mode: Lantern makes <b>no network requests</b>. Recon needs active lookups, which send your queries to public APIs (${ACTIVE_SERVICES}). The target itself is never contacted.</div><button class="btn sm primary" id="rcon">Enable active lookups</button></div>`}
      <form class="card row mt" id="rcf" autocomplete="off">
        <input id="rcq" class="grow mono" placeholder="example.com · 203.0.113.10 · AS15169 · username · name@example.com · bc1q… · CVE-2021-44228" value="${esc(rcState.q)}" spellcheck="false" ${on ? '' : 'disabled'} style="min-width:240px">
        <select id="rct" ${on ? '' : 'disabled'} aria-label="Selector type"><option value="">Auto-detect</option>${RECON_TYPES.map((t) => `<option value="${t}" ${rcState.type === t ? 'selected' : ''}>${esc(typeLabel(t))}</option>`).join('')}</select>
        <button class="btn primary" ${on ? '' : 'disabled'}>Run recon</button>
      </form>
      <div id="rcout" class="grid g2 mt"></div>`;
    $('#rcon', el)?.addEventListener('click', () => App.toggleActive());
    $('#rcoff', el)?.addEventListener('click', () => App.toggleActive());
    const out = $('#rcout', el);
    const card = (id, title, sub = '') => {
      let c = $(`#rc_${id}`, out);
      if (!c) { c = document.createElement('div'); c.className = 'card'; c.id = `rc_${id}`; out.appendChild(c); }
      c.innerHTML = `<h3>${esc(title)}<span class="spacer"></span><span class="muted small" data-st>${sub}</span></h3><div data-body><p class="muted small">Querying…</p></div>`;
      return { body: $('[data-body]', c), st: $('[data-st]', c), el: c };
    };
    const fail = (c, e, link) => { c.body.innerHTML = `<p class="small"><span class="status crit">Failed</span> ${esc(e.message)}</p>${link ? `<a class="lnk" href="${esc(link)}" target="_blank" rel="noopener noreferrer">Open the source site instead ↗</a>` : ''}`; };
    const addBtn = (type, value, label = '+') => `<button class="btn sm ghost" data-add="${esc(type)}" data-v="${esc(value)}" title="Add to case">${label}</button>`;

    async function runDomain(d) {
      // DNS
      const dns = card('dns', 'DNS records', 'DNS-over-HTTPS');
      try {
        const types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'CAA'];
        const res = await Promise.all(types.map((t) => doh(d, t).then((j) => [t, answers(j, t)]).catch(() => [t, []])));
        const rows = res.flatMap(([t, a]) => a.map((x) => ({ t, data: x.data, ttl: x.TTL })));
        rcState.results.dns = rows;
        dns.body.innerHTML = rows.length ? `<table class="tbl"><thead><tr><th>Type</th><th>Value</th><th class="num">TTL</th><th></th></tr></thead><tbody>${rows.map((r) => {
          const ipT = r.t === 'A' ? 'ipv4' : r.t === 'AAAA' ? 'ipv6' : null;
          const host = ['MX', 'NS', 'CNAME'].includes(r.t) ? r.data.split(' ').pop().replace(/\.$/, '') : null;
          return `<tr><td class="mono">${r.t}</td><td class="mono break">${esc(r.data)}</td><td class="num">${r.ttl}</td><td class="actions">${ipT ? addBtn(ipT, r.data) : host && isDomain(host) ? addBtn('domain', host) : ''}</td></tr>`;
        }).join('')}</tbody></table>` : '<p class="muted small">No records (NXDOMAIN or empty zone).</p>';
        dns.st.textContent = `${rows.length} records`;
      } catch (e) { fail(dns, e); }

      // Mail security
      const mail = card('mail', 'Email security posture', 'SPF · DMARC · MX');
      try {
        const [txt, dm, mx] = await Promise.all([doh(d, 'TXT'), doh('_dmarc.' + d, 'TXT'), doh(d, 'MX')]);
        const spf = answers(txt, 'TXT').map((a) => a.data).find((x) => /^v=spf1/i.test(x));
        const dmarc = answers(dm, 'TXT').map((a) => a.data).find((x) => /^v=DMARC1/i.test(x));
        const mxRaw = answers(mx, 'MX').map((a) => a.data.split(' ').pop().replace(/\.$/, ''));
        const nullMx = mxRaw.length === 1 && mxRaw[0] === '';
        const mxs = mxRaw.filter(Boolean);
        const pol = dmarc ? (dmarc.match(/;\s*p=(\w+)/i) || [])[1] : null;
        const prov = mxs.join(' ').match(/google|outlook|protection\.outlook|pphosted|mimecast|zoho|yandex|protonmail|icloud|messagingengine|secureserver|ovh|barracuda/i);
        const verifs = answers(txt, 'TXT').map((a) => a.data).filter((x) => /verification|verify|site-verification|_domainkey|MS=|atlassian|docusign|facebook-domain|apple-domain/i.test(x));
        mail.body.innerHTML = `<dl class="kv">
          <dt>SPF</dt><dd>${spf ? `<span class="status ${/[-~]all/.test(spf) ? 'good' : 'warn'}">${/-all/.test(spf) ? 'Strict (-all)' : /~all/.test(spf) ? 'Soft-fail (~all)' : 'Permissive'}</span><div class="mono small break">${esc(spf)}</div>` : '<span class="status crit">Missing</span> — anyone can spoof this domain'}</dd>
          <dt>DMARC</dt><dd>${dmarc ? `<span class="status ${pol === 'reject' ? 'good' : pol === 'quarantine' ? 'warn' : 'crit'}">p=${esc(pol || '?')}</span><div class="mono small break">${esc(dmarc)}</div>` : '<span class="status crit">Missing</span>'}</dd>
          <dt>Mail provider</dt><dd>${mxs.length ? `${prov ? `<b>${esc(prov[0])}</b> · ` : ''}<span class="mono small">${esc(mxs.join(', '))}</span>` : nullMx ? '<span class="muted">Null MX (RFC 7505) — the domain explicitly accepts no mail</span>' : '<span class="muted">No MX record — mail falls back to the A record, if any</span>'}</dd>
          ${verifs.length ? `<dt>Service verifications</dt><dd class="mono small break">${verifs.map(esc).join('<br>')}<div class="muted" style="font-family:var(--sans)">These reveal SaaS tools the organization uses.</div></dd>` : ''}
        </dl>`;
      } catch (e) { fail(mail, e); }

      // Hardening, DKIM selectors, third-party senders, wildcard
      const hard = card('hard', 'DNS hardening & mail services', 'DNSSEC · MTA-STS · DKIM · wildcard');
      try {
        const txtOf = async (name) => answers(await doh(name, 'TXT'), 'TXT').map((a) => a.data);
        const rnd = 'lantern-' + Math.random().toString(36).slice(2, 10);
        const [key, sts, rpt, bimi, wild, spfTxt, ...dk] = await Promise.all([
          doh(d, 'DNSKEY').catch(() => ({})), txtOf('_mta-sts.' + d).catch(() => []), txtOf('_smtp._tls.' + d).catch(() => []), txtOf('default._bimi.' + d).catch(() => []),
          doh(`${rnd}.${d}`, 'A').catch(() => ({})), txtOf(d).catch(() => []),
          ...DKIM_SELECTORS.map(([sel]) => doh(`${sel}._domainkey.${d}`, 'TXT').then((j) => (j.Answer || []).length > 0).catch(() => false)),
        ]);
        const signed = answers(key, 'DNSKEY').length > 0;
        const wildcard = answers(wild, 'A').map((a) => a.data);
        const sels = DKIM_SELECTORS.filter((_, i) => dk[i]);
        const spf = spfTxt.find((x) => /^v=spf1/i.test(x)) || '';
        const includes = [...spf.matchAll(/\b(?:include|redirect)[:=]([^\s]+)/gi)].map((m) => m[1].toLowerCase());
        rcState.results.hard = { signed, wildcard, sels: sels.map(([x]) => x), includes };
        hard.body.innerHTML = kvRows([
          ['DNSSEC', `<span class="status ${signed ? 'good' : 'warn'}">${signed ? 'Signed' : 'Unsigned'}</span>${signed ? '' : ' <span class="muted small">— answers can be spoofed in transit</span>'}`, true],
          ['MTA-STS', sts.find((x) => /^v=STSv1/i.test(x)) || 'not published'],
          ['TLS reporting', rpt.find((x) => /^v=TLSRPTv1/i.test(x)) || 'not published'],
          ['BIMI', bimi.find((x) => /^v=BIMI1/i.test(x)) || ''],
          ['DKIM selectors found', sels.length ? sels.map(([sel, who]) => `<span class="mono">${esc(sel)}</span>${who ? ` <span class="muted">(${esc(who)})</span>` : ''}`).join(' · ') : '<span class="muted">none of the common selectors</span>', true],
          ['SPF third parties', includes.length ? includes.map((h) => `<span class="mono">${esc(h)}</span>`).join('<br>') + '<div class="muted small" style="font-family:var(--sans)">Each include is a service allowed to send mail as this domain.</div>' : '', true],
          ['Wildcard DNS', wildcard.length ? `<span class="status warn">Yes</span> <span class="mono small">*.${esc(d)} → ${esc(wildcard.join(', '))}</span><div class="muted small">Any hostname resolves — treat brute-forced subdomains with suspicion.</div>` : '<span class="muted">No</span>', true],
        ], '');
      } catch (e) { fail(hard, e); }

      // RDAP
      const rd = card('rdap', 'Registration (RDAP)', 'rdap.org');
      try {
        const j = await fetchJSON(`https://rdap.org/domain/${encodeURIComponent(d)}`);
        const ev = rdapEvents(j);
        const registrar = (j.entities || []).find((e) => (e.roles || []).includes('registrar'));
        const registrant = (j.entities || []).find((e) => (e.roles || []).includes('registrant'));
        const age = ev.registration ? Math.floor((Date.now() - new Date(ev.registration)) / 86400000) : null;
        rcState.results.rdap = { ev, d };
        rd.body.innerHTML = `<dl class="kv">
          <dt>Registrar</dt><dd>${esc(vcardName(registrar) || '—')}</dd>
          ${registrant && vcardName(registrant) ? `<dt>Registrant</dt><dd>${esc(vcardName(registrant))}</dd>` : ''}
          <dt>Registered</dt><dd>${ev.registration ? `${esc(fmtUTC(ev.registration))} <span class="status ${age < 30 ? 'crit' : age < 365 ? 'warn' : 'good'}">${age} days old</span>` : '—'}</dd>
          <dt>Expires</dt><dd>${esc(fmtUTC(ev.expiration) || '—')}</dd>
          <dt>Last changed</dt><dd>${esc(fmtUTC(ev['last changed']) || '—')}</dd>
          <dt>Status</dt><dd class="small">${esc((j.status || []).join(', ') || '—')}</dd>
          <dt>Nameservers</dt><dd class="mono small">${(j.nameservers || []).map((n) => esc(n.ldhName?.toLowerCase())).join('<br>') || '—'}</dd>
        </dl>
        ${age !== null && age < 30 ? '<p class="small"><span class="status crit">Newly registered</span> Domains under 30 days old are a common phishing indicator.</p>' : ''}
        ${ev.registration ? `<button class="btn sm mt" id="rdtl">Add registration date to timeline</button>` : ''}`;
        $('#rdtl', rd.el)?.addEventListener('click', () => { addEventQuick({ when: ev.registration, title: `Domain registered: ${d}`, source: `https://rdap.org/domain/${d}`, entityValue: ['domain', d] }); });
      } catch (e) { fail(rd, e, `https://lookup.icann.org/en/lookup?name=${encodeURIComponent(d)}`); }

      // crt.sh
      const ct = card('ct', 'Certificate transparency — subdomains', 'certspotter · crt.sh');
      try {
        // certspotter answers browsers (CORS) and is fast; crt.sh is the fallback (often slow, no CORS on some networks).
        let rows, via;
        try {
          const j = await fetchJSON(`https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(d)}&include_subdomains=true&expand=dns_names`, {}, 25000);
          rows = j.flatMap((x) => (x.dns_names || []).map((n) => ({ n, t: x.not_before }))); via = 'certspotter (first page)';
        } catch {
          const j = await fetchJSON(`https://crt.sh/?q=${encodeURIComponent('%.' + d)}&output=json`, {}, 45000);
          rows = j.flatMap((x) => String(x.name_value).split('\n').map((n) => ({ n, t: x.not_before }))); via = 'crt.sh';
        }
        const names = new Map();
        for (const { n, t } of rows) {
          const h = n.trim().toLowerCase().replace(/^\*\./, '');
          if (!(h === d || h.endsWith('.' + d)) || h.includes(' ')) continue;
          const first = names.get(h); if (!first || String(t) < first) names.set(h, String(t || ''));
        }
        const list = [...names.entries()].sort((a, b) => a[0].localeCompare(b[0]));
        rcState.results.subs = list.map(([h]) => h);
        ct.st.textContent = `${list.length} unique names · ${via}`;
        ct.body.innerHTML = list.length ? `<div class="row mb"><button class="btn sm" id="ctall">Add all to case</button><button class="btn sm ghost" id="ctcopy">Copy list</button></div><div style="max-height:340px;overflow:auto"><table class="tbl"><thead><tr><th>Hostname</th><th>First cert</th><th></th></tr></thead><tbody>${list.map(([h, t]) => `<tr><td class="mono break">${esc(h)}</td><td class="mono small nowrap">${esc(String(t).slice(0, 10))}</td><td class="actions">${addBtn('domain', h)}</td></tr>`).join('')}</tbody></table></div>` : '<p class="muted small">No certificates logged for this domain.</p>';
        $('#ctall', ct.el)?.addEventListener('click', () => { let n = 0; list.forEach(([h]) => { if (App.addEntity('domain', h, { source: 'crt.sh' }).created) n++; }); App.touch(`Recon: added ${n} subdomains of ${d}`); toast(`${n} subdomains added`); });
        $('#ctcopy', ct.el)?.addEventListener('click', () => copyText(list.map(([h]) => h).join('\n')));
      } catch (e) { fail(ct, e, `https://crt.sh/?q=%25.${encodeURIComponent(d)}`); }

      await runWayback(d);
    }

    async function runWayback(target) {
      const wb = card('wb', 'Web archive history', 'Wayback availability API');
      try {
        // The availability API returns the capture closest to a timestamp: ask for 1990 (≈ first) and now (≈ latest).
        const base = `https://archive.org/wayback/available?url=${encodeURIComponent(target)}`;
        const [first, last] = await Promise.all([fetchJSON(base + '&timestamp=19900101'), fetchJSON(base)]);
        const f = first.archived_snapshots?.closest, l = last.archived_snapshots?.closest;
        const ts = (s) => s ? `${s.slice(0, 4)}-${s.slice(4, 6)}-${s.slice(6, 8)} ${s.slice(8, 10)}:${s.slice(10, 12)}Z` : '—';
        const link = (x) => (x && safeUrl(x.url) ? ` <a href="${esc(safeUrl(x.url))}" target="_blank" rel="noopener noreferrer">view ↗</a>` : '');
        wb.body.innerHTML = f || l ? `<dl class="kv"><dt>Earliest capture</dt><dd class="mono">${ts(f?.timestamp)}${link(f)}</dd><dt>Latest capture</dt><dd class="mono">${ts(l?.timestamp)}${link(l)}</dd></dl>
          <div class="row mt"><a class="lnk" href="https://web.archive.org/web/*/${esc(target)}*" target="_blank" rel="noopener noreferrer">All captures ↗</a>${f?.timestamp ? `<button class="btn sm" id="wbtl">Add first capture to timeline</button>` : ''}</div>` : '<p class="muted small">Never archived.</p>';
        $('#wbtl', wb.el)?.addEventListener('click', () => {
          const t = f.timestamp; addEventQuick({ when: `${t.slice(0, 4)}-${t.slice(4, 6)}-${t.slice(6, 8)}T${t.slice(8, 10)}:${t.slice(10, 12)}:${t.slice(12, 14)}Z`, title: `First archived capture of ${target}`, source: f.url, category: 'Domain / infra', entityValue: ['domain', target] });
        });
      } catch (e) { fail(wb, e, `https://web.archive.org/web/*/${target}`); }
    }

    async function runIP(ip) {
      const info = card('ipinfo', 'IP context', 'ipinfo.io');
      try {
        const j = await fetchJSON(`https://ipinfo.io/${encodeURIComponent(ip)}/json`);
        info.body.innerHTML = `<dl class="kv">${[['Hostname', j.hostname], ['Organization / ASN', j.org], ['City', j.city], ['Region', j.region], ['Country', j.country], ['Coordinates', j.loc], ['Timezone', j.timezone], ['Anycast', j.anycast ? 'yes' : ''], ['Bogon', j.bogon ? 'yes — not publicly routable' : '']].filter(([, v]) => v).map(([k, v]) => `<dt>${k}</dt><dd class="mono">${esc(v)}</dd>`).join('')}</dl>
          ${j.loc ? `<div class="row mt">${addBtn('location', j.loc, '+ Add location')}<span class="muted small">IP geolocation is approximate (city level at best).</span></div>` : ''}`;
      } catch (e) { fail(info, e, `https://ipinfo.io/${ip}`); }
      const ptr = card('ptr', 'Reverse DNS', 'PTR via DoH');
      try {
        const a = answers(await doh(ptrName(ip), 'PTR'), 'PTR');
        ptr.body.innerHTML = a.length ? a.map((x) => { const h = x.data.replace(/\.$/, ''); return `<div class="row"><span class="mono break">${esc(h)}</span>${isDomain(h) ? addBtn('domain', h) : ''}</div>`; }).join('') : '<p class="muted small">No PTR record.</p>';
      } catch (e) { fail(ptr, e); }
      const rd = card('rdapip', 'Network owner (RDAP)', 'rdap.org');
      try {
        const j = await fetchJSON(`https://rdap.org/ip/${encodeURIComponent(ip)}`);
        const ents = (j.entities || []).map((e) => `${vcardName(e) || e.handle} (${(e.roles || []).join(', ')})`);
        rd.body.innerHTML = `<dl class="kv">${[['Network name', j.name], ['Handle', j.handle], ['Range', j.startAddress && `${j.startAddress} – ${j.endAddress}`], ['CIDR', (j.cidr0_cidrs || []).map((c) => `${c.v4prefix || c.v6prefix}/${c.length}`).join(', ')], ['Country', j.country], ['Type', j.type], ['Contacts', ents.join('; ')], ['Registered', fmtUTC(rdapEvents(j).registration)]].filter(([, v]) => v).map(([k, v]) => `<dt>${k}</dt><dd class="small">${esc(v)}</dd>`).join('')}</dl>`;
      } catch (e) { fail(rd, e, `https://search.arin.net/rdap/?query=${ip}`); }

      const idb = card('idb', 'Exposed services', 'Shodan InternetDB');
      try {
        const j = await fetchJSON(`https://internetdb.shodan.io/${encodeURIComponent(ip)}`).catch((e) => { if (/HTTP 404/.test(e.message)) return { none: true }; throw e; });
        if (j.none) idb.body.innerHTML = '<p class="muted small">No scan data — nothing has been observed listening on this address.</p>';
        else {
          const vulns = j.vulns || [];
          idb.body.innerHTML = kvRows([
            ['Open ports', (j.ports || []).join(', ') || '—'],
            ['Tags', (j.tags || []).join(', ')],
            ['Hostnames', (j.hostnames || []).map((h) => `<span class="mono">${esc(h)}</span> ${isDomain(h) ? addBtn('domain', h) : ''}`).join('<br>'), true],
            ['Software (CPE)', (j.cpes || []).map(esc).join('<br>'), true],
            ['Known CVEs', vulns.length ? `<span class="status crit">${vulns.length}</span> ` + vulns.slice(0, 40).map((v) => `<span class="mono small">${esc(v)}</span> ${addBtn('cve', v)}`).join(' ') + (vulns.length > 40 ? ` <span class="muted">+${vulns.length - 40} more</span>` : '') : '', true],
          ], '') + `<p class="muted small">Passive data from Shodan’s weekly scans. CVEs are inferred from banners, not verified. ${extLink(`https://www.shodan.io/host/${ip}`, 'Full Shodan report')}</p>`;
          idb.st.textContent = `${(j.ports || []).length} ports · ${vulns.length} CVEs`;
        }
      } catch (e) { fail(idb, e, `https://www.shodan.io/host/${ip}`); }

      const rt = card('route', 'Routing & abuse contact', 'RIPEstat');
      try {
        const [po, ab] = await Promise.all([fetchJSON(`https://stat.ripe.net/data/prefix-overview/data.json?resource=${encodeURIComponent(ip)}`), fetchJSON(`https://stat.ripe.net/data/abuse-contact-finder/data.json?resource=${encodeURIComponent(ip)}`).catch(() => ({}))]);
        const asns = po.data?.asns || [], abuse = ab.data?.abuse_contacts || [];
        rt.body.innerHTML = kvRows([
          ['Announced prefix', po.data?.announced ? po.data.resource : 'not announced in BGP'],
          ['Origin AS', asns.map((a) => `<span class="mono">AS${esc(a.asn)}</span> ${esc(a.holder || '')} ${addBtn('asn', 'AS' + a.asn)} <a class="small" href="#" data-rc="AS${esc(a.asn)}">recon</a>`).join('<br>'), true],
          ['Registry block', [po.data?.block?.name, po.data?.block?.desc].filter(Boolean).join(' — ')],
          ['Abuse contact', abuse.map((m) => `<span class="mono">${esc(m)}</span> ${addBtn('email', m)}`).join('<br>'), true],
        ], '');
      } catch (e) { fail(rt, e, `https://stat.ripe.net/${ip}`); }
    }

    async function runASN(asn) {
      const num = asn.replace(/^AS/i, '');
      const ov = card('asov', `AS${num}`, 'RIPEstat');
      try {
        const [o, p] = await Promise.all([fetchJSON(`https://stat.ripe.net/data/as-overview/data.json?resource=AS${num}`), fetchJSON(`https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS${num}`).catch(() => ({}))]);
        const pref = (p.data?.prefixes || []).map((x) => x.prefix);
        const v4 = pref.filter((x) => !x.includes(':')), v6 = pref.filter((x) => x.includes(':'));
        const size = v4.reduce((n, c) => n + 2 ** (32 - +c.split('/')[1]), 0);
        rcState.results.prefixes = pref;
        ov.body.innerHTML = kvRows([['Holder', o.data?.holder], ['Announced', o.data?.announced ? 'yes' : 'no — not currently visible in BGP'], ['Registry block', [o.data?.block?.name, o.data?.block?.desc].filter(Boolean).join(' — ')], ['IPv4 prefixes', `${v4.length} (${size.toLocaleString()} addresses)`], ['IPv6 prefixes', String(v6.length)]], '')
          + (pref.length ? `<div class="row mt"><button class="btn sm ghost" id="aspcopy">Copy ${pref.length} prefixes</button></div><div class="mono small mt" style="max-height:220px;overflow:auto">${pref.slice(0, 400).map(esc).join('<br>')}</div>` : '');
        $('#aspcopy', ov.el)?.addEventListener('click', () => copyText(pref.join('\n')));
      } catch (e) { fail(ov, e, `https://bgp.he.net/AS${num}`); }
      const rd = card('asrdap', 'Registration (RDAP)', 'rdap.org');
      try {
        const j = await fetchJSON(`https://rdap.org/autnum/${num}`);
        const ev = rdapEvents(j);
        rd.body.innerHTML = kvRows([['Name', j.name], ['Handle', j.handle], ['Country', j.country], ['Contacts', (j.entities || []).map((e) => `${vcardName(e) || e.handle} (${(e.roles || []).join(', ')})`).join('; ')], ['Registered', fmtUTC(ev.registration)], ['Last changed', fmtUTC(ev['last changed'])]], 'small');
      } catch (e) { fail(rd, e, `https://www.peeringdb.com/asn/${num}`); }
    }

    // ---- username: public developer / social APIs that answer browsers
    async function runUsername(u) {
      u = u.replace(/^@/, '');
      const found = (c, n) => { c.st.innerHTML = n ? '<span class="status good">found</span>' : '<span class="muted">not found</span>'; };
      const notFound = (c, e, link) => { if (/HTTP 404/.test(e.message)) { c.body.innerHTML = '<p class="muted small">No account with this exact name.</p>'; found(c, 0); } else fail(c, e, link); };
      const created = (when, what, url) => (when ? ` <button class="btn sm ghost" data-ev="${esc(when)}" data-evt="${esc(what)}" data-evs="${esc(url)}">→ timeline</button>` : '');

      const gh = card('gh', 'GitHub', 'api.github.com');
      try {
        const j = await fetchJSON(`https://api.github.com/users/${encodeURIComponent(u)}`);
        found(gh, 1);
        gh.body.innerHTML = kvRows([
          ['Profile', `${extLink(j.html_url, j.login)} ${addBtn('url', j.html_url)}`, true], ['Numeric ID', String(j.id)], ['Name', j.name ? `${esc(j.name)} ${addBtn('person', j.name)}` : '', true], ['Type', j.type],
          ['Company', j.company], ['Location', j.location], ['Public email', j.email ? `${esc(j.email)} ${addBtn('email', j.email)}` : '', true],
          ['Website', j.blog ? `${extLink(/^https?:/i.test(j.blog) ? j.blog : 'https://' + j.blog, j.blog)}` : '', true],
          ['X / Twitter', j.twitter_username ? `${esc(j.twitter_username)} ${addBtn('username', j.twitter_username)}` : '', true],
          ['Bio', j.bio], ['Repos · followers', `${j.public_repos} · ${j.followers}`],
          ['Created', `${esc(fmtUTC(j.created_at))}${created(j.created_at, `GitHub account ${j.login} created`, j.html_url)}`, true], ['Last profile update', fmtUTC(j.updated_at)],
        ], '') + '<div id="ghc" class="mt"><p class="muted small">Looking for commit identities…</p></div>';
        try {
          const cs = await fetchJSON(`https://api.github.com/search/commits?q=${encodeURIComponent('author:' + u)}&sort=author-date&order=desc&per_page=100`, { headers: { accept: 'application/vnd.github+json' } });
          const ids = new Map();
          for (const it of cs.items || []) { const a = it.commit?.author || {}; if (!a.email) continue; const k = a.email.toLowerCase(); const o = ids.get(k) || { email: a.email, names: new Set(), n: 0, tz: new Set() }; o.n++; if (a.name) o.names.add(a.name); const tz = String(a.date || '').match(/([+-]\d\d:\d\d|Z)$/); if (tz) o.tz.add(tz[1] === 'Z' ? '+00:00' : tz[1]); ids.set(k, o); }
          const list = [...ids.values()].sort((a, b) => b.n - a.n);
          $('#ghc', gh.el).innerHTML = list.length ? `<h4 style="margin:0 0 6px">Commit identities <span class="muted small">(last ${cs.items.length} of ${cs.total_count} public commits)</span></h4><table class="tbl"><thead><tr><th>Email</th><th>Name(s)</th><th>UTC offsets</th><th class="num">Commits</th><th></th></tr></thead><tbody>${list.map((o) => `<tr><td class="mono break">${esc(o.email)}</td><td class="small">${esc([...o.names].join(', '))}</td><td class="mono small">${esc([...o.tz].join(' '))}</td><td class="num">${o.n}</td><td class="actions">${/noreply/i.test(o.email) ? '' : addBtn('email', o.email)}</td></tr>`).join('')}</tbody></table><p class="muted small">Git records the author’s email and local UTC offset in every commit — offsets hint at the time zone the work was done in.</p>` : '<p class="muted small">No public commits attributed to this account.</p>';
        } catch (e) { $('#ghc', gh.el).innerHTML = `<p class="muted small">Commit search unavailable (${esc(e.message)}) — GitHub rate-limits anonymous search to 10 per minute.</p>`; }
      } catch (e) { notFound(gh, e, `https://github.com/${u}`); }

      const gl = card('gl', 'GitLab', 'gitlab.com');
      try {
        const j = (await fetchJSON(`https://gitlab.com/api/v4/users?username=${encodeURIComponent(u)}`))[0];
        found(gl, j ? 1 : 0);
        gl.body.innerHTML = j ? kvRows([['Profile', `${extLink(j.web_url, j.username)} ${addBtn('url', j.web_url)}`, true], ['Numeric ID', String(j.id)], ['Name', j.name ? `${esc(j.name)} ${addBtn('person', j.name)}` : '', true], ['State', j.state]], '') : '<p class="muted small">No account with this exact name.</p>';
      } catch (e) { fail(gl, e, `https://gitlab.com/${u}`); }

      const bs = card('bsky', 'Bluesky', 'public.api.bsky.app · plc.directory');
      try {
        const handle = u.includes('.') ? u : `${u}.bsky.social`;
        const j = await fetchJSON(`https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor=${encodeURIComponent(handle)}`).catch((e) => { if (/HTTP 400/.test(e.message)) throw new Error('HTTP 404'); throw e; });
        found(bs, 1);
        const url = `https://bsky.app/profile/${j.handle}`;
        bs.body.innerHTML = kvRows([
          ['Profile', `${extLink(url, j.handle)} ${addBtn('url', url)}`, true], ['Display name', j.displayName], ['DID (permanent ID)', j.did], ['Bio', j.description],
          ['Posts · followers · following', `${j.postsCount ?? '?'} · ${j.followersCount ?? '?'} · ${j.followsCount ?? '?'}`],
          ['Created', j.createdAt ? `${esc(fmtUTC(j.createdAt))}${created(j.createdAt, `Bluesky account ${j.handle} created`, url)}` : '', true],
        ], '') + '<div id="plc" class="mt"></div>';
        if (/^did:plc:/.test(j.did)) {
          try {
            const log = await fetchJSON(`https://plc.directory/${j.did}/log/audit`);
            const hist = []; let last = '';
            for (const op of log) { const h = (op.operation?.alsoKnownAs || [])[0]?.replace(/^at:\/\//, '') || ''; const pds = op.operation?.services?.atproto_pds?.endpoint || ''; const key = h + '|' + pds; if (key !== last) { hist.push({ h, pds, t: op.createdAt }); last = key; } }
            $('#plc', bs.el).innerHTML = `<h4 style="margin:0 0 6px">Handle history <span class="muted small">(PLC directory audit log)</span></h4><table class="tbl"><thead><tr><th>From (UTC)</th><th>Handle</th><th>Data server</th><th></th></tr></thead><tbody>${hist.map((x) => `<tr><td class="mono small nowrap">${esc(fmtUTC(x.t, false))}</td><td class="mono break">${esc(x.h)}</td><td class="mono small break">${esc(x.pds.replace(/^https?:\/\//, ''))}</td><td class="actions">${x.h && x.h !== j.handle ? (isDomain(x.h) && !/\.bsky\.social$/.test(x.h) ? addBtn('domain', x.h) : addBtn('username', x.h.replace(/\.bsky\.social$/, ''))) : ''}</td></tr>`).join('')}</tbody></table><p class="muted small">Renaming a Bluesky account does not erase earlier handles — custom-domain handles in this list tie the account to a domain its owner controlled.</p>`;
          } catch { /* history is a bonus */ }
        }
      } catch (e) { notFound(bs, e, `https://bsky.app/profile/${u}`); }

      const hn = card('hn', 'Hacker News', 'hn.algolia.com');
      try {
        const j = await fetchJSON(`https://hn.algolia.com/api/v1/users/${encodeURIComponent(u)}`);
        found(hn, 1);
        const url = `https://news.ycombinator.com/user?id=${encodeURIComponent(j.username)}`;
        hn.body.innerHTML = kvRows([['Profile', `${extLink(url, j.username)} ${addBtn('url', url)}`, true], ['Karma', String(j.karma ?? '')], ['About', htmlToText(j.about || '')], ['Created', j.created_at ? `${esc(fmtUTC(j.created_at))}${created(j.created_at, `Hacker News account ${j.username} created`, url)}` : '', true]], '')
          + (j.about ? `<button class="btn sm ghost mt" id="hnx">Extract selectors from bio</button>` : '');
        $('#hnx', hn.el)?.addEventListener('click', () => App.go('extractor', { text: htmlToText(j.about) }));
      } catch (e) { notFound(hn, e, `https://news.ycombinator.com/user?id=${u}`); }

      const kb = card('kb', 'Keybase', 'keybase.io');
      try {
        const j = await fetchJSON(`https://keybase.io/_/api/1.0/user/lookup.json?usernames=${encodeURIComponent(u.toLowerCase())}&fields=basics,profile,proofs_summary,public_keys`);
        const t = (j.them || [])[0];
        found(kb, t ? 1 : 0);
        if (!t) kb.body.innerHTML = '<p class="muted small">No account with this exact name.</p>';
        else {
          const proofs = t.proofs_summary?.all || [], url = `https://keybase.io/${t.basics?.username}`;
          const ctime = t.basics?.ctime ? new Date(t.basics.ctime * 1000).toISOString() : '';
          kb.body.innerHTML = kvRows([['Profile', `${extLink(url, t.basics?.username)} ${addBtn('url', url)}`, true], ['Name', t.profile?.full_name ? `${esc(t.profile.full_name)} ${addBtn('person', t.profile.full_name)}` : '', true], ['Location', t.profile?.location], ['Bio', t.profile?.bio], ['PGP fingerprint', t.public_keys?.primary?.key_fingerprint], ['Created', ctime ? `${esc(fmtUTC(ctime))}${created(ctime, `Keybase account ${t.basics.username} created`, url)}` : '', true]], '')
            + (proofs.length ? `<h4 style="margin:12px 0 6px">Cryptographically proven accounts</h4><table class="tbl"><tbody>${proofs.map((p) => { const dom = ['dns', 'generic_web_site'].includes(p.proof_type) || isDomain(p.nametag); return `<tr><td class="small">${esc(p.proof_type)}</td><td class="mono break">${extLink(p.service_url, p.nametag)}</td><td class="actions">${addBtn(dom ? 'domain' : 'username', p.nametag)}</td></tr>`; }).join('')}</tbody></table><p class="muted small">Keybase proofs are signed by the account owner — strong evidence that these identities belong to the same person.</p>` : '');
        }
      } catch (e) { fail(kb, e, `https://keybase.io/${u}`); }
    }

    async function runEmail(email) {
      const [local, d] = email.split('@');
      const sum = card('em', 'Address', 'offline analysis');
      sum.body.innerHTML = kvRows([['Local part', local], ['Domain', d], ['Plus-addressing base', /\+/.test(local) ? `${local.split('+')[0]}@${d}` : ''], ['Provider type', FREEMAIL.has(d) ? 'Free webmail — the domain says nothing about the owner' : 'Custom / organizational domain — run recon on it'], ['Gravatar hash (SHA-256)', sha256(email)]])
        + `<div class="row mt">${FREEMAIL.has(d) ? '' : `<button class="btn sm" data-rc="${esc(d)}">Recon ${esc(d)}</button>`}<button class="btn sm ghost" data-pv="${esc(email)}">All pivots</button></div>`;
      const gh = card('ghe', 'GitHub commits by this address', 'api.github.com');
      try {
        const cs = await fetchJSON(`https://api.github.com/search/commits?q=${encodeURIComponent('author-email:' + email)}&sort=author-date&order=desc&per_page=50`, { headers: { accept: 'application/vnd.github+json' } });
        const who = new Map();
        for (const it of cs.items || []) { const login = it.author?.login || '', name = it.commit?.author?.name || ''; const k = login || name; if (!k) continue; const o = who.get(k) || { login, names: new Set(), repos: new Set(), n: 0 }; o.n++; if (name) o.names.add(name); if (it.repository?.full_name) o.repos.add(it.repository.full_name); who.set(k, o); }
        const list = [...who.values()].sort((a, b) => b.n - a.n);
        gh.st.textContent = `${cs.total_count} commits`;
        gh.body.innerHTML = list.length ? `<table class="tbl"><thead><tr><th>Account</th><th>Name(s) used</th><th>Repositories</th><th></th></tr></thead><tbody>${list.map((o) => `<tr><td class="mono">${o.login ? extLink(`https://github.com/${o.login}`, o.login) : '<span class="muted">unlinked</span>'}</td><td class="small">${esc([...o.names].join(', '))}</td><td class="mono small break">${esc([...o.repos].slice(0, 6).join(', '))}${o.repos.size > 6 ? ` +${o.repos.size - 6}` : ''}</td><td class="actions">${o.login ? addBtn('username', o.login) : ''}${[...o.names][0] ? addBtn('person', [...o.names][0], '+ name') : ''}</td></tr>`).join('')}</tbody></table><p class="muted small">A commit signed with this address reveals the GitHub account and the real name configured in the author’s Git client.</p>` : '<p class="muted small">No public commits use this address.</p>';
      } catch (e) { fail(gh, e, `https://github.com/search?q=author-email%3A${encodeURIComponent(email)}&type=commits`); }
      if (!FREEMAIL.has(d) && isDomain(d)) await runMailOnly(d);
    }
    async function runMailOnly(d) {
      const mail = card('mail', `Mail setup of ${d}`, 'SPF · DMARC · MX');
      try {
        const [txt, dm, mx] = await Promise.all([doh(d, 'TXT'), doh('_dmarc.' + d, 'TXT'), doh(d, 'MX')]);
        const spf = answers(txt, 'TXT').map((a) => a.data).find((x) => /^v=spf1/i.test(x));
        const dmarc = answers(dm, 'TXT').map((a) => a.data).find((x) => /^v=DMARC1/i.test(x));
        const mxs = answers(mx, 'MX').map((a) => a.data.split(' ').pop().replace(/\.$/, '')).filter(Boolean);
        mail.body.innerHTML = kvRows([['MX', mxs.join(', ') || 'none — this domain cannot receive mail'], ['SPF', spf || 'missing'], ['DMARC', dmarc || 'missing']]) + (mxs.length ? '' : '<p class="small"><span class="status crit">Undeliverable</span> Addresses at this domain cannot receive mail — likely fabricated or abandoned.</p>');
      } catch (e) { fail(mail, e); }
    }

    async function runBTC(addr) {
      const c = card('btc', 'On-chain summary', 'Blockstream · mempool.space');
      const sat = (n) => `${(n / 1e8).toLocaleString(undefined, { maximumFractionDigits: 8 })} BTC`;
      try {
        let base = 'https://blockstream.info/api', j;
        try { j = await fetchJSON(`${base}/address/${encodeURIComponent(addr)}`); } catch { base = 'https://mempool.space/api'; j = await fetchJSON(`${base}/address/${encodeURIComponent(addr)}`); }
        const s = j.chain_stats || {}, m = j.mempool_stats || {};
        c.st.textContent = base.replace(/^https:\/\/|\/api$/g, '');
        c.body.innerHTML = kvRows([['Balance', sat((s.funded_txo_sum || 0) - (s.spent_txo_sum || 0))], ['Total received', sat(s.funded_txo_sum || 0)], ['Total sent', sat(s.spent_txo_sum || 0)], ['Transactions', String(s.tx_count ?? 0)], ['Unconfirmed', m.tx_count ? `${m.tx_count} in mempool` : '']]) + '<div id="btx" class="mt"><p class="muted small">Loading recent transactions…</p></div>';
        try {
          const txs = await fetchJSON(`${base}/address/${encodeURIComponent(addr)}/txs`);
          const rows = txs.map((t) => {
            const inMine = (t.vin || []).filter((v) => v.prevout?.scriptpubkey_address === addr).reduce((n, v) => n + v.prevout.value, 0);
            const outMine = (t.vout || []).filter((v) => v.scriptpubkey_address === addr).reduce((n, v) => n + v.value, 0);
            const net = outMine - inMine;
            const others = [...new Set((net >= 0 ? (t.vin || []).map((v) => v.prevout?.scriptpubkey_address) : (t.vout || []).map((v) => v.scriptpubkey_address)).filter((a) => a && a !== addr))];
            return { txid: t.txid, when: t.status?.block_time ? new Date(t.status.block_time * 1000).toISOString() : '', net, others };
          });
          const oldest = rows[rows.length - 1];
          $('#btx', c.el).innerHTML = rows.length ? `<h4 style="margin:0 0 6px">Latest ${rows.length} transactions</h4><div style="max-height:360px;overflow:auto"><table class="tbl"><thead><tr><th>When (UTC)</th><th class="num">Net</th><th>Counterparties</th></tr></thead><tbody>${rows.map((r) => `<tr><td class="mono small nowrap">${r.when ? esc(fmtUTC(r.when, false)) : 'unconfirmed'}<div>${extLink(`https://mempool.space/tx/${r.txid}`, r.txid.slice(0, 10) + '…')}</div></td><td class="num mono nowrap"><span class="status ${r.net >= 0 ? 'good' : 'warn'}">${r.net >= 0 ? '+' : '−'}${esc(sat(Math.abs(r.net)))}</span></td><td class="mono small break">${r.others.slice(0, 4).map((a) => `${esc(a)} ${addBtn('btc', a)}`).join('<br>')}${r.others.length > 4 ? `<div class="muted">+${r.others.length - 4} more</div>` : ''}</td></tr>`).join('')}</tbody></table></div>
            ${(s.tx_count || 0) <= rows.length && oldest?.when ? `<button class="btn sm mt" id="btl">Add first activity to timeline</button>` : ''}
            <p class="muted small">Inputs spent together are usually controlled by one wallet (common-input heuristic); exchange and mixer addresses break that assumption. Counterparty lists are not proof of a relationship.</p>` : '<p class="muted small">No transactions.</p>';
          $('#btl', c.el)?.addEventListener('click', () => addEventQuick({ when: oldest.when, title: `First on-chain activity of ${trunc(addr, 20)}`, category: 'Transaction', source: `https://mempool.space/tx/${oldest.txid}`, entityValue: ['btc', addr] }));
        } catch (e) { $('#btx', c.el).innerHTML = `<p class="muted small">Transactions unavailable: ${esc(e.message)}</p>`; }
      } catch (e) { fail(c, e, `https://mempool.space/address/${addr}`); }
    }

    async function runCVE(id) {
      const c = card('cve', id, 'MITRE CVE record');
      try {
        const j = await fetchJSON(`https://cveawg.mitre.org/api/cve/${encodeURIComponent(id)}`);
        const cna = j.containers?.cna || {}, adp = j.containers?.adp || [];
        const metrics = [...(cna.metrics || []), ...adp.flatMap((a) => a.metrics || [])];
        const cvss = metrics.map((m) => m.cvssV4_0 || m.cvssV3_1 || m.cvssV3_0 || m.cvssV2_0).find(Boolean);
        const kev = metrics.map((m) => m.other).find((o) => o?.type === 'kev');
        const ssvc = metrics.map((m) => m.other).find((o) => o?.type === 'ssvc');
        const sev = cvss?.baseSeverity || (cvss?.baseScore >= 9 ? 'CRITICAL' : cvss?.baseScore >= 7 ? 'HIGH' : cvss?.baseScore >= 4 ? 'MEDIUM' : 'LOW');
        const affected = (cna.affected || []).map((a) => [a.vendor, a.product].filter((x) => x && x !== 'n/a').join(' ')).filter(Boolean);
        const refs = (cna.references || []).map((r) => r.url).filter(safeUrl);
        const desc = (cna.descriptions || []).find((x) => /^en/i.test(x.lang))?.value || cna.descriptions?.[0]?.value || '';
        c.body.innerHTML = (j.cveMetadata?.state === 'REJECTED' ? '<p><span class="status warn">Rejected</span> This CVE ID was withdrawn.</p>' : '') + kvRows([
          ['Title', cna.title], ['Description', desc],
          ['CVSS', cvss ? `<span class="status ${/CRIT|HIGH/.test(sev) ? 'crit' : sev === 'MEDIUM' ? 'warn' : 'good'}">${esc(cvss.baseScore)} ${esc(sev)}</span> <span class="mono small">${esc(cvss.vectorString || '')}</span>` : '<span class="muted">not scored in the record</span>', true],
          ['Known exploited (CISA KEV)', kev ? `<span class="status crit">Yes</span> added ${esc(kev.content?.dateAdded || '')}` : '', true],
          ['SSVC (CISA)', ssvc ? (ssvc.content?.options || []).map((o) => Object.entries(o).map(([k, v]) => `${k}: ${v}`).join('')).join(' · ') : ''],
          ['Affected', [...new Set(affected)].slice(0, 12).join('; ')],
          ['Published', j.cveMetadata?.datePublished ? `${esc(fmtUTC(j.cveMetadata.datePublished))} <button class="btn sm ghost" data-ev="${esc(j.cveMetadata.datePublished)}" data-evt="${esc(id)} published" data-evs="https://www.cve.org/CVERecord?id=${esc(id)}">→ timeline</button>` : '', true],
          ['Assigner', j.cveMetadata?.assignerShortName],
          ['References', refs.slice(0, 12).map((u) => extLink(u, trunc(u, 90))).join('<br>') + (refs.length > 12 ? `<div class="muted">+${refs.length - 12} more</div>` : ''), true],
        ], '');
      } catch (e) { fail(c, e, `https://www.cve.org/CVERecord?id=${id}`); }
      const ep = card('epss', 'Exploit prediction (EPSS)', 'FIRST.org');
      try {
        const d = (await fetchJSON(`https://api.first.org/data/v1/epss?cve=${encodeURIComponent(id)}`)).data?.[0];
        if (!d) ep.body.innerHTML = '<p class="muted small">No EPSS score yet.</p>';
        else { const p = +d.epss, pct = +d.percentile; ep.body.innerHTML = `<div class="row"><span class="status ${p >= 0.5 ? 'crit' : p >= 0.1 ? 'warn' : 'good'}">${(p * 100).toFixed(2)}%</span><span class="small">probability of exploitation in the next 30 days</span></div><div class="progress mt"><div style="width:${(pct * 100).toFixed(1)}%"></div></div><p class="muted small">Higher than ${(pct * 100).toFixed(1)}% of all scored CVEs · model date ${esc(d.date || '')}. EPSS estimates likelihood, CVSS measures severity — prioritise on both.</p>`; }
      } catch (e) { fail(ep, e, `https://api.first.org/data/v1/epss?cve=${id}`); }
    }

    out.addEventListener('click', (e) => {
      const b = e.target.closest('[data-add]'); if (!b) return;
      const r = App.addEntity(b.dataset.add, b.dataset.v, { source: `Recon: ${rcState.q}` });
      // The selector being researched joins the case with its first finding, so the graph shows where each item came from.
      const anchor = App.addEntity(rcState.type, rcState.q, { source: 'Recon' }).entity;
      const rel = { ipv4: 'resolves to', ipv6: 'resolves to', asn: 'announced by', cve: 'affected by', btc: 'transacted with', person: 'name used by', email: rcState.type === 'username' ? 'commits as' : 'contact' }[b.dataset.add] || (rcState.type === 'username' || rcState.type === 'email' ? 'same owner?' : 'related');
      if (r.entity && anchor && anchor.id !== r.entity.id) App.addLink(anchor.id, r.entity.id, rel);
      App.touch(r.created ? `Recon: added ${b.dataset.v}` : null);
      b.textContent = '✓'; b.disabled = true;
    });
    out.addEventListener('click', (e) => {
      const ev = e.target.closest('[data-ev]');
      if (ev) { addEventQuick({ when: ev.dataset.ev, title: ev.dataset.evt, source: ev.dataset.evs, category: /account/i.test(ev.dataset.evt) ? 'Account created' : 'Other', entityValue: [rcState.type, rcState.q] }); return; }
      const rc = e.target.closest('[data-rc]');
      if (rc) { e.preventDefault(); App.go('recon', { q: rc.dataset.rc }); return; }
      const pv = e.target.closest('[data-pv]');
      if (pv) App.go('pivot', { q: pv.dataset.pv });
    });
    $('#rcf', el).onsubmit = async (e) => {
      e.preventDefault();
      let q = refang($('#rcq', el).value.trim());
      if (!q) return;
      let type = $('#rct', el).value || detectType(q);
      if (type === 'url') { q = hostOf(q) || q; type = isIPv4(q) ? 'ipv4' : 'domain'; }
      if (type === 'keyword' || type === 'person') type = '';
      if (!RECON_TYPES.includes(type)) return toast('Recon handles domains, IPs, ASNs, usernames, emails, Bitcoin addresses and CVEs', 'error');
      q = cleanValue(type, type === 'domain' ? q.replace(/[/?#].*$/, '') : q);
      if ((type === 'domain' && !isDomain(q)) || (type === 'btc' && !btcValid(q)) || (type === 'email' && !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(q)) || (type === 'cve' && !/^CVE-\d{4}-\d{4,7}$/.test(q)) || (type === 'asn' && !/^AS\d+$/.test(q)) || (type === 'username' && !/^[\w.-]{1,253}$/.test(q))) return toast(`That does not look like a valid ${typeLabel(type).toLowerCase()}`, 'error');
      rcState.q = q; rcState.type = type; out.innerHTML = '';
      $('#rcq', el).value = q;
      if (App.settings.logPivots) App.touch(`Recon run (${typeLabel(type)}): ${q}`);
      await ({ domain: runDomain, ipv4: runIP, ipv6: runIP, asn: runASN, username: runUsername, email: runEmail, btc: runBTC, cve: runCVE })[type](q);
    };
    if (params.q && on) $('#rcf', el).requestSubmit();
  },
});
