'use strict';
/* Lantern — Recon: live, opt-in lookups against public APIs (never the target's own servers).
   DNS via DNS-over-HTTPS (Cloudflare, Google fallback), RDAP via rdap.org, certificate transparency via crt.sh,
   IP context via ipinfo.io, archive history via the Wayback CDX API. */

const RR = { A: 1, NS: 2, CNAME: 5, SOA: 6, PTR: 12, MX: 15, TXT: 16, AAAA: 28, CAA: 257 };
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
function vcardName(ent) { const fn = ent?.vcardArray?.[1]?.find((x) => x[0] === 'fn'); return fn ? fn[3] : ''; }
function rdapEvents(j) { const o = {}; (j.events || []).forEach((e) => (o[e.eventAction] = e.eventDate)); return o; }

const rcState = { q: '', results: {} };

App.register({
  id: 'recon', label: 'Recon', icon: 'recon',
  render(el, params) {
    if (params.q) { rcState.q = params.q; rcState.results = {}; }
    const on = App.settings.activeLookups;
    el.innerHTML = `
      ${viewHead('Recon', 'Live lookups for a domain or IP: DNS records, mail security (SPF/DMARC), RDAP registration, certificate-transparency subdomains, IP ownership and web-archive history.')}
      ${on ? `<div class="banner warn"><span>⚠</span><div class="grow">Active lookups are <b>on</b>. Queries go from your IP to Cloudflare/Google DNS, rdap.org, certspotter / crt.sh, ipinfo.io and archive.org — never directly to the target. Use a VPN or research VM if attribution matters.</div><button class="btn sm" id="rcoff">Turn off</button></div>`
        : `<div class="banner info"><span>ℹ</span><div class="grow">Passive mode: Lantern makes <b>no network requests</b>. Recon needs active lookups, which send your queries to public APIs (Cloudflare/Google DNS-over-HTTPS, rdap.org, certspotter / crt.sh, ipinfo.io, archive.org). The target itself is never contacted.</div><button class="btn sm primary" id="rcon">Enable active lookups</button></div>`}
      <form class="card row mt" id="rcf" autocomplete="off">
        <input id="rcq" class="grow mono" placeholder="example.com or 203.0.113.10" value="${esc(rcState.q)}" spellcheck="false" ${on ? '' : 'disabled'}>
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
    }

    out.addEventListener('click', (e) => {
      const b = e.target.closest('[data-add]'); if (!b) return;
      const r = App.addEntity(b.dataset.add, b.dataset.v, { source: `Recon: ${rcState.q}` });
      const anchor = App.findEntity(isIPv4(rcState.q) ? 'ipv4' : isIPv6(rcState.q) ? 'ipv6' : 'domain', rcState.q);
      if (r.entity && anchor && anchor.id !== r.entity.id) App.addLink(anchor.id, r.entity.id, b.dataset.add.startsWith('ip') ? 'resolves to' : 'related');
      App.touch(r.created ? `Recon: added ${b.dataset.v}` : null);
      b.textContent = '✓'; b.disabled = true;
    });
    $('#rcf', el).onsubmit = async (e) => {
      e.preventDefault();
      const q = refang($('#rcq', el).value.trim()).replace(/^https?:\/\//i, '').replace(/[/?#].*$/, '').toLowerCase();
      if (!q) return;
      rcState.q = q; out.innerHTML = '';
      if (App.settings.logPivots) App.touch(`Recon run: ${q}`);
      if (isIPv4(q) || isIPv6(q)) await runIP(q);
      else if (isDomain(q)) await runDomain(q);
      else toast('Enter a domain or an IP address', 'error');
    };
    if (params.q && on) $('#rcf', el).requestSubmit();
  },
});
