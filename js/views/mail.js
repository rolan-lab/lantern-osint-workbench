'use strict';
/* Lantern — email header analyzer. Everything runs locally: the Received chain, hop delays, originating IP,
   SPF/DKIM/DMARC verdicts and From / Return-Path / Reply-To alignment are parsed from pasted headers or a dropped .eml. */

function isPublicIPv4(ip) {
  if (!isIPv4(ip)) return false;
  const [a, b] = ip.split('.').map(Number);
  return !(a === 0 || a === 10 || a === 127 || a >= 224 || (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168));
}
const isPublicIP = (ip) => (isIPv4(ip) ? isPublicIPv4(ip) : isIPv6(ip) && !/^(::1$|fe80:|f[cd]|::ffff:)/i.test(ip));

/** RFC 2047 encoded-words (=?utf-8?B?…?= / =?iso-8859-1?Q?…?=) → text. */
function decodeMimeWords(s) {
  return String(s).replace(/(=\?[^?\s]+\?[bq]\?[^?\s]*\?=)\s+(?==\?)/gi, '$1').replace(/=\?([^?\s]+)\?([bq])\?([^?\s]*)\?=/gi, (m, cs, enc, txt) => {
    try {
      const bytes = enc.toLowerCase() === 'b' ? b64decodeBytes(txt) : Uint8Array.from(txt.replace(/_/g, ' ').replace(/=([0-9a-f]{2})/gi, (x, h) => String.fromCharCode(parseInt(h, 16))), (c) => c.charCodeAt(0) & 255);
      return new TextDecoder(cs.toLowerCase().replace(/\*.*$/, '')).decode(bytes);
    } catch { return m; }
  });
}
const MAIL_RX = /[a-z0-9._%+=-]+@(?:[a-z0-9-]+\.)+[a-z]{2,24}/i;
/** The address a header really carries: the one in <angle brackets> wins over anything typed into the display name. */
const mailAddr = (v) => { const s = String(v || ''), angle = [...s.matchAll(/<([^<>]*)>/g)].map((m) => m[1]).filter((x) => MAIL_RX.test(x)).pop(); return ((angle || s).match(MAIL_RX) || [''])[0].toLowerCase(); };
const mailDomain = (v) => mailAddr(v).split('@')[1] || '';

function parseReceived(v) {
  const semi = v.lastIndexOf(';');
  const dateStr = semi >= 0 ? v.slice(semi + 1).trim() : '';
  const body = semi >= 0 ? v.slice(0, semi) : v;
  const t = Date.parse(dateStr.replace(/\s*\([^)]*\)\s*$/, ''));
  const fromPart = (body.match(/\bfrom\s+([\s\S]*?)(?=\s+by\s|$)/i) || [])[1] || '';
  const ips = [...new Set([...fromPart.matchAll(/\[(?:IPv6:)?([0-9a-f:.]{3,45})\]|\(([0-9]{1,3}(?:\.[0-9]{1,3}){3})\)|(?<![\w.])((?:\d{1,3}\.){3}\d{1,3})(?![\w.])/gi)].map((m) => (m[1] || m[2] || m[3]).toLowerCase()).filter((x) => isIPv4(x) || isIPv6(x)))];
  return {
    from: (fromPart.match(/^(\S+)/) || [])[1] || '',
    helo: (fromPart.match(/\((?:HELO|EHLO)\s+([^\s)]+)/i) || fromPart.match(/\(([a-z0-9.-]+\.[a-z]{2,})[\s.[)]/i) || [])[1] || '',
    ips,
    by: (body.match(/\bby\s+(\S+)/i) || [])[1] || '',
    with: (body.match(/\bwith\s+(\S+)/i) || [])[1] || '',
    id: (body.match(/\bid\s+(\S+)/i) || [])[1] || '',
    for: mailAddr((body.match(/\bfor\s+(\S+)/i) || [])[1] || ''),
    tls: /\b(TLS|ESMTPS|ESMTPSA|version=TLS|using TLS|cipher)/i.test(body),
    time: Number.isFinite(t) ? t : null, dateStr,
  };
}

/** Parse raw headers (or a whole .eml — the body is ignored). */
function parseEmailHeaders(raw) {
  const text = String(raw || '').replace(/\r\n?/g, '\n').replace(/^\s*\n/, '');
  const end = text.search(/\n\s*\n/);
  const unfolded = (end >= 0 ? text.slice(0, end) : text).replace(/\n[ \t]+/g, ' ');
  const headers = [];
  for (const line of unfolded.split('\n')) { const m = line.match(/^([!-9;-~]+)\s*:\s?(.*)$/); if (m) headers.push({ name: m[1], value: m[2].trim() }); }
  const all = (n) => headers.filter((h) => h.name.toLowerCase() === n.toLowerCase()).map((h) => h.value);
  const get = (n) => all(n)[0] || '';
  const res = { headers, hops: [], flags: [], auth: {}, selectors: { ips: [], domains: [], emails: [] } };
  const flag = (level, text2) => res.flags.push({ level, text: text2 });
  if (!headers.length) return res;

  res.subject = decodeMimeWords(get('Subject'));
  res.fromRaw = decodeMimeWords(get('From'));
  res.from = mailAddr(get('From')); res.to = decodeMimeWords(get('To'));
  res.replyTo = mailAddr(get('Reply-To')); res.returnPath = mailAddr(get('Return-Path')); res.sender = mailAddr(get('Sender'));
  res.messageId = get('Message-ID').replace(/^<|>$/g, '');
  res.mailer = get('X-Mailer') || get('User-Agent') || '';
  res.dateStr = get('Date');
  const dt = Date.parse(res.dateStr.replace(/\s*\([^)]*\)\s*$/, ''));
  res.date = Number.isFinite(dt) ? dt : null;
  res.dateOffset = (res.dateStr.match(/([+-]\d{4})\s*(?:\([^)]*\))?\s*$/) || [])[1] || '';

  // Received headers are prepended by each server, so the list is newest-first: reverse into travel order.
  res.hops = all('Received').map(parseReceived).reverse();
  res.hops.forEach((h, i) => { const prev = res.hops.slice(0, i).reverse().find((x) => x.time !== null); h.delay = h.time !== null && prev ? (h.time - prev.time) / 1000 : null; });

  // Originating IP: client-supplied hint headers first, then the earliest hop that names a public address.
  const hint = ['X-Originating-IP', 'X-Sender-IP', 'X-Source-IP', 'X-Real-IP', 'X-Client-IP', 'X-Remote-IP'].map((n) => [n, (get(n).match(/[0-9a-f:.]{3,45}/i) || [''])[0].toLowerCase()]).find(([, ip]) => isPublicIP(ip));
  const hopIp = res.hops.flatMap((h) => h.ips).find(isPublicIP);
  res.originIp = hint ? hint[1] : hopIp || '';
  res.originVia = hint ? hint[0] : hopIp ? 'first Received hop' : '';

  // Authentication verdicts as recorded by the receiving server (topmost header wins).
  const ar = [...all('Authentication-Results'), ...all('ARC-Authentication-Results')].join(' ; ');
  const verdict = (k) => (ar.match(new RegExp(`\\b${k}=(\\w+)`, 'i')) || [])[1]?.toLowerCase() || '';
  res.auth = { spf: verdict('spf') || (get('Received-SPF').match(/^(\w+)/) || [])[1]?.toLowerCase() || '', dkim: verdict('dkim'), dmarc: verdict('dmarc'), raw: ar,
    dkimDomain: (ar.match(/header\.d=([^\s;]+)/i) || get('DKIM-Signature').match(/\bd=([^;\s]+)/i) || [])[1] || '',
    dkimSelector: (ar.match(/header\.s=([^\s;]+)/i) || get('DKIM-Signature').match(/\bs=([^;\s]+)/i) || [])[1] || '',
    spfDomain: (ar.match(/smtp\.mailfrom=([^\s;]+)/i) || [])[1] || '' };

  // ---- findings
  const reg = (d) => (d ? registrable(d) : '');
  const fromDom = mailDomain(res.from);
  for (const k of ['spf', 'dkim', 'dmarc']) { const v = res.auth[k]; if (v && !/^(pass|bestguesspass)$/.test(v) && v !== 'none') flag(k === 'dmarc' || v === 'fail' ? 'crit' : 'warn', `${k.toUpperCase()} result is “${v}” — the message did not authenticate as ${fromDom || 'the claimed sender'}.`); }
  if (!res.auth.spf && !res.auth.dkim && !res.auth.dmarc) flag('info', 'No authentication results recorded — headers may be from the sender’s own copy, or the receiver did not check.');
  if (res.replyTo && fromDom && reg(mailDomain(res.replyTo)) !== reg(fromDom)) flag('crit', `Reply-To (${res.replyTo}) goes to a different domain than From (${res.from}) — replies are diverted, a common fraud pattern.`);
  if (res.returnPath && fromDom && reg(mailDomain(res.returnPath)) !== reg(fromDom)) flag('warn', `Return-Path domain (${mailDomain(res.returnPath)}) differs from From (${fromDom}) — normal for mailing services, suspicious for personal mail.`);
  const shown = (res.fromRaw.match(/^\s*"?([^"<]*)"?\s*</) || [])[1] || '';
  const shownAddr = (shown.match(MAIL_RX) || [''])[0].toLowerCase();
  if (shownAddr && shownAddr !== res.from) flag('crit', `Display name shows “${shownAddr}” but the real sender is ${res.from} — display-name spoofing.`);
  if (res.auth.dkimDomain && fromDom && reg(res.auth.dkimDomain.toLowerCase()) !== reg(fromDom)) flag('info', `DKIM signed by ${res.auth.dkimDomain}, not by the From domain — the signature vouches for the sending service only.`);
  const midDom = (res.messageId.split('@')[1] || '').toLowerCase();
  if (midDom && fromDom && isDomain(midDom) && reg(midDom) !== reg(fromDom)) flag('info', `Message-ID was generated at ${midDom} — the system that actually composed the message.`);
  const firstHop = res.hops.find((h) => h.time !== null);
  if (res.date !== null && firstHop && Math.abs(firstHop.time - res.date) > 3600000) flag('warn', `Date header and first server timestamp differ by ${fmtDuration(Math.abs(firstHop.time - res.date) / 1000)} — wrong sender clock, delayed send or a forged Date.`);
  for (const h of res.hops) { if (h.delay !== null && h.delay < -120) flag('warn', `Time runs backwards by ${fmtDuration(-h.delay)} at ${h.by || 'a hop'} — clock skew or an inserted (forged) Received line.`); else if (h.delay !== null && h.delay > 1800) flag('info', `${fmtDuration(h.delay)} delay before ${h.by || 'a hop'} — queueing, greylisting or scheduled sending.`); }
  if (res.hops.length && !res.originIp) flag('info', 'No public originating IP — webmail providers (Gmail, Outlook.com, Proton) deliberately hide the sender’s address.');
  if (/phpmailer|swiftmailer|python|curl|perl|nodemailer|powershell/i.test(res.mailer)) flag('warn', `Sent by a script or library (${res.mailer}) rather than a mail client.`);
  if (get('X-PHP-Originating-Script') || get('X-PHP-Script')) flag('warn', `Sent from a PHP script: ${get('X-PHP-Originating-Script') || get('X-PHP-Script')} — often a compromised website.`);

  // ---- selectors
  const ips = new Set(res.hops.flatMap((h) => h.ips).filter(isPublicIP)); if (res.originIp) ips.add(res.originIp);
  const doms = new Set();
  for (const d of [fromDom, mailDomain(res.replyTo), mailDomain(res.returnPath), res.auth.dkimDomain.toLowerCase(), midDom, ...res.hops.flatMap((h) => [h.from, h.by, h.helo])]) { const x = String(d || '').toLowerCase().replace(/^\[|\]$/g, ''); if (x && isDomain(x)) doms.add(x); }
  res.selectors = { ips: [...ips], domains: [...doms], emails: [...new Set([res.from, res.replyTo, res.returnPath, res.sender].filter(Boolean))] };
  return res;
}
function fmtDuration(sec) {
  sec = Math.round(Math.abs(sec));
  if (sec < 60) return `${sec}s`;
  if (sec < 3600) return `${Math.floor(sec / 60)}m ${sec % 60}s`;
  if (sec < 86400) return `${Math.floor(sec / 3600)}h ${Math.floor((sec % 3600) / 60)}m`;
  return `${Math.floor(sec / 86400)}d ${Math.floor((sec % 86400) / 3600)}h`;
}

const mhState = { text: '' };
App.register({
  id: 'mail', label: 'Email headers', icon: 'mail',
  render(el, params) {
    if (params.text !== undefined) mhState.text = params.text;
    el.innerHTML = `
      ${viewHead('Email header analyzer', 'Trace where a message really came from. Paste the full headers (“Show original” in Gmail, “View message source” in Outlook) or drop an .eml file. Parsed locally — nothing is uploaded.')}
      <div class="card">
        <textarea id="mht" rows="9" class="mono" spellcheck="false" placeholder="Received: from mail.example.org (mail.example.org [203.0.113.5]) by mx.google.com with ESMTPS id …&#10;Authentication-Results: mx.google.com; spf=pass …; dkim=pass …; dmarc=pass …&#10;From: …">${esc(mhState.text)}</textarea>
        <div class="row mt"><button class="btn primary" id="mhgo">Analyze</button><button class="btn" id="mhfile">Load .eml…</button><button class="btn ghost" id="mhclear">Clear</button><span class="spacer"></span><span class="muted small">Message bodies are ignored; only headers are read.</span></div>
      </div>
      <div id="mhout" class="mt"></div>`;
    const ta = $('#mht', el), out = $('#mhout', el);
    const lvl = { crit: 'crit', warn: 'warn', info: 'good' }, lab = { crit: 'Critical', warn: 'Notable', info: 'Info' };
    const vBadge = (v) => (v ? `<span class="status ${/^pass/.test(v) ? 'good' : v === 'none' || v === 'neutral' ? 'warn' : 'crit'}">${esc(v)}</span>` : '<span class="muted">not recorded</span>');
    const addBtn = (type, value) => `<button class="btn sm ghost" data-add="${esc(type)}" data-v="${esc(value)}" title="Add to case">+</button>`;
    let R = null;
    const draw = () => {
      mhState.text = ta.value;
      if (!ta.value.trim()) { out.innerHTML = ''; return; }
      R = parseEmailHeaders(ta.value);
      if (!R.headers.length) { out.innerHTML = '<div class="empty"><b>No headers recognised</b>Paste the raw message source — lines such as “Received:” and “From:”.</div>'; return; }
      const order = { crit: 0, warn: 1, info: 2 };
      out.innerHTML = `
        <div class="grid g2">
          <div class="card"><h3>Message</h3>
            <dl class="kv">
              ${[['Subject', R.subject], ['From', R.fromRaw], ['To', R.to], ['Reply-To', R.replyTo], ['Return-Path', R.returnPath], ['Sender', R.sender], ['Date', R.dateStr + (R.date !== null ? ` → ${fmtUTC(new Date(R.date).toISOString())}` : '')], ['Sender UTC offset', R.dateOffset ? `${R.dateOffset} — the time zone the sending device was set to` : ''], ['Message-ID', R.messageId], ['Mail client', R.mailer]].filter(([, v]) => v).map(([k, v]) => `<dt>${k}</dt><dd class="break">${esc(v)}</dd>`).join('')}
            </dl>
            <div class="row mt">${R.date !== null ? '<button class="btn sm" id="mhtl">Add “sent” to timeline</button>' : ''}<button class="btn sm ghost" id="mhext">Send all headers to Extractor</button></div>
          </div>
          <div class="card"><h3>Origin &amp; authentication</h3>
            <dl class="kv">
              <dt>Originating IP</dt><dd>${R.originIp ? `<span class="mono">${esc(R.originIp)}</span> ${addBtn(isIPv4(R.originIp) ? 'ipv4' : 'ipv6', R.originIp)} <a href="#" data-rc="${esc(R.originIp)}" class="small">recon</a> <a href="#" data-pv="${esc(R.originIp)}" class="small">pivot</a><div class="muted small">from ${esc(R.originVia)}</div>` : '<span class="muted">hidden by the sending provider</span>'}</dd>
              <dt>SPF</dt><dd>${vBadge(R.auth.spf)} ${R.auth.spfDomain ? `<span class="mono small">${esc(R.auth.spfDomain)}</span>` : ''}</dd>
              <dt>DKIM</dt><dd>${vBadge(R.auth.dkim)} ${R.auth.dkimDomain ? `<span class="mono small">d=${esc(R.auth.dkimDomain)}${R.auth.dkimSelector ? ` s=${esc(R.auth.dkimSelector)}` : ''}</span>` : ''}</dd>
              <dt>DMARC</dt><dd>${vBadge(R.auth.dmarc)}</dd>
            </dl>
            <h4 style="margin:14px 0 6px">Findings</h4>
            ${R.flags.length ? [...R.flags].sort((a, b) => order[a.level] - order[b.level]).map((f) => `<div class="small" style="display:flex;gap:8px;align-items:flex-start;padding:3px 0"><span class="status ${lvl[f.level]}" style="flex:none;min-width:62px">${lab[f.level]}</span><span style="min-width:0">${esc(f.text)}</span></div>`).join('') : '<p class="muted small">Nothing unusual in the headers.</p>'}
          </div>
        </div>
        <div class="card mt"><h3>Delivery path<span class="spacer"></span><span class="muted small">${plural(R.hops.length, 'hop')} · oldest first</span></h3>
          ${R.hops.length ? `<div class="tbl-wrap"><table class="tbl"><thead><tr><th>#</th><th>From</th><th>By</th><th>Protocol</th><th>Time (UTC)</th><th class="num">Delay</th></tr></thead><tbody>${R.hops.map((h, i) => `<tr>
            <td>${i + 1}</td>
            <td class="mono small break">${esc(h.from || '—')}${h.helo && h.helo !== h.from ? `<div class="muted">helo ${esc(h.helo)}</div>` : ''}${h.ips.map((ip) => `<div>${esc(ip)} ${isPublicIP(ip) ? addBtn(isIPv4(ip) ? 'ipv4' : 'ipv6', ip) : '<span class="muted">private</span>'}</div>`).join('')}</td>
            <td class="mono small break">${esc(h.by || '—')}</td>
            <td class="small">${esc(h.with || '')}${h.tls ? ' <span class="status good">TLS</span>' : ''}</td>
            <td class="mono small nowrap">${h.time !== null ? esc(fmtUTC(new Date(h.time).toISOString())) : esc(h.dateStr || '—')}</td>
            <td class="num small nowrap">${h.delay === null ? '' : h.delay < 0 ? `<span class="status warn">−${esc(fmtDuration(h.delay))}</span>` : esc(fmtDuration(h.delay))}</td></tr>`).join('')}</tbody></table></div>
            <p class="muted small">Only the hops added by servers you trust (the recipient’s own) are reliable. Everything below the first trusted server can be forged by the sender.</p>` : '<p class="muted small">No Received headers found.</p>'}
        </div>
        <div class="grid g2 mt">
          <div class="card"><h3>Selectors<span class="spacer"></span><button class="btn sm" id="mhall">Add all to case</button></h3>
            ${[['ipv4', 'IP addresses', R.selectors.ips], ['domain', 'Domains & mail servers', R.selectors.domains], ['email', 'Addresses', R.selectors.emails]].filter(([, , l]) => l.length).map(([t, title, list]) => `<div class="small muted" style="margin:8px 0 4px">${title}</div>${list.map((v) => `<div class="row nowrap small"><span class="mono break" style="flex:1">${esc(v)}</span>${addBtn(t === 'ipv4' && !isIPv4(v) ? 'ipv6' : t, v)}<a href="#" data-pv="${esc(v)}">pivot</a></div>`).join('')}`).join('') || '<p class="muted small">None.</p>'}
          </div>
          <div class="card"><h3>All headers<span class="spacer"></span><span class="muted small">${R.headers.length}</span></h3>
            <div style="max-height:380px;overflow:auto"><table class="tbl"><tbody>${R.headers.map((h) => `<tr><td class="small nowrap" style="vertical-align:top"><b>${esc(h.name)}</b></td><td class="mono small break">${esc(trunc(decodeMimeWords(h.value), 600))}</td></tr>`).join('')}</tbody></table></div>
          </div>
        </div>`;
    };
    const add = (type, v) => App.addEntity(type, v, { source: `Email headers${R.subject ? `: ${trunc(R.subject, 60)}` : ''}` });
    out.addEventListener('click', (e) => {
      const a = e.target.closest('[data-add],[data-rc],[data-pv],button'); if (!a) return;
      if (a.dataset.add) { const r = add(a.dataset.add, a.dataset.v); App.touch(r.created ? `Email headers: added ${a.dataset.v}` : null); a.textContent = '✓'; a.disabled = true; }
      else if (a.dataset.rc) { e.preventDefault(); App.go('recon', { q: a.dataset.rc }); }
      else if (a.dataset.pv) { e.preventDefault(); App.go('pivot', { q: a.dataset.pv }); }
      else if (a.id === 'mhext') App.go('extractor', { text: R.headers.map((h) => `${h.name}: ${h.value}`).join('\n') });
      else if (a.id === 'mhtl') addEventQuick({ when: new Date(R.date).toISOString(), title: `Email sent: ${trunc(R.subject || '(no subject)', 80)}`, category: 'Communication', details: `From ${R.from || '?'}${R.originIp ? ` · origin ${R.originIp}` : ''}`, source: R.messageId ? `Message-ID ${R.messageId}` : 'Email headers', entityValue: R.from ? ['email', R.from] : null });
      else if (a.id === 'mhall') {
        let n = 0; const made = [];
        for (const ip of R.selectors.ips) { const r = add(isIPv4(ip) ? 'ipv4' : 'ipv6', ip); if (r.created) n++; made.push(r.entity); }
        for (const d of R.selectors.domains) { const r = add('domain', d); if (r.created) n++; }
        for (const m of R.selectors.emails) { const r = add('email', m); if (r.created) n++; made.push(r.entity); }
        const from = R.from && App.findEntity('email', R.from), origin = R.originIp && App.findEntity(isIPv4(R.originIp) ? 'ipv4' : 'ipv6', R.originIp);
        if (from && origin) App.addLink(from.id, origin.id, 'sent from');
        App.touch(`Email headers: added ${n} entities`); toast(`${plural(n, 'entity', 'entities')} added`); draw();
      }
    });
    const load = async (files) => { const f = files[0]; if (!f) return; if (f.size > 25e6) return toast('File is too large (25 MB max)', 'error'); ta.value = (await readFileAs(f, 'text')).slice(0, 400000); draw(); };
    ta.addEventListener('dragover', (e) => e.preventDefault());
    ta.addEventListener('drop', (e) => { e.preventDefault(); if (e.dataTransfer.files.length) load([...e.dataTransfer.files]); });
    $('#mhfile', el).onclick = () => { const i = document.createElement('input'); i.type = 'file'; i.accept = '.eml,.txt,.msg,message/rfc822,text/plain'; i.onchange = () => load([...i.files]); i.click(); };
    $('#mhgo', el).onclick = draw;
    $('#mhclear', el).onclick = () => { ta.value = ''; mhState.text = ''; out.innerHTML = ''; ta.focus(); };
    ta.addEventListener('paste', () => setTimeout(draw, 0));
    draw();
  },
});
