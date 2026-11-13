'use strict';
/* Lantern — analyst toolbox: encoders, time & ID decoders, IP/CIDR, domain lookalikes, hashing, JWT. */

// ---------------------------------------------------------------- IP helpers (also used by Pivot)
const ipToInt = (ip) => ip.split('.').reduce((a, o) => a * 256 + +o, 0);
const intToIp = (n) => [24, 16, 8, 0].map((s) => Math.floor(n / 2 ** s) % 256).join('.');
const V4_RANGES = [['0.0.0.0/8', '“This” network'], ['10.0.0.0/8', 'Private (RFC 1918)'], ['100.64.0.0/10', 'Carrier-grade NAT (RFC 6598)'], ['127.0.0.0/8', 'Loopback'], ['169.254.0.0/16', 'Link-local'], ['172.16.0.0/12', 'Private (RFC 1918)'], ['192.0.0.0/24', 'IETF protocol assignments'], ['192.0.2.0/24', 'Documentation (TEST-NET-1)'], ['192.88.99.0/24', '6to4 relay (deprecated)'], ['192.168.0.0/16', 'Private (RFC 1918)'], ['198.18.0.0/15', 'Benchmarking (RFC 2544)'], ['198.51.100.0/24', 'Documentation (TEST-NET-2)'], ['203.0.113.0/24', 'Documentation (TEST-NET-3)'], ['224.0.0.0/4', 'Multicast'], ['240.0.0.0/4', 'Reserved'], ['255.255.255.255/32', 'Limited broadcast']];
function cidrInfo(s) {
  const m = String(s).trim().match(/^(\d+\.\d+\.\d+\.\d+)\/(\d{1,2})$/);
  if (!m || !isIPv4(m[1]) || +m[2] > 32) return null;
  const bits = +m[2], size = 2 ** (32 - bits), net = Math.floor(ipToInt(m[1]) / size) * size, bc = net + size - 1;
  return { bits, size, net, bc, network: intToIp(net), broadcast: intToIp(bc), mask: intToIp(2 ** 32 - size), wildcard: intToIp(size - 1), first: intToIp(bits >= 31 ? net : net + 1), last: intToIp(bits >= 31 ? bc : bc - 1), usable: bits >= 31 ? size : size - 2 };
}
const inCidr = (n, cidr) => { const c = cidrInfo(cidr); return c && n >= c.net && n <= c.bc; };
function ipv4Info(ip) {
  const n = ipToInt(ip), r = V4_RANGES.find(([c]) => inCidr(n, c));
  return { cls: r ? r[1] : 'Public (globally routable)', public: !r, ptr: ip.split('.').reverse().join('.') + '.in-addr.arpa', int: n, hex: '0x' + n.toString(16).padStart(8, '0') };
}
function ipv6Class(ip) {
  const s = ip.toLowerCase();
  if (s === '::1') return 'Loopback';
  if (s === '::') return 'Unspecified';
  if (/^fe[89ab]/.test(s)) return 'Link-local';
  if (/^f[cd]/.test(s)) return 'Unique local (private)';
  if (/^ff/.test(s)) return 'Multicast';
  if (/^2001:0?db8:/.test(s)) return 'Documentation';
  if (/^::ffff:/.test(s)) return 'IPv4-mapped';
  if (/^2002:/.test(s)) return '6to4';
  if (/^2001:0{0,3}:/.test(s)) return 'Teredo';
  if (/^[23]/.test(s)) return 'Global unicast (public)';
  return 'Reserved / other';
}

// ---------------------------------------------------------------- domain helpers (also used by Pivot)
const MULTI_SUFFIX = new Set('co.uk org.uk ac.uk gov.uk me.uk ltd.uk plc.uk net.uk com.au net.au org.au edu.au gov.au co.nz org.nz govt.nz co.jp ne.jp or.jp ac.jp go.jp co.za org.za gov.za com.br net.br org.br gov.br com.cn net.cn org.cn gov.cn com.mx org.mx gob.mx co.in net.in org.in gov.in ac.in co.kr or.kr go.kr com.tr org.tr gov.tr com.sg org.sg gov.sg com.hk org.hk gov.hk co.il org.il gov.il ac.il com.ar gob.ar com.tw org.tw gov.tw com.my gov.my com.ph gov.ph com.pk com.ng com.eg com.sa gov.sa com.ua gov.ua co.id go.id com.vn com.co gov.co co.th go.th com.pe gob.pe com.ru org.ru github.io gitlab.io herokuapp.com pages.dev vercel.app netlify.app web.app firebaseapp.com azurewebsites.net cloudfront.net blogspot.com wordpress.com s3.amazonaws.com'.split(' '));
function registrable(d) {
  const p = String(d).toLowerCase().split('.').filter(Boolean);
  if (p.length <= 2) return p.join('.');
  return MULTI_SUFFIX.has(p.slice(-2).join('.')) ? p.slice(-3).join('.') : p.slice(-2).join('.');
}
const SCRIPTS = [['Latin', /[A-Za-zÀ-ɏ]/], ['Cyrillic', /[Ѐ-ӿ]/], ['Greek', /[Ͱ-Ͽ]/], ['Armenian', /[԰-֏]/], ['Hebrew', /[֐-׿]/], ['Arabic', /[؀-ۿ]/], ['Cherokee', /[Ꭰ-᏿]/], ['Thai', /[฀-๿]/], ['CJK', /[぀-ヿ一-鿿가-힯]/]];
function scriptMix(s) {
  const all = new Set(); let mixed = false;
  for (const label of String(s).split('.')) { const ls = SCRIPTS.filter(([, rx]) => rx.test(label)).map(([n]) => n); ls.forEach((x) => all.add(x)); if (ls.length > 1) mixed = true; }
  return { mixed, scripts: [...all] };
}
const CONFUSABLE = { 'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x', 'і': 'i', 'ј': 'j', 'ѕ': 's', 'ԁ': 'd', 'һ': 'h', 'ӏ': 'l', 'ԛ': 'q', 'ԝ': 'w', 'ɡ': 'g', 'ο': 'o', 'ν': 'v', 'α': 'a', 'ρ': 'p', 'τ': 't', 'ι': 'i', 'κ': 'k', 'ı': 'i', 'ł': 'l', 'ß': 'ss', 'ɑ': 'a', 'ⅼ': 'l', 'ｏ': 'o' };
const skeleton = (s) => [...String(s).normalize('NFKD').replace(/[̀-ͯ]/g, '')].map((ch) => CONFUSABLE[ch] || ch).join('').toLowerCase();
/** Non-ASCII domain whose look-alike skeleton is plain ASCII, e.g. Cyrillic “аррӏе.com” → “apple.com”. */
const wholeScriptSpoof = (uni) => /[^\x00-\x7f]/.test(uni) && /^[\x00-\x7f]+$/.test(skeleton(uni)) && skeleton(uni) !== uni.toLowerCase();

const KB = { q: 'wa', w: 'qeas', e: 'wrsd', r: 'etdf', t: 'ryfg', y: 'tugh', u: 'yihj', i: 'uojk', o: 'ipkl', p: 'ol', a: 'qwsz', s: 'awedxz', d: 'serfcx', f: 'drtgvc', g: 'ftyhbv', h: 'gyujnb', j: 'huikmn', k: 'jiolm', l: 'kop', z: 'asx', x: 'zsdc', c: 'xdfv', v: 'cfgb', b: 'vghn', n: 'bhjm', m: 'njk', 1: '2q', 2: '13w', 3: '24e', 4: '35r', 5: '46t', 6: '57y', 7: '68u', 8: '79i', 9: '80o', 0: '9p' };
const GLYPH_SWAPS = [['o', '0'], ['0', 'o'], ['l', '1'], ['1', 'l'], ['i', '1'], ['i', 'l'], ['l', 'i'], ['e', '3'], ['a', '4'], ['s', '5'], ['m', 'rn'], ['rn', 'm'], ['w', 'vv'], ['vv', 'w'], ['d', 'cl'], ['g', 'q'], ['q', 'g'], ['u', 'v'], ['b', '6']];
const ALT_TLDS = ['com', 'net', 'org', 'co', 'io', 'info', 'biz', 'xyz', 'online', 'site', 'app', 'dev', 'shop', 'top', 'live', 'support', 'us', 'uk', 'eu', 'cc', 'me', 'ai'];
function lookalikes(domain) {
  const reg = registrable(domain.toLowerCase());
  const dot = reg.indexOf('.'); if (dot < 1) return [];
  const name = reg.slice(0, dot), tld = reg.slice(dot + 1);
  const out = new Map();
  const add = (n, kind, t = tld) => {
    if (!n || (n === name && t === tld) || !/^[a-z0-9-]+$/.test(n) || /^-|-$/.test(n) || n.length > 63) return;
    const d = `${n}.${t}`; if (!out.has(d)) out.set(d, kind);
  };
  for (let i = 0; i < name.length; i++) {
    add(name.slice(0, i) + name.slice(i + 1), 'Omission');
    add(name.slice(0, i) + name[i] + name.slice(i), 'Repetition');
    if (i < name.length - 1) add(name.slice(0, i) + name[i + 1] + name[i] + name.slice(i + 2), 'Transposition');
    for (const k of KB[name[i]] || '') add(name.slice(0, i) + k + name.slice(i + 1), 'Adjacent key');
    if (i > 0) add(name.slice(0, i) + '-' + name.slice(i), 'Hyphenation');
    if ('aeiou'.includes(name[i])) for (const v of 'aeiou') if (v !== name[i]) add(name.slice(0, i) + v + name.slice(i + 1), 'Vowel swap');
    for (let b = 0; b < 7; b++) { const ch = String.fromCharCode(name.charCodeAt(i) ^ (1 << b)); if (/[a-z0-9-]/.test(ch)) add(name.slice(0, i) + ch + name.slice(i + 1), 'Bit-flip'); }
  }
  for (const [a, b] of GLYPH_SWAPS) { let idx = name.indexOf(a); while (idx >= 0) { add(name.slice(0, idx) + b + name.slice(idx + a.length), 'Homoglyph'); idx = name.indexOf(a, idx + 1); } }
  for (const ch of 'abcdefghijklmnopqrstuvwxyz') add(name + ch, 'Addition');
  for (const t of ALT_TLDS) add(name, 'TLD swap', t);
  for (const w of ['login', 'secure', 'account', 'support', 'verify', 'help', 'online', 'portal', 'app', 'auth', 'pay', 'id']) { add(`${name}-${w}`, 'Keyword'); add(`${w}-${name}`, 'Keyword'); }
  if (tld.includes('.')) add(name + tld.split('.')[0], 'Dot omission', tld.split('.').pop());
  return [...out.entries()].map(([d, kind]) => ({ domain: d, kind }));
}

// ---------------------------------------------------------------- time interpretations
const PLAUSIBLE = (ms) => ms > Date.UTC(1995, 0, 1) && ms < Date.now() + 2 * 365 * 86400000;
function timeInterpretations(input) {
  const s = String(input).trim(), out = [];
  if (!s) return out;
  const push = (label, ms, note = '') => { if (Number.isFinite(ms) && Math.abs(ms) < 8.64e15) out.push({ label, ms, note, plausible: PLAUSIBLE(ms) }); };
  let big = null;
  if (/^-?\d+$/.test(s)) big = BigInt(s); else if (/^0x[0-9a-f]+$/i.test(s)) big = BigInt(s);
  if (big !== null) {
    const n = Number(big);
    push('Unix time (seconds)', n * 1000);
    push('Unix time (milliseconds)', n);
    push('Unix time (microseconds)', Number(big / 1000n));
    push('Unix time (nanoseconds)', Number(big / 1000000n));
    push('Windows FILETIME / LDAP (100 ns since 1601)', Number(big / 10000n) - 11644473600000, 'Active Directory, NTFS, registry');
    push('WebKit / Chrome (µs since 1601)', Number(big / 1000n) - 11644473600000, 'Chrome & Edge history, cookies');
    push('Apple Cocoa / Mac absolute (s since 2001)', (n + 978307200) * 1000, 'iOS & macOS databases');
    push('Apple Cocoa (ns since 2001)', Number(big / 1000000n) + 978307200000, 'newer iOS databases');
    push('HFS+ (s since 1904)', (n - 2082844800) * 1000, 'classic Mac OS, some EXIF makernotes');
    push('GPS time (s since 1980-01-06)', (n + 315964800) * 1000, 'ignores ~18 leap seconds');
    if (n > 0 && n < 120000) push('Excel serial date (days since 1899-12-30)', (n - 25569) * 86400000, 'spreadsheet date cells');
  } else if (/^-?\d+\.\d+$/.test(s)) {
    const n = parseFloat(s);
    push('Unix time (seconds, fractional)', n * 1000);
    if (n < 120000) push('Excel serial date + time', (n - 25569) * 86400000);
    push('Apple Cocoa (s since 2001)', (n + 978307200) * 1000);
  } else {
    const w = parseWhen(s);
    if (w) push('Parsed date/time', new Date(w.iso).getTime(), /Z|UTC|[+-]\d\d:?\d\d$/i.test(s) ? '' : 'no zone given — read as UTC');
  }
  return out;
}
const TZS = ['UTC', 'America/Los_Angeles', 'America/New_York', 'America/Sao_Paulo', 'Europe/London', 'Europe/Berlin', 'Europe/Moscow', 'Asia/Dubai', 'Asia/Kolkata', 'Asia/Shanghai', 'Asia/Tokyo', 'Australia/Sydney'];
const inTz = (ms, tz) => { try { return new Intl.DateTimeFormat('en-GB', { timeZone: tz, year: 'numeric', month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', weekday: 'short', hour12: false }).format(new Date(ms)); } catch { return ''; } };

// ---------------------------------------------------------------- ID → timestamp decoders
const SNOWFLAKES = [
  ['X / Twitter (post, user)', (id) => Number((id >> 22n) + 1288834974657n)],
  ['Discord (user, message, server)', (id) => Number((id >> 22n) + 1420070400000n)],
  ['Instagram (media / user pk)', (id) => Number((id >> 23n) + 1314220021721n)],
  ['LinkedIn (post / activity URN)', (id) => Number(id >> 22n)],
  ['Mastodon (status)', (id) => Number(id >> 16n)],
  ['TikTok (video / comment)', (id) => Number(id >> 32n) * 1000],
  ['Threads / Facebook-style (unix s in top 32 bits)', null],
];
const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const B32SORT = '234567abcdefghijklmnopqrstuvwxyz';
function decodeId(raw) {
  const s = String(raw).trim().replace(/^urn:li:(activity|share|ugcPost):/i, '');
  const out = [];
  const add = (label, ms, extra = '') => out.push({ label, ms, extra, plausible: PLAUSIBLE(ms) && ms < Date.now() + 86400000 });
  const uuid = s.match(/^([0-9a-f]{8})-?([0-9a-f]{4})-?([0-9a-f])([0-9a-f]{3})-?([0-9a-f]{4})-?([0-9a-f]{12})$/i);
  if (uuid) {
    const [, tl, tm, ver, th, , node] = uuid;
    if (ver === '1') {
      const ts = (BigInt('0x' + th) << 48n) | (BigInt('0x' + tm) << 32n) | BigInt('0x' + tl);
      const mac = node.match(/../g).join(':');
      add('UUID v1 timestamp', Number(ts / 10000n) - 12219292800000, (parseInt(node.slice(0, 2), 16) & 1) ? 'node is random (multicast bit set)' : `node = MAC address ${mac} of the generating machine`);
    } else if (ver === '6') {
      const ts = (BigInt('0x' + tl) << 28n) | (BigInt('0x' + tm) << 12n) | BigInt('0x' + th);
      add('UUID v6 timestamp', Number(ts / 10000n) - 12219292800000);
    } else if (ver === '7') add('UUID v7 timestamp', parseInt(tl + tm, 16));
    else out.push({ label: `UUID v${ver}`, ms: NaN, extra: 'This UUID version carries no timestamp (v4 is random).' });
    return out;
  }
  if (/^[0-9a-f]{24}$/i.test(s)) add('MongoDB ObjectId', parseInt(s.slice(0, 8), 16) * 1000, `machine/process ${s.slice(8, 18)}, counter ${parseInt(s.slice(18), 16)}`);
  if (/^[0-9A-HJKMNP-TV-Z]{26}$/i.test(s)) { let ms = 0; for (const ch of s.slice(0, 10).toUpperCase()) ms = ms * 32 + CROCKFORD.indexOf(ch); add('ULID', ms); }
  if (/^[234567a-z]{13}$/.test(s)) { let v = 0n; for (const ch of s) v = v * 32n + BigInt(B32SORT.indexOf(ch)); add('Bluesky / AT Protocol TID', Number((v >> 10n) / 1000n)); }
  if (/^\d{6,20}$/.test(s)) {
    const id = BigInt(s);
    for (const [label, fn] of SNOWFLAKES) if (fn) { try { add(label, fn(id)); } catch { /* ignore */ } }
    if (s.length <= 13) add('Plain Unix time', s.length <= 10 ? +s * 1000 : +s, s.length <= 10 ? 'seconds' : 'milliseconds');
  }
  return out.sort((a, b) => b.plausible - a.plausible);
}

// ---------------------------------------------------------------- codecs
const htmlDecode = (s) => { const t = document.createElement('textarea'); t.innerHTML = s; return t.value; };
const rot = (s, n, lo, hi) => s.replace(/[\s\S]/g, (c) => { const k = c.charCodeAt(0); return k >= lo && k <= hi ? String.fromCharCode(lo + ((k - lo + n) % (hi - lo + 1))) : c; });
const HIDDEN = { 0x200b: 'ZERO WIDTH SPACE', 0x200c: 'ZERO WIDTH NON-JOINER', 0x200d: 'ZERO WIDTH JOINER', 0x2060: 'WORD JOINER', 0xfeff: 'ZERO WIDTH NO-BREAK SPACE / BOM', 0x00ad: 'SOFT HYPHEN', 0x200e: 'LEFT-TO-RIGHT MARK', 0x200f: 'RIGHT-TO-LEFT MARK', 0x202a: 'LRE', 0x202b: 'RLE', 0x202c: 'PDF (pop direction)', 0x202d: 'LRO', 0x202e: 'RIGHT-TO-LEFT OVERRIDE', 0x2066: 'LRI', 0x2067: 'RLI', 0x2068: 'FSI', 0x2069: 'PDI', 0x180e: 'MONGOLIAN VOWEL SEPARATOR', 0x3164: 'HANGUL FILLER', 0x115f: 'HANGUL CHOSEONG FILLER', 0x00a0: 'NO-BREAK SPACE' };
const CODEC_OPS = {
  b64e: ['Base64 encode', (s) => b64encode(s)],
  b64d: ['Base64 / Base64URL decode', (s) => b64decode(s)],
  urle: ['URL encode', (s) => encodeURIComponent(s)],
  urld: ['URL decode', (s) => { let t = s, i = 0; while (/%[0-9a-f]{2}/i.test(t) && i++ < 5) t = decodeURIComponent(t.replace(/\+/g, ' ')); return t; }],
  hexe: ['Hex encode', (s) => toHex(utf8(s))],
  hexd: ['Hex decode', (s) => new TextDecoder().decode(fromHex(s.replace(/0x|\\x/gi, '')))],
  htme: ['HTML entities encode', (s) => esc(s)],
  htmd: ['HTML entities decode', htmlDecode],
  uni: ['Unicode/escape decode (\\uXXXX, \\xXX, &#…;)', (s) => htmlDecode(s.replace(/\\u\{([0-9a-f]+)\}/gi, (_, h) => String.fromCodePoint(parseInt(h, 16))).replace(/\\u([0-9a-f]{4})/gi, (_, h) => String.fromCharCode(parseInt(h, 16))).replace(/\\x([0-9a-f]{2})/gi, (_, h) => String.fromCharCode(parseInt(h, 16))))],
  qp: ['Quoted-printable decode (emails)', (s) => new TextDecoder().decode(new Uint8Array([...s.replace(/=\r?\n/g, '').replace(/=([0-9A-F]{2})/gi, (_, h) => String.fromCharCode(parseInt(h, 16)))].map((c) => c.charCodeAt(0) & 255)))],
  binD: ['Binary → text', (s) => new TextDecoder().decode(new Uint8Array((s.replace(/[^01]/g, '').match(/.{8}/g) || []).map((b) => parseInt(b, 2))))],
  binE: ['Text → binary', (s) => [...utf8(s)].map((b) => b.toString(2).padStart(8, '0')).join(' ')],
  rot13: ['ROT13', (s) => rot(rot(s, 13, 65, 90), 13, 97, 122)],
  rot47: ['ROT47', (s) => rot(s, 47, 33, 126)],
  rev: ['Reverse', (s) => [...s].reverse().join('')],
  defang: ['Defang IOCs', defang],
  refang: ['Refang IOCs', refang],
  hidden: ['Reveal hidden / zero-width characters', (s) => {
    const found = []; [...s].forEach((ch, i) => { const cp = ch.codePointAt(0); if (HIDDEN[cp] || (cp >= 0xe0000 && cp <= 0xe007f)) found.push(`pos ${i}: U+${cp.toString(16).toUpperCase().padStart(4, '0')} ${HIDDEN[cp] || 'TAG CHARACTER (invisible)'}`); });
    const vis = [...s].map((ch) => { const cp = ch.codePointAt(0); return HIDDEN[cp] || (cp >= 0xe0000 && cp <= 0xe007f) ? `⟦U+${cp.toString(16).toUpperCase()}⟧` : ch; }).join('');
    return found.length ? `${found.length} hidden character(s) — may be a zero-width fingerprint used to trace leaks, or a spoofing trick.\n\n${found.join('\n')}\n\n--- text with markers ---\n${vis}` : 'No hidden or zero-width characters found.';
  }],
};

function decodeJWT(t) {
  const parts = String(t).trim().split('.');
  if (parts.length < 2) throw new Error('Not a JWT (expected header.payload.signature)');
  const header = JSON.parse(b64decode(parts[0])), payload = JSON.parse(b64decode(parts[1]));
  return { header, payload, signed: !!parts[2] };
}

// ---------------------------------------------------------------- view
const tbState = { tab: 'codec', codecIn: '', codecOp: 'b64d', timeIn: '', idIn: '', netIn: '', domIn: '', hashIn: '', jwtIn: '', lookalike: null };
const TB_TABS = [['codec', 'Encode / decode'], ['time', 'Time converter'], ['ids', 'ID → timestamp'], ['net', 'IP & CIDR'], ['domain', 'Domain & lookalikes'], ['hash', 'Hash & identify'], ['favicon', 'Favicon hash'], ['names', 'Name permutations'], ['jwt', 'JWT']];

App.register({
  id: 'toolbox', label: 'Toolbox', icon: 'toolbox',
  render(el, params) {
    if (params.tab) tbState.tab = params.tab;
    el.innerHTML = `${viewHead('Analyst toolbox', 'Offline utilities for the small transformations investigations are full of.')}
      <div class="tabs" role="tablist">${TB_TABS.map(([k, l]) => `<button class="tab ${tbState.tab === k ? 'active' : ''}" data-tab="${k}" role="tab" aria-selected="${tbState.tab === k}">${l}</button>`).join('')}</div>
      <div id="tbBody"></div>`;
    $('.tabs', el).onclick = (e) => { const t = e.target.closest('[data-tab]'); if (t) { tbState.tab = t.dataset.tab; App.refresh(); } };
    const body = $('#tbBody', el);
    const T = {
      codec: renderCodec, time: renderTime, ids: renderIds, net: renderNet, domain: renderDomain, hash: renderHash, jwt: renderJwt, favicon: renderFavicon, names: renderPermute,
    };
    (T[tbState.tab] || renderCodec)(body);
  },
});

const tlButton = (ms, title) => `<button class="btn sm ghost" data-tl="${ms}" data-title="${esc(title)}">→ timeline</button>`;
function bindTimelineButtons(root) {
  root.addEventListener('click', (e) => { const b = e.target.closest('[data-tl]'); if (b) addEventQuick({ when: new Date(+b.dataset.tl).toISOString(), title: b.dataset.title }); });
}

function renderCodec(root) {
  root.innerHTML = `<div class="grid g2">
    <div class="card"><h3>Input</h3><textarea id="cin" rows="12" placeholder="Paste encoded or plain text…">${esc(tbState.codecIn)}</textarea>
      <div class="row mt"><select id="cop">${Object.entries(CODEC_OPS).map(([k, [l]]) => `<option value="${k}" ${tbState.codecOp === k ? 'selected' : ''}>${esc(l)}</option>`).join('')}</select><button class="btn primary" id="crun">Run</button><span class="muted small" id="chint"></span></div></div>
    <div class="card"><h3>Output<span class="spacer"></span><button class="btn sm ghost" id="cswap" title="Use output as the next input (chain operations)">⇄ Chain</button><button class="btn sm ghost" id="ccopy">Copy</button><button class="btn sm ghost" id="cext">Extract selectors</button></h3><textarea id="cout" rows="12" readonly></textarea></div></div>`;
  const cin = $('#cin', root), cout = $('#cout', root);
  const guess = () => {
    const s = cin.value.trim(); let h = '';
    if (/^[A-Za-z0-9+/_-]{16,}={0,2}$/.test(s) && s.length % 4 !== 1) h = 'Looks like Base64';
    else if (/^(0x)?[0-9a-f\s]+$/i.test(s) && s.replace(/\s|0x/gi, '').length % 2 === 0 && s.length > 8) h = 'Looks like hex';
    else if (/%[0-9a-f]{2}/i.test(s)) h = 'Looks URL-encoded';
    else if (/^eyJ[\w-]+\.[\w-]+/.test(s)) h = 'Looks like a JWT — see the JWT tab';
    else if (/hxxp|\[\.\]/i.test(s)) h = 'Defanged indicators detected';
    else if (/[​-‏⁠﻿‪-‮]/.test(s)) h = 'Hidden characters present!';
    $('#chint', root).textContent = h;
  };
  const run = () => {
    tbState.codecIn = cin.value; tbState.codecOp = $('#cop', root).value;
    try { cout.value = CODEC_OPS[tbState.codecOp][1](cin.value); cout.classList.remove('invalid'); }
    catch (e) { cout.value = `Error: ${e.message}`; cout.classList.add('invalid'); }
  };
  cin.addEventListener('input', debounce(() => { guess(); run(); }, 200));
  $('#cop', root).onchange = run; $('#crun', root).onclick = run;
  $('#cswap', root).onclick = () => { cin.value = cout.value; run(); guess(); };
  $('#ccopy', root).onclick = () => copyText(cout.value);
  $('#cext', root).onclick = () => App.go('extractor', { text: cout.value });
  guess(); if (cin.value) run();
}

function renderTime(root) {
  root.innerHTML = `<div class="card"><h3>Convert a timestamp</h3>
    <div class="row"><input id="tin" class="grow mono" placeholder="1700000000 · 13345678901234567 · 2024-03-01 14:22 · 45123.5 · 0x65f1a2b3" value="${esc(tbState.timeIn)}"><button class="btn" id="tnow">Now</button></div>
    <p class="muted small">Numbers are tried against every common epoch; plausible results (1995 → near future) are highlighted.</p><div id="tout"></div></div>`;
  const draw = () => {
    tbState.timeIn = $('#tin', root).value;
    const rows = timeInterpretations(tbState.timeIn);
    const best = rows.find((r) => r.plausible) || rows[0];
    $('#tout', root).innerHTML = !rows.length ? '' : `<table class="tbl"><thead><tr><th>Interpretation</th><th>UTC</th><th></th><th></th></tr></thead><tbody>${rows.map((r) => `<tr style="${r.plausible ? '' : 'opacity:.5'}"><td>${esc(r.label)}${r.note ? `<div class="muted small">${esc(r.note)}</div>` : ''}</td><td class="mono nowrap">${esc(fmtUTC(new Date(r.ms).toISOString()))}</td><td>${r.plausible ? '<span class="status good">plausible</span>' : ''}</td><td class="actions">${tlButton(r.ms, r.label)}</td></tr>`).join('')}</tbody></table>
      ${best ? `<h4 style="margin:18px 0 6px">${esc(best.label)} — around the world</h4><div class="grid g3 small">${TZS.map((tz) => `<div><span class="muted">${esc(tz.replace('_', ' '))}</span><div class="mono">${esc(inTz(best.ms, tz))}</div></div>`).join('')}</div>
      <dl class="kv mt small"><dt>Unix seconds</dt><dd class="mono">${Math.floor(best.ms / 1000)}</dd><dt>Unix ms</dt><dd class="mono">${Math.floor(best.ms)}</dd><dt>ISO 8601</dt><dd class="mono">${new Date(best.ms).toISOString()}</dd><dt>RFC 2822</dt><dd class="mono">${new Date(best.ms).toUTCString()}</dd><dt>Windows FILETIME</dt><dd class="mono">${(BigInt(Math.floor(best.ms)) + 11644473600000n) * 10000n}</dd><dt>WebKit / Chrome</dt><dd class="mono">${(BigInt(Math.floor(best.ms)) + 11644473600000n) * 1000n}</dd><dt>Relative</dt><dd>${esc(relTime(new Date(best.ms).toISOString()))}</dd></dl>` : ''}`;
  };
  $('#tin', root).addEventListener('input', debounce(draw, 150));
  $('#tnow', root).onclick = () => { $('#tin', root).value = String(Math.floor(Date.now() / 1000)); draw(); };
  bindTimelineButtons(root); draw();
}

function renderIds(root) {
  root.innerHTML = `<div class="card"><h3>Extract creation time from an ID</h3>
    <div class="row"><input id="iin" class="grow mono" placeholder="Post/user/message ID · UUID · MongoDB ObjectId · ULID · Bluesky TID · urn:li:activity:…" value="${esc(tbState.idIn)}"></div>
    <p class="muted small">Many platforms embed a creation timestamp in their IDs. The ID’s platform decides which row applies — plausible dates are highlighted.</p>
    <div id="iout"></div>
    <details class="mt small"><summary class="ink2" style="cursor:pointer">Where to find IDs</summary><ul class="ink2"><li><b>X / Twitter</b> — the number in <span class="mono">/status/<b>1234…</b></span></li><li><b>Discord</b> — enable Developer Mode → right-click → Copy ID</li><li><b>Instagram</b> — the media “pk”, or decode a shortcode to its numeric ID</li><li><b>TikTok</b> — the number in <span class="mono">/video/<b>7234…</b></span></li><li><b>LinkedIn</b> — the number in <span class="mono">urn:li:activity:<b>7…</b></span> (view source / share link)</li><li><b>Mastodon</b> — the status number in the URL</li><li><b>Bluesky</b> — the record key in <span class="mono">/post/<b>3k…</b></span></li></ul></details></div>`;
  const draw = () => {
    tbState.idIn = $('#iin', root).value;
    const rows = tbState.idIn.trim() ? decodeId(tbState.idIn) : [];
    $('#iout', root).innerHTML = !tbState.idIn.trim() ? '' : !rows.length ? '<p class="muted">Unrecognised ID format.</p>'
      : `<table class="tbl"><thead><tr><th>If this is…</th><th>Created (UTC)</th><th></th><th></th></tr></thead><tbody>${rows.map((r) => `<tr style="${r.plausible || isNaN(r.ms) ? '' : 'opacity:.45'}"><td>${esc(r.label)}${r.extra ? `<div class="muted small">${esc(r.extra)}</div>` : ''}</td><td class="mono nowrap">${isNaN(r.ms) ? '—' : esc(fmtUTC(new Date(r.ms).toISOString()))}</td><td>${r.plausible ? '<span class="status good">plausible</span>' : ''}</td><td class="actions">${isNaN(r.ms) ? '' : tlButton(r.ms, `${r.label}: ID ${trunc(tbState.idIn.trim(), 40)} created`)}</td></tr>`).join('')}</tbody></table>`;
  };
  $('#iin', root).addEventListener('input', debounce(draw, 150));
  bindTimelineButtons(root); draw();
}

function renderNet(root) {
  root.innerHTML = `<div class="card"><h3>IP address &amp; CIDR calculator</h3>
    <div class="row"><input id="nin" class="grow mono" placeholder="203.0.113.7 · 10.0.0.0/22 · 2001:db8::1 · 198.51.100.7 in 198.51.100.0/24" value="${esc(tbState.netIn)}"></div><div id="nout" class="mt"></div></div>`;
  const draw = () => {
    const s = (tbState.netIn = $('#nin', root).value).trim(); const o = $('#nout', root);
    if (!s) { o.innerHTML = ''; return; }
    const kv = (rows) => `<dl class="kv">${rows.map(([k, v]) => `<dt>${esc(k)}</dt><dd class="mono">${esc(v)}</dd>`).join('')}</dl>`;
    const inM = s.match(/^(\S+)\s+in\s+(\S+)$/i);
    if (inM && isIPv4(inM[1]) && cidrInfo(inM[2])) { const yes = inCidr(ipToInt(inM[1]), inM[2]); o.innerHTML = `<span class="status ${yes ? 'good' : 'crit'}">${yes ? 'Inside' : 'Outside'}</span> <span class="mono">${esc(inM[1])}</span> is ${yes ? '' : 'not '}in <span class="mono">${esc(inM[2])}</span>`; return; }
    const c = cidrInfo(s);
    if (c) { o.innerHTML = kv([['Network', `${c.network}/${c.bits}`], ['Netmask', c.mask], ['Wildcard', c.wildcard], ['First host', c.first], ['Last host', c.last], ['Broadcast', c.broadcast], ['Addresses', c.size.toLocaleString()], ['Usable hosts', c.usable.toLocaleString()], ['Range type', ipv4Info(c.network).cls]]) + (c.size <= 1024 ? `<button class="btn sm mt" id="nexp">Copy all ${c.size} addresses</button>` : ''); $('#nexp', o)?.addEventListener('click', () => { const a = []; for (let n = c.net; n <= c.bc; n++) a.push(intToIp(n)); copyText(a.join('\n')); }); return; }
    if (isIPv4(s)) { const i = ipv4Info(s); o.innerHTML = kv([['Type', i.cls], ['Reverse DNS name', i.ptr], ['Decimal', i.int], ['Hex', i.hex], ['Binary', s.split('.').map((x) => (+x).toString(2).padStart(8, '0')).join('.')], ['Octal-dotted', s.split('.').map((x) => '0' + (+x).toString(8)).join('.')]]) + `<p class="small muted">Decimal / hex / octal forms are sometimes used to disguise IPs in URLs (e.g. <span class="mono">http://${i.int}/</span>).</p><button class="btn sm" id="npv">Pivot on this IP</button>`; $('#npv', o).onclick = () => App.go('pivot', { q: s, type: 'ipv4' }); return; }
    if (isIPv6(s)) { o.innerHTML = kv([['Type', ipv6Class(s)], ['Reverse DNS name', ptrName(s)]]); return; }
    if (/^\d{8,10}$/.test(s) && +s < 2 ** 32) { o.innerHTML = kv([['Integer → IPv4', intToIp(+s)], ['Type', ipv4Info(intToIp(+s)).cls]]); return; }
    o.innerHTML = '<p class="muted small">Enter an IPv4/IPv6 address, a CIDR block, an integer IP, or “IP in CIDR”.</p>';
  };
  $('#nin', root).addEventListener('input', debounce(draw, 150)); draw();
}

function renderDomain(root) {
  const on = App.settings.activeLookups;
  root.innerHTML = `<div class="grid g2">
    <div class="card"><h3>Domain inspector</h3><input id="din" class="mono" style="width:100%" placeholder="example.com · xn--pypal-4ve.com · аpple.com" value="${esc(tbState.domIn)}"><div id="dout" class="mt"></div></div>
    <div class="card"><h3>Lookalike / typosquat generator</h3>
      <p class="card-sub">Generates permutations (omission, transposition, adjacent keys, homoglyphs, bit-flips, TLD swaps, keyword combos) of the domain on the left — for brand protection and phishing hunting.</p>
      <div class="row"><button class="btn primary" id="lgen">Generate</button>${on ? '<button class="btn" id="lchk" disabled>Check which exist (DNS)</button>' : '<span class="muted small">Enable active lookups to check which permutations exist.</span>'}<span class="spacer"></span><button class="btn sm ghost" id="lcopy" disabled>Copy</button></div>
      <div id="lout" class="mt"></div></div></div>`;
  const draw = () => {
    const s = (tbState.domIn = $('#din', root).value).trim().toLowerCase().replace(/^https?:\/\//, '').replace(/[/?#].*$/, '');
    const o = $('#dout', root);
    if (!s) { o.innerHTML = ''; return; }
    const uni = domainToUnicode(s), ascii = domainToASCII(uni) || s, mix = scriptMix(uni), sk = skeleton(uni);
    o.innerHTML = `<dl class="kv"><dt>Unicode</dt><dd class="mono">${esc(uni)}</dd><dt>ASCII / punycode</dt><dd class="mono">${esc(ascii)}</dd><dt>Registrable domain</dt><dd class="mono">${esc(registrable(ascii))}</dd><dt>TLD</dt><dd class="mono">.${esc(ascii.split('.').pop())}</dd><dt>Scripts</dt><dd>${esc(mix.scripts.join(', ') || '—')}</dd>
      ${sk !== uni.toLowerCase() || mix.mixed ? `<dt>Looks like</dt><dd class="mono">${esc(sk)}</dd>` : ''}</dl>
      ${mix.mixed ? `<p class="small"><span class="status crit">Homograph risk</span> Mixes ${esc(mix.scripts.join(' and '))} characters in one label — a classic IDN spoofing technique.</p>`
        : wholeScriptSpoof(uni) ? `<p class="small"><span class="status crit">Homograph risk</span> Every letter is a non-Latin look-alike — this renders like <b class="mono">${esc(sk)}</b> but is a different domain.</p>`
          : uni !== ascii ? '<p class="small"><span class="status warn">IDN</span> Internationalized domain — check the Unicode form carefully.</p>' : ''}
      <div class="row mt"><button class="btn sm" id="dpv">Pivot</button><button class="btn sm" id="drc">Recon</button><button class="btn sm" id="ddk">Dorks</button></div>`;
    $('#dpv', o).onclick = () => App.go('pivot', { q: ascii, type: 'domain' });
    $('#drc', o).onclick = () => App.go('recon', { q: ascii });
    $('#ddk', o).onclick = () => App.go('dorks', { target: ascii });
  };
  const drawLook = () => {
    const L = tbState.lookalike; const o = $('#lout', root);
    if (!L) { o.innerHTML = ''; return; }
    $('#lcopy', root).disabled = false; if ($('#lchk', root)) $('#lchk', root).disabled = false;
    const exist = L.items.filter((x) => x.exists === true).length;
    o.innerHTML = `<div class="small ink2 mb">${L.items.length} permutations of <b class="mono">${esc(L.base)}</b>${L.checked ? ` · <span class="status ${exist ? 'crit' : 'good'}">${exist} exist in DNS</span>` : ''}</div>
      <div style="max-height:52vh;overflow:auto"><table class="tbl"><thead><tr><th>Domain</th><th>Technique</th><th>DNS</th><th></th></tr></thead><tbody>${[...L.items].sort((a, b) => (b.exists === true) - (a.exists === true)).map((x) => `<tr><td class="mono">${esc(x.domain)}</td><td class="small muted">${esc(x.kind)}</td><td class="small">${x.exists === true ? '<span class="status crit">exists</span>' : x.exists === false ? '<span class="muted">—</span>' : x.exists === 'err' ? '<span class="muted">error</span>' : ''}</td><td class="actions">${x.exists === true ? `<button class="btn sm ghost" data-ladd="${esc(x.domain)}">+ case</button><button class="btn sm ghost" data-lpv="${esc(x.domain)}">Pivot</button>` : ''}</td></tr>`).join('')}</tbody></table></div>`;
  };
  $('#din', root).addEventListener('input', debounce(draw, 150));
  $('#lgen', root).onclick = () => {
    const d = domainToASCII(tbState.domIn.trim()) || tbState.domIn.trim();
    if (!isDomain(d)) return toast('Enter a valid domain first', 'error');
    tbState.lookalike = { base: registrable(d), items: lookalikes(d), checked: false }; drawLook();
  };
  $('#lcopy', root).onclick = () => copyText(tbState.lookalike.items.map((x) => x.domain).join('\n'));
  $('#lchk', root)?.addEventListener('click', async (e) => {
    const L = tbState.lookalike; if (!L) return;
    const btn = e.target; btn.disabled = true;
    const queue = L.items.slice(0, 400); let done = 0;
    const worker = async () => { while (queue.length) { const x = queue.shift(); try { const j = await doh(x.domain, 'NS'); x.exists = j.Status === 0 && (j.Answer || j.Authority || []).length > 0 ? true : false; } catch { x.exists = 'err'; } done++; if (done % 10 === 0) { btn.textContent = `Checking… ${done}/${L.items.length}`; drawLook(); } } };
    await Promise.all(Array.from({ length: 6 }, worker));
    L.checked = true; btn.textContent = 'Check which exist (DNS)'; btn.disabled = false; drawLook();
    App.touch(`Lookalikes: checked ${done} permutations of ${L.base}`);
  });
  $('#lout', root).addEventListener('click', (e) => {
    const b = e.target.closest('button'); if (!b) return;
    if (b.dataset.ladd) { const r = App.addEntity('domain', b.dataset.ladd, { tags: ['lookalike'], source: `Lookalike of ${tbState.lookalike.base}` }); const base = App.findEntity('domain', tbState.lookalike.base); if (base && r.entity) App.addLink(r.entity.id, base.id, 'impersonates?'); App.touch(r.created ? `Added lookalike ${b.dataset.ladd}` : null); b.textContent = '✓'; b.disabled = true; }
    if (b.dataset.lpv) App.go('pivot', { q: b.dataset.lpv, type: 'domain' });
  });
  draw(); drawLook();
}

function renderHash(root) {
  root.innerHTML = `<div class="grid g2">
    <div class="card"><h3>Hash text</h3><textarea id="hin" rows="6" placeholder="Text to hash (UTF-8)">${esc(tbState.hashIn)}</textarea><label class="check mt"><input type="checkbox" id="hlow"> Lower-case &amp; trim first (e.g. emails for Gravatar)</label><div id="hout" class="mt"></div></div>
    <div class="card"><h3>Identify a hash</h3><input id="hid" class="mono" style="width:100%" placeholder="Paste a hash or hash string"><div id="hidout" class="mt"></div>
      <p class="muted small mt">To fingerprint files, use <a href="#/evidence">Evidence</a> (logs them) or <a href="#/metadata">Metadata</a>.</p></div></div>`;
  const draw = async () => {
    let s = (tbState.hashIn = $('#hin', root).value);
    if ($('#hlow', root).checked) s = s.trim().toLowerCase();
    if (!s) { $('#hout', root).innerHTML = ''; return; }
    const h = await hashBuffer(utf8(s));
    $('#hout', root).innerHTML = `<dl class="kv">${Object.entries(h).map(([k, v]) => `<dt>${k.toUpperCase()}</dt><dd class="mono break" data-copy="${v}" style="cursor:copy" title="Click to copy">${v}</dd>`).join('')}</dl>`;
  };
  $('#hin', root).addEventListener('input', debounce(draw, 150)); $('#hlow', root).onchange = draw;
  $('#hid', root).addEventListener('input', (e) => {
    const v = e.target.value.trim(), a = hashAlgo(v);
    $('#hidout', root).innerHTML = v ? (a ? `<span class="status good">${esc(a)}</span> <span class="muted small">(${v.length} chars)</span><div class="row mt"><button class="btn sm" id="hpv">Pivot on hash</button></div>` : '<span class="muted">Unknown format</span>') : '';
    $('#hpv', root)?.addEventListener('click', () => App.go('pivot', { q: v, type: 'hash' }));
  });
  root.addEventListener('click', (e) => { const c = e.target.closest('[data-copy]'); if (c) copyText(c.dataset.copy); });
  draw();
}

function renderJwt(root) {
  root.innerHTML = `<div class="card"><h3>Decode a JSON Web Token</h3><p class="card-sub">Decoded locally. The signature is not verified. Never paste live production tokens into online decoders.</p>
    <textarea id="jin" rows="4" placeholder="eyJhbGciOi…">${esc(tbState.jwtIn)}</textarea><div id="jout" class="mt"></div></div>`;
  const draw = () => {
    const s = (tbState.jwtIn = $('#jin', root).value).trim(); const o = $('#jout', root);
    if (!s) { o.innerHTML = ''; return; }
    try {
      const { header, payload, signed } = decodeJWT(s);
      const times = ['iat', 'nbf', 'exp', 'auth_time'].filter((k) => typeof payload[k] === 'number').map((k) => [k, fmtUTC(new Date(payload[k] * 1000).toISOString())]);
      const exp = payload.exp && payload.exp * 1000 < Date.now();
      o.innerHTML = `${String(header.alg).toLowerCase() === 'none' || !signed ? '<p><span class="status crit">Unsigned</span> alg “none” or missing signature.</p>' : ''}
        ${times.length ? `<dl class="kv mb">${times.map(([k, v]) => `<dt>${k}</dt><dd class="mono">${v}</dd>`).join('')}</dl>${payload.exp ? `<p class="small"><span class="status ${exp ? 'warn' : 'good'}">${exp ? 'Expired' : 'Not expired'}</span></p>` : ''}` : ''}
        <div class="grid g2"><div><div class="small muted">Header</div><pre class="out">${esc(JSON.stringify(header, null, 2))}</pre></div><div><div class="small muted">Payload</div><pre class="out">${esc(JSON.stringify(payload, null, 2))}</pre></div></div>`;
    } catch (e) { o.innerHTML = `<span class="status crit">Invalid</span> ${esc(e.message)}`; }
  };
  $('#jin', root).addEventListener('input', debounce(draw, 150)); draw();
}
