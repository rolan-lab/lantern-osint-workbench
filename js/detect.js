'use strict';
/* Lantern — selector types, normalisation, type detection and bulk extraction. */

// Families map onto the 8 validated categorical slots; identity is never colour-alone (each type also has a 2-letter glyph).
const FAMILIES = {
  people:   { label: 'People & orgs',     slot: 1 },
  accounts: { label: 'Accounts & contact', slot: 2 },
  infra:    { label: 'Infrastructure',     slot: 3 },
  crypto:   { label: 'Crypto',             slot: 4 },
  places:   { label: 'Locations',          slot: 5 },
  media:    { label: 'Media & documents',  slot: 6 },
  files:    { label: 'Hashes & files',     slot: 7 },
  vulns:    { label: 'Vulnerabilities',    slot: 8 },
  other:    { label: 'Other',              slot: 0 },
};
const TYPES = {
  person:   { label: 'Person',       fam: 'people',   glyph: 'PE' },
  org:      { label: 'Organization', fam: 'people',   glyph: 'OR' },
  email:    { label: 'Email',        fam: 'accounts', glyph: '@' },
  username: { label: 'Username',     fam: 'accounts', glyph: 'UN' },
  phone:    { label: 'Phone',        fam: 'accounts', glyph: 'PH' },
  domain:   { label: 'Domain',       fam: 'infra',    glyph: 'DO' },
  url:      { label: 'URL',          fam: 'infra',    glyph: 'UR' },
  ipv4:     { label: 'IPv4',         fam: 'infra',    glyph: 'IP' },
  ipv6:     { label: 'IPv6',         fam: 'infra',    glyph: 'I6' },
  mac:      { label: 'MAC address',  fam: 'infra',    glyph: 'MA' },
  btc:      { label: 'Bitcoin',      fam: 'crypto',   glyph: '₿' },
  eth:      { label: 'Ethereum',     fam: 'crypto',   glyph: 'Ξ' },
  location: { label: 'Location',     fam: 'places',   glyph: 'LO' },
  image:    { label: 'Image',        fam: 'media',    glyph: 'IM' },
  document: { label: 'Document',     fam: 'media',    glyph: 'DC' },
  hash:     { label: 'Hash',         fam: 'files',    glyph: '#' },
  cve:      { label: 'CVE',          fam: 'vulns',    glyph: 'CV' },
  keyword:  { label: 'Keyword',      fam: 'other',    glyph: 'KW' },
  other:    { label: 'Other',        fam: 'other',    glyph: '··' },
};
const typeLabel = (t) => (TYPES[t] || TYPES.other).label;
const famOf = (t) => (TYPES[t] || TYPES.other).fam;
const typeColorVar = (t) => `var(--c${FAMILIES[famOf(t)].slot})`;
const typeChip = (t) => `<span class="type-pill"><span class="dot" style="background:${typeColorVar(t)}"></span>${esc(typeLabel(t))}</span>`;
const TYPE_OPTIONS = Object.entries(TYPES).map(([k, v]) => [k, v.label]);

// ---------------------------------------------------------------- normalisation
function cleanValue(type, v) {
  v = String(v ?? '').trim();
  switch (type) {
    case 'email': return v.toLowerCase().replace(/^mailto:/, '');
    case 'domain': return v.toLowerCase().replace(/^\*\./, '').replace(/\.$/, '');
    case 'username': return v.replace(/^@/, '');
    case 'hash': case 'mac': case 'ipv6': return v.toLowerCase();
    case 'cve': return v.toUpperCase();
    case 'location': { const m = v.match(/^\s*(-?\d+(?:\.\d+)?)\s*[,;\s]\s*(-?\d+(?:\.\d+)?)\s*$/); return m ? `${+m[1]}, ${+m[2]}` : v; }
    default: return v;
  }
}
function entityKey(type, value) {
  const v = cleanValue(type, value);
  if (type === 'phone') return type + ':' + v.replace(/[^\d]/g, '');
  if (['eth', 'domain', 'email', 'username', 'person', 'org', 'keyword'].includes(type)) return type + ':' + v.toLowerCase();
  return type + ':' + v;
}
function hostOf(u) { try { return new URL(u).hostname.toLowerCase().replace(/^www\./, ''); } catch { return null; } }

// ---------------------------------------------------------------- defang / refang
function refang(t) {
  return String(t)
    .replace(/\bh[xX]{2}p(s?)(\[?:\]?)?\/\//gi, (m, s) => `http${s}://`)
    .replace(/\bh[xX]{2}p(s?)\b/gi, 'http$1')
    .replace(/\[:\/\/\]/g, '://').replace(/\[:\]/g, ':')
    .replace(/\s?[[({]\s*(?:\.|dot)\s*[\])}]\s?/gi, '.')
    .replace(/\s?[[({]\s*(?:@|at)\s*[\])}]\s?/gi, '@');
}
function defang(t) {
  return String(t)
    .replace(/\bhttp(s?):\/\//gi, (m, s) => `hxxp${s}[://]`)
    .replace(/([a-z0-9])\.(?=[a-z0-9-]+\b)/gi, '$1[.]')
    .replace(/@/g, '[@]');
}

// ---------------------------------------------------------------- validation helpers
const FILE_EXT = new Set('pdf html htm shtml js mjs json php asp aspx jsp exe dll jpg jpeg png gif svg webp bmp ico tif tiff heic txt rtf doc docx xls xlsx ppt pptx odt ods zip rar 7z gz tgz tar bz2 csv tsv xml py md css scss log ini cfg conf tmp bak mp4 mp3 wav mov avi mkv flac sys bat cmd ps1 sh yml yaml ts tsx jsx java class jar rb cpp hpp so bin iso img msi apk dmg lnk vbs eml msg pst db sqlite key pem crt cer der lock map woff woff2 ttf otf eot'.split(' '));
const GTLD = new Set(('com net org edu gov mil int info biz name pro mobi asia tel travel jobs cat aero coop museum post xxx onion i2p ' +
  'xyz online site top shop store tech app dev cloud live life world news blog link click space website club vip work fun icu buzz ' +
  'agency email digital network solutions services company media studio design group global today center rocks ninja guru zone ' +
  'systems tools wiki social chat support finance money bank capital fund ltd llc inc art photo pics win bid loan date download ' +
  'racing review stream trade party science cam men page web host hosting domains software security crypto games game bet casino ' +
  'porn sex adult dating love xin wang ren shop store sale market deals business consulting academy school college university education ' +
  'health care clinic legal law lawyer realestate properties house city country london nyc berlin paris tokyo moscow amsterdam ' +
  'google amazon apple microsoft aws azure gle youtube meta fyi lol pw red blue pink black gold green one plus pub run sbs cfd bond ' +
  'mom best cyou boats quest monster beauty hair makeup skin tokyo osaka yokohama nagoya shopping express foundation charity ngo ong ' +
  'church faith gives family events tickets show tv video audio film movie music radio band fm am rocks town today report press ' +
  'directory community forum help how foo zip mov new nexus ooo app ai io co me us uk').split(/\s+/));
function tldOk(tld) {
  tld = tld.toLowerCase();
  if (tld.startsWith('xn--')) return true;
  if (FILE_EXT.has(tld)) return false;
  if (tld.length === 2) return /^[a-z]{2}$/.test(tld);
  return GTLD.has(tld);
}
function isDomain(s) {
  s = String(s).toLowerCase().replace(/\.$/, '');
  if (s.length > 253 || !/^(?:[a-z0-9_](?:[a-z0-9-_]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,24}|xn--[a-z0-9-]{2,59})$/.test(s)) return false;
  return tldOk(s.slice(s.lastIndexOf('.') + 1));
}
function isIPv4(s) { return /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/.test(s); }
function isIPv6(s) {
  if (!s.includes(':') || (s.match(/::/g) || []).length > 1 || /:::/.test(s)) return false;
  const parts = s.split('::');
  const left = parts[0] ? parts[0].split(':') : [];
  const right = parts.length > 1 && parts[1] ? parts[1].split(':') : [];
  const all = [...left, ...right];
  if (!all.length || !all.every((g) => /^[0-9a-f]{1,4}$/i.test(g))) return false;
  return parts.length === 1 ? all.length === 8 : all.length <= 7;
}
function hashAlgo(h) {
  if (/^[a-f0-9]{32}$/i.test(h)) return 'MD5 / NTLM';
  if (/^[a-f0-9]{40}$/i.test(h)) return 'SHA-1';
  if (/^[a-f0-9]{64}$/i.test(h)) return 'SHA-256';
  if (/^[a-f0-9]{128}$/i.test(h)) return 'SHA-512';
  if (/^\$2[aby]\$\d\d\$[./A-Za-z0-9]{53}$/.test(h)) return 'bcrypt';
  if (/^\$argon2(id|i|d)\$/.test(h)) return 'Argon2';
  if (/^\$6\$/.test(h)) return 'sha512crypt';
  if (/^\$1\$/.test(h)) return 'md5crypt';
  if (/^\d+:[A-Za-z0-9+/]{2,}={0,2}:[A-Za-z0-9+/]{2,}$/.test(h)) return 'ssdeep (fuzzy)';
  if (/^T1[0-9A-F]{70}$/i.test(h)) return 'TLSH (fuzzy)';
  return '';
}
function parseCoords(s) {
  const m = String(s).match(/^\s*(-?\d{1,2}(?:\.\d+)?)\s*[,;\s]\s*(-?\d{1,3}(?:\.\d+)?)\s*$/);
  if (!m) return null;
  const lat = +m[1], lon = +m[2];
  return Math.abs(lat) <= 90 && Math.abs(lon) <= 180 ? { lat, lon } : null;
}
function phoneDigits(s) { return String(s).replace(/[^\d]/g, ''); }

// ---------------------------------------------------------------- type detection for a single selector
function detectType(raw) {
  const s = refang(String(raw || '').trim());
  if (!s) return null;
  if (/^CVE-\d{4}-\d{4,7}$/i.test(s)) return 'cve';
  if (/^(?:https?|ftp):\/\/\S+$/i.test(s)) return /\.(jpe?g|png|gif|webp|bmp|avif|heic)(\?|#|$)/i.test(s) ? 'image' : 'url';
  if (/^(mailto:)?[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$/i.test(s)) return 'email';
  if (isIPv4(s)) return 'ipv4';
  if (isIPv6(s)) return 'ipv6';
  if (/^(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}$/i.test(s)) return 'mac';
  if (parseCoords(s) && /[.]/.test(s)) return 'location';
  if (/^0x[a-f0-9]{40}$/i.test(s)) return 'eth';
  if (/^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}$/.test(s) && btcValid(s)) return 'btc';
  if (hashAlgo(s)) return 'hash';
  if (isDomain(s)) return 'domain';
  if (/^(?:\+|00)?[\d\s().-]{7,20}$/.test(s) && phoneDigits(s).length >= 7 && phoneDigits(s).length <= 15 && /^[+(\d]/.test(s)) return 'phone';
  if (/^@[\w.]{1,40}$/.test(s)) return 'username';
  if (/^[A-Za-z0-9_.-]{2,40}$/.test(s) && !/^\d+$/.test(s)) return 'username';
  return 'keyword';
}

// ---------------------------------------------------------------- bulk extraction
const PROFILE_RX = [
  [/^(?:www\.)?(?:twitter|x)\.com$/, /^\/([A-Za-z0-9_]{1,15})\/?$/, 'X / Twitter'],
  [/^(?:www\.)?instagram\.com$/, /^\/([A-Za-z0-9_.]{1,30})\/?$/, 'Instagram'],
  [/^(?:www\.)?github\.com$/, /^\/([A-Za-z0-9-]{1,39})\/?$/, 'GitHub'],
  [/^(?:www\.|old\.)?reddit\.com$/, /^\/(?:u|user)\/([A-Za-z0-9_-]{3,20})\/?/, 'Reddit'],
  [/^(?:www\.)?tiktok\.com$/, /^\/@([A-Za-z0-9_.]{2,24})\/?/, 'TikTok'],
  [/^(?:www\.)?youtube\.com$/, /^\/@([A-Za-z0-9_.-]{3,30})\/?/, 'YouTube'],
  [/^t\.me$/, /^\/([A-Za-z0-9_]{5,32})\/?$/, 'Telegram'],
  [/^(?:www\.)?facebook\.com$/, /^\/([A-Za-z0-9.]{5,50})\/?$/, 'Facebook'],
  [/^(?:[a-z]{2,3}\.)?linkedin\.com$/, /^\/in\/([A-Za-z0-9_-]{3,100})\/?/, 'LinkedIn'],
  [/^(?:www\.)?twitch\.tv$/, /^\/([A-Za-z0-9_]{4,25})\/?$/, 'Twitch'],
  [/^(?:www\.)?threads\.(?:net|com)$/, /^\/@([A-Za-z0-9_.]{1,30})\/?$/, 'Threads'],
  [/^bsky\.app$/, /^\/profile\/([A-Za-z0-9.-]{3,253})\/?$/, 'Bluesky'],
  [/^(?:www\.)?medium\.com$/, /^\/@([A-Za-z0-9_.]{1,40})\/?/, 'Medium'],
];
const PROFILE_RESERVED = new Set(['search', 'home', 'explore', 'login', 'signup', 'share', 'intent', 'hashtag', 'i', 'p', 'reel', 'reels', 'watch', 'status', 'settings', 'about', 'help', 'privacy', 'terms', 'notifications', 'messages', 'stories', 'features', 'pricing', 'orgs', 'topics', 'marketplace', 'groups', 'pages', 'events', 'joinchat', 'policies', 'directory', 'results', 'channel', 'tos', 'legal', 'jobs', 'company', 'feed', 'sharer.php', 'profile.php', 'watch', 'embed', 'download', 'tag', 'tags']);

// Big platforms that show up in almost any text; extracted but not pre-selected.
const NOISE_DOMAINS = new Set('google.com gmail.com googlemail.com youtube.com youtu.be facebook.com fb.com instagram.com twitter.com x.com t.co linkedin.com github.com gitlab.com microsoft.com outlook.com hotmail.com live.com office.com apple.com icloud.com amazon.com amazonaws.com cloudflare.com wikipedia.org reddit.com tiktok.com t.me telegram.org whatsapp.com wa.me yahoo.com bing.com duckduckgo.com w3.org schema.org gstatic.com googleapis.com googleusercontent.com akamaihd.net cloudfront.net archive.org web.archive.org'.split(' '));

/**
 * Extract selectors from free text. Returns [{type, value, count, note}] de-duplicated by entity key.
 */
function extractSelectors(text, { refangFirst = true, profiles = true } = {}) {
  let t = String(text || '');
  if (refangFirst) t = refang(t);
  const found = new Map();
  const add = (type, value, note = '') => {
    value = cleanValue(type, value);
    if (!value) return;
    const k = entityKey(type, value);
    const f = found.get(k);
    if (f) f.count++; else found.set(k, { type, value, count: 1, note });
  };
  const each = (rx, fn) => { rx.lastIndex = 0; let m; while ((m = rx.exec(t))) fn(m); };

  // URLs first (and remember spans so we don't double-extract usernames from paths)
  const urls = [];
  each(/\b(?:https?|ftp):\/\/[^\s<>"'`{}|\\^\]\[)]+[^\s<>"'`{}|\\^\]\[).,;:!?]/gi, (m) => {
    const u = m[0]; urls.push(u);
    add(/\.(jpe?g|png|gif|webp|bmp|avif|heic)(\?|#|$)/i.test(u) ? 'image' : 'url', u);
    if (profiles) {
      try {
        const x = new URL(u);
        for (const [hostRx, pathRx, site] of PROFILE_RX) {
          if (!hostRx.test(x.hostname.toLowerCase())) continue;
          const pm = x.pathname.match(pathRx);
          if (pm && !PROFILE_RESERVED.has(pm[1].toLowerCase())) add('username', pm[1], `from ${site} URL`);
        }
      } catch { /* not a URL */ }
    }
  });
  each(/\b[a-z0-9._%+-]+@((?:[a-z0-9-]+\.)+[a-z]{2,24})\b/gi, (m) => { if (tldOk(m[1].split('.').pop())) add('email', m[0]); });
  each(/\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b(?![.\d])/g, (m) => add('ipv4', m[0]));
  each(/(?<![0-9a-z:])[0-9a-f:]{3,39}(?![0-9a-z:])/gi, (m) => { if (isIPv6(m[0])) add('ipv6', m[0]); });
  each(/\b(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,24}|xn--[a-z0-9-]{2,59})\b(?!@)/gi, (m) => {
    const d = m[0].toLowerCase();
    if (isDomain(d)) add('domain', d.replace(/^www\./, ''));
  });
  each(/\bCVE-\d{4}-\d{4,7}\b/gi, (m) => add('cve', m[0]));
  each(/\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b/gi, (m) => add('mac', m[0]));
  each(/\b0x[a-f0-9]{40}\b/gi, (m) => add('eth', m[0]));
  each(/\b(?:bc1[ac-hj-np-z02-9]{11,71}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b/g, (m) => { if (btcValid(m[0])) add('btc', m[0]); });
  each(/(?<![\w$])(?:[a-f0-9]{128}|[a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32})(?![\w])/gi, (m) => {
    if (t.slice(Math.max(0, m.index - 2), m.index).toLowerCase() === '0x') return;
    if (/^\d+$/.test(m[0])) return; // long pure-digit runs are rarely hashes
    add('hash', m[0]);
  });
  each(/(?<![\w@./])@([A-Za-z0-9_](?:[A-Za-z0-9_.]{0,28}[A-Za-z0-9_])?)(?![\w@])/g, (m) => { if (!isDomain(m[1])) add('username', m[1], 'handle'); });
  each(/(?<![\w+])(?:\+|00)[1-9]\d{0,3}[\s.-]?(?:\(?\d{1,5}\)?[\s.-]?){1,5}\d{2,5}(?![\w])/g, (m) => { const n = phoneDigits(m[0]).length; if (n >= 8 && n <= 15) add('phone', m[0].trim()); });
  each(/(?<![\w+])\(?\b\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}\b/g, (m) => add('phone', m[0].trim()));
  each(/(?<![\d.])(-?\d{1,2}\.\d{4,})\s*,\s*(-?\d{1,3}\.\d{4,})(?!\d|\.\d)/g, (m) => { const c = parseCoords(`${m[1]},${m[2]}`); if (c) add('location', `${c.lat}, ${c.lon}`); });

  // Drop phone numbers that are just the national part of an international match (+1 (555)… vs (555)…).
  const phones = [...found.values()].filter((f) => f.type === 'phone').map((f) => phoneDigits(f.value));
  for (const [k, f] of found) {
    if (f.type !== 'phone') continue;
    const d = phoneDigits(f.value);
    if (phones.some((p) => p.length > d.length && p.endsWith(d))) found.delete(k);
  }
  for (const f of found.values()) if (f.type === 'domain' && NOISE_DOMAINS.has(f.value)) { f.noise = true; f.note = f.note || 'common platform'; }
  const order = Object.keys(TYPES);
  return [...found.values()].sort((a, b) => order.indexOf(a.type) - order.indexOf(b.type) || a.value.localeCompare(b.value));
}
