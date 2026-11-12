#!/usr/bin/env node
'use strict';
/* Lantern — dependency-free smoke tests for the pure logic (detection, geodesy, header parsing, hashing).
   Run: node tests/run.js   The browser files are plain scripts sharing one global scope, so they are concatenated into one VM context. */
const fs = require('fs'), path = require('path'), vm = require('vm');
const root = path.join(__dirname, '..');
const files = ['core', 'crypto', 'detect', 'pivots', 'geo', 'views/case', 'views/timeline', 'views/toolbox', 'views/tools2', 'views/mail', 'views/analysis', 'views/ops'];
const stubDoc = { documentElement: { setAttribute() {}, removeAttribute() {} }, querySelector: () => null, querySelectorAll: () => [], createElement: () => ({ style: {}, appendChild() {}, addEventListener() {} }) };
const ctx = vm.createContext({ console, TextEncoder, TextDecoder, URL, Intl, BigInt, setTimeout, clearTimeout, btoa, atob, crypto: globalThis.crypto, document: stubDoc, window: { addEventListener() {}, dispatchEvent() {} }, localStorage: { getItem: () => null, setItem() {} }, Event: class {}, Blob, navigator: {}, location: { hash: '' } });
const src = files.map((f) => fs.readFileSync(path.join(root, 'js', f + '.js'), 'utf8').replace(/^'use strict';/, '')).join('\n');
let pass = 0, fail = 0;
ctx.eq = (name, got, want) => { const a = JSON.stringify(got), b = JSON.stringify(want); if (a === b) pass++; else { fail++; console.log(`FAIL ${name}\n   got  ${a}\n   want ${b}`); } };
ctx.near = (name, got, want, tol) => { if (Math.abs(got - want) <= tol) pass++; else { fail++; console.log(`FAIL ${name}: got ${got}, want ${want} ± ${tol}`); } };
ctx.ok = (name, v) => ctx.eq(name, !!v, true);

vm.runInContext(src + `
// ---- selector detection
eq('detect email', detectType('Jane.Doe@Example.com'), 'email');
eq('detect domain', detectType('hxxps[:]//evil[.]example[.]com'.replace(/^hxxps\\[:\\]\\/\\//, '')), 'domain');
eq('detect ipv4', detectType('8.8.8.8'), 'ipv4');
eq('detect ipv6', detectType('2001:db8::1'), 'ipv6');
eq('detect asn', detectType('as15169'), 'asn');
eq('clean asn', cleanValue('asn', 'as 15169'), 'AS15169');
eq('detect tracker UA', detectType('UA-12345678-1'), 'tracker');
eq('detect tracker GTM', detectType('GTM-ABC123'), 'tracker');
eq('clean adsense', cleanValue('tracker', 'ca-pub-1234567890123456'), 'pub-1234567890123456');
eq('detect btc', detectType('1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa'), 'btc');
eq('detect btc bech32', detectType('bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq'), 'btc');
eq('detect eth', detectType('0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe'), 'eth');
eq('detect tron', detectType('TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t'), 'wallet');
eq('tron chain', altWallet('TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t'), 'TRON');
eq('doge chain', altWallet('DH5yaieqoZN36fDVciNyRueRGvGLR3mr7L'), 'Dogecoin');
eq('ltc chain', altWallet('LTC1QH3M7V7ZQ5KJ8'.toLowerCase()), '');
eq('bad tron checksum', altWallet('TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6u'), '');
eq('iban valid', ibanValid('GB82 WEST 1234 5698 7654 32'), true);
eq('iban invalid', ibanValid('GB82 WEST 1234 5698 7654 33'), false);
eq('detect iban', detectType('DE89370400440532013000'), 'iban');
eq('detect cve', detectType('cve-2021-44228'), 'cve');
eq('detect hash', detectType('44d88612fea8a8f36de82e1278abb02f'), 'hash');
eq('detect coords', detectType('48.8584, 2.2945'), 'location');
eq('detect username', detectType('torvalds'), 'username');

const ex = extractSelectors('Contact admin@evil-shop[.]com or hxxps://evil-shop[.]com/login from 203.0.113.9 (AS64496). GA: UA-55512345-2, ads ca-pub-1234567890123456, tag GTM-K9XQ2LD. Pay to TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t or IBAN DE89 3704 0044 0532 0130 00. See CVE-2024-3094. Profile https://github.com/octocat and https://keybase.io/chris');
const has = (t, v) => ex.some((r) => r.type === t && r.value === v);
ok('extract email', has('email', 'admin@evil-shop.com'));
ok('extract url', has('url', 'https://evil-shop.com/login'));
ok('extract ip', has('ipv4', '203.0.113.9'));
ok('extract asn', has('asn', 'AS64496'));
ok('extract UA', has('tracker', 'UA-55512345-2'));
ok('extract adsense', has('tracker', 'pub-1234567890123456'));
ok('extract gtm', has('tracker', 'GTM-K9XQ2LD'));
ok('extract tron', has('wallet', 'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t'));
ok('extract iban', has('iban', 'DE89370400440532013000'));
ok('no phone inside iban', !ex.some((r) => r.type === 'phone'));
ok('extract cve', has('cve', 'CVE-2024-3094'));
ok('extract github user', has('username', 'octocat'));
ok('extract keybase user', has('username', 'chris'));
ok('no false tracker from prose', !extractSelectors('G-FORCE and G-STRING are words; UA-1 too').some((r) => r.type === 'tracker'));

// ---- pivots resolve for every type, with no unfilled template variables
for (const t of Object.keys(TYPES)) { const sample = { email: 'a@example.com', domain: 'example.com', url: 'https://example.com/x', ipv4: '8.8.8.8', ipv6: '2001:db8::1', location: '48.8584, 2.2945', hash: '44d88612fea8a8f36de82e1278abb02f', cve: 'CVE-2021-44228', asn: 'AS15169', phone: '+44 20 7946 0958' }[t] || 'sample'; const g = pivotsFor(t, sample); ok('pivots ' + t, g.length && g.every((x) => x.items.every((i) => /^https:\\/\\//.test(i.url) && !/[{}]/.test(i.url)))); }

// ---- geodesy
eq('mgrs eiffel', toMGRS(48.8584, 2.2945), '31UDQ4825211954');
eq('mgrs sydney', toMGRS(-33.8568, 151.2153).slice(0, 5), '56HLH');
{ const p = fromMGRS('31U DQ 48252 11954'); near('mgrs→lat', p.lat, 48.8584, 2e-5); near('mgrs→lon', p.lon, 2.2945, 2e-5); }
{ const p = fromMGRS(toMGRS(-22.9519, -43.2105)); near('mgrs south roundtrip', p.lat, -22.9519, 2e-5); }
eq('geohash', toGeohash(48.8584, 2.2945, 9), 'u09tunquc');
eq('plus code', toPlusCode(48.8584, 2.2945, 10), '8FW4V75V+9R');
{ const p = fromPlusCode('8FW4V75V+9R'); near('plus→lat', p.lat, 48.8584, 1e-4); near('plus→lon', p.lon, 2.2945, 1e-4); }
eq('maidenhead', toMaidenhead(48.8584, 2.2945), 'JN18du');
{ const p = parseAnyCoords('40°26′46″N 79°58′56″W'); near('dms lat', p.lat, 40.44611, 1e-4); near('dms lon', p.lon, -79.98222, 1e-4); }
{ const p = parseAnyCoords('W 79 58 56, N 40 26 46'); near('dms swapped lat', p.lat, 40.44611, 1e-4); }
{ const p = parseAnyCoords('https://www.google.com/maps/@-33.8568,151.2153,17z'); near('url lat', p.lat, -33.8568, 1e-6); }
eq('junk coords', parseAnyCoords('hello world'), null);
eq('out of range', parseAnyCoords('95.0, 10.0'), null);
near('NYC–London km', haversine({ lat: 40.7128, lon: -74.006 }, { lat: 51.5074, lon: -0.1278 }) / 1000, 5570, 5);
near('bearing', bearing({ lat: 40.7128, lon: -74.006 }, { lat: 51.5074, lon: -0.1278 }), 51.2, 0.2);
{ const s = sunPosition(Date.UTC(2024, 5, 21, 12, 0), 51.5074, -0.1278); near('sun altitude London solstice', s.altitude, 61.9, 0.4); near('sun azimuth', s.azimuth, 178.7, 0.6); }
{ const t = sunTimes(Date.UTC(2024, 5, 21, 12), 51.5074, -0.1278); near('sunrise London', t.rise, Date.UTC(2024, 5, 21, 3, 43), 4 * 60000); near('sunset London', t.set, Date.UTC(2024, 5, 21, 20, 21), 4 * 60000); }
eq('polar day', sunTimes(Date.UTC(2024, 5, 21, 12), 78.2, 15.6).polar, 'day');
eq('shadow ratio solutions', solveShadow(Date.UTC(2024, 5, 21, 12), 51.5074, -0.1278, 'ratio', 1, 0.03).length, 2);

// ---- hashing
eq('mmh3 empty', mmh3(utf8('')), 0);
eq('mmh3 hello', mmh3(utf8('hello')), 613153351);
eq('mmh3 foo', mmh3(utf8('foo')), -156908512);
eq('mmh3 tail lengths', [mmh3(utf8('a')), mmh3(utf8('ab')), mmh3(utf8('abc')), mmh3(utf8('abcd'))], [1009084850, -1681926305, -1277324294, 1139631978]);

// ---- name permutations
{ const p = namePermutations({ first: 'José', last: 'Müller-Østergård' }).map((x) => x.v); ok('perm first.last', p.includes('jose.mullerostergard')); ok('perm flast', p.includes('jmullerostergard')); }

// ---- email headers
const H = [
  'Delivered-To: victim@corp.example',
  'Received: by 2002:a05:6402:1234:b0:1a2:b3c4:d5e6 with SMTP id x1csp123; Mon, 4 Mar 2024 10:00:09 -0800 (PST)',
  'Received: from mail-out.bulkmailer.example (mail-out.bulkmailer.example. [198.51.100.25]) by mx.google.com with ESMTPS id abc123 for <victim@corp.example> (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384); Mon, 04 Mar 2024 10:00:08 -0800 (PST)',
  'Received: from [192.168.1.44] (unknown [203.0.113.77])',
  '\\tby mail-out.bulkmailer.example (Postfix) with ESMTPSA id 4F00D;',
  '\\tMon,  4 Mar 2024 18:00:05 +0000 (UTC)',
  'Authentication-Results: mx.google.com; dkim=pass header.i=@bulkmailer.example header.s=s1 header.b=AbCd; spf=pass (google.com: domain of bounce@bulkmailer.example designates 198.51.100.25 as permitted sender) smtp.mailfrom=bounce@bulkmailer.example; dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=bank.example',
  'Return-Path: <bounce@bulkmailer.example>',
  'From: "=?UTF-8?B?U2VjdXJpdHkgVGVhbQ==?= security@bank.example" <alerts@bank.example>',
  'Reply-To: helpdesk@bank-secure-login.com',
  'To: victim@corp.example',
  'Subject: =?UTF-8?Q?Urgent=3A_verify_your_account?=',
  'Date: Mon, 4 Mar 2024 21:00:01 +0300',
  'Message-ID: <20240304180001.4F00D@mail-out.bulkmailer.example>',
  'X-Mailer: PHPMailer 6.8.0',
  '', 'body text with Received: fake line',
].join('\\r\\n');
const R = parseEmailHeaders(H);
eq('hdr subject', R.subject, 'Urgent: verify your account');
eq('hdr from', R.from, 'alerts@bank.example');
eq('hdr hops', R.hops.length, 3);
eq('hdr hop order', R.hops[0].by, 'mail-out.bulkmailer.example');
eq('hdr origin ip', R.originIp, '203.0.113.77');
eq('hdr hop delay', R.hops[1].delay, 3);
eq('hdr auth', [R.auth.spf, R.auth.dkim, R.auth.dmarc], ['pass', 'pass', 'fail']);
eq('hdr dkim d', R.auth.dkimSelector, 's1');
eq('hdr offset', R.dateOffset, '+0300');
ok('hdr flag dmarc', R.flags.some((f) => f.level === 'crit' && /DMARC/.test(f.text)));
ok('hdr flag reply-to', R.flags.some((f) => /Reply-To/.test(f.text)));
ok('hdr flag display-name spoof', R.flags.some((f) => /Display name/.test(f.text)));
ok('hdr flag script', R.flags.some((f) => /PHPMailer/.test(f.text)));
ok('hdr private ip excluded', !R.selectors.ips.includes('192.168.1.44'));
ok('hdr selectors', R.selectors.ips.includes('198.51.100.25') && R.selectors.domains.includes('bank-secure-login.com'));
eq('hdr empty', parseEmailHeaders('not headers at all').headers.length, 0);

// ---- ACH scoring & STIX
{ const c = newCase('t'); c.hypotheses = [{ id: 'a', text: 'A' }, { id: 'b', text: 'B' }];
  c.ach = [{ id: '1', text: 'e1', weight: 'high', ratings: { a: 'C', b: 'II' } }, { id: '2', text: 'e2', weight: 'low', ratings: { a: 'I', b: 'I' } }];
  eq('ach scores', achScores(c).map((s) => s.score), [0.5, 4.5]);
  eq('ach diagnostic', [achDiagnostic(c, c.ach[0]), achDiagnostic(c, c.ach[1])], [true, false]);
  ok('ach markdown', achMarkdown(c).join('\\n').includes('| 1 | A | 0.5 |'));
  c.entities = [{ id: 'x', type: 'domain', value: 'evil.example' }, { id: 'y', type: 'ipv4', value: '203.0.113.9' }, { id: 'z', type: 'keyword', value: 'skip me' }];
  c.links = [{ id: 'l', from: 'x', to: 'y', label: 'resolves to' }];
  const b = buildStix(c); eq('stix types', b.objects.map((o) => o.type), ['report', 'domain-name', 'ipv4-addr', 'relationship']); eq('stix rel', b.objects[3].relationship_type, 'resolves-to'); }
ok('migrate adds new fields', Array.isArray(migrate({ cases: { q: { id: 'q', name: 'old', updated: '', entities: [] } }, activeCaseId: 'q' }).cases.q.hypotheses));
`, ctx, { filename: 'lantern-bundle.js' });
console.log(`${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
