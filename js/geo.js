'use strict';
/* Lantern — geodesy & solar maths (pure functions, no DOM): coordinate formats (DMS, DDM, UTM, MGRS, Plus Code,
   geohash, Maidenhead), great-circle distance/bearing, and sun position for shadow analysis (chronolocation). */

const RAD = Math.PI / 180;
const norm360 = (d) => ((d % 360) + 360) % 360;
const normLon = (l) => ((((l + 180) % 360) + 360) % 360) - 180;

// ---------------------------------------------------------------- UTM / MGRS (WGS84, Krüger series)
const UTM = (() => {
  const a = 6378137, f = 1 / 298.257223563, k0 = 0.9996;
  const n = f / (2 - f), n2 = n * n, n3 = n2 * n;
  const A = (a / (1 + n)) * (1 + n2 / 4 + (n2 * n2) / 64);
  return {
    k0, A, e2n: (2 * Math.sqrt(n)) / (1 + n),
    alpha: [n / 2 - (2 * n2) / 3 + (5 * n3) / 16, (13 * n2) / 48 - (3 * n3) / 5, (61 * n3) / 240],
    beta: [n / 2 - (2 * n2) / 3 + (37 * n3) / 96, n2 / 48 + n3 / 15, (17 * n3) / 480],
    delta: [2 * n - (2 * n2) / 3 - 2 * n3, (7 * n2) / 3 - (8 * n3) / 5, (56 * n3) / 15],
  };
})();
const MGRS_BANDS = 'CDEFGHJKLMNPQRSTUVWX';
const MGRS_COLS = ['ABCDEFGH', 'JKLMNPQR', 'STUVWXYZ'];
const MGRS_ROWS = 'ABCDEFGHJKLMNPQRSTUV';

function utmZone(lat, lon) {
  let z = Math.floor((normLon(lon) + 180) / 6) + 1;
  if (z > 60) z = 60;
  if (lat >= 56 && lat < 64 && lon >= 3 && lon < 12) z = 32; // Norway
  if (lat >= 72 && lat < 84) { if (lon >= 0 && lon < 9) z = 31; else if (lon >= 9 && lon < 21) z = 33; else if (lon >= 21 && lon < 33) z = 35; else if (lon >= 33 && lon < 42) z = 37; } // Svalbard
  return z;
}
/** lat/lon → { zone, hemi, band, easting, northing }. Valid for 80°S – 84°N. */
function toUTM(lat, lon, zone) {
  if (lat < -80 || lat > 84) return null;
  zone = zone || utmZone(lat, lon);
  const phi = lat * RAD, dl = (lon - ((zone - 1) * 6 - 180 + 3)) * RAD;
  const t = Math.sinh(Math.atanh(Math.sin(phi)) - UTM.e2n * Math.atanh(UTM.e2n * Math.sin(phi)));
  const xi = Math.atan2(t, Math.cos(dl)), eta = Math.atanh(Math.sin(dl) / Math.sqrt(1 + t * t));
  let E = eta, N = xi;
  UTM.alpha.forEach((al, i) => { const j = 2 * (i + 1); E += al * Math.cos(j * xi) * Math.sinh(j * eta); N += al * Math.sin(j * xi) * Math.cosh(j * eta); });
  return { zone, hemi: lat >= 0 ? 'N' : 'S', band: MGRS_BANDS[Math.min(19, Math.floor((lat + 80) / 8))], easting: 500000 + UTM.k0 * UTM.A * E, northing: (lat >= 0 ? 0 : 10000000) + UTM.k0 * UTM.A * N };
}
function fromUTM(zone, hemi, easting, northing) {
  const xi = (northing - (hemi === 'S' ? 10000000 : 0)) / (UTM.k0 * UTM.A), eta = (easting - 500000) / (UTM.k0 * UTM.A);
  let xp = xi, ep = eta;
  UTM.beta.forEach((b, i) => { const j = 2 * (i + 1); xp -= b * Math.sin(j * xi) * Math.cosh(j * eta); ep -= b * Math.cos(j * xi) * Math.sinh(j * eta); });
  const chi = Math.asin(Math.sin(xp) / Math.cosh(ep));
  let phi = chi;
  UTM.delta.forEach((d, i) => { phi += d * Math.sin(2 * (i + 1) * chi); });
  return { lat: phi / RAD, lon: (zone - 1) * 6 - 180 + 3 + Math.atan2(Math.sinh(ep), Math.cos(xp)) / RAD };
}
/** MGRS grid reference; digits = 1..5 per axis (5 = 1 m, 4 = 10 m …). */
function toMGRS(lat, lon, digits = 5) {
  const u = toUTM(lat, lon); if (!u) return '';
  const e = Math.floor(u.easting), nn = Math.floor(u.northing);
  const col = MGRS_COLS[(u.zone - 1) % 3][Math.floor(e / 100000) - 1];
  const row = MGRS_ROWS[(Math.floor(nn / 100000) + (u.zone % 2 === 0 ? 5 : 0)) % 20];
  const part = (v) => String(Math.floor((v % 100000) / 10 ** (5 - digits))).padStart(digits, '0');
  return `${u.zone}${u.band}${col}${row}${part(e)}${part(nn)}`;
}
function fromMGRS(s) {
  const m = String(s).toUpperCase().replace(/\s+/g, '').match(/^(\d{1,2})([C-HJ-NP-X])([A-HJ-NP-Z])([A-HJ-NP-V])(\d{2,10})?$/);
  if (!m || (m[5] && m[5].length % 2)) return null;
  const zone = +m[1], band = m[2];
  if (zone < 1 || zone > 60) return null;
  const colIdx = MGRS_COLS[(zone - 1) % 3].indexOf(m[3]); if (colIdx < 0) return null;
  const d = (m[5] || '').length / 2, scale = 10 ** (5 - d);
  const e = (colIdx + 1) * 100000 + (d ? +m[5].slice(0, d) * scale : 0) + (d < 5 ? scale / 2 : 0);
  let rowIdx = MGRS_ROWS.indexOf(m[4]) - (zone % 2 === 0 ? 5 : 0); if (rowIdx < 0) rowIdx += 20;
  let nn = rowIdx * 100000 + (d ? +m[5].slice(d) * scale : 0) + (d < 5 ? scale / 2 : 0);
  // Row letters repeat every 2,000 km: pick the repetition that falls inside the latitude band.
  const bandLat = -80 + 8 * MGRS_BANDS.indexOf(band), hemi = bandLat >= 0 ? 'N' : 'S';
  const minN = Math.floor(toUTM(bandLat, (zone - 1) * 6 - 177, zone).northing / 100000) * 100000;
  while (nn < minN) nn += 2000000;
  const p = fromUTM(zone, hemi, e, nn);
  return Math.abs(p.lat) <= 90 ? p : null;
}

// ---------------------------------------------------------------- geohash, Plus Code, Maidenhead
const GH32 = '0123456789bcdefghjkmnpqrstuvwxyz';
function toGeohash(lat, lon, len = 9) {
  let la = [-90, 90], lo = [-180, 180], out = '', bit = 0, ch = 0, even = true;
  while (out.length < len) {
    const r = even ? lo : la, v = even ? lon : lat, mid = (r[0] + r[1]) / 2;
    if (v >= mid) { ch = ch * 2 + 1; r[0] = mid; } else { ch *= 2; r[1] = mid; }
    even = !even;
    if (++bit === 5) { out += GH32[ch]; bit = 0; ch = 0; }
  }
  return out;
}
function fromGeohash(s) {
  s = String(s).toLowerCase();
  if (!s || [...s].some((c) => !GH32.includes(c))) return null;
  const la = [-90, 90], lo = [-180, 180]; let even = true;
  for (const c of s) { const v = GH32.indexOf(c); for (let b = 4; b >= 0; b--) { const r = even ? lo : la, mid = (r[0] + r[1]) / 2; if ((v >> b) & 1) r[0] = mid; else r[1] = mid; even = !even; } }
  return { lat: (la[0] + la[1]) / 2, lon: (lo[0] + lo[1]) / 2, errLat: (la[1] - la[0]) / 2, errLon: (lo[1] - lo[0]) / 2 };
}
const OLC = '23456789CFGHJMPQRVWX';
/** Open Location Code ("Plus Code"), 10 digits ≈ 14 m cell; 11 adds one grid-refinement character (≈ 3 m). */
function toPlusCode(lat, lon, len = 10) {
  lat = Math.min(90 - 1e-9, Math.max(-90, lat)); lon = normLon(lon);
  let la = Math.round((lat + 90) * 8000 * 1e3) / 1e3, lo = Math.round((lon + 180) * 8000 * 1e3) / 1e3; // units of 1/8000°
  la = Math.floor(la); lo = Math.floor(lo);
  let code = '';
  for (let i = 0; i < 5; i++) { code = OLC[la % 20] + OLC[lo % 20] + code; la = Math.floor(la / 20); lo = Math.floor(lo / 20); }
  code = code.slice(0, 8) + '+' + code.slice(8);
  if (len > 10) {
    const fy = (((lat + 90) * 8000) % 1) * 5, fx = (((lon + 180) * 8000) % 1) * 4;
    code += OLC[Math.floor(fy) * 4 + Math.floor(fx)];
  }
  return code;
}
function fromPlusCode(s) {
  const c = String(s).toUpperCase().trim();
  if (!/^[23456789CFGHJMPQRVWX]{8}\+[23456789CFGHJMPQRVWX]{2,3}$/.test(c)) return null;
  const d = c.replace('+', '');
  let lat = -90, lon = -180, res = 20;
  for (let i = 0; i < 10; i += 2) { lat += OLC.indexOf(d[i]) * res; lon += OLC.indexOf(d[i + 1]) * res; if (i < 8) res /= 20; }
  let hLat = res, hLon = res;
  if (d.length > 10) { const g = OLC.indexOf(d[10]); hLat = res / 5; hLon = res / 4; lat += Math.floor(g / 4) * hLat; lon += (g % 4) * hLon; }
  return { lat: lat + hLat / 2, lon: lon + hLon / 2 };
}
function toMaidenhead(lat, lon) {
  const lo = normLon(lon) + 180, la = lat + 90, A = 'ABCDEFGHIJKLMNOPQRSTUVWX';
  return A[Math.floor(lo / 20)] + A[Math.floor(la / 10)] + Math.floor((lo % 20) / 2) + Math.floor(la % 10) + A[Math.floor((lo % 2) * 12)].toLowerCase() + A[Math.floor((la % 1) * 24)].toLowerCase();
}

// ---------------------------------------------------------------- text formats
function fmtDMS(lat, lon) {
  const one = (d, pos, neg) => { const a = Math.abs(d); let deg = Math.floor(a), m = Math.floor((a - deg) * 60), s = (a - deg - m / 60) * 3600; if (s >= 59.995) { s = 0; m++; } if (m >= 60) { m = 0; deg++; } return `${deg}°${String(m).padStart(2, '0')}′${s.toFixed(2).padStart(5, '0')}″${d < 0 ? neg : pos}`; };
  return `${one(lat, 'N', 'S')} ${one(lon, 'E', 'W')}`;
}
function fmtDDM(lat, lon) {
  const one = (d, pos, neg) => { const a = Math.abs(d), deg = Math.floor(a); return `${deg}° ${((a - deg) * 60).toFixed(4)}′ ${d < 0 ? neg : pos}`; };
  return `${one(lat, 'N', 'S')}, ${one(lon, 'E', 'W')}`;
}
/** Parse almost any coordinate notation. Returns { lat, lon, format } or null. */
function parseAnyCoords(input) {
  const s = String(input || '').trim();
  if (!s) return null;
  const ok = (lat, lon, format) => (Number.isFinite(lat) && Number.isFinite(lon) && Math.abs(lat) <= 90 && Math.abs(lon) <= 180 ? { lat, lon, format } : null);
  // Map URLs: @lat,lon · ?q=lat,lon · ll=lat,lon · mlat=..&mlon=.. · #map=z/lat/lon
  if (/^https?:\/\//i.test(s)) {
    const osm = s.match(/[?&]mlat=(-?\d+(?:\.\d+)?)&mlon=(-?\d+(?:\.\d+)?)/) || s.match(/#map=\d+\/(-?\d+(?:\.\d+)?)\/(-?\d+(?:\.\d+)?)/);
    const g = s.match(/!3d(-?\d+(?:\.\d+)?)!4d(-?\d+(?:\.\d+)?)/) || s.match(/@(-?\d+(?:\.\d+)?),(-?\d+(?:\.\d+)?)/) || s.match(/[?&](?:q|query|ll|center|cp|viewpoint|daddr|destination)=(?:loc:)?(-?\d+(?:\.\d+)?)(?:,|%2C|~)(-?\d+(?:\.\d+)?)/i);
    const m = osm || g;
    return m ? ok(+m[1], +m[2], 'map URL') : null;
  }
  const up = s.toUpperCase();
  let m = up.match(/^\s*(-?\d{1,3}(?:\.\d+)?)\s*°?\s*([NS])?\s*[,;\s]\s*(-?\d{1,3}(?:\.\d+)?)\s*°?\s*([EW])?\s*$/);
  if (m) return ok(+m[1] * (m[2] === 'S' ? -1 : 1), +m[3] * (m[4] === 'W' ? -1 : 1), 'decimal degrees');
  m = up.match(/^\s*([NS])\s*(\d{1,3}(?:\.\d+)?)\s*°?\s*[,;\s]\s*([EW])\s*(\d{1,3}(?:\.\d+)?)\s*°?\s*$/);
  if (m) return ok(+m[2] * (m[1] === 'S' ? -1 : 1), +m[4] * (m[3] === 'W' ? -1 : 1), 'decimal degrees');
  // DMS / DDM: two groups of deg [min [sec]] with a hemisphere letter before or after each.
  const part = '([NSEW])?\\s*(\\d{1,3})\\s*[°D\\s]\\s*(\\d{1,2}(?:\\.\\d+)?)\\s*[\'′M\\s]?\\s*(?:(\\d{1,2}(?:\\.\\d+)?)\\s*(?:"|″|\'\'|S(?![\\s,;]*\\d))?)?\\s*([NSEW])?';
  m = up.match(new RegExp(`^\\s*${part}\\s*[,;\\s]\\s*${part}\\s*$`));
  if (m) {
    const val = (h1, d, mi, sec, h2) => { const h = h1 || h2, v = +d + +mi / 60 + (sec ? +sec / 3600 : 0); return { v: /[SW]/.test(h || '') ? -v : v, h, bad: +mi >= 60 || (sec && +sec >= 60) }; };
    let a = val(m[1], m[2], m[3], m[4], m[5]), b = val(m[6], m[7], m[8], m[9], m[10]);
    if (a.bad || b.bad) return null;
    if (/[EW]/.test(a.h || '') && /[NS]/.test(b.h || '')) [a, b] = [b, a];
    return ok(a.v, b.v, m[4] ? 'degrees minutes seconds' : 'degrees decimal minutes');
  }
  const pc = fromPlusCode(s); if (pc) return ok(pc.lat, pc.lon, 'Plus Code');
  const mg = fromMGRS(s); if (mg) return ok(mg.lat, mg.lon, 'MGRS');
  m = up.match(/^(\d{1,2})\s*([C-HJ-NP-X])?\s+(\d{5,7}(?:\.\d+)?)\s*M?E?\s*[,\s]\s*(\d{1,8}(?:\.\d+)?)\s*M?N?$/);
  if (m && +m[1] >= 1 && +m[1] <= 60) { const hemi = m[2] && m[2] < 'N' ? 'S' : 'N'; const p = fromUTM(+m[1], hemi, +m[3], +m[4]); return ok(p.lat, p.lon, 'UTM'); }
  if (/^[0-9b-hjkmnp-z]{5,12}$/i.test(s) && /[a-z]/i.test(s)) { const gh = fromGeohash(s); if (gh) return ok(gh.lat, gh.lon, 'geohash'); }
  return null;
}
/** Every notation for a point: [[label, value], …]. */
function coordFormats(lat, lon) {
  const u = toUTM(lat, lon), r = (v, n) => +v.toFixed(n);
  return [
    ['Decimal degrees', `${r(lat, 6)}, ${r(lon, 6)}`],
    ['Degrees minutes seconds', fmtDMS(lat, lon)],
    ['Degrees decimal minutes', fmtDDM(lat, lon)],
    ['MGRS (1 m)', u ? toMGRS(lat, lon).replace(/^(\d+[A-Z])([A-Z]{2})(\d{5})(\d{5})$/, '$1 $2 $3 $4') : 'outside UTM limits'],
    ['UTM', u ? `${u.zone}${u.band} ${Math.round(u.easting)} ${Math.round(u.northing)}` : 'outside UTM limits'],
    ['Plus Code', toPlusCode(lat, lon, 11)],
    ['Geohash', toGeohash(lat, lon, 9)],
    ['Maidenhead locator', toMaidenhead(lat, lon)],
    ['geo: URI', `geo:${r(lat, 6)},${r(lon, 6)}`],
  ];
}

// ---------------------------------------------------------------- great-circle maths
const EARTH_R = 6371008.8;
function haversine(a, b) {
  const dp = (b.lat - a.lat) * RAD, dl = (b.lon - a.lon) * RAD;
  const h = Math.sin(dp / 2) ** 2 + Math.cos(a.lat * RAD) * Math.cos(b.lat * RAD) * Math.sin(dl / 2) ** 2;
  return 2 * EARTH_R * Math.asin(Math.min(1, Math.sqrt(h)));
}
function bearing(a, b) {
  const p1 = a.lat * RAD, p2 = b.lat * RAD, dl = (b.lon - a.lon) * RAD;
  return norm360(Math.atan2(Math.sin(dl) * Math.cos(p2), Math.cos(p1) * Math.sin(p2) - Math.sin(p1) * Math.cos(p2) * Math.cos(dl)) / RAD);
}
function destination(a, brg, dist) {
  const d = dist / EARTH_R, t = brg * RAD, p1 = a.lat * RAD;
  const p2 = Math.asin(Math.sin(p1) * Math.cos(d) + Math.cos(p1) * Math.sin(d) * Math.cos(t));
  return { lat: p2 / RAD, lon: normLon(a.lon + Math.atan2(Math.sin(t) * Math.sin(d) * Math.cos(p1), Math.cos(d) - Math.sin(p1) * Math.sin(p2)) / RAD) };
}
function midpoint(a, b) {
  const p1 = a.lat * RAD, p2 = b.lat * RAD, dl = (b.lon - a.lon) * RAD;
  const bx = Math.cos(p2) * Math.cos(dl), by = Math.cos(p2) * Math.sin(dl);
  return { lat: Math.atan2(Math.sin(p1) + Math.sin(p2), Math.sqrt((Math.cos(p1) + bx) ** 2 + by ** 2)) / RAD, lon: normLon(a.lon + Math.atan2(by, Math.cos(p1) + bx) / RAD) };
}
const COMPASS = ['N', 'NNE', 'NE', 'ENE', 'E', 'ESE', 'SE', 'SSE', 'S', 'SSW', 'SW', 'WSW', 'W', 'WNW', 'NW', 'NNW'];
const compass = (deg) => COMPASS[Math.round(norm360(deg) / 22.5) % 16];

// ---------------------------------------------------------------- sun position (low-precision solar ephemeris, ≈ 0.3° accuracy)
const J2000 = 2451545, OBLIQ = 23.4397 * RAD;
const sunDays = (ms) => ms / 86400000 - 0.5 + 2440588 - J2000;
const sunAnomaly = (d) => RAD * (357.5291 + 0.98560028 * d);
const sunEclLon = (M) => M + RAD * (1.9148 * Math.sin(M) + 0.02 * Math.sin(2 * M) + 0.0003 * Math.sin(3 * M)) + RAD * 102.9372 + Math.PI;
/** { azimuth (° clockwise from north), altitude (° above horizon), shadowBearing, shadowRatio (shadow length ÷ object height) } */
function sunPosition(ms, lat, lon) {
  const d = sunDays(ms), L = sunEclLon(sunAnomaly(d));
  const dec = Math.asin(Math.sin(OBLIQ) * Math.sin(L)), ra = Math.atan2(Math.sin(L) * Math.cos(OBLIQ), Math.cos(L));
  const phi = lat * RAD, H = RAD * (280.16 + 360.9856235 * d) + lon * RAD - ra;
  const alt = Math.asin(Math.sin(phi) * Math.sin(dec) + Math.cos(phi) * Math.cos(dec) * Math.cos(H));
  const az = norm360(Math.atan2(Math.sin(H), Math.cos(H) * Math.sin(phi) - Math.tan(dec) * Math.cos(phi)) / RAD + 180);
  const altitude = alt / RAD;
  return { azimuth: az, altitude, shadowBearing: norm360(az + 180), shadowRatio: altitude > 0.5 ? 1 / Math.tan(alt) : Infinity };
}
/** Sunrise, solar noon and sunset (ms since epoch) for the UTC calendar day containing `ms`. rise/set are null in polar day/night. */
function sunTimes(ms, lat, lon) {
  const lw = -lon * RAD, phi = lat * RAD, J0 = 0.0009;
  const noonMs = Date.UTC(new Date(ms).getUTCFullYear(), new Date(ms).getUTCMonth(), new Date(ms).getUTCDate(), 12) - (lon / 15) * 3600000;
  const n = Math.round(sunDays(noonMs) - J0 - lw / (2 * Math.PI));
  const ds = J0 + lw / (2 * Math.PI) + n, M = sunAnomaly(ds), L = sunEclLon(M), dec = Math.asin(Math.sin(OBLIQ) * Math.sin(L));
  const transit = (x) => J2000 + x + 0.0053 * Math.sin(M) - 0.0069 * Math.sin(2 * L);
  const toMs = (j) => (j + 0.5 - 2440588) * 86400000;
  const jNoon = transit(ds);
  const cosW = (Math.sin(-0.833 * RAD) - Math.sin(phi) * Math.sin(dec)) / (Math.cos(phi) * Math.cos(dec));
  if (cosW < -1 || cosW > 1) return { noon: toMs(jNoon), rise: null, set: null, polar: cosW < -1 ? 'day' : 'night' };
  const jSet = transit(J0 + (Math.acos(cosW) + lw) / (2 * Math.PI) + n);
  return { noon: toMs(jNoon), rise: toMs(jNoon - (jSet - jNoon)), set: toMs(jSet) };
}
/** Minutes of the UTC day (around local solar noon ± 12 h) when the sun matches a measured shadow.
    by = 'bearing' (shadow direction, °) or 'ratio' (shadow length ÷ object height). Returns [{ ms, pos, err }]. */
function solveShadow(dayMs, lat, lon, by, value, tolerance) {
  const t = sunTimes(dayMs, lat, lon), start = t.noon - 12 * 3600000, hits = [];
  let run = null;
  for (let i = 0; i <= 1440; i++) {
    const ms = start + i * 60000, p = sunPosition(ms, lat, lon);
    let err = Infinity;
    if (p.altitude > 0.5) err = by === 'bearing' ? Math.abs(((p.shadowBearing - value + 540) % 360) - 180) : Math.abs(p.shadowRatio - value) / Math.max(value, 0.01);
    if (err <= tolerance) { if (!run || err < run.err) run = { ms, pos: p, err }; } else if (run) { hits.push(run); run = null; }
  }
  if (run) hits.push(run);
  return hits;
}
