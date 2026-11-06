'use strict';
/* Lantern — hashing & encoding primitives (pure JS, no dependencies).
   MD5 / SHA-1 / SHA-256 are synchronous so they work everywhere; WebCrypto is used for speed when available. */

const utf8 = (s) => new TextEncoder().encode(String(s));
const toHex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
const fromHex = (hex) => { const h = hex.replace(/[^0-9a-f]/gi, ''); const out = new Uint8Array(h.length >> 1); for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16); return out; };
const rotl = (x, n) => (x << n) | (x >>> (32 - n));
const rotr = (x, n) => (x >>> n) | (x << (32 - n));

/** Merkle–Damgård padding. Returns a DataView over the padded message. */
function mdPad(bytes, littleEndian) {
  const len = bytes.length;
  const total = (((len + 8) >>> 6) + 1) * 64;
  const buf = new Uint8Array(total);
  buf.set(bytes); buf[len] = 0x80;
  const dv = new DataView(buf.buffer);
  const lo = (len * 8) >>> 0, hi = Math.floor(len / 0x20000000);
  if (littleEndian) { dv.setUint32(total - 8, lo, true); dv.setUint32(total - 4, hi, true); }
  else { dv.setUint32(total - 8, hi, false); dv.setUint32(total - 4, lo, false); }
  return dv;
}

const MD5_K = new Uint32Array(64).map((_, i) => Math.floor(Math.abs(Math.sin(i + 1)) * 4294967296));
const MD5_S = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21];
function md5(input) {
  const bytes = typeof input === 'string' ? utf8(input) : new Uint8Array(input);
  const dv = mdPad(bytes, true);
  let a0 = 0x67452301, b0 = 0xefcdab89 | 0, c0 = 0x98badcfe | 0, d0 = 0x10325476;
  const M = new Int32Array(16);
  for (let off = 0; off < dv.byteLength; off += 64) {
    for (let i = 0; i < 16; i++) M[i] = dv.getInt32(off + i * 4, true);
    let A = a0, B = b0, C = c0, D = d0;
    for (let i = 0; i < 64; i++) {
      let F, g;
      if (i < 16) { F = (B & C) | (~B & D); g = i; }
      else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) & 15; }
      else if (i < 48) { F = B ^ C ^ D; g = (3 * i + 5) & 15; }
      else { F = C ^ (B | ~D); g = (7 * i) & 15; }
      F = (F + A + MD5_K[i] + M[g]) | 0;
      A = D; D = C; C = B;
      B = (B + rotl(F, MD5_S[i])) | 0;
    }
    a0 = (a0 + A) | 0; b0 = (b0 + B) | 0; c0 = (c0 + C) | 0; d0 = (d0 + D) | 0;
  }
  const out = new DataView(new ArrayBuffer(16));
  [a0, b0, c0, d0].forEach((v, i) => out.setInt32(i * 4, v, true));
  return toHex(new Uint8Array(out.buffer));
}

function sha1(input) {
  const bytes = typeof input === 'string' ? utf8(input) : new Uint8Array(input);
  const dv = mdPad(bytes, false);
  const H = [0x67452301, 0xefcdab89 | 0, 0x98badcfe | 0, 0x10325476, 0xc3d2e1f0 | 0];
  const W = new Int32Array(80);
  for (let off = 0; off < dv.byteLength; off += 64) {
    for (let t = 0; t < 16; t++) W[t] = dv.getInt32(off + t * 4, false);
    for (let t = 16; t < 80; t++) W[t] = rotl(W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16], 1);
    let [a, b, c, d, e] = H;
    for (let t = 0; t < 80; t++) {
      let f, k;
      if (t < 20) { f = (b & c) | (~b & d); k = 0x5a827999; }
      else if (t < 40) { f = b ^ c ^ d; k = 0x6ed9eba1; }
      else if (t < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8f1bbcdc | 0; }
      else { f = b ^ c ^ d; k = 0xca62c1d6 | 0; }
      const tmp = (rotl(a, 5) + f + e + k + W[t]) | 0;
      e = d; d = c; c = rotl(b, 30); b = a; a = tmp;
    }
    H[0] = (H[0] + a) | 0; H[1] = (H[1] + b) | 0; H[2] = (H[2] + c) | 0; H[3] = (H[3] + d) | 0; H[4] = (H[4] + e) | 0;
  }
  const out = new DataView(new ArrayBuffer(20));
  H.forEach((v, i) => out.setInt32(i * 4, v, false));
  return toHex(new Uint8Array(out.buffer));
}

const SHA256_K = new Int32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);
function sha256Raw(input) {
  const bytes = typeof input === 'string' ? utf8(input) : new Uint8Array(input);
  const dv = mdPad(bytes, false);
  const H = new Int32Array([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]);
  const W = new Int32Array(64);
  for (let off = 0; off < dv.byteLength; off += 64) {
    for (let t = 0; t < 16; t++) W[t] = dv.getInt32(off + t * 4, false);
    for (let t = 16; t < 64; t++) {
      const s0 = rotr(W[t - 15], 7) ^ rotr(W[t - 15], 18) ^ (W[t - 15] >>> 3);
      const s1 = rotr(W[t - 2], 17) ^ rotr(W[t - 2], 19) ^ (W[t - 2] >>> 10);
      W[t] = (W[t - 16] + s0 + W[t - 7] + s1) | 0;
    }
    let [a, b, c, d, e, f, g, h] = H;
    for (let t = 0; t < 64; t++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const t1 = (h + S1 + ch + SHA256_K[t] + W[t]) | 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) | 0;
      h = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
    }
    H[0] += a; H[1] += b; H[2] += c; H[3] += d; H[4] += e; H[5] += f; H[6] += g; H[7] += h;
  }
  const out = new DataView(new ArrayBuffer(32));
  H.forEach((v, i) => out.setInt32(i * 4, v, false));
  return new Uint8Array(out.buffer);
}
const sha256 = (input) => toHex(sha256Raw(input));

/** Hash a buffer with MD5, SHA-1, SHA-256 (+ SHA-512 when WebCrypto is available). */
async function hashBuffer(buf) {
  const bytes = new Uint8Array(buf);
  const out = { md5: md5(bytes) };
  if (globalThis.crypto && crypto.subtle) {
    try {
      const [s1, s256, s512] = await Promise.all(['SHA-1', 'SHA-256', 'SHA-512'].map((a) => crypto.subtle.digest(a, bytes)));
      return Object.assign(out, { sha1: toHex(new Uint8Array(s1)), sha256: toHex(new Uint8Array(s256)), sha512: toHex(new Uint8Array(s512)) });
    } catch { /* fall through to JS */ }
  }
  return Object.assign(out, { sha1: sha1(bytes), sha256: sha256(bytes) });
}

// ---------------------------------------------------------------- crypto-address validation
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function b58decode(s) {
  let n = 0n;
  for (const ch of s) { const i = B58.indexOf(ch); if (i < 0) return null; n = n * 58n + BigInt(i); }
  let hex = n === 0n ? '' : n.toString(16);
  if (hex.length % 2) hex = '0' + hex;
  let lead = 0; for (const ch of s) { if (ch === '1') lead++; else break; }
  return new Uint8Array([...new Array(lead).fill(0), ...fromHex(hex)]);
}
function base58CheckValid(s, expectedLen = 25) {
  const b = b58decode(s);
  if (!b || b.length !== expectedLen) return false;
  const payload = b.slice(0, -4), chk = b.slice(-4);
  const h = sha256Raw(sha256Raw(payload));
  return chk.every((v, i) => v === h[i]);
}
const BECH32 = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
function bech32Valid(addr) {
  if (addr !== addr.toLowerCase() && addr !== addr.toUpperCase()) return false;
  const s = addr.toLowerCase();
  const pos = s.lastIndexOf('1');
  if (pos < 1 || pos + 7 > s.length || s.length > 90) return false;
  const hrp = s.slice(0, pos);
  const data = [...s.slice(pos + 1)].map((c) => BECH32.indexOf(c));
  if (data.includes(-1)) return false;
  const G = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let chk = 1;
  for (const v of [...[...hrp].map((c) => c.charCodeAt(0) >> 5), 0, ...[...hrp].map((c) => c.charCodeAt(0) & 31), ...data]) {
    const b = chk >>> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) if ((b >>> i) & 1) chk ^= G[i];
  }
  return chk === 1 || chk === 0x2bc830a3; // bech32 / bech32m
}
function btcValid(a) {
  if (/^(bc1|tb1)/i.test(a)) return bech32Valid(a);
  if (/^[13mn2]/.test(a)) return base58CheckValid(a);
  return false;
}

// ---------------------------------------------------------------- punycode (RFC 3492)
const PUNY = { base: 36, tMin: 1, tMax: 26, skew: 38, damp: 700, bias: 72, n: 128 };
function punyAdapt(delta, numPoints, first) {
  const { base, tMin, tMax, skew, damp } = PUNY;
  delta = first ? Math.floor(delta / damp) : delta >> 1;
  delta += Math.floor(delta / numPoints);
  let k = 0;
  while (delta > ((base - tMin) * tMax) >> 1) { delta = Math.floor(delta / (base - tMin)); k += base; }
  return Math.floor(k + ((base - tMin + 1) * delta) / (delta + skew));
}
function punyDecode(input) {
  const { base, tMin, tMax } = PUNY;
  const out = [];
  let n = PUNY.n, i = 0, bias = PUNY.bias;
  let b = input.lastIndexOf('-'); if (b < 0) b = 0;
  for (let j = 0; j < b; j++) out.push(input.charCodeAt(j));
  for (let idx = b > 0 ? b + 1 : 0; idx < input.length;) {
    const oldi = i; let w = 1;
    for (let k = base; ; k += base) {
      if (idx >= input.length) throw new Error('Invalid punycode');
      const c = input.charCodeAt(idx++);
      const digit = c >= 48 && c <= 57 ? c - 22 : c >= 65 && c <= 90 ? c - 65 : c >= 97 && c <= 122 ? c - 97 : base;
      if (digit >= base) throw new Error('Invalid punycode');
      i += digit * w;
      const t = k <= bias ? tMin : k >= bias + tMax ? tMax : k - bias;
      if (digit < t) break;
      w *= base - t;
    }
    const len = out.length + 1;
    bias = punyAdapt(i - oldi, len, oldi === 0);
    n += Math.floor(i / len); i %= len;
    out.splice(i++, 0, n);
  }
  return String.fromCodePoint(...out);
}
/** Domain → Unicode form (decodes xn-- labels). */
function domainToUnicode(d) {
  return String(d).split('.').map((l) => { if (/^xn--/i.test(l)) { try { return punyDecode(l.slice(4).toLowerCase()); } catch { return l; } } return l; }).join('.');
}
/** Domain → ASCII (punycode) form using the browser's IDNA implementation. */
function domainToASCII(d) {
  try { return new URL('http://' + String(d).trim()).hostname; } catch { return null; }
}

// ---------------------------------------------------------------- base64 helpers (UTF-8 safe)
function b64encode(str) { const b = utf8(str); let s = ''; for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode(...b.subarray(i, i + 0x8000)); return btoa(s); }
function b64decodeBytes(s) {
  let t = String(s).replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/');
  while (t.length % 4) t += '=';
  const bin = atob(t); const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function b64decode(s) { return new TextDecoder('utf-8', { fatal: false }).decode(b64decodeBytes(s)); }
