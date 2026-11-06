'use strict';
/* Lantern — local file metadata extraction. Nothing leaves the browser.
   Supports: JPEG (EXIF, GPS, XMP, IPTC, comments, C2PA marker), PNG (text chunks, eXIf, tIME, AI params, C2PA),
   WebP, TIFF/RAW, GIF, PDF (Info dict, XMP, revisions, risky features), Office OOXML / ODF (core/app props,
   comment & tracked-change authors, hidden sheets), ZIP listings, Windows PE (compile time). */

const dec8 = (b) => new TextDecoder('utf-8').decode(b);
const decLatin = (b) => new TextDecoder('windows-1252').decode(b);
const asciiAt = (u8, off, n) => { let s = ''; for (let i = 0; i < n && off + i < u8.length; i++) s += String.fromCharCode(u8[off + i]); return s; };
function indexOfBytes(u8, needle, from = 0, to = u8.length) {
  const n = typeof needle === 'string' ? [...needle].map((c) => c.charCodeAt(0)) : needle;
  outer: for (let i = from; i <= to - n.length; i++) { for (let j = 0; j < n.length; j++) if (u8[i + j] !== n[j]) continue outer; return i; }
  return -1;
}
async function inflate(bytes, format = 'deflate') {
  if (typeof DecompressionStream === 'undefined') throw new Error('DecompressionStream unsupported');
  const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream(format));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

function sniff(u8) {
  const a = (o, n) => asciiAt(u8, o, n);
  if (u8[0] === 0xff && u8[1] === 0xd8 && u8[2] === 0xff) return { id: 'jpeg', kind: 'JPEG image', exts: ['jpg', 'jpeg', 'jpe', 'jfif'] };
  if (a(0, 8) === '\x89PNG\r\n\x1a\n') return { id: 'png', kind: 'PNG image', exts: ['png'] };
  if (a(0, 4) === 'GIF8') return { id: 'gif', kind: 'GIF image', exts: ['gif'] };
  if (a(0, 4) === 'RIFF' && a(8, 4) === 'WEBP') return { id: 'webp', kind: 'WebP image', exts: ['webp'] };
  if (a(0, 4) === 'II*\0' || a(0, 4) === 'MM\0*') return { id: 'tiff', kind: 'TIFF / camera RAW', exts: ['tif', 'tiff', 'dng', 'cr2', 'nef', 'arw', 'orf', 'rw2', 'pef'] };
  if (a(0, 5) === '%PDF-') return { id: 'pdf', kind: 'PDF document', exts: ['pdf'] };
  if (a(0, 4) === 'PK\x03\x04') return { id: 'zip', kind: 'ZIP container', exts: null };
  if (a(4, 4) === 'ftyp') {
    const brand = a(8, 4);
    if (/hei[cx]|mif1|msf1|heim|heis|avif/.test(brand)) return { id: 'heic', kind: brand === 'avif' ? 'AVIF image' : 'HEIC/HEIF image', exts: ['heic', 'heif', 'avif'] };
    return { id: 'mp4', kind: `ISO media (${brand.trim()})`, exts: ['mp4', 'm4v', 'm4a', 'mov', '3gp'] };
  }
  if (a(0, 2) === 'MZ') return { id: 'pe', kind: 'Windows executable (PE)', exts: ['exe', 'dll', 'sys', 'scr', 'ocx', 'cpl', 'efi'] };
  if (a(0, 4) === '\x7fELF') return { id: 'elf', kind: 'ELF executable', exts: null };
  if (u8[0] === 0xd0 && u8[1] === 0xcf && u8[2] === 0x11 && u8[3] === 0xe0) return { id: 'ole', kind: 'OLE2 compound file (legacy Office / MSG)', exts: ['doc', 'xls', 'ppt', 'msg', 'msi', 'vsd'] };
  if (a(0, 2) === 'BM') return { id: 'bmp', kind: 'BMP image', exts: ['bmp', 'dib'] };
  if (a(0, 3) === 'ID3') return { id: 'mp3', kind: 'MP3 audio', exts: ['mp3'] };
  if (a(0, 6) === '7z\xbc\xaf\x27\x1c') return { id: '7z', kind: '7-Zip archive', exts: ['7z'] };
  if (a(0, 4) === 'Rar!') return { id: 'rar', kind: 'RAR archive', exts: ['rar'] };
  if (u8[0] === 0x1f && u8[1] === 0x8b) return { id: 'gz', kind: 'gzip archive', exts: ['gz', 'tgz'] };
  if (a(0, 5) === '{\\rtf') return { id: 'rtf', kind: 'RTF document', exts: ['rtf', 'doc'] };
  let printable = 0; const n = Math.min(u8.length, 2048);
  for (let i = 0; i < n; i++) { const c = u8[i]; if (c === 9 || c === 10 || c === 13 || (c >= 32 && c < 127) || c >= 128) printable++; }
  if (n && printable / n > 0.95) return { id: 'text', kind: 'Text', exts: null };
  return { id: 'unknown', kind: 'Unknown binary', exts: null };
}

// ---------------------------------------------------------------- TIFF / EXIF
const TIFF_TAGS = { 0x0100: 'ImageWidth', 0x0101: 'ImageHeight', 0x010e: 'ImageDescription', 0x010f: 'Make', 0x0110: 'Model', 0x0112: 'Orientation', 0x0131: 'Software', 0x0132: 'DateTime', 0x013b: 'Artist', 0x013c: 'HostComputer', 0x8298: 'Copyright', 0x8769: 'ExifIFD', 0x8825: 'GPSIFD', 0x9c9b: 'XPTitle', 0x9c9c: 'XPComment', 0x9c9d: 'XPAuthor', 0x9c9e: 'XPKeywords', 0x9c9f: 'XPSubject', 0xc614: 'UniqueCameraModel' };
const EXIF_TAGS = { 0x829a: 'ExposureTime', 0x829d: 'FNumber', 0x8827: 'ISO', 0x9003: 'DateTimeOriginal', 0x9004: 'DateTimeDigitized', 0x9010: 'OffsetTime', 0x9011: 'OffsetTimeOriginal', 0x9012: 'OffsetTimeDigitized', 0x9291: 'SubSecTimeOriginal', 0x920a: 'FocalLength', 0xa405: 'FocalLengthIn35mm', 0x9209: 'Flash', 0xa002: 'PixelXDimension', 0xa003: 'PixelYDimension', 0xa420: 'ImageUniqueID', 0xa430: 'CameraOwnerName', 0xa431: 'BodySerialNumber', 0xa433: 'LensMake', 0xa434: 'LensModel', 0xa435: 'LensSerialNumber', 0x9286: 'UserComment' };
const GPS_TAGS = { 0: 'GPSVersionID', 1: 'GPSLatitudeRef', 2: 'GPSLatitude', 3: 'GPSLongitudeRef', 4: 'GPSLongitude', 5: 'GPSAltitudeRef', 6: 'GPSAltitude', 7: 'GPSTimeStamp', 0x0c: 'GPSSpeedRef', 0x0d: 'GPSSpeed', 0x10: 'GPSImgDirectionRef', 0x11: 'GPSImgDirection', 0x12: 'GPSMapDatum', 0x1d: 'GPSDateStamp', 0x1f: 'GPSHPositioningError' };
const TIFF_SIZES = { 1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 1, 7: 1, 8: 2, 9: 4, 10: 8, 11: 4, 12: 8 };

function readTIFF(dv, start) {
  const len = dv.byteLength;
  const le = dv.getUint16(start) === 0x4949;
  const u16 = (o) => dv.getUint16(start + o, le);
  const u32 = (o) => dv.getUint32(start + o, le);
  if (u16(2) !== 42) throw new Error('Bad TIFF header');
  const bytesAt = (abs, n) => new Uint8Array(dv.buffer, dv.byteOffset + abs, n);
  const readVal = (type, count, off) => {
    const abs = start + off, sz = TIFF_SIZES[type] || 1;
    if (abs < 0 || abs + sz * count > len) return undefined;
    if (type === 2) { const b = bytesAt(abs, count); const z = b.indexOf(0); return dec8(z >= 0 ? b.subarray(0, z) : b).trim(); }
    if (type === 1 || type === 6 || type === 7) return count > 65536 ? `[${count} bytes]` : bytesAt(abs, count).slice();
    const arr = [];
    for (let i = 0; i < Math.min(count, 64); i++) {
      const o = abs + i * sz;
      if (type === 3) arr.push(dv.getUint16(o, le));
      else if (type === 4) arr.push(dv.getUint32(o, le));
      else if (type === 8) arr.push(dv.getInt16(o, le));
      else if (type === 9) arr.push(dv.getInt32(o, le));
      else if (type === 5) arr.push(dv.getUint32(o, le) / (dv.getUint32(o + 4, le) || 1));
      else if (type === 10) arr.push(dv.getInt32(o, le) / (dv.getInt32(o + 4, le) || 1));
      else if (type === 11) arr.push(dv.getFloat32(o, le));
      else if (type === 12) arr.push(dv.getFloat64(o, le));
    }
    return count === 1 ? arr[0] : arr;
  };
  const readIFD = (off, names) => {
    const tags = {};
    if (!off || start + off + 2 > len) return tags;
    const n = u16(off);
    if (n > 2000) return tags;
    for (let i = 0; i < n; i++) {
      const e = off + 2 + i * 12;
      if (start + e + 12 > len) break;
      const tag = u16(e), type = u16(e + 2), count = u32(e + 4);
      const size = (TIFF_SIZES[type] || 1) * count;
      const valOff = size > 4 ? u32(e + 8) : e + 8;
      try { const v = readVal(type, count, valOff); if (v !== undefined && names[tag]) tags[names[tag]] = v; } catch { /* skip bad tag */ }
    }
    return tags;
  };
  const ifd0 = readIFD(u32(4), TIFF_TAGS);
  const exif = ifd0.ExifIFD ? readIFD(ifd0.ExifIFD, EXIF_TAGS) : {};
  const gps = ifd0.GPSIFD ? readIFD(ifd0.GPSIFD, GPS_TAGS) : {};
  delete ifd0.ExifIFD; delete ifd0.GPSIFD;
  return { ifd0, exif, gps };
}

const ucs2 = (b) => (b instanceof Uint8Array ? new TextDecoder('utf-16le').decode(b).replace(/\0+$/, '') : String(b ?? ''));
function userComment(b) {
  if (!(b instanceof Uint8Array)) return String(b ?? '');
  const head = asciiAt(b, 0, 8), body = b.subarray(8);
  const s = head.startsWith('UNICODE') ? new TextDecoder('utf-16le').decode(body) : dec8(body);
  return s.replace(/\0+/g, '').trim();
}
const dms = (v, ref) => { if (!Array.isArray(v) || v.length < 3) return null; let d = v[0] + v[1] / 60 + v[2] / 3600; if (/[SW]/i.test(ref || '')) d = -d; return Number.isFinite(d) ? +d.toFixed(7) : null; };
const exifDate = (s, off) => { const m = String(s || '').match(/^(\d{4}):(\d\d):(\d\d) (\d\d):(\d\d):(\d\d)/); return m ? `${m[1]}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6]}${off || ''}` : null; };
const ORIENT = { 1: 'Normal', 2: 'Mirrored', 3: 'Rotated 180°', 4: 'Mirrored vertical', 5: 'Mirrored + 90° CCW', 6: 'Rotated 90° CW', 7: 'Mirrored + 90° CW', 8: 'Rotated 90° CCW' };
const EDITORS = /photoshop|lightroom|gimp|affinity|snapseed|picsart|facetune|pixelmator|canva|paint\.net|capture one|darktable|luminar|vsco|meitu|faceapp|midjourney|dall|stable diffusion|firefly|imagen|chatgpt/i;

function addField(res, group, key, value) {
  if (value === undefined || value === null || value === '' || (Array.isArray(value) && !value.length)) return;
  if (value instanceof Uint8Array) value = `[${value.length} bytes]`;
  if (Array.isArray(value)) value = value.map((x) => (typeof x === 'number' ? +x.toFixed(4) : x)).join(', ');
  if (typeof value === 'number') value = +value.toFixed(6);
  value = String(value);
  if (value.length > 4000) value = value.slice(0, 4000) + '… [truncated]';
  res.fields.push({ group, key, value });
}
function addDate(res, label, iso, note = '') { if (iso) res.dates.push({ label, iso, note }); }
function flag(res, level, text) { if (!res.flags.some((f) => f.text === text)) res.flags.push({ level, text }); }

function applyTIFF(res, t) {
  const { ifd0: a, exif: e, gps: g } = t;
  addField(res, 'Device', 'Make', a.Make); addField(res, 'Device', 'Model', a.Model);
  addField(res, 'Device', 'Lens', [e.LensMake, e.LensModel].filter(Boolean).join(' '));
  addField(res, 'Device', 'Body serial number', e.BodySerialNumber); addField(res, 'Device', 'Lens serial number', e.LensSerialNumber);
  addField(res, 'Device', 'Camera owner', e.CameraOwnerName); addField(res, 'Device', 'Host computer', a.HostComputer);
  if (e.BodySerialNumber || e.LensSerialNumber) flag(res, 'warn', 'Device serial number present — can link this photo to others from the same camera.');
  if (e.CameraOwnerName) flag(res, 'warn', 'Camera owner name embedded.');
  const dto = exifDate(e.DateTimeOriginal, e.OffsetTimeOriginal), dtd = exifDate(e.DateTimeDigitized, e.OffsetTimeDigitized), dtm = exifDate(a.DateTime, e.OffsetTime);
  addField(res, 'Dates', 'Captured (DateTimeOriginal)', e.DateTimeOriginal ? `${e.DateTimeOriginal}${e.OffsetTimeOriginal ? ' ' + e.OffsetTimeOriginal : ' (camera local time, zone unknown)'}` : '');
  addField(res, 'Dates', 'Digitized', e.DateTimeDigitized); addField(res, 'Dates', 'Modified (DateTime)', a.DateTime);
  addDate(res, 'Photo captured', dto, e.OffsetTimeOriginal ? '' : 'camera local time'); addDate(res, 'Photo file modified', dtm, e.OffsetTime ? '' : 'camera local time');
  if (e.DateTimeOriginal && a.DateTime && e.DateTimeOriginal !== a.DateTime) flag(res, 'info', 'Modified timestamp differs from capture timestamp — the file was likely re-saved or edited.');
  void dtd;
  addField(res, 'Capture', 'Exposure', e.ExposureTime ? (e.ExposureTime < 1 ? `1/${Math.round(1 / e.ExposureTime)} s` : `${e.ExposureTime} s`) : '');
  addField(res, 'Capture', 'Aperture', e.FNumber ? `f/${(+e.FNumber).toFixed(1)}` : ''); addField(res, 'Capture', 'ISO', e.ISO);
  addField(res, 'Capture', 'Focal length', e.FocalLength ? `${(+e.FocalLength).toFixed(1)} mm${e.FocalLengthIn35mm ? ` (${e.FocalLengthIn35mm} mm equiv.)` : ''}` : '');
  addField(res, 'Capture', 'Flash fired', e.Flash !== undefined ? ((e.Flash & 1) ? 'Yes' : 'No') : '');
  addField(res, 'Image', 'Orientation', ORIENT[a.Orientation]);
  if (e.PixelXDimension) addField(res, 'Image', 'EXIF dimensions', `${e.PixelXDimension} × ${e.PixelYDimension}`);
  addField(res, 'Image', 'Unique image ID', e.ImageUniqueID);
  addField(res, 'Authoring', 'Software', a.Software); addField(res, 'Authoring', 'Artist', a.Artist); addField(res, 'Authoring', 'Copyright', a.Copyright);
  addField(res, 'Authoring', 'Description', a.ImageDescription); addField(res, 'Authoring', 'Windows author', ucs2(a.XPAuthor));
  addField(res, 'Authoring', 'Windows title', ucs2(a.XPTitle)); addField(res, 'Authoring', 'Windows comment', ucs2(a.XPComment));
  addField(res, 'Authoring', 'Windows keywords', ucs2(a.XPKeywords)); addField(res, 'Authoring', 'Windows subject', ucs2(a.XPSubject));
  addField(res, 'Authoring', 'User comment', userComment(e.UserComment));
  if (a.Software && EDITORS.test(a.Software)) flag(res, 'warn', `Processed with editing/generation software: ${a.Software}`);
  if (a.Artist || ucs2(a.XPAuthor)) flag(res, 'warn', 'Author name embedded in file.');

  const lat = dms(g.GPSLatitude, g.GPSLatitudeRef), lon = dms(g.GPSLongitude, g.GPSLongitudeRef);
  if (lat !== null && lon !== null && !(lat === 0 && lon === 0)) {
    let alt = typeof g.GPSAltitude === 'number' ? g.GPSAltitude : null;
    const ar = g.GPSAltitudeRef instanceof Uint8Array ? g.GPSAltitudeRef[0] : g.GPSAltitudeRef;
    if (alt !== null && ar === 1) alt = -alt;
    let utc = null;
    if (g.GPSDateStamp && Array.isArray(g.GPSTimeStamp)) {
      const [h, m, s] = g.GPSTimeStamp; const d = String(g.GPSDateStamp).replace(/:/g, '-');
      utc = `${d}T${String(Math.floor(h)).padStart(2, '0')}:${String(Math.floor(m)).padStart(2, '0')}:${String(Math.floor(s)).padStart(2, '0')}Z`;
    }
    res.gps = { lat, lon, alt, dir: typeof g.GPSImgDirection === 'number' ? g.GPSImgDirection : null, dirRef: g.GPSImgDirectionRef, utc, err: g.GPSHPositioningError };
    addField(res, 'GPS', 'Coordinates', `${lat}, ${lon}`);
    addField(res, 'GPS', 'Altitude', alt !== null ? `${alt.toFixed(1)} m` : '');
    addField(res, 'GPS', 'Camera heading', res.gps.dir !== null ? `${res.gps.dir.toFixed(1)}° ${g.GPSImgDirectionRef === 'M' ? 'magnetic' : 'true'}` : '');
    addField(res, 'GPS', 'Horizontal error', g.GPSHPositioningError ? `${(+g.GPSHPositioningError).toFixed(1)} m` : '');
    addField(res, 'GPS', 'GPS time (UTC)', utc);
    addField(res, 'GPS', 'Map datum', g.GPSMapDatum);
    addDate(res, 'GPS fix (UTC)', utc);
    flag(res, 'crit', 'GPS coordinates embedded — this file reveals where it was taken.');
  }
}

function parseJPEG(dv, u8, res) {
  let off = 2; const len = dv.byteLength;
  while (off + 4 <= len) {
    if (u8[off] !== 0xff) { off++; continue; }
    const marker = u8[off + 1];
    if (marker === 0xff) { off++; continue; }
    if (marker === 0xd8 || marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) { off += 2; continue; }
    if (marker === 0xd9 || marker === 0xda) break;
    const size = dv.getUint16(off + 2), s = off + 4, e = Math.min(len, off + 2 + size);
    if (marker === 0xe1) {
      if (asciiAt(u8, s, 6) === 'Exif\0\0') { try { applyTIFF(res, readTIFF(dv, s + 6)); } catch (err) { flag(res, 'info', 'EXIF block present but unreadable: ' + err.message); } }
      else if (asciiAt(u8, s, 29) === 'http://ns.adobe.com/xap/1.0/\0') res.xmp = dec8(u8.subarray(s + 29, e));
    } else if (marker === 0xfe) addField(res, 'Authoring', 'JPEG comment', dec8(u8.subarray(s, e)).replace(/\0+$/, ''));
    else if (marker === 0xeb) { if (indexOfBytes(u8, 'c2pa', s, e) >= 0 || indexOfBytes(u8, 'jumb', s, e) >= 0) res.c2pa = true; }
    else if (marker === 0xed && asciiAt(u8, s, 13) === 'Photoshop 3.0') parseIPTC(u8, s, e, res);
    else if (marker === 0xe0 && asciiAt(u8, s, 5) === 'JFIF\0') addField(res, 'Image', 'JFIF version', `${u8[s + 5]}.${String(u8[s + 6]).padStart(2, '0')}`);
    else if (marker === 0xe2 && asciiAt(u8, s, 4) === 'MPF\0') addField(res, 'Image', 'Multi-picture (MPF)', 'Yes — may contain extra embedded images');
    else if (marker >= 0xc0 && marker <= 0xcf && ![0xc4, 0xc8, 0xcc].includes(marker)) {
      res.height = dv.getUint16(off + 5); res.width = dv.getUint16(off + 7);
      addField(res, 'Image', 'Encoding', marker === 0xc2 ? 'Progressive' : 'Baseline');
    }
    off = off + 2 + size;
  }
}
function parseIPTC(u8, s, e, res) {
  const NAMES = { 5: 'Object name', 25: 'Keywords', 55: 'Date created', 60: 'Time created', 80: 'By-line (creator)', 85: 'By-line title', 90: 'City', 92: 'Sub-location', 95: 'Province/State', 101: 'Country', 103: 'Transmission ref', 105: 'Headline', 110: 'Credit', 115: 'Source', 116: 'Copyright', 120: 'Caption', 122: 'Caption writer' };
  const vals = {};
  for (let i = s; i < e - 5; i++) {
    if (u8[i] !== 0x1c || u8[i + 1] !== 0x02) continue;
    const tag = u8[i + 2], n = (u8[i + 3] << 8) | u8[i + 4];
    if (n > 0x7fff || i + 5 + n > e) continue;
    if (NAMES[tag]) (vals[NAMES[tag]] = vals[NAMES[tag]] || []).push(dec8(u8.subarray(i + 5, i + 5 + n)));
    i += 4 + n;
  }
  for (const [k, v] of Object.entries(vals)) addField(res, 'IPTC', k, [...new Set(v)].join('; '));
  if (vals['City'] || vals['Country']) flag(res, 'info', 'IPTC location fields present.');
}

async function parsePNG(dv, u8, res) {
  let off = 8; const len = dv.byteLength;
  while (off + 12 <= len) {
    const clen = dv.getUint32(off), type = asciiAt(u8, off + 4, 4), d = off + 8, end = d + clen;
    if (end > len) break;
    try {
      if (type === 'IHDR') { res.width = dv.getUint32(d); res.height = dv.getUint32(d + 4); }
      else if (type === 'tEXt' || type === 'zTXt' || type === 'iTXt') {
        const z = u8.indexOf(0, d); const kw = decLatin(u8.subarray(d, z)); let text = '';
        if (type === 'tEXt') text = decLatin(u8.subarray(z + 1, end));
        else if (type === 'zTXt') text = decLatin(await inflate(u8.subarray(z + 2, end)));
        else {
          const compressed = u8[z + 1]; const langEnd = u8.indexOf(0, z + 3); const tkEnd = u8.indexOf(0, langEnd + 1);
          const raw = u8.subarray(tkEnd + 1, end); text = dec8(compressed ? await inflate(raw) : raw);
        }
        if (kw === 'XML:com.adobe.xmp') res.xmp = text;
        else {
          addField(res, 'PNG text', kw, text);
          if (/^(parameters|prompt|workflow|Dream|sd-metadata|invokeai_metadata|generation_data)$/i.test(kw)) flag(res, 'warn', `AI image-generation parameters present (“${kw}” chunk).`);
        }
      } else if (type === 'eXIf') applyTIFF(res, readTIFF(dv, d));
      else if (type === 'tIME') {
        const p = (n) => String(n).padStart(2, '0');
        const iso = `${dv.getUint16(d)}-${p(u8[d + 2])}-${p(u8[d + 3])}T${p(u8[d + 4])}:${p(u8[d + 5])}:${p(u8[d + 6])}Z`;
        addField(res, 'Dates', 'Last modified (PNG tIME)', iso); addDate(res, 'PNG last modified', iso);
      } else if (type === 'pHYs') { const ppu = dv.getUint32(d); if (u8[d + 8] === 1) addField(res, 'Image', 'Resolution', `${Math.round(ppu * 0.0254)} DPI`); }
      else if (type === 'caBX') res.c2pa = true;
      else if (type === 'IEND') break;
    } catch (err) { flag(res, 'info', `Could not read ${type} chunk: ${err.message}`); }
    off = end + 4;
  }
}

function parseWebP(dv, u8, res) {
  let off = 12; const len = dv.byteLength;
  while (off + 8 <= len) {
    const type = asciiAt(u8, off, 4), size = dv.getUint32(off + 4, true), d = off + 8;
    if (d + size > len) break;
    if (type === 'VP8X') { res.width = 1 + (u8[d + 4] | (u8[d + 5] << 8) | (u8[d + 6] << 16)); res.height = 1 + (u8[d + 7] | (u8[d + 8] << 8) | (u8[d + 9] << 16)); }
    else if (type === 'VP8 ' && !res.width) { res.width = dv.getUint16(d + 6, true) & 0x3fff; res.height = dv.getUint16(d + 8, true) & 0x3fff; }
    else if (type === 'EXIF') { const st = asciiAt(u8, d, 6) === 'Exif\0\0' ? d + 6 : d; try { applyTIFF(res, readTIFF(dv, st)); } catch { /* ignore */ } }
    else if (type === 'XMP ') res.xmp = dec8(u8.subarray(d, d + size));
    else if (type === 'C2PA') res.c2pa = true;
    off = d + size + (size & 1);
  }
}

// ---------------------------------------------------------------- PDF
function pdfString(tok) {
  if (!tok) return '';
  if (tok[0] === '<') {
    const b = fromHex(tok.slice(1, -1));
    return b[0] === 0xfe && b[1] === 0xff ? new TextDecoder('utf-16be').decode(b.subarray(2)) : decLatin(b);
  }
  // Per the PDF spec, a backslash before any other character is ignored; a backslash-newline is a line continuation.
  let s = tok.slice(1, -1).replace(/\\([nrtbf()\\]|[0-7]{1,3}|\r?\n|[\s\S])/g, (m, c) => ({ n: '\n', r: '\r', t: '\t', b: '\b', f: '\f', '(': '(', ')': ')', '\\': '\\' }[c] ?? (/^[0-7]+$/.test(c) ? String.fromCharCode(parseInt(c, 8)) : /^\r?\n$/.test(c) ? '' : c)));
  if (s.charCodeAt(0) === 0xfe && s.charCodeAt(1) === 0xff) { const b = new Uint8Array([...s.slice(2)].map((c) => c.charCodeAt(0) & 255)); s = new TextDecoder('utf-16be').decode(b); }
  return s.replace(/\0/g, '');
}
function pdfDate(s) {
  const m = String(s).match(/D:(\d{4})(\d\d)?(\d\d)?(\d\d)?(\d\d)?(\d\d)?([Zz+-])?(\d\d)?'?(\d\d)?/);
  if (!m) return null;
  const [, y, mo = '01', d = '01', h = '00', mi = '00', se = '00', z, oh, om] = m;
  const off = !z || z === 'Z' || z === 'z' ? (z ? 'Z' : '') : `${z}${oh || '00'}:${om || '00'}`;
  return `${y}-${mo}-${d}T${h}:${mi}:${se}${off}`;
}
function parsePDF(u8, res) {
  const MAX = 64 * 1024 * 1024;
  const s = u8.length > MAX ? decLatin(u8.subarray(0, 8e6)) + decLatin(u8.subarray(u8.length - 8e6)) : decLatin(u8);
  res._text = s;
  const v = s.slice(0, 20).match(/%PDF-(\d\.\d)/); if (v) addField(res, 'Document', 'PDF version', v[1]);
  const KEYS = ['Title', 'Author', 'Subject', 'Keywords', 'Creator', 'Producer', 'CreationDate', 'ModDate'];
  for (const k of KEYS) {
    const rx = new RegExp(`/${k}\\s*(\\((?:\\\\[\\s\\S]|[^\\\\)])*\\)|<[0-9A-Fa-f\\s]*>)`, 'g');
    let m, last = null; while ((m = rx.exec(s))) last = m[1];
    if (!last) continue;
    const val = pdfString(last).trim();
    if (k === 'CreationDate' || k === 'ModDate') {
      const iso = pdfDate(val); addField(res, 'Dates', k === 'CreationDate' ? 'Created' : 'Modified', iso || val);
      addDate(res, k === 'CreationDate' ? 'PDF created' : 'PDF modified', iso);
    } else addField(res, 'Document', k === 'Creator' ? 'Creator (authoring app)' : k === 'Producer' ? 'Producer (PDF engine)' : k, val);
    if (k === 'Author' && val) flag(res, 'warn', `Author embedded: “${trunc(val, 60)}”`);
  }
  const pages = (s.match(/\/Type\s*\/Page(?![s\w])/g) || []).length; if (pages) addField(res, 'Document', 'Pages (approx.)', pages);
  const eofs = (s.match(/%%EOF/g) || []).length;
  if (eofs > 1) { addField(res, 'Document', 'Revisions (incremental saves)', eofs); flag(res, 'info', `File was saved ${eofs} times incrementally — earlier revisions may still be recoverable.`); }
  if (/\/Encrypt\b/.test(s)) flag(res, 'info', 'Document is encrypted / permission-protected.');
  if (/\/(JavaScript|JS)\b/.test(s)) flag(res, 'crit', 'Contains JavaScript — treat as potentially malicious; open only in a sandbox.');
  if (/\/Launch\b/.test(s)) flag(res, 'crit', 'Contains a /Launch action (can execute programs).');
  if (/\/EmbeddedFile\b/.test(s)) flag(res, 'warn', 'Contains embedded file attachments.');
  if (/\/OpenAction\b/.test(s)) flag(res, 'info', 'Has an OpenAction (runs something on open).');
  if (/\/URI\s*\(/.test(s)) addField(res, 'Document', 'External links', (s.match(/\/URI\s*\(/g) || []).length);
}

// ---------------------------------------------------------------- ZIP / OOXML / ODF
async function parseZIP(dv, u8, res) {
  const len = dv.byteLength;
  let eocd = -1;
  for (let i = len - 22; i >= Math.max(0, len - 65557); i--) if (dv.getUint32(i, true) === 0x06054b50) { eocd = i; break; }
  if (eocd < 0) throw new Error('ZIP end-of-directory not found');
  const count = dv.getUint16(eocd + 10, true); let p = dv.getUint32(eocd + 16, true);
  const entries = [];
  for (let i = 0; i < count && p + 46 <= len; i++) {
    if (dv.getUint32(p, true) !== 0x02014b50) break;
    const nlen = dv.getUint16(p + 28, true), elen = dv.getUint16(p + 30, true), clen = dv.getUint16(p + 32, true);
    entries.push({ name: dec8(u8.subarray(p + 46, p + 46 + nlen)), method: dv.getUint16(p + 10, true), csize: dv.getUint32(p + 20, true), usize: dv.getUint32(p + 24, true), lho: dv.getUint32(p + 42, true), time: dv.getUint16(p + 12, true), date: dv.getUint16(p + 14, true) });
    p += 46 + nlen + elen + clen;
  }
  const names = new Set(entries.map((e) => e.name));
  const read = async (name, maxBytes = 25e6) => {
    const e = entries.find((x) => x.name === name);
    if (!e || e.usize > maxBytes || dv.getUint32(e.lho, true) !== 0x04034b50) return null;
    const n = dv.getUint16(e.lho + 26, true), x = dv.getUint16(e.lho + 28, true);
    const data = u8.subarray(e.lho + 30 + n + x, e.lho + 30 + n + x + e.csize);
    if (e.method === 0) return dec8(data);
    if (e.method === 8) return dec8(await inflate(data, 'deflate-raw'));
    return null;
  };
  const xml = (txt) => (txt ? new DOMParser().parseFromString(txt, 'application/xml') : null);
  const tag = (doc, local) => doc?.getElementsByTagNameNS('*', local)[0]?.textContent?.trim() || '';

  let kind = 'ZIP archive';
  const mimetype = names.has('mimetype') ? (await read('mimetype')) || '' : '';
  if ([...names].some((n) => n.startsWith('word/'))) kind = 'Word document (DOCX)';
  else if ([...names].some((n) => n.startsWith('xl/'))) kind = 'Excel workbook (XLSX)';
  else if ([...names].some((n) => n.startsWith('ppt/'))) kind = 'PowerPoint deck (PPTX)';
  else if (mimetype.includes('opendocument')) kind = `OpenDocument (${mimetype.split('.').pop()})`;
  else if (names.has('AndroidManifest.xml')) kind = 'Android package (APK)';
  else if (names.has('META-INF/MANIFEST.MF')) kind = 'Java archive (JAR)';
  res.kind = kind;
  res.extOk = { 'Word document (DOCX)': ['docx', 'docm', 'dotx'], 'Excel workbook (XLSX)': ['xlsx', 'xlsm', 'xltx'], 'PowerPoint deck (PPTX)': ['pptx', 'pptm', 'potx'], 'Android package (APK)': ['apk'], 'Java archive (JAR)': ['jar', 'war'] }[kind] || null;

  const core = xml(await read('docProps/core.xml'));
  if (core) {
    for (const [local, label] of [['title', 'Title'], ['subject', 'Subject'], ['creator', 'Author (creator)'], ['lastModifiedBy', 'Last modified by'], ['keywords', 'Keywords'], ['description', 'Description'], ['category', 'Category'], ['revision', 'Revision']]) addField(res, 'Document', label, tag(core, local));
    for (const [local, label] of [['created', 'Created'], ['modified', 'Modified'], ['lastPrinted', 'Last printed']]) { const v = tag(core, local); addField(res, 'Dates', label, v); addDate(res, `Document ${label.toLowerCase()}`, v); }
    const who = [tag(core, 'creator'), tag(core, 'lastModifiedBy')].filter(Boolean);
    if (who.length) flag(res, 'warn', `Author/editor names embedded: ${[...new Set(who)].join(', ')}`);
  }
  const app = xml(await read('docProps/app.xml'));
  if (app) {
    for (const [local, label] of [['Application', 'Application'], ['AppVersion', 'App version'], ['Company', 'Company'], ['Manager', 'Manager'], ['Template', 'Template'], ['TotalTime', 'Total editing time (min)'], ['Pages', 'Pages'], ['Words', 'Words'], ['Slides', 'Slides']]) addField(res, 'Document', label, tag(app, local));
    if (tag(app, 'Company')) flag(res, 'info', `Organization embedded: “${tag(app, 'Company')}”`);
  }
  const custom = xml(await read('docProps/custom.xml'));
  if (custom) for (const p of custom.getElementsByTagNameNS('*', 'property')) addField(res, 'Custom properties', p.getAttribute('name'), p.textContent.trim());
  const meta = xml(await read('meta.xml'));
  if (meta) {
    for (const [local, label] of [['generator', 'Generator'], ['initial-creator', 'Initial creator'], ['creator', 'Last editor'], ['title', 'Title'], ['editing-cycles', 'Editing cycles'], ['editing-duration', 'Editing duration']]) addField(res, 'Document', label, tag(meta, local));
    for (const [local, label] of [['creation-date', 'Created'], ['date', 'Modified']]) { const v = tag(meta, local); addField(res, 'Dates', label, v); addDate(res, `Document ${label.toLowerCase()}`, v); }
  }
  // People who commented or tracked changes (Word)
  const authors = new Set();
  for (const part of ['word/comments.xml', 'word/document.xml', 'word/people.xml']) {
    const t = await read(part); if (!t) continue;
    for (const m of t.matchAll(/w(?:15)?:author="([^"]+)"/g)) authors.add(m[1]);
  }
  if (authors.size) { addField(res, 'Document', 'Comment / tracked-change authors', [...authors].join('; ')); flag(res, 'warn', `Reviewer names found in comments/tracked changes: ${[...authors].slice(0, 5).join(', ')}`); }
  if (names.has('word/comments.xml')) flag(res, 'info', 'Contains reviewer comments.');
  const wb = await read('xl/workbook.xml');
  if (wb) {
    const sheets = [...wb.matchAll(/<sheet\b[^>]*>/g)].map((m) => ({ name: (m[0].match(/name="([^"]*)"/) || [])[1], state: (m[0].match(/state="([^"]*)"/) || [])[1] }));
    addField(res, 'Document', 'Sheets', sheets.map((s) => s.name + (s.state ? ` (${s.state})` : '')).join(', '));
    const hidden = sheets.filter((s) => s.state); if (hidden.length) flag(res, 'warn', `${hidden.length} hidden sheet(s): ${hidden.map((s) => s.name).join(', ')}`);
  }
  if ([...names].some((n) => /vbaProject\.bin$/i.test(n))) flag(res, 'crit', 'Contains VBA macros — treat as potentially malicious.');
  const media = entries.filter((e) => /\/media\//.test(e.name));
  if (media.length) addField(res, 'Container', 'Embedded media files', `${media.length} (each may carry its own EXIF — unzip and analyze them)`);
  addField(res, 'Container', 'Entries', entries.length);
  const stamps = entries.map((e) => { const d = e.date, t = e.time; const y = 1980 + (d >> 9); if (y <= 1980) return null; return `${y}-${String((d >> 5) & 15).padStart(2, '0')}-${String(d & 31).padStart(2, '0')}T${String(t >> 11).padStart(2, '0')}:${String((t >> 5) & 63).padStart(2, '0')}:${String((t & 31) * 2).padStart(2, '0')}`; }).filter(Boolean).sort();
  if (stamps.length) { addField(res, 'Container', 'Entry timestamps (local)', `${stamps[0]} → ${stamps[stamps.length - 1]}`); }
  if (kind === 'ZIP archive') addField(res, 'Container', 'Files', entries.slice(0, 60).map((e) => e.name).join('\n') + (entries.length > 60 ? `\n… +${entries.length - 60} more` : ''));
}

// ---------------------------------------------------------------- PE (Windows executables)
function parsePE(dv, res) {
  const pe = dv.getUint32(0x3c, true);
  if (pe + 24 > dv.byteLength || dv.getUint32(pe, true) !== 0x00004550) return;
  const MACH = { 0x14c: 'x86 (i386)', 0x8664: 'x64 (AMD64)', 0x1c0: 'ARM', 0xaa64: 'ARM64', 0x200: 'IA-64' };
  const machine = dv.getUint16(pe + 4, true), nsec = dv.getUint16(pe + 6, true), ts = dv.getUint32(pe + 8, true), ch = dv.getUint16(pe + 22, true);
  addField(res, 'Executable', 'Machine', MACH[machine] || '0x' + machine.toString(16));
  addField(res, 'Executable', 'Sections', nsec);
  addField(res, 'Executable', 'Type', ch & 0x2000 ? 'DLL' : 'Executable');
  const iso = new Date(ts * 1000).toISOString();
  addField(res, 'Dates', 'Compile timestamp (COFF)', `${iso}${ts > Date.now() / 1000 || ts < 631152000 ? '  (implausible — possibly forged or a reproducible-build hash)' : ''}`);
  if (ts > 631152000 && ts < Date.now() / 1000) addDate(res, 'PE compiled', iso);
  flag(res, 'crit', 'Executable file — do not run it outside an isolated analysis VM.');
}

// ---------------------------------------------------------------- XMP
function findXMP(u8, text) {
  const s = text || decLatin(u8.subarray(0, Math.min(u8.length, 4e6)));
  const a = s.indexOf('<x:xmpmeta'); if (a < 0) return null;
  const b = s.indexOf('</x:xmpmeta>', a); if (b < 0) return null;
  try { return dec8(new Uint8Array([...s.slice(a, b + 12)].map((c) => c.charCodeAt(0) & 255))); } catch { return s.slice(a, b + 12); }
}
function xmpGet(x, key) {
  const k = key.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  let m = x.match(new RegExp(`${k}="([^"]*)"`)); if (m) return m[1];
  m = x.match(new RegExp(`<${k}>\\s*<rdf:(?:Seq|Bag|Alt)>([\\s\\S]*?)</rdf:(?:Seq|Bag|Alt)>`));
  if (m) return [...m[1].matchAll(/<rdf:li[^>]*>([\s\S]*?)<\/rdf:li>/g)].map((x) => x[1].trim()).join('; ');
  m = x.match(new RegExp(`<${k}>([^<]*)</${k}>`)); return m ? m[1].trim() : '';
}
function applyXMP(res) {
  const x = res.xmp; if (!x) return;
  const F = [['xmp:CreatorTool', 'Creator tool'], ['dc:creator', 'Creator'], ['dc:rights', 'Rights'], ['dc:title', 'Title'], ['dc:description', 'Description'], ['photoshop:AuthorsPosition', 'Author position'], ['photoshop:City', 'City'], ['photoshop:State', 'State'], ['photoshop:Country', 'Country'], ['Iptc4xmpCore:Location', 'Location'], ['photoshop:Credit', 'Credit'], ['photoshop:Source', 'Source'], ['aux:SerialNumber', 'Camera serial'], ['exifEX:BodySerialNumber', 'Camera serial'], ['aux:Lens', 'Lens'], ['pdf:Producer', 'PDF producer'], ['xmpMM:DocumentID', 'Document ID'], ['xmpMM:OriginalDocumentID', 'Original document ID'], ['xmpMM:InstanceID', 'Instance ID'], ['Iptc4xmpExt:DigitalSourceType', 'Digital source type']];
  for (const [k, label] of F) addField(res, 'XMP', label, xmpGet(x, k));
  for (const [k, label] of [['xmp:CreateDate', 'XMP created'], ['xmp:ModifyDate', 'XMP modified'], ['photoshop:DateCreated', 'Photoshop date created']]) { const v = xmpGet(x, k); addField(res, 'XMP', label, v); addDate(res, label, v); }
  const hist = (x.match(/stEvt:action="?(\w+)/g) || []).length; if (hist) addField(res, 'XMP', 'Edit history events', hist);
  const sw = [...new Set([...x.matchAll(/stEvt:softwareAgent="([^"]+)"/g)].map((m) => m[1]))]; if (sw.length) addField(res, 'XMP', 'Edit history software', sw.join('; '));
  if (/trainedAlgorithmicMedia|compositeWithTrainedAlgorithmicMedia/i.test(x)) flag(res, 'warn', 'XMP marks this file as AI-generated (IPTC DigitalSourceType).');
  if (hist) flag(res, 'info', `XMP edit history has ${hist} event(s) — the file was processed in an editor.`);
  if (/c2pa/i.test(x)) res.c2pa = true;
}

/** Analyze a File. Returns { name, size, kind, width, height, fields[], dates[], flags[], gps, xmp, c2pa, hashes }. */
async function analyzeFile(file) {
  const buf = await readFileAs(file, 'buffer');
  const u8 = new Uint8Array(buf), dv = new DataView(buf);
  const res = { name: file.name, size: file.size, type: file.type, lastModified: file.lastModified ? new Date(file.lastModified).toISOString() : '', kind: 'Unknown', fields: [], dates: [], flags: [], gps: null, xmp: null, c2pa: false, hashes: null };
  res.hashes = await hashBuffer(buf);
  const sig = sniff(u8);
  res.kind = sig.kind;
  try {
    if (sig.id === 'jpeg') parseJPEG(dv, u8, res);
    else if (sig.id === 'png') await parsePNG(dv, u8, res);
    else if (sig.id === 'webp') parseWebP(dv, u8, res);
    else if (sig.id === 'gif') { res.width = dv.getUint16(6, true); res.height = dv.getUint16(8, true); }
    else if (sig.id === 'tiff') applyTIFF(res, readTIFF(dv, 0));
    else if (sig.id === 'pdf') parsePDF(u8, res);
    else if (sig.id === 'zip') await parseZIP(dv, u8, res);
    else if (sig.id === 'pe') parsePE(dv, res);
    else if (sig.id === 'heic') flag(res, 'info', 'HEIC/AVIF metadata parsing is not supported in-browser — convert with a desktop tool (e.g. ExifTool) for full EXIF.');
    else if (sig.id === 'ole') flag(res, 'info', 'Legacy OLE2 Office/Outlook file — use a dedicated tool (oletools, ExifTool) for full metadata. Treat macros as hostile.');
  } catch (e) { flag(res, 'info', 'Parser stopped early: ' + e.message); }
  if (!res.xmp && sig.id !== 'zip') res.xmp = findXMP(u8, res._text);
  delete res._text;
  applyXMP(res);
  if (res.c2pa) flag(res, 'info', 'Content Credentials (C2PA) manifest present — verify provenance at contentcredentials.org/verify.');
  if (res.width) res.fields.unshift({ group: 'Image', key: 'Dimensions', value: `${res.width} × ${res.height} px` });
  const ext = (file.name.includes('.') ? file.name.split('.').pop() : '').toLowerCase();
  const okExts = res.extOk || sig.exts;
  if (ext && okExts && !okExts.includes(ext)) flag(res, 'warn', `Extension “.${ext}” does not match the detected content (${res.kind}).`);
  if (['jpeg', 'png', 'webp', 'tiff'].includes(sig.id) && !res.fields.some((f) => ['Device', 'Dates', 'GPS', 'Authoring', 'XMP', 'IPTC', 'PNG text'].includes(f.group))) flag(res, 'info', 'No embedded metadata — typical of images downloaded from social platforms, which strip EXIF on upload.');
  const order = { crit: 0, warn: 1, info: 2 };
  res.flags.sort((a, b) => order[a.level] - order[b.level]);
  return res;
}
