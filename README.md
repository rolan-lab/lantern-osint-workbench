# Lantern — OSINT Workbench

A local-first investigation workbench for open-source intelligence. It covers collecting, pivoting, analyzing,
preserving and reporting, all in one browser tab, with **no server, no dependencies, no telemetry.**

## Run it

Double-click `index.html` (Chrome, Edge, Firefox or Safari). That's it.

Prefer a localhost origin? From this folder:

```bash
python -m http.server 8777 --bind 127.0.0.1
```

Then open http://127.0.0.1:8777. Your cases live in that browser's local storage, and `file://` and
`localhost` are separate stores. Use **Settings & data → Export full backup** to move between them.

## Desktop app (Windows .exe)

`dist\Lantern.exe` is a single-file Windows app (about 12 MB, no install). It opens Lantern in its own window using
the Microsoft Edge WebView2 engine that ships with Windows 11. Copy it anywhere, such as your Desktop, and double-click it.

- **First launch:** the exe isn't code-signed, so SmartScreen may say *"Windows protected your PC"*. Click
  **More info → Run anyway**. It starts in a few seconds while it unpacks.
- **Your data** is kept in `%LOCALAPPDATA%\Lantern\WebView`, separate from any browser. To move cases between the
  desktop app and the browser version, use **Settings & data → Export full backup / Import**.
- **Pivot links** open in your normal default browser. Exports (CSV, JSON, reports, PNG) go to your Downloads folder.
- It runs a tiny file server on `127.0.0.1:47863` (loopback only, serving the app's own files) so saved data stays
  tied to one fixed address. Only one copy runs at a time.
- **Rebuild** after changing the web app: run `desktop\build.bat`. It needs Python 3.10+, and its build tools
  go in `%TEMP%\lantern-build`. `desktop\lantern_app.py` is the launcher. Running `python desktop\lantern_app.py`
  also works for development (`pip install pywebview` first), and `--debug` opens DevTools.

## What's inside

| Area | Module | What it does |
|---|---|---|
| Case | **Dashboard** | Case summary, quick-capture box, activity log, methodology progress |
| | **Entities** | Every selector with tags, notes, source and **Admiralty grading** (A–F × 1–6); bulk import, CSV export, derive & auto-link |
| | **Link graph** | Force-directed link analysis (canvas). Drag to pin, Shift-click to link, filter by category, PNG export |
| | **Timeline** | UTC chronology with partial dates, gap markers, entity links, CSV export |
| | **Evidence** | Chain of custody: MD5/SHA-1/SHA-256 of files (hashed locally, not stored), URL capture log, Wayback/archive.today, integrity **verify** |
| | **Notes / Report** | Autosaving notes; Markdown, printable HTML (→ PDF) and JSON reports with optional IOC defanging |
| Collect | **Extractor** | Paste text/HTML/logs/emails → emails, domains, URLs, IPv4/6, phones, handles, BTC (checksum-validated)/ETH, hashes, CVEs, MACs, coordinates. Refangs `hxxp`/`[.]`, pulls usernames out of profile URLs, de-selects big-platform noise |
| | **Pivot** | 240 curated public lookups across 19 selector types (domain, IP, email, username across 44 sites, phone, hash, wallets, coordinates, CVE, person, org…). Each click is logged |
| | **Dorks** | Search-operator builder plus recon templates for domains, people and organizations |
| | **Recon** *(opt-in)* | Live DNS (DoH), SPF/DMARC/MX posture, RDAP registration and domain age, certificate-transparency subdomains, IP owner/ASN/PTR, Wayback history |
| Analyze | **Metadata** | EXIF + GPS (with camera heading), camera serials, IPTC/XMP, edit history, AI-generation markers, C2PA; PDF authors, revisions, JavaScript; DOCX/XLSX authors, tracked-change reviewers, hidden sheets, macros; PE compile time; extension-mismatch detection |
| | **Toolbox** | Encoders (Base64, URL, hex, QP, ROT, HTML, unicode), **zero-width character detector**, epoch converter (Unix/FILETIME/WebKit/Cocoa/HFS+/Excel/GPS) with world clock, **ID → timestamp** (X, Discord, Instagram, LinkedIn, TikTok, Mastodon, Bluesky TIDs, UUID v1/v6/v7, ULID, ObjectId), IP/CIDR calculator, IDN/homograph inspector, **typosquat generator** with DNS existence check, hash identify, JWT decode |
| Operate | **OPSEC & method** | Per-case methodology checklist (plan → environment → collect → analyze → report) and grading reference |

## Privacy & OPSEC model

- **Passive by default.** The app itself makes zero network requests, and there are no CDNs, fonts or analytics.
- **Pivot links** open in new tabs with `noopener,noreferrer`. The site you open sees your IP and query, so use a research
  VM / VPN and research accounts when attribution matters.
- **Active lookups** (toggle in the top bar) let Recon call public APIs: Cloudflare/Google DNS-over-HTTPS, rdap.org,
  certspotter/crt.sh, ipinfo.io and archive.org. The target's own servers are never contacted.
- **Data** is stored in this browser's `localStorage` (~5 MB). Clearing site data deletes it, so export regularly.
  Files you hash or analyze are never stored or uploaded.

## Use it responsibly

Lantern is for lawful research: journalism, threat intelligence, due diligence, security assessments you're authorized
to run, fraud investigation, and checking your own exposure. Define your scope and legal basis first, collect only what you
need, don't interact with or harass subjects, and never use leaked credentials or bypass access controls.

## Project layout

```
index.html          shell
css/app.css         styles (light + dark themes)
js/core.js          utilities, dialogs, state/storage, router
js/crypto.js        MD5/SHA-1/SHA-256, Base58Check & bech32, punycode, Base64
js/detect.js        selector types, validation, extraction
js/pivots.js        pivot resource library
js/metadata.js      file metadata parsers (JPEG/PNG/WebP/TIFF/PDF/OOXML/ODF/ZIP/PE)
js/views/*.js       one file per area
js/app.js           bootstrap
desktop/            Windows launcher (pywebview), icon generator, build.bat
dist/Lantern.exe    built desktop app
```

To add a pivot source, append `[name, urlTemplate]` to the right group in `js/pivots.js`
(`{q}` = URL-encoded value, `{raw}` = as-is; add `'paste'` as a third element for sites without query URLs).
