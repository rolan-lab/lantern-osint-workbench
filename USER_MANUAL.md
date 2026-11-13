# Lantern OSINT Workbench — User Manual

Lantern is a local-first workbench for open-source investigations. It runs entirely in your browser (or the
Windows desktop app), stores everything on your own machine, and makes no network requests unless you switch
on **Active lookups**.

This manual explains how to run it, how each tool works, and how to carry an investigation from the first
selector to a finished report.

**Contents**

1. [Getting started](#1-getting-started)
2. [Core concepts](#2-core-concepts)
3. [A first investigation in ten minutes](#3-a-first-investigation-in-ten-minutes)
4. [Case tools](#4-case-tools)
5. [Collect tools](#5-collect-tools)
6. [Analyze tools](#6-analyze-tools)
7. [Operate tools](#7-operate-tools)
8. [Workflows by investigation type](#8-workflows-by-investigation-type)
9. [Privacy, OPSEC and what leaves your machine](#9-privacy-opsec-and-what-leaves-your-machine)
10. [Data, backups and moving between devices](#10-data-backups-and-moving-between-devices)
11. [Troubleshooting](#11-troubleshooting)
12. [Legal and ethical use](#12-legal-and-ethical-use)
13. [Reference](#13-reference)

---

## 1. Getting started

### Run it

| How | Steps |
|---|---|
| **Browser, simplest** | Double-click `index.html`. Works in Chrome, Edge, Firefox and Safari. |
| **Browser, localhost** | In the project folder run `python -m http.server 8777 --bind 127.0.0.1`, then open `http://127.0.0.1:8777`. |
| **Windows desktop app** | Run `dist\Lantern.exe` (build it with `desktop\build.bat`; see the README). |
| **Hosted, any device** | Publish the folder with GitHub Pages (README → *Use it on your phone, tablet and other computers*) and open the address on your phone, tablet or laptop. |

Each of these — and each device and browser — keeps its **own separate data store**. A case created under
`file://` is not visible under `localhost`, in the desktop app, or on another device using the hosted copy. Move cases between them with **Settings & data → Export full backup / Import**.

### Install it on a phone or tablet

On a hosted copy, Lantern can be installed like an app, with its own icon, and then works without a connection
(Recon and pivot links still need one).

- **iPhone / iPad:** open the address in Safari → Share → **Add to Home Screen**.
- **Android:** open it in Chrome → ⋮ → **Install app** (or *Add to Home screen*).
- **Desktop Chrome / Edge:** click the install icon in the address bar.

On small screens the sidebar is behind the **☰** button. Cases do not sync between devices: export a backup on
one and import it on the other. iOS may clear the data of a site you have not opened for several weeks unless it
is installed to the Home Screen — install it, and keep backups.

### The screen

- **Sidebar** — every tool, grouped into *Case*, *Collect*, *Analyze* and *Operate*. Numbers show how many
  entities, links, events, evidence items and hypotheses the active case holds.
- **Top bar**
  - **Case selector** and **+ Case** — switch or create investigations.
  - **Quick pivot** — paste any selector and press Enter. Press `/` anywhere to jump to it.
  - **Passive / Active lookups badge** — click to toggle live lookups (see section 9).
  - **UTC clock** — all times in Lantern are UTC.
  - **Theme button** — cycles system, dark and light.

### Keyboard

| Key | Action |
|---|---|
| `/` | Focus the Quick pivot bar |
| `Enter` | Submit the current form or dialog |
| `Esc` | Close a dialog |
| Shift-click (Link graph) | Link two nodes |

---

## 2. Core concepts

**Case.** One investigation: its entities, links, timeline, evidence, hypotheses, notes, checklist and activity
log. Start every case by writing the question you are answering and your authority to ask it.

**Selector / entity.** A unique, searchable piece of information. Lantern recognises these types:

| Family | Types |
|---|---|
| People & orgs | Person, Organization |
| Accounts & contact | Email, Username, Phone |
| Infrastructure | Domain, URL, IPv4, IPv6, MAC address, **ASN**, **Tracker ID** (Google Analytics, Tag Manager, AdSense, Ads) |
| Crypto & finance | Bitcoin, Ethereum / EVM, **Other wallet** (Litecoin, Dogecoin, TRON, Dash, Zcash, Monero), **IBAN** |
| Locations | Location (latitude, longitude) |
| Media & documents | Image, Document |
| Hashes & files | Hash (MD5, SHA-1, SHA-256, SHA-512, ssdeep, TLSH, password-hash formats) |
| Vulnerabilities | CVE |
| Other | Keyword, Other |

Types are detected automatically. Bitcoin, Litecoin, Dogecoin, TRON, Dash and Zcash addresses and IBANs are
**checksum-validated**, so a mistyped value is rejected instead of polluting the case.

**Pivot.** Using one selector to find another — an email leads to a domain, the domain to an IP, the IP to
sibling domains. Lantern's job is to make each pivot one click and to record it.

**Link.** A relationship between two entities ("resolves to", "registered by", "same owner?"). Some links are
created automatically (email → its domain, URL → its host, subdomain → parent).

**Admiralty grade.** A two-part rating on an entity: source reliability **A–F** and information credibility
**1–6**. "B2" means a usually reliable source and probably true information. Grade the source and the
information separately.

**Activity log.** Every pivot, lookup and edit is timestamped in the case log, so your research path can be
reconstructed and defended.

**Passive vs active.** In *Passive* mode Lantern itself sends nothing. Pivot links are ordinary links that open
in a new tab when you click them. *Active lookups* allow the Recon tools to call public APIs from your browser.

---

## 3. A first investigation in ten minutes

Scenario: you received a suspicious link to `login-example-secure.com`.

1. Click **+ Case**, name it, and write the scope ("Is this domain part of a phishing campaign against us?").
2. Paste the domain into **Quick pivot** and press Enter. Lantern identifies it as a domain and shows insights
   plus grouped lookup links. Click **+ Add to case**.
3. Click **Open in Recon**. If you are in Passive mode, read the notice and enable Active lookups. Recon returns
   DNS records, mail security, DNSSEC and DKIM services, registration date, certificate-transparency subdomains
   and archive history. Use the **+** buttons to add what matters; each addition is linked to the domain.
4. Click an IP's **+**, then pivot on it to see the hosting provider, exposed services and sibling domains.
5. Open **Link graph** to see the structure so far. Drag nodes to arrange them.
6. In Recon, click **Add registration date to timeline**. Add other dated facts as you find them.
7. Open **Evidence → + Log web capture** to record the page with an archive link.
8. Open **Hypotheses**, add two or three competing explanations, and rate your evidence against them.
9. Open **Report**, tick **Defang indicators**, and copy the Markdown or download the HTML.

The **Playbooks** view contains this workflow, and seven others, as tick-lists.

---

## 4. Case tools

### Dashboard
Summary counts, **Quick capture** (paste any text and send it to the Extractor), entities by category, the
activity log and your next methodology steps. **Edit case** changes the name, scope and open/closed status.

### Entities
The table of every selector in the case.

- **Add** one entity, or **bulk import** a pasted list — types are detected per line.
- **Filter** by text or type, **sort**, select several rows for bulk tagging or deletion.
- Click a row to open the **entity sheet**: details, links, timeline events and quick pivots. From there you can
  edit, link, delete or open all pivots.
- **Derive & auto-link** creates implied entities and links (for example the domain of each email).
- **CSV export** for spreadsheets and other tools.

### Link graph
A force-directed picture of entities and links.

- **Drag** a node to pin it; **Shift-click** one node then another to link them.
- **Filter** by category with the legend, search by text.
- **PNG export** for reports.

Use the graph to spot hubs (an IP that many domains share) and bridges (the one email that connects two
clusters). Hubs that are shared infrastructure — a CDN, a large mail provider — are noise, not findings.

### Timeline
A UTC chronology. Events accept partial dates (year, month or day only), a category, linked entities and a
source. Large gaps are marked. Many tools have a **→ timeline** button that pre-fills an event: Recon
(registration, first archive capture, account creation), Toolbox (decoded timestamps and IDs), Metadata
(capture times), Email headers (sent time) and Geo (shadow-derived time).

### Evidence
Chain of custody.

- **Files:** drop files to record their name, size, MD5, SHA-1 and SHA-256. The files are hashed locally and
  are **not** stored in Lantern — keep the originals yourself, read-only.
- **+ Log web capture:** log a page with capture time, a title and archive links (Wayback Machine, archive.today).
- **Verify a file:** drop a file again later to prove it has not changed.

Hash and log a file *before* you analyse it.

### Hypotheses (ACH)
Analysis of Competing Hypotheses is a structured way to avoid confirmation bias.

1. **+ Hypothesis** for every explanation that could be true. They should exclude each other. Include the one
   you doubt and a "coincidence" or "deception" hypothesis. *Insert a starter pair* gives you a template.
2. **+ Evidence** for each fact, argument or notable absence. Give it a **weight**: High for a reliable,
   directly relevant source; Low for a single unverified claim.
3. Rate each row **across** the hypotheses: would I expect to see this if the hypothesis were true?
   `++` very consistent, `+` consistent, `n/a` neutral, `−` inconsistent, `−−` very inconsistent.
4. Read the **inconsistency score**. Only inconsistent ratings count (1 or 2 points, multiplied by the row's
   weight of 0.5, 1 or 2). The lowest score is the hypothesis least contradicted by the evidence.
5. Rows flagged **Not diagnostic** are rated the same for every hypothesis. They cannot separate the
   explanations, however important they feel.

A low score means "not disproved", not "proven". How close the runner-up is tells you how confident to be.
The matrix is included in the report.

### Notes
Free-form, autosaving Markdown notes. Dorks and playbook plans can be appended here from other tools.

### Report
Builds a structured report from the case.

- Choose **sections**: Summary, Hypotheses, Entities, Relationships, Timeline, Evidence, Notes, Activity log.
- **Defang indicators** rewrites URLs, domains, emails and IPs (`hxxp`, `[.]`) so they cannot be clicked by
  accident.
- Outputs: **Copy Markdown**, **Download .md**, **Download HTML**, **Print / PDF**, **Export case JSON** (full
  hand-off) and **STIX 2.1** (a bundle of observables, identities, vulnerabilities and relationships for
  threat-intelligence platforms such as MISP and OpenCTI).

---

## 5. Collect tools

### Extractor
Paste text, HTML source, email headers, logs or a threat report — or drop a file. Lantern pulls out every
selector, removes duplicates and validates them.

- **Refang** converts `hxxp://`, `[.]` and `[at]` back before extracting.
- **Usernames from profile URLs** turns profile links on more than 20 platforms into username entities.
- Very common platform domains (google.com and similar) are found but not pre-selected.
- Add the selection to the case with a **source**, **tags** and an optional link to an existing entity.
- **Copy**, **Copy defanged** or **CSV** export the list without adding it.

Tip: view the source of a web page (from an archive copy, not the live site) and paste the HTML. Tracker IDs
such as `UA-…`, `G-…`, `GTM-…` and `pub-…` are extracted — sites that share one are usually run by the same
account holder.

### Pivot
One selector in, every useful public lookup out — about 330 curated sources across 23 selector types.

- **Insights** are computed offline: phone country, hash algorithm, IP class, IDN homograph warnings, wallet
  chain, IBAN country and checksum, tracking parameters in URLs, and more.
- **Pivot further** suggests related selectors (an email's domain and local part).
- **Open in Recon / Geo / Dorks** hands the selector to the matching tool.
- Links marked **⧉** belong to sites with no search URL: the value is copied and the site opens for you to paste.
- **Open all** opens a whole group (allow pop-ups for the page).

Nothing is sent until you click, and each click is logged. The site you open sees your IP address and query.

### Dorks
A search-operator builder and a library of templates.

- **Builder:** exact phrase, all / any / none of the words, `site:`, `filetype:`, `intitle:`, `inurl:`,
  `intext:` and date limits. Open the query in Google, Bing, DuckDuckGo, Yandex or Brave, copy it, or save it
  to the case notes.
- **Templates:** enter a target and choose from *Domain footprint*, *Person / handle*, *Organization*,
  *Exposure of your own domain*, *Email address / phone* and *Location / event*.

The exposure templates are meant for assets you own or are authorised to assess. Finding an exposed file does
not authorise you to download or use it.

### Recon (opt-in, live)
Recon queries public APIs — never the target's own servers. It needs **Active lookups**. Enter a selector; the
type is detected, or choose it from the list.

| Selector | What you get | Sources |
|---|---|---|
| **Domain** | A, AAAA, CNAME, MX, NS, TXT, SOA, CAA records; SPF and DMARC posture; mail provider; SaaS verification records; DNSSEC; MTA-STS, TLS-RPT, BIMI; DKIM selectors that reveal the sending platforms; SPF third parties; wildcard DNS; registrar, registration date and domain age; certificate-transparency subdomains; first and last web-archive capture | DNS-over-HTTPS, rdap.org, certspotter / crt.sh, archive.org |
| **IP address** | Hostname, organisation, approximate location; reverse DNS; network owner; open ports, software and inferred CVEs; announced prefix, origin AS and abuse contact | ipinfo.io, rdap.org, Shodan InternetDB, RIPEstat |
| **ASN** | Holder, announced IPv4 / IPv6 prefixes (copyable), registration | RIPEstat, rdap.org |
| **Username** | GitHub profile, commit emails and UTC offsets; GitLab profile; Bluesky profile, permanent DID and **handle history**; Hacker News profile; Keybase profile and cryptographically proven accounts | GitHub, GitLab, Bluesky, plc.directory, Algolia, Keybase |
| **Email** | Offline breakdown; GitHub accounts and real names that committed with the address; mail setup of the domain | GitHub, DNS-over-HTTPS |
| **Bitcoin address** | Balance, totals, transaction count, latest transactions with counterparties | Blockstream, mempool.space |
| **CVE** | Description, CVSS, affected products, CISA KEV status, SSVC, references, EPSS exploitation probability | MITRE CVE, FIRST.org |

Working with results:

- **+** adds a finding to the case and links it to the selector you researched (which is added automatically).
- **→ timeline** records dated facts such as account creation or publication.
- If a card shows **Failed**, the service was unreachable or blocked; use the *Open the source site instead*
  link. Anonymous GitHub search allows about ten requests per minute.

Reading results carefully:

- IP geolocation is approximate — city level at best, and often the provider's office.
- InternetDB CVEs are inferred from version banners and are not verified.
- A username existing on a platform does not make it the same person.
- Bitcoin counterparties are not proof of a relationship; exchanges and mixers break the usual assumptions.

---

## 6. Analyze tools

### Metadata
Drop images, PDFs, Office documents or executables. Lantern reads them locally and reports:

- **Images:** EXIF capture time, camera make, model and serial, GPS position and heading, IPTC / XMP, editing
  software, AI-generation markers and C2PA content credentials.
- **PDF:** author, producer, creation and modification dates, revisions, embedded JavaScript.
- **Office / OpenDocument:** authors, last-modified-by, tracked-change reviewers, hidden sheets, macros.
- **Executables:** PE compile time.
- **Extension mismatch:** a file whose content does not match its name.

Buttons add the GPS position as a location, the dates as timeline events, or send all fields to the Extractor.
Most social platforms strip metadata, so its absence proves nothing. Metadata can also be forged — corroborate.

### Email headers
Paste full message headers or drop an `.eml` file. Everything is parsed locally.

- **Message:** decoded subject, From, Reply-To, Return-Path, Date and the sender's UTC offset.
- **Origin & authentication:** the originating IP when the provider exposes it, and SPF, DKIM and DMARC results
  as recorded by the receiving server.
- **Findings:** failed authentication, Reply-To or Return-Path on a different domain, display-name spoofing,
  clock inconsistencies, long delays, and scripted senders such as PHPMailer.
- **Delivery path:** each hop, oldest first, with protocol, TLS use and the delay between hops.
- **Selectors:** add IPs, domains and addresses to the case one by one or all at once.

Getting headers: Gmail → ⋮ → *Show original*. Outlook → *File → Properties* or *View message source*.
Apple Mail → *View → Message → All Headers*.

Only the hops added by the recipient's own servers are trustworthy; a sender can forge everything below them.
Webmail providers hide the sender's IP address by design.

### Geo & sun
- **Coordinate converter:** paste decimal degrees, DMS, degrees + decimal minutes, MGRS, UTM, a Plus Code, a
  geohash or a Google / OpenStreetMap URL. Lantern shows every notation; click a value to copy it.
  **Maps & imagery** opens the point in every map, street-level and satellite source.
- **Distance & bearing:** great-circle distance, bearings and midpoint between two points, with the fastest
  plausible travel time — useful for testing whether two sightings can be the same person.
- **Sun & shadows:** for a place and date, see the sun's azimuth and elevation, shadow direction and length,
  sunrise, solar noon and sunset, and a table through the day.

**Chronolocation — estimating the time of a photo from a shadow**

1. Geolocate the image first and enter the coordinates and date.
2. Measure the shadow. Either its *direction* (on north-up satellite imagery, the compass bearing the shadow
   points toward) or its *length divided by the object's height* (a person, a lamp post, a storey of about 3 m).
3. Choose the measurement type under **Solve from a measured shadow**, enter the value, and click **Find times**.
4. A length alone matches a morning and an afternoon time; the direction tells them apart. **No match** means
   the claimed place or date cannot be right, or the measurement is off.

Sun positions are accurate to about 0.3°. Your measurement is the larger source of error — state a time range.

### Toolbox
Offline utilities.

| Tab | Use |
|---|---|
| **Encode / decode** | Base64, URL, hex, quoted-printable, ROT, HTML entities, Unicode escapes; hidden / zero-width character detection; chain operations |
| **Time converter** | Unix, FILETIME, WebKit, Cocoa, HFS+, Excel and GPS epochs, with a world clock |
| **ID → timestamp** | Creation time embedded in X, Discord, Instagram, LinkedIn, TikTok, Mastodon and Bluesky IDs, UUID v1/v6/v7, ULID and MongoDB ObjectId |
| **IP & CIDR** | Range maths, address class, disguised (decimal / hex / octal) IP forms |
| **Domain & lookalikes** | Punycode and homograph inspection; typosquat generator with optional DNS existence check |
| **Hash & identify** | Hash text; identify a hash by format |
| **Favicon hash** | MurmurHash3 of a favicon file, with ready-made searches on Shodan, FOFA, Censys, ZoomEye and Criminal IP to find other servers using the same icon |
| **Name permutations** | Likely email addresses and usernames from a person's name and one or more domains |
| **JWT** | Decode a JSON Web Token locally (signature not verified) |

Name permutations are guesses. Confirm a pattern from a public source; never send mail to test an address.

---

## 7. Operate tools

### Playbooks
Eight step-by-step workflows: suspicious domain, suspicious email, username / persona, image verification and
geolocation, company due diligence, cryptocurrency tracing, IP / malware indicator triage and self-audit. Each
step has a button that opens the right tool and a note on why the step matters. Ticks are saved per case, and
**Copy steps into case notes** turns a playbook into a plan.

### OPSEC & method
A per-case checklist from planning to reporting, the Admiralty grading reference, ground rules and a statement
of exactly what Lantern itself sends over the network.

### Settings & data
Preferences (active lookups, activity logging, auto-linking, theme), storage use, **Export full backup**,
**Import**, per-case export / duplicate / delete, and **Erase all data**.

---

## 8. Workflows by investigation type

The Playbooks view has the full tick-lists. In short:

**Suspicious domain** — inspect the name (Toolbox) → Recon → subdomains → pivot on the IP → read existing scans
→ extract trackers from an archived copy of the page → lookalikes → timeline → report abuse.

**Suspicious email** — hash the original (Evidence) → Email headers → Recon the origin IP and sending domain →
Extractor on the body → Metadata on attachments → pivot on the sender.

**Username / persona** — define limits → pivot across platforms → username Recon → extract bio text → reverse
image search → decode IDs to dates → archives → require two independent selectors before linking accounts →
test with Hypotheses.

**Image verification** — best original → Metadata → reverse image search for the earliest copy → list visual
clues → match three or more features on imagery → chronolocate with Geo & sun → state what is and is not
verified.

**Company due diligence** — exact legal entity → registry filings → officers and their other companies →
sanctions, leaks and courts → web footprint → documents and job posts → physical address → reconcile dates.

**Crypto tracing** — validate → search the address verbatim → on-chain summary → counterparties and exchange
deposits → cautious clustering → sanctions check → timeline.

**Indicator triage** — Extractor on the alert → IP owner and exposure → anonymisation checks → hash reputation
→ CVE severity, KEV and EPSS → first / last seen → share as defanged CSV or STIX.

**Self-audit** — list your own selectors → breach exposure → username footprint → dork your name and address →
domain mail security → metadata in published files → commit emails.

---

## 9. Privacy, OPSEC and what leaves your machine

| Action | What is sent, and to whom |
|---|---|
| Using Lantern in **Passive** mode | Nothing. No analytics, fonts, CDNs or third-party scripts. |
| Clicking a **pivot or dork link** | Your browser opens that site. It sees your IP address and the query. No referrer is sent. |
| **Recon** and the lookalike DNS check (**Active lookups** on) | The selector you typed goes to the relevant public API from your IP address. |
| Hashing or analysing a **file** | Nothing. Files are read in memory and are never uploaded or stored. |

Services contacted by active lookups: Cloudflare and Google DNS-over-HTTPS, rdap.org, certspotter, crt.sh,
ipinfo.io, archive.org, Shodan InternetDB, RIPEstat, GitHub, GitLab, Bluesky and plc.directory, Hacker News
(Algolia), Keybase, Blockstream, mempool.space, MITRE CVE and FIRST EPSS.

Good practice:

- Use a dedicated browser profile or a research VM, and a VPN where attribution matters.
- Use research accounts, never personal ones. Stay logged out where a site notifies the profile owner.
- Stay passive toward subjects: no follows, likes, messages or friend requests.
- Do not submit private URLs or files to public scanners — submission publishes them.
- Archive key pages and hash downloads as you go; pages disappear.

---

## 10. Data, backups and moving between devices

- Data lives in the browser's `localStorage` under one key, limited to about 5 MB. Settings shows current use.
- **Clearing site data deletes your cases.** Private / incognito windows discard everything on close.
- **Export full backup** regularly. Backups and case exports are plain JSON and contain everything in the case
  — store them as carefully as the investigation requires.
- **Import** accepts a full backup or a single case file. An imported case that collides with an existing one
  is added as a copy.
- To move between `file://`, `localhost`, the desktop app or another computer: export on one, import on the other.
- Evidence files themselves are not stored — only their names and hashes.

---

## 11. Troubleshooting

| Problem | Cause and fix |
|---|---|
| My cases are gone | You opened Lantern from a different origin (`file://` vs `localhost` vs desktop app vs hosted copy), device or browser profile, or site data was cleared. Open it the same way as before, or import a backup. |
| "Save failed — browser storage may be full" | Export and delete closed cases. Long notes and very large entity lists are the usual cause. |
| A Recon card says **Failed — Request blocked** | An ad-blocker, privacy extension, corporate proxy or the service itself blocked the request. Allow the service or use the manual link on the card. |
| GitHub cards fail after several lookups | Anonymous GitHub API limits (60 requests per hour, 10 searches per minute). Wait a minute. |
| Certificate-transparency card is slow | crt.sh is often slow; certspotter is tried first. Use the manual link for very large domains. |
| "Open all" opens one tab | The browser blocked pop-ups. Allow pop-ups for the Lantern page. |
| Copy does nothing under `file://` | Some browsers restrict the clipboard on `file://`. Use the localhost method. |
| Coordinates are "Unrecognised" | Put latitude first, and separate the two values with a comma or space. MGRS needs its zone and band, for example `31U DQ 48252 11954`. |
| A wallet or IBAN is detected as a keyword | Its checksum failed — check for a typo or a missing character. |
| The hosted copy does not show new features | It loads the newest files whenever you are online; reload once. If it still looks old, close every Lantern tab and reopen it. |
| Desktop app does not show new features | Rebuild it with `desktop\build.bat` after updating the web files. |

To confirm the logic is intact after changes, run `node tests/run.js` in the project folder.

---

## 12. Legal and ethical use

Lantern is built for lawful research: journalism, threat intelligence, fraud and due-diligence work, security
assessments you are authorised to perform, and checking your own exposure.

- **Have a purpose and a legal basis** before collecting, and write it in the case scope. Data-protection law
  (GDPR and similar) applies to public personal data too.
- **Collect the minimum** needed to answer the question. Redact uninvolved third parties in reports.
- **Do not** use leaked credentials, bypass logins or access controls, impersonate real people, or contact,
  harass or expose the people you research.
- **Respect platform terms** and local law on scraping, recording and surveillance.
- **Corroborate** before you conclude. A wrong attribution harms a real person.
- **Escalate** threats to life, child exploitation or imminent harm to the appropriate authority and stop.

---

## 13. Reference

### Admiralty grading

| Source reliability | Information credibility |
|---|---|
| A · Completely reliable | 1 · Confirmed by other sources |
| B · Usually reliable | 2 · Probably true |
| C · Fairly reliable | 3 · Possibly true |
| D · Not usually reliable | 4 · Doubtful |
| E · Unreliable | 5 · Improbable |
| F · Reliability cannot be judged | 6 · Truth cannot be judged |

### Words of estimative probability

| Phrase | Likelihood |
|---|---|
| Almost certain | 95–99% |
| Very likely | 80–95% |
| Likely / probable | 55–80% |
| Roughly even chance | 45–55% |
| Unlikely | 20–45% |
| Very unlikely | 5–20% |
| Almost no chance | 1–5% |

State **confidence** (high, moderate, low — the quality of your sourcing) separately from likelihood.

### Defanging

| Live | Defanged |
|---|---|
| `http://` / `https://` | `hxxp[://]` / `hxxps[://]` |
| `example.com` | `example[.]com` |
| `user@example.com` | `user[@]example[.]com` |

The Extractor, Quick pivot and Recon accept defanged input and refang it automatically.

### Glossary

- **ASN** — Autonomous System Number: the network operator that announces an IP range.
- **CT (certificate transparency)** — public logs of every TLS certificate issued; a source of subdomains.
- **DKIM / SPF / DMARC** — email authentication: signature, permitted senders, and the policy tying them to From.
- **EPSS** — probability that a CVE will be exploited in the next 30 days.
- **KEV** — CISA's catalogue of vulnerabilities known to be exploited.
- **MGRS** — Military Grid Reference System, a grid notation for coordinates.
- **Passive DNS** — historical records of which names resolved to which addresses.
- **RDAP** — the structured successor to WHOIS for registration data.
- **STIX** — a standard JSON format for sharing threat intelligence.
