'use strict';
/* Lantern — structured analysis: Analysis of Competing Hypotheses (ACH) and investigation playbooks. */

// ---------------------------------------------------------------- ACH
const ACH_RATINGS = [['', '·', 'Not rated'], ['CC', '++', 'Very consistent'], ['C', '+', 'Consistent'], ['N', 'n/a', 'Neutral / not applicable'], ['I', '−', 'Inconsistent'], ['II', '−−', 'Very inconsistent']];
const ACH_WEIGHT = { high: 2, med: 1, low: 0.5 };
const ACH_WEIGHT_LABEL = { high: 'High', med: 'Medium', low: 'Low' };
/** Heuer's method: rank hypotheses by how much evidence contradicts them, not by how much supports them. */
function achScores(c) {
  return c.hypotheses.map((h) => {
    let score = 0, rated = 0;
    for (const ev of c.ach) { const r = ev.ratings?.[h.id] || ''; if (r) rated++; score += (r === 'I' ? 1 : r === 'II' ? 2 : 0) * (ACH_WEIGHT[ev.weight] || 1); }
    return { id: h.id, text: h.text, score, rated };
  });
}
/** Evidence rated identically for every hypothesis cannot discriminate between them. */
function achDiagnostic(c, ev) {
  if (c.hypotheses.length < 2) return true;
  const rs = c.hypotheses.map((h) => ev.ratings?.[h.id] || '');
  return rs.some((r) => !r) || new Set(rs.map((r) => (r === 'CC' ? 'C' : r === 'II' ? 'I' : r))).size > 1;
}
function achMarkdown(c) {
  if (!c.hypotheses.length) return [];
  const sc = achScores(c), L = [];
  const ranked = [...sc].sort((a, b) => a.score - b.score);
  L.push('## Competing hypotheses (ACH)', '', '| Rank | Hypothesis | Inconsistency score |', '|---|---|---|');
  ranked.forEach((h, i) => L.push(`| ${i + 1} | ${mdCell(h.text)} | ${h.score} |`));
  L.push('');
  if (c.ach.length) {
    L.push(`| Evidence | Weight | ${c.hypotheses.map((_, i) => `H${i + 1}`).join(' | ')} |`, `|---|---|${c.hypotheses.map(() => '---').join('|')}|`);
    c.ach.forEach((ev) => L.push(`| ${mdCell(ev.text)}${ev.source ? ` (${mdCell(ev.source)})` : ''} | ${ACH_WEIGHT_LABEL[ev.weight] || 'Medium'} | ${c.hypotheses.map((h) => ev.ratings?.[h.id] || '·').join(' | ')} |`));
    L.push('', c.hypotheses.map((h, i) => `**H${i + 1}** ${h.text}`).join(' · '), '', '*CC/C = consistent, N = neutral, I/II = inconsistent. The hypothesis with the lowest inconsistency score is the least contradicted by the evidence — not proven.*', '');
  }
  return L;
}

App.register({
  id: 'hypotheses', label: 'Hypotheses', icon: 'hypotheses',
  render(el) {
    const c = App.case, H = c.hypotheses, E = c.ach;
    const scores = achScores(c), min = Math.min(...scores.map((s) => s.score));
    const anyRated = scores.some((s) => s.rated);
    el.innerHTML = `
      ${viewHead('Competing hypotheses', 'Analysis of Competing Hypotheses (ACH): list every explanation that could be true, then rate each piece of evidence against each one. The goal is to <b>disprove</b> — the hypothesis with the least evidence against it survives.',
        `<button class="btn" id="hEv" ${H.length ? '' : 'disabled'}>+ Evidence</button><button class="btn primary" id="hAdd">+ Hypothesis</button>`)}
      ${!H.length ? `<div class="empty"><b>No hypotheses yet</b>Start with at least two mutually exclusive explanations — including the one you think is wrong and the null hypothesis (“coincidence”, “unrelated accounts”, “hoax”).<div class="row mt" style="justify-content:center"><button class="btn" id="hSeed">Insert a starter pair</button></div></div>` : `
      <div class="card"><div class="tbl-wrap"><table class="tbl ach">
        <thead><tr><th style="min-width:260px">Evidence &amp; arguments</th><th>Weight</th>${H.map((h, i) => `<th class="ach-h"><div class="row nowrap"><b>H${i + 1}</b><span class="spacer"></span><button class="btn sm ghost" data-hedit="${esc(h.id)}" title="Edit">✎</button><button class="btn sm ghost" data-hdel="${esc(h.id)}" title="Delete">✕</button></div><div class="small" style="font-weight:400;white-space:normal">${esc(h.text)}</div></th>`).join('')}<th></th></tr></thead>
        <tbody>${E.map((ev) => `<tr>
          <td><div>${esc(ev.text)}</div>${ev.source ? `<div class="small muted break">${esc(ev.source)}</div>` : ''}${achDiagnostic(c, ev) ? '' : '<div class="small"><span class="status warn">Not diagnostic</span> rated the same for every hypothesis — it cannot tell them apart.</div>'}</td>
          <td class="small nowrap">${esc(ACH_WEIGHT_LABEL[ev.weight] || 'Medium')}</td>
          ${H.map((h) => { const r = ev.ratings?.[h.id] || ''; return `<td><select class="ach-cell ach-${r || 'x'}" data-ev="${esc(ev.id)}" data-h="${esc(h.id)}" aria-label="Rating">${ACH_RATINGS.map(([k, s, l]) => `<option value="${k}" ${k === r ? 'selected' : ''} title="${l}">${k ? `${s}  ${l}` : '· rate'}</option>`).join('')}</select></td>`; }).join('')}
          <td class="actions"><button class="btn sm ghost" data-eedit="${esc(ev.id)}">Edit</button><button class="btn sm ghost" data-edel="${esc(ev.id)}">✕</button></td></tr>`).join('') || `<tr><td colspan="${H.length + 3}" class="muted">Add evidence, assumptions and notable absences (“no activity during the alleged trip”) as rows.</td></tr>`}</tbody>
        <tfoot><tr><td colspan="2"><b>Inconsistency score</b><div class="small muted">lower = less contradicted</div></td>${scores.map((s) => `<td><span class="status ${!anyRated ? '' : s.score === min ? 'good' : s.score >= min + 3 ? 'crit' : 'warn'}" style="font-size:14px">${s.score}</span>${anyRated && s.score === min ? '<div class="small muted">least contradicted</div>' : ''}</td>`).join('')}<td></td></tr></tfoot>
      </table></div></div>`}
      <div class="grid g2 mt">
        <div class="card"><h3>How to use the matrix</h3><ol class="small ink2" style="padding-left:18px;margin:0">
          <li>Write hypotheses that <b>exclude each other</b>. Include deception (“the evidence was planted”) when stakes are high.</li>
          <li>Add evidence row by row — and rate <b>across</b> the row: “if H1 were true, would I expect to see this?”</li>
          <li>Weight each row by how reliable the source is (Admiralty grade) — a single anonymous claim is Low.</li>
          <li>Delete or discount rows marked <i>not diagnostic</i>: they feel important but change nothing.</li>
          <li>Reject hypotheses with strong inconsistencies. What survives is your working conclusion, with its confidence set by how close the runner-up is.</li>
          <li>Ask what single new fact would overturn the result — that is your next collection task.</li></ol></div>
        <div class="card"><h3>Words of estimative probability</h3><p class="card-sub">Use consistent language in the report so readers know how sure you are.</p>
          <table class="tbl"><tbody>${[['Almost certain', '95–99%'], ['Very likely / highly probable', '80–95%'], ['Likely / probable', '55–80%'], ['Roughly even chance', '45–55%'], ['Unlikely', '20–45%'], ['Very unlikely', '5–20%'], ['Almost no chance / remote', '1–5%']].map(([a, b]) => `<tr><td>${a}</td><td class="mono num">${b}</td></tr>`).join('')}</tbody></table>
          <p class="muted small" style="margin-bottom:0">Confidence (high / moderate / low) describes the quality of your sources — state it separately from likelihood.</p></div>
      </div>`;

    const hypDlg = async (h) => { const r = await formDlg(h ? 'Edit hypothesis' : 'New hypothesis', [{ name: 'text', label: 'Hypothesis — a statement that could be proven false', type: 'textarea', rows: 3, required: true, value: h?.text || '', placeholder: 'e.g. The account @x and the domain example.com are run by the same person' }]); if (!r) return; if (h) h.text = r.text; else H.push({ id: uid(), text: r.text }); App.touch(h ? 'ACH: edited a hypothesis' : `ACH: added hypothesis “${trunc(r.text, 60)}”`); App.refresh(); };
    const evDlg = async (ev) => {
      const r = await formDlg(ev ? 'Edit evidence' : 'New evidence', [
        { name: 'text', label: 'Evidence, argument or notable absence', type: 'textarea', rows: 3, required: true, value: ev?.text || '', placeholder: 'e.g. Both use the same Google Analytics ID UA-1234567' },
        { name: 'source', label: 'Source / evidence reference', value: ev?.source || '', placeholder: 'E-003, URL, entity…' },
        { name: 'weight', label: 'Weight (source reliability × relevance)', type: 'select', options: [['high', 'High — reliable source, directly relevant'], ['med', 'Medium'], ['low', 'Low — single / unverified / circumstantial']], value: ev?.weight || 'med' },
      ]);
      if (!r) return;
      if (ev) Object.assign(ev, r); else E.push({ id: uid(), ...r, ratings: {} });
      App.touch(ev ? 'ACH: edited evidence' : `ACH: added evidence “${trunc(r.text, 60)}”`); App.refresh();
    };
    $('#hAdd', el).onclick = () => hypDlg();
    $('#hEv', el).onclick = () => evDlg();
    $('#hSeed', el)?.addEventListener('click', () => { H.push({ id: uid(), text: 'The selectors under investigation are controlled by the same actor.' }, { id: uid(), text: 'The overlap is coincidental — different, unrelated actors.' }, { id: uid(), text: 'The link was manufactured to mislead (impersonation / false flag).' }); App.touch('ACH: inserted starter hypotheses'); App.refresh(); });
    el.addEventListener('change', (e) => {
      const s = e.target.closest('[data-ev][data-h]'); if (!s) return;
      const ev = E.find((x) => x.id === s.dataset.ev); if (!ev) return;
      ev.ratings = ev.ratings || {}; if (s.value) ev.ratings[s.dataset.h] = s.value; else delete ev.ratings[s.dataset.h];
      App.touch(); App.refresh();
    });
    el.addEventListener('click', async (e) => {
      const b = e.target.closest('button'); if (!b) return;
      if (b.dataset.hedit) hypDlg(H.find((h) => h.id === b.dataset.hedit));
      else if (b.dataset.eedit) evDlg(E.find((x) => x.id === b.dataset.eedit));
      else if (b.dataset.hdel) { if (!(await confirmDlg('Delete this hypothesis and its ratings?', { title: 'Delete hypothesis', ok: 'Delete', danger: true }))) return; c.hypotheses = H.filter((h) => h.id !== b.dataset.hdel); E.forEach((ev) => { if (ev.ratings) delete ev.ratings[b.dataset.hdel]; }); App.touch('ACH: deleted a hypothesis'); App.refresh(); }
      else if (b.dataset.edel) { c.ach = E.filter((x) => x.id !== b.dataset.edel); App.touch('ACH: deleted evidence'); App.refresh(); }
    });
  },
});

// ---------------------------------------------------------------- Playbooks
// Step: [text, viewId to open (optional), why it matters / tip (optional)]
const PLAYBOOKS = [
  { id: 'domain', title: 'Suspicious domain or phishing site', when: 'A link in a message, a lookalike of your brand, infrastructure in a threat report.', steps: [
    ['Do not open the site from your normal browser. Record the URL exactly as received (defanged) in Evidence.', 'evidence', 'Opening it tells the operator someone is looking — and phishing kits often serve one victim once.'],
    ['Inspect the name itself: punycode, mixed scripts, homoglyphs, registrable domain.', 'toolbox', 'Toolbox → Domain & lookalikes. A Cyrillic “а” is invisible to the eye.'],
    ['Run Recon: registration date and registrar, nameservers, mail setup, DNSSEC, wildcard DNS.', 'recon', 'Under 30 days old + privacy registrar + free TLS certificate is the classic phishing profile.'],
    ['Harvest subdomains from certificate transparency and add the interesting ones.', 'recon', 'Look for login., secure., mail., and other brands on the same domain.'],
    ['Pivot on the hosting IP: reverse IP, passive DNS, Shodan InternetDB, ASN reputation.', 'pivot', 'Sibling domains on a small dedicated host usually belong to the same operator.'],
    ['Check reputation and prior scans: urlscan.io, VirusTotal, URLhaus — read existing results before submitting anything new.', 'pivot', 'Submitting a private URL to a public scanner publishes it.'],
    ['Look at the page safely via an existing urlscan screenshot or the Wayback Machine. Save the HTML and extract tracker IDs, emails and wallets from it.', 'extractor', 'Analytics / AdSense IDs and favicon hashes link a site to its siblings.'],
    ['Generate lookalikes of the impersonated brand and check which exist.', 'toolbox'],
    ['Put registration, first certificate and first archive capture on the timeline.', 'timeline', 'Infrastructure is usually staged days before a campaign starts.'],
    ['Report: registrar and host abuse contacts (Recon shows them), plus the impersonated brand.', 'report'],
  ] },
  { id: 'email', title: 'Suspicious email (phishing / BEC / threat)', when: 'You hold the original message and need to know who really sent it.', steps: [
    ['Export the original message (.eml or “Show original”) and hash it into Evidence before anything else.', 'evidence'],
    ['Analyze the headers: authentication results, Reply-To / Return-Path mismatches, originating IP, sending software.', 'mail', 'Only trust Received lines added by the recipient’s own mail servers.'],
    ['Recon the originating IP and the sending domain.', 'recon', 'Residential ISP, VPN exit, compromised web host and bulk mailer each tell a different story.'],
    ['Extract every selector from the body and attachments’ text: links, phone numbers, wallets, addresses.', 'extractor'],
    ['Check attachments in Metadata without opening them in their native app.', 'metadata', 'Author names, last-modified-by, macros and creation times survive in Office and PDF files.'],
    ['Pivot on the sender address: breach exposure, registered accounts, Gravatar, commits.', 'pivot'],
    ['Convert the Date offset and any embedded timestamps to build the sender’s working-hours pattern.', 'toolbox'],
    ['Write up indicators (defanged) and the delivery path.', 'report'],
  ] },
  { id: 'person', title: 'Username or online persona', when: 'Attributing an account, mapping a persona’s footprint, or auditing your own exposure.', steps: [
    ['Write down the purpose and limits first: what you need to know, and what you will not collect.', 'opsec', 'Proportionality is what separates research from stalking — and it is a legal requirement under GDPR-style laws.'],
    ['Pivot on the exact username across platforms; note where it does not exist as well.', 'pivot', 'A hit only means the name is taken — not that it is the same person.'],
    ['Run username Recon: GitHub commit emails and time zones, Bluesky handle history, Keybase proofs.', 'recon', 'Keybase proofs and commit emails are among the few cryptographically or technically strong links between accounts.'],
    ['Collect the profile’s own words: bio links, older handles, reused avatars. Paste profile text into the Extractor.', 'extractor'],
    ['Reverse-search the avatar and distinctive photos; read metadata on anything downloadable.', 'metadata'],
    ['Decode account and post IDs into creation times; add first and last activity to the timeline.', 'toolbox', 'Toolbox → ID → timestamp works even when the platform hides dates.'],
    ['Look for the past: Wayback captures of the profile, cached usernames, old bios.', 'pivot'],
    ['Require two independent selectors before you link two accounts. Record each link with a grade.', 'graph', 'Same username + same avatar is one selector reused, not two.'],
    ['Test the attribution against alternatives in the ACH matrix: coincidence, impersonation, shared account.', 'hypotheses'],
    ['Report only what the question needs; redact uninvolved third parties.', 'report'],
  ] },
  { id: 'image', title: 'Image or video verification & geolocation', when: 'Is this photo real, where and when was it taken, and is it the first appearance?', steps: [
    ['Get the highest-quality original you can; hash and log it.', 'evidence', 'Every repost recompresses and strips data.'],
    ['Read the metadata: capture time, device, GPS, editing software, AI-generation or C2PA markers.', 'metadata', 'Missing EXIF proves nothing — most platforms strip it.'],
    ['Reverse image search on several engines; sort by oldest to find the first appearance.', 'pivot', 'Yandex and Bing excel at faces and places; Google Lens at objects; TinEye at exact copies.'],
    ['List the clues you can see: language on signs, plates, road markings, architecture, vegetation, terrain, weather, power sockets.', 'notes'],
    ['Form a candidate location and compare with satellite imagery and street-level photos. Match at least three independent features.', 'geo', 'Geo & sun → Maps & imagery opens every map provider at the same point.'],
    ['Chronolocate: measure a shadow’s direction and length, then solve for the time of day.', 'geo', 'Historic weather and satellite revisit dates can bracket the date.'],
    ['Check the claimed date against the earliest copy online and against event timelines.', 'timeline'],
    ['State what is verified (place, time, source) and what is not — separately.', 'report'],
  ] },
  { id: 'company', title: 'Company due diligence', when: 'Vetting a counterparty, vendor, investment or shell company.', steps: [
    ['Pin down the exact legal entity: registered name, number, jurisdiction.', 'pivot', 'Similar names in other registries are a common trick.'],
    ['Pull registry filings: directors, shareholders, registered address, incorporation and dissolution dates.', 'pivot'],
    ['Map officers and their other appointments; add people and companies as linked entities.', 'graph', 'Hundreds of companies at one address, or directors with dozens of appointments, suggest nominees.'],
    ['Screen names against sanctions, PEP, leak and court databases.', 'pivot'],
    ['Check the web footprint: domain age versus claimed history, hosting, mail setup, shared tracker IDs.', 'recon'],
    ['Search documents and job posts for technology, clients and locations.', 'dorks'],
    ['Verify physical presence: map the address, look at street-level imagery.', 'geo'],
    ['Reconcile dates on the timeline: incorporation, domain registration, first web capture, first press.', 'timeline'],
    ['Record adverse findings with source grades; separate fact from inference.', 'report'],
  ] },
  { id: 'crypto', title: 'Cryptocurrency address tracing', when: 'A wallet in a ransom note, scam page or donation request.', steps: [
    ['Validate the address and chain; add it with the source where you found it.', 'pivot', 'Lantern checks Bitcoin, Litecoin, Dogecoin, TRON and Dash checksums — a typo is not an address.'],
    ['Search for the address verbatim on the open web, paste sites and abuse databases.', 'pivot'],
    ['Pull the on-chain summary: balance, volume, first and last activity.', 'recon'],
    ['Identify counterparties; look for exchange deposit addresses — the point where identity is known to a third party.', 'recon', 'Attribution labels from explorers are leads, not proof.'],
    ['Cluster cautiously: inputs spent together usually share an owner; change addresses and CoinJoin break the rule.', 'graph'],
    ['Check sanctions lists before anyone sends funds.', 'pivot'],
    ['Put transactions on the timeline next to messages and site registrations.', 'timeline'],
    ['Report transaction IDs, amounts, times (UTC) and the explorer used.', 'report'],
  ] },
  { id: 'indicator', title: 'IP address / malware indicator triage', when: 'An alert, a log entry or an indicator list needs context fast.', steps: [
    ['Paste the raw alert or log into the Extractor; keep the source text in Evidence.', 'extractor'],
    ['For IPs: owner, ASN, hosting type, reverse DNS, exposed services.', 'recon', 'Cloud and CDN addresses are shared — the same IP may be someone else tomorrow.'],
    ['Check anonymization: Tor exit history, VPN / proxy tags, residential proxy networks.', 'pivot'],
    ['For hashes: look up existing sandbox reports — never upload a sensitive file to a public service.', 'pivot'],
    ['For CVEs: severity, KEV status and EPSS exploitation probability.', 'recon'],
    ['Pivot between indicators via passive DNS and shared certificates; link what you can justify.', 'graph'],
    ['Note first-seen and last-seen for every indicator. Stale indicators cause false positives.', 'timeline'],
    ['Share defanged indicators as CSV or STIX.', 'report'],
  ] },
  { id: 'self', title: 'Your own exposure (self-audit)', when: 'Reducing what a stranger could learn about you or your organization.', steps: [
    ['List your own selectors: emails, usernames, phone, domains, home / office address.', 'entities'],
    ['Check breach exposure for every email; change reused passwords and enable MFA where it shows up.', 'pivot'],
    ['Search your usernames across platforms and remove forgotten accounts.', 'pivot'],
    ['Dork your name, phone and address in quotes; request removal from people-search sites.', 'dorks'],
    ['Check your domain’s mail security and exposed subdomains.', 'recon', 'A missing DMARC policy lets anyone send mail as you.'],
    ['Inspect files you publish for author names, GPS and software versions.', 'metadata'],
    ['Check your public commits for a personal email address and time zone.', 'recon'],
    ['Record what you changed and re-check in three months.', 'notes'],
  ] },
];

const pbState = { open: 'domain' };
App.register({
  id: 'playbooks', label: 'Playbooks', icon: 'playbooks',
  render(el, params) {
    if (params.open) pbState.open = params.open;
    const c = App.case;
    const prog = (p) => p.steps.filter((_, i) => c.playbooks[p.id]?.[i]).length;
    const p = PLAYBOOKS.find((x) => x.id === pbState.open) || PLAYBOOKS[0];
    el.innerHTML = `
      ${viewHead('Playbooks', 'Step-by-step workflows for the most common investigations. Each step opens the right tool; ticks are saved with the active case.')}
      <div class="grid pb-grid">
        <div class="stack" style="--gap:6px">${PLAYBOOKS.map((x) => `<button class="pb-item ${x.id === p.id ? 'active' : ''}" data-pb="${x.id}"><b>${esc(x.title)}</b><span class="small muted">${prog(x)}/${x.steps.length} steps</span></button>`).join('')}</div>
        <div class="card"><h3>${esc(p.title)}<span class="spacer"></span><span class="muted small">${prog(p)} of ${p.steps.length}</span></h3>
          <p class="card-sub"><b>Use when:</b> ${esc(p.when)}</p>
          <div class="progress mb"><div style="width:${(prog(p) / p.steps.length) * 100}%"></div></div>
          <ol class="pb-steps">${p.steps.map(([text, go, tip], i) => { const done = !!c.playbooks[p.id]?.[i]; return `<li class="${done ? 'done' : ''}"><input type="checkbox" id="pb_${i}" data-step="${i}" ${done ? 'checked' : ''} aria-label="Step ${i + 1} done"><div><label for="pb_${i}">${esc(text)}</label>${tip ? `<div class="small muted">${esc(tip)}</div>` : ''}</div>${go && App.views[go] ? `<a class="btn sm" href="#/${go}">${esc(App.views[go].label)} →</a>` : ''}</li>`; }).join('')}</ol>
          <div class="row mt"><button class="btn sm ghost" id="pbnotes">Copy steps into case notes</button><button class="btn sm ghost" id="pbreset">Reset ticks</button></div>
        </div>
      </div>`;
    el.addEventListener('click', (e) => {
      const b = e.target.closest('[data-pb]'); if (b) { pbState.open = b.dataset.pb; App.refresh(); return; }
      if (e.target.id === 'pbreset') { delete c.playbooks[p.id]; App.touch(); App.refresh(); }
      if (e.target.id === 'pbnotes') { c.notes += `${c.notes ? '\n\n' : ''}## Plan: ${p.title}\n${p.steps.map(([t], i) => `- [${c.playbooks[p.id]?.[i] ? 'x' : ' '}] ${t}`).join('\n')}\n`; App.touch(`Playbook “${p.title}” copied to notes`); toast('Appended to case notes'); }
    });
    el.addEventListener('change', (e) => {
      const i = e.target.dataset.step; if (i === undefined) return;
      c.playbooks[p.id] = c.playbooks[p.id] || {};
      if (e.target.checked) c.playbooks[p.id][i] = true; else delete c.playbooks[p.id][i];
      App.touch(e.target.checked ? `Playbook “${p.title}”: step ${+i + 1} done` : null); App.refresh();
    });
  },
});
