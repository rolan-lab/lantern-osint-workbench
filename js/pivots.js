'use strict';
/* Lantern — pivot library: public lookup resources per selector type.
   Item format: [name, urlTemplate, flag]. flag 'paste' = the site has no query URL; the value is copied to the
   clipboard and the site opens so you can paste it. Template vars: {q} url-encoded value, {raw} value, plus
   type-specific vars (see pivotVars). Nothing here is fetched by the app — links open in a new tab only when you click. */

const G = (q) => `https://www.google.com/search?q=${q}`;
const EXACT_SEARCH = { group: 'Exact-match web search', items: [
  ['Google', G('%22{q}%22')],
  ['Bing', 'https://www.bing.com/search?q=%22{q}%22'],
  ['DuckDuckGo', 'https://duckduckgo.com/?q=%22{q}%22'],
  ['Yandex', 'https://yandex.com/search/?text=%22{q}%22'],
  ['Brave', 'https://search.brave.com/search?q=%22{q}%22'],
  ['Pastes (Google)', G('site%3Apastebin.com+OR+site%3Aghostbin.site+OR+site%3Arentry.co+%22{q}%22')],
  ['GitHub code', 'https://github.com/search?q=%22{q}%22&type=code'],
] };

const PIVOTS = {
  domain: [
    { group: 'Registration & DNS', items: [
      ['ICANN RDAP lookup', 'https://lookup.icann.org/en/lookup?name={q}'],
      ['who.is', 'https://who.is/whois/{q}'],
      ['DomainTools whois', 'https://whois.domaintools.com/{q}'],
      ['SecurityTrails DNS', 'https://securitytrails.com/domain/{q}/dns'],
      ['ViewDNS IP history', 'https://viewdns.info/iphistory/?domain={q}'],
      ['ViewDNS reverse IP', 'https://viewdns.info/reverseip/?host={q}&t=1'],
      ['Robtex', 'https://www.robtex.com/dns-lookup/{q}'],
      ['DNSDumpster', 'https://dnsdumpster.com/', 'paste'],
    ] },
    { group: 'Certificates & subdomains', items: [
      ['crt.sh (all subdomains)', 'https://crt.sh/?q=%25.{q}'],
      ['Censys', 'https://search.censys.io/search?resource=hosts&q={q}'],
      ['Shodan hostname', 'https://www.shodan.io/search?query=hostname%3A{q}'],
      ['Google subdomains', G('site%3A*.{q}+-site%3Awww.{q}')],
    ] },
    { group: 'Reputation & scans', items: [
      ['VirusTotal', 'https://www.virustotal.com/gui/domain/{q}'],
      ['urlscan.io', 'https://urlscan.io/search/#domain:{q}'],
      ['AlienVault OTX', 'https://otx.alienvault.com/indicator/domain/{q}'],
      ['Cisco Talos', 'https://talosintelligence.com/reputation_center/lookup?search={q}'],
      ['URLhaus', 'https://urlhaus.abuse.ch/browse.php?search={q}'],
      ['ThreatFox', 'https://threatfox.abuse.ch/browse.php?search=ioc%3A{q}'],
    ] },
    { group: 'Web footprint & history', items: [
      ['Wayback Machine', 'https://web.archive.org/web/*/{raw}/*'],
      ['archive.today', 'https://archive.ph/{raw}'],
      ['BuiltWith', 'https://builtwith.com/{q}'],
      ['Similarweb', 'https://www.similarweb.com/website/{q}/'],
      ['Google site:', G('site%3A{q}')],
      ['Mentions elsewhere', G('%22{q}%22+-site%3A{q}')],
      ['GitHub code', 'https://github.com/search?q=%22{q}%22&type=code'],
    ] },
  ],
  ipv4: [
    { group: 'Infrastructure', items: [
      ['Shodan', 'https://www.shodan.io/host/{q}'],
      ['Censys', 'https://search.censys.io/hosts/{q}'],
      ['ipinfo.io', 'https://ipinfo.io/{q}'],
      ['bgp.he.net (ASN)', 'https://bgp.he.net/ip/{q}'],
      ['ARIN RDAP', 'https://search.arin.net/rdap/?query={q}'],
      ['ViewDNS reverse IP', 'https://viewdns.info/reverseip/?host={q}&t=1'],
      ['Robtex', 'https://www.robtex.com/ip-lookup/{q}'],
    ] },
    { group: 'Reputation & threat intel', items: [
      ['AbuseIPDB', 'https://www.abuseipdb.com/check/{q}'],
      ['GreyNoise', 'https://viz.greynoise.io/ip/{q}'],
      ['VirusTotal', 'https://www.virustotal.com/gui/ip-address/{q}'],
      ['AlienVault OTX', 'https://otx.alienvault.com/indicator/ip/{q}'],
      ['Cisco Talos', 'https://talosintelligence.com/reputation_center/lookup?search={q}'],
      ['urlscan.io', 'https://urlscan.io/search/#ip:%22{q}%22'],
      ['ThreatFox', 'https://threatfox.abuse.ch/browse.php?search=ioc%3A{q}'],
      ['Spamhaus', 'https://check.spamhaus.org/', 'paste'],
    ] },
  ],
  email: [
    { group: 'Breach & exposure', items: [
      ['Have I Been Pwned', 'https://haveibeenpwned.com/', 'paste'],
      ['Intelligence X', 'https://intelx.io/?s={q}'],
      ['DeHashed', 'https://dehashed.com/search?query={q}'],
    ] },
    { group: 'Accounts & identity', items: [
      ['Gravatar avatar', 'https://gravatar.com/avatar/{gravatar}?d=404&s=400'],
      ['Epieos', 'https://epieos.com/', 'paste'],
      ['Hunter verifier', 'https://hunter.io/email-verifier/{q}'],
      ['GitHub commits', 'https://github.com/search?q=%22{q}%22&type=commits'],
      ['PGP: keys.openpgp.org', 'https://keys.openpgp.org/search?q={q}'],
      ['PGP: Ubuntu keyserver', 'https://keyserver.ubuntu.com/pks/lookup?search={q}&op=index'],
    ] },
    EXACT_SEARCH,
  ],
  username: [
    { group: 'Profiles — social', items: [
      ['X / Twitter', 'https://x.com/{q}'], ['Instagram', 'https://www.instagram.com/{q}/'], ['Threads', 'https://www.threads.net/@{q}'],
      ['TikTok', 'https://www.tiktok.com/@{q}'], ['YouTube', 'https://www.youtube.com/@{q}'], ['Reddit', 'https://www.reddit.com/user/{q}'],
      ['Facebook', 'https://www.facebook.com/{q}'], ['LinkedIn', 'https://www.linkedin.com/in/{q}'], ['Telegram', 'https://t.me/{q}'],
      ['Bluesky', 'https://bsky.app/profile/{q}.bsky.social'], ['Mastodon.social', 'https://mastodon.social/@{q}'], ['Twitch', 'https://www.twitch.tv/{q}'],
      ['Pinterest', 'https://www.pinterest.com/{q}/'], ['Snapchat', 'https://www.snapchat.com/add/{q}'], ['Tumblr', 'https://{q}.tumblr.com'],
      ['Linktree', 'https://linktr.ee/{q}'], ['Medium', 'https://medium.com/@{q}'], ['Substack', 'https://{q}.substack.com'],
    ] },
    { group: 'Profiles — tech & hobby', items: [
      ['GitHub', 'https://github.com/{q}'], ['GitLab', 'https://gitlab.com/{q}'], ['Codeberg', 'https://codeberg.org/{q}'],
      ['Bitbucket', 'https://bitbucket.org/{q}/'], ['Docker Hub', 'https://hub.docker.com/u/{q}'], ['npm', 'https://www.npmjs.com/~{q}'],
      ['PyPI', 'https://pypi.org/user/{q}/'], ['Keybase', 'https://keybase.io/{q}'], ['Hacker News', 'https://news.ycombinator.com/user?id={q}'],
      ['dev.to', 'https://dev.to/{q}'], ['HackerOne', 'https://hackerone.com/{q}'], ['Kaggle', 'https://www.kaggle.com/{q}'],
      ['Replit', 'https://replit.com/@{q}'], ['Steam', 'https://steamcommunity.com/id/{q}'], ['Chess.com', 'https://www.chess.com/member/{q}'],
      ['Lichess', 'https://lichess.org/@/{q}'], ['SoundCloud', 'https://soundcloud.com/{q}'], ['Vimeo', 'https://vimeo.com/{q}'],
      ['Flickr', 'https://www.flickr.com/people/{q}/'], ['Behance', 'https://www.behance.net/{q}'], ['Dribbble', 'https://dribbble.com/{q}'],
      ['Patreon', 'https://www.patreon.com/{q}'], ['Letterboxd', 'https://letterboxd.com/{q}/'], ['Gravatar', 'https://gravatar.com/{q}'],
      ['About.me', 'https://about.me/{q}'], ['Product Hunt', 'https://www.producthunt.com/@{q}'],
    ] },
    { group: 'Username search engines', items: [
      ['WhatsMyName', 'https://whatsmyname.app/', 'paste'],
      ['Google (exact)', G('%22{q}%22')],
      ['Google (in URLs)', G('inurl%3A{q}')],
      ['GitHub users', 'https://github.com/search?q={q}&type=users'],
      ['Reddit mentions', 'https://www.reddit.com/search/?q=%22{q}%22'],
    ] },
  ],
  phone: [
    { group: 'Search', items: [
      ['Google (as written)', G('%22{q}%22')],
      ['Google (digits)', G('%22{digits}%22+OR+%22%2B{digits}%22')],
      ['Bing', 'https://www.bing.com/search?q=%22{q}%22'],
      ['DuckDuckGo', 'https://duckduckgo.com/?q=%22{q}%22'],
    ] },
    { group: 'Messaging & caller ID', items: [
      ['WhatsApp chat link', 'https://wa.me/{digits}'],
      ['Truecaller', 'https://www.truecaller.com/', 'paste'],
      ['NumLookup', 'https://www.numlookup.com/', 'paste'],
    ] },
  ],
  url: [
    { group: 'Scan & reputation', items: [
      ['VirusTotal', 'https://www.virustotal.com/gui/search/{qq}'],
      ['urlscan.io (search host)', 'https://urlscan.io/search/#page.domain:{host}'],
      ['urlscan.io (submit scan)', 'https://urlscan.io/', 'paste'],
      ['URLhaus', 'https://urlhaus.abuse.ch/browse.php?search={q}'],
      ['Google Safe Browsing', 'https://transparencyreport.google.com/safe-browsing/search?url={q}'],
    ] },
    { group: 'Archive & preserve', items: [
      ['Wayback: all captures', 'https://web.archive.org/web/*/{raw}'],
      ['Wayback: save now', 'https://web.archive.org/save/{raw}'],
      ['archive.today: newest', 'https://archive.ph/newest/{raw}'],
      ['archive.today: submit', 'https://archive.ph/?run=1&url={q}'],
      ['Ghostarchive', 'https://ghostarchive.org/search?term={q}'],
    ] },
    { group: 'Redirects & unshortening', items: [
      ['CheckShortURL', 'https://checkshorturl.com/expand.php?u={q}'],
      ['Redirect Detective', 'https://redirectdetective.com/', 'paste'],
    ] },
  ],
  image: [
    { group: 'Reverse image search', items: [
      ['Google Lens', 'https://lens.google.com/uploadbyurl?url={q}'],
      ['Bing Visual Search', 'https://www.bing.com/images/search?view=detailv2&iss=sbi&q=imgurl:{q}'],
      ['Yandex Images', 'https://yandex.com/images/search?rpt=imageview&url={q}'],
      ['TinEye', 'https://tineye.com/search?url={q}'],
    ] },
    { group: 'Forensics', items: [
      ['FotoForensics', 'https://fotoforensics.com/', 'paste'],
      ['Forensically', 'https://29a.ch/photo-forensics/', 'paste'],
      ['Wayback captures', 'https://web.archive.org/web/*/{raw}'],
    ] },
  ],
  hash: [
    { group: 'Malware & threat intel', items: [
      ['VirusTotal', 'https://www.virustotal.com/gui/file/{q}'],
      ['MalwareBazaar', 'https://bazaar.abuse.ch/browse.php?search={bazaar}'],
      ['Hybrid Analysis', 'https://www.hybrid-analysis.com/search?query={q}'],
      ['Triage', 'https://tria.ge/s?q={q}'],
      ['AlienVault OTX', 'https://otx.alienvault.com/indicator/file/{q}'],
      ['ThreatFox', 'https://threatfox.abuse.ch/browse.php?search=ioc%3A{q}'],
    ] },
    { group: 'Search', items: [['Google', G('%22{q}%22')], ['GitHub code', 'https://github.com/search?q={q}&type=code']] },
  ],
  btc: [
    { group: 'Explorers', items: [
      ['mempool.space', 'https://mempool.space/address/{q}'],
      ['Blockchain.com', 'https://www.blockchain.com/explorer/addresses/btc/{q}'],
      ['Blockstream', 'https://blockstream.info/address/{q}'],
      ['WalletExplorer', 'https://www.walletexplorer.com/address/{q}'],
      ['Arkham', 'https://intel.arkm.com/explorer/address/{q}'],
    ] },
    { group: 'Abuse & sanctions', items: [
      ['Chainabuse', 'https://www.chainabuse.com/address/{q}'],
      ['OFAC sanctions search', 'https://sanctionssearch.ofac.treas.gov/', 'paste'],
      ['Google', G('%22{q}%22')],
    ] },
  ],
  eth: [
    { group: 'Explorers', items: [
      ['Etherscan', 'https://etherscan.io/address/{q}'],
      ['Blockscan (multichain)', 'https://blockscan.com/address/{q}'],
      ['Ethplorer', 'https://ethplorer.io/address/{q}'],
      ['DeBank', 'https://debank.com/profile/{q}'],
      ['Arkham', 'https://intel.arkm.com/explorer/address/{q}'],
    ] },
    { group: 'Abuse & sanctions', items: [
      ['Chainabuse', 'https://www.chainabuse.com/address/{q}'],
      ['OFAC sanctions search', 'https://sanctionssearch.ofac.treas.gov/', 'paste'],
      ['Google', G('%22{q}%22')],
    ] },
  ],
  location: [
    { group: 'Maps', items: [
      ['Google Maps', 'https://www.google.com/maps/search/?api=1&query={lat},{lon}'],
      ['OpenStreetMap', 'https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=17/{lat}/{lon}'],
      ['Bing aerial', 'https://www.bing.com/maps?cp={lat}~{lon}&lvl=18&style=a'],
      ['Yandex Maps', 'https://yandex.com/maps/?ll={lon},{lat}&z=17&pt={lon},{lat}'],
      ['Apple Maps', 'https://maps.apple.com/?ll={lat},{lon}&q=Pin&t=k'],
      ['Google Earth', 'https://earth.google.com/web/@{lat},{lon},300a,800d,35y,0h,45t,0r'],
    ] },
    { group: 'Street level & social', items: [
      ['Google Street View', 'https://www.google.com/maps/@?api=1&map_action=pano&viewpoint={lat},{lon}'],
      ['Mapillary', 'https://www.mapillary.com/app/?lat={lat}&lng={lon}&z=17'],
      ['KartaView', 'https://kartaview.org/map/@{lat},{lon},17z'],
      ['Snap Map', 'https://map.snapchat.com/@{lat},{lon},15.00z'],
      ['Wikipedia nearby', 'https://en.wikipedia.org/wiki/Special:Nearby#/coord/{lat},{lon}'],
    ] },
    { group: 'Imagery & analysis', items: [
      ['Sentinel Hub EO Browser', 'https://apps.sentinel-hub.com/eo-browser/?zoom=14&lat={lat}&lng={lon}'],
      ['SunCalc (shadows)', 'https://www.suncalc.org/#/{lat},{lon},17/null/null/null/null'],
      ['Wikimapia', 'https://wikimapia.org/#lat={lat}&lon={lon}&z=17&m=w'],
      ['Overpass Turbo', 'https://overpass-turbo.eu/', 'paste'],
    ] },
  ],
  cve: [
    { group: 'Vulnerability intel', items: [
      ['NVD', 'https://nvd.nist.gov/vuln/detail/{q}'],
      ['CVE.org', 'https://www.cve.org/CVERecord?id={q}'],
      ['CISA KEV', 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext={q}'],
      ['EPSS score (FIRST)', 'https://api.first.org/data/v1/epss?cve={q}'],
      ['Vulners', 'https://vulners.com/search?query={q}'],
    ] },
    { group: 'Exploits & discussion', items: [
      ['Exploit-DB', 'https://www.exploit-db.com/search?cve={cvenum}'],
      ['GitHub repositories', 'https://github.com/search?q={q}&type=repositories'],
      ['Google', G('%22{q}%22')],
    ] },
  ],
  mac: [
    { group: 'Vendor & sightings', items: [
      ['MAC vendor lookup', 'https://maclookup.app/search/result?mac={q}'],
      ['Wireshark OUI lookup', 'https://www.wireshark.org/tools/oui-lookup.html', 'paste'],
      ['WiGLE', 'https://wigle.net/search', 'paste'],
    ] },
  ],
  person: [
    { group: 'Search', items: [
      ['Google (exact)', G('%22{q}%22')], ['Bing (exact)', 'https://www.bing.com/search?q=%22{q}%22'],
      ['DuckDuckGo', 'https://duckduckgo.com/?q=%22{q}%22'], ['Yandex', 'https://yandex.com/search/?text=%22{q}%22'],
      ['Documents (PDF/DOC)', G('%22{q}%22+(filetype%3Apdf+OR+filetype%3Adocx+OR+filetype%3Axlsx)')],
    ] },
    { group: 'Professional & academic', items: [
      ['LinkedIn people', 'https://www.linkedin.com/search/results/people/?keywords={q}'],
      ['LinkedIn via Google', G('site%3Alinkedin.com%2Fin+%22{q}%22')],
      ['Google Scholar', 'https://scholar.google.com/scholar?q=%22{q}%22'],
      ['ORCID', 'https://orcid.org/orcid-search/search?searchQuery={q}'],
    ] },
    { group: 'Public records & due diligence', items: [
      ['OpenSanctions', 'https://www.opensanctions.org/search/?q={q}'],
      ['ICIJ Offshore Leaks', 'https://offshoreleaks.icij.org/search?q={q}'],
      ['OCCRP Aleph', 'https://aleph.occrp.org/search?q={q}'],
      ['CourtListener', 'https://www.courtlistener.com/?q=%22{q}%22'],
      ['OpenCorporates officers', 'https://opencorporates.com/officers?q={q}'],
      ['Wikipedia', 'https://en.wikipedia.org/w/index.php?search={q}'],
      ['Wikidata', 'https://www.wikidata.org/w/index.php?search={q}'],
      ['Google News', 'https://news.google.com/search?q=%22{q}%22'],
    ] },
  ],
  org: [
    { group: 'Company registries', items: [
      ['OpenCorporates', 'https://opencorporates.com/companies?q={q}'],
      ['SEC EDGAR full-text', 'https://www.sec.gov/edgar/search/#/q=%22{q}%22'],
      ['UK Companies House', 'https://find-and-update.company-information.service.gov.uk/search?q={q}'],
      ['GLEIF (LEI)', 'https://search.gleif.org/#/search/simpleSearch={q}'],
    ] },
    { group: 'Sanctions, leaks & news', items: [
      ['OpenSanctions', 'https://www.opensanctions.org/search/?q={q}'],
      ['ICIJ Offshore Leaks', 'https://offshoreleaks.icij.org/search?q={q}'],
      ['OCCRP Aleph', 'https://aleph.occrp.org/search?q={q}'],
      ['Google News', 'https://news.google.com/search?q=%22{q}%22'],
      ['Wikipedia', 'https://en.wikipedia.org/w/index.php?search={q}'],
    ] },
    { group: 'People & footprint', items: [
      ['LinkedIn companies', 'https://www.linkedin.com/search/results/companies/?keywords={q}'],
      ['Crunchbase', 'https://www.crunchbase.com/textsearch?q={q}'],
      ['GitHub orgs', 'https://github.com/search?q={q}&type=users'],
      ['Shodan (org:)', 'https://www.shodan.io/search?query=org%3A%22{q}%22'],
      ['crt.sh (cert subject O=)', 'https://crt.sh/?O={q}'],
    ] },
  ],
  keyword: [
    { group: 'Web search', items: [
      ['Google', G('{q}')], ['Bing', 'https://www.bing.com/search?q={q}'], ['DuckDuckGo', 'https://duckduckgo.com/?q={q}'],
      ['Yandex', 'https://yandex.com/search/?text={q}'], ['Baidu', 'https://www.baidu.com/s?wd={q}'], ['Brave', 'https://search.brave.com/search?q={q}'],
    ] },
    { group: 'Social & community', items: [
      ['X (latest)', 'https://x.com/search?q={q}&f=live'], ['Reddit', 'https://www.reddit.com/search/?q={q}'],
      ['YouTube', 'https://www.youtube.com/results?search_query={q}'], ['TikTok', 'https://www.tiktok.com/search?q={q}'],
      ['Bluesky', 'https://bsky.app/search?q={q}'], ['Telegram (TGStat)', 'https://tgstat.com/search?q={q}'],
    ] },
    { group: 'Code, news & archives', items: [
      ['GitHub code', 'https://github.com/search?q={q}&type=code'], ['grep.app', 'https://grep.app/search?q={q}'],
      ['Google News', 'https://news.google.com/search?q={q}'], ['Pastes (Google)', G('site%3Apastebin.com+{q}')],
    ] },
  ],
};
// ---- selector types added after the first release
PIVOTS.asn = [
  { group: 'Routing & ownership', items: [
    ['Hurricane Electric BGP', 'https://bgp.he.net/{raw}'],
    ['bgp.tools', 'https://bgp.tools/as/{asnum}'],
    ['RIPEstat', 'https://stat.ripe.net/{raw}'],
    ['PeeringDB', 'https://www.peeringdb.com/asn/{asnum}'],
    ['IPinfo', 'https://ipinfo.io/{raw}'],
    ['Cloudflare Radar', 'https://radar.cloudflare.com/as{asnum}'],
  ] },
  { group: 'Exposed hosts & reputation', items: [
    ['Shodan (asn:)', 'https://www.shodan.io/search?query=asn%3A{raw}'],
    ['Censys hosts', 'https://search.censys.io/search?resource=hosts&q=autonomous_system.asn%3A{asnum}'],
    ['Spamhaus ASN-DROP list', 'https://www.spamhaus.org/drop/asndrop.json'],
    ['Google (exact)', G('%22{q}%22')],
  ] },
];
PIVOTS.tracker = [
  { group: 'Sites sharing this ID', items: [
    ['PublicWWW (source search)', 'https://publicwww.com/websites/%22{q}%22/'],
    ['BuiltWith relationships', 'https://builtwith.com/relationships/tag/{q}'],
    ['SpyOnWeb', 'https://spyonweb.com/{q}'],
    ['AnalyzeID', 'https://analyzeid.com/id/{q}'],
    ['DNSlytics reverse analytics', 'https://dnslytics.com/reverse-analytics', 'paste'],
    ['urlscan.io search', 'https://urlscan.io/search/#%22{q}%22'],
  ] },
  { group: 'Search', items: [
    ['Google (exact)', G('%22{q}%22')], ['Bing (exact)', 'https://www.bing.com/search?q=%22{q}%22'],
    ['GitHub code', 'https://github.com/search?q=%22{q}%22&type=code'],
  ] },
];
PIVOTS.wallet = [
  { group: 'Explorers', items: [
    ['Blockchair (multi-chain)', 'https://blockchair.com/search?q={q}'],
    ['Tronscan (TRON)', 'https://tronscan.org/#/address/{q}'],
    ['Litecoin Space (LTC)', 'https://litecoinspace.org/address/{q}'],
    ['Dogechain (DOGE)', 'https://dogechain.info/address/{q}'],
    ['Arkham Intel', 'https://intel.arkm.com/explorer/address/{q}'],
  ] },
  { group: 'Abuse & sanctions', items: [
    ['Chainabuse reports', 'https://www.chainabuse.com/address/{q}'],
    ['OFAC sanctions search', 'https://sanctionssearch.ofac.treas.gov/', 'paste'],
    ['OpenSanctions', 'https://www.opensanctions.org/search/?q={q}'],
    ['Google (exact)', G('%22{q}%22')],
  ] },
];
PIVOTS.iban = [
  { group: 'Validate & identify the bank', items: [
    ['IBAN checker (iban.com)', 'https://www.iban.com/iban-checker', 'paste'],
    ['OpenIBAN (bank code, BIC)', 'https://openiban.com/validate/{q}?getBIC=true&validateBankCode=true'],
  ] },
  { group: 'Mentions & due diligence', items: [
    ['Google (exact)', G('%22{q}%22')], ['Bing (exact)', 'https://www.bing.com/search?q=%22{q}%22'],
    ['OpenSanctions', 'https://www.opensanctions.org/search/?q={q}'],
    ['OCCRP Aleph', 'https://aleph.occrp.org/search?q={q}'],
  ] },
];
// ---- extra sources for existing types
PIVOTS.domain.push({ group: 'More infrastructure intel', items: [
  ['Cloudflare Radar', 'https://radar.cloudflare.com/domains/domain/{q}'],
  ['host.io', 'https://host.io/{q}'],
  ['DNSlytics', 'https://dnslytics.com/domain/{q}'],
  ['Pulsedive', 'https://pulsedive.com/indicator/?ioc={q}'],
  ['MXToolbox', 'https://mxtoolbox.com/SuperTool.aspx?action=mx%3a{q}&run=toolpage'],
  ['DNSViz (DNSSEC)', 'https://dnsviz.net/d/{q}/dnssec/'],
  ['FOFA', 'https://en.fofa.info/result?qbase64={fofa}'],
  ['Wayback: every archived URL', 'https://web.archive.org/web/*/{q}/*'],
  ['Wayback: robots.txt history', 'https://web.archive.org/web/*/{q}/robots.txt'],
] });
PIVOTS.ipv4.push({ group: 'Exposure, anonymizers & routing', items: [
  ['Shodan InternetDB (JSON)', 'https://internetdb.shodan.io/{q}'],
  ['Criminal IP', 'https://www.criminalip.io/asset/report/{q}'],
  ['Pulsedive', 'https://pulsedive.com/indicator/?ioc={q}'],
  ['Spur (VPN / proxy context)', 'https://spur.us/context/{q}'],
  ['Tor ExoneraTor (was it a relay?)', 'https://metrics.torproject.org/exonerator.html?ip={q}&timestamp={recent}&lang=en'],
  ['Cloudflare Radar', 'https://radar.cloudflare.com/ip/{q}'],
  ['FOFA', 'https://en.fofa.info/result?qbase64={fofa}'],
] });
PIVOTS.email.push({ group: 'Code & reputation', items: [
  ['GitHub commits by this email', 'https://github.com/search?q=author-email%3A{q}&type=commits'],
  ['GitHub users (in:email)', 'https://github.com/search?q={q}+in%3Aemail&type=users'],
  ['EmailRep (JSON)', 'https://emailrep.io/{q}'],
  ['Mail domain in Recon-style tools (MXToolbox)', 'https://mxtoolbox.com/SuperTool.aspx?action=mx%3a{domain}&run=toolpage'],
] });
PIVOTS.username.push({ group: 'Code, archives & aggregators', items: [
  ['GitHub commits by author', 'https://github.com/search?q=author%3A{q}&type=commits'],
  ['IDCrawl', 'https://www.idcrawl.com/u/{q}'],
  ['Wayback: X / Twitter profile', 'https://web.archive.org/web/*/twitter.com/{q}*'],
  ['Wayback: Instagram profile', 'https://web.archive.org/web/*/instagram.com/{q}*'],
  ['Namechk', 'https://namechk.com/', 'paste'],
] });
PIVOTS.location.push({ group: 'Live activity & terrain', items: [
  ['Flightradar24', 'https://www.flightradar24.com/{lat},{lon}/10'],
  ['MarineTraffic', 'https://www.marinetraffic.com/en/ais/home/centerx:{lon}/centery:{lat}/zoom:10'],
  ['NASA FIRMS (active fires)', 'https://firms.modaps.eosdis.nasa.gov/map/#d:24hrs;@{lon},{lat},10.0z'],
  ['Copernicus Browser (Sentinel)', 'https://browser.dataspace.copernicus.eu/?zoom=14&lat={lat}&lng={lon}'],
  ['Zoom Earth', 'https://zoom.earth/maps/satellite/#view={lat},{lon},14z'],
  ['PeakVisor (mountain panorama)', 'https://peakvisor.com/panorama.html?lat={lat}&lng={lon}'],
  ['ShadeMap (shadows)', 'https://shademap.app/@{lat},{lon},15z'],
] });
PIVOTS.person.push({ group: 'Ownership & influence', items: [
  ['LittleSis (power networks)', 'https://littlesis.org/search?q={q}'],
  ['Open Ownership register', 'https://register.openownership.org/search?q={q}'],
  ['UK Companies House officers', 'https://find-and-update.company-information.service.gov.uk/search/officers?q={q}'],
  ['Interpol Red Notices', 'https://www.interpol.int/How-we-work/Notices/Red-Notices/View-Red-Notices', 'paste'],
] });
PIVOTS.org.push({ group: 'Ownership & regional registries', items: [
  ['Open Ownership register', 'https://register.openownership.org/search?q={q}'],
  ['LittleSis', 'https://littlesis.org/search?q={q}'],
  ['North Data (EU)', 'https://www.northdata.com/{q}'],
  ['Pappers (France)', 'https://www.pappers.fr/recherche?q={q}'],
  ['CourtListener', 'https://www.courtlistener.com/?q=%22{q}%22'],
] });
PIVOTS.cve.push({ group: 'Advisories & detection', items: [
  ['OSV', 'https://osv.dev/list?q={q}'],
  ['GitHub advisories', 'https://github.com/advisories?query={q}'],
  ['CVE Details', 'https://www.cvedetails.com/cve/{q}/'],
  ['Sploitus', 'https://sploitus.com/?query={q}#exploits'],
  ['Nuclei templates', 'https://github.com/search?q=repo%3Aprojectdiscovery%2Fnuclei-templates+{q}&type=code'],
] });
PIVOTS.hash.push({ group: 'More sandboxes', items: [
  ['Joe Sandbox', 'https://www.joesandbox.com/search?q={q}'],
  ['Kaspersky OpenTIP', 'https://opentip.kaspersky.com/{q}/'],
  ['Pulsedive', 'https://pulsedive.com/indicator/?ioc={q}'],
] });
PIVOTS.btc.push({ group: 'More tracing', items: [
  ['Blockchair', 'https://blockchair.com/bitcoin/address/{q}'],
  ['BitcoinWhosWho', 'https://www.bitcoinwhoswho.com/address/{q}'],
] });
PIVOTS.eth.push({ group: 'More tracing', items: [
  ['MetaSleuth (fund flow)', 'https://metasleuth.io/result/eth/{q}'],
  ['Blockchair', 'https://blockchair.com/ethereum/address/{q}'],
] });
PIVOTS.ipv6 = PIVOTS.ipv4;
PIVOTS.document = PIVOTS.keyword;
PIVOTS.other = PIVOTS.keyword;
PIVOTS.domain.push(EXACT_SEARCH);
PIVOTS.username.push(EXACT_SEARCH);

/** Variables available to URL templates for a given selector. */
function pivotVars(type, value) {
  const v = cleanValue(type, value);
  const vars = { q: encodeURIComponent(v), raw: v, qq: encodeURIComponent(encodeURIComponent(v)) };
  if (type === 'email') { vars.gravatar = sha256(v.trim().toLowerCase()); vars.domain = v.split('@')[1] || ''; }
  if (type === 'url' || type === 'image') vars.host = encodeURIComponent(hostOf(v) || '');
  if (type === 'location') { const c = parseCoords(v); if (c) { vars.lat = c.lat; vars.lon = c.lon; } }
  if (type === 'phone') vars.digits = phoneDigits(v).replace(/^00/, '');
  if (type === 'cve') vars.cvenum = v.replace(/^CVE-/i, '');
  if (type === 'hash') { const algo = { 32: 'md5', 40: 'sha1', 64: 'sha256' }[v.length] || 'sha256'; vars.bazaar = encodeURIComponent(`${algo}:${v}`); }
  if (type === 'username') vars.q = encodeURIComponent(v.replace(/^@/, ''));
  if (type === 'asn') vars.asnum = v.replace(/^AS/i, '');
  if (type === 'domain') vars.fofa = encodeURIComponent(b64encode(`domain="${v}"`));
  if (type === 'ipv4' || type === 'ipv6') { vars.fofa = encodeURIComponent(b64encode(`ip="${v}"`)); vars.recent = new Date(Date.now() - 3 * 86400000).toISOString().slice(0, 10); }
  return vars;
}
const fillTemplate = (tpl, vars) => tpl.replace(/\{(\w+)\}/g, (_, k) => vars[k] ?? '');

/** Resolved resource groups for a selector: [{group, items:[{name,url,paste}]}]. */
function pivotsFor(type, value) {
  const vars = pivotVars(type, value);
  const groups = PIVOTS[type] || PIVOTS.keyword;
  return groups.map((g) => ({ group: g.group, items: g.items.map(([name, tpl, flag]) => ({ name, url: fillTemplate(tpl, vars), paste: flag === 'paste' })) }));
}

/** Related selectors worth pivoting to (e.g. email → its domain). */
function relatedSelectors(type, value) {
  const v = cleanValue(type, value), out = [];
  if (type === 'email') { const d = v.split('@')[1]; if (d) out.push(['domain', d]); const u = v.split('@')[0]; if (u && u.length > 2) out.push(['username', u.replace(/\+.*$/, '')]); }
  if (type === 'url' || type === 'image') { const h = hostOf(v); if (h) out.push([isIPv4(h) ? 'ipv4' : 'domain', h]); }
  if (type === 'domain') { const p = v.split('.'); if (p.length > 2) out.push(['domain', p.slice(-2).join('.')]); }
  return out;
}

// Country calling codes (most common) for phone context.
const CALLING_CODES = { 1: 'USA / Canada / NANP', 7: 'Russia / Kazakhstan', 20: 'Egypt', 27: 'South Africa', 30: 'Greece', 31: 'Netherlands', 32: 'Belgium', 33: 'France', 34: 'Spain', 36: 'Hungary', 39: 'Italy', 40: 'Romania', 41: 'Switzerland', 43: 'Austria', 44: 'United Kingdom', 45: 'Denmark', 46: 'Sweden', 47: 'Norway', 48: 'Poland', 49: 'Germany', 51: 'Peru', 52: 'Mexico', 53: 'Cuba', 54: 'Argentina', 55: 'Brazil', 56: 'Chile', 57: 'Colombia', 58: 'Venezuela', 60: 'Malaysia', 61: 'Australia', 62: 'Indonesia', 63: 'Philippines', 64: 'New Zealand', 65: 'Singapore', 66: 'Thailand', 81: 'Japan', 82: 'South Korea', 84: 'Vietnam', 86: 'China', 90: 'Türkiye', 91: 'India', 92: 'Pakistan', 93: 'Afghanistan', 94: 'Sri Lanka', 95: 'Myanmar', 98: 'Iran', 211: 'South Sudan', 212: 'Morocco', 213: 'Algeria', 216: 'Tunisia', 218: 'Libya', 220: 'Gambia', 221: 'Senegal', 233: 'Ghana', 234: 'Nigeria', 237: 'Cameroon', 249: 'Sudan', 251: 'Ethiopia', 254: 'Kenya', 255: 'Tanzania', 256: 'Uganda', 260: 'Zambia', 263: 'Zimbabwe', 351: 'Portugal', 352: 'Luxembourg', 353: 'Ireland', 354: 'Iceland', 355: 'Albania', 356: 'Malta', 357: 'Cyprus', 358: 'Finland', 359: 'Bulgaria', 370: 'Lithuania', 371: 'Latvia', 372: 'Estonia', 373: 'Moldova', 374: 'Armenia', 375: 'Belarus', 376: 'Andorra', 380: 'Ukraine', 381: 'Serbia', 382: 'Montenegro', 385: 'Croatia', 386: 'Slovenia', 387: 'Bosnia & Herzegovina', 389: 'North Macedonia', 420: 'Czechia', 421: 'Slovakia', 852: 'Hong Kong', 853: 'Macau', 855: 'Cambodia', 856: 'Laos', 880: 'Bangladesh', 886: 'Taiwan', 960: 'Maldives', 961: 'Lebanon', 962: 'Jordan', 963: 'Syria', 964: 'Iraq', 965: 'Kuwait', 966: 'Saudi Arabia', 967: 'Yemen', 968: 'Oman', 970: 'Palestine', 971: 'United Arab Emirates', 972: 'Israel', 973: 'Bahrain', 974: 'Qatar', 975: 'Bhutan', 976: 'Mongolia', 977: 'Nepal', 992: 'Tajikistan', 993: 'Turkmenistan', 994: 'Azerbaijan', 995: 'Georgia', 996: 'Kyrgyzstan', 998: 'Uzbekistan' };
function phoneCountry(v) {
  const s = String(v).trim();
  if (!/^(\+|00)/.test(s)) return null;
  const d = phoneDigits(s).replace(/^00/, '');
  for (const len of [3, 2, 1]) { const cc = d.slice(0, len); if (CALLING_CODES[cc]) return { cc: '+' + cc, country: CALLING_CODES[cc], national: d.slice(len) }; }
  return null;
}
