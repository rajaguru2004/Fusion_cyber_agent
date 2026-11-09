# Threat-intel data sources and the master-server intelligence pipeline (state as of 9 November 2026)

Scope and method: I fetched terms pages, licence files and docs on 9 Nov 2026 unless a finding says otherwise. "Via search snippet" means I could not open the page itself (JS-rendered, bot-blocked or out of budget), so the wording came from a search-result extract; re-verify those before signing contracts. Licence files and repo activity dates were read straight from the repositories (raw LICENSE files, PyPI metadata, GitHub commit Atom feeds). The web-search budget ran out near the end of the session, so a few platform details are listed as Gaps. None of this is legal advice. The commercial classifications are a reading of the published terms, to confirm with counsel or the vendor.

---

## 1. Feeds: current (2025-2026) terms for commercial use, authentication, rate limits and update frequency

### Takeaway
Free threat-intel terms tightened in 2025-2026. abuse.ch now requires authentication for all access, and commercial use of URLhaus, MalwareBazaar and ThreatFox goes through a paid Spamhaus subscription. Only Feodo Tracker, SSLBL and YARAify stay CC0 for commercial use. Most popular free tiers forbid commercial use or redistribution: the VirusTotal public API, OTX, AbuseIPDB free, Censys free, the GreyNoise free tier and CrowdSec free keys. Data the company can legally ship inside a paid agent today is mostly CC0, BSD or CC-BY material: Feodo/SSLBL/YARAify, Spamhaus DROP (with attribution), ET Open IP lists, CISA KEV, MISP warninglists, DB-IP Lite, IPinfo Lite and Malpedia's signator rules. The company's own sensor and customer telemetry is also safe to ship. Everything else needs a paid or partner licence.

### Cited Findings

#### abuse.ch (URLhaus, MalwareBazaar, ThreatFox, Feodo Tracker, SSLBL, YARAify)
- The current Terms of Use show "Last Updated: 21st October 2026" and "Effective Date: 4th November 2025". Spamhaus Technology Limited "acts as the primary licensee of the abuse.ch datasets" (s.1). — [abuse.ch Terms of Use](https://abuse.ch/terms-of-use/)
- Authentication: access is "provided only to" users authenticated through the portal at auth.abuse.ch (s.2.1). — [abuse.ch Terms of Use](https://abuse.ch/terms-of-use/)
- Non-commercial use and fair use: "Authenticated Users may access the Platforms for not-for-profit purposes", "subject to usage limitations imposed by abuse.ch and/or Spamhaus" (s.3.1). The limits are "defined as volumes of Queries and Exports reasonably expected for non-commercial or non-profit purposes", and "Exceeding these limits may result in restricted access" (s.3.2). No numeric thresholds are published. — [abuse.ch Terms of Use](https://abuse.ch/terms-of-use/)
- CC0 datasets: Feodo Tracker, SSL Blacklist and YARAify are "free to use without limitations according to Creative Commons principles (CC0)" "for both commercial and non-commercial purposes". They are "served as it is on best effort", and abuse.ch "cannot be held liable for any false positive or damage" (s.3.4). The terms state no licence for MalwareBazaar, URLhaus or ThreatFox. — [abuse.ch Terms of Use](https://abuse.ch/terms-of-use/)
- Commercial use: commercial use of MalwareBazaar, URLhaus and ThreatFox "may require a paid subscription, which will be managed by Spamhaus, and will be subject to separate terms and conditions" (s.4.1). Commercial users can qualify for free use after they "contribute consistently over a period of six months", paying via Spamhaus during that period. A review "acting in our or their sole discretion" follows (s.4.2). — [abuse.ch Terms of Use](https://abuse.ch/terms-of-use/)
- AI and scraping restrictions: the data "may not be used by users to customise, train … or otherwise improve any artificial intelligence model or product" without "Spamhaus' express prior written consent" (s.7.3). Section 7 also bars high-volume automated access such as scrapers and the removal of copyright notices. — [abuse.ch Terms of Use](https://abuse.ch/terms-of-use/)
- Timeline: the "Community First" post of 18 Nov 2024 announced that authentication would become mandatory from 30 June 2025. — [abuse.ch blog](https://abuse.ch/blog/community-first/). Elastic made the Auth-Key a required setting in its abuse.ch integration because of this change. — [elastic/integrations #14277](https://github.com/elastic/integrations/issues/14277)
- Later abuse.ch posts: "Introducing: abuse.ch's Hunting Platform" (11 Mar 2025), "Creating sustainability for abuse.ch and its community" (29 Jul 2025), which says "abuse.ch is currently undergoing significant changes", and "Introducing the abuse.ch Community Hub" (28 Jul 2026). — [abuse.ch blog index](https://abuse.ch/blog/)
- URLhaus API page:
  - "In order to interact with the URLhaus API, you need to obtain an Auth-Key first." The key is free, and every dataset download must include it.
  - "This API is available free of charge under the fair use principles."
  - "Use of the API by companies, networks, or individuals with commercial or for-profit needs may require a paid subscription for the enhanced abuse.ch commercial API", which offers better reliability and "a unified query language across all abuse.ch APIs".
  - Database dumps (CSV/JSON) "are generated every 5 minutes. Please do not fetch it more often than every 5 minutes". The RPZ zone and Snort/Suricata rules are also regenerated every 5 minutes, and the ClamAV signature database "gets updated once per minute".

  — [URLhaus API](https://urlhaus.abuse.ch/api/)
- Spamhaus commercial abuse.ch API: it covers MalwareBazaar (samples and hash lookups), ThreatFox (IoCs) and URLhaus (URLs). "Trial the commercial abuse.ch APIs, free for 30 days. No credit card details required." Pricing is quote-only: "request a quote in the Customer Portal". — [Spamhaus abuse.ch API](https://www.spamhaus.com/data-access/abusech-api/)
- Third-party summaries disagree: one eSecurityPlanet table still calls URLhaus "free for both commercial and non-commercial use", which conflicts with the primary terms above. — [eSecurityPlanet](https://www.esecurityplanet.com/products/threat-intelligence-feeds/) vs [abuse.ch Terms](https://abuse.ch/terms-of-use/)
- YARAhub/YARAify rules carry per-author licences, including CC BY-NC-SA 4.0 ("no commercial"). "You are obliged to respect the license agreement chosen by the author of the YARA rule" (via search snippet). — [YARAify FAQ](https://yaraify.abuse.ch/faq/)

#### AbuseIPDB
- Plans:

  | Plan | Price | Checks/reports per day | Block checks per day | Blacklist downloads per day | Other |
  |---|---|---|---|---|---|
  | Individual (free) | $0 | 1,000 | 100 | 5, up to 10,000 IPs | 5 bulk reports/day |
  | Basic | $25/month or $228/year | 10,000 | not recorded | 100, up to 100,000 IPs | customisable blacklist |
  | Premium | $99/month or $1,068/year | 50,000 | not recorded | 500, up to 500,000 IPs | |
  | Enterprise | custom | | | | "direct data access" for ISPs and enterprises |

  — [AbuseIPDB pricing](https://www.abuseipdb.com/pricing)
- Terms, "Last Updated: 3/15/2023":
  - s.7: "You may not use Free plans for commercial purposes". Commercial users must subscribe to Basic or higher.
  - s.9: you may not "reproduce, duplicate, copy, sell, resell or exploit any portion of the Website (including the API and associated data)" without express permission.
  - s.6: using multiple accounts to increase quota is "STRICTLY PROHIBITED".
  - s.4: reporters grant AbuseIPDB an "irrevocable, perpetual, sublicensable, transferable, non-exclusive, and royalty-free worldwide right and license" to submitted reports.

  — [AbuseIPDB Terms](https://www.abuseipdb.com/legal)

#### Spamhaus DROP (EDROP merged)
- DROP is "available at no cost, regardless of size or business type". "eDROP data was combined into the DROP list on 10 April 2024". — [Spamhaus DROP](https://www.spamhaus.org/blocklists/do-not-route-or-peer/)
- Format and freshness: the free data is "provided in JSON format", and text files "will be deprecated". Listings "are re-evaluated on a daily basis". Without regular updates the list "can cause problems". — [Spamhaus DROP](https://www.spamhaus.org/blocklists/do-not-route-or-peer/)
- Fetch guidance on the same page conflicts: "Please DO NOT auto-fetch the DROP list more than once per hour!" vs "should not be downloaded from our website more than once per day". — [Spamhaus DROP](https://www.spamhaus.org/blocklists/do-not-route-or-peer/)
- Product use: "credit for the use must be given to The Spamhaus Project", and "the date and copy text should remain with the file and data". — [Spamhaus DROP](https://www.spamhaus.org/blocklists/do-not-route-or-peer/)
- DROP Terms of Use: "The DROP Lists are provided to you free of charge subject to these Terms" (s.2.1). The lists are protected by copyright and database right, and nothing grants a licence in them (s.3.1). The "Spamhaus" name may not be used in marketing or commercial materials (s.3.2). — [Spamhaus DROP terms (served at the drop-fair-use-policy URL)](https://www.spamhaus.org/blocklists/drop-fair-use-policy/)

#### FireHOL IP lists
- "IP Lists are a property of their maintainers", "provided and maintained by their respective owners". FireHOL's own software is GPLv2, and the site is "provided as-is, without any warranty". To unlist an aggregated IP "you will either have to whitelist it using your own means, or wait for the aggregation period to expire." — [FireHOL IP lists](https://iplists.firehol.org/)

#### Emerging Threats (Proofpoint) Open
- Live server check on 9 Nov 2026:
  - `blockrules/compromised-ips.txt` exists, about 511 lines, Last-Modified 6 Nov 2026.
  - `fwrules/emerging-Block-IPs.txt` exists, Last-Modified 6 Nov 2026.
  - Both need no key.

  — [ET blockrules/](https://rules.emergingthreats.net/blockrules/), [ET fwrules/](https://rules.emergingthreats.net/fwrules/)
- The `emerging-Block-IPs.txt` header lists its inputs as "Spam nets identified by Spamhaus", "Top Attackers listed by DShield" and "Abuse.ch". It carries a BSD licence: "Copyright (c) 2003-2026, Emerging Threats … Redistribution and use in source and binary forms, with or without modification, are permitted provided that…". — [emerging-Block-IPs.txt](https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt)
- The ET Open ruleset LICENSE says: "This distribution may contain rules under three different licenses". SIDs 1–3464 and 100000000–100000908 are GPLv2, SIDs 2000000–2799999 are BSD, and SIDs 2800000–2900000 are under the ETPRO licence. — [ET Open LICENSE](https://rules.emergingthreats.net/open/suricata-7.0.3/LICENSE)
- Update cadence: "ET is updated once daily on weekdays". Check `version.txt` first, and "We do not recommend downloading the ruleset more frequently than once per hour". — [ET OPEN download instructions](https://rules.emergingthreats.net/OPEN_download_instructions.html)
- ET Pro reputation lists are published hourly and need "an authorized license key issued for evaluation purposes or through purchase" (via search snippet). — [Proofpoint ET RepList brief](https://proofpoint.com/sites/default/files/technical-briefs/pfpt-us-tb-emerging-threats-intellience-replist.pdf)

#### AlienVault OTX (LevelBlue)
- The EULA says:
  - "OTX is free to end users for non-commercial use."
  - The grant is "limited, terminable, non-exclusive, non-transferable".
  - Users may not "license, sell, rent, lease, transfer, assign, distribute, display, disclose, or otherwise commercially exploit OTX" "or otherwise make it available to any third party (e.g., as a service bureau)".
  - Submitted content "may be retained, used, and distributed at AlienVault's sole discretion".
  - The contracting party is AlienVault, Inc., and the page shows no effective date.

  — [LevelBlue OTX EULA](https://levelblue.com/terms/otx-eula)
- Conflicting vendor marketing: a LevelBlue blog says service providers can deliver OTX data to customers over STIX/TAXII (via search snippet). This is not a licence grant. — [LevelBlue blog](https://www.levelblue.com/blogs/levelblue-blog/otx-is-now-a-free-stix-taxii-server)

#### CrowdSec CTI and blocklists
- Pricing FAQ: "Can I use CrowdSec data commercially as part of my offering?" Answer: "Yes, by subscribing to our Partnership Program, you can embed CrowdSec security data into your solutions … make commercial use of it, whether for reselling or other purposes." Partner pricing is on request. — [CrowdSec pricing](https://www.crowdsec.net/pricing)
- List prices: IP Reputation API "from $49/month for 5,000 queries"; Platinum Blocklists "from $1900/month for SMB"; Local CTI replication "from $9K/month". — [CrowdSec pricing](https://www.crowdsec.net/pricing)
- Free CTI key: "Community Plan Free Key - 40 / month · Testing integrations, personal servers, ad-hoc lookups" (via search snippet). Other CrowdSec pages cite 1,500 per month or 50 per day, so the figure is inconsistent. — [CrowdSec CTI keys doc](https://doc.crowdsec.net/u/console/cti/cti_api_keys)
- The Security Engine itself is MIT-licensed. — [crowdsec LICENSE](https://github.com/crowdsecurity/crowdsec/blob/master/LICENSE)

#### GreyNoise
- EULA, "Last modified: May 7, 2025":
  - Free Customers get a "non-exclusive, non-transferable revocable license", and "such use is limited to your internal business purposes or noncommercial purposes such as academic research" (s.3.1).
  - Users may not "rent, lease, lend, sell, license, sublicense, assign, distribute, publish, transfer" the platform, or create "Derived Products, other than in accordance with the terms of your Quotation" (s.3.2). Free users have no Quotation.
  - Using GreyNoise data to train AI or ML models is prohibited.

  — [GreyNoise EULA](https://greynoise.io/terms)
- Community API quota: "50 searches per week", shared with the Visualizer (via search snippet; the docs page may be stale). — [GreyNoise docs](https://docs.greynoise.io/docs/using-the-greynoise-community-api)

#### Shodan and Censys (attack-surface data)
- Shodan plans:

  | Plan | Price | Query credits | Commercial use |
  |---|---|---|---|
  | Membership | $49 one-time | 100 | not listed |
  | Freelancer | $69/month | 10,000 | "Commercial Use" |
  | Small Business | $359/month | 200,000 | "Commercial Use" |
  | Corporate | $1,099/month | unlimited | "Commercial Use", plus "InternetDB API Commercial Use" |

  FAQ: "Yes, you can integrate the API in your products as long as the data is attributed to Shodan." — [Shodan billing](https://account.shodan.io/billing)
- Shodan Enterprise: "The Enterprise Data License includes commercial rights, without attribution". InternetDB and CVEDB are described as free for non-commercial use only (via search snippet). — [Shodan enterprise comparison](https://enterprise.shodan.io/product-comparison)
- Censys ToS: "Censys Free Customers, Censys Researcher Customers and all unregistered Customers are expressly prohibited from using the Service and Censys Data for commercial purposes of any kind, including internal business purposes" (via search snippet). — [Censys ToS](https://censys.com/terms-of-service/)
- Censys staff said API access was removed for Free users in November 2024. — [Censys community](https://community.censys.com/search-findings-use-cases-and-queries-32/while-generating-api-key-for-free-it-shows-you-do-not-have-access-to-the-censys-api-previously-it-was-working-fine-243). The tier table instead says "lookup endpoints only". — [Censys docs](https://docs.censys.com/docs/data-access-tiers-entitlements)

#### VirusTotal
- Public API: "Non-commercial, or academic use", "4 interactions per minute". Private/Premium API: "Commercial or Government use is allowed" under a premium services agreement, "Paid, pricing depends on usage". — [VirusTotal docs: public vs private](https://docs.virustotal.com/docs/difference-public-private)
- API overview (via search snippet): "The Public API must not be used in commercial products or services". It "can not be used as a substitute for antivirus products" or "integrated in any project that may harm the antivirus industry directly or indirectly". "Noncompliance of these terms will result in immediate permanent ban". Multiple accounts are not allowed. — [VirusTotal API overview](https://docs.virustotal.com/docs/api-overview)

#### Hybrid Analysis (CrowdStrike)
- Users must pass a "Vetting Process prior to obtaining an API key or downloading malware samples", and keys may not be shared (via search snippets). — [Anomali HA integration doc](https://docs.anomali.com/Content/ThreatStream%20Administration/Integrations/Hybrid_Analysis.htm)
- A third-party listing tells users to "only use these samples for research purposes". — [SourceForge listing](https://sourceforge.net/software/product/Hybrid-Analysis/)
- Anomali reports public-API limits of 200 requests per minute and 2,000 per hour. — [Anomali](https://docs.anomali.com/Content/ThreatStream%20Administration/Integrations/Hybrid_Analysis.htm)

#### CISA KEV
- The `cisagov/kev-data` repo publishes the catalogue as CSV and JSON plus a schema under CC0 1.0. It is updated whenever the catalogue changes and "should match cisa.gov within minutes". — [cisagov/kev-data](https://github.com/cisagov/kev-data), [README](https://raw.githubusercontent.com/cisagov/kev-data/main/README.md), [Socket](https://socket.dev/blog/cisa-brings-kev-data-to-github)
- One secondary source says BOD 26-04 replaced BOD 22-01 on 10 June 2026. A repo mirror still cites BOD 22-01. Unverified. — [Socket glossary](https://socket.dev/glossary/cisa-kev)

#### Malpedia (Fraunhofer FKIE)
- ToS: "The whole content of the website is released under Creative Common's CC BY-NC-SA 3.0 license." Non-public material is to be treated as "TLP:AMBER (unless designated or agreed upon otherwise)", and "every registration has undergone vetting". — [Malpedia ToS](https://malpedia.caad.fkie.fraunhofer.de/usage/tos)
- The auto-generated YARA rules in `malpedia/signator-rules` "are released under the CC BY-SA 4.0 license, allowing commercial usage". The latest release is dated 2026-05-04 (via search snippet). — [malpedia/signator-rules](https://github.com/malpedia/signator-rules)

#### Mining-pool lists (CoinBlockerLists)
- The project moved from GitHub to GitLab. It ships `list.txt`, `list_optional.txt` and `MiningServerIPList.txt`. — [Netgate forum](https://forum.netgate.com/post/784118)
- A third-party aggregator lists its licence as AGPLv3. I could not verify this against the project LICENSE because GitLab returned 403/Cloudflare challenges. — [threat-hostlist](https://github.com/PeterDaveHello/threat-hostlist)

#### GeoIP: MaxMind GeoLite, IPinfo Lite, DB-IP Lite
- **MaxMind GeoLite EULA, "Updated on: February 12, 2026":**
  - s.3: copyrightable elements "are governed by the Creative Commons License" (CC BY-SA 4.0). Attribution is required, for example "This product includes GeoLite Data created by MaxMind, available from https://www.maxmind.com". A separate "non-exclusive, non-transferable limited license … for your own internal business purposes" also applies.
  - s.6: "Except as explicitly permitted by the Creative Commons License, you will not disclose the Services to any third party without notifying MaxMind … and obtaining MaxMind's prior written consent". Any third parties must be bound by the same duties.
  - s.6: licensees "shall cease use of and destroy (i) any old versions of the Services within thirty (30) days following the release of the updated GeoLite Databases".
  - s.4: no FCRA uses.
  - s.9: "MaxMind reserves the right to stop offering the Services free of charge at any time".

  — [MaxMind GeoLite EULA](https://www.maxmind.com/en/geolite2/eula)
- MaxMind's Commercial Redistribution licence for GeoLite costs "$5,000/year" (Country) or "$10,000/year" (City) per product. "For every product you sell that incorporates the GeoLite database, you must purchase an additional Commercial Redistribution License". Customers must be bound to "Internal Restricted Business Purposes" (via search snippet). — [MaxMind support: Commercial License for GeoLite](https://support.maxmind.com/hc/en-us/articles/4408928143643)
- **IPinfo Lite:** "Our IPinfo Lite data downloads service is released under Creative Commons Attribution-ShareAlike 4.0 International License. Simply credit IPinfo as your data source by including a link to our website on your platform." It combines country and ASN data in CSV, JSON, MMDB and Parquet, downloaded with a token. — [IPinfo Lite database docs](https://ipinfo.io/developers/ipinfo-lite-database). Updated daily for IPv4 and IPv6 (via search snippet). — [ipinfo.io/lite](https://ipinfo.io/lite). Launched 8 May 2025. — [Business Wire syndication](https://business.mammothtimes.com/mammothtimes/article/bizwire-2025-5-8-ipinfo-launches-ipinfo-lite-unlimited-country-level-geolocation-api-and-database-download)
- **DB-IP Lite:** "licensed under a Creative Commons Attribution 4.0 International License … You are free to use this database in your application, provided you give attribution to DB-IP.com". "Lite downloads are updated monthly". — [DB-IP Lite](https://db-ip.com/db/lite.php). A Fedora-legal commenter argued that DB-IP's extra web-app link clause goes beyond CC BY 4.0. — [Fedora legal list](https://lists.fedorahosted.org/archives/list/legal@lists.fedoraproject.org/message/2VFOH3ZEPS2A5XLKS423ZRHZLCIQDYPD)

### Inferences

**Classification for use inside a paid agent product** (my reading of the cited terms):

| Source | Class | Basis / conditions |
|---|---|---|
| Feodo Tracker, SSLBL, YARAify (platform data) | **Free for commercial product** | CC0 per abuse.ch ToU s.3.4. Auth-Key still required. Individual YARAhub rules keep their author's licence, so drop NC-licensed rules. |
| Spamhaus DROP (incl. former EDROP) | **Free for commercial product, with attribution** | "no cost, regardless of size or business type". Credit Spamhaus, keep date/copy text, don't use the Spamhaus name in marketing. Get written confirmation for bulk redistribution, because ToU s.3.1 grants "no licence" in the data. |
| ET Open `compromised-ips.txt`, `emerging-Block-IPs.txt` | **Free for commercial product (BSD)**, with upstream caveat | BSD header, but the content is derived from Spamhaus, DShield and abuse.ch, whose own terms may apply. |
| CISA KEV | **Free for commercial product** | CC0. |
| MISP warninglists (as allowlist data) | **Free for commercial product** | CC0, except the X4BNet-derived list, which is MIT (see Q2). |
| Malpedia signator-rules | **Free for commercial product (share-alike)** | CC BY-SA 4.0. Derived rule files must stay CC BY-SA, with attribution. |
| IPinfo Lite / DB-IP Lite | **Free for commercial product** | CC BY-SA 4.0 / CC BY 4.0, with attribution. IPinfo's share-alike applies to derived datasets. |
| Shodan (Freelancer and above) | **Needs paid licence** | Paid plans allow commercial use and "integrate the API in your products" with attribution. Bulk data or no-attribution use needs the Enterprise Data License. |
| URLhaus, MalwareBazaar, ThreatFox | **Needs paid/commercial licence** | Spamhaus subscription (30-day trial, quote-based). Possibly free after six months of consistent contribution, at abuse.ch/Spamhaus discretion. |
| AbuseIPDB | **Needs paid licence** | Free plans are non-commercial. Basic or higher for commercial use; Enterprise or express permission for redistribution or resale of data. |
| VirusTotal | **Needs paid licence** | The public API is barred from commercial products. Use Premium. |
| CrowdSec CTI / blocklists embedded in a product | **Needs paid licence** | Partnership Program. |
| Censys | **Needs paid licence** | Free tier banned even for internal business use. |
| GreyNoise | **Needs paid licence** for product use | Free tier allows only internal business or non-commercial use, with no redistribution or derived products. Vendor analysts may use it for internal triage. |
| MaxMind GeoLite | **Needs paid licence** to embed in a sold agent | Per-product Commercial Redistribution licence, or use IPinfo Lite / DB-IP Lite instead. The EULA s.6 third-party-disclosure clause conflicts with CC BY-SA and needs legal review. |
| ET Pro / ET Intelligence | **Needs paid licence** | Licence key. |
| AlienVault OTX | **Non-commercial only** | EULA bans commercial exploitation and service-bureau use. Marketing copy conflicts. |
| Malpedia website content / non-public data | **Non-commercial only** | CC BY-NC-SA 3.0; TLP:AMBER for vetted-only material. |
| Hybrid Analysis | **Unclear (likely non-commercial/research)** | Vetting and research-only wording; the ToS could not be read. |
| CoinBlockerLists | **Unclear** | Licence unverified (reportedly AGPLv3). |
| FireHOL aggregates | **Unclear / per-source** | "property of their maintainers". Classify each constituent list separately. |

- For the motivating incident (SSH brute force, cryptominer, C2, persistence), a legally clean v1 bundle could combine:
  - ET compromised IPs (BSD) plus the company's own SSH-attacker telemetry, for brute-forcers.
  - Feodo Tracker and SSLBL (CC0), for botnet C2.
  - Spamhaus DROP, for hijacked netblocks.
  - Self-curated mining-pool domains and IPs from the company's own analysis, instead of an unverified-licence list.
  - Paid add-ons where budget allows: ThreatFox/MalwareBazaar via Spamhaus, for miner family hashes and IOCs, and AbuseIPDB paid plans.
- abuse.ch's six-month contribution path suggests that agent-collected samples could earn free commercial access. Contributing customer-derived samples, however, needs the consent controls described in Q4.
- Respect fetch-rate rules in the master-server scheduler rather than per agent: URLhaus no more than every 5 minutes, DROP at most hourly (daily is safer), ET daily or hourly after a `version.txt` check, and MaxMind's 30-day destruction rule. Agents should only ever pull from the company's server. Fan-out from thousands of agents directly to abuse.ch or Spamhaus would breach fair-use terms and leak customer IPs to third parties.

### Gaps
- abuse.ch numeric query and export limits, and Spamhaus commercial pricing, are not published (quote only).
- I could not read the Hybrid Analysis ToS text: the page is JS-rendered and returned no text.
- I found no OTX API rate limits or EULA effective date.
- I did not verify the composition of FireHOL level1/2/3, or the terms of DShield (SANS ISC), which is an input to ET's block list.
- The CoinBlockerLists licence is unverified (GitLab was blocked).
- CrowdSec's free CTI quota is inconsistent across its docs, and Partnership Program terms are not public.
- The GreyNoise Community quota (50 per week) may be stale.
- I did not verify VirusTotal public API daily or monthly quotas.
- MaxMind commercial redistribution pricing came from a search snippet. How the Feb 2026 EULA's CC BY-SA grant interacts with its s.6 disclosure restriction needs legal review.
- KEV's governing directive (BOD 26-04 vs 22-01) is unverified.

---

## 2. Threat-intel platform on the master server (MISP, OpenCTI, YETI): licences, STIX 2.1/TAXII 2.1 export, curation, scoring, ageing and allowlisting

### Takeaway
MISP (AGPL-3.0) and OpenCTI Community Edition (Apache-2.0) are both active and suitable. YETI (Apache-2.0) is a lighter option. AGPL obligations only bite if the company modifies MISP and lets customers interact with that modified instance over the network. Running MISP internally behind a proprietary export API is the low-risk pattern. OpenCTI has native TAXII 2.1 collections, live streams and built-in indicator decay rules. MISP has warninglists (CC0) and a decaying model. Together these give the curation tools needed to stop CDN and cloud IPs reaching agents.

### Cited Findings
- **MISP licence and activity.** MISP is under the GNU AGPL v3. — [MISP LICENSE](https://github.com/MISP/MISP/blob/2.5/LICENSE). The 2.5 branch had commits on 1 Nov 2026. — [MISP commits feed](https://github.com/MISP/MISP/commits/2.5.atom)
- **AGPL §13** says: "if you modify the Program, your modified version must prominently offer all users interacting with it remotely through a computer network … an opportunity to receive the Corresponding Source of your version by providing access to the Corresponding Source from a network server at no charge". — [GNU AGPL v3 text](https://www.gnu.org/licenses/agpl-3.0.txt)
- **OpenCTI licence.** "The OpenCTI Community Edition is licensed under the Apache License, Version 2.0", while "The OpenCTI Enterprise Edition is licensed under the OpenCTI Enterprise Edition License". Files without a licence header belong to the CE under Apache 2.0. Copyright is "2021-2026 Filigran SAS". — [OpenCTI LICENSE](https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE). Commits are current as of 9 Nov 2026. — [OpenCTI commits feed](https://github.com/OpenCTI-Platform/opencti/commits/master.atom)
- **YETI** is Apache-2.0 with commits on 28 Oct 2026. — [YETI LICENSE](https://github.com/yeti-platform/yeti/blob/main/LICENSE), [YETI commits feed](https://github.com/yeti-platform/yeti/commits/main.atom)
- **OpenCTI sizing** (latest docs): Core "2 cores and at least 8GB RAM" (stateless); MinIO/S3 1 core, ≥128 MB RAM, ≥16 GB SSD. The 5.8 docs add Elasticsearch at 2 cores, ≥8 GB RAM and ≥16 GB SSD; Redis at 1 core and ≥1 GB; RabbitMQ at 1 core and ≥512 MB; and workers at 1 core and ≥128 MB each (via search snippets). — [OpenCTI deployment overview](https://docs.opencti.io/latest/deployment/overview/), [5.8.X overview](https://docs.opencti.io/5.8.X/deployment/overview/)
- **OpenCTI data sharing.** Three native mechanisms, under "Data > Data sharing":
  - TAXII 2.1 collections serving STIX 2.1 bundles, consumed with an access token. Pagination "should be handled by the consumer", and nested dependencies "are not always contained/resolved in the bundle".
  - Live streams carrying "create, update and delete events".
  - CSV feeds (default cap 5,000 entries, `DATA_SHARING__MAX_CSV_FEED_RESULT`).

  Filters cover entity types, labels and marking definitions. — [OpenCTI data sharing docs](https://docs.opencti.io/latest/usage/feeds/)
- **OpenCTI decay rules** (via search snippets of the docs):
  - "Built-in decay rules are applied by default based on an indicator's main observable type".
  - The lifetime is "the time (in days) during which the value will be lowered until it reaches 0".
  - An indicator is revoked at the first of two events: reaching the revoke score, or reaching valid_until.
  - Indicators start at the source's score, or 50 by default.
  - "Only new indicators created are impacted when decay rules are changed or created".
  - A new score resets the decay.

  — [OpenCTI decay rules](https://docs.opencti.io/latest/administration/decay-rules/), [Indicators lifecycle](https://docs.opencti.io/latest/usage/indicators-lifecycle), [Filigran blog](https://filigran.io/blog/introducing-decay-rules-implementation-for-indicators-in-opencti) ("four built-in decay rules")
- **MISP decaying model:**
  - "score = base_score * P", where P depends on `lifetime` and `decay_speed`.
  - The base score comes from taxonomy tags such as admiralty-scale source reliability.
  - A sighting means "the score is refreshed back to the value of the original base_score and a new decay is initiated from that point forward".
  - `attribute/restSearch` supports `includeDecayScore`, `excludeDecayed` ("Filter out all expired IOCs"), `decayingModel` and `modelOverrides`.

  — [MISP: Decaying of Indicators](https://www.misp-project.org/2019/09/12/Decaying-Of-Indicators.html)
- **MISP warninglists** are licensed CC0 1.0. "The X4BNet-derived VPN and datacenter data retain their upstream MIT license notice". The lists cover:
  - CDNs and WAFs: Akamai, Cloudflare, Fastly, Imperva, Sucuri, Bunny, Zscaler and others.
  - Clouds: AWS, Azure (incl. China, Germany and US Gov), GCP, OCI, DigitalOcean and Linode.
  - Public DNS resolvers.
  - Top-domain lists: Tranco, Majestic, Umbrella, Cloudflare Radar and CrUX.
  - Reserved address space: RFC1918, RFC5735, RFC6598 and others.
  - Scanners: Shadowserver, Shodan, Censys, Rapid7 and Onyphe.
  - EICAR and empty-file hashes.

  Each list is typed `false_positive` or `known` (shared infrastructure), and the API uses the lists to filter false positives. — [misp-warninglists](https://github.com/MISP/misp-warninglists)
- **STIX conversion in MISP.** `misp-stix` (BSD-2-Clause) converts MISP to and from STIX 1.1.1/1.2 and STIX 2.0/2.1, and "is used by the MISP core software to perform STIX conversion". — [misp-stix](https://github.com/MISP/misp-stix)
- **TAXII 2.1** is an OASIS Standard dated 10 June 2021. Its features include:
  - API Roots group collections.
  - `added_after` "filters objects to only include those objects added after the specified timestamp" (server receipt time).
  - Results "MUST be sorted in ascending order by the date it was added".
  - `X-TAXII-Date-Added-First/Last` headers.
  - `more`/`next` pagination.
  - `match[version]`.
  - A manifest endpoint "to decide whether it's worth retrieving the actual objects".

  It has no deletion feed and no retention guarantee. — [OASIS TAXII 2.1](https://docs.oasis-open.org/cti/taxii/v2.1/os/taxii-v2.1-os.html)

### Inferences
- **Licence posture.** Running unmodified MISP internally creates no AGPL source-offer duty, because customers never interact with it remotely. Keep MISP and MWDB (see Q3) behind a proprietary "intel compiler" service that exports agent bundles. Don't expose a modified MISP UI to customers. If MISP is patched, either upstream the patches or publish them. OpenCTI CE has no copyleft, but avoid EE-headed files unless the EE licence is purchased.
- **Suggested shape.** OpenCTI (or MISP) as the system of record, with feeds ingested through connectors. A separate, small, proprietary curation and export service then reads indicators above a score threshold, applies allowlists, and compiles a signed agent bundle (see Q5). The agent bundle should not be raw STIX: agents need compact typed sets (IP radix tree, hash set, YARA-X compiled rules). TAXII 2.1 `added_after` is a good model for the master-to-SOC/partner interface, not necessarily for agents.
- **Scoring and ageing defaults** (my proposal, to tune):
  - IPs: short lifetime (days to weeks) and decay unless re-sighted. Cloud and VPS IPs churn quickly.
  - Domains and URLs: weeks.
  - File hashes (SHA-256): effectively non-decaying, but revocable.
  - YARA rules: versioned, never auto-expired.
  - Use sightings from agents to refresh scores. That is the network effect (Q4).
- **Allowlisting.** Before anything ships to agents, run three filters:
  - Hard-block anything matching MISP warninglists of type `false_positive`, plus local mandatory allowlists: the company's master-server IPs, distro mirrors used by apt/dnf, cloud metadata/link-local addresses, RFC1918 and customer-declared admin IPs.
  - Downgrade `known` (shared hosting, CDN, cloud) hits to "alert only, never auto-block".
  - Require at least two independent sources or a high-confidence first-party detection before an IP becomes an auto-block indicator.

### Gaps
- I did not retrieve OpenCTI's actual built-in decay values (lifetime and revoke score) per observable type, or the scope of the OpenCTI Enterprise Edition licence and its feature list.
- I could not verify the current MISP TAXII 2.1 server or push options (the search budget was exhausted). Only STIX conversion via misp-stix is confirmed.
- YETI's STIX/TAXII capabilities and MISP hardware sizing were not researched.

---

## 3. Malware-analysis pipeline for samples uploaded by agents

### Takeaway
For a Linux-first product, Assemblyline 4 (MIT, actively maintained) plus Karton (BSD-3) and MWDB (AGPL-3 with a plugin exception) give a scalable triage, storage and orchestration backbone. capa (Apache-2.0, supports ELF), YARA-X (BSD-3) and TLSH (Apache/BSD) cover static analysis. Linux dynamic analysis is the weak spot:
- CAPEv2 says "Linux guests don't have official CAPE support!"
- LiSa (Apache-2.0) has had no commits since February 2022.
- Cuckoo3 targets Windows and says it is "not production ready just yet".

Budget for building a custom Linux detonation stage, for example QEMU or KVM with eBPF tracing, rather than relying on an off-the-shelf sandbox. Watch third-party rule licences: Elastic's rules are ELv2, and some YARAhub rules are non-commercial.

### Cited Findings
- **Assemblyline 4 (CCCS).**
  - The `assemblyline` package is v4.8.0.1 with licence "MIT". — [PyPI assemblyline](https://pypi.org/project/assemblyline/)
  - assemblyline-base had commits on 4 Nov 2026. — [commits feed](https://github.com/CybercentreCanada/assemblyline-base/commits/master.atom)
  - Docker appliance: "The recommended minimum system requirement for this appliance is 4 CPUs and 8 GB of RAM". Supported OSes are Ubuntu 22.04/24.04 and RHEL 8.5, and the appliance is "suited for very small single machine deployment". — [AL4 Docker appliance](https://cybercentrecanada.github.io/assemblyline4_docs/installation/appliance/docker/)
  - The MicroK8s appliance needs 6 CPUs and 12 GB (via search snippet). — [AL4 MicroK8s](https://cybercentrecanada.github.io/assemblyline4_docs/installation/appliance/kubernetes-microk8s)
  - "Redis is our only component that cannot be scaled". — [AL4 cluster optimizations](https://cybercentrecanada.github.io/assemblyline4_docs/installation/cluster/optimizations)
- **CAPEv2.**
  - Licence: "Cuckoo Sandbox is copyrighted by the Cuckoo Foundation and is licensed under the following GNU General Public License version 3." — [CAPEv2 LICENSE](https://github.com/kevoreilly/CAPEv2/blob/master/LICENSE)
  - Very active, with commits on 9 Nov 2026. — [commits feed](https://github.com/kevoreilly/CAPEv2/commits/master.atom)
  - Linux docs: "Linux guests don't have official CAPE support!" Tracee eBPF tracing is a "Community Feature", which should "automatically highlight events such as fileless execution and syscall hooking". Example QEMU VMs cover x32, x64, ARM, MIPS and MIPSel, on an Ubuntu-based guest setup. — [CAPE Linux guest docs](https://capev2.readthedocs.io/en/latest/installation/guest/linux.html)
- **Karton and MWDB (CERT.PL).**
  - Karton is BSD 3-Clause (karton-core 5.9.1), with commits on 29 Oct 2026. — [karton LICENSE](https://github.com/CERT-Polska/karton/blob/master/LICENSE), [PyPI karton-core](https://pypi.org/project/karton-core/)
  - mwdb-core is AGPL-3.0 "with a special exception": "Plugins which merely make function calls to the mwdb-core software, and for that purpose include it by reference shall not be considered modifications of the software." — [mwdb-core LICENSE](https://github.com/CERT-Polska/mwdb-core/blob/master/LICENSE)
  - MWDB is "a malware repository component for automated malware collection and analysis systems", runs behind mwdb.cert.pl, stores binaries and static/dynamic configs, tracks relations, and offers webhooks and plugins. Version 2.20.0 is on PyPI, with commits on 6 Nov 2026. — [mwdb-core](https://github.com/CERT-Polska/mwdb-core), [PyPI](https://pypi.org/project/mwdb-core/)
- **LiSa.**
  - "Project providing automated Linux malware analysis on various CPU architectures". It supports x86_64, i386, arm, mips and aarch64, using QEMU, buildroot images, radare2 static analysis, SystemTap syscall tracing, network analysis, Celery and RabbitMQ, and docker-compose.
  - Licensed Apache-2.0. — [LiSa](https://github.com/danielpoliakov/lisa)
  - The last commit was on 15 Feb 2022. — [commits feed](https://github.com/danielpoliakov/lisa/commits/master.atom)
- **Strelka (Target).** "Real-time, container-based file scanning at enterprise scale". It has "over 50 file scanners" (ScanYara, ScanPe, ScanEntropy, ScanZip…) and runs on Docker Compose. Licensed Apache-2.0. "Users are advised to precompile their YARA rules". The last commit was 18 Aug 2026. — [Strelka](https://github.com/target/strelka), [commits feed](https://github.com/target/strelka/commits/master.atom)
- **Cuckoo3 (CERT-EE).** EUPL-1.2. "This is not a production ready solution just yet". It runs only on Ubuntu with Python 3.10, and the README mentions only Windows sandboxes. The last commit was 18 Dec 2025. — [Cuckoo3](https://github.com/cert-ee/cuckoo3), [commits feed](https://github.com/cert-ee/cuckoo3/commits/main.atom)
- **capa.** Runs against "a PE, ELF, .NET module, shellcode file, or a sandbox report" (CAPE JSON, DRAKVUF logs, VMRay archives). Licensed Apache-2.0, with flare-capa at v10.0.0. The capa-rules repo is also Apache-2.0. — [capa](https://github.com/mandiant/capa), [PyPI flare-capa](https://pypi.org/project/flare-capa/), [capa-rules LICENSE](https://github.com/mandiant/capa-rules/blob/master/LICENSE.txt)
- **YARA and YARA-X.** YARA (BSD-3-style) says "This project is in maintenance mode", pointing to the YARA-X stable announcement. YARA-X is BSD-3-style, at v1.23.0 on PyPI, with commits on 9 Nov 2026. — [YARA README](https://github.com/VirusTotal/yara), [YARA-X is stable](https://virustotal.github.io/yara-x/blog/yara-x-is-stable/), [YARA-X LICENSE](https://github.com/VirusTotal/yara-x/blob/main/LICENSE), [PyPI yara-x](https://pypi.org/project/yara-x/)
- **Fuzzy hashing.** TLSH "is provided for use under two licenses: Apache OR BSD". — [TLSH LICENSE](https://github.com/trendmicro/tlsh/blob/master/LICENSE). ssdeep is GPL v2. — [ssdeep COPYING](https://github.com/ssdeep-project/ssdeep/blob/master/COPYING)
- **Rule generation.** yarGen ("Yara Rule Generator", Florian Roth) is BSD-licensed. — [yarGen LICENSE](https://github.com/Neo23x0/yarGen/blob/master/LICENSE)
- **Third-party rule-set licences:**
  - Neo23x0 signature-base is under the "Detection Rule License (DRL) 1.1" ("Permission is hereby granted, free of charge … to deal in the Rules without restriction…"). — [signature-base LICENSE](https://github.com/Neo23x0/signature-base/blob/master/LICENSE)
  - Elastic protections-artifacts is under "Elastic License 2.0". — [protections-artifacts LICENSE](https://github.com/elastic/protections-artifacts/blob/main/LICENSE.txt). ELv2 says: "You may not provide the software to third parties as a hosted or managed service, where the service provides users with access to any substantial set of the features or functionality of the software." — [Elastic License 2.0](https://www.elastic.co/licensing/elastic-license)
  - Malpedia signator rules are CC BY-SA 4.0 (see Q1).

### Inferences
- **Licence fit for internal use.** Assemblyline (MIT), Karton (BSD-3), capa (Apache), YARA-X (BSD), TLSH and Strelka (Apache) carry no copyleft risk even when distributed. CAPE (GPLv3) and Cuckoo3 (EUPL-1.2) are fine for internal server use, but would carry copyleft duties if shipped to customers in an on-prem appliance. MWDB (AGPL) is fine internally, and its plugin exception allows proprietary plugins.
- **In the Go agent itself:** prefer TLSH (Apache/BSD) over ssdeep (GPLv2) if fuzzy hashes are computed on the host. Embed YARA-X or libyara (BSD) for scanning. Compute ssdeep only server-side.
- **Proposed flow:**
  1. The agent sends SHA-256, TLSH and metadata first.
  2. The master checks MWDB/MISP. Only unknown, suspicious ELF binaries or scripts are uploaded, respecting the consent and redaction policy in Q4.
  3. Karton routes the sample to Assemblyline (static analysis, capa, YARA-X, unpackers) and to a custom Linux detonation VM. Candidates are CAPE with an unofficial Linux guest plus Tracee, or a bespoke QEMU/KVM plus eBPF stage modelled on LiSa.
  4. Results go to MWDB (samples and configs) and OpenCTI/MISP (IOCs: miner wallet, pool domains, C2 IPs, dropped file hashes, persistence paths).
- **Producing new detections:**
  - Hashes are auto-promoted only when the verdict is high-confidence.
  - YARA candidates come from yarGen or analyst rules and must pass three gates before release: (a) compiling under YARA-X; (b) a goodware corpus scan, at minimum all ELF binaries from current Debian/Ubuntu/RHEL/Alma/Rocky/Fedora/AL2023 base images and common packages, with zero hits; (c) a back-test against MWDB family clusters (TLSH distance).
  - Only then do rules go into the signed bundle (Q5), starting in shadow (alert-only) mode.
- **Rule hygiene.** Don't ship Elastic ELv2 rules or NC-licensed YARAhub rules inside the commercial agent without permission. DRL 1.1, CC BY-SA and Apache rules are usable with attribution or share-alike handling.
- **Hardware for a starter master stack:** at least 4 vCPU and 8 GB RAM for the Assemblyline appliance, roughly 8–16 GB for OpenCTI with Elasticsearch, plus a bare-metal or nested-virtualisation host for detonation. A single 16–32 vCPU and 64 GB RAM server could host a small deployment. This is my estimate from the minimums above, not a vendor figure.

### Gaps
- I did not verify CAPE hardware requirements, real-world Linux analysis quality, or whether DRAKVUF Sandbox supports Linux guests.
- I did not check which Assemblyline services specifically handle ELF.
- I did not retrieve Karton or MWDB sizing.
- I did not check the licences of pure-Go TLSH/ssdeep implementations, or the details of YARA-X Go bindings.
- I did not read the full DRL 1.1 attribution conditions.
- I did not verify whether EUPL-1.2 treats SaaS or network access as distribution.

---

## 4. Network effects from many customers, and the privacy and legal side (incl. India: DPDP, CERT-In)

### Takeaway
Comparable products build their network effect the same way. Each agent sends minimal signals (attacker IP, scenario, time), a central consensus or trust engine filters for poisoning and false positives, and the curated list is redistributed. CrowdSec admits only about 2% of reported IPs to its community blocklist, and gives non-contributors a capped "Lite" list. Sample upload needs consent tiers. Microsoft's model is the reference: "safe" executables are sent automatically, and files likely to contain personal data prompt the user. In India the vendor must handle three regimes:
- **CERT-In (in force since 2022):** 6-hour incident reporting (cryptominers are explicitly listed), 180-day log retention "within the Indian jurisdiction", and NTP sync.
- **DPDP Rules 2025:** notified 13 Nov 2025. The substantive duties start 13 May 2027, including a 72-hour detailed breach update to the Board and a one-year log retention safeguard.

### Cited Findings
- **CrowdSec consensus and trust.** The consensus algorithm builds the community blocklist from crowdsourced IPs, using a Trust Scoring System for contributors. Inconsistent reporters get lower trust. A "Consensus Calculator" drops attackers that fail "a minimum baseline in the number of reports and the trust score of the reporting users", and other rules consider history and range reputation. "Only 2% of the 700,000+ IPs in the database make it to the community blacklist" (vendor figures, via search snippets). — [CrowdSec: our data](https://crowdsec.net/our-data), [CrowdSec FAQ](https://www.crowdsec.net/faq)
- **CrowdSec community blocklist tiers:**
  - Free contributing engines get a list "tailored to the behavior it reports" of about 15 thousand IPs.
  - Premium gets "up to 60 thousand malicious IPs based on your scenarios".
  - The "Lite" tier, for non-contributors or those "flagged for cheating or abusing the system", is capped at 3 thousand.
  - Only unmodified official Hub scenarios count. For custom ones, "the consensus engine ignores those signals".

  — [CrowdSec docs: Community Blocklist](https://docs.crowdsec.net/docs/next/central_api/community_blocklist)
- **What CrowdSec shares.** The v1.1 FAQ lists the shared data as attacker IP, scenario name and start/end times, says full logs are not sent, and explains opting out via the `online_client` config. — [CrowdSec v1.1 FAQ](https://doc.crowdsec.net/docs/v1.1/faq). A forum post claims that after six months the IP is truncated to /24 and the timestamp rounded to the hour (old, unverified). — [CrowdSec discourse](https://discourse.crowdsec.net/t/is-crowdsec-acting-against-european-privacy-regulations/1363)
- **BitNinja Defense Network.** "If an IP is globally challenge listed, it is challenge listed by all BitNinja servers". — [BitNinja docs: IP reputation](https://doc.bitninja.io/docs/IP%20filter/ip_reputation). Vendor list-size claims conflict: "over 10 million" vs "100M+". BitNinja claims Imunify360's list is about 15,000 IPs, which is a competitor claim. — [BitNinja vs Imunify360](https://bitninja.com/blog/bitninja-vs-imunify360/)
- **Imunify360.** Bad IPs are "blocked proactively, based on evidence gathered across millions of servers protected by Imunify360" (vendor/partner claim). — [Cloudways](https://www.cloudways.com/blog/introducing-proactive-security/)
- **Wazuh CTI.** "The Wazuh CTI service is the upstream source of threat intelligence and security content provided by Wazuh. It provides detection content, indicators of compromise (IoCs), and vulnerability intelligence through the Wazuh CTI API". — [Wazuh 5.0-rc docs](https://documentation.wazuh.com/5.0-rc/wazuh-cti/index.html). The public site currently offers vulnerability intelligence only. — [Wazuh 5.0-beta: how it works](https://documentation.wazuh.com/5.0-beta/wazuh-cti/how-it-works.html), [Introducing Wazuh CTI](https://wazuh.com/blog/introducing-wazuh-cti/)
- **Contributor licences in other services.** AbuseIPDB takes an "irrevocable, perpetual, sublicensable, transferable … royalty-free worldwide right and license" to reports. — [AbuseIPDB Terms](https://www.abuseipdb.com/legal). OTX may retain, use and "distribute" submitted content "at AlienVault's sole discretion". — [OTX EULA](https://levelblue.com/terms/otx-eula)
- **Sample-submission consent model (Microsoft Defender).**
  - Options are "Send safe samples automatically (the default behavior)", send all, or send none.
  - Safe samples are those "considered to not commonly contain PII data like: .bat, .scr, .dll, .exe".
  - "Files that are likely to contain personal information prompt the user for additional confirmation".
  - On Linux, "Safe: only suspicious samples that don't contain personally identifiable information (PII) are submitted automatically".

  — [MS Learn: cloud protection and sample submission](https://learn.microsoft.com/en-us/defender-endpoint/cloud-protection-microsoft-antivirus-sample-submission), [MS Learn: Defender for Endpoint on Linux privacy](https://learn.microsoft.com/en-au/defender-endpoint/linux-privacy)
- **CERT-In Directions** (No. 20(3)/2022-CERT-In, dated 28 April 2022):
  - (i) Entities "shall connect to the Network Time Protocol (NTP) Server of National Informatics Centre (NIC) or National Physical Laboratory (NPL) or with NTP servers traceable to these NTP servers".
  - (ii) Entities "shall mandatorily report cyber incidents as mentioned in Annexure I to CERT-In within 6 hours of noticing such incidents or being brought to notice about such incidents".
  - (iv) Entities "shall mandatorily enable logs of all their ICT systems and maintain them securely for a rolling period of 180 days and the same shall be maintained within the Indian jurisdiction".
  - (v) "Data Centres, Virtual Private Server (VPS) providers, Cloud Service providers and Virtual Private Network Service (VPN Service) providers" must keep validated subscriber data "for a period of 5 years or longer".
  - Annexure I includes "Unauthorised access of IT systems/data", "Malicious code attacks such as spreading of virus/worm/Trojan/Bots/Spyware/Ransomware/Cryptominers", "Attack on servers such as Database, Mail and DNS…" and "Attacks or malicious/ suspicious activities affecting Cloud computing systems/servers/software/applications".
  - The direction became "effective after 60 days from the date on which it is issued".

  — [CERT-In Directions PDF](https://www.cert-in.org.in/PDF/CERT-In_Directions_70B_28.04.2022.pdf)
- **CERT-In FAQs on log location.** Commentators disagree on whether logs can be kept abroad. Legal 500 reads the FAQs as allowing logs outside India if produced "in reasonable time". AZB reads them as requiring a copy retained in India. The obligations also reach foreign entities serving Indian users. — [Legal 500](https://www.legal500.com/developments/?p=32500), [AZB](https://www.azbpartners.com/bank/cert-in-directions/), [Mondaq](https://www.mondaq.com/india/security/1212912/unwinding-cert-ins-directions-on-cyber-security-practices-and-reporting-of-cyber-incidents), [Linklaters](https://www.linklaters.com/en/insights/blogs/digilinks/2022/may/india-new-and-onerous-cyber-security-framework-and-breach-reporting-obligations)
- **DPDP Rules 2025.**
  - Notified 13 Nov 2025. Institutional provisions took effect immediately, consent-manager rules from 13 Nov 2026, and substantive obligations from 13 May 2027.
  - Breach handling: a preliminary notice to the Data Protection Board "without delay", notice to affected Data Principals without delay, and a detailed update to the Board within 72 hours (extendable).
  - Safeguards "such as encryption, masking or tokenisation", access controls and monitoring, and retaining "logs and relevant data for one year".
  - Security obligations must be written into processor contracts.
  - Cross-border transfer is allowed except to restricted countries, with possible localisation for significant data fiduciaries.
  - CERT-In's six-hour reporting still applies separately.

  — [AZB & Partners](https://www.azbpartners.com/bank/update-indias-digital-personal-data-protection-framework-comes-into-effect/). Some reports give 14 Nov 2025 as the notification date, and one ties Rule 10's breach reporting to 13 May 2027. — [Legal 500 / Saga Legal](https://www.legal500.com/firms/237811-saga-legal/c-india/news-and-developments/the-privacy-timer-starts-now-analysing-the-dpdp-rules-and-its-18-month-countdown), [India Briefing](https://www.india-briefing.com/news/dpdp-rules-2025-india-data-protection-law-compliance-40769.html)

### Inferences
- **Network-effect design (CrowdSec-style).**
  - Agents report only (attacker IP, detection ID or version, first/last seen, count, customer-tenant pseudonym).
  - The master runs consensus: an IP becomes a fleet-wide auto-block only when it is seen by N distinct tenants with trust weighting, or confirmed by a high-confidence first-party detection such as a honeypot or sandbox C2. Tenant trust rises with accurate history.
  - Only signals from unmodified vendor detections count, which mirrors CrowdSec's anti-poisoning rule.
  - Offer a contributor tier (full list) versus non-contributors (smaller list). This is a proven incentive.
- **Privacy defaults for samples and telemetry:**
  - Hash-first, upload-later. Auto-upload only ELF, scripts and cron/systemd unit files flagged by detections.
  - Never auto-upload anything under /home or /root, .env files, keys, databases or documents. Those need an explicit console approval, modelled on Microsoft's "safe samples" plus a prompt.
  - Redact secrets in command lines and environment variables (tokens, passwords, connection strings) before sending.
  - Keep raw samples in the vendor's own MWDB. Share with third parties (MalwareBazaar, VirusTotal Premium) only under a per-tenant opt-in, because public repositories redistribute samples and customer binaries can be proprietary.
- **India positioning:**
  - The vendor's own servers fall under CERT-In. The motivating incident (SSH compromise and a cryptominer) is a reportable incident type within 6 hours.
  - The product can sell compliance features: 180-day tamper-evident log retention (India-region storage option), NTP-source checks, and a CERT-In-format incident export from each Discord-alerted incident.
  - Under DPDP the vendor is likely a Data Processor for customer telemetry, so it needs a DPA with security clauses. It may be a Data Fiduciary for the pooled-intel use, which needs a notice/consent or legitimate-use analysis. Host the master in an Indian region by default, with region options for EU customers later.

### Gaps
- I did not find Imunify360 or BitNinja primary documentation on what data is collected, consent or retention, and their size figures are vendor marketing.
- I did not confirm Wazuh CTI IoC feed availability or terms.
- I did not research DPDP "legitimate uses" for security processing, the processor-vs-fiduciary classification for pooled threat intel, or penalty amounts.
- I did not read the primary CERT-In FAQ text; the logs-outside-India question is ambiguous across law firms.
- I did not research the EU GDPR position (for example, the legitimate-interest basis for network security).

---

## 5. Secure distribution of intel to agents: signed bundles, deltas, TUF/Sigstore, staged rollout, and poisoned-feed protection

### Takeaway
Treat the intel bundle like executable code:
- Sign it with offline-rooted, threshold keys and expiring metadata (TUF), optionally logged in a transparency log (Sigstore).
- Ship deltas against versioned snapshots, with full-snapshot fallback (ClamAV's CVD/CDIFF model).
- Roll out in rings with automatic halt and customer-controlled pinning.

The CrowdStrike Channel File 291 outage on 19 July 2024 shows that a content-only update with a schema mismatch can take down hosts fleet-wide. CrowdStrike's fixes were input-count validation, runtime bounds checks, successive deployment rings and customer control over content rollout. Those map directly onto agent design.

### Cited Findings
- **TUF.**
  - Core roles are Root, Targets, Snapshot and Timestamp, with delegations. Root assigns keys and signature thresholds per role.
  - It defends against rollback ("Attackers should not be able to make clients install software older than what the client previously knew to be available") and indefinite-freeze attacks via expiring metadata, in which the timestamp role is central.
  - TUF reached CNCF "graduate" status in December 2019 (Wikipedia).

  — [TUF security](https://theupdateframework.io/security/), [TUF specification](https://theupdateframework.io/specification), [Wikipedia: The Update Framework](https://en.wikipedia.org/wiki/The_Update_Framework)
- **go-tuf** is Apache-2.0. — [go-tuf LICENSE](https://github.com/theupdateframework/go-tuf/blob/master/LICENSE). A past go-tuf CVE involved rollback protection not considering previously trusted metadata for non-root roles. — [go-tuf CVEs](https://releasealert.dev/github/theupdateframework/go-tuf/cves)
- **Sigstore cosign.**
  - Default keyless signing uses the Fulcio CA and the Rekor transparency log.
  - `sign-blob` writes a bundle containing the signature, certificate and Rekor entry.
  - `verify-blob --bundle … --certificate-identity … --certificate-oidc-issuer …` pins the signer identity, and bundles support offline verification.

  — [Sigstore quickstart](https://docs.sigstore.dev/quickstart/quickstart-cosign/), [cosign README](https://cdn.jsdelivr.net/gh/sigstore/cosign@main/README.md). cosign v2.6.0 added Rekor v2 and a new bundle format. — [cosign v2.6.0 release notes](https://newreleases.io/project/github/sigstore/cosign/release/v2.6.0)
- **ClamAV delta model.**
  - FreshClam finds the on-disk version and "requests every CDIFF between that version and the latest".
  - If a CDIFF can't be downloaded it falls back to the full CVD, and a zero-byte CDIFF is an intentional "download the whole CVD" signal.
  - The advantage is "incremental update using database patch files, along with automatic testing of new databases".

  — [ClamAV blog: CVDs, CDIFFs](https://blog.clamav.net/2021/03/clamav-cvds-cdiffs-and-magic-behind.html), [FreshClam FAQ](https://docs.clamav.net/faq/faq-freshclam.html), [ClamAV private mirror docs](https://docs.clamav.net/appendix/CvdPrivateMirror.html)
- **TAXII 2.1 incremental sync.** `added_after` plus ascending date-added ordering, `X-TAXII-Date-Added-Last` checkpoints, and a manifest endpoint. There is no deletion feed, so revocations must be explicit objects. — [OASIS TAXII 2.1](https://docs.oasis-open.org/cti/taxii/v2.1/os/taxii-v2.1-os.html)
- **ET freshness check.** Check "https://rules.emergingthreats.net/version.txt … incremented each time we publish". ET also provides MD5 files to validate downloads. — [ET OPEN download instructions](https://rules.emergingthreats.net/OPEN_download_instructions.html)
- **CrowdStrike Channel File 291** (Executive Summary RCA, 6 Aug 2024):
  - "On July 19, 2024, a Rapid Response Content update was delivered to certain Windows hosts … The sensor expected 20 input fields, while the update provided 21 input fields … the mismatch resulted in an out-of-bounds memory read, causing a system crash". Earlier Channel 291 content had "performed as expected in production" in March–April 2024.
  - Remediations:
    - "upgraded tests for Template Type development".
    - "an updated deployment ring process, ensuring Template Instances pass successive deployment rings before rollout into production".
    - "New capabilities … that allow customers to control how Rapid Response Content is deployed".
    - "Validation for the number of input fields".
    - Additional Content Validator checks.
    - Content Interpreter bounds checking added on 25 Jul 2024.
    - Two independent third-party code and process reviews.
  - About 99% of Windows sensors were back online by 29 Jul 2024.

  — [CrowdStrike Executive Summary RCA](https://crowdstrike.com/wp-content/uploads/2024/08/Executive-Summary_Root-Cause-Analysis_Channel-File-291.pdf), [full RCA](https://crowdstrike.com/wp-content/uploads/2024/08/Channel-File-291-Incident-Root-Cause-Analysis-08.06.2024.pdf)
- The full RCA frames the same bug the other way round: the IPC Template Type defined 21 fields, but the integration code supplied 20 values. — [TechTarget on the RCA](https://www.techtarget.com/searchSecurity/news/366602392/CrowdStrike-details-errors-that-led-to-mass-IT-outage)
- **Stale-data obligations from data providers.** Spamhaus warns that a stale DROP "can cause problems". MaxMind requires old GeoLite versions to be destroyed within 30 days of a new release. — [Spamhaus DROP](https://www.spamhaus.org/blocklists/do-not-route-or-peer/), [MaxMind EULA](https://www.maxmind.com/en/geolite2/eula)

### Inferences
- **Bundle format:**
  - A monotonic `bundle_version` and a schema version that the agent checks before parsing. Reject unknown major versions, which avoids the CrowdStrike 20-vs-21-field class of bug.
  - Typed sections: hash set, IP/CIDR radix set, domain set, YARA-X compiled rules, policy, and allowlist.
  - Per-section SHA-256, with a TUF targets entry per artifact.
  - Signed with a TUF repository via go-tuf: offline root keys (YubiKey/HSM, 2-of-3 threshold), an online timestamp key with a short expiry (for example 24 hours) so agents can detect freeze attacks, and snapshot/targets keys separated.
  - Optionally also cosign-sign releases and record them in Rekor, or a private transparency log, for auditability.
- **Delta updates.** Publish full snapshots (for example daily) plus small add/remove deltas (for example every 5–15 minutes) keyed by from-version to to-version, as in ClamAV. The agent falls back to the full snapshot on any gap or hash mismatch. Revocations are explicit "remove" entries, because TAXII-style pulls can't express deletes.
- **Agent-side safety rails:**
  - Parse and compile new content in a separate, resource-limited child process. For example, YARA-X compile with a time and memory cap.
  - Keep the last-known-good bundle and auto-roll back on a crash loop or compile failure.
  - Cap the blast radius per update: refuse auto-block or quarantine if an update would suddenly match more than X% of running processes or system binaries, or block the host's default gateway, DNS resolvers, package mirrors, cloud metadata IP or the master server.
  - Run new rules in shadow mode first.
  - Never quarantine package-manager-owned binaries on a hash match alone. Require package-integrity mismatch plus detection, which also fits the "replaced system binaries" scenario.
- **Staged rollout:**
  - Rings: internal canary hosts, then a honeypot/test fleet, then about 1% of customers, then 10%, then 100%.
  - Rings advance automatically only if detection-rate and false-positive telemetry stay within baseline. One click halts or reverts.
  - Customers get "N-1 content pinning" and a choice of fast or slow ring, mirroring CrowdStrike's post-incident customer controls.
  - Allowlist and revocation content uses an expedited path, because it reduces risk. New block content follows the slow path.
- **Poisoned-feed defence on the master:**
  - Per-source quotas and anomaly checks, for example a feed suddenly adding /8s, top-domain hits, CDN or cloud ranges, or more than 10x its normal daily volume.
  - Hold the batch for human review when any check trips.
  - Require two sources or first-party confirmation for auto-block.
  - Test every bundle against the goodware corpus and the warninglists (Q2/Q3) before signing.

### Gaps
- I did not read the full CrowdStrike RCA's details on ring sizes and timing.
- I did not retrieve the details of ClamAV's CVD signature verification, or whether CDIFFs are signed separately.
- I found no source on which EDR or AV vendors use TUF specifically for detection-content updates.
- I did not research self-hosted Sigstore (private Fulcio/Rekor) for an air-gapped or vendor-controlled trust root.
