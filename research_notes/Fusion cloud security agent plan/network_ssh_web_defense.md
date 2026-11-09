# Network, SSH/Identity, Deception and Web-Attack Defenses for Linux Servers (state as of 2026-11-09)

Scope: the "network and identity" layer of a lightweight Go/systemd EDR agent for Debian/Ubuntu and RHEL-family (RHEL, AlmaLinux, Rocky, Fedora, Amazon Linux 2023) cloud servers and VPSs. The agent has a deterministic detection engine, a policy-controlled response engine, a company master server (IOC/YARA/policy) and Discord alerts. Motivating incident: SSH compromise, then a cryptominer with a watchdog, cron + systemd persistence and replaced system binaries.

Method note: primary sources (vendor docs repositories, man pages, release feeds, license files, NVD, ET Open rule tarball, Repology package database) were fetched directly on 2026-11-09. The shared web-search budget ran out partway through, so a few items could not be searched. Each section's Gaps lists them.

---

## 1. CrowdSec (architecture, SSH/HTTP detection, blocklist/CTI, footprint, license and commercial/MSSP terms) compared with Fail2ban and sshguard

### Takeaway
The CrowdSec Security Engine is MIT-licensed, written in Go and uses less than 100 MB of RAM. The current version is v1.8.2 (2026-10-27). It is the most complete open-source option for log-behaviour detection, IP reputation, firewall bouncing and WAF on one host. Its nftables bouncer already uses google/nftables with timeout sets.

The data side is licensed differently. The Console EULA forbids using the community blocklist, IP addresses or attack scenarios "to provide services on behalf of third parties" and forbids redistributing them. A commercial agent that protects customers' servers therefore needs CrowdSec's Partnership/OEM program for blocklist and CTI data. The MIT engine and the MIT hub content can be embedded freely. Fail2ban (GPL-2.0, v1.1.1, 2026-08-15) and sshguard (ISC-style, v2.6.0, 2026-10-17) are simpler log-to-ban daemons. They are good fallbacks or reference designs, not replacements.

### Cited Findings

#### CrowdSec architecture
- The Security Engine is "an open-source, lightweight security engine that detects and blocks malicious actors. It analyzes logs and HTTP requests using behavior-based patterns called scenarios." — [CrowdSec docs: Security Engine intro](https://docs.crowdsec.net/docs/intro)
- Components:
  - The **Log Processor** handles detection over many data sources and over HTTP requests from compatible web servers. **AppSec** is part of the Log Processor.
  - The **Local API (LAPI)** sits between Log Processors and Remediation Components, and between the engine and the **Central API**, which shares alerts and returns blocklists.
  - **Remediation Components (bouncers)** enforce blocks in iptables, firewalls, web servers or reverse proxies.
  - All components talk over an HTTP API, which allows multi-machine setups.
  - Deployment options: single machine, distributed multi-server, centralised logs ("run CrowdSec next to your log pipeline, not on production workloads"), Kubernetes, Docker data source, or WAF only.
  - Source: [CrowdSec docs: intro](https://docs.crowdsec.net/docs/intro)
- Acquisition data sources in the v1.8 docs: file, journald, syslog, docker, kubernetes, kubernetes_audit, http, appsec, cloudwatch, kinesis, kafka, loki, s3, victorialogs, windows_event_log. — [CrowdSec docs: data sources](https://docs.crowdsec.net/docs/log_processor/data_sources/introduction) (docs repository snapshot of 2026-11-05)
- Bouncers poll LAPI in **stream mode** (`/v1/decisions/stream?startup=true`, then deltas of new and deleted decisions) or **query mode** (look up one IP, range or username). — [CrowdSec docs: Remediation Component API](https://docs.crowdsec.net/docs/local_api/bouncers)
- Profiles turn alerts into decisions. Defaults are type `ban`, scope `ip`, duration `4h`. — [CrowdSec docs: profiles](https://docs.crowdsec.net/docs/local_api/profiles/intro). Escalating bans are possible with `duration_expr`, for example `Sprintf('%dh', (GetDecisionsCount(Alert.GetValue()) + 1) * 4)`. — [CrowdSec docs: profile examples](https://docs.crowdsec.net/docs/local_api/profiles/captcha_profile)
- Centralised **allowlists** (`cscli allowlists create/add`, IPs or ranges, optional expiry such as `-e 7d`):
  - local alerts for allowlisted IPs are dropped;
  - allowlisted IPs are removed from blocklist pulls before database insertion;
  - allowlisted IPs bypass AppSec;
  - `cscli` refuses manual decisions on them unless a special flag is passed.
  - The older `capi_whitelists_path` is deprecated.
  - Source: [CrowdSec docs: AllowLists](https://docs.crowdsec.net/docs/local_api/centralized_allowlists); [CrowdSec configuration reference](https://docs.crowdsec.net/docs/configuration/crowdsec_configuration)

#### CrowdSec detection of SSH brute force, password spraying, credential stuffing and HTTP scanning
- `crowdsecurity/ssh-bf`: leaky bucket on `ssh_failed-auth` events, grouped by source IP, capacity 5, leakspeed 10s, blackhole 1m, MITRE T1110. — [hub: ssh-bf.yaml](https://github.com/crowdsecurity/hub/blob/master/scenarios/crowdsecurity/ssh-bf.yaml)
- `crowdsecurity/ssh-bf_user-enum` uses the same bucket with `distinct: evt.Meta.target_user`. It fires when one IP tries 5 or more distinct usernames, which is the per-source signature of password spraying or user enumeration (T1589). — [hub: ssh-bf.yaml](https://github.com/crowdsecurity/hub/blob/master/scenarios/crowdsecurity/ssh-bf.yaml)
- `ssh-slow-bf` and `ssh-slow-bf_user-enum`: capacity 10, leakspeed 60s. — [hub: ssh-slow-bf.yaml](https://github.com/crowdsecurity/hub/blob/master/scenarios/crowdsecurity/ssh-slow-bf.yaml)
- `ssh-time-based-bf`: a conditional bucket for attackers who evade rate limits. It needs 4 or more failures whose median interval exceeds 10 minutes, is cancelled by an `auth_success` from the same IP, has a 2h window, and is set `remediation: false` (alert only, confidence 1). — [hub: ssh-time-based-bf.yaml](https://github.com/crowdsecurity/hub/blob/master/scenarios/crowdsecurity/ssh-time-based-bf.yaml)
- Other SSH scenarios: `ssh-cve-2024-6387` (regreSSHion probing, built from auth-timeout and dispatch-fatal lines, capacity 3 per 180s) and `ssh-refused-conn`. — [hub: ssh-cve-2024-6387.yaml](https://github.com/crowdsecurity/hub/blob/master/scenarios/crowdsecurity/ssh-cve-2024-6387.yaml); [hub: ssh-refused-conn.yaml](https://github.com/crowdsecurity/hub/blob/master/scenarios/crowdsecurity/ssh-refused-conn.yaml)
- The sshd parser recognises:
  - PAM `authentication failure` lines;
  - `Invalid user ...`;
  - `Failed keyboard-interactive/pam for invalid user`;
  - pre-auth `Connection closed/reset by authenticating|invalid user` and `Disconnected from ... [preauth]`;
  - `Unable to negotiate`;
  - `not allowed because not listed in AllowUsers`;
  - `Timeout before authentication`;
  - `ssh_dispatch_run_fatal ... message authentication code incorrect`;
  - TCP-wrapper `refused connect`.
  - Source: [hub: sshd-logs.yaml parser](https://github.com/crowdsecurity/hub/blob/master/parsers/s01-parse/crowdsecurity/sshd-logs.yaml)
- HTTP scenarios:
  - `http-probing`: 404/403/400 responses on non-static resources, at least 10 distinct paths per IP+FQDN, leakspeed 10s, blackhole 5m.
  - `http-crawl-non_statics`: GET/HEAD on non-static resources, capacity 40, leakspeed 0.5s.
  - `http-sensitive-files`: requests ending in a sensitive-file list (.log, .db, .git), capacity 4, leakspeed 5s.
  - `http-generic-bf`: generic HTTP authentication failures, capacity 5 per 10s, plus a 401-on-POST variant keyed by IP+path.
  - Sources: [hub: http-probing.yaml](https://github.com/crowdsecurity/hub/blob/master/scenarios/crowdsecurity/http-probing.yaml); [hub: http-crawl-non_statics.yaml](https://github.com/crowdsecurity/hub/blob/master/scenarios/crowdsecurity/http-crawl-non_statics.yaml); [hub: http-sensitive-files.yaml](https://github.com/crowdsecurity/hub/blob/master/scenarios/crowdsecurity/http-sensitive-files.yaml); [hub: http-generic-bf.yaml](https://github.com/crowdsecurity/hub/blob/master/scenarios/crowdsecurity/http-generic-bf.yaml)
- The hub also has `http-path-traversal-probing`, `http-sqli-probing`, `http-xss-probing`, `http-bad-user-agent`, `http-cve-probing`, `http-admin-interface-probing`, WordPress, xmlrpc and Magento brute-force scenarios, `mysql-bf`, `pgsql-bf` and `iptables-scan-multi_ports`. — [hub scenarios directory](https://github.com/crowdsecurity/hub/tree/master/scenarios/crowdsecurity)
- **Credential stuffing** on web logins: the AppSec component can rate-limit in `pre_eval` hooks with `RateLimit()`. Example: `POST /login` limited to 5/m per client IP, with HTTP 429 returned after the limit. — [CrowdSec docs: AppSec rate limiting](https://docs.crowdsec.net/docs/appsec/rate_limiting)
- Hub content (scenarios, parsers, AppSec rules) is MIT-licensed. — [hub LICENSE](https://github.com/crowdsecurity/hub/blob/master/LICENSE)

#### CrowdSec remediation: firewall bouncer (nftables / iptables)
- `crowdsec-firewall-bouncer` supports iptables, nftables, ipset-only and pf, over IPv4 and IPv6. It is recommended for infrastructure services (SSH, databases, SMTP). For web applications CrowdSec recommends a WAF-capable bouncer, or both together. — [CrowdSec docs: firewall bouncer](https://docs.crowdsec.net/u/bouncers/firewall)
- Packages: `crowdsec-firewall-bouncer-nftables` or `crowdsec-firewall-bouncer-iptables` via `apt` or `yum`. Run `iptables -V`; if it shows `nf_tables`, the system uses nftables. — [CrowdSec docs: firewall bouncer](https://docs.crowdsec.net/u/bouncers/firewall)
- Modes:
  - **managed** (default) creates the sets and rules itself;
  - **set-only** manages only the contents of sets the admin created (documented example: `table ip crowdsec`, `set crowdsec-blacklists { type ipv4_addr; flags timeout; }`, a chain on `hook input priority filter` with `ip saddr @crowdsec-blacklists drop`).
  - `nftables` mode "relies on github.com/google/nftables". `iptables` mode shells out to `iptables` and `ipset`.
  - Default nft tables are `crowdsec` and `crowdsec6`, chains `crowdsec-chain` and `crowdsec6-chain`.
  - Source: [CrowdSec docs: firewall bouncer](https://docs.crowdsec.net/u/bouncers/firewall)
- Other config: `deny_action` DROP (default) or REJECT, `deny_log`, and `iptables_chains` (default `INPUT`). The docs say to add `DOCKER-USER` to `iptables_chains` if dockerised applications accept remote connections. ipset timeouts are capped at 2,147,483 s (about 596 h). `ipset_size` defaults to 131,072. Prometheus metrics count dropped packets and bytes per origin (CAPI, local engine, lists). — [CrowdSec docs: firewall bouncer](https://docs.crowdsec.net/u/bouncers/firewall)

#### CrowdSec AppSec (WAF) component
- How it works: the web server or proxy forwards each request over a local HTTP interface to the engine (example `listen_addr: 127.0.0.1:7422`).
  - **In-band** rules return block (403) or captcha for the current request.
  - **Out-of-band** rules run asynchronously and feed scenarios, for example to extend a ban after repeated virtual-patch hits.
  - Supported fronts: Nginx, OpenResty, Apache, Traefik, Envoy Gateway, HAProxy SPOA, WordPress.
  - Features: virtual patching, legacy ModSecurity rule support, bot detection with a browser challenge.
  - Sources: [CrowdSec docs: AppSec intro](https://docs.crowdsec.net/docs/appsec/intro); [AppSec rule management](https://docs.crowdsec.net/docs/appsec/configuration_rule_management)
- OWASP CRS compatibility is provided through **Coraza**. — [CrowdSec docs: AppSec CRS](https://docs.crowdsec.net/docs/appsec/crs/intro)
- Official benchmark (v1.8.2, AWS c6i.4xlarge, 4 cores, hub with 206 vpatch rules plus full CRS) — [CrowdSec docs: WAF benchmark](https://docs.crowdsec.net/docs/appsec/benchmark):
  - in-band mean is 0.233 ms for virtual patching and 1.058 ms for CRS;
  - a 16 KB POST costs 0.5 ms with vpatch and 79.5 ms with CRS;
  - sizing guidance is about 1,000 CRS req/s or 4,000 vpatch req/s per physical core;
  - vpatch should run in-band unconditionally, and CRS in-band suits GET-heavy traffic only;
  - the out-of-band queue silently drops work when full (watch `cs_appsec_outofband_dropped_total`).

#### CrowdSec community blocklist, CTI API, pricing and EULA (commercial / MSSP)
- Community Blocklist tiers — [CrowdSec docs: Community Blocklist](https://docs.crowdsec.net/docs/central_api/community_blocklist):
  - **Lite**: up to 3,000 IPs, for free users who do not regularly contribute signals or who are flagged for abuse.
  - **Community**: about 15,000 IPs tailored to the scenarios the engine runs, for free contributors.
  - **Premium**: up to 60,000 IPs for paying users, with no contribution required.
  - It is "only available when using the Security Engine".
  - Only signals from **unmodified** hub scenarios count (checked by content hash). Custom or tainted scenarios are excluded from consensus.
- Pricing page (fetched 2026-11-09) — [CrowdSec pricing](https://www.crowdsec.net/pricing):
  - Platinum Blocklists from **$1,900/month** for SMB, "access to all blocklists on any number of endpoints within the company";
  - IP Reputation (CTI) API from **$49/month for 5,000 queries**;
  - local CTI replication from **$9K/month**;
  - Live Exploit Tracker from **$2k/month** (SMB), with "OEM pricing available";
  - Console Premium is "Pay as you Grow per enrolled Security Engine", with optional emergency bug fixes at $1K/month and premium support at $1K/month.
- Pricing FAQ: "Can I use CrowdSec data commercially as part of my offering? Yes, by subscribing to our Partnership Program, you can embed CrowdSec security data into your solutions and make commercial use of it, whether for reselling or other purposes. Partner pricing differs from standard pricing." — [CrowdSec pricing](https://www.crowdsec.net/pricing)
- CTI API key quotas — [CrowdSec docs: CTI API](https://docs.crowdsec.net/u/cti_api/intro):
  - Community plan free key: **120 queries/month**;
  - Premium plan free key: **1,500/month**;
  - Premium key options: **5K, 25K or 100K/month**.
- The free tier lists "3 Free-tier Blocklists". This comes from a search-result summary of [app.crowdsec.net/pricing](https://app.crowdsec.net/pricing) and the page was not fetched.
- CrowdSec EULA v2.0.1 (dated 2024/02/29) — [CrowdSec EULA PDF](https://booking.crowdsec.net/hubfs/EULA%20Crowdsec%20v2%20.pdf) via [EULA page](https://booking.crowdsec.net/crowdsec-eula):
  - It governs the **Console/SaaS ("Solution")**.
  - "Assets" means "information, publications, IP addresses, attack scenarios, and, in general, all data transmitted to or accessible by the Crowdsec Console".
  - Prohibited: to "use the Solution or the Assets to provide services on behalf of third parties, including entities of the group to which the End User belongs, in any form whatsoever, including SaaS mode".
  - Prohibited: to "distribute or market the Solution or the Assets ... In particular ... distributing or marketing IP addresses or attack scenarios provided or made accessible by the Service".
  - The EULA "does not concern and does not modify in any way the rights of use of the software ... under open source licenses".
  - Users grant CrowdSec an irrevocable, royalty-free, sub-licensable licence to the Assets they transmit, "not limited to personal use, but also extends to any commercial use".
  - The Community licence is free and "allows a time- and features-limited access".
- Licenses: crowdsec engine is MIT — [crowdsec LICENSE](https://github.com/crowdsecurity/crowdsec/blob/master/LICENSE). cs-firewall-bouncer is MIT — [bouncer LICENSE](https://github.com/crowdsecurity/cs-firewall-bouncer/blob/main/LICENSE)

#### CrowdSec footprint, versions and packaging
- Requirements and performance — [CrowdSec docs: getting started](https://docs.crowdsec.net/u/getting_started/intro); [CrowdSec FAQ](https://docs.crowdsec.net/u/troubleshooting/security_engine):
  - minimum 1 CPU core, **100 MB free RAM** and 1 GB free disk, on amd64, arm64 or armhf;
  - "in a small to medium setup should use less than 100 MB of memory";
  - CPU is the main cost under heavy log processing;
  - it handles "several thousands of events per second".
- Versions: crowdsec **v1.8.2 (2026-10-27)** and cs-firewall-bouncer **v0.0.38 (2026-11-03)**. — [crowdsec releases](https://github.com/crowdsecurity/crowdsec/releases); [bouncer releases](https://github.com/crowdsecurity/cs-firewall-bouncer/releases)
- Recommended install is the vendor repository at packagecloud (`curl -s https://install.crowdsec.net | sudo sh`, or a manual apt/yum repo). — [CrowdSec docs: Linux install](https://docs.crowdsec.net/u/getting_started/installation/linux)
- Distro packages are stale. Debian 12/13 and Ubuntu 24.04/26.04 ship crowdsec **1.4.6** and the bouncer **0.0.25**, and no EPEL/RHEL package is listed. — [Repology: crowdsec](https://repology.org/project/crowdsec/versions); [Repology: crowdsec-firewall-bouncer](https://repology.org/project/crowdsec-firewall-bouncer/versions)

#### Fail2ban
- **1.1.1 "triple-one-win" was released 2026-08-15**, the first release since 1.1.0 (2024-04-25). It fixes catastrophic regex backtracking (GHSA-33wh-ccjc-p397) and systemd journal-handle leaks. Default banactions now live in per-distro `paths-*.conf` files. — [fail2ban releases](https://github.com/fail2ban/fail2ban/releases); [ChangeLog](https://github.com/fail2ban/fail2ban/blob/master/ChangeLog)
- `paths-debian.conf` and `paths-fedora.conf` set `banaction = nftables` and `banaction_allports = nftables[type=allports]`. — [paths-debian.conf](https://github.com/fail2ban/fail2ban/blob/master/config/paths-debian.conf); [paths-fedora.conf](https://github.com/fail2ban/fail2ban/blob/master/config/paths-fedora.conf)
- The development branch adds a `cowrie.conf` filter for Cowrie JSON logs and an Authelia filter. — [ChangeLog](https://github.com/fail2ban/fail2ban/blob/master/ChangeLog)
- Mechanism: a jail matches regex filters over a log or journal backend.
  - Defaults: `bantime = 10m`, `findtime = 10m`, `maxretry = 5`, `backend = auto`.
  - `ignoreip` (CIDR/DNS list) and `ignoreself` exist but are commented in the shipped config.
  - Optional `bantime.increment` grows bans 1, 2, 4, 8… times, with `bantime.maxtime` and `bantime.rndtime`.
  - Source: [jail.conf](https://github.com/fail2ban/fail2ban/blob/master/config/jail.conf)
- The nftables action creates `table inet f2b-table` and `chain f2b-chain` (hook input, **priority -1**), one address set per jail, and adds or deletes elements on ban or unban. Default blocktype is `reject`. Expiry is handled by fail2ban itself, not by kernel set timeouts. Firewalld actions also exist (`firewallcmd-rich-rules`, `firewallcmd-ipset`, `firewallcmd-multiport`, and others), as does `ufw`. — [action.d/nftables.conf](https://github.com/fail2ban/fail2ban/blob/master/config/action.d/nftables.conf); [action.d directory](https://github.com/fail2ban/fail2ban/tree/master/config/action.d)
- License **GPL-2.0**. — [COPYING](https://github.com/fail2ban/fail2ban/blob/master/COPYING)
- Packages: Debian 13 1.1.0, Ubuntu 24.04 1.0.2, Ubuntu 22.04 0.11.2, EPEL 8 1.0.2, EPEL 9 and EPEL 10 1.1.0. — [Repology: fail2ban](https://repology.org/project/fail2ban/versions)

#### sshguard
- **2.6.0 released 2026-10-17.** It adds Dropbear, MySQL, SSH pre-auth-timeout and pfSense signatures, a block-time multiplier option and grouping attacks by subnet. 2.5.1 (2025-04-29) fixed a DoS in the quoted-string parser. — [sshguard CHANGELOG](https://github.com/SSHGuard/sshguard/blob/master/CHANGELOG.rst); [releases](https://github.com/SSHGuard/sshguard/releases)
- Mechanism: each detected attack adds to an attack score, usually by 10. Defaults:
  - block when the score exceeds `-a` 30;
  - first block lasts `-p` 120 s, multiplied by `-m` 2 for repeat offenders;
  - the score resets after `-s` 1800 s of quiet.
  - Optional permanent blacklist file (`-b`), and a whitelist (`-w`) of IPs, CIDRs or hostnames.
  - Source: [sshguard(8)](https://github.com/SSHGuard/sshguard/blob/master/doc/sshguard.8.rst)
- Backends: `sshg-fw-nft-sets`, firewalld, ipset, iptables, pf, ipfw, ipfilter, null. The nft backend creates `ip`/`ip6` tables `sshguard`, a chain `blacklist` on hook input at **priority -10**, and an `attackers` set with `flags interval`. sshguard releases entries itself (no kernel timeouts). — [src/fw](https://github.com/SSHGuard/sshguard/tree/master/src/fw); [sshg-fw-nft-sets.sh](https://github.com/SSHGuard/sshguard/blob/master/src/fw/sshg-fw-nft-sets.sh)
- License: permissive ISC-style ("Permission to use, copy, modify, and distribute this software for any purpose with or without fee..."). — [COPYING](https://github.com/SSHGuard/sshguard/blob/master/COPYING)
- Packages: Debian 13 2.4.3, Ubuntu 24.04 2.4.2, EPEL 8/9 2.4.2, EPEL 10 and Fedora 2.5.1. — [Repology: sshguard](https://repology.org/project/sshguard/versions)

### Inferences
- **Licensing model for Fusion.**
  - Embedding or co-installing the MIT engine, bouncer and hub content (scenarios, parsers, vpatch YAML) is allowed with attribution.
  - Using the free community blocklist, Console or CTI data to protect *clients'* servers looks like "providing services on behalf of third parties" with the Assets. Redistributing blocklist IPs through Fusion's master server would be "distributing ... IP addresses". Both are prohibited unless covered by a Partnership/OEM agreement.
  - Product plan: either (a) let each customer enrol their own CrowdSec engine under their own Console account (Fusion only reads local LAPI decisions as a bouncer), or (b) negotiate partner/OEM terms before pushing CrowdSec data from the master server.
- **Integration options.**
  - Run the agent as a LAPI *bouncer* in stream mode to consume decisions.
  - Optionally act as a LAPI *machine* to push its own alerts.
  - Or reimplement the leaky-bucket logic natively in Go. The scenario parameters above are a good starting calibration: 5 failures per 10 s, 10 per 60 s, at least 5 distinct users, a time-based median interval over 10 min, and alert-only for low-confidence cases.
  - Keep one allowlist source of truth and push it into CrowdSec allowlists, Fail2ban `ignoreip` and sshguard `-w`. Any third-party banner that drops an admin IP will otherwise defeat Fusion's allowlist, because an nftables drop is final (see §2).
- **Password spraying across many IPs** (low and slow, distributed) is not caught by per-IP buckets. It needs per-username aggregation across sources, which Fusion can compute centrally (master server), plus the community blocklist or OpenSSH PerSourcePenalties (§5).
- **Fallbacks.** Fail2ban is the most widely packaged fallback (GPL, so run it as a separate process; do not link). sshguard is a tiny permissive C daemon, good where Python is unwanted. Neither uses kernel set timeouts, so a crashed daemon can leave bans in place. Fusion's own design should prefer kernel-expiring elements (§2).
- **Footprint budget on a 1 GB VPS.** CrowdSec engine (<100 MB) plus bouncer is acceptable. Vpatch-only AppSec costs about 0.2–0.5 ms per request. Full CRS in-band is expensive for POST-heavy apps (Laravel forms), so run it out-of-band or with body limits.

### Gaps
- No official RAM figures for Fail2ban (Python) or sshguard. They are generally small, but no measurement was found.
- The CrowdSec Partnership/MSSP price list is not public ("contact us"). Whether the free Console may be used by an MSP managing client engines under client-owned accounts was not confirmed by a primary source. Ask CrowdSec legal.
- The free-tier "3 blocklists" figure comes from a search summary, not a fetched page.
- No CrowdSec or Fail2ban documentation describes cross-IP password-spraying aggregation. Treat it as a design task.

---

## 2. Firewall control for automated response (nftables sets/timeouts, firewalld, iptables-nft, UFW, google/nftables, conntrack, Docker/Podman)

### Takeaway
Drive bans through a **dedicated agent-owned nftables table** using google/nftables (Apache-2.0, pure Go). Give it timeout-flagged sets so that every ban expires in the kernel even if the agent dies. Hook it early (prerouting at raw priority, plus input and forward) so it covers host services and Docker/Podman-published ports, and check the allowlist before any drop.

nftables semantics make this coexist with firewalld, UFW and Docker: a drop anywhere is final, and an accept only ends that one base chain. The same semantics mean Fusion can never "re-allow" what another tool drops. Docker's nftables backend (29.x) is still experimental with no `DOCKER-USER` chain. Podman 6 (netavark 2.0) is nftables-only. After a ban, delete conntrack entries and kill attacker sessions.

### Cited Findings

#### nftables semantics, sets and timeouts
- Set syntax: `add set ... { type ...; flags ...; timeout ...; gc-interval ...; elements = {...}; size ...; comment ...; policy ...; auto-merge; }`.
  - `timeout` is "time an element stays in the set, mandatory if set is added to from the packet path".
  - `gc-interval` only affects memory reclaim, not expiry.
  - Timed-out entries stay until the garbage collector removes them.
  - Source: [nft(8) man page](https://www.netfilter.org/projects/nftables/manpage.html)
- Evaluation — [nft(8): overall evaluation of the ruleset](https://www.netfilter.org/projects/nftables/manpage.html):
  - "Tables are merely a concept ... not relevant to the evaluation of the ruleset".
  - Chains on the same hook run in priority order (lower first).
  - An `accept` "ends the evaluation of the current base chain ... The packet advances to the next base chain".
  - A `drop` "immediately ends the evaluation of the whole ruleset ... It is therefore not possible to have a drop verdict changed to an accept in a later chain".
- `socket cgroupv2 level N "<path>"` matches packets by the owning socket's cgroup v2 ancestor, for example `"user.slice"`. This enables per-systemd-unit rules. — [nft(8)](https://www.netfilter.org/projects/nftables/manpage.html)
- iptables compatibility: legacy binaries are renamed `*-legacy`. The nf_tables-backed tools carry `-nft` (`xtables-nft-multi`, `iptables-nft`, and so on). — [nftables wiki: Legacy xtables tools](https://wiki.nftables.org/wiki-nftables/index.php/Legacy_xtables_tools). Detect the backend with `iptables -V` (`nf_tables` in the output). — [CrowdSec firewall bouncer docs](https://docs.crowdsec.net/u/bouncers/firewall)

#### google/nftables Go library
- A "third-party Go package to programmatically interact with nftables ... implemented in pure Go, i.e. does not wrap libnftnl". The README still warns it "is in very early stages". — [google/nftables README](https://github.com/google/nftables)
- Set support includes `HasTimeout`, a set-level `Timeout`, per-element `Timeout` (written as `NFTA_SET_ELEM_TIMEOUT` when the set has the timeout flag), `Expires`, element `Comment`, `Counter`, `Dynamic`, `Interval` and `AutoMerge`. — [google/nftables set.go](https://github.com/google/nftables/blob/main/set.go)
- License **Apache-2.0**. Latest tag **v0.3.0 (2025-02-06)**, still pre-1.0. — [LICENSE](https://github.com/google/nftables/blob/main/LICENSE); [releases](https://github.com/google/nftables/releases)
- In production use by CrowdSec's firewall bouncer (nftables mode). — [CrowdSec firewall bouncer docs](https://docs.crowdsec.net/u/bouncers/firewall)
- Conntrack from Go: `ti-mo/conntrack` (MIT). — [ti-mo/conntrack LICENSE](https://github.com/ti-mo/conntrack/blob/master/LICENSE)

#### conntrack and session killing
- `conntrack -D/--delete` deletes entries. `-E/--event` shows a real-time event log. Filters include source/destination, mark and labels. — [conntrack(8)](https://manpages.debian.org/trixie/conntrack/conntrack.8.en.html)
- `ss -K/--kill` "attempts to forcibly close sockets" (IPv4/IPv6). It silently skips sockets the kernel cannot close. — [ss(8)](https://manpages.debian.org/trixie/iproute2/ss.8.en.html)
- `conntrack-tools` is packaged everywhere: Debian 13 1.4.8, Ubuntu 24.04 1.4.8, Alma/Rocky 9 1.4.7, CentOS Stream 10 1.4.8. — [Repology: conntrack-tools](https://repology.org/project/conntrack-tools/versions)

#### firewalld (RHEL-family default)
- `NftablesTableOwner` (default **yes**): "the generated nftables rule set will be owned exclusively by firewalld. This prevents other entities from mistakenly (or maliciously) modifying firewalld's rule set." — [firewalld.conf(5) source](https://github.com/firewalld/firewalld/blob/main/doc/xml/firewalld.conf.xml)
- `FlushAllOnReload` defaults to yes. The iptables backend "is deprecated". — [firewalld.conf(5) source](https://github.com/firewalld/firewalld/blob/main/doc/xml/firewalld.conf.xml)
- `StrictForwardPorts` (default no): if yes, firewalld will "NOT accept traffic that was DNAT'd by other entities, e.g. docker ... not allow published container ports until they're explicitly allowed via firewalld"; if no, docker and podman integrate seamlessly. — [firewalld.conf(5) source](https://github.com/firewalld/firewalld/blob/main/doc/xml/firewalld.conf.xml)
- The **direct interface is deprecated** and "superseded by policies". — [firewalld.direct(5) source](https://github.com/firewalld/firewalld/blob/main/doc/xml/firewalld.direct.xml)
- `--add-rich-rule`, `--add-port` and `--add-service` accept `--timeout=<timeval>`: the rule "will be active for the specified amount of time and will be removed automatically", but `--timeout` is not combinable with `--permanent`. — [firewall-cmd(1) source](https://github.com/firewalld/firewalld/blob/main/doc/xml/firewall-cmd.xml.in)
- Rich-rule sources can be `ipset="..."`. — [firewalld.richlanguage(5) source](https://github.com/firewalld/firewalld/blob/main/doc/xml/firewalld.richlanguage.xml)
- ipset options include `timeout`, `hashsize` and `maxelem`. Entries added to an ipset with timeout "are not tracked by firewalld", and querying such an ipset "will yield an error". — [firewalld.ipset(5) source](https://github.com/firewalld/firewalld/blob/main/doc/xml/firewalld.ipset.xml); [firewall-cmd(1) source](https://github.com/firewalld/firewalld/blob/main/doc/xml/firewall-cmd.xml.in)
- Latest tag v2.5.2. — [firewalld tags](https://github.com/firewalld/firewalld/tags)

#### Docker
- iptables backend — [Docker docs: Docker with iptables](https://docs.docker.com/engine/network/firewall-iptables/):
  - Docker creates `DOCKER-USER`, `DOCKER-FORWARD`, `DOCKER`, `DOCKER-BRIDGE`, `DOCKER-INTERNAL` and `DOCKER-CT`.
  - `FORWARD` jumps unconditionally to `DOCKER-USER`, `DOCKER-FORWARD` and `DOCKER-INGRESS`.
  - When Docker enables IP forwarding it sets the `FORWARD` policy to DROP.
  - Rules must go in `DOCKER-USER`, because rules appended to FORWARD run after Docker's.
  - Packets reach `DOCKER-USER` *after DNAT*, so matching the original address and port needs `-m conntrack --ctorigdst/--ctorigdstport`.
  - Direct-routed packets to container IPs are dropped earlier in `raw PREROUTING`.
- Docker and **ufw are incompatible**. Published-port traffic "gets diverted before it goes through the ufw firewall settings". Docker routes it in the `nat` table "before it reaches the INPUT and OUTPUT chains that ufw uses". — [Docker docs: packet filtering and firewalls](https://docs.docker.com/engine/network/packet-filtering-firewalls/)
- Docker with **firewalld**: Docker creates a firewalld zone `docker` (target ACCEPT) and a policy `docker-forwarding` (ANY→docker). Setting `iptables`/`ip6tables: false` "is not appropriate for most users". — [Docker docs: packet filtering and firewalls](https://docs.docker.com/engine/network/packet-filtering-firewalls/)
- **nftables backend** ("introduced in Docker 29.0.0 is experimental") — [Docker docs: Docker with nftables](https://docs.docker.com/engine/network/firewall-nftables/):
  - Enabled with `"firewall-backend": "nftables"`. Not available in Swarm mode.
  - Tables `ip docker-bridges` and `ip6 docker-bridges`. "Do not modify Docker's tables".
  - **There is no `DOCKER-USER`**. Add your own table with base chains of the same type and hook, ordered by priority.
  - Because an nftables accept is not final, overriding Docker's drop needs `--bridge-accept-fwmark`, with the mark set at `filter - 1` or lower.
  - Docker will not enable IP forwarding itself in this mode.
  - An iptables `FORWARD` policy DROP will still drop packets Docker's nft rules accepted.
- Docker docs still label nftables experimental as of the 2026-11-09 docs snapshot. Latest Engine is **v29.9.3 (2026-11-03)**, with 29.10.0-rc.1 out. — [moby releases](https://github.com/moby/moby/releases); [Docker docs: Docker with nftables](https://docs.docker.com/engine/network/firewall-nftables/)
- The Docker daemon over TCP should use TLS on **2376**. — [Docker docs: protect the daemon socket](https://docs.docker.com/engine/security/protect-access/)

#### Podman / netavark
- `containers.conf` `firewall_driver`: empty means netavark picks. Options are `iptables`, `nftables`, `none`, and `firewalld` ("experimental ... not recommend outside of testing"). — [containers.conf(5)](https://github.com/containers/common/blob/main/docs/containers.conf.5.md)
- netavark 1.12 made nftables the default driver on Fedora 41. **netavark v2.0.0 (2026-06-10) "Removed iptables support"** and is required for Podman 6.0. It also made bridge networks strictly isolated by default. — [netavark RELEASE_NOTES](https://github.com/containers/netavark/blob/main/RELEASE_NOTES.md); [netavark releases](https://github.com/containers/netavark/releases)
- Current Podman releases: 6.1.4 and 5.8.9 (2026-10-12). — [podman releases](https://github.com/containers/podman/releases)

#### Existing tools' hook priorities
- Fail2ban nft action: input hook, priority -1. — [nftables.conf](https://github.com/fail2ban/fail2ban/blob/master/config/action.d/nftables.conf)
- sshguard: input hook, priority -10. — [sshg-fw-nft-sets.sh](https://github.com/SSHGuard/sshguard/blob/master/src/fw/sshg-fw-nft-sets.sh)
- CrowdSec set-only example: input hook, priority `filter`. — [CrowdSec firewall bouncer](https://docs.crowdsec.net/u/bouncers/firewall)

### Inferences (response-engine design for safe firewall actions)
- **Own table, never edit others'.**
  - Create `table inet fusion` through netlink (google/nftables batch, so changes apply atomically).
  - Never touch `firewalld`, `docker-bridges`, `f2b-*` or `crowdsec*` tables. firewalld's `NftablesTableOwner` protects only firewalld's table, so a separate table is the supported coexistence path.
  - The firewalld direct interface is deprecated; do not use it.
  - Optionally mirror bans into a firewalld ipset or a rich rule with `--timeout` for admin visibility. This is not required.
- **Where to hook.**
  - The `input` hook alone misses Docker/Podman-published ports, because that traffic is DNAT'd and forwarded.
  - A `prerouting` filter chain at `priority raw` (-300) drops banned source IPs before conntrack and DNAT. It covers host services and published container ports with either Docker backend, without needing `DOCKER-USER`. This follows from the nft hook and priority semantics; validate it on Docker 29 iptables/nftables and netavark 2.x.
  - Add an `output` chain for egress controls (§4) and a `forward` chain only if needed.
  - A sketch (to validate):
    ```
    table inet fusion {
      set allow4 { type ipv4_addr; flags interval; }               # admins, master server, break-glass, cloud metadata/DNS
      set allow6 { type ipv6_addr; flags interval; }
      set ban4   { type ipv4_addr; flags timeout; timeout 1h; size 65536; }   # per-element timeouts override default
      set ban6   { type ipv6_addr; flags timeout; timeout 1h; size 65536; }
      chain pre {
        type filter hook prerouting priority raw; policy accept;
        ip saddr @allow4 accept        # only ends THIS chain; others may still drop
        ip6 saddr @allow6 accept
        ip saddr @ban4 counter drop
        ip6 saddr @ban6 counter drop
      }
    }
    ```
- **Kernel-enforced expiry as a dead-man switch.** Every ban carries an element timeout (graduated, for example 15 min → 1 h → 24 h, capped). If the agent crashes or is removed, bans lapse in the kernel and do not need cleanup. Permanent blocks only come from explicit, human-approved policy.
- **Allowlist-first and "never ban" guards before any action.** Never ban:
  - configured admin CIDRs;
  - the master server and Discord/API egress;
  - the IP of any **currently established SSH session**, from `ss`/utmp or recent `Accepted publickey ... from <ip>` in the journal;
  - the default gateway, DNS resolvers, cloud metadata (169.254.169.254) and RFC1918 peers (unless policy says otherwise).
  - Cap bans per minute, never ban prefixes shorter than /24 (IPv4) or /48 (IPv6) automatically, and support simulation ("would ban") mode.
  - The same allowlist must be pushed into CrowdSec, Fail2ban and sshguard. An nft drop elsewhere is final, so Fusion cannot override it.
- **Break-glass.**
  - (a) A local CLI or TUI command and a root-only file that flushes `table inet fusion` and pauses response.
  - (b) An automatic rollback timer for any rule touching the SSH port, in commit-confirm style: apply, verify, else revert.
  - (c) If the master server is unreachable for N minutes, stop adding bans, but keep timeouts running so bans drain.
  - (d) Document cloud serial-console access per provider.
- **Killing live sessions after a ban.**
  - An existing TCP flow keeps working if the host firewall accepts `ct state established` before the drop. Dropping in a prerouting raw chain avoids that.
  - Then delete flows with `conntrack -D -s <ip>` (and `-d <ip>` for reply direction), or `ss -K dst <ip>`.
  - Terminate attacker-owned `sshd-session` processes or `loginctl terminate-session`, after checking the session is not from an allowlisted IP.
- **UFW hosts.** Leave UFW in place. Fusion's table is evaluated alongside it, and drops are final either way. Docker-published ports bypass UFW, which is another reason to enforce at prerouting.
- **iptables-legacy hosts.** Both legacy x_tables and nf_tables hooks run, so an nft drop still applies. Detect the backend with `iptables -V` and report it in inventory.

### Gaps
- Whether `firewall-cmd --reload` or `FlushAllOnReload` ever touches non-firewalld nft tables was not confirmed from a primary source (the expectation is no). Test on RHEL 9/10.
- Kernel support for timeouts on interval sets (CIDR bans with expiry) across RHEL 9 (5.14) and older Ubuntu kernels was not verified. Separate host and CIDR sets may be needed.
- Exact Docker 29 nftables base-chain priorities live in moby internal docs and were not fetched. Docker says they "are likely to change between Docker Engine releases".
- Amazon Linux 2023's default firewall stance (no firewalld by default?) and AL2023 package availability for these tools were not verified. Repology has no AL2023 rows.

---

## 3. Network IDS/IPS: Suricata, Zeek, Snort 3 on a single cloud server; lighter alternatives

### Takeaway
Suricata 8.0.x is the only maintained branch; 7.0 has been EOL since 2026-07-07. It is the practical NIDS if one is wanted. In IDS mode (AF_PACKET, tpacket-v3) with a trimmed ET Open ruleset it fits roughly 160–450 MB, from user reports. Inline NFQUEUE IPS on a single VPS can drop all traffic if Suricata stops, unless `bypass` is set, so drive blocking from the agent instead.

Zeek is heavy, analysis-oriented and poorly packaged in distros. Snort 3 (GPLv2) is not packaged in distros (Ubuntu still ships Snort 2.9) and its best rules are paid. For miners, reverse shells and C2, process-attributed connection telemetry (eBPF, conntrack events) on the host gives most of the value at a fraction of the cost.

### Cited Findings
- **Suricata** stable is **8.0.8 (2026-10-29)**. — [suricata.io download](https://suricata.io/download/)
- EOL policy: a major version every 2 years, each supported 3 years. "**7.0.x: end of life since July 7th, 2026**"; 6.0.x EOL 2024-08-01. — [Suricata EOL policy](https://suricata.io/our-story/eol-policy/)
- License GPLv2. — [Suricata LICENSE](https://github.com/OISF/suricata/blob/master/LICENSE)
- Packaging:
  - OISF PPA `ppa:oisf/suricata-stable` (Ubuntu); `dnf copr enable @oisf/suricata-8.0` plus EPEL for EL and rebuilds; Debian backports. — [Suricata install docs: Ubuntu](https://docs.suricata.io/en/latest/install/ubuntu.html); [RPM](https://docs.suricata.io/en/latest/install/rpm.html); [Debian](https://docs.suricata.io/en/latest/install/debian.html)
  - Distro versions are mostly on the EOL 7.0 branch: Debian 13 7.0.10, Ubuntu 24.04 7.0.3, EPEL 8/9 7.0.17. EPEL 10 has 8.0.7 and Fedora 44 has 8.0.8. — [Repology: suricata](https://repology.org/project/suricata/versions)
- **NFQUEUE IPS**: `nft add rule filter IPS queue num 3-5 options fanout,bypass`. "By default, if no userspace program is listening on an Netfilter queue, then all packets that are to be queued are dropped." `bypass` makes the queue "behave like ACCEPT if there is no program listening", at the cost of losing blocking while Suricata is down. — [Suricata docs: IPS inline for Linux](https://docs.suricata.io/en/latest/ips/setting-up-ipsinline-for-linux.html)
- Suricata 8 adds an experimental **firewall mode**: a default-drop policy, a new `accept` action, rule hooks and separate firewall rule files. "features and behavior are still subject to change". — [Suricata docs: firewall mode design](https://docs.suricata.io/en/latest/firewall/firewall-design.html)
- Memory controls include `detect.profile` (`low`, `medium` default, `high`), flow memcap and hash sizes, and `stream.memcap` (example 64mb). — [Suricata docs: suricata.yaml](https://docs.suricata.io/en/latest/configuration/suricata-yaml.html)
- **Real-world footprint** (forum user report, 2026-02-10): Suricata 7.x with about 48,000 ET Open rules in AF_PACKET mode used 900–1,828 MB RSS with tpacket-v2 and **160–454 MB with tpacket-v3**. An OISF developer replied that "Suricata 8.0 uses v3 by default". — [Suricata forum: tpacket-v3 vs v2 memory](https://forum.suricata.io/t/real-world-data-af-packet-tpacket-v3-vs-v2-memory-impact/6193)
- **Comparable OSS design**: NFTBan, a Go daemon that consumes Suricata `eve.json` and applies temporary nftables bans on single VPSs. On a 4-core VPS it reported about 800 MB RSS, about 15% CPU and **300–500 ms alert→nft-ban latency**. Tuning applied: 60 s established TCP timeout, HTTP body inspection off, unused parsers off. — [Suricata forum: NFTBan tuning thread](https://forum.suricata.io/t/af-packet-mode-guidance-requested-on-performance-oriented-suricata-tuning-for-single-server-automated-response-nftban/6146). NFTBan is MPL-2.0, latest v1.236.0 (2026-11-08). — [NFTBan GitHub](https://github.com/itcmsgr/nftban)
- **ET Open licensing** (LICENSE inside the 2026-11-06 tarball) — [ET Open suricata-7.0.3 ruleset](https://rules.emergingthreats.net/open/suricata-7.0.3/emerging.rules.tar.gz); [ET Open index](https://rules.emergingthreats.net/open/):
  - SIDs 1–3464 and 100000000–100000908 are **GPLv2**;
  - SIDs 2000000–2799999 are **BSD** ("Copyright (c) 2003-2026, Emerging Threats");
  - SIDs 2800000–2900000 fall under the ET Pro license.
  - The tarball has 61 files, including emerging-coinminer, attack_response, web_server, scan, dns and compromised.
  - ET publishes suricata-5.0 and suricata-7.0.3 trees.
- **Zeek**: v9.0.1 and LTS 8.0.11 (2026-10-26). Binary packages come via the openSUSE Build Service (`zeek-8.0` LTS, `zeek` latest, nightly, rc), for example `security:zeek` for xUbuntu_24.04. — [Zeek releases](https://github.com/zeek/zeek/releases); [Zeek install docs](https://docs.zeek.org/en/master/install.html). BSD-style license. — [Zeek COPYING](https://github.com/zeek/zeek/blob/master/COPYING). Distro packages are stale: EPEL 8/9 zeek 4.2.0, Fedora 6.0.4. — [Repology: zeek](https://repology.org/project/zeek/versions)
- **RITA** (Active Countermeasures) ingests Zeek logs for beaconing, long connections, DNS tunnelling and threat-intel checks. It needs Docker Engine with Compose and is GPLv3. — [RITA README](https://github.com/activecm/rita); [RITA LICENSE](https://github.com/activecm/rita/blob/main/LICENSE)
- **Snort 3**: 3.13.2.0 (2026-11-05), GPLv2. — [snort3 releases](https://github.com/snort3/snort3/releases); [LICENSE](https://github.com/snort3/snort3/blob/master/LICENSE). Ubuntu ships only Snort 2.9.x (22.04: 2.9.15.1, 24.04: 2.9.20). — [Repology: snort](https://repology.org/project/snort/versions)
- **Talos rules** (from a search summary; pages not fetched):
  - Community ruleset is free (GPLv2).
  - Registered users get Talos rules after a 30-day delay.
  - Subscribers pay.
  - A newer rule source is delivered only to subscribers.
  - Subscriber license v3.1 restricts distribution.
  - Sources: [snort.org](https://www.snort.org/); [snort.org/subscribe](https://snort.org/subscribe); [Snort Subscriber Rules License 3.1 copy](https://open.windriver.com/info/uni-license-list/licenses/snort-subscriber-rules-3.1.html)
- **Lighter alternatives**:
  - BCC/eBPF `tcpconnect` "traces the kernel function performing active TCP connections (eg, via a connect() syscall)" and prints PID, COMM, source and destination addresses and port. — [bcc tcpconnect example](https://github.com/iovisor/bcc/blob/master/tools/tcpconnect_example.txt)
  - `conntrack -E` streams flow events. — [conntrack(8)](https://manpages.debian.org/trixie/conntrack/conntrack.8.en.html)

### Inferences
- **When a NIDS is worth it.** On a 1 GB VPS, skip Suricata by default; the host agent, CrowdSec and nft bans cover SSH and web. On 2–4 GB servers with public services, offer Suricata 8 IDS as an optional module:
  - AF_PACKET with tpacket-v3, `detect.profile: low`;
  - only the ET categories that matter (coinminer, attack_response, compromised/botcc, exploit/web_server, scan);
  - HTTP body inspection off, short flow timeouts;
  - consume `eve.json` alerts into the deterministic engine.
- **Avoid NFQUEUE inline** on single-NIC VPSs. If used, always set `bypass` (fail-open), because a Suricata crash otherwise drops all queued traffic, including SSH.
- **Use the vendor branch.** Distro Suricata on Debian 13 and Ubuntu 24.04 is on EOL 7.0; prefer the OISF PPA/COPR (8.0).
- **Zeek and RITA** are better on the master server or a dedicated sensor, for example offline analysis of exported flow logs, than on customer VPSs.
- **Snort 3** offers no advantage here: no distro packages, and the best rules are paid with redistribution limits.
- **ET Open in a commercial product.** The BSD-licensed SIDs (2000000–2799999) can be shipped or redistributed with attribution. GPLv2 SIDs carry GPL obligations on redistribution. Fusion's master server could curate a subset.
- **Host telemetry first.** An eBPF connect/accept tracer attributes each flow to PID, executable and cgroup. That is more useful than packets for the motivating incident (miner, watchdog, reverse shell) and costs little.

### Gaps
- No official OISF minimum-RAM guidance for Suricata 8 on 1–2 GB hosts. The figures above are user reports.
- No primary measurement found for Zeek memory on a small single host.
- The Snort/Talos licensing facts came from search summaries; snort.org was not fetched directly.

---

## 4. Outbound and DNS controls: reverse shells, mining pools (Stratum), C2 beaconing, DNS sinkholing/RPZ, dnstap, per-service egress allowlisting, eBPF/cgroup egress filtering

### Takeaway
Detect miners by **protocol content and process context**, not ports:
- Stratum JSON-RPC `"method":"login"` with an `"agent"` field (XMRig-style), or `mining.subscribe`/`mining.authorize`;
- `stratum+tcp://` on a command line;
- known miner binaries;
- pool DNS names.

Real malware uses ports 80, 442 and 4444. Enforce **default-deny egress for service accounts** (php-fpm, nginx, www-data) with systemd `IPAddressAllow=`/`IPAddressDeny=` (cgroup eBPF) or nftables `socket cgroupv2` rules. Add a **DNS RPZ sinkhole** (Unbound has RPZ and dnstap; dnsmasq can sinkhole but has no dnstap) fed by the master server's IOC list.

### Cited Findings
- **ET Open Stratum signatures**: — [ET Open ruleset](https://rules.emergingthreats.net/open/suricata-7.0.3/emerging.rules.tar.gz)
  - "ET INFO Cryptocurrency Miner Checkin" matches outbound TCP starting with `{"id":`, containing `"jsonrpc":`, `","method":"login","params":`, `"pass":"` and `"agent":"`, while excluding HTML. "M2" drops the `pass` requirement.
  - "ET COINMINER W32/BitCoinMiner.MultiThreat Subscribe/Authorize Stratum Protocol Message" matches `"method":` followed closely by `"mining.`.
  - Server-side matches cover `mining.notify` responses.
  - DNS and TLS-SNI matches cover pools, for example `xmr.2miners.com` in DNS and `pool.supportxmr.com` in SNI.
- **Falco rules (Apache-2.0)** — [Falco sandbox rules](https://github.com/falcosecurity/rules/blob/main/rules/falco-sandbox_rules.yaml); [falcosecurity/rules LICENSE](https://github.com/falcosecurity/rules/blob/main/LICENSE):
  - `miner_ports` = 25, 3333, 3334, 3335, 3336, 3357, 4444, 5555, 5556, 5588, 5730, 6099, 6666, 7777, 7778, 8000, 8001, 8008, 8080, 8118, 8333, 8888, 8899, 9332, 9999, 14433, 14444, 45560, 45700.
  - "Detect outbound connections to common miner pool ports" is **disabled by default** because of DNS noise.
  - "Detect crypto miners using the Stratum protocol" matches cmdlines containing `stratum+tcp`, `stratum2+tcp`, `stratum+ssl` or `stratum2+ssl`.
  - `miner_binaries` = xmrig, xmr-stak, minerd, minergate, cpuminer, ccminer, ethminer, cgminer, bfgminer, sgminer, claymore, nbminer, t-rex, gminer, lolminer, phoenixminer, teamredminer, nanominer, bminer, wildrig, srbminer.
  - A `miner_domains` list is included (for example `ca.minexmr.com`, `cn.stratum.slushpool.com`).
- **Port lists are insufficient.** Outlaw (Elastic, 2025-04-01) routes "Mining traffic ... to multiple Monero pools over plaintext ports (:80, :4444), SSL (:442), and occasionally TOR". It uses modified XMRig binaries named `kswapd0`/`kswapd01` and IRC (STEALTH SHELLBOT) for C2. — [Elastic Security Labs: Outlaw](https://www.elastic.co/security-labs/outlaw-linux-malware)
- **Reverse shells**:
  - ET "ET ATTACK_RESPONSE Interactive Reverse Shell Without TTY (Outbound)" matches outbound `sh: no job control in this shell`. — [ET Open ruleset](https://rules.emergingthreats.net/open/suricata-7.0.3/emerging.rules.tar.gz)
  - Falco "Redirect STDOUT/STDIN to Network Connection in Container" fires on a `dup*` syscall whose result fd is 0, 1 or 2 and whose fd type is ipv4/ipv6. It is behaviour-based and "may generate noise". — [Falco rules](https://github.com/falcosecurity/rules/blob/main/rules/falco_rules.yaml)
- **C2 beaconing**: RITA does beaconing, long-connection and DNS-tunnelling detection over Zeek logs. — [RITA](https://github.com/activecm/rita)
- **Unbound RPZ** — [unbound.conf(5)](https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound.conf.html):
  - multiple `rpz:` clauses, applied in order;
  - `rpz-action-override` = nxdomain, nodata, passthru, drop, disabled or cname (with `rpz-cname-override`);
  - `rpz-log`/`rpz-log-name` log applied actions;
  - zones load from a primary, a URL or a zonefile.
- **Unbound dnstap**: built with `--enable-dnstap`; `dnstap-enable` plus per-type switches (`dnstap-log-client-query-messages`, `...-client-response-messages`, `...-resolver-*`, `...-forwarder-*`, all default no). — [unbound.conf(5)](https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound.conf.html)
- Unbound packages: Debian 13 1.26.2, Ubuntu 24.04 1.19.2, Alma/Rocky 9 1.24.2, CentOS Stream 10 1.26.1. — [Repology: unbound](https://repology.org/project/unbound/versions)
- **dnsmasq**:
  - `--address=/<domain>/[<ipaddr>]` answers locally and never forwards (sinkhole), and `/#/` matches any domain.
  - `--log-queries[=extra]` logs queries; `extra` adds a per-query serial and the requestor IP.
  - The man page has **no dnstap support** (0 mentions).
  - Source: [dnsmasq man page](https://thekelleys.org.uk/dnsmasq/docs/dnsmasq-man.html)
  - Packages: Debian 13 2.91, Ubuntu 24.04 2.91, Alma/Rocky 9 2.85. — [Repology: dnsmasq](https://repology.org/project/dnsmasq/versions)
- **systemd per-service egress** — [systemd.resource-control(5)](https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html):
  - `IPAddressAllow=` and `IPAddressDeny=` (since v235) filter ingress (by source) and egress (by destination) for the unit's cgroup. Allow wins over deny; otherwise access is granted.
  - Recommended allow-listing pattern: "`IPAddressDeny=any` on an upper-level slice ... plus individual per-service `IPAddressAllow=`".
  - The filter "cannot be bypassed by prefixing '+'", but has no effect where eBPF cgroup support is missing. Do not rely on it exclusively.
  - `SocketBindAllow=`/`SocketBindDeny=` restrict `bind()`.
- **nftables per-service egress**: `socket cgroupv2 level N "<slice/unit>"` matching. — [nft(8)](https://www.netfilter.org/projects/nftables/manpage.html)

### Inferences
- **Layered miner and C2 detection in the agent.**
  - (1) Process: binary name and hash, cmdline `stratum+tcp`, deleted or memfd executables, sustained CPU.
  - (2) Connection: eBPF connect events with PID, cgroup and destination. Flag long-lived outbound flows from unexpected processes, especially web or service users.
  - (3) Optional Suricata ET COINMINER/INFO rules.
  - (4) DNS: queries to pool domains through RPZ logging or dnstap.
  - Treat ports (3333/4444/14444, and so on) only as a weak score component.
- **Egress policy per service.** On typical Laravel/PHP servers, php-fpm only needs DB, Redis, SMTP and a few APIs. Default-deny for `php-fpm.service`, `nginx.service`, `redis.service` and `docker` containers turns RCE-to-reverse-shell or RCE-to-miner-download into a blocked, alerting event.
  - Implement with systemd drop-ins (`IPAddressDeny=any` plus allowlist) or nft `socket cgroupv2` / `meta skuid` rules in the agent table.
  - Ship it in **learn mode first** (observe 7 days, then propose), so legitimate integrations do not break.
- **DNS.** Unbound on 127.0.0.1 with an RPZ zone generated by the master server (IOC domains, mining pools, DoH endpoints if policy allows) gives both blocking and per-query logging (`rpz-log`; dnstap for structured events).
  - On Ubuntu, `systemd-resolved` is the stub resolver. Forward resolved to the local Unbound, or point `/etc/resolv.conf` at Unbound. Both need care to avoid breaking resolution.
  - Malware can bypass local DNS with hardcoded IPs or DoH, so DNS controls complement egress firewalling rather than replace it.
- **Beaconing analytics.** The agent ships compact flow summaries (5-tuple, process, start/stop, bytes) to the master, which runs RITA-like periodicity scoring. Avoid running Zeek or RITA on small VPSs.

### Gaps
- Mining-pool blocklists: CoinBlockerLists (GitLab) returned HTTP 403, so its license and maintenance status were not verified. No other primary pool-list source was fetched. Falco's and ET's lists are partial and dated.
- Interaction details of `systemd-resolved` with a local Unbound on Ubuntu 24.04/26.04 were not fetched.
- No primary data on the false-positive rate of the Falco dup-to-socket rule outside containers.

---

## 5. SSH hardening and identity: ssh-audit, sshd_config, pam_faillock, MFA, SPA/port knocking, session recording, authorized_keys tampering, geo/ASN signals

### Takeaway
OpenSSH itself now does much of the brute-force throttling. **PerSourcePenalties is on by default since 9.8** (2024-07-01), and an `invaliduser` penalty was added in 10.3. OpenSSH 10.0 made **ML-KEM hybrid PQ key exchange the default**, removed DSA and split pre-auth into `sshd-auth`. The latest release is **OpenSSH 10.6 (2026-10-06)**.

Audit configurations with **ssh-audit 3.9.0** (MIT; built-in policies and hardening guides for Debian 13, Rocky 10 and Ubuntu 26.04). Enforce key-only login, no root, `AllowGroups`, low `MaxAuthTries`, and FIDO2 `sk` keys or SSH certificates for MFA. pam_faillock only protects PAM/password paths and can lock admins out, so use it cautiously. Session recording comes from tlog or pam_tty_audit.

Outlaw-style key implants (`chattr +ia` on `~/.ssh`) call for file-integrity monitoring and immutable-attribute checks on `authorized_keys`. Geo/ASN anomalies should only alert. IPinfo Lite (CC BY-SA 4.0) and DB-IP Lite (CC BY 4.0) are product-friendly. MaxMind GeoLite requires consent before disclosure to third parties.

### Cited Findings
- **OpenSSH releases**: 10.6 (2026-10-06), 10.5 (2026-08-11), 10.4 (2026-07-06), 10.3 (2026-04-02), 10.2 (2025-10-10), 10.1 (2025-10-06), 10.0 (2025-04-09), 9.8 (2024-07-01). — [OpenSSH release notes](https://www.openssh.org/releasenotes.html)
- **9.8 changes**: sshd "will now penalise client addresses that ... do not successfully complete authentication ... controlled by a new sshd_config(5) PerSourcePenalties option and is on by default". Once the penalty passes a threshold, "all connections from the client address will be refused (along with any others in the same PerSourceNetBlockSize CIDR range)", and repeat offences accrue up to a maximum. 9.8 also split sshd into `sshd` plus `sshd-session`, so log lines now come from "sshd-session". Log parsers must handle that. — [OpenSSH 9.8 notes](https://www.openssh.org/releasenotes.html)
- **PerSourcePenalties defaults**: `crash` 90s, `authfail` 5s, `invaliduser` 5s, `refuseconnection` 10s, `noauth` 1s, `grace-exceeded` 10s, `max` 10m, `min` 15s, `max-sources4/6` 65536, `overflow` permissive. `PerSourcePenaltyExemptList` exempts addresses. — [sshd_config(5)](https://man.openbsd.org/sshd_config)
- `invaliduser` was added in **10.3**, "applied to login attempts for usernames that do not match real accounts". — [OpenSSH 10.3 notes](https://www.openssh.org/releasenotes.html)
- **10.0 changes**: DSA removed; `mlkem768x25519-sha256` is the default key agreement; a new `sshd-auth` binary for the pre-auth attack surface; finite-field DH removed from the server's default KEX list. — [OpenSSH 10.0 notes](https://www.openssh.org/releasenotes.html)
- **10.1 changes**: the client warns when it negotiates a non-post-quantum key agreement (`WarnWeakCrypto`, default on). — [OpenSSH 10.1 notes](https://www.openssh.org/releasenotes.html)
- **sshd_config defaults** — [sshd_config(5)](https://man.openbsd.org/sshd_config):
  - `MaxAuthTries` 6; `MaxStartups` 10:30:100; `LoginGraceTime` 120 s;
  - `PermitRootLogin` defaults to `prohibit-password`; `PasswordAuthentication` defaults to yes;
  - `AuthorizedKeysFile` defaults to `.ssh/authorized_keys .ssh/authorized_keys2` and accepts tokens and absolute paths;
  - `StrictModes` yes;
  - `AllowGroups` matches primary or supplementary groups;
  - `AuthenticationMethods` can require chains (for example `publickey,keyboard-interactive`);
  - `TrustedUserCAKeys` enables user certificates and requires principals;
  - `PubkeyAuthOptions touch-required|verify-required` applies to FIDO `ecdsa-sk`/`ed25519-sk`.
- FIDO/U2F authenticator support arrived in **OpenSSH 8.2 (2020-02-14)**. — [OpenSSH 8.2 notes](https://www.openssh.org/releasenotes.html)
- **Mozilla OpenSSH guideline** — [Mozilla OpenSSH guidelines](https://infosec.mozilla.org/guidelines/openssh):
  - "Modern" config: Ed25519-first host keys; `curve25519-sha256@libssh.org` and ECDH KEX; `chacha20-poly1305`/AES-GCM/CTR ciphers; ETM MACs; `AuthenticationMethods publickey`; `LogLevel VERBOSE`; sftp logging; `PermitRootLogin No`.
  - MFA is recommended. When keyboard-interactive is used for OTP, ensure PAM cannot authenticate with passwords.
  - The page carries a ©2017 footer, so it **predates PQ KEX and is dated**.
- **ssh-audit** — [ssh-audit README](https://github.com/jtesta/ssh-audit); [LICENSE](https://github.com/jtesta/ssh-audit/blob/master/LICENSE):
  - **v3.9.0 (2026-07-04)**, MIT.
  - Audits server and client algorithms, banner, version and CVE history; policy scans (`-P`, `-L`); built-in hardening guides (`--list-hardening-guides`/`--get-hardening-guide`).
  - New in 3.9.0: warnings for KEX without quantum protection; policies for OpenSSH 10.0–10.4; guides and policies for Debian 13, Rocky 10 and Ubuntu 26.04; the DHEat DoS test (`--dheat`, CVE-2002-20001); SOCKS5 and UNIX-socket targets.
  - Python 3.10–3.14 with no dependencies; pip, snap or Docker.
  - Distro packages lag: Debian 13 3.3.0, Ubuntu 24.04 3.1.0, EPEL 9/10 3.3.0. — [Repology: ssh-audit](https://repology.org/project/ssh-audit/versions)
- **pam_faillock** — [faillock.conf(5)](https://github.com/linux-pam/linux-pam/blob/master/modules/pam_faillock/faillock.conf.5.xml); [pam_faillock(8)](https://github.com/linux-pam/linux-pam/blob/master/modules/pam_faillock/pam_faillock.8.xml):
  - `deny` default 3; `fail_interval` 900 s; `unlock_time` 600 s (0 = never);
  - `even_deny_root` and `root_unlock_time`; `admin_group`; `local_users_only`; `silent`; `audit`.
  - Hooks are `preauth`, `authfail` and `authsucc`.
  - The tally directory `/var/run/faillock` is cleared at reboot unless `dir=` is set.
  - Shipped in Debian's `libpam-modules` (bookworm) and Ubuntu noble. — [Debian manpage](https://manpages.debian.org/bookworm/libpam-modules/pam_faillock.8.en.html); [Ubuntu manpage](https://manpages.ubuntu.com/manpages/noble/man8/pam_faillock.8.html)
- **MFA packages**: Google Authenticator PAM is `google-authenticator` in EPEL 8/9/10 (1.07/1.09/1.11) and Fedora (1.11), and the `google-authenticator` source package in Debian 13 (20191231) and Ubuntu 26.04 (20250213-1.11). — [Repology: google-authenticator-libpam](https://repology.org/project/google-authenticator-libpam/versions). The Debian/Ubuntu binary package is commonly `libpam-google-authenticator`; that name was not verified from a fetched source.
- **fwknop (SPA)** — [fwknop README](https://github.com/mrash/fwknop); [COPYING](https://github.com/mrash/fwknop/blob/master/COPYING); [releases](https://github.com/mrash/fwknop/releases); [Repology: fwknop](https://repology.org/project/fwknop/versions):
  - Authorisation via "only a single packet which is encrypted, non-replayable, and authenticated via an HMAC", behind a default-drop firewall, so services "cannot be scanned for with Nmap".
  - Supports iptables, firewalld, PF and ipfw, plus custom scripts for ipset or nftables.
  - Argues port knocking is weak against replay and spoofing DoS.
  - GPLv2. Release 2.6.11 tagged 2024-02-07 (pre-release dated 2019).
  - Packages: Debian 13 2.6.11, Ubuntu 24.04 2.6.10, EPEL 8/9 2.6.10, EPEL 10 2.6.11.
- **Session recording**:
  - **tlog** records terminal I/O as JSON to syslog or journald. `tlog-rec-session` runs as the login shell "with protection from recorded users", and `tlog-play` replays. GPLv2, v14 (2024-02-06). — [tlog README](https://github.com/Scribery/tlog); [COPYING](https://github.com/Scribery/tlog/blob/main/COPYING); [releases](https://github.com/Scribery/tlog/releases)
  - tlog packages: v14 in Alma/Rocky 9, CentOS Stream 10, Ubuntu 24.04 and Fedora; v12.1 in Debian 12. — [Repology: tlog](https://repology.org/project/tlog/versions)
  - **pam_tty_audit** enables kernel TTY input auditing per user pattern ("By default, the kernel does not audit input on any TTY"); view with `aureport --tty`. `log_passwd` (logging input with echo off) is off by default. — [pam_tty_audit(8)](https://github.com/linux-pam/linux-pam/blob/master/modules/pam_tty_audit/pam_tty_audit.8.xml)
- **authorized_keys tampering (Outlaw)**: after SSH brute force, "the malware replaces the existing SSH authorized_keys file with a new version containing a malicious SSH public key". It "removes and recreates the victim's ~/.ssh folder, injects an attacker-controlled SSH public key, and re-applies restrictive permissions (chattr +ia)". The script also runs `chattr -ia .ssh; lockr -ia .ssh`. — [Elastic Security Labs: Outlaw (2025-04-01)](https://www.elastic.co/security-labs/outlaw-linux-malware)
- **Kinsing** brute-forces SSH, searches `bash_history` and private keys, parses `known_hosts` and `/etc/hosts`, and uses valid SSH credentials to move laterally. — [MITRE ATT&CK S0599 Kinsing](https://attack.mitre.org/software/S0599/)
- **Geo/ASN data licences**:
  - IPinfo Lite: country plus ASN, updated daily, unlimited, "released under the Creative Commons Attribution-ShareAlike 4.0 ... freely use and incorporate the data into commercial and non-commercial applications" with attribution. — [IPinfo Lite](https://ipinfo.io/lite)
  - DB-IP Lite: CC BY 4.0, updated monthly, attribution required. — [DB-IP Lite](https://db-ip.com/db/lite.php)
  - MaxMind GeoLite EULA (updated 2026-02-12) — [MaxMind GeoLite EULA](https://www.maxmind.com/en/geolite2/eula); [MaxMind GeoLite](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data):
    - needs an account and licence key, and incorporates CC BY-SA 4.0;
    - "you will not disclose the Services to any third party without notifying MaxMind ... and obtaining MaxMind's prior written consent" (except as CC permits);
    - old versions must be destroyed within 30 days of an update.

### Inferences
- **Policy baseline**, checked in audit mode first and applied only with operator approval:
  - `PermitRootLogin no`, `PasswordAuthentication no`, `KbdInteractiveAuthentication no` unless OTP is used;
  - `AllowGroups sshusers`, `MaxAuthTries 3`, `LoginGraceTime 30`, `MaxStartups 10:30:60`, `LogLevel VERBOSE`;
  - keep PerSourcePenalties on, with `PerSourcePenaltyExemptList` set to admin and bastion CIDRs;
  - prefer the default KEX on OpenSSH ≥10, and run ssh-audit policy checks per distro;
  - MFA options: FIDO2 `ed25519-sk` with `PubkeyAuthOptions verify-required`, or short-lived SSH certificates (`TrustedUserCAKeys` plus principals), or `AuthenticationMethods publickey,keyboard-interactive` with TOTP.
- **Safe config changes.**
  - Validate with `sshd -t`.
  - Keep the current session open and apply with an automatic rollback timer.
  - Never restart sshd in a way that drops the operator. A reload keeps existing sessions.
  - Always verify that at least one allowlisted admin path works.
- **pam_faillock** doesn't count public-key failures, because those don't go through the PAM auth stack. It can let attackers deliberately lock named admin accounts if password auth is enabled. If enabled at all, keep `even_deny_root` off, use a short `unlock_time` and `local_users_only`. Network-level throttling (PerSourcePenalties plus agent bans) is the better primary control.
- **SPA / port knocking.** fwknop is mature but low-activity (last tagged release 2024). For "hide SSH" use cases, a WireGuard/VPN or bastion-only `AllowUsers user@CIDR` plus agent allowlists are simpler. Offer fwknop as optional.
- **authorized_keys tamper detection**, a deterministic, high-fidelity rule set:
  - FIM baseline and hash of every `AuthorizedKeysFile` path;
  - inotify/fanotify or an auditd watch (`-w <path> -p wa`) for writes;
  - alert on any `chattr +i/+a` on `~/.ssh` or authorized_keys (Outlaw IOC), and on keys with known-bad fingerprints or comments from the master server;
  - auto-response: quarantine the added key line, keep a backup, alert. Do not delete the original admin keys.
  - Hardening option: move keys to root-owned `/etc/ssh/authorized_keys/%u` via `AuthorizedKeysFile` so a user-level compromise can't add keys.
- **Geo/ASN signals.** Use IPinfo Lite or DB-IP Lite (attribution in UI and docs) for "new country/ASN for this user" and "login from hosting ASN" anomalies. Produce **alert-only** decisions; never auto-block successful key-based admin logins on geo alone. Avoid bundling GeoLite in the product unless MaxMind consents.
- **Session recording.** On RHEL-family, tlog is packaged and is the native choice (journald). On Debian/Ubuntu, pam_tty_audit with auditd is the low-cost option. Both have privacy implications, so make them per-policy opt-in.

### Gaps
- The Red Hat session-recording documentation (tlog + SSSD/Cockpit integration) returned 404 at the guessed URL, so SSSD-based enablement steps are not sourced here.
- The OpenSSH versions shipped by Debian 13, Ubuntu 24.04/26.04, RHEL 9/10 and AL2023 (and so PerSourcePenalties availability) were not looked up. RHEL 9 is believed to ship OpenSSH 8.7 without PerSourcePenalties, but this was not verified.
- auditd rule syntax and `auditctl` documentation were not fetched; the syntax above is standard but unsourced here.

---

## 6. Deception: Cowrie, OpenCanary, self-hosted Canarytokens; canary file and credential design; licenses

### Takeaway
Cowrie (SSH/Telnet honeypot, BSD-3-Clause, v3.1.6, 2026-11-09) and OpenCanary (multi-protocol, BSD-3-Clause, v0.9.10, 2026-09-21) are permissively licensed, active Python projects. Canarytokens is **GPLv3 with Thinkst's broad "derivative work" interpretation**; they sell alternative licences for embedding in proprietary software. So Fusion should **implement its own canary files, credentials and tripwire listeners in Go** rather than embed Canarytokens code. Self-hosted Canarytokens needs real domains with NS delegation and an email provider.

### Cited Findings
- **Cowrie** — [Cowrie README](https://github.com/cowrie/cowrie/blob/main/README.rst); [releases](https://github.com/cowrie/cowrie/releases); [LICENSE](https://github.com/cowrie/cowrie/blob/main/LICENSE.rst); [cowrie.cfg.dist](https://github.com/cowrie/cowrie/blob/main/src/cowrie/data/etc/cowrie.cfg.dist):
  - medium/high-interaction SSH and Telnet honeypot with an emulated shell and fake filesystem;
  - proxy mode to real or QEMU backends, and an experimental LLM mode;
  - saves files fetched with wget/curl or uploaded via SFTP/scp; JSON logging; UML-compatible session replay;
  - install via pip, Docker or git;
  - v3.1.6 released 2026-11-09 (weekly 3.1.x cadence); BSD-3-Clause;
  - default config: SSH `listen_endpoints = tcp:2222:interface=0.0.0.0`, Telnet disabled (2223), JSON log output enabled.
- Fail2ban's development branch adds a Cowrie JSON filter and jail. — [fail2ban ChangeLog](https://github.com/fail2ban/fail2ban/blob/master/ChangeLog)
- **OpenCanary** — [OpenCanary README](https://github.com/thinkst/opencanary); [default settings.json](https://github.com/thinkst/opencanary/blob/master/opencanary/data/settings.json); [LICENSE](https://github.com/thinkst/opencanary/blob/master/LICENSE); [releases](https://github.com/thinkst/opencanary/releases):
  - a daemon in Python 3.10+ with "extremely low resource requirements ... a Raspberry Pi or a VM with minimal resources"; the open-source version of Thinkst Canary;
  - modules: ftp, git, http, httpproxy, https, llmnr, mssql, mysql, ntp, portscan, rdp, redis, sip, smb (requires Samba), snmp (requires Scapy), ssh, tcpbanner, telnet, tftp, vnc;
  - Portscan uses **iptables (not nftables)** and is Linux-only;
  - alerting uses Python logging handlers (file, syslog and others);
  - BSD-3-style licence (Thinkst 2018); v0.9.10 (2026-09-21).
- **Canarytokens licence**: "GNU General Public License ... Version 3 ... BUT ONLY WITH ALL OF THE CLARIFICATIONS AND EXCEPTIONS DESCRIBED HEREIN ... If you wish to embed Canarytokens technology into proprietary software, we sell alternative licenses". Thinkst counts as derivative any work that "Integrates source code", "Is designed specifically to execute Covered Software and parse the results", "Links ... to a library which does any of the above", or ships it in an installer, including one that fetches it at runtime. — [Canarytokens LICENSE](https://github.com/thinkst/canarytokens/blob/master/LICENSE). The canarytokens-docker wrapper repo is BSD. — [canarytokens-docker LICENSE](https://github.com/thinkst/canarytokens-docker/blob/master/LICENSE)
- **Self-hosted Canarytokens** — [canarytokens-docker README](https://github.com/thinkst/canarytokens-docker):
  - needs at least one domain (two for PDF tokens);
  - the domain's nameservers must point to the Docker host, set at the registrar;
  - needs an email provider (Mailgun, SMTP or SendGrid);
  - v2 is legacy and v3 is recommended;
  - `CANARY_AWSID_URL` lets you point AWS-key tokens at a private or different URL.
- **AWS API key token**: fake keys that alert when used against the AWS API. Alerts pass through AWS logging with **"a delay of between 2 and 30 minutes"**. — [Canarytokens docs: AWS keys](https://docs.canarytokens.org/guide/aws-keys-token.html)

### Inferences
- **On-host canaries Fusion can implement natively** (no third-party code):
  - **Canary files** with enticing paths and realistic content: `/root/.aws/credentials`, `/var/www/.env.backup` with fake `DB_PASSWORD`, `~/.ssh/id_ed25519_old`, `/root/kubeconfig.bak`. Monitor `open`/`read` by any process other than the agent (fanotify, or an eBPF LSM/tracepoint). A read is a high-confidence "hands-on-keyboard" indicator; respond by alert plus forensic snapshot.
  - **Canary credentials**: a DB user (for example `backup_admin`) that exists with no privileges, plus a log or auth-plugin watch for any login attempt. A fake SSH user in `/etc/passwd` with nologin, where any `Invalid/Failed ... for backup_admin` triggers.
  - **Fake cloud keys**: Fusion's master-side AWS account issues inert IAM keys and alerts on CloudTrail use. This is the same concept as Canarytokens, implemented independently; expect a 2–30 min delay.
- **Tripwire listeners.** Tiny Go listeners on ports attackers scan for but the host doesn't use (2375 Docker API, 6379 Redis, 23 Telnet, 3389 RDP). Any connection gives a high-confidence scanner signal and an automatic temporary ban, subject to the allowlist.
- **Cowrie and OpenCanary placement.** They are better as master-side sensor fleets (separate small VPSs) feeding the threat-intel pipeline (attacker IPs, dropped payload hashes, Outlaw/Kinsing scripts) than on customer production servers.
  - Running Cowrie on port 22 means moving real sshd to another port and redirecting. That adds operational and lockout risk.
  - Cowrie and OpenCanary are BSD, so bundling or redistributing them is permissible with notices.
- **Canarytokens** can still be used as an *external* service by customers (canarytokens.org or self-hosted). Fusion should not ship code that executes or parses Canarytokens output if it wants to avoid Thinkst's derivative interpretation.

### Gaps
- No footprint numbers were found for Cowrie (Python/Twisted). OpenCanary's claim is qualitative.
- canarytokens.org (hosted free service) terms of use for commercial or MSSP usage were not fetched.

---

## 7. Web attacks: ModSecurity v3 + OWASP CRS, Coraza, CrowdSec AppSec, BunkerWeb, NAXSI; SQLi/RCE/path traversal/webshell upload; correlating WAF logs with host process events

### Takeaway
The OWASP CRS v4 rule set (Apache-2.0; v4.30.0 and LTS v4.25.2, 2026-10-03) is the common detection core. It can run on:
- ModSecurity v3 (now an OWASP project, Apache-2.0, v3.0.17, 2026-09-29);
- **Coraza**, an embeddable Go engine (Apache-2.0, v3.8.1, 2026-10-02, "100% compatible" with CRS v4);
- **CrowdSec AppSec**, which uses Coraza for CRS and adds MIT-licensed virtual-patch rules, including Laravel Ignition CVE-2021-3129 and PHPUnit CVE-2017-9841.

BunkerWeb is AGPLv3 with a PRO tier. The original NAXSI is archived; a community fork exists with a last release in Jan 2025.

Debian and Ubuntu still package CRS 3.3.x. For a Go agent, Coraza or CrowdSec AppSec is the natural integration. Correlation should join WAF/access-log events to php-fpm and nginx child-process trees by time, cgroup and user, then respond by killing the tree, blocking egress and banning the source IP.

### Cited Findings
- **ModSecurity** was "transferred from Trustwave to OWASP in February 2024". — [OWASP ModSecurity project](https://owasp.org/www-project-modsecurity/). Releases v3.0.17 and v2.9.15 came out on 2026-09-29. — [ModSecurity releases](https://github.com/owasp-modsecurity/ModSecurity/releases). Apache-2.0. — [ModSecurity LICENSE](https://github.com/owasp-modsecurity/ModSecurity/blob/v3/master/LICENSE)
- **OWASP CRS** is a flagship project, Apache-2.0, for use with ModSecurity, Coraza and other compatible WAFs. Latest **v4.30.0** and **v4.25.2 (LTS)**, both 2026-10-03. — [CRS README](https://github.com/coreruleset/coreruleset); [CRS releases](https://github.com/coreruleset/coreruleset/releases)
- CRS rule families, by file — [CRS rules directory](https://github.com/coreruleset/coreruleset/tree/main/rules):
  - 920 protocol enforcement, 921 protocol attack, 922 multipart attack;
  - **930 LFI/path traversal**, 931 RFI, **932 RCE (Unix/Windows command injection)**, **933 PHP injection**, 934 generic;
  - 941 XSS, **942 SQLi**, 943 session fixation, 944 Java;
  - 949 blocking evaluation (anomaly scoring).
- Rule **933110** "PHP Injection Attack: PHP Script File Upload Found" inspects `FILES` and `X-Filename`-style headers for `.php*`, `.phtml`, `.phar` and similar extensions. — [REQUEST-933-APPLICATION-ATTACK-PHP.conf](https://github.com/coreruleset/coreruleset/blob/main/rules/REQUEST-933-APPLICATION-ATTACK-PHP.conf)
- **Distro CRS versions**: Debian 13 3.3.7, Ubuntu 24.04 3.3.5, Alma/Rocky 9 3.3.5 (`mod_security_crs`), CentOS Stream 10 4.22.0, Fedora 44 4.15.0. Most LTS distros still ship CRS 3. — [Repology: modsecurity-crs](https://repology.org/project/modsecurity-crs/versions)
- **Coraza** — [Coraza README](https://github.com/corazawaf/coraza); [LICENSE](https://github.com/corazawaf/coraza/blob/main/LICENSE); [releases](https://github.com/corazawaf/coraza/releases):
  - "open source, enterprise-grade, high performance WAF ... written in Go, supports ModSecurity SecLang rulesets and is 100% compatible with the OWASP Core Rule Set v4";
  - "a library at its core" (`coraza.NewWAF(...)`);
  - integrations: Caddy (stable, "needs a maintainer"), proxy-wasm/Envoy (stable), Traefik WASM (experimental), HAProxy SPOE (experimental), libcoraza C for nginx (experimental);
  - Apache-2.0; v3.8.1 (2026-10-02).
- **CrowdSec AppSec**: Coraza-backed CRS; in-band and out-of-band; a benchmark of 0.23 ms (vpatch) and 1.06 ms (CRS) in-band per request; supported fronts nginx, OpenResty, Apache, Traefik, Envoy Gateway, HAProxy and WordPress. — [AppSec intro](https://docs.crowdsec.net/docs/appsec/intro); [AppSec CRS](https://docs.crowdsec.net/docs/appsec/crs/intro); [benchmark](https://docs.crowdsec.net/docs/appsec/benchmark)
  - The hub holds 227 `vpatch-*.yaml` rules (count of hub directory, 2026-11-09). — [hub appsec-rules](https://github.com/crowdsecurity/hub/tree/master/appsec-rules/crowdsecurity)
  - `vpatch-CVE-2021-3129` matches a URI ending `/_ignition/execute-solution` **and** a JSON body `parameters.viewFile` matching `php://filter|phar://`. — [vpatch-CVE-2021-3129.yaml](https://github.com/crowdsecurity/hub/blob/master/appsec-rules/crowdsecurity/vpatch-CVE-2021-3129.yaml)
  - `vpatch-CVE-2017-9841` matches a URI ending `/util/php/eval-stdin.php`. — [vpatch-CVE-2017-9841.yaml](https://github.com/crowdsecurity/hub/blob/master/appsec-rules/crowdsecurity/vpatch-CVE-2017-9841.yaml)
  - The hub also has `vpatch-laravel-debug-mode`. — [hub appsec-rules](https://github.com/crowdsecurity/hub/tree/master/appsec-rules/crowdsecurity)
- **CVE-2021-3129**: "Ignition before 2.5.2, as used in Laravel ... allows unauthenticated remote attackers to execute arbitrary code because of insecure usage of file_get_contents() and file_put_contents() ... sites using debug mode with Laravel before 8.4.2". CVSS 9.8. Added to the CISA KEV catalogue 2023-09-18. — [NVD CVE-2021-3129](https://nvd.nist.gov/vuln/detail/CVE-2021-3129)
- **CVE-2017-9841**: "Util/PHP/eval-stdin.php in PHPUnit before 4.8.28 and 5.x before 5.6.3 allows remote attackers to execute arbitrary PHP code via HTTP POST data beginning with a '<?php ' substring ... exposed /vendor folder". CVSS 9.8. KEV since 2022-02-15. — [NVD CVE-2017-9841](https://nvd.nist.gov/vuln/detail/CVE-2017-9841)
- **BunkerWeb** — [BunkerWeb README](https://github.com/bunkerity/bunkerweb); [LICENSE.md](https://github.com/bunkerity/bunkerweb/blob/master/LICENSE.md); [releases](https://github.com/bunkerity/bunkerweb/releases):
  - an nginx-based "secure by default" web server and reverse proxy;
  - integrated ModSecurity with OWASP CRS, automatic bans on "strange behaviors based on HTTP status codes", connection and request limits, bot challenges, Let's Encrypt;
  - **AGPLv3**, with a **PRO** version under a paid licence key (30-day trial);
  - latest stable line 1.6.17 (1.6.18-rc3 on 2026-11-05).
- **NAXSI** — [nbs-system/naxsi](https://github.com/nbs-system/naxsi); [wargio/naxsi](https://github.com/wargio/naxsi); [wargio releases](https://github.com/wargio/naxsi/releases); [wargio LICENSE](https://github.com/wargio/naxsi/blob/main/LICENSE):
  - nbs-system: "the development of Naxsi has been stopped and the repository will be archived", pointing to the community fork wargio/naxsi;
  - the fork's latest release is **1.7 (2025-01-05)**, GPLv3;
  - design: a small "DROP-by-default" pattern scorer that needs whitelists or a learning phase.

### Inferences
- **Which WAF for Fusion.**
  - **Option A:** the customer already runs nginx or Traefik. Recommend CrowdSec AppSec (vpatch in-band, CRS out-of-band) or BunkerWeb. Fusion reads their decisions and logs.
  - **Option B:** Fusion embeds **Coraza** as a library for a future reverse-proxy mode or log-replay detection. This is Apache-2.0, so it is safe for a commercial product.
  - Avoid NAXSI (stalled) and distro CRS 3.3.x (outdated). BunkerWeb's AGPL matters only if Fusion modifies and offers it as a network service.
- **Laravel/PHP specifics.**
  - Block or alert on `/_ignition/execute-solution`, `/vendor/phpunit/.../eval-stdin.php`, `/.env` and `/vendor/` paths through vpatch rules and CrowdSec `http-sensitive-files`.
  - Host checks: `APP_DEBUG=true` in production `.env` is a CVE-2021-3129 prerequisite; a web-exposed `vendor/` directory or document root above `public/` is a CVE-2017-9841 prerequisite. Both are cheap posture rules for the agent.
- **WAF ↔ process correlation (deterministic join)** for "Laravel/PHP RCE leading to a shell":
  - (1) A WAF or access-log event: source IP, URI, time t, nginx `$request_id` if logged.
  - (2) An eBPF/audit exec event where the parent chain contains `php-fpm` (pool user www-data, cgroup `php-fpm.service` or the pool slice) and the child is `sh`, `bash`, `curl`, `wget`, `python`, `perl`, `nc` or `base64`, within t to t+N seconds.
  - (3) A follow-on outbound connect from that tree to a new destination, a file write to `/tmp`, `/dev/shm` or the webroot (`*.php`), or a crontab/systemd write.
  - Score the chain. If high confidence:
    - kill the process tree (by cgroup if possible);
    - apply a temporary egress deny to the php-fpm cgroup;
    - ban the request source IP;
    - quarantine new `.php` files in writable upload directories (CRS 933110 detects the upload side);
    - snapshot the evidence.
  - Passing `$request_id` into PHP via `fastcgi_param` lets logs carry a join key.

### Gaps
- No primary benchmark for ModSecurity v3 + CRS 4 on nginx versus Coraza on small VPSs (only CrowdSec's own AppSec numbers).
- BunkerWeb resource footprint and PRO pricing were not fetched.
- Whether CRS 4.x ships a Laravel-specific plugin or exclusion package was not checked; CRS has application exclusion plugins, but Laravel coverage is unverified.

---

## 8. Attack-to-defense mapping: concrete attacks each defense stops

### Takeaway
Every control above maps to a concrete stage of the motivating incident class (SSH brute force → key implant → miner with watchdog and persistence) or of the common web route (Laravel/PHPUnit RCE → shell → miner). The highest-leverage controls for a 1–2 GB VPS are:
- key-only SSH with PerSourcePenalties plus agent bans;
- authorized_keys FIM with immutable-bit detection;
- per-service egress deny;
- Stratum-aware outbound detection;
- vpatch WAF rules.

### Cited Findings

| Attack (example) | Stage | Defense(s) that stop or detect it | Evidence / source |
|---|---|---|---|
| SSH dictionary brute force (Hydra-style) | Initial access | CrowdSec `ssh-bf` (5 failures/10 s) and `ssh-slow-bf` (10/60 s), nft ban; OpenSSH ≥9.8 `PerSourcePenalties` (authfail 5 s, max 10 m); Fail2ban sshd jail (5/10 min → 10 min ban); sshguard (score > 30 → 120 s ×2) | [ssh-bf.yaml](https://github.com/crowdsecurity/hub/blob/master/scenarios/crowdsecurity/ssh-bf.yaml); [sshd_config(5)](https://man.openbsd.org/sshd_config); [jail.conf](https://github.com/fail2ban/fail2ban/blob/master/config/jail.conf); [sshguard(8)](https://github.com/SSHGuard/sshguard/blob/master/doc/sshguard.8.rst) |
| Password spraying / user enumeration | Initial access | CrowdSec `ssh-bf_user-enum` (≥5 distinct users per IP); OpenSSH 10.3 `invaliduser` penalty; key-only auth makes it moot | [ssh-bf.yaml](https://github.com/crowdsecurity/hub/blob/master/scenarios/crowdsecurity/ssh-bf.yaml); [OpenSSH notes](https://www.openssh.org/releasenotes.html) |
| Low-and-slow brute force | Initial access | CrowdSec `ssh-time-based-bf` (median gap >10 min, alert-only) | [ssh-time-based-bf.yaml](https://github.com/crowdsecurity/hub/blob/master/scenarios/crowdsecurity/ssh-time-based-bf.yaml) |
| Credential stuffing on web login | Initial access | CrowdSec AppSec `RateLimit("login","5/m")` returns 429; `http-generic-bf` | [AppSec rate limiting](https://docs.crowdsec.net/docs/appsec/rate_limiting); [http-generic-bf.yaml](https://github.com/crowdsecurity/hub/blob/master/scenarios/crowdsecurity/http-generic-bf.yaml) |
| HTTP scanning for `.env`, `.git`, admin panels | Recon | CrowdSec `http-probing`, `http-sensitive-files`, `http-admin-interface-probing` → ban | [hub scenarios](https://github.com/crowdsecurity/hub/tree/master/scenarios/crowdsecurity) |
| **Outlaw** SSH-key implant (`~/.ssh` recreated, attacker key, `chattr +ia`) | Persistence | FIM on AuthorizedKeysFile, immutable-bit detection, root-owned AuthorizedKeysFile path; key-only + PerSourcePenalties to stop the initial brute force | [Elastic: Outlaw](https://www.elastic.co/security-labs/outlaw-linux-malware); [sshd_config(5)](https://man.openbsd.org/sshd_config) |
| Outlaw miner (`kswapd0`, modified XMRig) to pools on :80/:4444/:442 | Impact | Stratum content signatures (ET "Cryptocurrency Miner Checkin", "Subscribe/Authorize Stratum"); process and cmdline (`stratum+tcp`, miner binaries); egress deny | [Elastic: Outlaw](https://www.elastic.co/security-labs/outlaw-linux-malware); [ET Open](https://rules.emergingthreats.net/open/suricata-7.0.3/emerging.rules.tar.gz); [Falco sandbox rules](https://github.com/falcosecurity/rules/blob/main/rules/falco-sandbox_rules.yaml) |
| Miner to pool on 3333/4444/14444 | Impact | Falco `miner_ports` list as a weak score; RPZ sinkhole of pool domains; per-service egress allowlists (systemd `IPAddressDeny=any` + allow) | [Falco sandbox rules](https://github.com/falcosecurity/rules/blob/main/rules/falco-sandbox_rules.yaml); [unbound.conf(5)](https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound.conf.html); [systemd.resource-control](https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html) |
| **Kinsing** via exposed Docker API (Ubuntu container whose entrypoint installs cron and fetches `d.sh`; kills rival miners; `kdevtmpfsi` miner) | Initial access + impact | Don't expose the daemon (TLS on 2376 only); tripwire listener on 2375; enforce bans at prerouting/`DOCKER-USER`; cron FIM; miner detection | [Aqua: Kinsing (2020-04-03)](https://www.aquasec.com/blog/threat-alert-kinsing-malware-container-vulnerability/); [MITRE S0599](https://attack.mitre.org/software/S0599/); [Docker: protect access](https://docs.docker.com/engine/security/protect-access/); [Docker iptables](https://docs.docker.com/engine/network/firewall-iptables/) |
| Kinsing lateral movement via harvested SSH keys and known_hosts | Lateral movement | Restrict outbound SSH from servers (egress allowlist); alert on ssh client exec from service users | [MITRE S0599](https://attack.mitre.org/software/S0599/) |
| Exposed Redis abuse | Initial access | `bind 127.0.0.1`, protected mode (Redis ≥3.2), firewall the port; tripwire on 6379 | [Redis security docs](https://redis.io/docs/latest/operate/oss_and_stack/management/security/) |
| **PHPUnit CVE-2017-9841** (`POST /vendor/phpunit/.../eval-stdin.php` with `<?php`) | Initial access (web RCE) | CrowdSec `vpatch-CVE-2017-9841`; CRS 933 (PHP injection); posture check for web-exposed `vendor/` | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2017-9841); [vpatch rule](https://github.com/crowdsecurity/hub/blob/master/appsec-rules/crowdsecurity/vpatch-CVE-2017-9841.yaml) |
| **Laravel Ignition CVE-2021-3129** (`/_ignition/execute-solution`, `viewFile` = `phar://` or `php://filter`) | Initial access (web RCE) | CrowdSec `vpatch-CVE-2021-3129`; posture check `APP_DEBUG=false` | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2021-3129); [vpatch rule](https://github.com/crowdsecurity/hub/blob/master/appsec-rules/crowdsecurity/vpatch-CVE-2021-3129.yaml) |
| Webshell upload (`.php`/`.phtml`/`.phar`) | Persistence | CRS 933110; FIM on writable upload directories | [CRS REQUEST-933](https://github.com/coreruleset/coreruleset/blob/main/rules/REQUEST-933-APPLICATION-ATTACK-PHP.conf) |
| Reverse shell to attacker VPS (`bash -i >& /dev/tcp/...`) | Execution / C2 | Egress default-deny for php-fpm/www-data; ET "Interactive Reverse Shell Without TTY"; Falco-style dup-to-socket fd 0/1/2 detection; eBPF connect attribution | [ET Open](https://rules.emergingthreats.net/open/suricata-7.0.3/emerging.rules.tar.gz); [Falco rules](https://github.com/falcosecurity/rules/blob/main/rules/falco_rules.yaml); [bcc tcpconnect](https://github.com/iovisor/bcc/blob/master/tools/tcpconnect_example.txt) |
| C2 beaconing (periodic HTTP/IRC) | C2 | Flow periodicity scoring (RITA-style) on the master; Outlaw's IRC C2 caught by egress allowlists | [RITA](https://github.com/activecm/rita); [Elastic: Outlaw](https://www.elastic.co/security-labs/outlaw-linux-malware) |
| Port scanning of the host | Recon | CrowdSec `iptables-scan-multi_ports`; OpenCanary `portscan` module (iptables only) or Go tripwire listeners | [hub scenarios](https://github.com/crowdsecurity/hub/tree/master/scenarios/crowdsecurity); [OpenCanary README](https://github.com/thinkst/opencanary) |
| Post-compromise credential theft (reading `.aws/credentials`, `.env`) | Credential access | Canary files and fake keys (AWS-key alert delay 2–30 min if API-based) | [Canarytokens AWS keys](https://docs.canarytokens.org/guide/aws-keys-token.html) |
| regreSSHion CVE-2024-6387 probing | Initial access | CrowdSec `ssh-cve-2024-6387`; patch OpenSSH; PerSourcePenalties `crash`/`grace-exceeded` | [hub scenario](https://github.com/crowdsecurity/hub/blob/master/scenarios/crowdsecurity/ssh-cve-2024-6387.yaml); [sshd_config(5)](https://man.openbsd.org/sshd_config) |

### Inferences
- **Mapped to the company's own incident** (SSH compromise → miner + watchdog + cron/systemd persistence + replaced binaries):
  - Key-only auth plus agent bans would most likely have stopped initial access.
  - Failing that, authorized_keys FIM with the immutable-bit IOC and Stratum-aware egress detection are the earliest deterministic tripwires.
  - Persistence and replaced-binary detection belong to the host-integrity layer, covered by other research notes.
- **Response policy defaults** (policy-controlled, safe):
  - auto-ban (temporary, kernel-expiring) only for high-confidence network-layer events: brute-force buckets, vpatch hits, tripwire listener hits, Stratum checkins from non-allowlisted processes;
  - auto-kill only for process trees that match miner or reverse-shell chains;
  - everything identity-related (geo/ASN anomalies, new key added by an admin's own session) is alert-only and passed to the AI investigation layer for recommendations.

### Gaps
- **Kinsing + Redis:** no primary source fetched ties Kinsing specifically to Redis exploitation. The searches covered Docker API and Openfire vectors only, and the web-search budget was exhausted before a targeted search. Treat the Redis row as generic exposed-Redis hardening.
- Hydra is cited as an attack archetype only; no tool-specific source was fetched.
- No measured end-to-end time to block for the proposed agent; NFTBan's 300–500 ms alert→nft latency is the only comparable reported figure.
