# Real-world attacks on Linux cloud servers / VPS (2022 to Nov 2026) and the lightweight Linux server-security competitor landscape

Notes compiled 2026-11-09 for The Fusion Apps security-agent plan (Debian/Ubuntu + RHEL-family, EDR + policy-controlled autonomous response, master server with malware intel, Discord alerting). ATT&CK IDs are my mapping to MITRE ATT&CK Enterprise technique definitions ([ATT&CK techniques index](https://attack.mitre.org/techniques/enterprise/)) unless marked "(vendor-mapped)", meaning the cited source gave the ID itself.

## Q1. Major Linux server campaigns and malware families: kill chains (initial access -> execution -> persistence -> privilege escalation -> defense evasion -> C2 -> impact)

### Takeaway
Most attacks on SMB-hosted Linux servers are automated and financially motivated. They brute-force SSH or exploit an exposed or unpatched service (Redis, Docker API, WebLogic/ActiveMQ/RocketMQ, Laravel/PHP, JupyterLab, Hadoop, hosting panels, edge appliances), run a shell dropper, and deploy an XMRig-family miner. The miner is protected by a watchdog, cron, systemd or shell-rc persistence, an LD_PRELOAD or kernel rootkit, trojanized utilities, SSH-key or backdoor-account implants and chattr locks; the dropper also kills competing miners and security agents and wipes logs. A second, stealthier class (Ebury, Plague, Skidmap's pam_unix, Symbiote, Auto-color, BPFDoor, CWPdoor, the XZ backdoor) backdoors the authentication path itself (sshd, PAM, the control-panel web server) and evades antivirus engines (Plague 0/66, CWPdoor 0/63 on VirusTotal). Changes in 2025 and 2026: AI-assisted tooling (Koske, SysGoRAT), miners that avoid root and abuse PAM/su, mass exploitation of React2Shell and DevOps tools, and multi-platform ransomware that ships Linux encryptors.

### Cited Findings

#### A. Mass cryptojacking and worm families

**Kinsing (H2Miner), active 2019 to 2024+**
- Initial access: exploited Apache ActiveMQ CVE-2023-46604 (CVSS 9.8) in Nov 2023 (T1190) — [Trend Micro](https://www.trendmicro.com/en_us/research/23/k/cve-2023-46604-exploited-by-kinsing.html); Wiz logged a May 2024 Kinsing campaign targeting Apache Tomcat — [Wiz Threat Landscape](https://threats.wiz.io/all-incidents/kinsing-campaigns-2023-2024); earlier waves hit Docker hosts, SaltStack/Citrix and Log4j — [Red Canary](https://redcanary.com/blog/threat-intelligence/kinsing-malware-citrix-saltstack/), [Sandfly](https://sandflysecurity.com/blog/log4j-kinsing-linux-malware-in-the-wild).
- Privilege escalation and cloud pivot: Nov 2023 was the first publicly documented in-the-wild exploitation of glibc "Looney Tunables" CVE-2023-4911 (T1068), in a trial campaign whose goal was harvesting cloud-provider credentials, including IAM-role credentials from the instance metadata service (T1552.005) — [Aqua Nautilus](https://www.aquasec.com/blog/loony-tunables-vulnerability-exploited-by-kinsing/), [The Hacker News](https://thehackernews.com/2023/11/kinsing-actors-exploit-linux-flaw-to.html).
- Persistence: a systemd service named "bot" (T1543.002), plus cron that repeatedly re-downloads and runs the install script (T1053.003) — [Trend Micro 2020](https://www.trendmicro.com/en_gb/research/20/k/analysis-of-kinsing-malwares-use-of-rootkit.html). Sandfly's IOCs include a root crontab entry, /lib/systemd/system/bot.service, /etc/kinsing and /dev/shm/.ICE-d-unix — [Sandfly](https://sandflysecurity.com/blog/log4j-kinsing-linux-malware-in-the-wild).
- Defense evasion: a beurk-based user-mode rootkit, preloaded via /etc/ld.so.preload as /etc/libsystem.so, hides processes and files named kinsing, kdevtmpfsi and lib_system.so (T1574.006, T1014) — [Trend Micro 2020](https://www.trendmicro.com/en_gb/research/20/k/analysis-of-kinsing-malwares-use-of-rootkit.html). The 2023 ActiveMQ wave again loaded its rootkit through /etc/ld.so.preload — [Trend Micro 2023](https://www.trendmicro.com/en_us/research/23/k/cve-2023-46604-exploited-by-kinsing.html).
- Impact and spread: the XMRig miner is named kdevtmpfsi and sits in /tmp, /var/tmp or /dev/shm (T1496.001) — [Sandfly](https://sandflysecurity.com/blog/log4j-kinsing-linux-malware-in-the-wild), [Red Canary](https://redcanary.com/blog/threat-intelligence/kinsing-malware-citrix-saltstack/). It moves laterally over SSH and md5sum-checks payloads before running them (T1021.004) — [Red Canary](https://redcanary.com/blog/threat-intelligence/kinsing-malware-citrix-saltstack/). It reportedly hunts and kills rival miners — [Cyber Security News](https://cybersecuritynews.com/hackers-infect-linux-machines-via-apache-activemq-vulnerability).

**TeamTNT on CentOS VPS (Group-IB, 18 Sep 2024; attribution "moderate confidence"). This is the closest public analogue to the Fusion incident.**
- Initial access: SSH brute force on a CentOS 7 VPS, then upload of a script (T1110.001) — [Group-IB](https://www.group-ib.com/blog/teamtnt/), [Cyber Security News](https://cybersecuritynews.com/vps-servers-running-centos-under-attack/).
- The script's steps, in order, all per [Group-IB](https://www.group-ib.com/blog/teamtnt/):
  1. Exits if /etc/.system/rtm/xmrig.log was written in the last 600 s.
  2. Disables iptables and UFW, disables the NMI watchdog, deletes /var/log/syslog, and changes attributes on /tmp, /var/tmp, /root/.ssh and /root/.ssh/authorized_keys (T1562.004, T1070.002, T1222.002).
  3. Detects aliyun.service and runs Alibaba's uninstaller from update.aegis.aliyun.com (T1562.001).
  4. Disables SELinux and AppArmor (T1562.001).
  5. Kills competing miners using a long signature list (strings, ports, IPs, paths, process names, e-mails, domains).
  6. Kills containerised miners and removes their images.
  7. Unlocks /etc/resolv.conf and sets Google DNS.
  8. Installs `tntrecht` (/usr/local/bin/tntrecht in the body text; /usr/bin/tntrecht in the IOC list) and renames legitimate binaries with a "tnt" prefix (`tntcurl`, `tntwget`).
  9. Unlocks /var/spool/cron, /etc/crontab, /etc/cron.d and /var/spool/cron/crontabs, wipes the existing jobs, and adds a 30-minute job that pulls a payload from 65.108.48.150. It backdates the crontab to 2018-05-15 (T1053.003, T1070.006).
  10. If running as root, compiles the public Diamorphine LKM in /var/tmp/…/dia/ and loads diamorphine.ko with insmod. Signal 31 hides a process, 63 toggles module visibility and 64 grants root; files are hidden by MAGIC_PREFIX (T1547.006, T1014).
  11. Locks files with chattr, then disables chattr itself and blocks reboot, power-off and recovery (T1222.002, T1490).
  12. Creates user `hilde`, adds it to sudo, and plants a public key for hilde and root (T1136.001, T1098.004).
  13. Moves SSH to port 11222, enables public-key auth, and opens 11222/tcp.
  14. Runs `history -c` (T1070.003).

**TeamTNT "Docker Gatling Gun" (Aqua Nautilus, 25 Oct 2024)**
- Initial access: masscan and ZGrab scans of about 16.7M IPs for Docker daemons on ports 2375, 2376, 4243 and 4244 (T1046, T1190) — [Aqua](https://www.aquasec.com/blog/threat-alert-teamtnts-docker-gatling-gun-campaign/).
- Execution and persistence: an Alpine container runs the malicious commands (T1610). Scripts are TDGGinit.sh, TDGG.sh and scan.pl. About 30 images were pushed to the breached Docker Hub account nmlm99. Compromised daemons are joined to the attacker's Docker Swarm (Aqua maps this to "Create Cloud Instance") — [Aqua](https://www.aquasec.com/blog/threat-alert-teamtnts-docker-gatling-gun-campaign/). Datadog first saw the Swarm-corralling attempts in Oct 2024 — [The Hacker News](https://thehackernews.com/2024/10/notorious-hacker-group-teamtnt-launches.html).
- Evasion and C2: "prochider" rootkits (xmrig.so, systemd.so). Sliver implants (SPLENDID_ISLAND, bioset) replace Tsunami and talk over mTLS, WireGuard, HTTP(S) or DNS to 45.154.2.77 (solscan.one:8888) — [Aqua](https://www.aquasec.com/blog/threat-alert-teamtnts-docker-gatling-gun-campaign/).
- Impact: XMRig, T-Rex, CGMiner, BFGMiner and SGMiner; victim compute rented out on Mining Rig Rentals; harvesting of SSH, AWS, Docker, s3cfg, GitHub, gcloud, Ngrok and PostgreSQL credentials and cloud metadata (T1552.001/.005) — [Aqua](https://www.aquasec.com/blog/threat-alert-teamtnts-docker-gatling-gun-campaign/).

**8220 Gang (Water Sigbin), active since 2017**
- Initial access: n-day exploits. A May 2023 to Feb 2024 campaign used Log4Shell, Confluence CVE-2022-26134 and WebLogic CVE-2017-3506 — [Uptycs](https://www.uptycs.com/blog/8220-gang-cryptomining-cloud-based-infrastructure-cyber-threat). In 2024 it used WebLogic CVE-2017-3506, CVE-2017-10271 and CVE-2023-21839 (T1190) — [The Hacker News on Trend Micro](https://thehackernews.com/2024/06/8220-gang-exploits-oracle-weblogic.html).
- Tooling: k4spreader, a cgo installer first seen Feb 2024. It handles persistence and self-update, disables the firewall, terminates rival botnets such as Kinsing, and installs the Tsunami DDoS bot and the PwnRig miner (T1562.004, T1496.001) — [XLab](https://blog.xlab.qianxin.com/8220-k4spreader-new-tool-en/).
- Evasion: disables SELinux and bypasses firewalls on Linux (T1562.001) — [KPMG, Apr 2024](https://assets.kpmg.com/content/dam/kpmg/in/pdf/2024/04/kpmg-ctip-8220-gang-09-apr-2024.pdf).

**Outlaw / "Dota" (Elastic Security Labs, 1 Apr 2025): an SSH worm-miner of Romanian origin**
- Initial access: SSH brute force by the BLITZ component (also seen as `kthreadadd`), with target lists and credentials pulled from an SSH C2 (T1110.001) — [Elastic](https://www.elastic.co/security-labs/outlaw-linux-malware).
- Execution: dropper `tddwrt7s.sh` fetches `dota3.tar.gz`, which unpacks to a hidden `.rsync` folder; `initall`/`init` then installs to `~/.configrc6` (T1105, T1059.004) — [Elastic](https://www.elastic.co/security-labs/outlaw-linux-malware).
- Persistence, with the exact crontab lines: `5 6 * * 0 ~/.configrc6/a/upd`, `@reboot ~/.configrc6/a/upd`, `5 8 * * 0 ~/.configrc6/b/sync`, `@reboot ~/.configrc6/b/sync`, `0 0 */3 * * ~/.configrc6/c/aptitude` (T1053.003). `upd` is a watchdog that restarts the miner. It deletes and recreates `~/.ssh` with an attacker key and locks it with `chattr +ia` (T1098.004, T1222.002) — [Elastic](https://www.elastic.co/security-labs/outlaw-linux-malware).
- Evasion: the miner runs as `kswapd0` (modified XMRig 6.22.1) next to `kswapd01`, a socat relay usually on port 4444 (T1036.005). It removes or locks `~/.xmrig.json` and `~/.config/xmrig.json`, and its `stop` scripts kill competing miners by name, PID or network traffic — [Elastic](https://www.elastic.co/security-labs/outlaw-linux-malware).
- C2: SHELLBOT, a Perl IRC bot used as a backup channel, delivered as base64 blobs piped to perl (T1071, T1140) — [Elastic](https://www.elastic.co/security-labs/outlaw-linux-malware).
- Impact and spread: Monero pools on ports 80 and 4444 (plaintext), 442 (SSL) and occasionally Tor, with hugepages enabled. BLITZ changes the victim's password (T1531), exfiltrates recon over sftp-server, scans the local subnet and copies dota3.tar.gz to new hosts (T1021.004, T1570) — [Elastic](https://www.elastic.co/security-labs/outlaw-linux-malware).

**perfctl (Aqua Nautilus, 3 Oct 2024): a 3–4-year campaign that likely targeted millions of servers and compromised thousands**
- Initial access: probes about 20,000 directory-traversal paths for exposed configs, credentials and login pages. Aqua's honeypot was hit through Apache RocketMQ CVE-2023-33246, which ran the `rconf` script. The script has a raw-TCP HTTP GET for hosts without curl or wget, and remounts /tmp as exec if it is noexec (T1190) — [Aqua](https://www.aquasec.com/blog/perfctl-a-stealthy-malware-targeting-millions-of-linux-servers/); scale — [BleepingComputer](https://www.bleepingcomputer.com/news/security/linux-malware-perfctl-behind-years-long-crypto-mining-campaign/).
- Privilege escalation: embedded PwnKit exploit, CVE-2021-4034 (T1068) — [Aqua](https://www.aquasec.com/blog/perfctl-a-stealthy-malware-targeting-millions-of-linux-servers/).
- Execution and masquerading: the payload (`avatar.php`, renamed `httpd`) copies itself to /tmp under its parent's name (e.g. /tmp/sh), runs the copy, and kills and deletes the original (T1036.005, T1070.004). It keeps a PID file at /tmp/.apid and works out of /tmp/.xdiag/ — [Aqua](https://www.aquasec.com/blog/perfctl-a-stealthy-malware-targeting-millions-of-linux-servers/).
- Persistence: copies at /root/.config/cron/perfcc, /usr/bin/perfcc, /usr/lib/libpprocps.so and /usr/lib/libfsnkdev.so. A `~/.profile` hook runs perfcc (T1546.004). `/usr/bin/wizlmsh` (about 12 KB) is a watchdog that restarts the payload. /etc/profile's PATH is changed so the trojanized utilities run first (T1574.007) — [Aqua](https://www.aquasec.com/blog/perfctl-a-stealthy-malware-targeting-millions-of-linux-servers/).
- Defense evasion: rootkit `libgcwrap.so` via LD_PRELOAD hooks `pam_authenticate` and `pcap_loop` (T1574.006, T1556.003, T1014). Trojanized `ldd`, `top`, `lsof` and `crontab` in ~/.local/bin hide the miner's CPU use, its libraries, files and sockets, and its cron jobs. Strings are XOR-encrypted with key 0xAC and binaries are packed. It sleeps 10 minutes after launch, and stops noisy activity whenever a new user appears in btmp/utmp (T1497.002). It also kills competing malware and shuts down security controls — [Aqua](https://www.aquasec.com/blog/perfctl-a-stealthy-malware-targeting-millions-of-linux-servers/).
- C2: a local Unix socket, and Tor to the outside world (T1090.003) — [Aqua](https://www.aquasec.com/blog/perfctl-a-stealthy-malware-targeting-millions-of-linux-servers/).
- Impact: XMRig mining over Tor (T1496.001), plus proxyjacking via bitping.com, earn.fm, speedshare.app and repocket.com (T1496.002) — [Aqua](https://www.aquasec.com/blog/perfctl-a-stealthy-malware-targeting-millions-of-linux-servers/).

**Skidmap (Redis variant reported by Trustwave in Aug 2023; original analysis by Trend Micro in 2019)**
- Initial access: unauthenticated ("NO AUTH") Redis. It sets Redis variables containing base64-encoded cron tasks (T1190, T1053.003) — [The Hacker News](https://thehackernews.com/2023/08/new-skidmap-redis-malware-variant.html), [Security Affairs](https://securityaffairs.com/149258/malware/skidmap-malware-redis-servers.html).
- Execution: an ELF dropper disguised as a GIF (T1036.008) installs a distro- and kernel-specific package named gold, stream or euler — [The Hacker News](https://thehackernews.com/2023/08/new-skidmap-redis-malware-variant.html).
- Evasion: kernel modules — `mcpuinfo.ko` hides the miner and `kmeminfo.ko` inspects and manipulates packets (T1547.006, T1014). It purges logs (T1070.002) and launches a bot that fetches further rootkit payloads — [Security Affairs 2023](https://securityaffairs.com/149258/malware/skidmap-malware-redis-servers.html).
- Auth backdoor (2019 analysis): replaces pam_unix.so with a version that accepts one specific password for any user (T1556.003); a netlink rootkit fakes network and CPU statistics — [Security Affairs 2019](https://securityaffairs.com/91441/malware/skidmap-linux-miner.html).

**P2Pinfect (Cado/Darktrace; first seen Jul 2023; ransomware stage from 16 May 2024)**
- Initial access: abuse of Redis replication — `SLAVEOF` to the attacker node, then writing and loading a .so. It also abuses Redis config commands to write a cron job, and sprays common SSH passwords (T1190, T1110.003) — [Darktrace](https://www.darktrace.com/blog/from-dormant-to-dangerous-p2pinfect-evolves-to-deploy-new-ransomware-and-cryptominer). It has used the Lua sandbox escape CVE-2022-0543. Unit 42 counted more than 307,000 public Redis instances, about 934 possibly vulnerable — [The Record](https://therecord.media/redis-malware-worm-botnet).
- Persistence and privilege escalation: an SSH key in authorized_keys (T1098.004). It edits the sshd config to allow root password login and restarts SSH, changes other users' passwords, and uses sudo where permitted (T1548.003). It also restricts Redis to IPs that already have connections, which locks out competitors — [Darktrace](https://www.darktrace.com/blog/from-dormant-to-dangerous-p2pinfect-evolves-to-deploy-new-ransomware-and-cryptominer).
- Evasion: a user-mode rootkit at `/home/<user>/.lib/libs.so.1`, activated by appending `export LD_PRELOAD=…` to .bashrc (T1574.006, T1546.004). It hooks fopen, open, lstat, unlink and readdir, hides its PIDs, /tmp/bash and the miner, and filters ports 60100–60150 out of /proc/net/tcp(6). A watchdog, /tmp/bash, renames itself `[kworker/1:0H]` and health-checks the main binary — [Darktrace](https://www.darktrace.com/blog/from-dormant-to-dangerous-p2pinfect-evolves-to-deploy-new-ransomware-and-cryptominer).
- C2: a P2P mesh with gossip-propagated JSON commands; each peer listens on a random port in 60100–60150 — [Darktrace](https://www.darktrace.com/blog/from-dormant-to-dangerous-p2pinfect-evolves-to-deploy-new-ransomware-and-cryptominer).
- Impact: a miner talking to c3pool through Hetzner IPs on TCP 19999. The `rsagen` ransomware appends `.encrypted` and drops the note "Your data has been locked!.txt" (T1496.001, T1486) — [Darktrace](https://www.darktrace.com/blog/from-dormant-to-dangerous-p2pinfect-evolves-to-deploy-new-ransomware-and-cryptominer).
- Prevalence: the top family in AhnLab's SSH honeypots — 56.3% in Q1 2025, 50.0% in Q2 2025, 80.4% in Q4 2025 and 70.3% in Q1 2026 — [AhnLab Q1-25](https://asec.ahnlab.com/en/87357/), [Q2-25](https://asec.ahnlab.com/en/88927/), [Q4-25](https://asec.ahnlab.com/en/92004/), [Q1-26](https://asec.ahnlab.com/en/93336/).

**Migo (Cado Security Labs, Feb 2024): a Redis miner**
- Initial access: Redis commands that switch off protected mode and other protective settings so the server accepts writes (T1190, T1562.001) — [Darktrace/Cado](https://www.darktrace.com/blog/migo-a-redis-miner-with-novel-system-weakening-techniques).
- Execution: a Go payload fetches the XMRig tar.gz from GitHub's CDN — [Darktrace/Cado](https://www.darktrace.com/blog/migo-a-redis-miner-with-novel-system-weakening-techniques).
- Persistence: a systemd service plus a timer that fires every 5 seconds (T1543.002, T1053.006) — [Infosecurity Magazine](https://www.infosecurity-magazine.com/news/linux-malware-migo-targets-redis/).
- Evasion: a modified libprocesshider in /etc/ld.so.preload (T1574.006). It edits /etc/hosts to block cloud providers, and obfuscates symbols and strings at compile time — [Darktrace/Cado](https://www.darktrace.com/blog/migo-a-redis-miner-with-novel-system-weakening-techniques), [Infosecurity Magazine](https://www.infosecurity-magazine.com/news/linux-malware-migo-targets-redis/).

**RedTail (first noted by CSA in Dec 2023; Akamai, May 2024)**
- Initial access: PAN-OS CVE-2024-3400 (exploited since at least 21 Apr 2024), Ivanti Connect Secure CVE-2023-46805 and CVE-2024-21887, TP-Link CVE-2023-1389, VMware Workspace ONE CVE-2022-22954 and ThinkPHP RCEs (T1190) — [Akamai](https://www.akamai.com/blog/security-research/2024/may/2024-redtail-cryptominer-pan-os-cve-exploit). A later campaign used PHP-CGI CVE-2024-4577 — [AVAR 2024](https://events.aavar.org/avar2024/?p=7036).
- Execution and persistence: a bash script picks the right architecture and downloads a UPX-packed, modified XMRig named `.redtail` (T1027.002); a cron job keeps it across reboots (T1053.003) — [Akamai](https://www.akamai.com/blog/security-research/2024/may/2024-redtail-cryptominer-pan-os-cve-exploit).
- Evasion: forks repeatedly, debugs its own process and kills GDB (T1622). The mining config is encrypted and decrypted only at runtime — [Akamai](https://www.akamai.com/blog/security-research/2024/may/2024-redtail-cryptominer-pan-os-cve-exploit).
- Impact: RandomX with hugepages. There is no wallet in the config, which points to private pools or proxies such as proxies.identitynetwork.top:2137 and several IPs on port 2137 — [Akamai](https://www.akamai.com/blog/security-research/2024/may/2024-redtail-cryptominer-pan-os-cve-exploit).

**Diicot, formerly Mexals (Romanian group; Cado 2023; Wiz, 17 Dec 2024)**
- Initial access: SSH brute force. The `.bisis` scanner looks for SSH banners and the malware tries hardcoded pairs such as root / `!Q2w3e4r` (T1110.001, vendor-mapped) — [Wiz](https://www.wiz.io/blog/diicot-threat-group-malware-campaign). Earlier waves used a custom Go brute-forcer called "aliases" — [Darktrace/Cado](https://www.darktrace.com/blog/tracking-diicot-an-emerging-romanian-threat-actor).
- Environment logic: the `Update` payload compares the distro against a list of cloud distros (Azure, Amazon, Linode, Oracle). Cloud hosts get only the spreader; everything else gets the miner — [Wiz](https://www.wiz.io/blog/diicot-threat-group-malware-campaign).
- Persistence: four cron jobs — `Update`; `History`, which restarts Update; `.b`, which restarts the `cache` reverse shell; and `.c`, which downloads `black3` (T1053.003, vendor-mapped) — [Wiz](https://www.wiz.io/blog/diicot-threat-group-malware-campaign). The loader adds an attacker SSH key (T1098.004) — [Darktrace/Cado](https://www.darktrace.com/blog/tracking-diicot-an-emerging-romanian-threat-actor).
- Evasion: the UPX magic is changed to `YTS\x99` and the checksum corrupted, so unpackers fail (T1027.002, vendor-mapped). The miner is disguised as /var/tmp/Documents/Opera — [Wiz](https://www.wiz.io/blog/diicot-threat-group-malware-campaign).
- C2 and impact: C2 moved from Discord to HTTP — errors go to port 1418, success reports to port 47 or 8000 (T1071.001, vendor-mapped). A custom XMRig mines on pool.supportxmr.com:443 and Zephyr pools on 7777 and 8080, earning more than $16,000 (T1496.001, vendor-mapped) — [Wiz](https://www.wiz.io/blog/diicot-threat-group-malware-campaign). Akamai later documented a resurgence of the Mexals campaign — [Akamai](https://www.akamai.com/blog/security-research/mexals-cryptojacking-malware-resurgence).

**Sysrv (Imperva, Mar 2024)**
- The `ldr.sh` dropper installs a Go worm, which fetches a packed XMRig from a sites.google.com page dressed up as an error page (T1102, T1105) — [Imperva](https://www.imperva.com/blog/new-sysrv-botnet-variant-makes-use-of-google-subdomain-to-spread-xmrig-miner/).

**Commando Cat (Cado, early 2024; Trend Micro, Jun 2024)**
- Uses the exposed Docker remote API to deploy the `cmd.cat/chattr` image, then reaches the host through chroot and volume binding and binds `/var/run/docker.sock` (T1610, T1611). A script fetches the miner; Trend Micro suspects the ZiggyStarTux (Kaiten-based) IRC bot — [Trend Micro](https://www.trendmicro.com/en_us/research/24/f/commando-cat-a-novel-cryptojacking-attack-.html), [The Hacker News](https://thehackernews.com/2024/06/commando-cat-cryptojacking-attacks.html).

**Androxgh0st (FBI/CISA advisory AA24-016A, 16 Jan 2024)**
- Scans for Laravel apps and sends GET/POST requests to `/.env` to steal AWS, Microsoft 365, SendGrid, Twilio and SMTP credentials (T1552.001). It exploits Laravel CVE-2018-15133, which CISA added to KEV the same day; the advisory also lists PHPUnit CVE-2017-9841 and Apache CVE-2021-41773 — [CISA](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-016a), [SecurityWeek](https://www.securityweek.com/us-gov-issues-warning-for-androxgh0st-malware-attacks/). More than 40,000 devices were reportedly infected per Fortinet telemetry (press figure) — [SecurityWeek](https://www.securityweek.com/us-gov-issues-warning-for-androxgh0st-malware-attacks/).

#### B. DDoS / proxy botnets

**XorDDoS (Cisco Talos, Apr 2025)**
- Activity tracked from Nov 2023 to Feb 2025; 71.3% of attacks targeted the US. A brute-force shell script tries root credential combinations across thousands of servers. Persistence uses an embedded init script plus cron. A new central controller and a "VIP" sub-controller appear to be sold, and the operators are Chinese-speaking — [Talos](https://blog.talosintelligence.com/unmasking-the-new-xorddos-controller-and-infrastructure/), [The Hacker News](https://thehackernews.com/2025/04/experts-uncover-new-xorddos-controller.html).
- Older-sample artifacts: `/etc/cron.hourly/gcc.sh`; /lib/libudev.so copied to random-named files in /usr/bin, /bin or /tmp; `/var/run/gcc.pid` — [Trend Micro encyclopedia](https://www.trendmicro.com/vinfo/us/threat-encyclopedia/malware/ELF_XORDDOS.ARE). It also drops an /etc/init.d script with rc1–5 symlinks and uses kernel-rootkit hiding (T1037.004, T1053.003, T1014, T1498) — [TheSecMaster](https://thesecmaster.com/how-can-you-protect-your-linux-infrastructure-from-xorddos-malware).

**Chaos (Darktrace, Apr 2026)**
- The first documented Chaos targeting of 64-bit Linux servers. Initial access was a misconfigured Apache Hadoop, abused by submitting an application with embedded shell commands to the resource manager (T1190). Persistence is a systemd unit plus a keep-alive script on disk (T1543.002). The binary deletes itself after running. It offers HTTP/TLS/TCP/UDP/WebSocket DDoS and a new SOCKS5 proxy (T1498, T1090). C2 is gmserver[.]osfc[.]org[.]cn — [Help Net Security](https://www.helpnetsecurity.com/2026/04/08/chaos-malware-cloud-misconfigured-servers/).

#### C. Stealth backdoors and rootkits in the authentication path

**Ebury (ESET, 14 May 2024)**
- About 400,000 Linux, FreeBSD and OpenBSD servers compromised since 2009, with more than 100,000 still compromised in late 2023. It is an OpenSSH backdoor and credential stealer (T1554, T1556) — [ESET WeLiveSecurity](https://www.welivesecurity.com/en/eset-research/ebury-alive-unseen-400k-linux-servers-compromised-cryptotheft-financial-gain/).
- Spread: mainly with credentials stolen from servers it already controls (T1078, T1021.004) — [ESET press release](https://www.eset.com/int/about/newsroom/press-releases/research/eset-research-ebury-botnet-alive-growing-400k-linux-servers-compromised-for-cryptocurrency-theft-and-financial-gain/). Through a compromised hosting provider it installs onto every server the provider rents out; an ESET test server rented from one was infected within 7 days. ARP-spoofing AitM captured SSH credentials from more than 200 targets in 2023, including Bitcoin and Ethereum nodes (T1557.002) — [ESET](https://www.welivesecurity.com/en/eset-research/ebury-alive-unseen-400k-linux-servers-compromised-cryptotheft-financial-gain/).
- Evasion and impact: v1.8 (late 2023) adds a DGA (T1568.002) and an improved userland rootkit that hides its process, file, socket and mapped memory (T1014). Monetization: spam, traffic redirection, theft of card data from HTTP POSTs, and crypto-wallet theft (T1657) — [ESET](https://www.welivesecurity.com/en/eset-research/ebury-alive-unseen-400k-linux-servers-compromised-cryptotheft-financial-gain/).

**CWPdoor (QiAnXin XLab, disclosed 5 Nov 2026). Relevant to RHEL-family hosting servers running Control Web Panel.**
- Installation needs root; how attackers get root is unknown. The installer `cwpsrv_update.sh` (captured 29 Jun 2026) replaces CWP's `cwpsrv` (versions 1.15.10 and 1.24.0), restores the original timestamps and deletes the `cwpsrv.prev-*` backup (T1554, T1070.006) — [The Hacker News](https://thehackernews.com/2026/11/hackers-hide-linux-backdoor-in-control.html).
- Trigger and evasion: a request carrying a timestamp and signature in custom `X-Ngx-Integrity*` headers executes the embedded command, and such requests never appear in access logs. VirusTotal detection was 0/63. It uses the Unix socket `ngx_http_integrity_helper`. Detection: `ss -axp | grep integrity` and `strings /usr/local/cwpsrv/bin/cwpsrv | grep X-Ngx-Integrity` — [The Hacker News](https://thehackernews.com/2026/11/hackers-hide-linux-backdoor-in-control.html).
- An archive uploaded from Brazil held both CWPdoor and Ebury; the link between them is unproven — [The Hacker News](https://thehackernews.com/2026/11/hackers-hide-linux-backdoor-in-control.html). More than 340,000 CWP instances are publicly exposed — [SC World](https://www.scworld.com/brief/new-cwpdoor-malware-targets-linux-servers-via-control-web-panel).

**Plague (Nextron Systems, 1 Aug 2025)**
- A malicious PAM module (T1556.003). Samples date from 29 Jul 2024 and are named `libselinux.so.8`, `hijack` and `libse.so`; they scored 0/66 on VirusTotal. Hardcoded passwords include `Mvi4Odm6tld7`, `IpV57KNK32Ih` and `changeme` — [Nextron](https://www.nextron-systems.com/2025/08/01/plague-a-newly-discovered-pam-based-backdoor-for-linux/).
- Anti-forensics: unsets SSH_CONNECTION and SSH_CLIENT and sets HISTFILE=/dev/null (T1070.003).
- Obfuscation and anti-analysis: layered string obfuscation (XOR, then KSA/PRGA, then DRBG); checks its own filename and that ld.so.preload is absent from the environment (T1622, T1497).
- Detection: YARA rule `MAL_LNX_PLAGUE_BACKDOOR_Jul25` — [Nextron](https://www.nextron-systems.com/2025/08/01/plague-a-newly-discovered-pam-based-backdoor-for-linux/). Nextron advises auditing /lib/security and /etc/pam.d and reviewing auth logs — [Security Affairs](https://securityaffairs.com/180701/malware/new-linux-backdoor-plague-bypasses-auth-via-malicious-pam-module.html).

**Symbiote (Intezer/BlackBerry, Jun 2022)**
- A shared object loaded into every process via LD_PRELOAD (T1574.006, vendor-mapped). It hooks libc and libpcap, and hooks BPF setup (setsockopt) to hide its traffic from packet captures. A hardcoded password lets the operator log in as any user, and it steals credentials. First detected Nov 2021, aimed at the Latin American financial sector — [Intezer](https://intezer.com/blog/new-linux-threat-symbiote), [BlackBerry](https://blogs.blackberry.com/en/2022/06/symbiote-a-new-nearly-impossible-to-detect-linux-threat).

**Auto-color (Unit 42, Feb 2025)**
- Used Nov–Dec 2024 against universities and governments in North America and Asia; the initial access vector was not seen. With root it copies itself to `/var/log/cross/auto-color`, installs a library implant (`libcext.so.2` per The Hacker News) and registers it in the preload configuration (T1574.006). Its libc hooks remove attacker connections from /proc/net/tcp (T1014). The C2 config is custom-encrypted. Capabilities: reverse shell, proxy, file operations and a kill-switch uninstall. Unit 42 recommends monitoring changes to the preload file and anomalies in /proc/net/tcp — [Unit 42](https://unit42.paloaltonetworks.com/new-linux-backdoor-auto-color/), [The Hacker News](https://thehackernews.com/2025/02/new-linux-malware-auto-color-grants.html).

**BPFDoor (Red Menshen / Earth Bluecrow)**
- A passive backdoor whose BPF socket filter wakes on a magic packet (T1205.002). v1 artifacts are /dev/shm/kdmtmpflush (the binary deletes itself after starting) and a zero-byte /var/run/haldrund.pid. v2 dropped the /dev/shm execution — [Sandfly analysis](https://sandflysecurity.com/blog/bpfdoor-an-evasive-linux-backdoor-technical-analysis/), [Sandfly hunting](https://sandflysecurity.com/blog/bpfdoor-detection-analysis-and-hunting-tactics-on-linux).
- Apr 2025: Trend Micro found a controller (reverse shell over TCP, UDP or ICMP) used in 2024 against telecom, finance and retail in South Korea, Hong Kong, Myanmar, Malaysia and Egypt. Attribution is moderate because the source code leaked in 2022 — [Trend Micro](https://www.trendmicro.com/en_hk/research/25/d/bpfdoor-hidden-controller.html).
- The SK Telecom breach (Apr 2025) involved BPFDoor; about 27M user records were compromised — [Korea Times](https://koreatimes.co.kr/business/tech-science/20250519/27-mil-user-records-leaked-in-sk-telecom-data-breach).
- Dec 2025: Unit 42 said a React2Shell implant earlier labelled BPFDoor was actually KSwapDoor — [SecurityWeek](https://www.securityweek.com/wide-range-of-malware-delivered-in-react2shell-attacks/).

**Koske (Aqua Nautilus, 24 Jul 2025): AI-assisted**
- Initial access: a misconfigured JupyterLab. Polyglot JPEGs on iili.io, postimages.org and i.imgs.ovh carry a C rootkit and a shell script that run from memory (T1190, T1027.009) — [Aqua](https://www.aquasec.com/blog/ai-generated-malware-in-panda-image-hides-persistent-linux-threat/).
- Persistence: `.bashrc` and `.bash_logout` run `.bashrc.koske` (T1546.004); /etc/rc.local is linked to a custom systemd service (T1037.004); cron every 30 minutes and @reboot (T1053.003); and a self-restarting `shellkoske.service` (T1543.002) — [Aqua](https://www.aquasec.com/blog/ai-generated-malware-in-panda-image-hides-persistent-linux-threat/).
- Evasion: `hideproc.so`, loaded via LD_PRELOAD or /etc/ld.so.preload, hooks readdir() to hide "koske" and "hideproc", reading the PID to hide from /dev/shm/.hiddenpid (T1574.006, T1014) — [Aqua](https://www.aquasec.com/blog/ai-generated-malware-in-panda-image-hides-persistent-linux-threat/).
- Network tampering: resets proxy variables, flushes iptables, rewrites /etc/resolv.conf to Cloudflare/Google DNS and locks it with `chattr +i` (T1562.004, T1222.002) — [Aqua](https://www.aquasec.com/blog/ai-generated-malware-in-panda-image-hides-persistent-linux-threat/).
- Impact: detects CPU and GPU, then runs ccminer across 18 coins with automatic switching — [Aqua](https://www.aquasec.com/blog/ai-generated-malware-in-panda-image-hides-persistent-linux-threat/). Aqua flags the code as LLM-assisted — [BetaNews](https://betanews.com/2025/07/24/hackers-are-using-ai-and-panda-images-to-infect-linux-machines-heres-how/).

**sedexp (Stroz Friedberg/Aon, Aug 2024)**
- Persists through a udev rule, `ACTION=="add", ENV{MAJOR}=="1", ENV{MINOR}=="8", RUN+="asedexpb run:+"` (T1546.017). It hides files, webshells and modified Apache configs, has been active since at least 2022, and is financially motivated — [Aon](https://aon.com/en/insights/cyber-labs/unveiling-sedexp), [Security Affairs](https://securityaffairs.com/167567/malware/linux-malware-sedexp.html).

**XZ Utils backdoor (CVE-2024-3094, disclosed 29 Mar 2024)**
- A supply-chain backdoor in xz 5.6.0 and 5.6.1 aimed at sshd authentication (T1195.001). It reached testing, unstable and rolling distros (Debian testing/unstable, Fedora Rawhide/40 beta) but not RHEL, Debian stable or released Ubuntu — [Qualys](https://blog.qualys.com/vulnerabilities-threat-research/2024/03/29/xz-utils-sshd-backdoor), [Tenable](https://Tenable.com/blog/frequently-asked-questions-cve-2024-3094-supply-chain-backdoor-in-xz-utils).

#### D. Linux ransomware, ESXi encryptors and data extortion
- RansomEXX2 (IBM X-Force, Nov 2022): a Rust rewrite aimed primarily at Linux, using AES-256 with RSA; only 14 of more than 60 AV engines detected it — [IBM X-Force](https://www.ibm.com/think/x-force/ransomexx-upgrades-rust).
- Royal added a Linux/ESXi encryptor in early 2023; it originally used BlackCat's encryptor before switching to Zeon — [BleepingComputer](https://www.bleepingcomputer.com/news/security/linux-version-of-royal-ransomware-targets-vmware-esxi-servers). Akira Linux variants have been seen since June 2023 — [SentinelOne](https://www.sentinelone.com/blog/from-conti-to-akira-decoding-the-latest-linux-esxi-ransomware-families/).
- LockBit 5.0 (Sep 2025) targets Windows, Linux, ESXi and Proxmox — [vpncentral](https://vpncentral.com/lockbit-5-0-ransomware-hits-windows-linux-esxi/). Acronis reported it in active cross-platform attacks in Feb 2026 — [SecurityBrief UK](https://securitybrief.co.uk/story/lockbit-5-0-ransomware-targets-windows-linux-esxi).
- Qilin (late 2025) runs its Linux ELF encryptor on Windows through WSL, copied over with WinSCP and launched via Splashtop's SRManager.exe. Qilin claimed more than 700 victims in 62 countries in 2025 and also uses BYOVD — [BleepingComputer](https://www.bleepingcomputer.com/news/security/qilin-ransomware-abuses-wsl-to-run-linux-encryptors-in-windows/).
- Gunra's Linux variant (Jul 2025) runs up to 100 encryption threads and supports partial encryption — [Dark Reading](https://www.darkreading.com/threat-intelligence/nimble-gunra-ransomware-linux-variant).
- 2026 newcomers:
  - Pay2Key's Linux encryptor checks for root, reads a JSON config and disables SELinux and AppArmor before ChaCha20 encryption (Morphisec, 24 Mar 2026; T1562.001, T1486) — [Morphisec](https://www.morphisec.com/?p=9858).
  - GenieLocker hit Windows, Linux servers and ESXi in a single intrusion, using XChaCha20-Poly1305 (Kaspersky, Mar 2026) — [Securelist](https://securelist.com/genielocker-ransomware-for-windows-linux-and-esxi/120843/).
  - Vect 2.0 permanently destroys files over 131 KB on Windows, Linux and ESXi (Feb 2026; T1485) — [Secure.com](https://www.secure.com/news/vect-2-0-ransomware-targets-windows-linux-esxi).
- Exposed databases: a Ransomnews study (published 26 May 2026; data May 2021 to 13 May 2026) found ransom or wipe notes on 30,515 of 65,907 exposed systems (46.3%):

  | Engine | With note | Exposed |
  |---|---|---|
  | MongoDB | 3,525 | 3,532 |
  | MySQL | 2,930 | 2,931 |
  | Elasticsearch | 6,055 | 6,185 |
  | Kibana | 3,739 | 3,821 |

  Most attacks copy and delete data rather than encrypt it. The study traced 514 BTC wallets, of which 318 never received a payment; the standard demand is 0.01 BTC, and total confirmed revenue was 9.78 BTC (T1485, T1657) — [Security Affairs](https://securityaffairs.com/192711/cyber-crime/the-hidden-ransomware-economy-running-on-exposed-databases.html).
- Automated MongoDB extortion was still active in Feb 2026, alongside exploitation of "MongoBleed" CVE-2025-14847 and CVE-2024-3372 — [Rescana](https://www.rescana.com/post/exposed-mongodb-servers-remain-prime-targets-for-automated-data-extortion-attacks-and-vulnerability). Exposed Redis is usually abused to compromise the host for mining rather than ransomed; 5.3% of cloud environments expose Redis — [Wiz](https://www.wiz.io/it-it/blog/database-ransomware-research).

#### E. Notable new Linux server campaigns, 2025 to 2026
- **React2Shell (CVE-2025-55182, CVSS 10, Dec 2025):** an unauthenticated RCE in React Server Components that also affects Next.js, Waku, React Router and RedwoodSDK. Payloads included:
  - XMRig, per Google Threat Intelligence; UNC6588 used wget to pull the COMPOOD backdoor — [Google Cloud](https://cloud.google.com/blog/topics/threat-intelligence/threat-actors-exploit-react2shell-cve-2025-55182).
  - XMRig 6.24.0 from GitHub, the PeerBlight backdoor (BitTorrent DHT fallback C2), the CowTunnel reverse proxy and the ZinFoq Go implant — [Huntress](https://www.huntress.com/blog/peerblight-linux-backdoor-exploits-react2shell).
  - KSwapDoor and ZnDoor — [SecurityWeek](https://www.securityweek.com/wide-range-of-malware-delivered-in-react2shell-attacks/).
  - CISA added the flaw to KEV.
- **Non-root, PAM-abusing XMRig campaign (identified May 2026; Group-IB published 30 Jul 2026):**
  - Initial access came through a trusted third party's standard account (T1199); the actor escalated to root, then used `pam_rootok` and `su` to become several low-privileged users without their passwords.
  - It planted redundant cron jobs in multiple unmonitored accounts, so cleaning up only the root compromise leaves the implant in place.
  - It uses a /tmp/.lock mutex and deletes its own binary to run from memory. The `-h` flag spoofs the process name (example: `ssh`). Stratum traffic carries the User-Agent "Java/Agent" and goes to the pool `unable.download`. It also tampered with auth logs.
  - Group-IB maps the concealment to T1564.013 (vendor-mapped). It advises alerting on rsyslog/auditd stops, real-time log forwarding, and reviewing /var/log/secure and audit.log for USER_START events tied to pam_rootok — [Group-IB](https://www.group-ib.com/blog/xmrig-covert-linux-pam-abuse/).
- **Realm C2 campaign (Wiz, 13–23 Jun 2026):** compromised thousands of Linux hosts, mainly in large managed Kubernetes clusters, by exploiting Argo Workflows and Gogs. It deployed miners and used stolen service-account tokens to spread to more than 300 more nodes through privileged container escape (T1611) — [Wiz Threat Landscape](https://threats.wiz.io/all-incidents/cryptojacking-campaign-targeting-k8s-clusters).
- **SysGoRAT / CL-UNK-1211 (Unit 42; activity Oct 2025 to Apr 2026; reported 2 Nov 2026):** targeted government Linux servers.
  - The Go RAT uses WebSocket C2 to 104.194.158[.]65:443 and offers command, shell, proxy and `persist` commands.
  - Credential theft: replaces .bashrc with a password-stealing version (T1546.004), injects code into PHP login pages, and scans config and history files for cleartext passwords (T1552.001/.003). PHP web shells provide persistence (T1505.003).
  - Unit 42 assesses the shell and PHP scripts as likely AI-generated. The attackers tried to disable endpoint protection and wipe logs, and ran in-memory reverse shells — [The Hacker News](https://thehackernews.com/2026/11/government-linux-servers-targeted-with.html).
- **Showboat (May 2026):** a Linux backdoor used against a Middle East telecom since mid-2022, with C2, SOCKS5 proxying and file theft — [The Hacker News](https://thehackernews.com/2026/05/showboat-linux-malware-hits-middle-east.html).
- **AhnLab SSH honeypots, 2026:**
  - Q1 (Q1 2026 report): one attacker installed V2Ray to use the host as a proxy — [AhnLab](https://asec.ahnlab.com/en/93336/).
  - Q2 (published 3 Jul 2026): after login the attacker downloads `run`, which launches `mysql` (actually XMRig) and `meta` (an SSH scanner fed by `ranges` and `pass` files) from `pack.Jpg`. Other cases included ShellBot named `.B0t`, MIG LogCleaner, XHide and Shc-compiled scripts — [AhnLab](https://asec.ahnlab.com/en/94396/).
  - Q3 (published 14 Oct 2026): ShellBot, XMRig, XHide, the Fisieredoor backdoor and the goauto/tsm brute-forcers, plus a user-mode rootkit in /etc/ld.so.preload that ran XMRig disguised as "bash" — [OTX mirror of AhnLab Q3 2026](https://radar.offseq.com/threat/statistical-report-on-malware-targeting-linux-ssh-servers-in-the-third-quarter-of-2026-e9e135b7e4c8d4c6).
- **SSH lateral-movement tooling (Sysdig 2024):** SSH-Snake was weaponized by CRYSTALRAY to steal more than 1,500 credentials, and the RUBYCARP botnet went undetected for over a decade — [Sysdig 2024 Global Threat Report](https://sysdig.com/wp-content/uploads/2024-global-threat-report.pdf).

### Inferences
- The company's own incident (SSH compromise, a miner with a watchdog, cron and systemd persistence, replaced system binaries) matches the most common public pattern. TeamTNT's CentOS VPS chain, Outlaw/Dota and perfctl are near-identical, so it was almost certainly commodity tooling rather than a targeted attack. Reinfection is likely unless every credential and key is rotated, because Ebury, Outlaw and P2Pinfect all reuse stolen credentials or keys.
- Commodity families converge on about a dozen host artifacts: /etc/ld.so.preload, the cron directories, systemd units and timers, shell rc/profile files, authorized_keys, PAM modules, executables in /tmp, /var/tmp or /dev/shm, processes whose binary is deleted, chattr flags, kernel-thread-named userland processes, mining-pool or Tor egress, and kernel module loads. A small agent that watches these well covers most real attacks on SMB VPS.
- Backdoors in the authentication path (Ebury, Plague, Skidmap's pam_unix, CWPdoor, XZ) defeat signature AV (0/66, 0/63). Integrity checks against the package-manager database and known-good hashes are the only reliable host-side control; a signature feed from the master server alone will miss them.
- Miners that avoid root (Group-IB 2026) and per-user persistence (Outlaw's ~/.configrc6, P2Pinfect's .bashrc) mean the agent must watch every user's crontab, ~/.config/systemd/user, shell rc files and authorized_keys, not just root's.
- AI-assisted malware (Koske, SysGoRAT) and React2Shell-style mass exploitation shorten the time from disclosure to commodity payload. Behavioral detection (execution from writable dirs, preload changes, pool egress) ages better than IOC lists.

### Gaps
- Kinsing's 2025 activity (CVE-2025-9074 Docker escape, runc CVEs, a Sharpire backdoor) appears only in an unverified Q&A site ([Security Scientist](https://answers.securityscientist.net/q/22591/what-do-the-latest-kinsing-campaigns-2024-2025-tell-us-about-its-evolution)). No primary vendor confirmation was found.
- I found no primary 2025–2026 report of 8220 Gang activity; the latest found is 2024 (k4spreader, WebLogic).
- Ebury's deployment mechanics (OpenSSH patching, libkeyutils, preload injection) are not in ESET's 2024 blog text, and the full white paper was not read. The 2019 hosting-provider figure (about 2,500 physical and 60,000 virtual servers) appeared only in press coverage of the paper and was not verified.
- The figure for Microsoft's 2022 XorDDoS surge (254% vs 256%) appears only in secondary blogs. The XorDDoS artifact paths come from older (2015–2016) encyclopedia entries.
- The 2025 BPFDoor variant statistics (about 150 new samples in 2025, IPv6 filtering) come from a post whose comparison table was flagged as AI-generated; they are not included as findings.
- The exact Migo Redis "weakening" commands, the date of Akamai's Mexals-resurgence blog, and the CWPdoor initial-access vector (not identified by XLab) were not established.
- MITRE ATT&CK software pages were not fetched; IDs not marked "(vendor-mapped)" are my own mapping.

## Q2. Artifact-level behaviors mapped to ATT&CK, detection signal and stopping response (by defensive module)

### Takeaway
Every module the Fusion agent plans to ship has a documented, recent real-world attack it would have caught:
- **Auth logs:** SSH brute force by Outlaw, Diicot, XorDDoS, TeamTNT and P2Pinfect.
- **Process exec:** /tmp and /dev/shm execution and deleted binaries (perfctl, BPFDoor, Kinsing, Group-IB 2026), and kernel-thread masquerading (Outlaw, P2Pinfect).
- **File integrity:** ld.so.preload (Kinsing, Migo, perfctl, Koske, Auto-color); cron and systemd persistence (nearly all); authorized_keys (Outlaw, TeamTNT, P2Pinfect); PAM (Plague, Skidmap); replaced binaries (perfctl, CWPdoor, Ebury).
- **Network:** mining-pool, Tor and IRC egress; BPF magic packets.
- **Resource usage:** sustained CPU, hugepages and MSR writes.

The response that actually stops these campaigns is ordered:
1. Freeze the whole process tree and its watchdogs.
2. Clear immutable flags.
3. Remove all persistence, including per-user entries.
4. Kill the frozen processes.
5. Block egress.
6. Restore binaries from packages.
7. Rotate credentials.

### Cited Findings

#### Detection-to-response matrix (each row cites real campaigns)

| # | Attacker behavior / artifact (real examples) | ATT&CK | Primary detection signal | Response that stops it |
|---|---|---|---|---|
| 1 | SSH password guessing/spraying: Outlaw BLITZ ([Elastic](https://www.elastic.co/security-labs/outlaw-linux-malware)); Diicot hardcoded pairs ([Wiz](https://www.wiz.io/blog/diicot-threat-group-malware-campaign)); XorDDoS root-credential script ([Talos](https://blog.talosintelligence.com/unmasking-the-new-xorddos-controller-and-infrastructure/)); TeamTNT on CentOS ([Group-IB](https://www.group-ib.com/blog/teamtnt/)); P2Pinfect sprayer ([Darktrace](https://www.darktrace.com/blog/from-dormant-to-dangerous-p2pinfect-evolves-to-deploy-new-ransomware-and-cryptominer)) | T1110.001/.003, T1078 | Auth logs: failure bursts, then a success from the same or a new IP. Elastic rules: "Potential External Linux SSH Brute Force Detected", "Successful SSH Authentication from Unusual IP Address" ([Elastic](https://www.elastic.co/security-labs/outlaw-linux-malware)) | Block the source IP in the firewall; alert on the success; force key-only auth; kill the new session's process tree |
| 2 | Download-and-execute after login: tddwrt7s.sh, then dota3.tar.gz ([Elastic](https://www.elastic.co/security-labs/outlaw-linux-malware)); rconf with a raw-TCP GET ([Aqua](https://www.aquasec.com/blog/perfctl-a-stealthy-malware-targeting-millions-of-linux-servers/)); `run` from pack.Jpg ([AhnLab Q2-26](https://asec.ahnlab.com/en/94396/)); polyglot JPEG payloads ([Aqua Koske](https://www.aquasec.com/blog/ai-generated-malware-in-panda-image-hides-persistent-linux-threat/)); base64 piped to perl ([Elastic](https://www.elastic.co/security-labs/outlaw-linux-malware)) | T1105, T1059.004, T1140, T1027.009 | Process exec: sshd, then a shell, then curl/wget/raw socket, then sh/perl. Elastic rule "Base64 Decoded Payload Piped to Interpreter" ([Elastic](https://www.elastic.co/security-labs/outlaw-linux-malware)) | Kill the tree; quarantine the dropped files; block the download host |
| 3 | Execution from writable dirs or of deleted binaries: /tmp/httpd → /tmp/sh, original deleted ([Aqua perfctl](https://www.aquasec.com/blog/perfctl-a-stealthy-malware-targeting-millions-of-linux-servers/)); /dev/shm/kdmtmpflush, deleted ([Sandfly](https://sandflysecurity.com/blog/bpfdoor-an-evasive-linux-backdoor-technical-analysis/)); kdevtmpfsi in /tmp, /var/tmp or /dev/shm ([Sandfly](https://sandflysecurity.com/blog/log4j-kinsing-linux-malware-in-the-wild)); /tmp/.lock with a self-deleted binary ([Group-IB 2026](https://www.group-ib.com/blog/xmrig-covert-linux-pam-abuse/)); Chaos deletes itself ([Help Net](https://www.helpnetsecurity.com/2026/04/08/chaos-malware-cloud-misconfigured-servers/)) | T1070.004, T1036.005 | Process exec and /proc scan: exe under /tmp, /var/tmp or /dev/shm, or /proc/PID/exe "(deleted)". Aqua: flag httpd or sh running from /tmp ([Aqua](https://www.aquasec.com/blog/perfctl-a-stealthy-malware-targeting-millions-of-linux-servers/)) | Copy /proc/PID/exe for evidence, then freeze and kill. Aqua recommends mounting /tmp and /dev/shm noexec ([Aqua](https://www.aquasec.com/blog/perfctl-a-stealthy-malware-targeting-millions-of-linux-servers/)) |
| 4 | Process-name masquerading: kswapd0 and kthreadadd ([Elastic](https://www.elastic.co/security-labs/outlaw-linux-malware)); [kworker/1:0H] ([Darktrace](https://www.darktrace.com/blog/from-dormant-to-dangerous-p2pinfect-evolves-to-deploy-new-ransomware-and-cryptominer)); XMRig named `mysql` ([AhnLab Q2-26](https://asec.ahnlab.com/en/94396/)) or `bash` ([AhnLab Q3-26 via OTX](https://radar.offseq.com/threat/statistical-report-on-malware-targeting-linux-ssh-servers-in-the-third-quarter-of-2026-e9e135b7e4c8d4c6)); spoofed `ssh` ([Group-IB 2026](https://www.group-ib.com/blog/xmrig-covert-linux-pam-abuse/)); /var/tmp/Documents/Opera ([Wiz](https://www.wiz.io/blog/diicot-threat-group-malware-campaign)) | T1036.005, T1036.004 | Process exec: a kernel-thread name with a userland exe, or comm/argv that doesn't match the exe path or package owner | Kill and quarantine the exe; add its hash to master intel |
| 5 | Miner running (resource hijack): XMRig 6.22.1 on all threads with hugepages and MSR writes ([Elastic](https://www.elastic.co/security-labs/outlaw-linux-malware)); RandomX with hugepages on port 2137 private pools ([Akamai](https://www.akamai.com/blog/security-research/2024/may/2024-redtail-cryptominer-pan-os-cve-exploit)); supportxmr:443 and Zephyr :7777/:8080 ([Wiz](https://www.wiz.io/blog/diicot-threat-group-malware-campaign)); c3pool on :19999 ([Darktrace](https://www.darktrace.com/blog/from-dormant-to-dangerous-p2pinfect-evolves-to-deploy-new-ransomware-and-cryptominer)); Stratum with UA "Java/Agent" to unable.download ([Group-IB 2026](https://www.group-ib.com/blog/xmrig-covert-linux-pam-abuse/)); mining over Tor ([Aqua](https://www.aquasec.com/blog/perfctl-a-stealthy-malware-targeting-millions-of-linux-servers/)) | T1496.001 | Resource: sustained high CPU, including CPU spikes while the server is idle ([Aqua](https://www.aquasec.com/blog/perfctl-a-stealthy-malware-targeting-millions-of-linux-servers/)). Network: Stratum JSON-RPC and pool ports. Elastic rule "MSR Write Access Enabled" ([Elastic](https://www.elastic.co/security-labs/outlaw-linux-malware)) | Kill; block pool domains, IPs and Tor at the firewall/DNS (Group-IB advises blocking unable.download ([Group-IB](https://www.group-ib.com/blog/xmrig-covert-linux-pam-abuse/))); remove persistence |
| 6 | Watchdog or self-restart: `upd` restarts the miner ([Elastic](https://www.elastic.co/security-labs/outlaw-linux-malware)); `wizlmsh` restarts the payload ([Aqua](https://www.aquasec.com/blog/perfctl-a-stealthy-malware-targeting-millions-of-linux-servers/)); systemd timer every 5 s ([Infosecurity](https://www.infosecurity-magazine.com/news/linux-malware-migo-targets-redis/)); self-restarting shellkoske.service ([Aqua](https://www.aquasec.com/blog/ai-generated-malware-in-panda-image-hides-persistent-linux-threat/)); `History`/`.b` crons restart payloads ([Wiz](https://www.wiz.io/blog/diicot-threat-group-malware-campaign)); /tmp/bash health-checker ([Darktrace](https://www.darktrace.com/blog/from-dormant-to-dangerous-p2pinfect-evolves-to-deploy-new-ransomware-and-cryptominer)); Chaos keep-alive script ([Help Net](https://www.helpnetsecurity.com/2026/04/08/chaos-malware-cloud-misconfigured-servers/)) | T1053.003, T1053.006, T1543.002 | Process exec: the same exe hash or cmdline respawns within seconds of a kill, and the parent is cron, systemd or a sibling | Freeze (SIGSTOP) the whole tree/cgroup and the sibling watchdogs first; remove persistence; then SIGKILL (see Inferences) |
| 7 | Cron persistence: exact Outlaw entries ([Elastic](https://www.elastic.co/security-labs/outlaw-linux-malware)); TeamTNT 30-min job, timestamp faked to 2018-05-15 ([Group-IB](https://www.group-ib.com/blog/teamtnt/)); /etc/cron.hourly/gcc.sh ([Trend Micro](https://www.trendmicro.com/vinfo/us/threat-encyclopedia/malware/ELF_XORDDOS.ARE)); cron written by Redis ([THN Skidmap](https://thehackernews.com/2023/08/new-skidmap-redis-malware-variant.html), [Darktrace P2Pinfect](https://www.darktrace.com/blog/from-dormant-to-dangerous-p2pinfect-evolves-to-deploy-new-ransomware-and-cryptominer)); per-user crons in low-privileged accounts ([Group-IB 2026](https://www.group-ib.com/blog/xmrig-covert-linux-pam-abuse/)) | T1053.003, T1070.006 | FIM on /etc/crontab, /etc/cron.d, /etc/cron.{hourly,daily,…} and /var/spool/cron(/crontabs) for all users. Elastic rule "Cron Job Created or Modified" ([Elastic](https://www.elastic.co/security-labs/outlaw-linux-malware)). Don't trust mtime, since TeamTNT backdated it | Quarantine the entry, then restore the baseline |
| 8 | systemd persistence: bot.service ([Sandfly](https://sandflysecurity.com/blog/log4j-kinsing-linux-malware-in-the-wild)); service plus 5 s timer ([Infosecurity](https://www.infosecurity-magazine.com/news/linux-malware-migo-targets-redis/)); shellkoske.service ([Aqua](https://www.aquasec.com/blog/ai-generated-malware-in-panda-image-hides-persistent-linux-threat/)); Chaos unit ([Help Net](https://www.helpnetsecurity.com/2026/04/08/chaos-malware-cloud-misconfigured-servers/)) | T1543.002, T1053.006 | FIM on /etc/systemd/system, /lib/systemd/system, /usr/lib/systemd/system and ~/.config/systemd/user; daemon-reload events | stop, disable and mask the unit; quarantine the file |
| 9 | Shell rc/profile hooks: ~/.profile runs perfcc ([Aqua](https://www.aquasec.com/blog/perfctl-a-stealthy-malware-targeting-millions-of-linux-servers/)); .bashrc/.bash_logout run .bashrc.koske ([Aqua](https://www.aquasec.com/blog/ai-generated-malware-in-panda-image-hides-persistent-linux-threat/)); `export LD_PRELOAD` in .bashrc ([Darktrace](https://www.darktrace.com/blog/from-dormant-to-dangerous-p2pinfect-evolves-to-deploy-new-ransomware-and-cryptominer)); .bashrc replaced to steal passwords ([THN SysGoRAT](https://thehackernews.com/2026/11/government-linux-servers-targeted-with.html)) | T1546.004 | FIM on /etc/profile, /etc/profile.d, /etc/bash.bashrc and each user's .bashrc, .profile and .bash_logout | Revert to baseline; alert; rotate passwords typed since the change |
| 10 | PATH interception and utility swaps: /etc/profile PATH puts trojanized ldd, top, lsof and crontab first ([Aqua](https://www.aquasec.com/blog/perfctl-a-stealthy-malware-targeting-millions-of-linux-servers/)); TeamTNT renames curl/wget to tntcurl/tntwget ([Group-IB](https://www.group-ib.com/blog/teamtnt/)) | T1574.007, T1036 | FIM on PATH-defining files; new executables in ~/.local/bin or /usr/local/bin that shadow system binaries; renamed system binaries | Remove the shadows; restore packages |
| 11 | Dynamic-linker hijack and userland rootkits: /etc/libsystem.so ([Trend Micro](https://www.trendmicro.com/en_gb/research/20/k/analysis-of-kinsing-malwares-use-of-rootkit.html)); libprocesshider ([Darktrace Migo](https://www.darktrace.com/blog/migo-a-redis-miner-with-novel-system-weakening-techniques)); libgcwrap.so ([Aqua](https://www.aquasec.com/blog/perfctl-a-stealthy-malware-targeting-millions-of-linux-servers/)); hideproc.so ([Aqua Koske](https://www.aquasec.com/blog/ai-generated-malware-in-panda-image-hides-persistent-linux-threat/)); Auto-color implant ([Unit 42](https://unit42.paloaltonetworks.com/new-linux-backdoor-auto-color/)); Symbiote ([Intezer](https://intezer.com/blog/new-linux-threat-symbiote)); XMRig hidden as "bash" ([AhnLab Q3-26 via OTX](https://radar.offseq.com/threat/statistical-report-on-malware-targeting-linux-ssh-servers-in-the-third-quarter-of-2026-e9e135b7e4c8d4c6)) | T1574.006, T1014 | FIM on /etc/ld.so.preload (AhnLab and Unit 42 both call out monitoring it); new .so files in lib dirs; LD_PRELOAD in /proc/PID/environ; /proc versus `ps`/`ls` view mismatch | Clear immutable flags; remove the preload entry; quarantine the .so; restart affected daemons |
| 12 | PAM backdoors: Plague as libselinux.so.8 with static passwords, unsetting SSH_CONNECTION/SSH_CLIENT and HISTFILE=/dev/null ([Nextron](https://www.nextron-systems.com/2025/08/01/plague-a-newly-discovered-pam-based-backdoor-for-linux/)); replaced pam_unix.so ([Security Affairs](https://securityaffairs.com/91441/malware/skidmap-linux-miner.html)); hooked pam_authenticate ([Aqua](https://www.aquasec.com/blog/perfctl-a-stealthy-malware-targeting-millions-of-linux-servers/)); pam_rootok/su abuse ([Group-IB 2026](https://www.group-ib.com/blog/xmrig-covert-linux-pam-abuse/)) | T1556.003, T1070.003 | FIM and package verification on /lib/security, /lib64/security, /usr/lib/x86_64-linux-gnu/security and /etc/pam.d (Nextron's advice ([Security Affairs](https://securityaffairs.com/180701/malware/new-linux-backdoor-plague-bypasses-auth-via-malicious-pam-module.html))); auth logs showing USER_START with pam_rootok ([Group-IB](https://www.group-ib.com/blog/xmrig-covert-linux-pam-abuse/)) | Reinstall the PAM package; terminate sessions; rotate all credentials; isolate the host |
| 13 | Trojanized or replaced binaries: Ebury in OpenSSH ([ESET](https://www.welivesecurity.com/en/eset-research/ebury-alive-unseen-400k-linux-servers-compromised-cryptotheft-financial-gain/)); cwpsrv replaced with timestamps restored, 0/63 VT ([THN CWPdoor](https://thehackernews.com/2026/11/hackers-hide-linux-backdoor-in-control.html)); ldd, top, lsof, crontab ([Aqua](https://www.aquasec.com/blog/perfctl-a-stealthy-malware-targeting-millions-of-linux-servers/)); liblzma used against sshd ([Qualys](https://blog.qualys.com/vulnerabilities-threat-research/2024/03/29/xz-utils-sshd-backdoor)) | T1554, T1195.001, T1070.006 | Binary-integrity FIM: hash against the dpkg/rpm database and a baseline taken at install (timestamps are unreliable); new listening Unix sockets (e.g. `ngx_http_integrity_helper`); unexpected helper children of daemons ([THN](https://thehackernews.com/2026/11/hackers-hide-linux-backdoor-in-control.html)) | Restore via package reinstall; rotate credentials; treat the host as compromised (XLab's advice for CWPdoor ([THN](https://thehackernews.com/2026/11/hackers-hide-linux-backdoor-in-control.html))) |
| 14 | SSH key implants, backdoor accounts and sshd changes: ~/.ssh recreated with an attacker key and `chattr +ia` ([Elastic](https://www.elastic.co/security-labs/outlaw-linux-malware)); user `hilde` with sudo, keys for hilde and root, SSH moved to port 11222 ([Group-IB](https://www.group-ib.com/blog/teamtnt/)); key plus PermitRootLogin with password ([Darktrace](https://www.darktrace.com/blog/from-dormant-to-dangerous-p2pinfect-evolves-to-deploy-new-ransomware-and-cryptominer)); Diicot key ([Cado](https://www.darktrace.com/blog/tracking-diicot-an-emerging-romanian-threat-actor)) | T1098.004, T1136.001, T1548.003 | FIM on every authorized_keys, sshd_config(.d), /etc/passwd, /etc/shadow and /etc/sudoers(.d). Elastic rule "SSH Authorized Keys File Modification" ([Elastic](https://www.elastic.co/security-labs/outlaw-linux-malware)) | Remove the key (after clearing flags); lock or delete the account; revert sshd_config and reload; Discord alert |
| 15 | Immutability and anti-remediation: Outlaw `chattr +ia` ([Elastic](https://www.elastic.co/security-labs/outlaw-linux-malware)); Koske `chattr +i /etc/resolv.conf` ([Aqua](https://www.aquasec.com/blog/ai-generated-malware-in-panda-image-hides-persistent-linux-threat/)); TeamTNT disables chattr and blocks reboot and recovery ([Group-IB](https://www.group-ib.com/blog/teamtnt/)) | T1222.002, T1490 | Process exec of chattr, or ioctl flag changes on persistence files. Elastic rule "File made Immutable by Chattr" ([Elastic](https://www.elastic.co/security-labs/outlaw-linux-malware)) | The agent must carry its own attribute-clearing code, since the system chattr may be disabled |
| 16 | Disabling defenses and killing security/cloud agents: Aliyun aegis uninstall, iptables/UFW off, SELinux/AppArmor off, NMI watchdog off ([Group-IB](https://www.group-ib.com/blog/teamtnt/)); SELinux disabled ([KPMG 8220](https://assets.kpmg.com/content/dam/kpmg/in/pdf/2024/04/kpmg-ctip-8220-gang-09-apr-2024.pdf)); firewall disabled ([XLab k4spreader](https://blog.xlab.qianxin.com/8220-k4spreader-new-tool-en/)); /etc/hosts blocks cloud providers ([Darktrace Migo](https://www.darktrace.com/blog/migo-a-redis-miner-with-novel-system-weakening-techniques)); perfctl shuts down security controls ([Aqua](https://www.aquasec.com/blog/perfctl-a-stealthy-malware-targeting-millions-of-linux-servers/)); SysGoRAT tried to disable EDR ([THN](https://thehackernews.com/2026/11/government-linux-servers-targeted-with.html)); Pay2Key disables SELinux/AppArmor ([Morphisec](https://www.morphisec.com/?p=9858)) | T1562.001, T1562.004, T1562.012 | Process exec of setenforce 0, systemctl stop/disable of auditd, rsyslog, firewalld or ufw, or iptables -F; FIM on /etc/selinux/config and /etc/hosts. Group-IB: alert on logging-service stops ([Group-IB](https://www.group-ib.com/blog/xmrig-covert-linux-pam-abuse/)) | Re-enable; kill the caller; tamper alert to master when the agent heartbeat stops |
| 17 | Killing competing miners: Outlaw `stop` scripts ([Elastic](https://www.elastic.co/security-labs/outlaw-linux-malware)); k4spreader kills Kinsing ([XLab](https://blog.xlab.qianxin.com/8220-k4spreader-new-tool-en/)); TeamTNT signature list ([Group-IB](https://www.group-ib.com/blog/teamtnt/)); perfctl kills competitors ([Aqua](https://www.aquasec.com/blog/perfctl-a-stealthy-malware-targeting-millions-of-linux-servers/)) | (no dedicated technique; T1489 when services are stopped) | Process exec: a non-admin process mass-kills others, or runs pkill/kill loops against miner names | Treat it as a high-confidence compromise signal and run the full containment |
| 18 | Log and history clearing: deletes /var/log/syslog and runs `history -c` ([Group-IB](https://www.group-ib.com/blog/teamtnt/)); log purge ([Security Affairs Skidmap](https://securityaffairs.com/149258/malware/skidmap-malware-redis-servers.html)); HISTFILE=/dev/null ([Nextron](https://www.nextron-systems.com/2025/08/01/plague-a-newly-discovered-pam-based-backdoor-for-linux/)); MIG LogCleaner ([AhnLab Q2-26](https://asec.ahnlab.com/en/94396/)); auth-log tampering ([Group-IB 2026](https://www.group-ib.com/blog/xmrig-covert-linux-pam-abuse/)); requests hidden from access logs ([THN CWPdoor](https://thehackernews.com/2026/11/hackers-hide-linux-backdoor-in-control.html)); log wiping ([THN SysGoRAT](https://thehackernews.com/2026/11/government-linux-servers-targeted-with.html)) | T1070.002, T1070.003, T1070.006 | FIM for truncation or deletion under /var/log; exec of log cleaners. Group-IB recommends real-time forwarding to tamper-resistant storage ([Group-IB](https://www.group-ib.com/blog/xmrig-covert-linux-pam-abuse/)) | Stream logs to the master in real time so local wiping doesn't destroy evidence |
| 19 | Kernel rootkits and udev persistence: Diamorphine via insmod ([Group-IB](https://www.group-ib.com/blog/teamtnt/)); mcpuinfo.ko and kmeminfo.ko ([Security Affairs](https://securityaffairs.com/149258/malware/skidmap-malware-redis-servers.html)); udev rule RUN+="asedexpb run:+" ([Aon](https://aon.com/en/insights/cyber-labs/unveiling-sedexp)) | T1547.006, T1014, T1546.017 | Module-load events, kernel taint, new .ko files; FIM on /etc/udev/rules.d, /lib/udev/rules.d and /etc/modules-load.d | Isolate the network (keeping the master channel); recommend a rebuild, because a host with a kernel rootkit can't be trusted |
| 20 | Stealth or unusual C2: BPF magic-packet listener ([Sandfly](https://sandflysecurity.com/blog/bpfdoor-an-evasive-linux-backdoor-technical-analysis/)); Tor ([Aqua](https://www.aquasec.com/blog/perfctl-a-stealthy-malware-targeting-millions-of-linux-servers/)); IRC SHELLBOT ([Elastic](https://www.elastic.co/security-labs/outlaw-linux-malware)); P2P on ports 60100–60150 ([Darktrace](https://www.darktrace.com/blog/from-dormant-to-dangerous-p2pinfect-evolves-to-deploy-new-ransomware-and-cryptominer)); DGA ([ESET](https://www.welivesecurity.com/en/eset-research/ebury-alive-unseen-400k-linux-servers-compromised-cryptotheft-financial-gain/)); WebSocket on 443 ([THN SysGoRAT](https://thehackernews.com/2026/11/government-linux-servers-targeted-with.html)); payloads from Google Sites ([Imperva](https://www.imperva.com/blog/new-sysrv-botnet-variant-makes-use-of-google-subdomain-to-spread-xmrig-miner/)) or image hosts ([Aqua](https://www.aquasec.com/blog/ai-generated-malware-in-panda-image-hides-persistent-linux-threat/)); BitTorrent DHT fallback ([Huntress](https://www.huntress.com/blog/peerblight-linux-backdoor-exploits-react2shell)); socat reverse shells (Elastic rule "Socat Reverse Shell or Listener Activity" ([Elastic](https://www.elastic.co/security-labs/outlaw-linux-malware))) | T1205.002, T1090.003, T1071, T1568.002, T1102 | Network: AF_PACKET/raw sockets held by non-network daemons; Tor or IRC egress; new listeners on high ports; /proc/net vs netstat mismatch | Kill; block egress; quarantine |
| 21 | Exposed Docker API and container abuse: ports 2375, 2376, 4243 and 4244, Swarm join ([Aqua](https://www.aquasec.com/blog/threat-alert-teamtnts-docker-gatling-gun-campaign/)); cmd.cat/chattr with docker.sock bind and chroot ([Trend Micro](https://www.trendmicro.com/en_us/research/24/f/commando-cat-a-novel-cryptojacking-attack-.html)); privileged-container escape and stolen service-account tokens ([Wiz 2026](https://threats.wiz.io/all-incidents/cryptojacking-campaign-targeting-k8s-clusters)) | T1610, T1611, T1578.002 (Aqua-mapped) | Exposure audit: dockerd listening on 0.0.0.0. Process: containers with host mounts or docker.sock. Trend Micro advises detection rules on Docker remote-API calls ([Trend Micro](https://www.trendmicro.com/en_us/research/24/f/commando-cat-a-novel-cryptojacking-attack-.html)) | Stop and remove the container; firewall the port; leave the Swarm |
| 22 | Redis/DB misconfiguration abuse: protected-mode off ([Darktrace Migo](https://www.darktrace.com/blog/migo-a-redis-miner-with-novel-system-weakening-techniques)); SLAVEOF and module load, CONFIG used to write cron ([Darktrace P2Pinfect](https://www.darktrace.com/blog/from-dormant-to-dangerous-p2pinfect-evolves-to-deploy-new-ransomware-and-cryptominer)); 46% of exposed DBs carry ransom notes ([Security Affairs](https://securityaffairs.com/192711/cyber-crime/the-hidden-ransomware-economy-running-on-exposed-databases.html)) | T1190, T1485 | Exposure audit (6379, 27017, 9200, 3306 on public interfaces with no auth); the redis user writing to cron or ~/.ssh; mass deletes | Firewall the port; set requirepass, protected-mode and binding (Wiz's guidance ([Wiz](https://www.wiz.io/blog/wiz-research-redis-rce-cve-2025-49844))) |
| 23 | Credential harvesting: /.env scraping ([CISA](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-016a)); IMDS IAM credentials ([Aqua](https://www.aquasec.com/blog/loony-tunables-vulnerability-exploited-by-kinsing/)); TeamTNT list of AWS, gcloud, Docker and Git credentials ([Aqua](https://www.aquasec.com/blog/threat-alert-teamtnts-docker-gatling-gun-campaign/)); history and config scraping ([THN SysGoRAT](https://thehackernews.com/2026/11/government-linux-servers-targeted-with.html)) | T1552.001/.003/.004/.005 | Process exec: curl/wget to 169.254.169.254 from unusual processes; reads of ~/.aws/credentials, .env or id_* by a shell spawned by a web or DB service | Alert; rotate the credentials; block metadata access for non-agent processes |
| 24 | Encryption or wiping: rsagen `.encrypted` with "Your data has been locked!.txt" ([Darktrace](https://www.darktrace.com/blog/from-dormant-to-dangerous-p2pinfect-evolves-to-deploy-new-ransomware-and-cryptominer)); Gunra with 100 threads ([Dark Reading](https://www.darkreading.com/threat-intelligence/nimble-gunra-ransomware-linux-variant)); Vect 2.0 destroying files over 131 KB ([Secure.com](https://www.secure.com/news/vect-2-0-ransomware-targets-windows-linux-esxi)); DB copy-and-delete ([Security Affairs](https://securityaffairs.com/192711/cyber-crime/the-hidden-ransomware-economy-running-on-exposed-databases.html)) | T1486, T1485, T1490 | FIM rate: mass renames or writes and new ransom-note files; canary files | Kill and suspend the writer; isolate the network; restore from backup |
| 25 | Proxyjacking or proxy abuse: bitping, earn.fm, speedshare and repocket ([Aqua](https://www.aquasec.com/blog/perfctl-a-stealthy-malware-targeting-millions-of-linux-servers/)); V2Ray install ([AhnLab Q1-26](https://asec.ahnlab.com/en/93336/)); Chaos SOCKS5 ([Help Net](https://www.helpnetsecurity.com/2026/04/08/chaos-malware-cloud-misconfigured-servers/)); Auto-color proxy ([Unit 42](https://unit42.paloaltonetworks.com/new-linux-backdoor-auto-color/)) | T1496.002, T1090 | Process exec of known proxyware; long-lived outbound tunnels; bandwidth anomalies | Kill; block the proxyware domains |

#### Vendor-published hunting guidance worth reusing as baseline rules
- **Aqua (perfctl):**
  - Inspect /tmp, /usr, /root and /home/*/.local/bin for masquerading binaries.
  - Check ~/.profile, /etc/profile and /etc/ld.so.preload, and verify ldd, top, lsof and crontab.
  - Watch for Tor, pool and proxyjacking traffic.
  - Mount /tmp and /dev/shm noexec and restrict outbound traffic.
  - [Aqua](https://www.aquasec.com/blog/perfctl-a-stealthy-malware-targeting-millions-of-linux-servers/)
- **Elastic (Outlaw):** detection rules for brute force, cron changes, authorized_keys changes, base64-to-interpreter, chattr immutability, MSR writes and socat, plus ES|QL/OSQuery hunts for cron and SSH-key persistence — [Elastic](https://www.elastic.co/security-labs/outlaw-linux-malware).
- **XLab (CWPdoor):** `ss -axp | grep integrity`, `ps aux | grep cwpsrv` and `strings … | grep X-Ngx-Integrity`. Restore cwpsrv, upgrade, rotate panel credentials, and treat the whole server as compromised — [The Hacker News](https://thehackernews.com/2026/11/hackers-hide-linux-backdoor-in-control.html).
- **ESET (Ebury):** publishes IoCs (malware-ioc repository, windigo folder) and a detection script (malware-research repository, ebury folder) — [ESET](https://www.welivesecurity.com/en/eset-research/ebury-alive-unseen-400k-linux-servers-compromised-cryptotheft-financial-gain/).
- **Sandfly (BPFDoor):** v1 can be caught by its filenames, but v2 dropped /dev/shm, so detection should target tactics rather than IOCs — [Sandfly](https://sandflysecurity.com/blog/bpfdoor-detection-analysis-and-hunting-tactics-on-linux).

### Inferences
- **Response order for "miner + watchdog + cron/systemd + replaced binaries" (the Fusion incident):**
  1. Capture evidence: hash, a copy of /proc/PID/exe, cmdline, environ, maps and sockets.
  2. SIGSTOP every process in the suspicious tree, plus anything with the same exe hash or a deleted exe, and any process that respawned within N seconds. This freezes watchdogs like `upd`, `wizlmsh` and /tmp/bash so they can't restart the miner.
  3. Clear immutable/append flags with the agent's own code, since attackers disable chattr.
  4. Quarantine every persistence point: system and per-user cron, systemd units and timers (system and user), rc.local, shell rc/profile, ld.so.preload, authorized_keys and udev rules.
  5. SIGKILL the frozen set.
  6. Block pool, Tor and C2 egress with nftables or firewalld.
  7. Verify and reinstall tampered packages (`dpkg --verify`/`debsums` plus `apt-get install --reinstall` on Debian/Ubuntu; `rpm -Va` plus `dnf reinstall` on RHEL).
  8. Rotate SSH keys and passwords, because Ebury, Outlaw and P2Pinfect reuse stolen credentials.
  9. If a kernel module or PAM/sshd tampering is found, isolate (keeping only the master channel) and recommend a rebuild.
- **Safe autonomy:** let policy auto-execute steps 1–6 only on high-confidence combinations — e.g. (exe in /tmp, /dev/shm or deleted) AND (pool or Tor egress, or a master-intel hash match). Require one-click Discord approval for destructive steps on package-owned paths (step 7) and for account or SSH changes. Never kill sshd itself or the agent's management channel.
- **Self-protection:**
  - Ship the agent as a static binary that reads /proc and the kernel directly, rather than through libc or system utilities. perfctl, Kinsing, Migo, Koske, P2Pinfect and Auto-color all lie through hooked libc or trojanized ldd/top/lsof.
  - Cross-check the process list from /proc enumeration against `ps` and look for discrepancies.
  - Have the master alert on a missed heartbeat, since TeamTNT uninstalls cloud agents and SysGoRAT targets EDR.
- **Debian vs RHEL:**
  - Auth logs are /var/log/auth.log on Debian/Ubuntu and /var/log/secure on RHEL (Group-IB cites /var/log/secure), or journald on both.
  - MAC is AppArmor on Debian/Ubuntu and SELinux on RHEL. Attackers disable both (TeamTNT, 8220, Pay2Key), so "MAC disabled" is a high-value tamper signal.
  - PAM module directories differ by distro; check both /lib64/security and /usr/lib/x86_64-linux-gnu/security.
- **Baseline:** /etc/ld.so.preload normally doesn't exist on stock Debian/Ubuntu/RHEL servers. Any creation of it should be high severity. This comes from general Linux practice; I found no vendor statistic to confirm it.

### Gaps
- I found no public false-positive rates or benchmarks for these detections on production SMB servers, nor any vendor data on the safety of automated kill/remove actions.
- I found no authoritative source quantifying how often attackers chattr-lock persistence or disable chattr. It is documented in individual cases (Outlaw, Koske, TeamTNT) but has no prevalence statistic.
- Exact mining-pool ports vary per campaign. I found no maintained public list of pool domains and ports from a primary source; the master server would need its own feed.

## Q3. Common initial-access vectors for SMB-hosted Linux servers, with statistics

### Takeaway
Two vectors dominate:
- **Weak SSH credentials.** These still drive commodity botnets: P2PInfect alone was 50–80% of malware installs in AhnLab's SSH honeypots in 2025 and early 2026, and DShield logged 20M+ brute-force attempts in four months of 2026.
- **Exposed or vulnerable services.** Google reports that software exploitation overtook credentials as the top cloud initial-access vector in H2 2025 (44.5% vs 27.2%).

Exploitation is fast:
- Sysdig has tracked cloud attacks going from initial access to impact in ≤10 minutes since 2023.
- Patchstack measured a weighted median of 5 hours from disclosure to mass exploitation of WordPress plugin bugs.
- VulnCheck found about 29% of 2025 KEVs exploited on or before the day the CVE was published.

Exposed data stores are mass-extorted: 46% of exposed DB/admin systems in a 2021–2026 study carried ransom notes.

### Cited Findings

#### Cloud-wide initial access
- Google Cloud Threat Horizons (H1 2026 report, covering H2 2025):
  - Weak or absent credentials fell to 27.2% of initial access, from 47.1% in H1 2025.
  - Software exploitation reached 44.5%, overtaking credentials as the main vector for the first time.
  - Misconfiguration fell to 21% from 29.4%.
  - [Help Net Security](https://www.helpnetsecurity.com/2026/03/11/google-cloud-environments-cyber-threats-report/), [Google Cloud](https://cloud.google.com/security/report/resources/cloud-threat-horizons-report-h1-2026).
- Sysdig has tracked cloud attacks going from initial access to impact in 10 minutes or less since 2023. Its "555" benchmark targets 5 s to detect, 5 min to triage and 5 min to respond — [Sysdig](https://sysdig.com/555-benchmark).
- Exploitation timing (VulnCheck):
  - Full year 2025: 28.96% of the 884 KEVs first exploited that year showed exploitation on or before the day the CVE was published, up from 23.6% in 2024 — [VulnCheck 2026](https://www.vulncheck.com/blog/state-of-exploitation-2026).
  - The H1 2025 figure was 32.1% — [VulnCheck 1H 2025](https://www.vulncheck.com/blog/state-of-exploitation-1h-2025).

#### SSH brute force and credential stuffing
- AhnLab SSH honeypots, share of attack sources that reached malware installation — [AhnLab Q1-25](https://asec.ahnlab.com/en/87357/), [Q2-25](https://asec.ahnlab.com/en/88927/), [Q4-25](https://asec.ahnlab.com/en/92004/), [Q1-26](https://asec.ahnlab.com/en/93336/):

  | Quarter | P2PInfect | Other notable families |
  |---|---|---|
  | Q1 2025 | 56.3% | Tsunami 25.4% |
  | Q2 2025 | 50.0% | Tsunami 38.5% |
  | Q4 2025 | 80.4% | Prometei 8.3%, XMRig 2.4% |
  | Q1 2026 | 70.3% | — |

  AhnLab names weak credentials and unpatched systems as the root causes — [AhnLab Q2-26](https://asec.ahnlab.com/en/94396/).
- A DShield honeypot logged more than 20 million SSH brute-force attempts between Feb and May 2026 — [Aviatrix](https://aviatrix.ai/threat-research-center/behavior-of-coordinated-ssh-brute-force-attacks-2026/).
- Families with SSH brute force as the main entry: Outlaw ([Elastic](https://www.elastic.co/security-labs/outlaw-linux-malware)), Diicot ([Wiz](https://www.wiz.io/blog/diicot-threat-group-malware-campaign)), XorDDoS ([Talos](https://blog.talosintelligence.com/unmasking-the-new-xorddos-controller-and-infrastructure/)), TeamTNT on CentOS 7 VPS ([Group-IB](https://www.group-ib.com/blog/teamtnt/)) and P2Pinfect ([Darktrace](https://www.darktrace.com/blog/from-dormant-to-dangerous-p2pinfect-evolves-to-deploy-new-ransomware-and-cryptominer)). SSH-Snake (via CRYSTALRAY) harvested more than 1,500 credentials for lateral movement — [Sysdig 2024](https://sysdig.com/wp-content/uploads/2024-global-threat-report.pdf).
- Credential reuse at hosting scale: Ebury spreads with stolen credentials, abuses hosting-provider access, and infected an ESET test VPS within 7 days of renting it — [ESET](https://www.welivesecurity.com/en/eset-research/ebury-alive-unseen-400k-linux-servers-compromised-cryptotheft-financial-gain/).

#### Exposed Docker API, Redis and databases
- Docker API: secondary coverage of an older Aqua honeypot study reports 50% of misconfigured Docker APIs attacked within 56 minutes, with bots taking about 5 h on average to find a new honeypot — [Bournemouth CERT digest](https://cert.bournemouth.ac.uk/50-of-misconfigured-containers-hit-by-botnets-in-an-hour/). A UCSB RAID 2023 container-orchestration honeypot drew attackers within minutes of launch — [UCSB paper](https://sites.cs.ucsb.edu/~chris/research/doc/raid23_cohp.pdf). TeamTNT scanned about 16.7M IPs on ports 2375, 2376, 4243 and 4244 — [Aqua](https://www.aquasec.com/blog/threat-alert-teamtnts-docker-gatling-gun-campaign/).
- Redis:
  - Wiz counted about 330,000 internet-exposed Redis instances, about 60,000 without authentication. The official Redis container image doesn't require auth by default.
  - RediShell (CVE-2025-49844, CVSS 10, Oct 2025) is an RCE via Lua that affects Redis ≤8.2.1.
  - [Wiz](https://www.wiz.io/blog/wiz-research-redis-rce-cve-2025-49844), [Help Net Security](https://www.helpnetsecurity.com/2025/10/07/redis-patches-critical-redishell-rce-vulnerability-update-asap-cve-2025-49844/).
  - Campaigns: Migo, P2Pinfect and Skidmap (see Q1).
- Databases: 46.3% of 65,907 exposed MongoDB, MySQL, Elasticsearch, Kibana and admin-panel systems carried ransom or wipe notes. MongoDB was hit on 3,525 of 3,532 instances on the default port — [Security Affairs](https://securityaffairs.com/192711/cyber-crime/the-hidden-ransomware-economy-running-on-exposed-databases.html). Misconfiguration (no auth, unrestricted exposure) remains the main cause even as MongoBleed is exploited — [Rescana](https://www.rescana.com/post/exposed-mongodb-servers-remain-prime-targets-for-automated-data-extortion-attacks-and-vulnerability).

#### Vulnerable PHP / Laravel / WordPress and leaked .env credentials
- Leaked .env files (Unit 42, Aug 2024): an extortion campaign hit 110,000 domains through exposed .env files, exposing more than 90,000 unique variables (about 7,000 cloud and 1,515 social-media). The attackers built a Lambda-based scanner that swept more than 230M endpoints — [Unit 42](https://unit42.paloaltonetworks.com/large-scale-cloud-extortion-operation/), [Security Affairs](https://securityaffairs.com/167180/cyber-crime/extortion-campaign-environment-variable-files.html).
- Androxgh0st scrapes /.env and exploits Laravel CVE-2018-15133. CISA advises keeping production Laravel out of debug mode and removing and revoking cloud credentials in .env — [CISA AA24-016A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-016a).
- Laravel APP_KEY leaks (GitGuardian/Synacktiv, Jul 2025): more than 260,000 APP_KEYs were pulled from GitHub (2018 to May 2025). Over 600 Laravel apps were vulnerable to RCE through decrypt()'s automatic deserialization. Counts differ between reports — [The Hacker News](https://thehackernews.com/2025/07/over-600-laravel-apps-exposed-to-remote.html).
- WordPress (Patchstack's 2026 report on 2025 data):
  - 11,334 new ecosystem vulnerabilities, up 42% from 7,966; 91% in plugins and only 6 in core.
  - A weighted median of 5 hours to first mass exploitation; about 45% of heavily targeted bugs were exploited within 24 h.
  - [Patchstack](https://patchstack.com/whitepaper/state-of-wordpress-security-in-2026/), via secondary coverage ([Search Engine World](https://www.searchengineworld.com/wordpress-security-in-2026-what-the-data-says-and-what-you-must-do)).
- PHP-CGI CVE-2024-4577 was used by RedTail — [AVAR 2024](https://events.aavar.org/avar2024/?p=7036). React2Shell (Dec 2025) was a single-request unauthenticated RCE across Next.js and other React Server Components stacks, used to drop miners and backdoors — [Huntress](https://www.huntress.com/blog/peerblight-linux-backdoor-exploits-react2shell).

#### Vulnerable middleware, DevOps tools and edge services
- Middleware and big-data stacks:
  - RocketMQ CVE-2023-33246 led to perfctl — [Aqua](https://www.aquasec.com/blog/perfctl-a-stealthy-malware-targeting-millions-of-linux-servers/).
  - ActiveMQ CVE-2023-46604 led to Kinsing — [Trend Micro](https://www.trendmicro.com/en_us/research/23/k/cve-2023-46604-exploited-by-kinsing.html).
  - WebLogic n-days led to 8220 — [The Hacker News](https://thehackernews.com/2024/06/8220-gang-exploits-oracle-weblogic.html).
  - Misconfigured Hadoop led to Chaos (2026) — [Help Net Security](https://www.helpnetsecurity.com/2026/04/08/chaos-malware-cloud-misconfigured-servers/).
- DevOps and data-science tools:
  - Misconfigured JupyterLab led to Koske — [Aqua](https://www.aquasec.com/blog/ai-generated-malware-in-panda-image-hides-persistent-linux-threat/).
  - Argo Workflows and Gogs flaws led to the Realm C2 campaign (Jun 2026) — [Wiz](https://threats.wiz.io/all-incidents/cryptojacking-campaign-targeting-k8s-clusters).
- Edge appliances and hosting panels:
  - PAN-OS CVE-2024-3400 and Ivanti Connect Secure CVE-2023-46805/CVE-2024-21887 led to RedTail — [Akamai](https://www.akamai.com/blog/security-research/2024/may/2024-redtail-cryptominer-pan-os-cve-exploit).
  - More than 340,000 Control Web Panel instances are exposed (CWPdoor context) — [SC World](https://www.scworld.com/brief/new-cwpdoor-malware-targets-linux-servers-via-control-web-panel).
- Supply chain and trust:
  - XZ Utils backdoor (Mar 2024) — [Qualys](https://blog.qualys.com/vulnerabilities-threat-research/2024/03/29/xz-utils-sshd-backdoor).
  - Trusted third-party access as the entry point (Group-IB 2026) — [Group-IB](https://www.group-ib.com/blog/xmrig-covert-linux-pam-abuse/).
  - Compromise of a hosting provider's infrastructure (Ebury) — [ESET](https://www.welivesecurity.com/en/eset-research/ebury-alive-unseen-400k-linux-servers-compromised-cryptotheft-financial-gain/).

### Inferences
- For a typical startup or SaaS VPS, the ranking is:
  1. SSH password auth exposed to the internet, which is still the most common commodity entry.
  2. Exposed unauthenticated services: Redis 6379, Docker 2375/2376, MongoDB 27017, Elasticsearch 9200, JupyterLab, Hadoop.
  3. Unpatched web stack (WordPress plugins, Laravel debug/.env/APP_KEY, PHP-CGI, Next.js/React).
  4. Hosting panels and edge appliances.
- The agent should ship an "exposure audit" at install: list 0.0.0.0 listeners on these ports, password-auth status in sshd_config, and world-readable .env files in web roots. This prevents rather than detects, and maps directly to the campaigns above.
- With attack-to-impact under 10 minutes, and WordPress mass exploitation at about 5 h median, containment can't wait for a human reading Discord. Auto-containment for high-confidence signals, with Discord for notification and approval of riskier steps, is justified by the published timelines.
- Google's data shows exploitation overtaking credentials. A product that only does SSH brute-force blocking (fail2ban/CrowdSec-style) addresses the shrinking share of the problem, so process, integrity and egress monitoring are needed for the growing share.

### Gaps
- I found no 2025–2026 primary measurement of SSH honeypot "time to first compromise". AhnLab reports family shares, not elapsed time.
- The Aqua "56 minutes" Docker statistic comes from secondary coverage of an older (likely pre-2022) report. The Unit 42 Docker-honeypot figure (850 attacks over 50 days, about one every 90 minutes) and Uptycs's "compromised within three hours" anecdote appeared in search results without confirmed dates; both are excluded from findings.
- A claim that compromised cloud instances are used for mining "within 22 seconds" of exploitation appeared only in a secondary article attributed to Google and could not be verified.
- No source gave the share of VPS compromises by vector specifically for small hosting customers (as opposed to all cloud).

## Q4. Competitor landscape (concise)

### Takeaway
The market splits into four groups:
- **Hosting-panel suites** (Imunify360, BitNinja, Monarx): cheap per server ($5–$48/month), built around cPanel-style web hosting and web malware.
- **Open-source/DIY tools** (Wazuh, CrowdSec): free, but operationally heavy or limited to the log/IP layer.
- **Agentless Linux EDR** (Sandfly): strong Linux depth, polling-based.
- **Enterprise EDR/CNAPP** (CrowdStrike, SentinelOne, Microsoft, Elastic, Sysdig, Aqua, Uptycs, Upwind): mostly quote-based, priced around $5–$95+ per host per month or $30k+/yr contracts, and aimed at security teams.

None of the sources reviewed shows a product combining:
- a low-RAM agent sized for SMB VPS fleets,
- on-host EDR with integrity monitoring,
- policy-controlled autonomous remediation of miner/persistence chains, and
- native ChatOps (Discord) alerting.

### Cited Findings

**Imunify360 (CloudLinux)**
- **Target:** web hosts and VPS/dedicated owners on cPanel-style servers. Kualo runs it on all its shared servers — [Kualo](https://www.kualo.com/knowledgebase/security-imunify/an-introduction-to-imunify360).
- **Model:** a server-level agent suite with malware scanning and cleanup (real-time, daily, on-demand), a firewall with ML/shared IP reputation, IDPS, and "proactive defence" analysing code execution — [Kualo](https://www.kualo.com/knowledgebase/security-imunify/an-introduction-to-imunify360).
- **Pricing:** per server, by number of hosted accounts:

  | Tier | List $/server/month | Bulk (≥5 servers) |
  |---|---|---|
  | Entry | $12 | $5 |
  | Tier 2 | $25 | $10 |
  | Tier 3 | $35 | $14 |
  | Tier 4 | $45 | $20 |

  The license must cover every account on the server — [Imunify360 pricing](https://imunify360.com/pricing/). ImunifyAV+ rose $1 to $7 per server per month from 1 Jan 2026 — [Imunify blog](https://blog.imunify360.com/imunifyav-pricing-update-changes-effective-in-2026).
- **Gap:** licensing and dashboards are panel- and hosting-account-centric (cPanel); nothing found on autonomous host-EDR remediation or ChatOps.

**BitNinja**
- **Target:** hosting providers and server owners.
- **Model:** per-server agent with port and web honeypots, IP reputation and greylisting, WAF, AI malware scanner, DoS mitigation and CAPTCHA — [Software Advice](https://www.softwareadvice.com/ddos-protection/bitninja-profile/), [FitGap](https://us.fitgap.com/products/019391/bitninja).
- **Pricing:** per server by hosted users. The official page lists no figures; third-party figures conflict ($6–$48/month, plus a free tier for 0–1 user on ≤2 vCPU/2 GB) — [BitNinja pricing](https://bitninja.com/pricing/), [FitGap](https://us.fitgap.com/products/019391/bitninja).
- **Gap:** web and network attack focus; not a process/persistence EDR.

**Sandfly Security**
- **Target:** critical infrastructure, telecom (shipped in Ericsson's XDR), cloud (DigitalOcean), air-gapped networks — [Sandfly](https://sandflysecurity.com/).
- **Model:** agentless; it only needs SSH on the hosts — [Sandfly pricing](https://sandflysecurity.com/pricing/). It detects stolen SSH credentials, lateral movement, weak passwords and drift, from cloud to embedded devices — [Sandfly](https://sandflysecurity.com/).
- **Pricing:** 10 hosts for $99/yr on the home tier. Professional plans start at 10 hosts and Enterprise is quote-based — [Sandfly pricing](https://sandflysecurity.com/pricing/), [DigitalOcean brief](https://sandflysecurity.com/sharing/Sandfly-Solution-Brief-Digital-Ocean.pdf).
- **Gap:** polling is not real-time process control; the response capabilities aren't documented on the pages reviewed.

**Wazuh**
- **Target:** cost-sensitive teams that self-host a SIEM/XDR.
- **Model:** open-source agent plus server. Capabilities include file integrity monitoring, rootkit behavior detection, and Active Response (block SSH brute force, disable a user, remove a malicious file) — [Wazuh docs](https://documentation.wazuh.com/current/user-manual/capabilities/index.html).
- **Pricing:** open source is free. Wazuh Cloud is quote-based; third-party estimates start around $571/month — [CostBench](https://costbench.com/software/siem/wazuh/).
- **Gap:** heavy to operate and tune. Users report agent memory growth, e.g. above 50 MB in a 2021 Windows thread — [Wazuh group](https://groups.google.com/g/wazuh/c/0mgj1yY60x0). Responses are DIY scripts.

**CrowdSec**
- **Target:** sysadmins and hosts wanting crowd-sourced IP blocking.
- **Model:** an open-source Security Engine parses logs into scenarios; remediation components ("bouncers") block at the firewall or reverse proxy; a community blocklist is shared via the Central API — [CrowdSec docs](https://docs.crowdsec.net/docs/concepts).
- **Pricing:** free Community plan. Paid plans are priced by number of Security Engines, and Enterprise adds premium remediation and full blocklist update frequency — [CrowdSec pricing](https://www.crowdsec.net/pricing), [CrowdSec console docs](https://docs.crowdsec.net/u/console/premium_upgrade). Third-party figures: $29 per extra engine slot; blocklist-as-a-service from $900/month — [FitGap](https://us.fitgap.com/products/019297/crowdsec).
- **Gap:** stops IPs, not on-host malware, persistence or rootkits.

**Monarx**
- **Target:** web hosts selling website-security add-ons — [InMotion/PR Newswire](https://prnewswire.com/news-releases/inmotion-hosting-elevates-server-security-with-monarx-partnership-302307928.html).
- **Pricing:** sold through hosts; Monarx's own pricing is contact-sales. Host retail prices: Hostek $19.99/month per site; Prostack from £15.84/month — [Hostek](https://blog.hostek.com/?p=196), [Prostack](https://prostack.uk/portal/index.php?m=monarx), [Monarx pricing](https://www.monarx.com/pricing).
- **Market signal:** Monarx's own review of 65 hosts found 37 bundle website protection at no extra cost — [webhosting.today](https://webhosting.today/2026/11/05/monarx-reviewed-65-hosts-10-of-12-large-hosting-brands-sell-website-security-add-ons/).
- **Gap:** web/PHP layer only.

**CrowdStrike Falcon for Linux / Falcon Cloud Security**
- **Model:** the Linux sensor runs in kernel mode (a module) or user mode (eBPF), and can choose automatically — [Red Hat catalog](https://catalog.redhat.com/en/software/applications/detail/114205). A third-party guide says sensor 7.30 (Oct 2025) removed the option to force kernel mode where user mode works — [TechnologyMatch](https://technologymatch.com/blog/extending-edr-to-linux-servers). Unsupported kernels drop into Reduced Functionality Mode — [Duke OIT](https://oit.duke.edu/help/articles/kb0035319/).
- **Pricing:** quote-based, per cloud workload. An AWS Marketplace reviewer calls it high for smaller organizations — [AWS Marketplace](https://aws.amazon.com/marketplace/pp/prodview-ulqav6trzgy76).
- **Gap:** enterprise sales motion, and a kernel-compatibility matrix that matters on mixed VPS kernels.

**SentinelOne Singularity Cloud Workload Security**
- **Model:** a Linux agent re-architected on eBPF, with no kernel modules — [AWS APN blog](https://aws.amazon.com/blogs/apn/enhancing-amazon-eks-security-with-sentinelones-real-time-ebpf-protection-on-aws). The Complete Cloud Workload bundle cites support for 15 Linux distros — [AppDirect](https://catalog.appdirect.com/en-US/apps/449075/sentinelone-complete-cloud-workload/features).
- **Pricing:** not public, sold via partners. Third-party endpoint prices run $69.99 (Core) to $209.99 (Commercial) per endpoint per year — [Vertice](https://vertice.one/vendors/sentinelone), [SentinelOne pricing](https://www.sentinelone.com/de/pricing/).
- **Gap:** enterprise focus.

**Microsoft Defender for Endpoint on Linux / Defender for Servers**
- **Model:** agent. The eBPF sensor is the supplementary event provider and falls back to Netlink; AuditD support ended with version 101.2408.0000. Microsoft claims under 1% average CPU — [Microsoft Learn](https://learn.microsoft.com/en-us/defender-endpoint/linux-support-ebpf).
- **Pricing:** about $5 per server per month for Plan 1 and about $15 for Plan 2 (third-party; verify with the Azure calculator) — [apis.io](https://apis.io/plans/microsoft-defender/microsoft-defender-plans-pricing/), [Azure pricing page](https://azure.microsoft.com/en-us/pricing/details/defender-for-cloud/). Plan 2 adds vulnerability assessment and agentless scanning — [Cloudaware](https://ce.prod.cloudaware.com/ce/ca/azure/subscription/microsoft-defender-for-servers/description/).
- **Gap:** tied to the Microsoft security stack and portal.

**Elastic Defend (Elastic Security)**
- **Model:** Linux protection built on eBPF — [Elastic XDR page](https://www.elastic.co/kr/security/xdr). Elastic publishes Linux detection rules such as those cited for Outlaw — [Elastic Security Labs](https://www.elastic.co/security-labs/outlaw-linux-malware).
- **Pricing:** in Mar 2026 Elastic said it eliminated per-endpoint pricing for Elastic Security XDR — [Nasdaq press release](https://www.nasdaq.com/press-release/elastic-eliminates-endpoint-pricing-xdr-2026-03-23). Its serverless docs still describe billing per protected endpoint — [Elastic docs](https://www.elastic.co/guide/en/serverless/main/security-billing.html). The two conflict.
- **Gap:** requires running or buying the Elastic stack.

**Sysdig Secure**
- **Model:** licensed per host — [Sysdig pricing](https://sysdig.com/pricing-secure/). It promotes the 555 benchmark for cloud detection and response — [Sysdig](https://sysdig.com/555-benchmark).
- **Pricing:** CNAPP Enterprise on AWS Marketplace is $0.13 per host-hour, about $95 per host per month if the host runs continuously — [AWS Marketplace](https://aws.amazon.com/marketplace/pp/prodview-of3ndsfqn2cwc), [CubeAPM review](https://cubeapm.com/blog/sysdig-pricing-review/).
- **Gap:** price point and container/Kubernetes-first positioning.

**Aqua Security**
- **Model:** a CNAPP whose eBPF "Lightning Enforcer" deploys on hosts or clusters and is built on the open-source Tracee eBPF engine. Aqua claims 65% less load than a non-eBPF agent (vendor-reported) — [Aqua blog](https://www.aquasec.com/blog/combat-zero-day-threats-with-aquas-ebpf-lightning-enforcer/), [Tracee](https://aquasec.com/products/tracee).
- **Pricing:** not found. Aqua's own Nautilus research is a major source on Linux threats (see Q1).

**Uptycs**
- **Model:** agentless discovery and scanning plus an optional eBPF sensor for runtime detection and response — [Uptycs CWPP](https://www.uptycs.com/cwpp). The sensor filters and deduplicates in-kernel and supports ARM64, POWER and s390x — [Uptycs eBPF guide](https://www.uptycs.com/hubfs/eBFP_Capabilities_Guide.pdf?hsLang=en).
- **Pricing:** not public; volume discounts are advertised.

**Upwind**
- **Model:** a runtime-first CNAPP — agentless scanning plus an eBPF sensor, sold as a single SKU — [HackerNoon comparison](https://hackernoon.com/upwind-vs-wiz-comparing-pricing-runtime-security-and-ai-protection).
- **Pricing:** a sample AWS Marketplace listing shows $30,000 for 12 months (full CNAPP); sales are mainly annual contracts — [HackerNoon comparison](https://hackernoon.com/upwind-vs-wiz-comparing-pricing-runtime-security-and-ai-protection), [rfp.wiki](https://www.rfp.wiki/vendors/upwind).
- **Gap:** enterprise contract minimums.

### Inferences
- **Price gap:** SMB VPS owners pay $5–$20/month for a $5–$40 VPS. Enterprise CWPP (quote-based, about $95/host/month on Sysdig's marketplace listing, $30k/yr Upwind sample) is out of reach. The hosting suites are affordable but panel- and web-centric. A $2–$8 per server per month EDR with fleet bundles would sit in open space.
- **ChatOps gap:** none of the reviewed sources describes native Discord alerting or approval workflows. Wazuh, CrowdSec and Sandfly integrate via webhooks/SIEM per their docs, but approve/deny from chat was not found.
- **Safe-autonomy gap:**
  - Wazuh's Active Response is script-based DIY.
  - CrowdSec blocks IPs only.
  - Imunify360 and BitNinja auto-clean web malware but don't unwind cron/systemd/preload/PAM chains.
  - Sandfly is agentless.
  - A policy engine that freezes miner trees, removes persistence and restores package-owned binaries, with approval tiers, is a clear differentiator. It is grounded in the real campaigns in Q1/Q2.
- **Lightweight agent:** the enterprise agents trend toward eBPF (CrowdStrike user mode, SentinelOne, Microsoft, Elastic, Aqua, Uptycs, Upwind). eBPF is table stakes for a low-overhead design. Debian and RHEL support alone won't differentiate, since all the large vendors support both. The differentiators would be memory footprint on 1 GB VPSs, no kernel module, and fallback behavior on old VPS kernels.

### Gaps
- No public pricing was found for CrowdStrike, SentinelOne Cloud Workload Security, Aqua or Uptycs. Imunify360's tier user-counts were not fully confirmed (the pricing page returned 403), and BitNinja's figures conflict across aggregators.
- No vendor-published RAM footprints were found for most agents. Microsoft gives only a CPU claim; Wazuh data is anecdotal.
- Each vendor's Discord, Slack or webhook integration support was not verified product by product. The ChatOps gap is inferred from the absence of evidence, not confirmed.
- No independent reviews comparing these products on SMB VPS fleets were found.
