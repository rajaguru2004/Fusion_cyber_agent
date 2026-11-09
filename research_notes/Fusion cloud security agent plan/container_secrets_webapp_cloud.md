# Container, Secrets, Web-App and Cloud Modules for the Fusion Linux Security Agent

Research date: 2026-11-09. License, archive status, star counts and last-push dates come from the GitHub REST API and raw LICENSE/README files fetched that day. "Known exploited" status comes from the CISA KEV JSON feed, catalog version 2026.11.06 (1,769 entries). Distro package versions come from sources.debian.org and Fedora mdapi (Rawhide, F43, EPEL9, EPEL10) on the same day. Where a fact comes only from secondary coverage, the bullet says so.

## 1. Docker host and container posture: benchmarks and linters, detecting risky container configs, hardening modes (rootless, userns-remap, no-new-privileges), reading Docker/containerd/Podman state safely, and mapping host PIDs/cgroups to containers

### Takeaway
Docker Bench, Dockle and Hadolint are useful references but weak foundations to build on. Docker Bench is a shell script pinned to CIS Docker Benchmark v1.6.0, two versions behind the current v1.8.0. Dockle's license is ambiguous. Hadolint is GPL-3.0 and lints Dockerfiles, which is a CI-time job. The agent should run its own posture checks in Go against the Engine API (`inspect` fields) with a hard-coded allowlist of read-only endpoints. On RHEL it must treat Podman (rootful and per-user rootless) as a separate engine with its own sockets, journald events and `libpod-<id>` cgroups.

### Cited Findings

**Posture tools: license, status and packaging**

| Tool | What it does | License | Status (2026-11-09) | Distro packages | Source |
|---|---|---|---|---|---|
| Docker Bench for Security | Shell script checking a host and its containers against CIS Docker Benchmark **v1.6.0**; checks named `check_<section>_<number>`, community checks `check_c_<n>` | Apache-2.0 (LICENSE.md) | README says the `docker/docker-bench-security` image is out of date and must be built manually (issue #405) | Not in Debian or Fedora/EPEL | [repo README](https://github.com/docker/docker-bench-security); [Debian API](https://sources.debian.org/api/src/docker-bench-security/); [Fedora mdapi](https://mdapi.fedoraproject.org/f43/srcpkg/docker-bench-security) |
| Dockle | Container image linter ("Container Image Linter for Security"); its checkpoints include CIS Benchmarks | **Conflicting:** the LICENSE file at HEAD is Apache-2.0, but the README carries a "License: AGPL v3" badge | Active | Not in Debian or Fedora/EPEL | [goodwithtech/dockle](https://github.com/goodwithtech/dockle) |
| Hadolint | Dockerfile linter | GPL-3.0 | Active | Fedora 2.12.0 (F43), 2.15.1 (Rawhide); not in Debian | [hadolint/hadolint](https://github.com/hadolint/hadolint); [Fedora mdapi](https://mdapi.fedoraproject.org/rawhide/srcpkg/hadolint) |
| Falco rules (reference logic) | Runtime rules with stable, incubating and sandbox maturity | Apache-2.0 | 9.5k stars, pushed 2026-11-09 | Upstream ships .deb/.rpm with systemd setup and a choice of `kmod` or `modern_ebpf` driver; not in Debian or Fedora repos | [falcosecurity/falco](https://github.com/falcosecurity/falco); [falcosecurity/rules](https://github.com/falcosecurity/rules); [Falco DEB/RPM install](https://falco.org/docs/setup/packages/) |
| Tracee / Tetragon (eBPF alternatives) | Runtime security and forensics using eBPF | Apache-2.0 / Apache-2.0 | Tracee pushed 2026-11-01 | n/a | [aquasecurity/tracee](https://github.com/aquasecurity/tracee); [cilium/tetragon](https://github.com/cilium/tetragon) |

- The Docker Bench container mode "is being run with a *lot* of privilege -- sharing the host's filesystem, pid and network namespaces" — [docker-bench-security README](https://github.com/docker/docker-bench-security)
- CIS published Docker Benchmark **v1.8.0** in its August 2025 update, adding support for Docker Server v28. v1.7.0 was published in August 2024. The CIS Docker page lists 1.8.0 as current. A November 2026 CIS update had no Docker entry — [CIS August 2025 update](https://www.cisecurity.org/insights/blog/cis-benchmarks-august-2025-update); [CIS Docker Benchmark page](https://www.cisecurity.org/benchmark/docker); [CIS August 2024 update](https://www.cisecurity.org/blog/cis-benchmarks-august-2024-update); [CIS November 2026 update](https://www.cisecurity.org/insights/blog/cis-benchmarks-november-2026-update)
- Docker Bench still ships check 4.5, "Ensure Content trust for Docker is Enabled" — [README](https://github.com/docker/docker-bench-security). Docker Content Trust is being retired (see Q4), so that check is obsolete.

**Docker's own statements on its attack surface and hardening**
- "only trusted users should be allowed to control your Docker daemon." A container given the host's `/` "can alter your host filesystem without any restriction." "Exposing the daemon API over HTTP without TLS is not permitted." Containers start "with a restricted set of capabilities". User namespaces are "available but not enabled by default" — [Docker Engine security](https://docs.docker.com/engine/security/)
- "The `docker` group grants root-level privileges to the user." — [Linux post-installation steps](https://docs.docker.com/engine/install/linux-postinstall/)
- Rootless mode runs both the daemon and the containers as a non-root user, and "does not require root privileges even during the installation". The docs contrast it with `userns-remap`, where "the daemon itself is running with root privileges". Rootless needs at least 65,536 subordinate IDs per user in `/etc/subuid` and `/etc/subgid` — [Rootless mode](https://docs.docker.com/engine/security/rootless/); [userns-remap](https://docs.docker.com/engine/security/userns-remap/)
- Engine v29 makes the containerd image store the default on fresh installs; upgraded hosts are not switched automatically. The launch blog says the minimum API version was raised to 1.44. The v29 release notes, at 29.4.1, say it was lowered back to 1.40 (Docker 19.03, moby#52067). The notes run to 29.9.2, dated 2026-10-20 — [Docker Engine v29 blog](https://www.docker.com/blog/docker-engine-version-29/); [Engine 29 release notes](https://docs.docker.com/engine/release-notes/29/)
- Firewall caveat in Docker's Debian and Ubuntu install docs: "If you use ufw or firewalld… when you expose container ports using Docker, these ports bypass your firewall rules." Docker "is only compatible with `iptables-nft` and `iptables-legacy`", and rules created with `nft` are not supported on a Docker host — [Install on Debian](https://docs.docker.com/engine/install/debian/); [Install on Ubuntu](https://docs.docker.com/engine/install/ubuntu/)

**Docker vs Podman on Debian and RHEL-family hosts**
- Docker CE install docs list as supported: RHEL 8, 9 and 10; Fedora 43, 44 and 45; Debian 13 "Trixie" and 12 "Bookworm"; Ubuntu 26.10, 26.04 LTS, 24.04 LTS and 22.04 LTS. They require removing conflicting packages first, which includes `podman` on RHEL and `podman-docker` on Debian and Ubuntu — [RHEL](https://docs.docker.com/engine/install/rhel/); [Fedora](https://docs.docker.com/engine/install/fedora/); [Debian](https://docs.docker.com/engine/install/debian/); [Ubuntu](https://docs.docker.com/engine/install/ubuntu/)
- Red Hat removed the Docker engine and `docker` command from RHEL 8 and 9. Docker from upstream projects "is unsupported" on RHEL. The `podman-docker` package redirects `docker` commands to Podman and links `/var/run/docker.sock` to `/var/run/podman/podman.sock`. The RHEL 10 docs say Podman supports the Docker socket API — [RHEL 9: Starting with containers](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/building_running_and_managing_containers/assembly_starting-with-containers_building-running-and-managing-containers); [RHEL 10: Introduction to containers](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/building_running_and_managing_containers/introduction-to-containers)
- An undated Podman mailing-list post quotes Red Hat support as saying rootless Podman is supported only when accessed by ssh-ing in as that user. Treat it as possibly stale — [lists.podman.io thread](https://lists.podman.io/archives/list/podman@lists.podman.io/thread/IF55JKXTKLIFH5MQ2OVFRBOGELLC62TL/)
- Podman's REST API (`podman system service`) has two layers: a "compatibility layer offering support for the Docker v1.40 API" and a native Libpod layer. It supports systemd socket activation, including a per-user unit at `/usr/lib/systemd/user/podman.socket` — [podman-system-service(1)](https://docs.podman.io/en/latest/markdown/podman-system-service.1.html)
- Podman events go to **journald** by default. `events_logger` in containers.conf can switch them to `file` or `none`. Setting `events_container_create_inspect_data=true` adds a JSON inspect payload to container-create events — [podman-events(1)](https://docs.podman.io/en/latest/markdown/podman-events.1.html)
- Quadlet (systemd-managed Podman containers) reads unit files from `/etc/containers/systemd/`, `/usr/share/containers/systemd/`, `~/.config/containers/systemd/` and `/etc/containers/systemd/users/${UID}` — [podman-systemd.unit(5)](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)
- Distro versions on 2026-11-09:
  - Fedora/EPEL: podman 5.8.9 (F43) and 6.2.0~rc1 (Rawhide); runc 1.5.2 (F43/Rawhide) and 1.5.1 (EPEL10); crun 1.30.1; containerd 2.2.10 (F43/EPEL9), 2.2.5 (EPEL10) and 2.4.2 (Rawhide); criu 4.3 (Fedora only).
  - Debian: podman in trixie, forky and sid; runc, crun, containerd and criu in bookworm and trixie.
  - Sources: [Fedora mdapi podman](https://mdapi.fedoraproject.org/rawhide/srcpkg/podman); [Fedora mdapi runc](https://mdapi.fedoraproject.org/f43/srcpkg/runc); [Debian podman](https://sources.debian.org/api/src/podman/); [Debian containerd](https://sources.debian.org/api/src/containerd/)

**Risky-config detection logic in Falco rules (portable, Apache-2.0)**
- Incubating: "Launch Privileged Container" and "Launch Excessively Capable Container" (audit-style rules with trusted-image exemptions). Sandbox: "Launch Sensitive Mount Container", "Container Run as Root User", "Privileged Container Device Access" and "Container Access to Host Sensitive Paths" (`/host`, `/rootfs`, `/hostfs`) — [falco-incubating_rules.yaml](https://github.com/falcosecurity/rules/blob/main/rules/falco-incubating_rules.yaml); [falco-sandbox_rules.yaml](https://github.com/falcosecurity/rules/blob/main/rules/falco-sandbox_rules.yaml)
- The `sensitive_mount` macro treats these mount destinations as sensitive: `/proc*`, `/var/run/docker.sock`, `/var/run/crio/crio.sock`, `/run/containerd/containerd.sock`, `/var/lib/kubelet`, `/var/lib/kubelet/pki`, `/`, `/home/admin` and `/etc` — [falco-sandbox_rules.yaml](https://github.com/falcosecurity/rules/blob/main/rules/falco-sandbox_rules.yaml)

**Reading state safely**
- Tecnativa's docker-socket-proxy: "Giving access to your Docker socket could mean giving root access to your host." The proxy returns HTTP 403 for dangerous API sections. With `POST` disabled, only `GET` and `HEAD` are allowed, which makes the API read-only — [Tecnativa/docker-socket-proxy](https://github.com/Tecnativa/docker-socket-proxy)
- `docker events` streams real-time events with `--since` and filters. For historical queries, "Only the last 256 log events are returned" — [docker system events](https://docs.docker.com/reference/cli/docker/system/events/)

**Mapping host PIDs and cgroups to containers**
- On cgroup v2 with the systemd driver, Docker container cgroups live at `/sys/fs/cgroup/system.slice/docker-<id>.scope/`. The cgroupfs driver uses `/sys/fs/cgroup/docker/<id>/`. Inside a container with a private cgroup namespace, `/proc/self/cgroup` shows only `0::/`; `/proc/self/mountinfo` is the usual fallback — [Docker forums answer](https://forums.docker.com/t/how-to-get-container-id-from-within-the-container-with-cgroup-v2/134752/2); [runc systemd cgroup driver doc](https://github.com/opencontainers/runc/blob/main/docs/systemd.md)
- Podman names container cgroups `libpod-<id>` under the container's cgroup parent, and uses `libpod-payload-<id>` in one mode — [podman libpod/container_internal_linux.go](https://github.com/containers/podman/blob/main/libpod/container_internal_linux.go)
- Rootless Podman containers also see `0::/` in `/proc/self/cgroup` — [lists.podman.io thread](https://lists.podman.io/archives/list/podman@lists.podman.io/thread/SU6MZNN7X7P62HE6CSMKH425DE5EFPOK)

### Inferences
- **Build posture checks natively. Don't embed the tools.** For each container, read `GET /containers/json` and `GET /containers/{id}/json`. Flag:
  - `HostConfig.Privileged`, `CapAdd` (especially SYS_ADMIN, SYS_PTRACE, SYS_MODULE, NET_ADMIN, DAC_READ_SEARCH) and `Devices`
  - `SecurityOpt` containing `seccomp=unconfined`, `apparmor=unconfined` or `label=disable`, or missing `no-new-privileges`
  - `NetworkMode=host`, `PidMode=host`, `IpcMode=host`, `UsernsMode=host` and `CgroupnsMode=host`
  - `Mounts` whose source is `/`, `/var/run/docker.sock`, `/run/podman/podman.sock`, `/proc`, `/etc`, `/root` or `/var/lib/docker`
  - `Config.User` empty or 0, `ReadonlyRootfs=false`, and published ports bound to 0.0.0.0, which Docker says bypass ufw/firewalld
  - The same check ids should run against Podman's compat API.
- Run Docker Bench (Apache-2.0) as an optional on-demand audit plugin and map its output to the agent's own check IDs. Re-validate against CIS v1.8.0, because the script targets v1.6.0. Before shipping CIS text or IDs commercially, check CIS licensing (see Gaps).
- Keep Hadolint (GPL-3.0) and Dockle (license unclear) out of the agent binary. Dockerfile linting belongs in customer CI. If needed, run them as separate unmodified executables after legal review. Trivy's misconfiguration scanner (Apache-2.0, Q4) covers similar ground.
- **Socket safety.**
  - The agent already runs as root on the host. Have it dial the Unix socket directly and never proxy or re-expose it, whether over TCP, into a container, or to the master server.
  - Wrap the client in a per-method, per-path allowlist, the same model as docker-socket-proxy. In monitor mode allow only `GET`/`HEAD` plus the `/events` stream. Enable response endpoints (`/pause`, `/networks/*/disconnect`, `/checkpoints`) only under policy.
  - Negotiate the API version; the Docker SDK can do this. A floor of 1.40 covers Docker 19.03+ and Podman's compat layer.
- Never offer a "monitoring container" that bind-mounts `docker.sock`. It is exactly the configuration attackers abuse (Q2) and that Falco's `sensitive_mount` flags.
- **RHEL design points:**
  - Expect Podman (often rootless), sometimes alongside Docker CE.
  - Discover rootful engines at `/run/podman/podman.sock` and `/var/run/docker.sock`. Discover rootless engines by enumerating `/run/user/<uid>/podman/podman.sock` and `/run/user/<uid>/docker.sock` for users with lingering enabled.
  - Read Podman events from journald, since there is no daemon to stream from.
  - Parse Quadlet `.container` files under the listed paths to understand restart behaviour.
- **PID to container mapping:** read `/proc/<pid>/cgroup` from the host namespace and match these patterns:
  - `docker-<64hex>.scope` and `/docker/<64hex>` for Docker
  - `libpod-<64hex>(.scope)` for Podman, under `machine.slice` when rootful and the user's `user@<uid>.service` subtree when rootless
  - `cri-containerd-<id>.scope` for Kubernetes
  - Also compare `/proc/<pid>/ns/{pid,mnt,net}` inode numbers with PID 1's. That catches processes isolated by hand (`unshare`, `runc run` launched by an attacker) that no engine knows about.
- The 256-event replay cap means the events stream cannot be the only source of truth. After every reconnect, resync from a full container list.

### Gaps
- I couldn't confirm whether Dockle is currently Apache-2.0 or AGPL-3.0. The repo shows both, and I found no relicensing note; the GitHub API was rate-limited for this repo.
- CIS Benchmark licensing for commercial products (reusing benchmark IDs or text in a paid agent) was not researched. CIS typically licenses vendor use through SecureSuite, but this was not verified.
- I found no official Red Hat statement in this pass on whether a per-user rootless Podman socket accessed by a root agent is supported.
- Amazon Linux 2023's Docker packaging, and whether runc or crun is the default Podman runtime on each RHEL minor release, were not verified.

## 2. Runtime container attacks and escapes and how to detect them: exposed Docker API abuse, docker.sock abuse, privileged container plus host mount plus chroot, runc CVE-2024-21626 and later runc/containerd escapes, cgroup release_agent, nsenter, and the telemetry/rules that catch each

### Takeaway
The dominant real-world container attack on VPS hosts is still a Docker API exposed to the internet. The pattern is to create a container that bind-mounts host `/` or `docker.sock`, `chroot` into the host, then drop a miner and persistence. TeamTNT, Commando Cat, Kinsing and several 2025 botnets all follow it. Runtime escape CVEs keep coming: runc CVE-2024-21626, the November 2025 runc trio, and the low-severity CVE-2026-41579. None of the runc or containerd bugs is in CISA KEV, but the cgroup v1 `release_agent` escape (CVE-2022-0492) was added in June 2026. Detection needs both container-config telemetry from engine events and syscall/exec telemetry from eBPF, using Falco-style rules.

### Cited Findings

**Exposed Docker API campaigns**
- **TeamTNT "Docker Gatling Gun"** (Aqua, October 2024): gains access through exposed Docker daemons on ports **2375, 2376, 4243 and 4244**. It hosted malware on a compromised Docker Hub account (`nmlm99`), switched its backdoor from Tsunami to Sliver, enrolled victims into a Docker Swarm and rented out their compute — [Aqua: Docker Gatling Gun](https://www.aquasec.com/blog/threat-alert-teamtnts-docker-gatling-gun-campaign/); [The Hacker News](https://thehackernews.com/2024/10/notorious-hacker-group-teamtnt-launches.html)
- **Commando Cat** (Trend Micro, June 2024; Cado documented it first): deploys benign-looking containers built with the public Commando project. It uses the `cmd.cat/chattr` image, `chroot`s into the host and bind-mounts `/var/run/docker.sock`. It then fetches a shell script that downloads a Monero miner. Trend's hunting guidance is to look for container-create events referencing `cmd.cat` — [Trend Micro](https://www.trendmicro.com/en_us/research/24/f/commando-cat-a-novel-cryptojacking-attack-.html); [The Hacker News](https://thehackernews.com/2024/06/commando-cat-cryptojacking-attacks.html)
- **2025 campaigns:**
  - Trend Micro (June 2025): exposed Docker APIs used to drop XMRig via Tor-hidden infrastructure — [The Hacker News, Sept 2025](https://thehackernews.com/2025/09/tor-based-cryptojacking-attack-expands.html)
  - Akamai (Sept 2025): a variant locks other attackers out of the compromised Docker API, removes rival containers and scans for more exposed APIs — [Akamai](https://www.akamai.com/blog/security-research/new-malware-targeting-docker-apis-akamai-hunt)
  - Kaspersky: a Dero miner spreading through exposed container environments on TCP 2375 — [Kaspersky](https://www.kaspersky.com/about/press-releases/kaspersky-uncovers-dero-crypto-miner-spreading-via-exposed-container-environments)
- Kinsing-era activity (Aqua, 2020): thousands of daily attempts against misconfigured Docker daemon API ports — [Dark Reading](https://www.darkreading.com/attacks-breaches/misconfigured-containers-again-targeted-by-cryptominer-malware/d/d-id/1337492)
- A search for a *new* exposed-Docker-API campaign dated 2026 found none. The reporting found runs to late 2025 (search on 2026-11-09).

**Escape CVEs**
- **CVE-2024-21626 "Leaky Vessels"** (runc `process.cwd` and leaked file descriptors): a malicious image `WORKDIR` such as `/proc/self/fd/<n>` gives the container access to the host filesystem. It is fixed in runc 1.1.12. The other three Leaky Vessels CVEs affect BuildKit at build time. Snyk published an eBPF dynamic detector, which covers only the WORKDIR runtime case, fires only during container init and assumes containerd, plus a static Dockerfile detector — [Snyk advisory](https://snyk.io/blog/cve-2024-21626-runc-process-cwd-container-breakout/); [snyk/leaky-vessels-dynamic-detector](https://github.com/snyk/leaky-vessels-dynamic-detector)
- **November 2025 runc trio**, disclosed by Aleksa Sarai on 2025-11-05:
  - CVE-2025-31133: masked-paths race (rated 7.3)
  - CVE-2025-52565: `/dev/console` bind-mount redirection
  - CVE-2025-52881: arbitrary write gadgets and procfs write redirects; also needed updates to the SELinux package
  - Fixed in runc **1.2.8, 1.3.3 and 1.4.0-rc.3**. Coverage describes the trio as container escape to host root, and Red Hat shipped runc updates.
  - Sources: [oss-security disclosure](https://www.openwall.com/lists/oss-security/2025/11/05/3); [Sysdig](https://sysdig.com/blog/runc-container-escape-vulnerabilities); [Orca](https://orca.security/resources/blog/new-runc-vulnerabilities-allow-container-escape/)
- **CVE-2026-41579 (runc, 2026):** an image whose `/dev` is a symlink can make runc delete or create `ptmx` files outside the rootfs. Red Hat's preliminary score is 3.6. Fixes are in runc **1.3.6, 1.4.3 and 1.5.0**. Higher-level runtimes such as Podman and containerd do not guard against it themselves, so their users are exposed through a malicious image. No in-the-wild exploitation was found — [Red Hat CVE page](https://access.redhat.com/security/cve/CVE-2026-41579); [SentinelOne](https://www.sentinelone.com/vulnerability-database/cve-2026-41579/)
- containerd CVE-2026-46680, a Kubernetes `runAsNonRoot` bypass via large numeric User values, is reported by a single aggregator. It is a privilege issue, not a host escape. Unverified — [craftedsignal feed](https://feed.craftedsignal.io/tags/containerd/)
- **CISA KEV (catalog 2026.11.06):**
  - No runc, containerd, Moby/Docker Engine, Podman or CRI-O entries. The only container-runtime entry is Docker Desktop CVE-2019-15752, added 2021-11-03.
  - **CVE-2022-0492** (Linux kernel, "privilege escalation via the cgroups v1 release_agent feature") was **added 2026-06-02**.
  - Other Linux kernel entries added in 2026 (KEV titles only; impact details not checked): CVE-2018-14634 (2026-01-26), CVE-2026-31431 (2026-05-01), CVE-2022-0995 (2026-08-26), CVE-2026-53362 (2026-08-27), CVE-2026-53266, CVE-2025-39964 and CVE-2025-39682 (2026-09-18), and CVE-2026-46300 (2026-10-28). Sudo CVE-2025-32463 was added 2025-09-29.
  - Sources: [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog); [KEV JSON feed](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json)
- Patched runtime versions in distros on 2026-11-09: runc 1.5.2 (Fedora 43), 1.5.1 (EPEL10) — [Fedora mdapi runc](https://mdapi.fedoraproject.org/f43/srcpkg/runc)

**Falco rules mapped to each technique** (rule names and tags from the falcosecurity/rules files on 2026-11-09)

| Technique | Falco rule (maturity) | Source |
|---|---|---|
| cgroup `release_agent` escape | "Detect release_agent File Container Escapes" (stable, T1611): a container with certain capabilities modifies `release_agent` to escape | [falco_rules.yaml](https://github.com/falcosecurity/rules/blob/main/rules/falco_rules.yaml) |
| `nsenter --target 1` / setns | "Change thread namespace" (incubating): the desc names `nsenter --target 1`; needs profiling | [falco-incubating_rules.yaml](https://github.com/falcosecurity/rules/blob/main/rules/falco-incubating_rules.yaml) |
| unshare-based privilege change | "Change namespace privileges via unshare" (incubating, T1611) | same |
| Mounting host disks from a privileged container | "Mount Launched in Privileged Container" (incubating); "Debugfs Launched in Privileged Container" (stable) | incubating and stable files |
| Privileged or over-capable launch | "Launch Privileged Container", "Launch Excessively Capable Container" (incubating) | incubating file |
| Host path / docker.sock mounts | "Launch Sensitive Mount Container", "Container Access to Host Sensitive Paths" (sandbox) | [falco-sandbox_rules.yaml](https://github.com/falcosecurity/rules/blob/main/rules/falco-sandbox_rules.yaml) |
| Payload drop and exec | "Drop and execute new binary in container" (stable); "Fileless execution via memfd_create" (stable); "Execution from /dev/shm" (stable) | stable file |
| Mining | "Detect outbound connections to common miner pool ports", "Detect crypto miners using the Stratum protocol", "Known Cryptominer Process Executed" (sandbox) | sandbox file |
| Process injection | "PTRACE attached to process" (stable) | stable file |
| Persistence | "Schedule Cron Jobs" (incubating); "Write below binary dir", "Modify binary dirs", "Write below etc" (sandbox); "Adding ssh keys to authorized_keys" (incubating) | incubating and sandbox files |
| Cloud credential theft from a container | "Contact cloud metadata service from container" (incubating) | incubating file |

### Inferences
- **Highest-value checks for the company's own Docker hosts:**
  - (a) Alert critically if `dockerd` (or a Podman service) listens on TCP: parse `ss -ltnp`, `/etc/docker/daemon.json` `hosts`, and `-H tcp://` in the systemd unit. Treat ports 2375, 2376, 4243 and 4244 as known-abused.
  - (b) Treat any container *create* event as critical when it combines `Privileged`, a bind of `/` or `docker.sock`, or `PidMode=host` with an image not in the customer's allowlist (for example `alpine`, or anything from `cmd.cat`). This is Commando Cat's and TeamTNT's signature.
  - (c) Alert on `chroot`, `nsenter`, `unshare`, `mount`, or a write to `release_agent` / `notify_on_release` from a process whose cgroup maps to a container.
- `release_agent` is a cgroup v1 feature, per the KEV wording. On hosts mounted cgroup2-only (`stat -fc %T /sys/fs/cgroup` returns `cgroup2fs`) the classic technique is unavailable, so the agent can lower its priority there. Its KEV addition in 2026 shows it is still used against older or hybrid hosts.
- No runtime CVEs in KEV does not mean low risk. Patch level is easy to check deterministically: report runc/crun/containerd versions against the fixed versions above, via `runc --version` and package queries, as a posture finding.
- Leaky-Vessels-style escapes need an attacker-chosen image or Dockerfile. For a VPS customer, the practical control is image provenance (Q4) plus detecting containers created from unexpected images.
- The agent can implement these rules itself using cilium/ebpf, so Falco needn't ship as a dependency. Falco's Apache-2.0 rules can be ported with attribution. Alternatively, shipping Falco alongside is license-compatible (Apache-2.0).

### Gaps
- I didn't fetch primary advisories for each of the November 2025 runc CVEs. Exact preconditions such as custom mount configs or malicious images come from secondary coverage, and affected-version ranges for CVE-2025-52565 vary between sources.
- No authoritative source was found for any 2026 containerd escape CVE. CVE-2026-46680 is single-sourced.
- No 2026 exposed-Docker-API campaign report was found. That may reflect search coverage rather than absence of activity.
- I found no Docker Engine API audit log. Detecting `docker.sock` abuse from inside a container must rely on eBPF or audit on `connect()` to the socket path, or on correlating engine events with the calling process. This needs prototyping.

## 3. Container incident response: pause vs stop, network disconnect, export/diff/inspect/logs, CRIU checkpoint, preserving evidence, and RHEL/Podman differences

### Takeaway
`pause` uses the cgroup freezer: processes are suspended without being told, and memory and sockets are preserved. That makes it the best default containment step. `stop` sends SIGTERM then SIGKILL and destroys volatile evidence. `network disconnect` cuts traffic but leaves the process running, so it can be observed. Evidence capture is `inspect` + `diff` + `export`/`commit` (none of these includes volumes) + logs, plus an optional CRIU checkpoint. CRIU checkpointing is experimental in Docker but a first-class feature in Podman, with `--export`, `--leave-running` and `--create-image`. On RHEL, Podman has no daemon: events are in journald, and Quadlet or systemd may restart a container you stop.

### Cited Findings
- `docker pause` "uses the freezer cgroup". Unlike SIGSTOP, "the process is unaware, and unable to capture, that it is being suspended" — [docker container pause](https://docs.docker.com/reference/cli/docker/container/pause/)
- `docker stop`: the main process gets `SIGTERM` and, after a grace period, `SIGKILL`. The first signal can be changed with `STOPSIGNAL` or `--signal` — [docker container stop](https://docs.docker.com/reference/cli/docker/container/stop/)
- `docker export` writes a container's filesystem as a tar archive but "doesn't export the contents of volumes" — [docker container export](https://docs.docker.com/reference/cli/docker/container/export/)
- `docker diff` lists files and directories added (`A`), deleted (`D`) or changed (`C`) since the container was created — [docker container diff](https://docs.docker.com/reference/cli/docker/container/diff/)
- `docker commit` pauses the container and its processes by default (`--pause`/`--no-pause`), and "Commits do not include any data contained in mounted volumes" — [docker container commit](https://docs.docker.com/reference/cli/docker/container/commit/)
- `docker network disconnect` requires a running container and has a `-f/--force` option — [docker network disconnect](https://docs.docker.com/reference/cli/docker/network/disconnect/)
- Docker's "Checkpoint and Restore is an experimental feature" built on CRIU. `docker checkpoint create` supports `--leave-running` and `--checkpoint-dir` — [docker checkpoint](https://docs.docker.com/reference/cli/docker/checkpoint/)
- `podman container checkpoint` checkpoints all processes of a container:
  - `--export` writes a zstd-compressed archive that includes rootfs changes unless `--ignore-rootfs` is set, and can be imported on another system.
  - `--leave-running` briefly pauses the container so memory and filesystem state are consistent; containers run with `--cgroups=disabled` cannot be frozen.
  - `--tcp-established` is needed when there are established TCP connections.
  - `--keep` retains CRIU logs; `--print-stats` outputs JSON timings.
  - `--create-image` produces an OCI image containing the checkpoint, annotated with host details.
  - gVisor checkpoints without CRIU.
  - Source: [podman-container-checkpoint(1)](https://docs.podman.io/en/latest/markdown/podman-container-checkpoint.1.html)
- CRIU packaging: Fedora criu 4.3 (not in EPEL9/10); Debian criu in bookworm and trixie — [Fedora mdapi criu](https://mdapi.fedoraproject.org/f43/srcpkg/criu); [Debian criu](https://sources.debian.org/api/src/criu/)
- Docker replays only the last 256 events for `--since` queries. Podman events are in journald by default and can be filtered with journald identifiers — [docker system events](https://docs.docker.com/reference/cli/docker/system/events/); [podman-events(1)](https://docs.podman.io/en/latest/markdown/podman-events.1.html)
- Quadlet units under `/etc/containers/systemd/`, `~/.config/containers/systemd/` and similar paths put Podman containers under systemd management — [podman-systemd.unit(5)](https://docs.podman.io/en/latest/markdown/podman-systemd.unit.5.html)

### Inferences
- **Suggested autonomous-response ladder** (policy-gated; each step logged to the master server before execution):
  1. **Snapshot metadata.** Collect `inspect` JSON, image ID/digest, `top`/process tree, and `/proc/<pid>/{exe,cmdline,maps,fd,status}` with environment variables redacted. Collect network connections from `/proc/<pid>/net` inside the netns, `docker diff`, and the last N log lines. For the json-file driver, also copy `/var/lib/docker/containers/<id>/<id>-json.log`.
  2. **Contain.** Use `pause` by default. It freezes miners and watchdogs inside the container without tipping them off and keeps memory for capture. Use `network disconnect` (or a DROP rule on the container's veth) when analysts want to watch behaviour. Note that `--network host` containers cannot be disconnected; for those, pause, or block by PID/cgroup with eBPF or nftables.
  3. **Acquire.** Take a `commit` (pauses by default) or `export`, plus a separate tar of each volume, because neither command includes volumes. Optionally take a CRIU checkpoint for memory; with Podman, `--export`/`--create-image` gives a portable evidence artifact. Hash everything and ship it to the master server.
  4. **Only then** stop or remove. Never `docker rm` before acquisition.
- **Watchdog-aware containment.** The motivating incident had a miner plus a watchdog plus cron and systemd persistence. If a container is the payload, the watchdog may sit on the host or in another container and will recreate it. Correlate container create events with the parent of whoever called the API, and contain host persistence (cron, systemd units) in the same transaction.
- **RHEL/Podman specifics:**
  - There is no central daemon. Act through the rootful socket or, for rootless containers, as the owning user (for example `machinectl shell` or `runuser -u <user> -- podman …`).
  - If a container is a Quadlet or systemd unit, `systemctl stop`/`mask` the unit. Otherwise systemd restart policies will resurrect it.
  - Collect `journalctl` Podman events as evidence.
- Pausing a container with the agent's own policy engine in mind: a frozen cgroup still holds its resources and network listeners in the kernel. Combine with network isolation when the container is serving malicious traffic (for example a webshell).

### Gaps
- I couldn't confirm whether Podman checkpointing works for **rootless** containers. The man page doesn't say, and historically CRIU needed root.
- I couldn't confirm whether Docker CE on RHEL ships CRIU support out of the box; RHEL's own criu packaging was not verified.
- Memory-acquisition tooling outside CRIU (AVML, LiME, gcore) and its licenses were not researched in this pass.

## 4. Image security: Trivy/Grype scanning, Syft SBOMs, cosign/Sigstore verification, secrets in image layers, and deployment policy gates

### Takeaway
The open-source scanner stack is permissively licensed: Trivy, Grype, Syft, OSV-Scanner and cosign are all Apache-2.0. The March 2026 Trivy supply-chain compromise shows the agent must pin scanner binaries and images by digest and checksum and never auto-pull "latest". The malicious artifacts were the v0.69.4 binary, Docker Hub tags 0.69.5 and 0.69.6, and 76 force-pushed trivy-action tags. Docker Content Trust is being retired, so signature gates should use Sigstore/cosign. On Podman/RHEL, `containers-policy.json` `sigstoreSigned` gives a native pull-time gate; Docker has no native equivalent.

### Cited Findings

| Tool | Role | License | Go module / embeddability | Distro packages (2026-11-09) | Source |
|---|---|---|---|---|---|
| Trivy | Vulnerabilities, misconfigurations, secrets and SBOM for images, filesystems and repos | Apache-2.0 | `github.com/aquasecurity/trivy` | Fedora 0.69.3 (F43/Rawhide), EPEL10 0.64.1, EPEL9 0.50.4; not in Debian; upstream rpm repo `aquasecurity.github.io/trivy-repo` | [aquasecurity/trivy](https://github.com/aquasecurity/trivy); [Trivy install docs](https://github.com/aquasecurity/trivy/blob/main/docs/getting-started/installation.md); [Fedora mdapi](https://mdapi.fedoraproject.org/f43/srcpkg/trivy) |
| Grype | Vulnerability scanner for images and filesystems | Apache-2.0 | `github.com/anchore/grype` | Fedora 0.117.0 (F43), 0.120.0 (Rawhide); not in Debian | [anchore/grype](https://github.com/anchore/grype); [Fedora mdapi](https://mdapi.fedoraproject.org/rawhide/srcpkg/grype) |
| Syft | "CLI tool and library for generating a Software Bill of Materials from container images and filesystems" | Apache-2.0 | `github.com/anchore/syft` | Debian sid only; not in Fedora | [anchore/syft](https://github.com/anchore/syft) |
| OSV-Scanner | Scans lockfiles (npm, composer, pip and others; 11+ ecosystems and 19+ lockfile types); layer-aware container image scanning; guided remediation; SLSA 3 | Apache-2.0 | `github.com/google/osv-scanner/v2` | Not found in Fedora | [google/osv-scanner](https://github.com/google/osv-scanner) |
| cosign | Signing and verification for containers and binaries; keyless verify needs `--certificate-identity` and `--certificate-oidc-issuer` (or the `-regexp` variants) | Apache-2.0 | `github.com/sigstore/cosign` | Debian trixie, forky and sid; not in Fedora | [sigstore/cosign](https://github.com/sigstore/cosign); [Debian cosign](https://sources.debian.org/api/src/cosign/) |

**Trivy compromise timeline (2026)**
- Late February: a misconfiguration in Trivy's GitHub Actions leaked a privileged token. Credential rotation on 1 March was incomplete.
- 19 March, about 17:43 UTC: 76 of 77 `trivy-action` tags (all except v0.35.0) and all 7 `setup-trivy` tags were force-pushed to malicious commits. A compromised service account published a malicious **Trivy v0.69.4** to GitHub Releases, Docker Hub, GHCR and ECR. It was contained about 3 hours later.
- 22 March: malicious Docker Hub images **0.69.5 and 0.69.6** appeared.
- Aqua's safe versions: Trivy **v0.69.2–v0.69.3**, trivy-action **v0.35.0**, setup-trivy **v0.2.6**.
- IOCs include `~/.config/systemd/user/sysmon.py` persistence, `scan.aquasecurtiy[.]org` and `45.148.10.212`.
- Aqua says SHA pinning "remains the only truly immutable protection" and that GitHub's "Immutable" badge did not prevent the tag force-pushes. Its post does not mention cosign.
- Tracked as CVE-2026-33634 / GHSA-69fq-xp46-6x23; Aqua's own advisory is GHSA-cxm3-wv7p-598c.
- Sources: [Aqua: what you need to know](https://www.aquasec.com/blog/trivy-supply-chain-attack-what-you-need-to-know/); [OSV GHSA-69fq-xp46-6x23](https://osv.dev/vulnerability/GHSA-69fq-xp46-6x23); [Snyk analysis](https://snyk.io/articles/trivy-github-actions-supply-chain-compromise/)

**Secrets in image layers**
- Trivy scans every plaintext file (and `.pyc`) in images, filesystems and repos using built-in rules plus custom configuration. It "tries to detect a base image and skip those layers for secret scanning" — [Trivy secret scanning docs](https://github.com/aquasecurity/trivy/blob/main/docs/guide/scanner/secret.md)
- Betterleaks scans "all platforms, historical layers, configuration, and embedded attestations, with digest provenance and deleted/overwritten path reporting" — [betterleaks README](https://github.com/betterleaks/betterleaks)
- Titus scans Docker/OCI images "from any registry, tarball, or OCI layout directory — no Docker daemon or binary required" — [praetorian-inc/titus](https://github.com/praetorian-inc/titus)

**Signing and policy gates**
- Docker is retiring Docker Content Trust (Notary v1):
  - Fewer than 0.05% of Docker Hub pulls used it.
  - Docker Official Image DCT signing certificates began expiring on **8 August 2025**, breaking pulls with `DOCKER_CONTENT_TRUST=1`.
  - Per InfoQ, DCT could not be enabled on new registries from 30 September 2025, and DCT data will be deleted on 31 March 2028.
  - A Docker docs excerpt seen in search, but not opened, says `notary.docker.io` shuts down on 8 December 2026.
  - Sources: [Docker: Retiring DCT](https://www.docker.com/blog/retiring-docker-content-trust/); [Docker: DCT retirement and migration guidance](https://www.docker.com/blog/docker-content-trust-retirement-and-migration-guidance/); [InfoQ](https://www.infoq.com/news/2025/08/docker-content-trust-retired)
- `containers-policy.json`, used by Podman, Buildah and Skopeo on RHEL and Fedora, supports a `sigstoreSigned` requirement with `fulcio` and Rekor settings — [containers-policy.json(5)](https://github.com/containers/image/blob/main/docs/containers-policy.json.5.md)

### Inferences
- **Recommended host-side design:**
  - The agent uses the Syft library (Apache-2.0) in-process to build an SBOM per running image digest. It ships only the SBOM to the master server, which matches against Grype/OSV data centrally. Hosts then need no vulnerability database and no scanner binary.
  - Where on-host scanning is unavoidable, run Trivy or Grype as an external binary pinned by version and SHA-256 and verified with cosign. Never take `latest` or a mutable tag.
  - Use a version allowlist that excludes Trivy 0.69.4–0.69.6.
- Note that Trivy skips base-image layers for secret scanning. If the goal is "secrets ever baked into any layer, including deleted ones", Betterleaks or Titus layer-history scanning gives better coverage.
- **Deployment gates:**
  - For Docker hosts there is no native admission control. Make the agent detective: on each `create`/`start` event, check the image digest against a customer allowlist or cosign verification result, and auto-pause on violation when policy allows.
  - For Podman/RHEL, recommend `sigstoreSigned` policies so the gate is preventive.
  - Retire Docker Bench's DCT check and replace it with a "signed by expected identity (cosign)" check.
- Fedora and EPEL lag upstream (EPEL9 Trivy 0.50.4). If the agent depends on distro packages, it must handle old scanner versions. Bundling a pinned, signed binary in the agent's own repo is more predictable.

### Gaps
- Syft's exact SBOM output formats (SPDX and CycloneDX versions) and Grype's database licensing and redistribution terms were not re-verified in this pass.
- Trivy's post-incident release-signing changes (provenance or attestations Aqua said it would add) are not documented in the Aqua post. The current verification procedure should be confirmed before integration.
- Docker authorization plugins as a possible preventive gate on Docker hosts were not researched.

## 5. Secrets: Gitleaks (and successor Betterleaks), TruffleHog (AGPL), detect-secrets, Nosey Parker (now Titus), Kingfisher and Trivy; detection approaches, safe handling, exposed .env/.git, Laravel APP_KEY RCE, and Androxgh0st

### Takeaway
For a proprietary Go agent the license-clean choices are:
- **Gitleaks v8** (MIT; importable `detect` package), now in security-fixes-only mode.
- Its successor **Betterleaks v2** (MIT, maintained by the Gitleaks author, Go SDK).
- **Titus** (Apache-2.0 Go library, replacing the archived Nosey Parker).

TruffleHog is AGPL-3.0, so keep it out of the agent binary. The agent should detect locally, keep live validation opt-in and on-host, and send only redacted fingerprints. The highest-impact web-stack secret risks are verified real-world attacks:
- `.env` and `/.git/config` files served over HTTP (Androxgh0st, EMERALDWHALE)
- leaked Laravel `APP_KEY`s, which give deserialization RCE (about 600 apps trivially exploitable per GitGuardian/Synacktiv, July 2025)

### Cited Findings

**Scanners**

| Tool | Approach | License | Status | Embeddability | Source |
|---|---|---|---|---|---|
| Gitleaks | Regex rules plus Shannon-entropy thresholds; `--redact[=0..100]`; recursive decoding (`--max-decode-depth`); archive scanning (`--max-archive-depth`) | MIT | README: "Gitleaks is feature complete… Future releases will be security patches only… shifting my focus to Betterleaks"; 30.8k stars, pushed 2026-10-28 | Go module `github.com/zricethezav/gitleaks/v8`; `detect` package exposes `NewDetector`, `NewDetectorDefaultConfig`, `DetectBytes`, `DetectString`; in Debian trixie, forky and sid and Fedora 8.30.x | [gitleaks README](https://github.com/gitleaks/gitleaks); [detect.go](https://github.com/gitleaks/gitleaks/blob/master/detect/detect.go) |
| Betterleaks | Successor by "the folks who made Gitleaks, including the original author", sponsored by Aikido. Adds validation via HTTP requests defined in Expr rules, credential analysis, optional revocation, Expr filters, BPE-token "rare not random" filtering, aho-corasick plus RE2, container layer scanning | MIT | 2.9k stars; v2 on `main`, v1 on `v1.x`; "SDK scanners still make no provider requests" | Go SDK module `github.com/betterleaks/betterleaks/v2` (Go ≥1.26); Fedora 1.8.1 (F43), 1.9.0 (Rawhide), EPEL9 1.8.1, EPEL10 1.8.0 (`dnf install betterleaks`); not in Debian | [betterleaks README](https://github.com/betterleaks/betterleaks); [v2 migration guide](https://github.com/betterleaks/betterleaks/blob/main/docs/v2_migration.md); [Fedora mdapi](https://mdapi.fedoraproject.org/epel9/srcpkg/betterleaks) |
| TruffleHog | Discovery, classification of 800+ secret types, live validation and analysis | **AGPL-3.0** | 29k stars, active | Go module `github.com/trufflesecurity/trufflehog/v3`; installer can verify checksum signatures with cosign; Debian sid only | [trufflehog README](https://github.com/trufflesecurity/trufflehog) |
| detect-secrets (Yelp) | Baseline file (`.secrets.baseline`) plus "periodic diff outputs against heuristically crafted regex statements"; pluggable detectors | Apache-2.0 | Pushed 2026-04-02 (slow) | Python; not in Debian or Fedora under that name | [Yelp/detect-secrets](https://github.com/Yelp/detect-secrets) |
| Nosey Parker | Regex scanner, about 188 rules, deduplication | Apache-2.0 | **Archived**; README: "Nosey Parker is now Replaced by Titus… Officially Retired" | — | [praetorian-inc/noseyparker](https://github.com/praetorian-inc/noseyparker); [Praetorian announcement](https://www.praetorian.com/blog/titus-open-source-secret-scanner/) |
| Titus | 487 rules drawn from Nosey Parker and Kingfisher; Hyperscan/Vectorscan with pure-Go fallback; live validation; risk score 0–100; image and binary/archive extraction; CLI, Go library, Burp and Chrome extensions | Apache-2.0 | 765 stars, pushed 2026-11-05 | `go get github.com/praetorian-inc/titus`; `titus.NewScanner()`, with validation opt-in via `titus.WithValidation()` | [praetorian-inc/titus](https://github.com/praetorian-inc/titus) |
| Kingfisher (MongoDB) | Detect, validate, map blast radius, triage, revoke; validation on by default (`--no-validate` for detection only; `--no-update-check`); offline checksum checks in custom rules | Apache-2.0 | 1.3k stars, pushed 2026-11-09 | Rust; embeddable from Rust, Python and Node.js, not Go | [mongodb/kingfisher](https://github.com/mongodb/kingfisher) |
| Trivy secret scanner | Built-in regex rules plus allow-rules, configurable | Apache-2.0 | see Q4 | External binary | [Trivy secret docs](https://github.com/aquasecurity/trivy/blob/main/docs/guide/scanner/secret.md) |

- AGPL-3.0 §13 requires offering the Corresponding Source to users who interact with a *modified* program over a network. The rest of the GPL-3.0-style copyleft applies to distributed combined works — [GNU AGPL-3.0 text](https://www.gnu.org/licenses/agpl-3.0.html)

**Real-world secret exposure attacks against PHP/Laravel stacks**
- **Laravel APP_KEY leaks** (GitGuardian with Synacktiv, 10 July 2025):
  - About 260,000 APP_KEYs were extracted from GitHub (2018 to 30 May 2025), yielding **about 600 trivially compromisable apps**.
  - About 28,000 APP_KEY/APP_URL pairs were exposed; about 10% were still valid, leaving **about 120 apps** vulnerable to trivial RCE.
  - 63% of exposures came from `.env` files or variants, and 35% were co-leaked with other secrets such as database, cloud and AI tokens.
  - Mechanism: Laravel `decrypt()` unserializes data, so a known key lets an attacker forge encrypted cookies or payloads carrying phpggc gadget chains (covering Laravel up to v12). Tools: `laravel-crypto-killer`.
  - `SESSION_DRIVER=cookie` stays exploitable (CVE-2024-55556). CVE-2018-15133 affected Laravel before 5.6.30.
  - 50 keys deleted from repos were still valid in production. GitGuardian's guidance is to rotate, not merely delete.
  - Sources: [GitGuardian](https://blog.gitguardian.com/exploiting-public-app_key-leaks/); [The Hacker News](https://thehackernews.com/2025/07/over-600-laravel-apps-exposed-to-remote.html)
- **Androxgh0st** (FBI/CISA AA24-016A, 16 January 2024):
  - A botnet that scans for exposed Laravel `.env` files to steal credentials.
  - It exploits PHPUnit CVE-2017-9841 (`/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php`), Laravel CVE-2018-15133 and Apache CVE-2021-41773. Requests to `/.env` are an IOC.
  - Mitigations: don't run Laravel in debug or testing mode, and remove and revoke cloud credentials kept in `.env`.
  - Sources: [CISA AA24-016A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-016a); [IC3 PDF](https://www.ic3.gov/CSA/2024/240116.pdf)
- CVE-2018-15133 (Laravel deserialization) was added to KEV on 2024-01-16, the same day as the advisory — [CISA KEV JSON](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json)
- **EMERALDWHALE** (Sysdig, 30 October 2024):
  - Stole **more than 15,000 cloud credentials** by mass-scanning (httpx, masscan) for exposed `/.git/config` files and Laravel `.env` files.
  - A list of more than 67,000 URLs with exposed `/.git/config` was sold on Telegram for $100.
  - Sysdig sampled 6,000 Git tokens and found about 2,000 valid.
  - Sources: [Sysdig](https://www.sysdig.com/blog/emeraldwhale); [The Register](https://www.theregister.com/2024/10/31/emeraldwhale_credential_theft)
- Reported in 2026 aggregator coverage, unverified: a months-long credential-theft campaign exploiting Livewire CVE-2025-54068, attributed to Imperva, harvested credentials (payment keys, AWS keys) from about 6,167 apps — [rankiteo aggregator (low quality)](https://blog.rankiteo.com/lar1782311560-laravel-vulnerability-may-2026/)

### Inferences
- **Library choice:**
  - Embed Betterleaks v2 SDK (MIT) or Titus (Apache-2.0) for an actively maintained Go engine.
  - Gitleaks v8 `detect` is a stable fallback (MIT, patches only).
  - Port Kingfisher (Rust) rules as data rather than code; Titus already did this under Apache-2.0.
  - Don't link TruffleHog. Shipping its unmodified binary alongside the agent is probably "aggregation", but AGPL obligations and the vendor's commercial alternative call for legal review.
- **Safe-handling rules for the agent:**
  - (a) Scan locally, and never upload file contents.
  - (b) Send rule ID, path, line, entropy, the first and last 2–4 characters, and an HMAC-SHA256 of the secret keyed per tenant. A plain hash of a low-entropy secret can be brute-forced. The master server can still deduplicate and track rotation.
  - (c) Off by default: live validation sends the secret to the provider's API, which may itself raise alerts or legal questions on customer systems. If enabled, it runs on-host. Titus and the Betterleaks SDK default to no provider requests; Kingfisher validates by default, so pass `--no-validate`.
  - (d) Redact in all logs and Discord alerts, following Gitleaks `--redact` semantics.
- **Web-exposure self-test:**
  - For each vhost or app container, request locally (with the correct `Host` header) paths such as `/.env`, `/.env.production`, `/.git/config`, `/.git/HEAD`, `/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php`, `/storage/logs/laravel.log`, `/_ignition/execute-solution`, `/telescope` and `/phpinfo.php`.
  - Alert on any 200 response with matching content.
  - Also parse access logs for mass-scanner bursts on `/.env` and `/.git/config`, especially those that returned 200. That indicates a leak already happened, so trigger rotation guidance.
- **Laravel-specific posture:**
  - Flag `APP_DEBUG=true`, `APP_ENV` not `production`, `SESSION_DRIVER=cookie`, a `.env` inside the web root or the image, and an `APP_KEY` identical across environments or present in git history.
  - On any APP_KEY exposure, recommend rotation plus re-encryption.
  - Runtime signal: `php-fpm` spawning a shell (see Q6) shortly after requests with oversized `laravel_session`/`XSRF-TOKEN` cookies.

### Gaps
- I didn't verify whether TruffleHog's validation is on by default in the current version (historically yes), or its exact flag names.
- No benchmark comparing precision and recall across Betterleaks, Titus, Gitleaks, Kingfisher and TruffleHog was found in this pass.
- GitGuardian's commercial "has my secret leaked" style services and their APIs were not researched.
- The Livewire credential-theft campaign figures (Imperva, about 6,167 apps) come only from a low-quality aggregator.

## 6. Web-app stack tooling: composer audit, npm audit, OSV-Scanner, WPScan, Wordfence Intelligence, Patchstack, Enlightn; webshell and code-drift detection; known exploited PHP/Laravel/WordPress/Node CVEs 2023-2026

### Takeaway
Free, commercially usable dependency intelligence exists. Composer 2.9+ blocks insecure versions at resolve time by default, OSV-Scanner is Apache-2.0, and the Wordfence Intelligence feed is free for commercial use but has needed a free API key since v1 and v2 were switched off on 9 March 2026. WPScan's CLI and API require a paid commercial license, Patchstack's API is paid, and Enlightn is archived.

2025–2026 exploitation hit core platforms as much as plugins, per CISA KEV:
- React Server Components "React2Shell": ransomware-linked, mass cryptomining
- Laravel Livewire
- Four WordPress core CVEs in July–November 2026
- Two PHP unauthenticated RCEs added in October 2026
- cPanel/WP2 auth bypass

Webshell and drift detection should combine "web-server process spawned a shell" telemetry, FIM on code paths and git drift.

### Cited Findings

**Dependency and vulnerability-data tools**
- **Composer:**
  - 2.9 (RC1, 7 November 2025) added `audit.block-insecure`, **default true**. It blocks `update`/`require`/`remove` from selecting versions with security advisories and replaces `roave/security-advisories`. `COMPOSER_NO_AUDIT=1` skips only the post-install report, not the filter.
  - Current Composer docs describe a unified `policy` configuration section, and Fedora/EPEL ship Composer 2.11.1. A secondary source says advisory blocking moved under `policy` in 2.10.
  - Sources: [Composer 2.9 release (Packagist blog)](https://blog.packagist.com/composer-2-9/); [2.9.0-RC1 changelog](https://getcomposer.org/changelog/2.9.0-RC1); [Composer config docs: policy](https://getcomposer.org/doc/06-config.md#policy); [Fedora mdapi composer](https://mdapi.fedoraproject.org/epel9/srcpkg/composer)
- **npm audit** "submits a description of the dependencies configured in your project to your default registry and asks for a report of known vulnerabilities". `npm audit signatures` verifies registry signatures — [npm-audit docs](https://docs.npmjs.com/cli/commands/npm-audit)
- **OSV-Scanner** (Apache-2.0) supports npm, composer and other lockfiles, container images and guided remediation — [google/osv-scanner](https://github.com/google/osv-scanner)
- **WPScan:**
  - The CLI is under the "WPScan Public Source License", which is dual-licensed. "Cases that include commercialization of WPScan require a commercial, non-free license." Examples include SaaS or managed services, distributing it as part of a commercial product, and use as a value-added service. Testing your own systems is free.
  - The API's free plan is 25 requests per day for non-commercial use; commercial use requires a paid license with quoted pricing.
  - Sources: [WPScan LICENSE](https://github.com/wpscanteam/wpscan/blob/master/LICENSE); [WPScan pricing](https://wpscan.com/pricing/)
- **Wordfence Intelligence:**
  - Launched in December 2022 as a free vulnerability database usable for commercial purposes.
  - Feed v3 requires a free API key; v1 and v2 were scheduled to be disabled on **9 March 2026**. Rate limits apply (HTTP 429).
  - The governing Terms and Conditions were not fully read; see Gaps.
  - Sources: [Wordfence 2022 announcement](https://www.wordfence.com/blog/2022/12/wordfence-free-vulnerability-database/); [v3 feed docs](https://www.wordfence.com/help/wordfence-intelligence/v3-accessing-and-consuming-the-vulnerability-data-feed/); [portal terms](https://www.wordfence.com/threat-intel/vendor/vulnerability-management-portal/terms/)
- **Patchstack:**
  - The Vulnerability Database API is a paid upgrade for Developer and Business plans: **$149/month per 500 daily API calls**, granted after describing your use case.
  - The "Threat Intelligence Extended" tier (bulk and 24-hour feeds) has custom pricing and rate limits.
  - The public database is browsable for free, but no explicit redistribution license was found.
  - Sources: [Patchstack DB API upgrade](https://docs.patchstack.com/patchstack-app/upgrades/vulnerability-database-api); [Threat Intelligence Extended](https://docs.patchstack.com/api-reference/threat-intelligence-extended/)
- **Enlightn** (Laravel security and performance analyzer): **archived**, last push 2024-06-15. Its LICENSE.md is LGPL-3.0 (Copyright Enlightn Software) — [enlightn/enlightn](https://github.com/enlightn/enlightn)

**Known exploited CVEs relevant to PHP/Laravel/WordPress/Node stacks** (CISA KEV catalog 2026.11.06; "ransomware=Known" is KEV's ransomware-use flag)

| KEV date added | CVE | Product | Notes from KEV | 
|---|---|---|---|
| 2023-09-18 | CVE-2021-3129 | Laravel Ignition | Unauthenticated RCE via `file_get_contents`/`file_put_contents`; ransomware=Known |
| 2024-01-16 | CVE-2018-15133 | Laravel Framework | Deserialization (APP_KEY); used by Androxgh0st |
| 2024-06-12 | CVE-2024-4577 | PHP | PHP-CGI argument injection on **Windows-based** PHP; ransomware=Known |
| 2025-02-20 / 2025-06-02 / 2026-03-20 | CVE-2025-23209, CVE-2024-56145, CVE-2025-35939, CVE-2025-32432 | Craft CMS (PHP) | Code injection and related flaws |
| 2025-07-07 | CVE-2016-10033 | PHPMailer | Command injection (old bug, newly listed) |
| 2025-12-05 | CVE-2025-55182 | React Server Components ("React2Shell") | Unauthenticated RCE via payload decoding at Server Function endpoints; CVE-2025-66478 rejected but associated; ransomware=Known |
| 2026-02-05 | CVE-2025-11953 | React Native Community CLI | Metro dev-server OS command injection |
| 2026-03-20 | CVE-2025-54068 | Laravel Livewire | Code injection giving unauthenticated RCE "in specific scenarios" (GHSA-29cq-5w36-x7w3) |
| 2026-04-30 | CVE-2026-41940 | cPanel & WHM and WP2 (WordPress Squared) | Login-flow auth bypass; ransomware=Known |
| 2026-05-26, 2026-06-15 | CVE-2026-48172, CVE-2026-54420 | LiteSpeed cPanel plugin | Privilege escalation; symlink following |
| 2026-05-22 | CVE-2026-9082 | Drupal core | SQL injection |
| 2026-07-21 | CVE-2026-60137 + CVE-2026-63030 | WordPress core | SQL injection (when a plugin or theme passes untrusted input) chained with an "interpretation conflict" flaw, giving **unauthenticated RCE on default installs**; fixed in WordPress 7.0.2 |
| 2026-09-25 | CVE-2026-87902 | WordPress core | Remote file inclusion via page-template resolution, giving RCE (GHSA-7hp8-65ch-5whp) |
| 2026-10-26 | CVE-2026-109618, CVE-2026-109619 | PHP | Memory corruption and stale request-state flaws, each giving **unauthenticated RCE** |
| 2026-11-03 | CVE-2026-119977 | WordPress core | TOCTOU race during full-package core upgrades (predictable web-accessible staging paths), giving unauthenticated code execution; WordPress 7.1.4 referenced |

Sources for the table: [CISA KEV JSON](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json); [WordPress 7.0.2 release](https://wordpress.org/news/2026/07/wordpress-7-0-2-release/); [GHSA-7hp8-65ch-5whp](https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-7hp8-65ch-5whp); [Livewire GHSA-29cq-5w36-x7w3](https://github.com/livewire/livewire/security/advisories/GHSA-29cq-5w36-x7w3); [cPanel security update 2026-04-28](https://support.cpanel.net/hc/en-us/articles/40073787579671-cPanel-WHM-Security-Update-04-28-2026)

- A KEV filter for "plugin", "WordPress", "WooCommerce" or "Elementor" (excluding WordPress core) returned **no WordPress plugin entries added in 2023–2026**. Plugin mass exploitation is tracked by Wordfence and Patchstack rather than KEV — [CISA KEV JSON](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json)
- **React2Shell in the wild:**
  - Google Threat Intelligence Group (12 December 2025) saw XMRig deployment and multiple China-nexus clusters.
  - Huntress reported Next.js exploitation dropping miners and a "PeerBlight" Linux backdoor.
  - CloudSEK and Security Affairs (January 2026) reported RondoDox botnet mass exploitation dropping miners and Mirai variants.
  - Affected frameworks include Next.js, Waku, React Router and RedwoodSDK.
  - Sources: [Google Cloud / GTIG](https://cloud.google.com/blog/topics/threat-intelligence/threat-actors-exploit-react2shell-cve-2025-55182); [Huntress](https://www.huntress.com/blog/peerblight-linux-backdoor-exploits-react2shell); [Security Affairs](https://securityaffairs.com/186386/uncategorized/react2shell-under-attack-rondodox-botnet-spreads-miners-and-malware.html); [The Hacker News](https://thehackernews.com/2025/12/react2shell-exploitation-delivers.html)
- **Livewire CVE-2025-54068:** v3 up to 3.6.3 is affected and 3.6.4 fixes it. Synacktiv estimated more than 130,000 apps potentially exposed — [Red Hot Cyber (secondary)](https://www.redhotcyber.com/en/post/livewire-vulnerability-exposed-130k-apps-at-risk-of-remote-code-execution); [Livewire advisory](https://github.com/livewire/livewire/security/advisories/GHSA-29cq-5w36-x7w3)

**Webshell detection rules (Falco sandbox, Apache-2.0)**
- "Web Server Spawned Shell": nginx, apache or php-fpm spawning an interactive shell, a "strong indicator of webshell exploitation"; tunable through the `user_known_web_server_shell_activities` macro. Related sandbox rules: "Web Server Spawned Suspicious Child Process", "Reverse Shell from Web Server", "Interpreted procs outbound network activity" and "Network Tool Executed During NPM Package Install" — [falco-sandbox_rules.yaml](https://github.com/falcosecurity/rules/blob/main/rules/falco-sandbox_rules.yaml)

### Inferences
- **Dependency intelligence without license risk:**
  - Parse `composer.lock` and `package-lock.json` on hosts and in container images (via the SBOM step in Q4) and match on the master server against OSV data (OSV-Scanner, Apache-2.0).
  - For WordPress plugins and themes, add the Wordfence Intelligence v3 feed (free, commercial OK, API key) on the master server, with attribution and terms review.
  - Don't ship WPScan inside the product or call its API commercially without a contract. Patchstack is a paid option for broader WordPress coverage.
  - Enlightn should not be a dependency. If Laravel-specific config checks are wanted, implement them natively (APP_DEBUG, APP_KEY, session driver, exposed Telescope or Horizon, Ignition in production).
- **Prioritisation:** a VPS EDR should raise severity for any component on KEV: PHP 8.x (CVE-2026-109618/9), WordPress core (four 2026 CVEs), Livewire, React/Next.js (React2Shell), Craft, Drupal, cPanel/WP2 and LiteSpeed's cPanel plugin. The agent can run a daily KEV sync on the master server, a single JSON file, and map it against host and image inventories.
- **Webshell and code-drift detection:**
  - (a) eBPF/fanotify FIM that alerts when the web or PHP-FPM user creates or modifies `.php`, `.phtml`, `.phar` or `.js` files under code paths (`/var/www`, `app/`, `public/`, `vendor/`, `wp-content/plugins|themes`). Any `.php` under `wp-content/uploads/` or Laravel `storage/` is critical.
  - (b) A `git status --porcelain` and `git diff --stat` drift check for git-deployed apps, using hashes against `git ls-files -s` to avoid needing the network.
  - (c) For containerised apps, periodic `docker diff` of app containers: `A`/`C` entries under the app root outside expected cache and log directories mean drift. Recommend read-only root filesystems.
  - (d) Process telemetry such as Falco's "Web Server Spawned Shell".
  - The motivating incident (replaced system binaries) argues for running the same FIM on `/usr/bin`, `/usr/sbin` and `/lib` with package-manager verification (`rpm -Va`, `dpkg --verify`/debsums). That module belongs to the host-integrity research track.
- WordPress CVE-2026-119977 exploits the *upgrade* window via web-accessible staging paths. FIM should expect bursts during upgrades and alert on PHP execution from upgrade staging directories rather than suppressing everything during updates.

### Gaps
- I didn't read the full Wordfence Intelligence Terms and Conditions (attribution or redistribution requirements for the free commercial feed).
- No explicit license terms for redistributing Patchstack data were found.
- KEV gives no affected-version or SAPI details for PHP CVE-2026-109618/109619. php.net advisories were not fetched.
- WordPress plugin mass-exploitation in 2025–2026 (for example OttoKit/SureTriggers CVE-2025-27007, reported by secondary sources) was not verified against Wordfence or Patchstack primary data.
- npm's current advisory source and the behaviour of `npm audit` against private registries were not researched further.

## 7. Cloud control plane (later phase): Prowler, ScoutSuite, CloudSploit, Steampipe/Powerpipe; AWS CloudTrail/GuardDuty; what DigitalOcean, Hetzner, Linode/Akamai and OVH APIs expose; Stratus Red Team; realistic monitoring for VPS-only customers

### Takeaway
The CSPM ecosystem is AWS-, Azure- and GCP-centric. Prowler (Apache-2.0) is the only active, permissively licensed multi-cloud option, and it has **no DigitalOcean, Hetzner, Linode or OVH provider**. ScoutSuite is GPL-2.0 and mostly dormant since September 2025. CloudSploit is GPL-3.0. Steampipe and Powerpipe are AGPL-3.0, but their DigitalOcean, Linode and Hetzner (`hcloud`) plugins are Apache-2.0.

VPS providers expose firewalls, snapshots and resource or action history, but little identity-attributed audit data:
- DigitalOcean: security history only in the control panel
- Hetzner: per-resource actions only, with no audit log
- Linode: 90-day account events, with audit logs in limited availability
- OVH: proper audit, IAM and activity logs via Logs Data Platform

For VPS-only customers the host agent remains the primary sensor. The control-plane module should focus on firewall and snapshot drift and on detecting unexpected new resources.

### Cited Findings

**CSPM and query tools**

| Tool | License | Status (2026-11-09) | Coverage | Source |
|---|---|---|---|---|
| Prowler | Apache-2.0 | 15.2k stars, pushed 2026-11-09; OSS CLI plus self-hosted "Prowler Local Server" | Check counts: AWS 662, Azure 191, GCP 110, Kubernetes 92, GitHub 24, M365 144, OCI 52, Alibaba 63, Cloudflare 43, MongoDB Atlas 10, OpenStack 34, NHN 6 (unofficial); IaC via Trivy; LLM via promptfoo. **No DigitalOcean, Hetzner, Linode or OVH** | [prowler README](https://github.com/prowler-cloud/prowler) |
| ScoutSuite (NCC Group) | GPL-2.0 | Last push 2025-09-23 | Multi-cloud auditing | [nccgroup/ScoutSuite](https://github.com/nccgroup/ScoutSuite) |
| CloudSploit (Aqua) | GPL-3.0 | Pushed 2026-09-22 | CSPM | [aquasecurity/cloudsploit](https://github.com/aquasecurity/cloudsploit) |
| Steampipe | AGPL-3.0 (CLI) | Pushed 2026-11-06 | SQL over APIs; plugins `steampipe-plugin-digitalocean`, `-linode` and `-hcloud` exist, each Apache-2.0; a `-vultr` plugin was not found and the OVH check timed out | [turbot/steampipe](https://github.com/turbot/steampipe); [DO plugin](https://github.com/turbot/steampipe-plugin-digitalocean); [Linode plugin](https://github.com/turbot/steampipe-plugin-linode); [hcloud plugin](https://github.com/turbot/steampipe-plugin-hcloud) |
| Powerpipe | AGPL-3.0 | Pushed 2026-11-05 | Dashboards and benchmarks over Steampipe | [turbot/powerpipe](https://github.com/turbot/powerpipe) |
| Stratus Red Team (Datadog) | Apache-2.0 | 2.4k stars, pushed 2026-11-09 | Granular cloud adversary emulation for AWS, Azure, GCP, Entra ID and Kubernetes; technique counts by tactic include Defense Evasion 14, Impact 14, Exfiltration 12, Credential Access 9, Discovery 5 and Execution 5. No VPS-provider techniques | [DataDog/stratus-red-team](https://github.com/DataDog/stratus-red-team); [technique list](https://github.com/DataDog/stratus-red-team/blob/main/docs/attack-techniques/list.md) |

**AWS**
- GuardDuty Runtime Monitoring for EC2:
  - Uses a GuardDuty security agent built on eBPF, tracepoints and kprobes, on AMD64 and ARM64 (Graviton2 and later).
  - Supports Amazon Linux 2 and 2023; Ubuntu 20.04/22.04 and Debian 11/12 (June 2024); RHEL, CentOS and Fedora (agent v1.5.0); with later additions including Oracle Linux, Rocky, AlmaLinux 9/10 and newer Ubuntu, Debian and RHEL releases.
  - The agent is capped at 10% of total vCPU and 128 MB–1 GB of memory depending on instance size.
  - Sources: [EC2 support prerequisites](https://docs.aws.amazon.com/guardduty/latest/ug/prereq-runtime-monitoring-ec2-support.html); [Supported OS/kernel](https://docs.aws.amazon.com/guardduty/latest/ug/prereq-runtime-monitoring-cpu-os-kernel-support.html); [Ubuntu/Debian announcement](https://aws.amazon.com/about-aws/whats-new/2024/06/amazon-guardduty-ec2-runtime-monitoring-ubuntu-debian-os); [agent release history](https://docs.aws.amazon.com/guardduty/latest/ug/runtime-monitoring-agent-release-history.html)

**VPS providers**
- **DigitalOcean:**
  - A team's **Security History** (actions such as creating or deleting resources and API tokens, with user, originating IP and time) is viewable **in the control panel**. Older data requires a support ticket, and logins are on the account Activity tab.
  - "The DigitalOcean API and CLI client, `doctl`, do not support teams."
  - Removing someone from a team "does not revoke their access to Droplets via SSH keys or other credentials".
  - The API has an `actions:read` scope for resource events. A public feature request asks for an audit-event ingestion API.
  - Sources: [View Security History (updated 2026-07-13)](https://docs.digitalocean.com/platform/teams/how-to/view-security-history/); [Team limits](https://docs.digitalocean.com/platform/teams/limits/); [API scopes: actions](https://docs.digitalocean.com/reference/api/scopes/actions/); [ideas.digitalocean.com request](https://ideas.digitalocean.com/infrastructure/p/api-support-for-basic-ingestion-of-the-latest-audit-events)
- **Hetzner Cloud:**
  - Listing all actions via `GET /actions` was deprecated ("Starting 1 October 2023, it will no longer be available") and later removed. Only `GET /v1/actions?id=` and per-resource action endpoints remain (`GET /<resource>/actions/{action_id}`).
  - Firewall endpoints include `POST /v1/firewalls`, `…/actions/set_rules`, `apply_to_resources` and `remove_from_resources`.
  - A search of the changelog found **no audit-log or activity-log feature**.
  - Source: [Hetzner Cloud API changelog](https://docs.hetzner.cloud/changelog)
- **Linode/Akamai:**
  - `GET /account/events` returns account events for the last **90 days**, filtered by the caller's permissions (`events:read_only` scope). Cloud Firewall reads use `firewall:read_only`.
  - **Audit logs** (time-stamped JSONL records of APIv4 operations and login events) are in **limited availability**.
  - Sources: [List events](https://techdocs.akamai.com/linode-api/reference/get-events); [Firewalls audit logs (LA)](https://techdocs.akamai.com/cloud-computing/docs/firewalls-audit-logs)
- **OVHcloud:**
  - Account logs can be forwarded to Logs Data Platform at three levels: **Audit** (logins, password changes), **Access policy** (IAM allow and deny decisions) and **Activity** (all API calls and Control Panel actions).
  - Subscriptions are created with `POST /me/logs/audit/log/subscription` and `POST /iam/log/subscription`.
  - Forwarding is free; LDP storage is billed.
  - Source: [OVHcloud: account logs with LDP](https://docs.ovhcloud.com/en/guides/manage-and-operate/iam/logs-forwarding)

### Inferences
- **What a VPS-only customer can realistically monitor from the master server**, using read-only provider tokens that are stored on the master server and never on the monitored host:
  - (1) **Firewall drift**: DigitalOcean Cloud Firewalls, Hetzner Firewalls, Linode Cloud Firewall. Alert on rules opening 22, 2375/2376, database ports, or 0.0.0.0/0.
  - (2) **Snapshot and backup posture and recency**, which supports ransomware recovery.
  - (3) **Inventory drift**: new Droplets, servers or Linodes, volumes, or API tokens. Attackers holding stolen tokens commonly spin up miners. On DigitalOcean the token and team events are not API-visible, so the agent can only diff inventory.
  - (4) **Provider events** where available: Linode 90-day events, OVH LDP audit and activity streams, Hetzner per-resource actions such as `rebuild`, `enable_rescue` or `reset_password` on a server, which are high-signal events for console-level compromise.
  - (5) For AWS customers, ingest CloudTrail and GuardDuty findings rather than rebuilding them.
- Use Prowler (Apache-2.0) for AWS, Azure, GCP and Kubernetes customers in the later phase. For DigitalOcean, Hetzner and Linode, write native Go checks against their official APIs. Steampipe's Apache-2.0 plugins can be studied, but the AGPL Steampipe engine shouldn't be embedded.
- **Autonomous cloud-side response** is possible but needs write tokens: attach a "quarantine" firewall, or snapshot before remediation. Keep these as master-server actions with human approval at first. A compromised host must never hold a token that can delete snapshots or create resources.
- Use Stratus Red Team (Apache-2.0) only for testing AWS, Azure and GCP detections. VPS control-plane detections need custom test scripts, for example creating and deleting a firewall rule through each provider's API.

### Gaps
- CloudTrail specifics (event-history retention, data-event costs) and GuardDuty foundational data sources were not re-verified in this pass.
- I couldn't confirm whether the DigitalOcean API exposes Droplet console or recovery-mode events, or whether any DigitalOcean audit-log API launched after July 2026.
- The OVH Steampipe plugin's existence and license were not confirmed (the request timed out). Vultr, Contabo, Scaleway and IONOS were not researched.
- No source was found describing Hetzner's or DigitalOcean's roadmap for audit logs.
