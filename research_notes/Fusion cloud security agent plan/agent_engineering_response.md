# Fusion Cloud Security Agent: Engineering the Agent, Response Engine and Control Plane (research notes, state as of 2026-11-09)

Scope: a commercial, lightweight Go agent for Linux cloud servers/VPS (Debian/Ubuntu via apt; RHEL, AlmaLinux, Rocky, Fedora, Amazon Linux 2023 via dnf), run as a systemd service, with a deterministic detection engine, a policy-controlled response engine, a company master server (intel + policies), Discord alerting/approvals, and an LLM layer that only investigates and recommends. Motivating incident: SSH compromise, a cryptominer with a watchdog, cron and systemd persistence, and replaced system binaries.

Conventions: "Cited Findings" are sourced facts (primary docs preferred; secondary sources are flagged). "Inferences" are design recommendations derived from those facts and are not themselves sourced claims. Licenses of Go libraries were checked against each project's LICENSE file on GitHub on 2026-11-09. The session's web-search budget ran out near the end of the research; anything not verified is listed under Gaps.

## 1. Safe response primitives on Linux, their risks, and how Wazuh, CrowdSec, Falco Talon, Tetragon and commercial EDRs implement them

### Takeaway
For watchdog-style miners, contain at the cgroup level. Freeze the whole tree with `cgroup.freeze`, neutralize persistence while it is frozen, then kill it with `cgroup.kill`, which handles concurrent forks. Per-PID SIGSTOP/SIGKILL races the watchdog. For the network, keep your own nftables table with timeout sets. A drop in any base chain is final even if firewalld accepts the packet. Add conntrack/socket teardown to cut flows that are already open. Account response takes several steps, because `passwd -l` and `usermod -L` do not stop SSH-key logins. The open-source responders are mostly timed "add/delete" scripts (Wazuh active response, CrowdSec bouncers). Falco Talon targets Kubernetes. Tetragon is the only one that enforces synchronously in the kernel. On Linux, Microsoft Defender for Endpoint (MDE) isolates hosts with iptables rules that keep only the vendor channel open. Those rules auto-expire, and any admin iptables change undoes them.

### Cited Findings

#### Process containment: kill vs freeze
- cgroup v2 freezer: writing "1" to `cgroup.freeze` "causes freezing of the cgroup and all descendant cgroups", and all processes "will be stopped and will not run until the cgroup will be explicitly unfrozen". Completion is shown by `frozen 1` in `cgroup.events`. "Processes in the frozen cgroup can be killed by a fatal signal". "If a process is moved to a frozen cgroup, it stops". Processes can enter or leave a frozen cgroup "either by an explicit move by a user, or if freezing of the cgroup races with fork()" — [Linux kernel cgroup-v2 docs](https://docs.kernel.org/admin-guide/cgroup-v2.html)
- `cgroup.kill`: writing "1" kills "all processes located in the affected cgroup tree ... via SIGKILL". "Killing a cgroup tree will deal with concurrent forks appropriately and is protected against migrations". It fails with EOPNOTSUPP in threaded cgroups — [kernel cgroup-v2 docs](https://docs.kernel.org/admin-guide/cgroup-v2.html)
- `cgroup.kill` was introduced in Linux 5.14 — [Kernelnewbies Linux 5.14](https://kernelnewbies.org/Linux_5.14). The cgroup v2 freezer arrived in Linux 5.2 ("tasks can be killed, ptrace works, there is no separate controller"). The same release added `CLONE_PIDFD` for race-free use with `pidfd_send_signal(2)` — [Kernelnewbies Linux 5.2](https://kernelnewbies.org/Linux_5.2)
- `pids.max`: fork/clone returns -EAGAIN when a new process would violate the limit ("it is not possible to violate a cgroup PID policy through fork() or clone()"), but migrations can push `pids.current` above `pids.max` — [kernel cgroup-v2 docs](https://docs.kernel.org/admin-guide/cgroup-v2.html)
- `memory.high` throttles and "never invokes the OOM killer". `memory.max` invokes the OOM killer inside the cgroup — [kernel cgroup-v2 docs](https://docs.kernel.org/admin-guide/cgroup-v2.html)
- `pidfd_send_signal()` lets a caller avoid races in which the target PID has been recycled for another process — [pidfd_send_signal(2)](https://man7.org/linux/man-pages/man2/pidfd_send_signal.2.html)
- `systemctl freeze` (systemd 246+) uses the cgroup freezer, works only on the unified hierarchy, and the "Unit is automatically thawed just before we execute a job against the unit, e.g. before the unit is stopped". `systemctl kill --kill-whom=` accepts `main`, `control`, `cgroup` or `all` — [systemctl(1)](https://man7.org/linux/man-pages/man1/systemctl.1.html)

#### Persistence removal: cron, systemd, immutable bits, replaced binaries
- `systemctl mask` links units to /dev/null and "prohibits all kinds of activation". It creates the symlink in /etc/systemd/system (or /run/systemd/system with `--runtime`), and "If a matching unit file already exists under these directories this operation will hence fail", so mask is "primarily useful to mask units shipped by the vendor" — [systemctl(1)](https://man7.org/linux/man-pages/man1/systemctl.1.html)
- Per-user crontab spools differ by family. Debian `cron` uses /var/spool/cron/crontabs ("not intended to be edited directly") — [Debian crontab(1)](https://manpages.debian.org/bookworm/cron/crontab.1.en.html). cronie (RHEL family) uses /var/spool/cron — [cronie crontab(1)](https://man7.org/linux/man-pages/man1/crontab.1.html)
- `chattr +i`: an immutable file cannot be modified, deleted, renamed or linked. "Only the superuser or a process possessing the CAP_LINUX_IMMUTABLE capability can set or clear this attribute" — [chattr(1)](https://man7.org/linux/man-pages/man1/chattr.1.html)
- The March 2026 trojanized Trivy binary created a systemd **user** service (`sysmon.py`) for persistence on non-CI hosts — [Wiz](https://www.wiz.io/blog/trivy-compromised-teampcp-supply-chain-attack). Persistence sweeps must therefore cover per-user units, not just system units.
- perfctl (Aqua Nautilus, Oct 2024) replaced `ldd`, `top`, `crontab` and `lsof` with trojanized versions and hooked libpcap and PAM functions. The recommended mitigations included mounting /tmp and /dev/shm `noexec` — [Aqua](https://www.aquasec.com/blog/perfctl-a-stealthy-malware-targeting-millions-of-linux-servers/), [BleepingComputer](https://www.bleepingcomputer.com/news/security/linux-malware-perfctl-behind-years-long-crypto-mining-campaign/)

#### Blocking execution
- `FAN_OPEN_EXEC_PERM` (Linux 5.0+) raises a permission event when a file is opened for execution (`execve`, `execveat`, `uselib`). It needs a `FAN_CLASS_CONTENT` or `FAN_CLASS_PRE_CONTENT` group — [fanotify_mark(2)](https://man7.org/linux/man-pages/man2/fanotify_mark.2.html)
- The listener replies `FAN_ALLOW` or `FAN_DENY`, and a denied caller gets EPERM. Since Linux 6.13, `FAN_CLASS_PRE_CONTENT` groups can return EIO, EBUSY, ETXTBSY and other errnos via `FAN_DENY_ERRNO` — [fanotify(7)](https://man7.org/linux/man-pages/man7/fanotify.7.html)

#### Network blocking
- nftables verdicts across base chains on the same hook: "an accept verdict ... isn't necessarily final", while "drops take immediate effect, with no further rules or chains being evaluated". Two base chains with the same priority have "no guaranteed evaluation order" — [nftables wiki: Configuring chains](https://wiki.nftables.org/wiki-nftables/index.php/Configuring_chains)
- Sets take `flags timeout`, per-element timeouts, `size` and `gc-interval`. The man page advises giving sets a maximum size and elements a timeout "so their number will not grow indefinitely". Timed-out entries remain until garbage collection, so a set "can not accept more elements, even if all elements timed out, if the gc-interval is set too large" — [nft(8)](https://www.netfilter.org/projects/nftables/manpage.html)
- firewalld's nftables backend keeps its rules in its own table and no longer flushes the whole ruleset — [firewalld.org](https://firewalld.org/2018/07/nftables-backend). A newer firewalld (v2.2.0 "table ownership" patch carried in AlmaLinux c9s) keeps `nft flush ruleset` from flushing firewalld's table — [AlmaLinux firewalld patch](https://git.almalinux.org/rpms/firewalld/src/branch/c9s/0020-v2.2.0-feat-nftables-table-ownership.patch). Some users report conflicts and advise running only one firewall manager per RHEL host — [Rocky forum](https://forums.rockylinux.org/t/rocky-9-5-breaks-netfilter/16551)
- `conntrack -D` deletes connection-tracking entries — [conntrack(8)](https://manpages.debian.org/bookworm/conntrack/conntrack.8.en.html). `ss -K` "attempts to forcibly close sockets" for IPv4/IPv6 and silently skips sockets the kernel cannot close — [ss(8)](https://man7.org/linux/man-pages/man8/ss.8.html)

#### Accounts and SSH keys
- `passwd -l` "does not disable the account. The user may still be able to login using another authentication token (e.g. an SSH key). To disable the account, administrators should use usermod --expiredate 1" (an expiry of 1970-01-02) — [passwd(1)](https://man7.org/linux/man-pages/man1/passwd.1.html)
- `usermod -L` puts "!" in front of the password hash. `usermod -e` sets the expiry date, and -1 or an empty string clears it — [usermod(8)](https://man7.org/linux/man-pages/man8/usermod.8.html)
- `loginctl terminate-user` "kills all processes of all sessions of the user" — [loginctl(1)](https://man7.org/linux/man-pages/man1/loginctl.1.html)
- sshd `RevokedKeys` accepts a text file or an OpenSSH KRL. "If this file is not readable, then public key authentication will be refused for all users". It "may be consulted for each public key authentication attempt" and should only be replaced atomically. The default `AuthorizedKeysFile` is `.ssh/authorized_keys .ssh/authorized_keys2`. `AuthorizedKeysCommand` runs only after the files produce no match. `DenyUsers` refuses matching users even if `AllowUsers` would permit them — [sshd_config(5)](https://man.openbsd.org/sshd_config)

#### How existing tools implement response
- **Wazuh active response (AR).**
  - Default Linux scripts: disable-account, firewall-drop (iptables), firewalld-drop, host-deny (/etc/hosts.deny), ip-customblock, ipfw, npf, pf, wazuh-slack, restart.sh, restart-wazuh, route-null and kaspersky — [Wazuh default AR scripts](https://documentation.wazuh.com/current/user-manual/capabilities/active-response/default-active-response-scripts.html)
  - Protocol: each script reads one JSON message on STDIN with `version`, `origin`, `command` (`add` or `delete`) and `parameters.{extra_args, alert, program}`. Before acting, a stateful script sends `check_keys` with keys from the alert (for example the source IP) and gets back `continue` or `abort`. `abort` is used, for example, when the action "is repeating a previous active response action that hasn't timed out yet". The timeout is set by `<timeout>` in the server's `<active-response>` block, and a missing newline on STDOUT "might" deadlock — [Wazuh custom AR scripts](https://documentation.wazuh.com/current/user-manual/capabilities/active-response/custom-active-response-scripts.html)
  - Responses are stateless or stateful (auto-revert), and Wazuh warns that "poorly designed rules and responses can increase endpoint vulnerability" — [Wazuh AR overview](https://documentation.wazuh.com/current/user-manual/capabilities/active-response/index.html)
  - License: GPLv2, with the new engine under AGPL-3.0-or-later and some shared libraries under GPL-2.0-only OR AGPL-3.0-or-later — [Wazuh LICENSE](https://github.com/wazuh/wazuh/blob/main/LICENSE)
- **CrowdSec firewall bouncer** ("remediation component").
  - Modes: iptables, nftables, ipset or pf. "Managed" mode creates the sets and rules itself. "Set-only" mode fills sets you created, and its example nftables sets use `flags timeout`.
  - It polls the Local API at `update_frequency`. `deny_action` is `DROP` (default) or `REJECT`. It supports IPv4 and IPv6, and caps ipset timeouts at 2147482 s — [CrowdSec docs](https://docs.crowdsec.net/u/bouncers/firewall/)
  - License: MIT, for both the bouncer and CrowdSec — [bouncer LICENSE](https://github.com/crowdsecurity/cs-firewall-bouncer/blob/main/LICENSE), [CrowdSec LICENSE](https://github.com/crowdsecurity/crowdsec/blob/master/LICENSE)
- **Falco Talon.**
  - A "Response Engine for managing threats in your Kubernetes". Apache-2.0, status "incubating" — [GitHub](https://github.com/falcosecurity/falco-talon)
  - Actionners: `kubernetes:terminate` (`grace_period_seconds`, `ignore_daemonsets`, `ignore_statefulsets`, `min_healthy_replicas`), `kubernetes:label`/`annotation`, `kubernetes:networkpolicy` (blocks all pod egress except `allow_cidr`/`allow_namespaces`), `kubernetes:exec`/`script`/`log`/`download`/`tcpdump`/`delete`/`cordon`/`drain`/`sysdig`, `calico:networkpolicy`, `cilium:networkpolicy`, `aws:lambda` and `gcp:function` — [Talon actionners](https://falco-talon.github.io/docs/actionners/list/)
- **Tetragon.**
  - Enforcement happens "in the kernel inline with the operation itself". Override is limited to "system calls and security check functions". SIGKILL terminates synchronously but "does not guarantee that the data will not be written" when sent during `write()`, so it should be combined with Override — [Tetragon enforcement](https://tetragon.io/docs/concepts/enforcement/)
  - Override requirements: `CONFIG_BPF_KPROBE_OVERRIDE` and functions marked `ALLOW_ERROR_INJECTION`. `security_` hooks can be overridden from kernel 5.7.
  - `NotifyEnforcer` serves kernels without multi-kprobe support (raw syscall tracepoint), and only one enforcer definition is allowed.
  - Only the Post action has `rateLimit`, scoped per thread, process or global — [Tetragon selectors](https://tetragon.io/docs/concepts/tracing-policy/selectors/)
  - License: Apache-2.0 — [Tetragon LICENSE](https://github.com/cilium/tetragon/blob/main/LICENSE)
- **Microsoft Defender for Endpoint (MDE) on Linux.** Source: [Microsoft Learn, updated 2026-11-04](https://learn.microsoft.com/en-us/defender-endpoint/respond-machine-alerts)
  - Network isolation works on all supported Linux versions.
  - Prerequisites: iptables, ip6tables, `CONFIG_NETFILTER` and the owner match (`CONFIG_NETFILTER_XT_MATCH_OWNER` on 5.x+ kernels).
  - Isolation "disconnects the compromised device from the network while retaining connectivity to the Defender for Endpoint service".
  - Exclusions are not supported on Linux.
  - "An isolated device is removed from isolation when an administrator modifies or adds a new iptable rule".
  - Isolation lifts automatically after 7 days. If a device is offline, the action is retried for up to 3 days.
  - Operators need the "Active remediation actions" role. Full-tunnel VPNs break the service connection.
  - Automatic isolation ("attack disruption") "works only on end-user workstations".
- **SentinelOne.** Network Quarantine disconnects the endpoint, with configurable allow rules. Locally, `sentinelctl unquarantine_net -k <passphrase>` releases it — [SonicWall KB, third-party](https://www.sonicwall.com/support/knowledge-base/sentinelone-s1-manually-restore-network-connectivity/241205152755593). Health check: `sentinelctl management status` — [GitLab handbook](https://handbook.gitlab.com/handbook/security/corporate/systems/sentinelone/troubleshooting)
- **CrowdStrike.** Only the sensor's cloud allowlist was found (TLS 1.2+ on 443 to cloudsink.net and crowdstrike.com hosts) — [Dell KB mirror of Falcon requirements](https://www.dell.com/support/kbdoc/en-uk/000177899/crowdstrike-falcon-sensor-system-requirements)

#### Go libraries for these primitives (licenses verified)
- google/nftables: Apache-2.0 — [LICENSE](https://github.com/google/nftables/blob/main/LICENSE)
- ti-mo/conntrack: MIT — [LICENSE](https://github.com/ti-mo/conntrack/blob/master/LICENSE)
- florianl/go-conntrack: MIT — [LICENSE](https://github.com/florianl/go-conntrack/blob/main/LICENSE)
- mdlayher/netlink: MIT — [LICENSE](https://github.com/mdlayher/netlink/blob/main/LICENSE.md)
- godbus/dbus: BSD-2-Clause — [LICENSE](https://github.com/godbus/dbus/blob/master/LICENSE)
- coreos/go-systemd: Apache-2.0 — [LICENSE](https://github.com/coreos/go-systemd/blob/main/LICENSE)
- cilium/ebpf: MIT — [LICENSE](https://github.com/cilium/ebpf/blob/main/LICENSE)

### Inferences

**Containment playbook for the motivating incident (watchdog miner with cron/systemd persistence, replaced binaries, SSH entry).** Order matters. Every step writes an undo record before it runs.

1. **Snapshot evidence** (read-only). Capture the process tree (`/proc/*/stat`, `cmdline`, `environ`, `exe` link, `maps`, open fds, cgroup path), sockets, recent auth events, and hashes of each `/proc/<pid>/exe`. Copy deleted-but-running binaries from `/proc/<pid>/exe`.
2. **Freeze the whole suspect tree.** Create a quarantine cgroup inside the agent's delegated subtree, for example `/sys/fs/cgroup/system.slice/fusion-agent.service/quarantine/<incident>`. This needs `Delegate=yes`, or else a separate `fusion-quarantine.slice`. Set `pids.max=0`, write `1` to `cgroup.freeze`, then migrate the suspect PIDs by writing to `cgroup.procs`, parents first, re-scanning until the set is stable.
   - Why not freeze the source cgroup: cron-spawned malware lives in `cron.service` (Debian) or `crond.service` (RHEL), and freezing or killing that unit would also hit legitimate jobs and the cron daemon.
   - Use pidfds to avoid PID-reuse mistakes. Prefer the freezer over SIGSTOP: a stopped child is visible to its watchdog parent (via `SIGCHLD`/`waitpid`), and any process with permission can resume it with SIGCONT, whereas the frozen state is controlled only through the cgroup file. This is an inference from POSIX job-control semantics; test it.
   - If the malware runs as its own systemd unit, `systemctl freeze <unit>` is simpler. Remember systemd auto-thaws a unit before a stop job.
3. **Neutralize persistence while frozen.**
   - System and user cron: /etc/crontab, /etc/cron.d, /etc/cron.{hourly,daily,weekly,monthly}, anacrontab, the user spool (Debian /var/spool/cron/crontabs/<user>, RHEL /var/spool/cron/<user>) and at jobs.
   - systemd: system units and timers in /etc/systemd/system and /run, drop-ins, generators, and user units in `~/.config/systemd/user` (the Trivy trojan used this). Use stop, disable, move the unit file to the vault, then mask. mask fails while the file still exists in /etc.
   - Other hooks: rc.local, /etc/profile.d, shell rc files, `/etc/ld.so.preload`, and authorized_keys.
   - Run `chattr -i` first where the attacker set immutable bits, and record that you did.
4. **Block C2 and mining-pool endpoints** in the nftables timeout sets (snippet below). Flush matching conntrack entries and run `ss -K` on live sockets.
5. **Kill the tree** with `echo 1 > cgroup.kill` (SIGKILL, fork-safe), then remove the empty cgroup.
6. **Quarantine the dropped binaries** (vault design below).
7. **Repair replaced system binaries.** Do not just quarantine them, because that breaks the OS. Compare them against known-good hashes taken from signed package metadata or the master server's hash database. Do not trust the local `dpkg`/`rpm` database or `debsums`/`rpm -Va` alone: on-host root can alter them, and those tools may themselves be trojanized. Then run `apt-get install --reinstall <pkg>` or `dnf reinstall <pkg>` from signed repos, which needs approval.
8. **Watch for respawn** for N minutes (hash, path and cmdline heuristics), then report.
9. **Recommend credential rotation and SSH key revocation** through the approval flow.

**nftables design.** Use a dedicated `table inet fusion` and never touch other tables, which avoids fights with firewalld or ufw. Because drop is final across base chains, the agent's drops take effect even when firewalld's chain accepts the packet. Example:
  ```
  table inet fusion {
    set block4 { type ipv4_addr; flags timeout; size 65536; }
    set block6 { type ipv6_addr; flags timeout; size 65536; }
    set mgmt4  { type ipv4_addr; flags interval; }   # control plane, bastions (used by isolation mode)
    chain in  { type filter hook input   priority -5; policy accept; ip saddr @block4 drop; ip6 saddr @block6 drop; }
    chain out { type filter hook output  priority -5; policy accept; ip daddr @block4 drop; ip6 daddr @block6 drop; }
    chain fwd { type filter hook forward priority -5; policy accept; ip saddr @block4 drop; ip daddr @block4 drop; ip6 saddr @block6 drop; ip6 daddr @block6 drop; }
  }
  nft add element inet fusion block4 '{ 203.0.113.7 timeout 24h }'
  conntrack -D -s 203.0.113.7; conntrack -D -d 203.0.113.7; ss -K dst 203.0.113.7
  ```
  - Implement this with google/nftables (Apache-2.0) and ti-mo/conntrack (MIT) over netlink rather than shelling out.
  - Re-assert the table on start, after firewalld reloads, and when a netlink monitor sees the table deleted. MDE's isolation silently ends when an admin edits iptables, which is a known weakness to avoid.
  - Every element gets a TTL, and permanent blocks still get a maximum TTL that the policy renews.
  - Never insert control-plane, gateway, DNS-resolver or allow-listed admin CIDRs into block sets. Enforce that in the policy engine, not only in the UI.

**Host isolation that keeps management access.** Add a separate `isolate` chain set (input/output/forward, `policy drop`) that allows:
  - loopback and established/related traffic;
  - TCP/443 to pinned control-plane IPs, resolved at isolation time so isolation does not depend on DNS;
  - SSH from the bastion/admin CIDRs only;
  - DHCP and ICMPv6 neighbour discovery and router advertisements, to keep the interface alive;
  - optionally NTP and the configured resolvers.

  Treat the cloud metadata endpoint (169.254.169.254) as an explicit policy choice. Cloud guest agents need it, but attackers steal credentials from it. Persist the isolation state on disk and re-apply it at boot. Offer a maximum duration with alerting, as MDE does (7 days), but do not auto-release just because the agent lost contact with the server; an attacker could trigger that.

**Container isolation.** Either enter the container's network namespace (`/proc/<pid>/ns/net`) and install the same `inet fusion` table there, or drop the container's IP/veth traffic in the host `forward` chain. On Kubernetes, use a deny-egress NetworkPolicy like Talon's `kubernetes:networkpolicy`. Docker's own iptables-nft rules cannot override the agent's drops.

**Account and SSH response (approval-gated by default).**
  1. Capture `sshd -T` (effective config) and every authorized_keys file.
  2. Run `usermod -e 1` (blocks key-based logins; `-L` alone does not) plus `usermod -L`.
  3. Add the attacker key(s) to a root-owned `RevokedKeys` file referenced from a drop-in such as `/etc/ssh/sshd_config.d/00-fusion.conf`. Replace the file atomically, because an unreadable file disables public-key auth for everyone.
  4. Remove the key line from authorized_keys (keep a backup; clear `chattr +i` first).
  5. Run `sshd -t` before reloading. The unit is `ssh.service` on Debian/Ubuntu and `sshd.service` on RHEL.
  6. Run `loginctl terminate-user` and kill any leftover processes.
  7. Never lock the last administrative path without a break-glass account.

**Quarantine vault.**
  - Location: `/var/lib/fusion/quarantine` (0700 root). The original file is opened `O_NOFOLLOW` (or with `openat2` and `RESOLVE_NO_SYMLINKS`; verify kernel support). Hash the open fd (SHA-256, plus SHA-1 and MD5 for intel matching), then rename within the same filesystem, or copy, fsync and unlink across filesystems after re-checking the inode (prevents TOCTOU and symlink tricks).
  - Store the content wrapped (AES-GCM or XOR) with mode 0400 so it can never execute and other AV tools will not re-detect it.
  - Record metadata: path, dev and inode, mode, uid/gid, size, timestamps, xattrs (`security.selinux`, `security.capability`), ACLs, chattr flags, owning package and its verification result, the PIDs that had it open, and the incident ID.
  - Restore re-applies mode, owner, xattrs and SELinux label, or runs `restorecon`. ctime cannot be restored.
  - fanotify `FAN_OPEN_EXEC_PERM` can additionally deny re-execution of known-bad hashes, but a hung permission listener blocks every exec on the watched mount. Keep the handler tiny, give it a watchdog, and fail open with an alert.

**Protected-target list** (enforced in the actuator itself, not only in policy). Match by cgroup, path, package ownership and hash, never by process name alone, since malware masquerades as kworker and similar names. Protect:
  - PID 1, kernel threads, and the agent's own cgroup;
  - systemd-journald, udevd, logind and dbus;
  - the sshd listener (session children are allowed targets);
  - containerd, dockerd and runc shims;
  - cloud guest agents (amazon-ssm-agent, google-guest-agent, waagent, qemu-ga);
  - package managers mid-transaction (dpkg, apt, rpm, dnf);
  - databases, unless the policy explicitly allows them.

**Rollback.** Write an undo journal entry before each action. Examples: `nft delete element`, `systemctl unmask` and restore the unit file, re-insert a crontab line, restore a file from the vault, `usermod -U` and `-e ''`, remove a RevokedKeys line, release isolation. After a crash, the agent reconciles half-done actions on restart.

**Distro differences to handle at runtime.** Cron spool paths differ. ssh unit names differ. RHEL-family usually runs firewalld (nftables backend), while Debian/Ubuntu may run ufw or iptables-nft. SELinux (RHEL) vs AppArmor (Debian/Ubuntu) changes file-label restoration on restore.

**Licensing note.** Do not copy Wazuh code into a proprietary agent (GPLv2/AGPLv3). Using CrowdSec (MIT) and the MIT/Apache Go netlink libraries is fine.

### Gaps
- CrowdStrike Falcon network containment for Linux (mechanism, allowlist behaviour, auto-expiry): no primary source was found. Only sensor connectivity requirements were.
- SentinelOne's official Linux network-quarantine documentation was not reachable. The findings rely on third-party KB articles.
- Wazuh `<active-response>` options (`location`: local/server/defined-agent/all, `repeated_offenders`): the reference page could not be fetched (domain check failed), so they are not cited here.
- Whether `usermod -e 1` blocks SSH key logins on every target distro depends on PAM/sshd account checks. The passwd(1) man page recommends it, but no distro-by-distro test was found.
- Behaviour of moving processes out of systemd-managed cgroups into an agent-managed subtree, and how systemd reacts, was not verified against systemd's cgroup delegation docs. Test on Debian 12/13, Ubuntu 22.04/24.04, RHEL 9/10 and AL2023.
- Is `openat2` with `RESOLVE_NO_SYMLINKS` available on every target kernel (RHEL 8 is on 4.18)? Not verified.

## 2. Policy engine for "which actions are allowed": OPA/Rego, Cedar, CEL, expr; response levels, thresholds, dry-run, cooldowns, kill switch, exclusions, tamper-evident audit log

### Takeaway
All four engines are permissively licensed and embed in Go:
- **OPA**: Apache-2.0; the most expressive, but heavier.
- **Cedar**: Apache-2.0; purpose-built for "principal / action / resource" authorization, though cedar-go lacks a schema validator and partial evaluation.
- **CEL**: Apache-2.0; non-Turing-complete, with linear-time evaluation.
- **expr**: MIT; fast, side-effect-free, and already used by CrowdSec.

A pragmatic split: CEL (or expr) in the agent to gate actions; Cedar or OPA on the control plane to decide which human or service may approve which action on which host group. Policy itself should be data that is signed, versioned and dry-runnable. Audit records should be hash-chained, checkpoints signed and shipped off-host (the journald FSS model), and anchored server-side.

### Cited Findings
- **OPA**
  - License: Apache-2.0 — [OPA LICENSE](https://github.com/open-policy-agent/opa/blob/main/LICENSE)
  - Performance guidance — [OPA policy performance docs](https://www.openpolicyagent.org/docs/policy-performance):
    - In the "linear fragment", adding rules does "not significantly increase the evaluation time". Rule indexing covers equality, glob, prefix/suffix and `in`; negations are never indexed.
    - An example `opa bench` run on an RBAC policy took about 45 µs per operation.
    - "Policy evaluation is currently single-threaded", and in embedded use "it is your responsibility to dispatch concurrent queries".
    - Raw JSON data uses about 20x more memory than its serialized size. 10,000 ACL-style rules take about 130 MB, and 100,000 rules about 1.1 GB.
    - Set `GOMEMLIMIT` slightly below the container's memory limit. The page states that since Go 1.25, GOMAXPROCS follows the cgroup CPU quota (minimum 2).
  - Governance: on 2025-08-20 the OPA creators announced that they and other Styra developers were joining Apple. OPA "remains a CNCF graduated" project, and governance and licensing are unchanged — [OPA blog](https://openpolicyagent.org/blog/note-from-teemu-tim-and-torin-to-the-open-policy-agent-community-2dbbfe494371), [Oso](https://osohq.com/post/opa-maintainers-join-apple-oss-community-to-maintain-styra-products)
  - Reports conflict on Styra's commercial products (open-sourced vs sunset). A single 2026 source says the Enterprise OPA (EOPA) repository was archived and donated to the community — [youngju.dev, 2026-07-17](https://www.youngju.dev/blog/2026-07-17-opa-post-styra-apple-acquihire-reality.en)
- **cedar-go** — [GitHub](https://github.com/cedar-policy/cedar-go)
  - Apache-2.0.
  - Includes the core authorizer, JSON marshalling, datetime/duration types, and schema parsing and construction.
  - Not yet included: the schema validator (experimental in `x/exp/schema`), the formatter, partial evaluation, and policy templates. Supports the two most recent Go versions.
  - API: `cedar.NewPolicySet()`, `ps.Add(...)`, `cedar.Authorize(ps, entities, cedar.Request{Principal, Action, Resource, Context})`.
- **cel-go** — [GitHub](https://github.com/google/cel-go)
  - Apache-2.0; canonical home now `cel.dev/cel-go` (source at `github.com/cel-expr/cel-go`).
  - "A non-Turing complete language". It "evaluates linearly with respect to the size of the expression and the input being evaluated when macros are disabled".
  - The compiled `cel.Program` is "stateless, thread-safe, and cachable", and parse/check costs more than evaluation.
  - API: `cel.NewEnv` → `env.Compile` → `env.Program` → `prg.Eval`.
- **expr-lang/expr** — [GitHub](https://github.com/expr-lang/expr)
  - MIT.
  - Memory-safe, side-effect-free, always terminating, statically typed. Optimizing compiler plus bytecode VM.
  - Users include Google, Uber, CrowdSec ("incorporates Expr into its security automation tool") and Argo.
- **Precedents for response levels and auto-expiry**
  - Wazuh separates stateless from stateful (auto-reverting) responses, uses a `<timeout>`, and has `check_keys`→`abort` to suppress repeats of an unexpired action — [Wazuh custom AR](https://documentation.wazuh.com/current/user-manual/capabilities/active-response/custom-active-response-scripts.html)
  - MDE isolation auto-lifts after 7 days, and MDE limits *automatic* isolation to end-user workstations — [Microsoft Learn](https://learn.microsoft.com/en-us/defender-endpoint/respond-machine-alerts)
- **Vendor "bounded autonomy"** (vendor-stated)
  - CrowdStrike says Charlotte AI Detection Triage "operates within a model of bounded autonomy, ensuring security teams maintain full oversight" — [CrowdStrike press release](https://www.crowdstrike.com/en-us/press-releases/crowdstrike-delivers-next-breakthrough-in-ai-powered-agentic-cybersecurity-with-charlotte-ai-detection-triage/)
  - CrowdStrike's Charlotte AI datasheet, as summarized in search results, says users define what gets automated, when and under what conditions (datasheet not opened directly) — [Charlotte AI datasheet](https://www.crowdstrike.com/content/dam/crowdstrike/marketing/en-us/documents/pdfs/data-sheets/crowdstrike-charlotte-ai-datasheet.pdf)
- **Tamper-evident logging precedent: systemd-journald Forward Secure Sealing (FSS)** — [journalctl(1)](https://www.freedesktop.org/software/systemd/man/latest/journalctl.html)
  - `journalctl --setup-keys` generates a sealing key that "shall remain on the host" and a verification key that "should be stored externally".
  - The sealing interval defaults to 15 min. "Shorter intervals increase CPU consumption but shorten the time range of undetectable journal alterations".
- **Transparency-log technology**: Rekor v2 moved to a tile-based backend using Trillian-Tessera — [Sigstore blog](https://blog.sigstore.dev/rekor-v2-ga/)

### Inferences

**Engine choice**

| Use | Engine | Why |
|---|---|---|
| In-agent action gating ("may action X run on target Y now?") | **CEL** (or expr) | Non-Turing-complete and linear-time, so a policy cannot hang the actuator. Programs are cacheable and thread-safe. Small dependency surface. |
| Detection-rule conditions | **expr** (or CEL) | Same evaluator family; CrowdSec precedent. Keep one language per layer. |
| Control-plane authorization (which operator or Discord role may approve which action on which host group; per-tenant RBAC) | **Cedar** | Principal/action/resource model. Use the Rust Cedar toolchain in CI to validate schemas until cedar-go ships its validator. |
| Server-side policies needing rich data joins | **OPA/Rego** | Expressive. Budget memory carefully (the OPA doc's numbers) and expect a maintainer shift to Apple-employed developers. |

**Action levels** (per action type, policy-controlled, signed):

| Level | Meaning | Typical actions |
|---|---|---|
| L0 `observe` | alert only | any |
| L1 `auto` | reversible, small blast radius, always with TTL | `net.block_ip` (TTL 24h), `process.freeze` |
| L2 `auto_with_policy` | needs policy match + confidence ≥ threshold + not excluded + inside budgets | `process.kill_tree`, `file.quarantine`, `cron.disable_entry`, `systemd.disable_mask` (attacker-created units only) |
| L3 `approval` | human approval (1 or 2 approvers), expiring | `host.isolate`, `account.lock`, `ssh.revoke_key`, `pkg.reinstall`, actions on package-owned files |
| L4 `forbidden` | never automated, CLI or dashboard only | permanent delete, reboot, bootloader or kernel changes, package removal, arbitrary script execution |

**Example policy document** (signed, versioned; conditions in CEL):
  ```yaml
  apiVersion: fusion.policy/v1
  kind: ResponsePolicy
  metadata: {name: linux-default, version: 42, signer: policy-key-2026a}
  spec:
    mode: enforce            # observe | dry_run | enforce
    automation_enabled: true # kill switch (fleet, group or host scope)
    budgets: {destructive_per_host_per_hour: 5, fleet_circuit_breaker: {same_rule_hosts: 20, window: 10m}}
    actions:
      process.kill_tree: {level: auto_with_policy, min_confidence: 0.90, cooldown: 10m,
                          when: 'det.family in ["coinminer","miner_watchdog"] && !target.protected'}
      file.quarantine:   {level: auto_with_policy, min_confidence: 0.95, when: '!target.package_owned'}
      net.block_ip:      {level: auto, ttl: 24h, max_ttl: 7d, when: '!(target.ip in policy.never_block)'}
      host.isolate:      {level: approval, approvers: 2, approval_ttl: 15m}
    exclusions:
      - {kind: path, value: /opt/backup/bin/rclone, expires: 2027-01-31, owner: ops-team, reason: "backup job"}
  ```

**Confidence** is computed deterministically: rule severity, an exact intel hash match from the master server, the number of corroborating signals (e.g., new-IP SSH login → download to /tmp → chmod +x → exec → outbound to a pool port → cron write), and target sensitivity. The LLM never sets it (see Section 8).

**Dry-run / shadow mode.** Evaluate everything and record "would have done X" decisions with the full policy trace. Ship new policies and content in dry-run first, and let customers promote them. A per-rule `mode` overrides the global one.

**Cooldowns and budgets.**
  - Per `(action, target)` cooldown, with de-duplication like Wazuh's `check_keys`.
  - A per-host budget for destructive actions.
  - A **fleet circuit breaker**: if one rule or content version triggers automated actions on more than N hosts (or X%) within T minutes, drop that rule to `approval` and page a human. This is the CrowdStrike lesson applied to response.

**Kill switch.**
  - Two scopes: "automation off" (everything becomes observe), and "sensor safe mode" (detach eBPF and fanotify hooks, keep heartbeats).
  - Both are signed server commands, plus a local root-only `fusionctl automation off` that is audited.
  - Fail safe: if the policy signature or version cannot be verified, the agent falls back to observe-only instead of acting on an unverified policy.

**Exclusions** are first-class signed objects: by hash, path + hash, process (path + user + cgroup/unit), container image digest, CIDR, user, or host group. Each has an owner, a reason and a mandatory expiry. They are evaluated in the agent before any action.

**Hash-chained audit log** (agent and server).
  - Record: `{seq, ts, prev_hash, actor (rule|policy|human:<id>|ai-recommendation), action, target, inputs_digest, policy_version, decision, result, undo_ref}`, with `hash = SHA-256(prev_hash || canonical_json(record))`.
  - Every 100 records or 60 s, sign a checkpoint `{agent_id, seq, head_hash}` with the agent's Ed25519 key. Ship the checkpoint with the heartbeat so the server sees chain continuity and gaps immediately (the FSS "verification key off-host" principle).
  - Server side: an append-only table (no UPDATE/DELETE grants) with its own chain, periodically anchored to an external WORM or transparency-log store (Trillian-Tessera-style tiles).
  - Local files can additionally get the append-only attribute (`chattr +a`); this is a speed bump against root, not a guarantee.

### Gaps
- CEL's runtime cost-limit and cost-estimation APIs (used by Kubernetes) are not described on the cel-go README; check the cel-go docs before relying on them.
- No independent, recent head-to-head benchmark of OPA vs CEL vs expr vs cedar-go was found. The README performance claims are qualitative.
- Cedar's foundation status (e.g., a CNCF sandbox application) and cedar-go's maintainers were not confirmed.
- No vendor documentation was found describing *how* commercial EDRs implement per-action confidence thresholds. The level design above is an inference.

## 3. Agent architecture in Go: telemetry pipeline, local rules and correlation, offline buffering, resource limits, event schema, transport, enrollment and identity, heartbeat, central storage

### Takeaway
Build a single static Go binary with two processes: a privileged core (collectors + actuator, no network listener) and an unprivileged uplink/analysis process. Feed eBPF, audit and fanotify events through a normalize → enrich → match → correlate pipeline. Spool to bbolt or pure-Go SQLite with priority-aware eviction. Hard-cap resources with systemd cgroup settings plus GOMEMLIMIT (Go 1.25+ respects CPU quota). Use an internal protobuf schema and map to OCSF for export. Transport is gRPC bidirectional streaming over mTLS on 443, with command envelopes signed separately from TLS. Store incidents and policy in PostgreSQL and high-volume telemetry in ClickHouse (both permissively licensed).

### Cited Findings
- **Embedded stores (licenses verified)**
  - etcd-io/bbolt: MIT — [LICENSE](https://github.com/etcd-io/bbolt/blob/main/LICENSE)
  - Badger (now hypermodeinc/badger): Apache-2.0 — [LICENSE](https://github.com/hypermodeinc/badger/blob/main/LICENSE)
  - mattn/go-sqlite3: MIT — [LICENSE](https://github.com/mattn/go-sqlite3/blob/master/LICENSE)
  - modernc.org/sqlite (pure Go, hosted on GitLab): BSD-style — [LICENSE](https://gitlab.com/cznic/sqlite/-/raw/master/LICENSE)
  - cockroachdb/pebble: BSD-3-Clause — [LICENSE](https://github.com/cockroachdb/pebble/blob/master/LICENSE)
- **Resource control**
  - systemd `CPUQuota=` uses the cpu controller. `MemoryHigh=` is a "throttling limit". `MemoryMax=` is the "absolute limit". `TasksMax=` uses the pids controller — [systemd.resource-control(5)](https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html)
  - Kernel semantics: memory.high never OOM-kills; memory.max OOM-kills inside the cgroup — [kernel docs](https://docs.kernel.org/admin-guide/cgroup-v2.html)
  - Go 1.25 (blog of 2025-08-20) defaults GOMAXPROCS to the cgroup CPU bandwidth limit when it is below the core count. It rounds up (2.5 CPUs gives 3), re-checks periodically, and applies only when GOMAXPROCS is unset and go.mod says ≥1.25. CPU requests/weights are ignored — [Go blog](https://go.dev/blog/container-aware-gomaxprocs)
  - OPA's guidance: set GOMEMLIMIT slightly below the hard memory limit — [OPA docs](https://www.openpolicyagent.org/docs/policy-performance)
- **Event schemas**
  - OCSF is Apache-2.0 — [ocsf-schema LICENSE](https://github.com/ocsf/ocsf-schema/blob/main/LICENSE)
  - A Remediation category (ID 7) arrived in OCSF 1.3.0, with File, Process and Network Remediation Activity classes — [Tenzir OCSF reference](https://docs.tenzir.com/reference/ocsf/1-3-0/classes/remediation_activity), [Query.ai](https://query.ai/resources/blogs/whats-new-in-ocsf-1-3)
  - OCSF 1.7.0 has 83 event classes — [Tenzir](https://docs.tenzir.com/reference/ocsf/1-7-0). 1.9.0-dev exists — [LinkML OCSF](https://lmodel.github.io/ocsf/elements/)
  - OCSF joined the Linux Foundation (announced in a Splunk blog of 2024-11-19) — [Splunk](https://www.splunk.com/en_us/blog/security/ocsf-joins-the-linux-foundation-with-splunk-support.html)
  - ECS is Apache-2.0 — [ECS LICENSE](https://github.com/elastic/ecs/blob/main/LICENSE.txt). Elastic and OpenTelemetry announced the convergence of ECS into OTel Semantic Conventions "so that OpenTelemetry Semantic Conventions truly is a successor" of ECS — [OpenTelemetry blog](https://opentelemetry.io/blog/2023/ecs-otel-semconv-convergence/)
- **Transports (licenses verified)**
  - grpc-go: Apache-2.0 — [LICENSE](https://github.com/grpc/grpc-go/blob/master/LICENSE)
  - connect-go: Apache-2.0 — [LICENSE](https://github.com/connectrpc/connect-go/blob/main/LICENSE)
  - nats-server and nats.go: Apache-2.0 — [nats-server](https://github.com/nats-io/nats-server/blob/main/LICENSE), [nats.go](https://github.com/nats-io/nats.go/blob/main/LICENSE)
  - eclipse-paho/paho.mqtt.golang: EPL-2.0 — [LICENSE](https://github.com/eclipse-paho/paho.mqtt.golang/blob/master/LICENSE)
  - mochi-mqtt/server: MIT — [LICENSE](https://github.com/mochi-mqtt/server/blob/main/LICENSE.md)
- **NATS licensing scare (2025)**
  - In April 2025 Synadia sought to reclaim NATS from CNCF and move it toward a non-open-source license (the Business Source License). CNCF responded publicly and petitioned to cancel Synadia's trademarks — [CNCF blog, 2025-04-24](https://www.cncf.io/blog/2025/04/24/protecting-nats-and-the-integrity-of-open-source-cncfs-commitment-to-the-community/), [The New Stack](https://thenewstack.io/synadia-attempts-to-reclaim-nats-back-from-cncf/)
  - On 2025-05-01 CNCF and Synadia agreed: Synadia assigns its two NATS trademarks to the Linux Foundation, and CNCF keeps the repositories and domain "under the Apache 2.0 license" — [CNCF](https://www.cncf.io/announcements/2025/05/01/cncf-and-synadia-align-on-securing-the-future-of-the-nats-io-project/), [InfoQ](https://www.infoq.com/news/2025/05/nats-cncf-open-source)
  - Coverage of the dispute quotes Synadia's position that "An Apache 2.0 licensed server version will always remain available and supported". The exact originating page was not confirmed — [Synadia response](https://www.synadia.com/blog/synadia-response-to-cncf), [InfoQ](https://www.infoq.com/news/2025/05/nats-cncf-open-source)
- **Telemetry libraries**
  - cilium/ebpf: MIT — [LICENSE](https://github.com/cilium/ebpf/blob/main/LICENSE)
  - elastic/go-libaudit: Apache-2.0 — [LICENSE](https://github.com/elastic/go-libaudit/blob/master/LICENSE.txt)
  - Tetragon: Apache-2.0 — [LICENSE](https://github.com/cilium/tetragon/blob/main/LICENSE)
- **Central storage**
  - ClickHouse: Apache-2.0 — [LICENSE](https://github.com/ClickHouse/ClickHouse/blob/master/LICENSE). OpenSearch: Apache-2.0 — [LICENSE](https://github.com/opensearch-project/OpenSearch/blob/main/LICENSE.txt)
  - TimescaleDB ships an Apache-2 Edition and a Community Edition under the Timescale License (TSL). TSL "prevents third parties from selling TimescaleDB Community Edition as a service", and "Many of the most recent features ... are only available in TimescaleDB Community Edition". `SHOW timescaledb.license;` shows which edition is active — [Tiger Data docs](https://www.tigerdata.com/docs/about/latest/timescaledb-editions), [timescaledb LICENSE](https://github.com/timescale/timescaledb/blob/main/LICENSE)
- **Fleet health precedents**
  - CrowdStrike's RCA tracked recovery by the share of sensors online ("~99% of Windows sensors are online" as of 2024-07-29) — [CrowdStrike RCA](https://www.crowdstrike.com/wp-content/uploads/2024/08/Channel-File-291-Incident-Root-Cause-Analysis-08.06.2024.pdf)
  - MDE retries pending isolation for 3 days on offline devices — [Microsoft Learn](https://learn.microsoft.com/en-us/defender-endpoint/respond-machine-alerts)

### Inferences

**Process model** (privilege separation, OpenSSH-style).

`fusion-agentd` (root core):
  - eBPF, audit and fanotify collectors, plus the actuator.
  - Holds the trust anchors (policy and command verification keys).
  - No outbound sockets of its own and no listener.
  - Talks to the other processes over a Unix socket checked with `SO_PEERCRED`.

`fusion-uplink` (unprivileged user `_fusion`, strict systemd sandbox):
  - TLS to the master server, plus parsing and spooling.
  - Forwards server commands to the core without trusting them; the core verifies their signatures itself.

The TUI and CLI connect to the core socket as members of the `fusion` group.

Benefit: all parsing of network input happens unprivileged (Kaseya/SolarWinds lesson), and a compromised uplink cannot forge commands.

**Pipeline.**
  ```
  eBPF (cilium/ebpf, CO-RE) / audit netlink (go-libaudit) / fanotify / proc scans
    -> normalizer (internal protobuf Event)
    -> enrichment (process-tree cache, user, container/k8s metadata, package ownership, file hashes, cgroup/unit)
    -> stateless rule match (expr/CEL)
    -> stateful correlation (per-host sequences with windows: ssh_login(new_ip) -> write(/tmp|/dev/shm) -> chmod+x -> exec -> connect(pool ports) -> cron/systemd write)
    -> detection -> response planner -> policy (CEL) -> approval gate -> actuator -> audit chain
    -> telemetry sampler -> spool -> uplink
  ```
  - Filter in the kernel (eBPF maps of interesting paths, comms and ports) to keep event rates down on small VPSes.
  - If eBPF fails to load (kernel or verifier differences), degrade to audit plus fanotify plus /proc polling rather than crash-looping. This mirrors CrowdStrike's 2024 Linux experience; see Section 6.

**Spool.**
  - bbolt (MIT, single-writer B+tree, one file, no background compaction) or modernc SQLite in WAL mode (pure Go, so CGO_ENABLED=0 is preserved).
  - Cap the size (e.g., 256 MB) and evict by priority: drop low-value telemetry first, never detections or audit records.
  - Badger's LSM with value-log GC is heavier than a small agent needs.

**Resource budget for 1–2 vCPU VPS targets** (unit snippet in Section 4): CPUQuota=15–25%, MemoryHigh≈200M, MemoryMax≈300M, TasksMax≈128, GOMEMLIMIT≈180MiB, Nice/IOWeight lowered. Go ≥1.25 picks up the CPU quota automatically. Under memory pressure, shed telemetry before detections.

**Event schema.** Use a compact internal protobuf (versioned, with field numbers you control) on the wire. Map it to OCSF on the server for exports and SIEM integrations:
  - Process Activity, File System Activity, Network Activity, Authentication;
  - Detection Finding;
  - the Remediation classes (File, Process, Network Remediation Activity), which fit the response audit naturally.

  Track OTel semantic conventions (the successor to ECS) only if you need log and trace interop.

**Transport.**
  - A gRPC bidirectional stream over TLS 1.3 with mTLS on 443: batched events (1–5 s, zstd), heartbeats, command delivery and acknowledgements.
  - Server→agent commands are **signed envelopes**: Ed25519 signature by the approval/policy service, `agent_id`, `nonce`, `not_after`, `policy_version`, action and target. The core verifies them independently of TLS.
  - NATS JetStream is reasonable *inside* the control plane for fan-out and durable queues. MQTT adds nothing for this use case, and the Paho client is EPL-2.0.

**Enrollment and identity.**
  1. The admin creates a single-use bootstrap token (short TTL, scoped to tenant or host group).
  2. On install, the agent generates its key pair locally (Ed25519 or ECDSA P-256, file mode 0600 under /var/lib/fusion/identity; optionally TPM-sealed). It sends a CSR plus the token plus host facts (machine-id, cloud instance ID).
  3. The server issues a short-lived client certificate (e.g., 30 days, renewed at about 2/3 of lifetime) with a SPIFFE-like URI SAN such as `spiffe://fusion/<tenant>/agent/<uuid>`.
  4. Pin the server CA in the package. Keep the **command-signing key separate from the TLS CA**. Support revocation (server deny list) and re-enrollment detection (same machine-id, new key → alert).
  5. Optional zero-touch: verify cloud instance-identity documents.

**Heartbeat and dead-man switch.**
  - Every 30 s (with jitter) the agent sends: versions (agent, content, policy), uptime, last event seq, audit chain head, health of each sensor (eBPF attached? fanotify active? nft table present?), isolation state and resource usage.
  - Server marks the agent "late" at 3 missed intervals and "offline" at 5–10 minutes, then alerts. It distinguishes graceful stops (the agent reports "shutting down: reason") from silent loss, and cross-checks the cloud instance state to cut false alarms.

**Central storage split.**
  - **PostgreSQL**: agents, enrollment, policies, incidents, approvals, audit checkpoints. ACID, row-level security for multi-tenancy, append-only audit tables.
  - **ClickHouse** (Apache-2.0): high-volume telemetry in MergeTree partitioned by day, with a TTL of 30–90 days.
  - **OpenSearch**: only if analysts need full-text search.
  - **TimescaleDB**: possible if you want a single Postgres stack. Use the Apache-2 edition, or check the TSL terms with counsel for a hosted SaaS.

**Licensing summary.** Every library recommended above is MIT, BSD or Apache-2.0. Avoid EPL-2.0 (Paho) and the GPL/AGPL code (Wazuh) inside the proprietary agent.

### Gaps
- Vendor enrollment designs (Wazuh authd, Elastic Fleet enrollment tokens) and keepalive timers were not fetched; the Wazuh docs domain was blocked for fetching.
- Recent bbolt vs SQLite vs Pebble write-amplification and memory benchmarks for agent-sized workloads were not found.
- Badger's maintenance outlook after the Dgraph/Hypermode ownership changes was not verified beyond the repository move.
- OCSF class UIDs and the exact changes in 1.5–1.7 were not verified from schema.ocsf.io.
- Whether BTF (needed for eBPF CO-RE) is available on every target kernel (RHEL 8, AL2023, Debian 12/13, Ubuntu 22.04+) was not verified.

## 4. Packaging and distribution for apt and dnf: building, signed repositories, signing, SELinux/AppArmor, hardened systemd unit, secure auto-update (TUF/Sigstore), staged rollout rings

### Takeaway
Build one static Go binary and package it with nFPM via GoReleaser (both MIT). Publish signed repositories with aptly (MIT) for apt and createrepo_c (GPL-2.0, server-side only) for dnf. Use strong OpenPGP keys: Debian's APT (sqv/Sequoia) rejects SHA-1 key bindings since 2026-02-01, apt-key is gone in Debian 13, and RPM 6 identifies keys by fingerprint. Ship a `-selinux` noarch subpackage (Fedora's independent-policy pattern) and an AppArmor profile via dh_apparmor-style postinst. Split the systemd units so the network-facing part is strictly sandboxed. Deliver rule/intel content through a TUF repository (go-tuf v2, Apache-2.0) with offline root keys and ring delegations. Sign artifacts with Sigstore in CI. Roll out canary-first with bake time and customer pinning (the CrowdStrike RCA lessons).

### Cited Findings
- **nFPM and GoReleaser**
  - Licenses: nFPM MIT — [LICENSE](https://github.com/goreleaser/nfpm/blob/main/LICENSE.md); GoReleaser MIT — [LICENSE](https://github.com/goreleaser/goreleaser/blob/main/LICENSE.md)
  - Signing: nFPM has separate `signature` blocks under `rpm:` and `deb:`, and "The package is signed if a key_file is set". The deb signature method is `debsign` (default) or `dpkg-sig`. The passphrase comes from `$NFPM_<ID>_DEB_PASSPHRASE` and falls back to `$NFPM_<ID>_PASSPHRASE` — [nfpm Go docs](https://pkg.go.dev/github.com/goreleaser/nfpm/v2)
  - A common failure is "no signing key in keyring" — [nfpm discussion #563](https://www.github.com/goreleaser/nfpm/discussions/563)
- **Repository tools**: aptly MIT — [LICENSE](https://github.com/aptly-dev/aptly/blob/master/LICENSE); createrepo_c GPL-2.0 — [LICENSE](https://github.com/rpm-software-management/createrepo_c/blob/master/LICENSE); pulpcore GPL-2.0 — [LICENSE](https://github.com/pulp/pulpcore/blob/main/LICENSE)
- **Debian repository keys**
  - apt-key "has been removed with Debian 13 'Trixie'". Keys go in /etc/apt/keyrings/ and are referenced with `Signed-By` in deb822 `.sources` files — [Kicksecure APT notes](https://www.kicksecure.com/wiki/Dev/APT), [debian-devel 2025-09](https://lists.debian.org/debian-devel/2025/09/msg00037.html)
  - Debian's third-party guidance: scope each key to its repository rather than trusting it globally via /etc/apt/trusted.gpg.d — [Debian wiki: UseThirdParty](https://wiki.debian.org/DebianRepository/UseThirdParty)
  - The key file extension must match the format: `.asc` for armored, `.gpg` for binary. Otherwise APT warns of an "unsupported filetype" and ignores the key — [WineHQ report](https://list.winehq.org/mailman3/hyperkitty/list/wine-bugs@winehq.org/thread/KIZ7K67TTCPN2GNII3A3NAKYVPAWPMGK)
- **APT/Sequoia (sqv) policy**
  - Debian's default APT Sequoia policy set a SHA-1 second-preimage cutoff of `2026-02-01`. Repositories whose keys carry SHA-1 binding signatures now fail with "Policy rejected non-revocation signature (PrimaryKeyBinding) requiring second pre-image resistance". Affected repos included Tor, Elastic 8, GlusterFS and NVIDIA — [NVIDIA forum](https://forums.developer.nvidia.com/t/apt-update-fails-due-to-obsolete-key/359462), [Tor GitLab](https://gitlab.torproject.org/tpo/tpa/debian/deb.torproject.org-keyring/-/issues/1), [Elastic forum](https://discuss.elastic.co/t/apt-raises-warning-for-repo-on-debian-13/381567), [GlusterFS issue](https://github.com/gluster/glusterfs/issues/4664)
  - DSA-1024 keys are "not considered secure" on trixie — [Prosody issue #1936](https://issues.prosody.im/1936)
  - A local override in `/etc/crypto-policies/back-ends/apt-sequoia.config` is only a stopgap. The fix is to re-sign with a new key. These are forum and bug-tracker sources; no official Debian release note was found.
- **RPM 6.0 and Fedora 43**
  - RPM 6.0 was released in September 2025 — [rpm-maint announcement](https://lists.rpm.org/pipermail/rpm-maint/2025-September/033817.html). It adds OpenPGP v6 keys, including PQC keys, and multiple signatures per package — [RPM 6.0.0 notes](https://rpm.org/releases/6.0.0), [Fedora change](https://fedoraproject.org/wiki/Changes/RPM-6.0)
  - Upstream defaults to enforcing signature checking, but "Fedora 43 still defaults to the legacy behavior" — [Fedora change](https://fedoraproject.org/wiki/Changes/RPM-6.0)
  - Keys are identified by full key ID or fingerprint — [Fedora discussion](https://discussion.fedoraproject.org/t/f43-change-proposal-rpm-6-0-system-wide/146855)
  - Fedora 43 kept the v4 package format — [Fedora devel-announce](https://lists.fedoraproject.org/archives/list/devel-announce@lists.fedoraproject.org/thread/QTJFBMRA4W4GERUGE7UPBOGLONCREUMQ/)
- **DNF signature options**: `gpgcheck` (packages) and `repo_gpgcheck` (repository metadata) both default to False in dnf.conf. Metadata keys are stored separately, per repository. `gpgcheck` "can only be used to strengthen" the RPM `%_pkgverify_level` policy — [DNF configuration reference](https://dnf.readthedocs.io/en/latest/conf_ref.html)
- **SELinux independent policy (Fedora)** — [Fedora wiki: SELinux/IndependentPolicy](https://fedoraproject.org/wiki/SELinux/IndependentPolicy)
  - Ship a `<product>-selinux` noarch subpackage. The main package requires it conditionally: `Requires: (%{name}-selinux if selinux-policy-%{selinuxtype})`.
  - `BuildRequires: selinux-policy-devel`. Source files are `.te`, `.if` and `.fc`. Build with `make -f %{_datadir}/selinux/devel/Makefile <module>.pp` and compress with `bzip2 -9`.
  - Scriptlets: `%selinux_modules_install -s %{selinuxtype}` in `%post`, `%selinux_modules_uninstall` in `%postun`, and `%selinux_relabel_pre` / `%selinux_relabel_post` (for daemons, run relabel in `%post`).
  - Modules install at priority 200, overriding distro modules at 100.
- **AppArmor via debhelper**: `dh_apparmor --profile-name=...` installs the profile and reloads it in postinst with `apparmor_parser -r -W -T` — [dh_apparmor(1)](https://manpages.debian.org/bookworm/dh-apparmor/dh_apparmor.1.en.html)
- **systemd hardening and supervision**
  - `ProtectSystem=strict` mounts "the entire file system hierarchy ... read-only, except for the API file system subtrees /dev/, /proc/ and /sys/" — [systemd.exec(5)](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html). The same page documents `NoNewPrivileges=`.
  - `WatchdogSec=` "Configures the watchdog timeout for a service". `Restart*`/`RestartSec=`/`RestartMaxDelaySec=` (v254) are documented — [systemd.service(5)](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html)
  - `RefuseManualStop=` makes a unit stoppable only as a dependency of another unit. `StartLimitIntervalSec=`/`StartLimitBurst=` rate-limit starts — [systemd.unit(5)](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html)
  - go-systemd's `daemon.SdNotify` writes directly to `$NOTIFY_SOCKET` (unixgram) in pure Go, without libsystemd — [go-systemd source](https://github.com/coreos/go-systemd/blob/main/daemon/sdnotify.go)
- **TUF (The Update Framework)**
  - Protects against arbitrary software installation, rollback, fast-forward, indefinite freeze, endless data, extraneous dependencies, mix-and-match, wrong software installation, malicious mirrors preventing updates, and key compromise. Principles: compartmentalized trust; "Keys that are kept online or used in an automated fashion should not pose an immediate risk to clients if compromised"; "a threshold/quorum of signatures" — [TUF security](https://theupdateframework.io/docs/security/)
  - go-tuf v2: Apache-2.0. Metadata API, `updater` client, delegations including succinct hash bins (TAP 15), TAP 4 multi-repo, Ed25519/RSA/ECDSA keys. The old v0.7.0 is deprecated — [go-tuf](https://github.com/theupdateframework/go-tuf)
- **Sigstore**
  - Rekor v2 reached GA, with a tile-based backend (Trillian-Tessera) and shard URLs distributed through TUF. Cosign v2.6.0 and the Go, Python and Java clients support it. The public-good instance keeps Rekor v1 as the default log "for the foreseeable future" — [Sigstore blog](https://blog.sigstore.dev/rekor-v2-ga/), [Sigstore blog index](https://blog.sigstore.dev/)
  - sigstore-go 1.0 shipped in May 2025 (per the Sigstore blog listing). sigstore-go and cosign are Apache-2.0 — [sigstore-go LICENSE](https://github.com/sigstore/sigstore-go/blob/main/LICENSE), [cosign LICENSE](https://github.com/sigstore/cosign/blob/main/LICENSE)
- **Self-update library**: minio/selfupdate is Apache-2.0 — [LICENSE](https://github.com/minio/selfupdate/blob/master/LICENSE)
- **Staged rollout (CrowdStrike RCA, 2024-08-06)**
  - "New Template Instances that have passed canary testing are to be successively promoted to wider deployment rings or rolled back if problems are detected". Each ring is followed by "additional bake-in time".
  - Customers "can choose where and when Rapid Response Content updates are deployed".
  - Source: [CrowdStrike RCA](https://www.crowdstrike.com/wp-content/uploads/2024/08/Channel-File-291-Incident-Root-Cause-Analysis-08.06.2024.pdf)

### Inferences

**Build**
  - `CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -buildid="` gives a static binary that runs unchanged on every glibc target, is reproducible, and is not affected by `/etc/ld.so.preload` userland rootkits such as perfctl's hooks.
  - GoReleaser + nFPM produce `.deb` and `.rpm` packages:
    - `/usr/sbin/fusion-agentd`, `/usr/bin/fusionctl`
    - `/usr/lib/systemd/system/fusion-agent.service` (+ `fusion-uplink.service`)
    - `/etc/fusion/agent.yaml` as `config|noreplace`
    - `/var/lib/fusion` (0700)
    - maintainer scripts (postinst/prerm/postrm)
  - Use debhelper or rpmbuild only if you need distro-policy-grade packages, e.g., to land in Fedora EPEL or Debian.

**APT repo**
  - Workflow: `aptly repo create fusion-stable && aptly repo add fusion-stable dist/*.deb && aptly publish repo -gpg-key=<subkey-fpr> -distribution=stable fusion-stable`. This produces Release, Release.gpg and InRelease. Serve them as static files (S3/CloudFront or nginx).
  - One suite works for all Debian/Ubuntu releases because the binary is static. Use per-codename suites only if MAC policy files differ.
  - Client config:
    ```
    # /etc/apt/sources.list.d/fusion.sources
    Types: deb
    URIs: https://pkg.fusion.example/apt
    Suites: stable
    Components: main
    Signed-By: /etc/apt/keyrings/fusion-archive.asc
    ```

**RPM repo**
  - Workflow: `rpmsign --addsign` (SHA-256+ digests) → `createrepo_c --update` → `gpg --detach-sign --armor repodata/repomd.xml` (produces `repomd.xml.asc`).
  - Client config (always set both checks explicitly, because dnf.conf defaults are False):
    ```
    # /etc/yum.repos.d/fusion.repo
    [fusion]
    name=Fusion Security Agent
    baseurl=https://pkg.fusion.example/rpm/$basearch
    enabled=1
    gpgcheck=1
    repo_gpgcheck=1
    gpgkey=https://pkg.fusion.example/keys/fusion-rpm.asc
    ```
  - The same repo serves RHEL 8/9/10, Alma, Rocky, Fedora and AL2023, with an arch split only.

**Signing keys**
  - An offline OpenPGP primary key (Ed25519 or RSA-4096) with SHA-512 self/binding signatures, which survive the sqv policy. Signing subkeys live on an HSM or YubiKey, separately for apt and rpm.
  - **Never store signing keys in CI secrets**: TeamPCP stole GPG keys from Aqua's bot account (Section 6). Signing happens in a separate, approval-gated release job.
  - Pre-publish the next key in a `fusion-archive-keyring` package well before rotation.
  - Plan for RPM 6 enforcing mode and OpenPGP v6/PQC keys by testing on Fedora 43+.

**SELinux**
  - Ship `fusion-agent-selinux` per the Fedora pattern, starting from a generated template. Types: `fusion_agent_t` for the domain, `fusion_agent_exec_t`, `fusion_agent_var_lib_t`, `fusion_agent_etc_t`, `fusion_agent_log_t`.
  - An EDR legitimately needs broad read access plus bpf, perfmon, net_admin (nftables), kill, sys_ptrace (/proc) and cgroup/fanotify privileges. In practice a confined domain mostly limits the blast radius if the agent itself is exploited.
  - Ship it permissive first (`semanage permissive -a fusion_agent_t`), then enforce once the AVC denial logs are clean across the distro matrix.
  - Confine the unprivileged uplink much more tightly than the core.

**AppArmor**
  - Profile `usr.sbin.fusion-agentd`, in complain mode first. nFPM-built debs must call `apparmor_parser -r -W -T` in postinst themselves, mirroring dh_apparmor.
  - Ubuntu and Debian enable AppArmor; RHEL-family does not ship it.

**Unit files.** The network-facing uplink gets the strict sandbox:
  ```ini
  # fusion-uplink.service (unprivileged, network-facing)
  [Service]
  User=_fusion
  Group=_fusion
  ExecStart=/usr/libexec/fusion/fusion-uplink
  Restart=always
  RestartSec=2s
  ProtectSystem=strict
  ProtectHome=yes
  PrivateTmp=yes
  PrivateDevices=yes
  NoNewPrivileges=yes
  CapabilityBoundingSet=
  RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
  SystemCallFilter=@system-service
  StateDirectory=fusion-uplink
  MemoryMax=150M
  CPUQuota=10%
  ```

  The privileged core gets supervision and resource limits, but must keep the privileges response actions need:
  ```ini
  # fusion-agent.service (privileged core)
  [Unit]
  StartLimitIntervalSec=0
  [Service]
  Type=notify
  NotifyAccess=main
  ExecStart=/usr/sbin/fusion-agentd
  Restart=always
  RestartSec=2s
  WatchdogSec=30s
  OOMScoreAdjust=-900
  CPUQuota=20%
  MemoryHigh=200M
  MemoryMax=300M
  TasksMax=128
  Delegate=yes        # own sub-cgroups for quarantine
  ProtectSystem=full
  ReadWritePaths=/var/lib/fusion /var/log/fusion
  ```
  - Run `systemd-analyze security` on both units and track the score in CI.
  - Prefer systemd's D-Bus API (godbus/dbus BSD-2, go-systemd/dbus Apache-2.0) for stop/disable/mask, so PID 1 performs the writes and the core needs fewer write paths.
  - Add `RefuseManualStop=yes` only together with a documented `fusionctl maintenance` path (Section 5).

**Binary updates**
  - Customers update through their package manager. They can pin versions (apt preferences or `apt-mark hold`, the dnf versionlock plugin).
  - Rings are separate suites/repos (`canary`, `stable`), or a server-assigned "target version" that the core installs by running the package manager in a transient unit (`systemd-run --unit=fusion-upgrade ...`), so the upgrade survives the agent's own restart.

**Content updates** (rules, intel hashes, policies, correlation definitions) go through TUF via go-tuf v2:
  - **Roles**: root offline (2-of-3 YubiKeys held by different people); targets offline or HSM; snapshot and timestamp online with short expiries (timestamp about 1 day) so freeze attacks surface.
  - **Delegations**: delegated targets per ring (`rings/canary`, `rings/early`, `rings/stable`) and per tenant for custom rules.
  - The initial `root.json` is embedded in the package.
  - **Activation checks** before any content goes live:
    1. Verify the TUF metadata.
    2. Run the schema check and compile every rule, with per-rule bounds and timeout checks.
    3. Activate atomically (rename).
    4. Keep the last known-good version.
    5. If a crash loop or watchdog miss happens within N minutes of activation, auto-revert and report.
  - Also sign release artifacts with cosign or Sigstore in CI. Verify offline in the agent using a trusted root delivered via TUF; do not depend on reaching Rekor at runtime.

**Rings.**
  1. Internal dogfood fleet.
  2. Canary (about 1%, deliberately diverse distros and kernels: Debian 12/13, Ubuntu 22.04/24.04/26.04, RHEL 8/9/10, Alma/Rocky, Fedora current, AL2023; x86_64 and arm64).
  3. 10%.
  4. 50%.
  5. 100%.

  Each step waits a bake time (hours for content, days for binaries) and halts automatically on crash or restart rate, watchdog misses, heartbeat loss, CPU/RSS regressions or detection-volume spikes. Customers choose channels (fast/slow/manual) and version pinning (N, N-1, N-2), as CrowdStrike now offers for Rapid Response Content.

### Gaps
- reprepro's license and maintenance state were not verified. Fetch rate limits stopped the check.
- Whether RHEL 9/10 crypto policies reject SHA-1 RPM or repository signatures was not verified from Red Hat docs.
- Ubuntu's apt-key status in 24.04/26.04 and whether Ubuntu adopted the same sqv SHA-1 cutoff were not verified.
- No official Debian release note on the sqv cutoff was found; the evidence is bug trackers and forums.
- The exact date of Rekor v2 GA (a third-party source says October 2025) and the sigstore-go version that added Rekor v2 support were not confirmed.
- Packaging specifics for Amazon Linux 2023 (repository priorities, deterministic upgrades with third-party repos) were not researched.

## 5. Tamper protection: systemd supervision, protecting agent files and process, dead-man's switch, detecting stop/uninstall attempts, and malware that kills or uninstalls security agents

### Takeaway
On Linux, root can always defeat a host agent: reboot with a different kernel command line, unload modules, or edit units. So tamper *prevention* is only a speed bump: systemd Restart/WatchdogSec/RefuseManualStop, `chattr +i`, an SELinux domain, and BPF-LSM hooks where `bpf` is in the active LSM list. Tamper *detection* is what makes it reliable: signed heartbeats with a server-side dead-man's switch, an audit-chain head in every heartbeat, uninstall-intent notifications from package scripts, and high-severity detections for attempts to stop, uninstall or blind the agent. The threat is real and well documented. The Rocke group (2019) gained root and then uninstalled five Alibaba/Tencent agents using the vendors' own published uninstall procedures.

### Cited Findings
- **systemd supervision**
  - `Restart=` and `RestartSec=` restart crashed services. `WatchdogSec=` requires the service to ping systemd periodically or be treated as failed — [systemd.service(5)](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html)
  - `RefuseManualStop=` denies explicit stop requests while allowing stops as a dependency of another unit — [systemd.unit(5)](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html)
- `chattr +i` can be set or cleared only by root or CAP_LINUX_IMMUTABLE — [chattr(1)](https://man7.org/linux/man-pages/man1/chattr.1.html). It therefore stops non-root tampering and careless edits, not a root attacker.
- **BPF LSM availability**
  - Active LSMs come from the `lsm=` boot parameter or the compile-time `CONFIG_LSM`. Check `/sys/kernel/security/lsm`. Many distros enable `CONFIG_BPF_LSM` without listing `bpf` in `CONFIG_LSM` — [Tracee docs](https://aquasecurity.github.io/tracee/dev/docs/install/lsm-support)
  - Red Hat kernel engineers proposed adding `bpf` to Fedora/ARK's default list. An older thread gives RHEL's `CONFIG_LSM="yama,integrity,selinux"` — [Fedora kernel list](https://lists.fedorahosted.org/archives/list/kernel@lists.fedoraproject.org/message/ARCBPZG57BA5YK7PZXJ4JRKQGUWM6I6N/), [LSM list 2021](https://kernsec.org/pipermail/linux-security-module-archive/2021-February/025730.html)
  - A 2024 Ubuntu jammy bug says BPF LSM must be enabled by adding `bpf` to the list — [Launchpad #2054810](https://bugs.launchpad.net/ubuntu/jammy/+source/linux/+bug/2054810/comments/0)
  - Oracle UEK 7.3 enables BPF-LSM at boot — [Oracle UEK notes](https://docs.oracle.com/en/operating-systems/uek/7/relnotes7.3/7.3-feature-bpf-lsm.html)
- **In-kernel enforcement without BPF-LSM**: Tetragon can override `security_` hooks from kernel 5.7 when `CONFIG_BPF_KPROBE_OVERRIDE` is set — [Tetragon selectors](https://tetragon.io/docs/concepts/tracing-policy/selectors/)
- **Malware removing agents (Rocke group, Jan 2019)**
  - The malware uninstalled the Alibaba Threat Detection Service (Aegis), Alibaba CloudMonitor, Alibaba Cloud Assistant, Tencent Host Security (YunJing) and Tencent Cloud Monitor agents.
  - It first gained full administrative control, then abused it "to uninstall these products in the same way a legitimate administrator would", following the vendors' published uninstall guides.
  - Initial access came through Apache Struts 2, Oracle WebLogic and Adobe ColdFusion vulnerabilities.
  - Source: [Unit 42](https://unit42.paloaltonetworks.com/malware-used-by-rocke-group-evolves-to-evade-detection-by-cloud-security-products)
- perfctl trojanized `top`, `ldd`, `lsof` and `crontab` and hooked PAM and libpcap to hide itself — [Aqua](https://www.aquasec.com/blog/perfctl-a-stealthy-malware-targeting-millions-of-linux-servers/)
- **Commercial precedents for tamper exposure**
  - MDE's Linux isolation is undone when "an administrator modifies or adds a new iptable rule" — [Microsoft Learn](https://learn.microsoft.com/en-us/defender-endpoint/respond-machine-alerts)
  - SentinelOne requires an agent passphrase for local `sentinelctl` actions such as lifting network quarantine — [SonicWall KB](https://www.sonicwall.com/support/knowledge-base/sentinelone-s1-manually-restore-network-connectivity/241205152755593)

### Inferences

**Layered self-protection.**

*Supervision*
  - `Restart=always`, `RestartSec=2s`, `StartLimitIntervalSec=0`, `WatchdogSec=30s` with `daemon.SdNotify(false, "WATCHDOG=1")` from a health goroutine that checks real liveness (event loop progress, not just a timer).
  - `OOMScoreAdjust=-900`.
  - `RefuseManualStop=yes` plus a documented `fusionctl maintenance start --token <signed>` that cleanly lifts protection and stops the agent, and is audited.

*Files*
  - Binaries are package-owned. After install, set `chattr +i` on `/usr/sbin/fusion-agentd`, the units and `/etc/fusion/*.pub`; remove it in prerm.
  - Watch these paths (eBPF/fanotify) and alert on any write, rename or unlink not done by the package manager during an authorized upgrade.

*Process*
  - Where `bpf` is in `/sys/kernel/security/lsm`, attach BPF-LSM programs that deny:
    - SIGKILL/SIGSTOP/SIGTERM to agent PIDs from non-agent tasks (`task_kill`);
    - `ptrace` attach to the agent;
    - writes, unlinks and renames on agent paths;
    - `bpf()` operations that would detach the agent's programs (needs careful design).
  - Each denial must have a break-glass path verified by a signed maintenance token, and must emit an alert.
  - Elsewhere, fall back to detection only (eBPF tracepoints such as signal generation, plus the audit subsystem).
  - Never ship kernel modules.

*SELinux domain*: limits what a compromised agent can do. It will not stop an `unconfined_t` root admin, so do not market it as anti-tamper.

**Dead-man's switch.**
  - Signed heartbeats every 30 s. The server alerts after N misses, distinguishing announced shutdown, package removal, reboot and silent loss, and cross-checking cloud APIs.
  - Each heartbeat carries the audit-chain head and sensor health, so "agent running but blinded" is visible (e.g., eBPF detached, nft table missing, fanotify mark gone).

**Uninstall handling.**
  - The `prerm` / `%preun` scriptlet sends an "uninstall initiated by uid X, tty Y, parent cmdline Z" event and flushes the spool.
  - If no valid uninstall token is present, the server raises a **high-severity "agent removed" incident** but does not block the package manager. Failing prerm would wedge dpkg/rpm and anger admins.
  - Clean deregistration requires a token issued from the dashboard.

**Detection rules for "blind the agent" behaviour** (ship by default, mapped to MITRE ATT&CK T1562.001):
  - `systemctl stop|disable|mask fusion*`, `kill -9` on agent PIDs, `apt|dnf remove fusion-agent`, `rm`/`mv` on agent paths;
  - `chattr` on agent files, or renaming or deleting the `chattr` binary;
  - `/etc/hosts` or resolver changes that redirect the control-plane domain;
  - nft or iptables rules dropping control-plane IPs;
  - `setenforce 0`, `aa-teardown`, `systemctl stop apparmor`, `ufw disable`, `iptables -F`, `nft flush ruleset`;
  - writes to `/etc/ld.so.preload`;
  - scripts that iterate over known security-agent names. Bundle a list of known cloud-agent uninstall command lines (Aegis, YunJing, cloud monitors) as IOCs.

**The static Go binary helps.** Userland rootkits that hook libc or use `ld.so.preload` (perfctl style) cannot hide `/proc` entries or files from a statically linked agent that reads the kernel interfaces directly. Kernel rootkits remain out of scope for the first release, apart from integrity checks (module list, BPF program inventory, tainted flags).

### Gaps
- No primary documentation was found on how CrowdStrike Falcon (Linux) or MDE on Linux implement tamper or uninstall protection. The search found only macOS tamper-protection material for MDE, plus MDE offboarding docs ([Microsoft Learn: offboarding](https://learn.microsoft.com/defender-endpoint/linux-off-board-endpoints)).
- The current default LSM lists for RHEL 9/10, AL2023, Ubuntu 24.04/26.04 and Debian 13 kernels (is `bpf` active by default?) were not verified.
- 2024–2026 reports of TeamTNT, Kinsing, 8220 Gang or WatchDog scripts that uninstall Aegis/YunJing or kill other agents could not be fetched; the search budget was exhausted. Rocke (2019) is the only verified primary source. Recheck vendor reports (Trend Micro, Cado/Darktrace, Aqua, Unit 42) for current script command lines.
- No measured data on the operational risk of BPF-LSM self-protection (e.g., blocking legitimate admin operations, interaction with kernel updates) was found.

## 6. Lessons from incidents for this product's design: CrowdStrike July 2024, Kaseya VSA 2021, SolarWinds, xz-utils 2024, and 2025–2026 supply-chain incidents affecting security tools or their CI

### Takeaway
1. Content is code: validate it, bounds-check the interpreter, stage it through canary rings, and give customers control over timing (CrowdStrike).
2. A trusted management channel that can push arbitrary actions is a weapon: agents must accept only allow-listed, signed, expiring commands whose keys are not on the internet-facing server (Kaseya).
3. Build systems are targets: use hermetic, ephemeral, provenance-attested builds (SolarWinds).
4. Every dependency loaded into a privileged process is attack surface: keep the dependency set minimal and pure Go (xz).
5. Security vendors' own CI is now a primary target: pin Actions by SHA, rotate every credential completely after an incident, and keep signing keys out of CI (Trivy/TeamPCP, March 2026).

### Cited Findings
- **CrowdStrike Channel File 291 (2024-07-19; RCA 2024-08-06)** — [CrowdStrike RCA](https://www.crowdstrike.com/wp-content/uploads/2024/08/Channel-File-291-Incident-Root-Cause-Analysis-08.06.2024.pdf)
  - Root cause: the new IPC Template Type "defined 21 input parameter fields, but the integration code ... supplied only 20". Rapid Response Content is interpreted by a "regular-expression based engine". Testing used wildcard matching for the 21st field. On 2024-07-19 a non-wildcard criterion triggered an out-of-bounds read.
  - Findings: no compile-time field-count validation; a missing runtime bounds check; a Content Validator logic error; Template Instance validation should include the Content Interpreter; Template Instances should have staged deployment.
  - Fixes and dates: bounds checks were added 2024-07-25, with the hotfix generally available by 2024-08-09; validator checks were due by 2024-08-19; canary rings with bake-in time; customer control over "where and when" Rapid Response Content deploys; two independent third-party code reviews.
- **CrowdStrike on Linux (2024)**
  - Before July 2024, Falcon was linked to Debian servers becoming unbootable (April 2024; reportedly because the Debian configuration was not in the test matrix). In June 2024 Red Hat warned of a "kernel panic observed after booting 5.14.0-427.13.1.el9_4.x86_64 by falcon-sensor process".
  - CrowdStrike called the RHEL issue a kernel bug and said the user-level BPF component, not the kernel module, was affected. These are secondary sources — [The Register](https://www.theregister.com/2024/07/21/crowdstrike_linux_crashes_restoration_tools/), [TechSpot](https://www.techspot.com/news/103899-crowdstrike-also-broke-debian-rocky-linux-earlier-year.html), [Rocky forum](https://forums.rockylinux.org/t/crowdstrike-freezing-rockylinux-after-9-4-upgrade/14041), [CIQ KB](https://kb.ciq.com/article/rocky-linux/rl-kernel-panic-crowdstrike-falcon)
- **Kaseya VSA (July 2021)**
  - REvil exploited on-premises VSA servers; the vulnerability is reported as CVE-2021-30116. Kaseya estimated "fewer than 1,500 downstream businesses" were affected.
  - CISA and FBI guidance (2021-07-04): use Kaseya's detection tool; follow Kaseya's instructions, including shutting down on-prem VSA servers — [CISA/US-CERT](https://us-cert.cisa.gov/ncas/current-activity/2021/07/04/cisa-fbi-guidance-msps-and-their-customers-affected-kaseya-vsa), [HIPAA Journal](https://www.hipaajournal.com/kaseya-ksa-supply-chain-attack-revil-ransomware/)
- **SolarWinds SUNSPOT/SUNBURST**
  - SUNSPOT lived on the Orion build servers. When it detected MsBuild.exe building Orion, it swapped one source file for a variant containing SUNBURST, restored the original afterwards, and hid the change from build logs. It began inserting SUNBURST on 2020-02-20 — [CrowdStrike SUNSPOT analysis](https://crowdstrike.com/blog/sunspot-malware-technical-analysis/)
  - It was resident only on the build servers, not in the shipped patches — [KPMG](https://kpmg.com/us/en/articles/2023/solarwinds-explainer.html)
- **xz-utils (CVE-2024-3094, CVSS 10)**
  - Andres Freund reported on 2024-03-29 that xz 5.6.0/5.6.1 release tarballs were backdoored. The activating m4 (build-to-host.m4) was in the tarballs but not in git, and the payload hid in binary test files.
  - sshd was reachable because distro patches link sshd to libsystemd, which loads liblzma. CISA advised downgrading to 5.4.6 — [Wiz](https://www.wiz.io/blog/cve-2024-3094-critical-rce-vulnerability-found-in-xz-utils), [Akamai](https://www.akamai.com/blog/security-research/critical-linux-backdoor-xz-utils-discovered-what-to-know)
  - Binarly reportedly found the backdoor still present in some Debian Docker Hub images in August 2025 (secondary) — [Xygeni](https://xygeni.io/?p=17996)
  - OpenSSH 9.8 (2024-07-01) added systemd notification "using a standalone implementation that doesn't depend on libsystemd" — [OpenSSH release notes](https://www.openssh.com/releasenotes.html)
- **Trivy / TeamPCP (March 2026), a security tool's CI compromised** — [Wiz](https://www.wiz.io/blog/trivy-compromised-teampcp-supply-chain-attack)
  - Root cause: incomplete containment of an earlier incident in early March 2026 (a "PWN request"), which let the attackers keep access through the `aqua-bot` service account. They stole credentials including **GPG keys** and Docker Hub, Twitter and Slack credentials.
  - Timeline:
    - **2026-03-19**: imposter commits; backdoored Trivy **v0.69.4** binaries on GitHub Releases, Docker Hub, GHCR and ECR; most trivy-action tags force-pushed (Wiz: 75 of 76; others report 76 of 77) and 7 setup-trivy tags.
    - **2026-03-22**: malicious 0.69.5 and 0.69.6 images on Docker Hub.
    - **2026-03-23**: a parallel compromise of Checkmarx's `kics-github-action` identified.
  - Payload: read the GitHub Runner.Worker process memory for secrets, harvested cloud, Kubernetes and SSH credentials, and exfiltrated them (or committed them to a `tpcp-docs` repository). On non-CI hosts it installed a systemd user service.
  - Primary mitigation: pin Actions to full commit SHAs.
  - Other summaries add the npm "CanisterWorm" (deployed 2026-03-20 with stolen npm publish tokens; Wiz reported it on 03-22) and date the spread to Checkmarx and LiteLLM to 2026-03-24. That conflicts slightly with Wiz identifying the kics-github-action compromise on 03-23 — [Cloud Security Alliance](https://labs.cloudsecurityalliance.org/research/csa-research-note-teampcp-supply-chain-ci-cd-20260324-csa-st/), [Kudelski Security](https://kudelskisecurity.com/research/investigating-two-variants-of-the-trivy-supply-chain-compromise), [Legit Security](https://www.legitsecurity.com/blog/the-trivy-supply-chain-compromise-what-happened-and-playbooks-to-respond)
  - CSA advises treating any pipeline that ran Trivy 0.69.4–0.69.6, or used trivy-action between 2026-03-19 and 03-23, as fully compromised.
- **Agentic supply chain**: OWASP's 2026 agentic list includes ASI04 "Agentic Supply Chain Vulnerabilities" — [Speakeasy summary](https://www.speakeasy.com/blog/owasp-agentic-top-10-explained)

### Inferences

| Incident lesson | Concrete requirement for Fusion |
|---|---|
| CrowdStrike: content mismatch slipped past the validator | Content schema versioned and bound to the agent version (the agent rejects content needing unsupported fields). Validator and agent share one compiled rule loader, so CI runs the *same* code the agent runs. Fuzz the rule compiler. Per-rule panic recovery and evaluation timeouts. Replay a corpus of real telemetry in CI. |
| CrowdStrike: global simultaneous push | TUF ring delegations plus bake time; automatic halt on health signals; customer channels and pinning; release notes per content version; the fleet circuit breaker from Section 2. |
| CrowdStrike Linux 2024: kernel/eBPF interplay | Nightly CI against distro kernel updates (Debian, Ubuntu HWE, RHEL/Alma/Rocky z-stream, AL2023, Fedora). eBPF-load failure degrades to fallback sensors instead of crashing. No kernel modules. A remote "sensor safe mode" switch. |
| Kaseya: management plane pushed ransomware as a "hotfix" | No "run arbitrary script/command" capability in the agent at all. Commands are drawn from a closed, versioned action catalog. Command envelopes are signed by a separate approval service (HSM-held key, two-person rule for high-impact actions), not by the internet-facing API. Agents enforce local policy even against valid commands (e.g., never isolate without the mgmt allowlist). Admin UI behind SSO + WebAuthn and not exposed broadly. Fleet-wide action rate limits. |
| SolarWinds: build-server implant | Ephemeral, hermetic build runners. Reproducible Go builds (`-trimpath`, pinned toolchain, vendored modules with checksum DB). SLSA provenance plus Sigstore signatures. Rebuild verification on an independent builder before release. Two-person review on release branches. |
| xz: malicious maintainer, tarball-only payload, libsystemd linking | Pure-Go agent (`CGO_ENABLED=0`; sd_notify via go-systemd, like OpenSSH 9.8 dropping libsystemd). Minimal, pinned and vendored dependency set, with alerts on maintainer or ownership changes in dependencies. Build from git, never from release tarballs. |
| Trivy/TeamPCP 2026: security vendor CI, stolen GPG keys, moved tags | Pin all third-party Actions by full SHA. Minimal `GITHUB_TOKEN` permissions. No `pull_request_target` on untrusted code. Signing keys in HSM/KMS behind a manual approval, never in CI secrets. After any incident, rotate *every* credential (incomplete rotation caused the second wave). Monitor your own repos for force-pushed tags and unexpected releases. |
| Rocke / malware uninstalling agents | Tamper detection plus dead-man's switch (Section 5). |

### Gaps
- The following 2025 incidents could not be verified in this session (search budget exhausted) and should be researched before being cited:
  - the tj-actions/changed-files and reviewdog Action compromises (March 2025);
  - the npm "Shai-Hulud" worm waves (September and November 2025), reportedly including trojanized CrowdStrike-published npm packages;
  - the Nx "s1ngularity" incident (August 2025), reportedly using local AI CLIs to hunt secrets;
  - the Salesloft Drift OAuth-token theft affecting several security vendors (August 2025);
  - the F5 source-code breach (October 2025).
- The Notepad++ update-infrastructure hijack (disclosed early 2026) was also not verified.
- No primary Aqua Security advisory for the Trivy incident was fetched; the details come from Wiz, CSA, Kudelski and Legit.
- The exact Kaseya CVE set (beyond CVE-2021-30116) and Kaseya's own post-incident engineering changes were not researched.

## 7. Discord as the notification and approval interface: webhooks, rate limits, slash commands and buttons, Ed25519 verification, approval flows, Go libraries and licenses, risks and mitigations

### Takeaway
Use Discord webhooks only for notification, routed to severity channels and coalesced per incident. Run approvals through an HTTP Interactions Endpoint hosted by the **control plane**, never by agents:
- verify the Ed25519 signature on every request (Discord deliberately sends bad signatures and removes endpoints that accept them);
- answer within 3 seconds, deferring if needed;
- map the Discord user ID to a Fusion identity and role server-side;
- bind each approval to a single-use nonce and expiry;
- require two distinct approvers for high-impact actions, and step-up to the dashboard (WebAuthn) for the most destructive ones.

Discord text is not end-to-end encrypted, and accounts and webhook URLs get stolen. Keep secrets and raw attacker-controlled strings out of messages, and treat a Discord click as one factor, not the authority.

### Cited Findings
- **Delivery modes**: interactions arrive "in two mutually-exclusive ways": Gateway (the default) or HTTP via an Interactions Endpoint URL set in the app settings — [Discord interactions overview](https://docs.discord.com/developers/interactions/overview)
- **HTTP endpoint requirements** — [Discord interactions overview](https://docs.discord.com/developers/interactions/overview)
  - Reply to `PING` (type 1) with `200` and `PONG` (type 1).
  - Every request carries `X-Signature-Ed25519` and `X-Signature-Timestamp`. Verify the signature over timestamp + raw body with the application's public key, and return `401` on failure.
  - Discord runs automated, routine security checks, including requests with deliberately invalid signatures. If the endpoint fails them, Discord will "remove your interactions URL and alert you via email and System DM".
- **Response timing and payload** — [Discord: receiving and responding](https://docs.discord.com/developers/interactions/receiving-and-responding)
  - "You must send an initial response within 3 seconds", or the token is invalidated. Tokens "are valid for 15 minutes" for follow-ups.
  - Callback types: 4 CHANNEL_MESSAGE_WITH_SOURCE, 5 DEFERRED_CHANNEL_MESSAGE_WITH_SOURCE, 6 DEFERRED_UPDATE_MESSAGE (components and modal submits only), 7 UPDATE_MESSAGE, 9 MODAL.
  - The payload includes `member` (with permissions) for guild invocations, `user` for DMs, `app_permissions`, `guild_id` and `channel_id`.
  - Interaction endpoints "are not bound to the application's Global Rate Limit". Interaction webhooks share normal webhook rate-limit properties.
- **Rate limits** — [Discord rate limits](https://docs.discord.com/developers/topics/rate-limits)
  - Limits are per-route buckets, computed per top-level resource (channels, guilds, **webhooks**).
  - Headers: `X-RateLimit-Limit`, `-Remaining`, `-Reset`, `-Reset-After`, `-Bucket`, and on 429 `-Scope` and `-Global`. The 429 body has `retry_after`.
  - Bots get 50 requests/s globally. 10,000 invalid requests (401/403/429) per 10 minutes triggers a temporary Cloudflare restriction.
  - "rate limits should not be hard coded". Do not reuse a webhook after it returns 404.
- **Encryption**
  - Discord's DAVE protocol end-to-end encrypts audio and video calls (announced September 2024, now default). Text messages "are not end-to-end encrypted" and follow Discord's content-moderation approach. Stage channels are excluded — [Discord blog](https://discord.com/blog/meet-dave-e2ee-for-audio-video), [TechRepublic](https://www.techrepublic.com/article/news-discord-dave-end-to-end-encryption/), [The Next Web](https://thenextweb.com/news/discord-end-to-end-encrypted-voice-video-all-users)
  - EFF criticized the exclusion of text — [EFF](https://www.eff.org/node/109999)
- **Go libraries (licenses verified)**: bwmarrin/discordgo BSD-3-Clause — [LICENSE](https://github.com/bwmarrin/discordgo/blob/master/LICENSE); disgoorg/disgo Apache-2.0 — [LICENSE](https://github.com/disgoorg/disgo/blob/main/LICENSE)

### Inferences

**Topology.**
  - Agents → master server → a Discord notifier service that holds the webhook URLs and bot token. Agents never hold Discord credentials.
  - Optional fallback: if the master is unreachable for more than X minutes, an agent may post a minimal, redacted "agent cannot reach control plane" message to a dedicated low-trust webhook. Webhook URLs are bearer secrets, so rotate them.

**Notifications.**
  - Channels: `#fusion-critical` (with role mention), `#fusion-high`, `#fusion-info`, `#fusion-audit` (approvals and actions log).
  - One message per incident, edited in place as the state changes. Batch low-severity alerts into digests.
  - A client-side queue honours the bucket headers and `retry_after`, with jittered backoff, and never hard-codes limits.

**Message hygiene.**
  - Truncate and escape every attacker-controlled field (process names, command lines, file names, usernames, SSH key comments, HTTP headers). Render them inside code blocks, and disable mention parsing so a payload cannot @everyone.
  - Never include secrets: redact `password=`, tokens, AWS keys and private-key blobs from command lines.
  - Include the incident ID and a dashboard link instead of raw evidence.

**Approval flow** (HTTP interactions on the control plane):
  1. The incident needs an L3 action. The server creates `approval{id, action, target, policy_version, required_approvers=2, expires=10–15 min, nonce}` and posts buttons with `custom_id="apr:<id>:<nonce>:approve|deny"`.
  2. A click arrives as a POST: verify the Ed25519 signature over `timestamp+body` (reject stale timestamps, e.g., older than 5 min, as defence in depth) → check that `guild_id`/`channel_id` match the configured tenant → map `member.user.id` to a Fusion user with the right Cedar/OPA permission. Never trust the Discord role alone; also re-check role IDs → enforce single use per user and approval → record it.
  3. Reply within 3 s with type 6 (DEFERRED_UPDATE_MESSAGE), then edit the message: "1/2 approvals: @alice".
  4. When the second distinct approver arrives (different Discord ID *and* different Fusion identity), the approval service signs the command envelope (Section 3) and queues it. The agent verifies it and checks local policy before executing.
  5. For destructive or broad actions (fleet-wide isolation, account lock on root, package reinstall on many hosts), the Discord button only produces a **dashboard link** that requires SSO + WebAuthn step-up to confirm.
  6. Expired, denied or replayed nonces are rejected and logged to the audit chain with Discord user IDs.

**Slash commands** (e.g., `/fusion status <host>`, `/fusion incident <id>`, `/fusion automation off <scope>`): read-only by default, ephemeral replies, guild-restricted. State-changing commands follow the same approval path, and `automation off` (a *safety-increasing* action) can be single-approver.

**Library choice.** HTTP interactions need only `crypto/ed25519` from the standard library plus JSON types, so a library is optional. disgo (Apache-2.0) or discordgo (BSD-3) work for REST and webhook calls. Avoid running a Gateway bot unless you need presence or message-reading features.

**Risk register and mitigations.**

| Risk | Mitigation |
|---|---|
| Account takeover of an approver (token theft, phishing) | Two-person rule; dashboard step-up for high-risk actions; approver allowlist with periodic review; require Discord 2FA for approver roles as policy; anomaly checks (approval from a newly joined account or role). |
| Webhook URL leak | Rotation; only non-sensitive content; posting through a server-side notifier. |
| No E2EE for text, data residency | Minimal content; links instead of evidence. |
| Discord outage | Dashboard and CLI approvals as the primary path; Discord as a convenience channel. |
| Social engineering via spoofed messages from other bots | Only the bot's own interactions are trusted; ignore message text. |

### Gaps
- Discord component limits (custom_id length, button count), `allowed_mentions` semantics and `default_member_permissions` for slash commands were not fetched in this session. Verify them in the Discord docs before implementation.
- Whether disgo includes a ready-made HTTP interactions server with signature verification was not verified.
- No 2025–2026 data on Discord account-takeover or token-stealer prevalence, or on recent Discord platform breaches, was gathered; the search budget was exhausted.
- Webhook-specific numeric rate limits are not published (Discord asks apps to read the headers), so capacity planning needs empirical testing.

## 8. AI investigation layer safety: read-only allow-listed tools, prompt injection via attacker-controlled data, structured output validation, deterministic enforcement; vendor approaches; OWASP guidance

### Takeaway
Treat every log line, file name, process name, SSH username and HTTP header the LLM reads as attacker-controlled. Two 2026 preprints show injection payloads in log fields steering LLM analysts, with 76.4% success for payloads split across entries in one benchmark. The LLM must therefore:
- run on the control plane with only read-only, parameterized, allow-listed tools;
- have no shell and no free-form queries;
- have no external communication path beyond fixed intel lookups, which avoids the "lethal trifecta";
- emit schema-validated JSON whose "recommended actions" are enum values that go through the same deterministic policy and approval path as everything else.

Vendors market this as "bounded autonomy" with human oversight. OWASP's LLM Top 10 (2025) and Agentic Top 10 (2026) name the relevant risks: Prompt Injection, Improper Output Handling, Excessive Agency, Goal Hijack, Tool Misuse, and Memory/Context Poisoning.

### Cited Findings
- **OWASP Top 10 for LLM Applications 2025**: LLM01 Prompt Injection, LLM02 Sensitive Information Disclosure, LLM03 Supply Chain, LLM04 Data and Model Poisoning, LLM05 Improper Output Handling, LLM06 Excessive Agency, LLM07 System Prompt Leakage, LLM08 Vector and Embedding Weaknesses, LLM09 Misinformation, LLM10 Unbounded Consumption — [OWASP GenAI](https://genai.owasp.org/llm-top-10/)
- **OWASP Top 10 for Agentic Applications 2026** (published 2025-12-09 by the Agentic Security Initiative, peer-reviewed by 100+ experts): ASI01 Agent Goal Hijack, ASI02 Tool Misuse and Exploitation, ASI03 Identity and Privilege Abuse, ASI04 Agentic Supply Chain Vulnerabilities, ASI05 Unexpected Code Execution, ASI06 Memory and Context Poisoning, ASI07 Insecure Inter-Agent Communication, ASI08 Cascading Failures, ASI09 Human-Agent Trust Exploitation, ASI10 Rogue Agents. Names come from secondary summaries; the official page links the PDF — [OWASP GenAI resource page](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/), [Speakeasy](https://www.speakeasy.com/blog/owasp-agentic-top-10-explained), [Astrix](https://astrix.security/learn/blog/the-owasp-agentic-top-10-just-dropped-heres-what-you-need-to-know/)
  - ASI01 is described as manipulating the agent's objective through processed content (indirect injection). EchoLeak (CVE-2025-32711) is the cited zero-click example — [Cycode](https://cycode.com/blog/owasp-top-10-agentic-applications/)
- **The "lethal trifecta"** (2025-06-16): access to private data, exposure to untrusted content, and the ability to communicate externally. "We still don't know how to 100% reliably prevent this from happening", and 95% detection "is a failing grade". Avoid combining all three — [Simon Willison](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/)
- **Design patterns** (Beurer-Kellner et al., arXiv 2506.08837, June 2025): six patterns.
  - Action-Selector: the LLM only maps requests to predefined tool calls.
  - Plan-Then-Execute: the tool-call plan is fixed before reading untrusted data, though arguments can still be influenced.
  - Also LLM Map-Reduce, Dual LLM, Code-Then-Execute (CaMeL) and Context-Minimization — [arXiv](https://arxiv.org/pdf/2506.08837), [Willison summary](https://simonwillison.net/2025/Jun/13/prompt-injection-design-patterns/)
  - A critique: these constrain *which* actions run, not the *content* of action arguments — [ARMO](https://www.armosec.io/blog/design-patterns-for-securing-llm-agents/)
- **Log-substrate injection research (2026 preprints, not yet peer-reviewed)**
  - "Poisoning the Watchtower" (May 2026): a taxonomy of direct override, persona hijack, context manipulation and obfuscated payloads, hidden in user-agent, URI, DNS query and auth-user fields, changing what the analyst model concludes — [alphaXiv 2605.24421](https://www.alphaxiv.org/abs/2605.24421)
  - "LogInject" (July 2026): 12,847 entries with 2,569 adversarial samples. Split-payload attacks reached 76.4% success. Layered defences cut attacks by 90.4% but left 8.4% residual vulnerability — [alphaXiv 2607.14493](https://www.alphaxiv.org/abs/2607.14493)
- **Practical cases**
  - OpenClaw logged unsanitized Origin and User-Agent headers into agent workflows; fixed in 2026.2.13 with truncation and sanitization — [PointGuard AI](https://www.pointguardai.com/ai-security-incidents/openclaw-log-poisoning-enables-indirect-prompt-injection-risk)
  - A User-Agent injection made a SOC summarizer misreport the source IP — [LevelBlue SpiderLabs](https://www.levelblue.com/blogs/spiderlabs-blog/rogue-ai-agents-in-your-socs-and-siems-indirect-prompt-injection-via-log-files)
  - DEF CON 34 AI Village poster on telemetry injection vectors — [AI Village](https://aivillage.org/posters/poisoning-the-soc-prompt-injection-via-ingested-telemetry/)
- **CrowdStrike (vendor-stated)**
  - Charlotte AI Detection Triage (February 2025) "operates within a model of bounded autonomy" — [press release](https://www.crowdstrike.com/en-us/press-releases/crowdstrike-delivers-next-breakthrough-in-ai-powered-agentic-cybersecurity-with-charlotte-ai-detection-triage/)
  - Charlotte AI Agentic Response and Agentic Workflows were unveiled at RSA on 2025-04-28 — [BusinessWire](https://www.businesswire.com/news/home/20250428067495/en/crowdstrike-unleashes-new-agentic-outcome-driven-ai-innovations-to-power-the-next-evolution-of-the-soc)
  - Agents are tested against Falcon Complete analysts' decisions — [CrowdStrike blog](https://www.crowdstrike.com/en-us/blog/inside-crowdstrikes-science-backed-approach-to-building-soc-agents/)
- **Microsoft (secondary reporting)**
  - At Ignite 2025, Security Copilot agents were expanded across Defender, Entra, Intune and Purview, with a phased rollout to Microsoft 365 E5 customers. The Security Alert Triage Agent extends phishing triage to identity and cloud alerts — [Petri](https://petri.com/security-copilot-agents-threat-detection-compliance/), [SRA](https://sra.io/blog/microsoft-ignite-2025-the-6-security-announcements-shaping-2026/), [Microsoft Tech Community](https://techcommunity.microsoft.com/t5/microsoft-security-copilot-blog/from-alert-overload-to-decisive-action-how-security-copilot/ba-p/4504213)
  - MDE's automatic device isolation (attack disruption) is limited to end-user workstations — [Microsoft Learn](https://learn.microsoft.com/en-us/defender-endpoint/respond-machine-alerts)
- **Google**
  - Google announced an alert triage agent for Google Security Operations that "analyzes the context of each alert, gathers relevant information, and renders a verdict", with preview planned for Q2 2025 — [Google Cloud blog](https://cloud.google.com/blog/products/identity-security/security-summit-2025-enabling-defenders-and-securing-ai-innovation)
  - In 2026 the Triage and Investigation agent was reported as generally available after investigating more than 5 million alerts (secondary). It can be embedded in playbooks — [TechInformed](https://techinformed.com/?p=38684), [Google Cloud RSAC 2026](https://cloud.google.com/blog/products/identity-security/rsac-26-supercharging-agentic-ai-defense-with-frontline-threat-intelligence)

### Inferences

**Placement.** The LLM runs only on the control plane. It is a **recommender**: it never receives a token that can execute anything. Agents never call an LLM, and LLM output never reaches an agent except as a human-approved action.

**Tooling (read-only, allow-listed, parameterized).** Examples:
  - `get_incident(id)`, `get_process_tree(incident_id, depth≤N)`, `get_events(incident_id, kinds[], window≤1h, limit≤500)`
  - `get_file_meta(hash)`, `lookup_intel(hash|ip|domain)`
  - `get_host_inventory(host_id)`, `list_persistence(host_id)`, `get_policy_decision_trace(action_id)`

  Every tool runs under the *requesting user's* permissions (tenant scoping). There is no SQL or log-query passthrough, no shell, no URL fetch and no email or Discord posting by the LLM. Tool outputs are size-capped. This breaks the trifecta's "external communication" leg and limits ASI02 (Tool Misuse) and ASI03 (Privilege Abuse).

**Data handling against prompt injection.**
  - Pass telemetry as typed JSON fields, never interpolated into instructions. Mark untrusted spans explicitly.
  - Normalize and strip control characters and zero-width or bidirectional text. Truncate long fields.
  - Hash or redact secrets before the model sees them.
  - Run a deterministic "instruction-like content in telemetry" detector. Flag hits in the UI, and treat them as a **detection signal in their own right**, since attackers planting prompts in User-Agent strings are attacking the SOC.
  - Prefer Plan-Then-Execute: the investigation plan is a fixed template per incident type and the model fills in parameters. Use a Dual-LLM / context-minimization split for summarizing raw untrusted text.

**Output contract.** Strict JSON schema validated server-side (reject, do not repair):
  ```json
  {"summary": "...", "attack_chain": [{"step": "...", "evidence_refs": ["evt:..."]}],
   "hypotheses": [{"text": "...", "confidence": "low|medium|high"}],
   "recommended_actions": [{"action": "net.block_ip|process.kill_tree|file.quarantine|host.isolate|account.lock|ssh.revoke_key|none",
                            "target_ref": "evt:...|file:sha256:...|ip:...", "rationale": "..."}],
   "open_questions": ["..."]}
  ```
  - Every `evidence_ref` must resolve to stored events, or the claim is dropped. This counters LLM09 Misinformation.
  - `target_ref` must resolve to an entity in *this* incident.
  - Recommended actions enter the normal policy engine as `actor=ai-recommendation`. They default to **L3 approval** regardless of the action's normal level. The LLM's confidence never feeds the deterministic confidence score.

**Human factors (ASI09).**
  - The UI shows the evidence-backed deterministic findings separately from the AI narrative, labels AI text clearly, and shows the policy trace for any action.
  - Approvers must click through to the evidence for L3 actions recommended by the AI.

**Operations.**
  - Log every prompt, tool call and output (hashed in the audit chain).
  - Build an evaluation suite with injected log fields (LogInject-style corpus) and run it on every model or prompt change.
  - Pin model versions per tenant and set cost and timeout caps (LLM10).
  - Let customers opt out or self-host the model, or restrict it to particular regions.

### Gaps
- No primary Microsoft or Google documentation detailing tool permissions or guardrail architecture for Security Copilot or Google SecOps agents was fetched; the findings rely on secondary reporting.
- The official OWASP Agentic Top 10 PDF and its mitigation text were not read directly; names come from consistent secondary summaries.
- CrowdStrike's specific approval-gate mechanics for Charlotte AI Agentic Response were not found in primary documentation.
- The log-injection papers are recent preprints. Their success rates depend on the models and setups tested, and they had not been checked for peer review.

## 9. Terminal UI options in Go for the first release (brief)

### Takeaway
Use Bubble Tea v2 (MIT, Charm), stable since 2026-02-23 with Lip Gloss v2 and Bubbles v2 and new `charm.land/...` import paths, for a polished operator TUI. tview (MIT) is a simpler widget-based option for table/form-heavy screens. Either way the TUI is an unprivileged client of the core's Unix socket and must route every action through the same policy and approval engine.

### Cited Findings
- Charm announced on 2026-02-23 that Bubble Tea, Lip Gloss and Bubbles v2 are "out of beta and ready to use" — [Charm blog](https://charm.land/blog/v2/), [newreleases: Bubble Tea v2.0.0](https://newreleases.io/project/github/charmbracelet/bubbletea/release/v2.0.0)
- In v2, Bubble Tea manages input and output and directs Lip Gloss, ending v1's competition between the two libraries for terminal I/O. Import paths moved to `charm.land/bubbletea/v2`, `charm.land/lipgloss/v2` and so on — [newreleases: Lip Gloss v2.0.0](https://newreleases.io/project/github/charmbracelet/lipgloss/release/v2.0.0), [newreleases: Wish v2.0.0](https://newreleases.io/project/github/charmbracelet/wish/release/v2.0.0)
- Licenses: Bubble Tea MIT — [LICENSE](https://github.com/charmbracelet/bubbletea/blob/main/LICENSE); tview MIT — [LICENSE](https://github.com/rivo/tview/blob/master/LICENSE.txt)

### Inferences
- **Bubble Tea v2** (Elm-style model/update/view) suits streaming incident views, live process trees and approval dialogs.
- **tview** gets CRUD-style tables and forms (agents, exclusions, policies) built faster, with less custom code.
- Wish v2 (Charm's SSH server library) could later expose the TUI over SSH. That would add an attack surface, so keep it out of the first release.

Security of the TUI:
  - Run it as a non-root user in a `fusion` group, talking to the core over `/run/fusion/core.sock`, authorized via `SO_PEERCRED` plus group membership.
  - Read-only views by default. State-changing actions create the same approval objects as Discord and the dashboard.
  - Render attacker-controlled strings safely: strip ANSI escape sequences from process names and command lines, which prevents terminal-escape injection.

### Gaps
- No performance comparison between Bubble Tea v2 and tview was gathered. The "10x faster" claim in one secondary headline was unsupported in the excerpts seen.
