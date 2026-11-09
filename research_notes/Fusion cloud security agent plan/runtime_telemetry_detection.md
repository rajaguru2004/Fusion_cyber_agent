# Linux Host Runtime Telemetry and Behavioral Detection Engines: Sensor-Layer Notes for a Lightweight Commercial Go EDR Agent (as of 2026-11-09)

Method note: repository status (license SPDX, archived flag, last push, latest releases) was pulled directly from the GitHub API and release Atom feeds on 2026-11-09. Rule inventories were taken from shallow clones of the rule repositories on the same day. Distro package versions come from the Repology API. The shared web-search budget ran out near the end of the session, so a few items are listed under Gaps instead of being verified.

---

## 1. eBPF runtime sensors: Falco (modern_ebpf, falcosecurity/libs, Talon), Tetragon, Tracee, KubeArmor, sysdig OSS, bpftrace (+ Kunai)

### Takeaway
- Falco is the most mature detect-only eBPF sensor. It has the lowest measured overhead in the one recent independent benchmark, and Apache-2.0 rules with MITRE tags. It cannot block, and its response add-on (Talon) works only with Kubernetes and has slowed down.
- Tetragon is the strongest open-source option for in-kernel enforcement: synchronous SIGKILL, return-value override and LSM hooks. It needs BTF, and its tuned policies cost a lot of syscall latency. Override also needs `CONFIG_BPF_KPROBE_OVERRIDE`, which some distro kernels lack, Debian 13 for example.
- Tracee has had no release since Nov 2025.
- KubeArmor can block with BPF-LSM on VMs, but it produces very large telemetry volume.
- sysdig OSS is slowing.
- bpftrace is an investigation tool, not an agent.
- None of these is a drop-in, policy-driven host EDR for small VPS fleets. All of them are useful as reference designs or as optional "run alongside" sensors.

### Cited Findings

**Falco and falcosecurity/libs**
- Status: Falco repo is Apache-2.0 with ~9.6k stars and was pushed 2026-11-09. Releases: 0.45.0 (2026-09-21), 0.45.1 (2026-10-19), 0.45.2 (2026-10-29). — [GitHub falcosecurity/falco releases](https://github.com/falcosecurity/falco/releases); [Falco blog](https://falco.org/blog/)
- Falco 0.44.0 (2026-05-26) "completes the deprecation cycle started in 0.42.0 and 0.43.0": it removes the legacy eBPF probe, the gVisor engine and the gRPC output. — [Falco blog index](https://falco.org/blog/)
- Falco 0.45.0 added raw byte matching in rule conditions and new reload status/control endpoints. — [Falco blog](https://falco.org/blog/)
- Two drivers are supported: the **modern eBPF probe (default)** and the **kernel module**.
  - Modern eBPF is "embedded into Falco" using CO-RE, so nothing is downloaded or built. It needs the **BPF ring buffer** and a **kernel that exposes BTF**. "Usually, all versions >=5.8 are enough", but the features can be backported to older kernels. Check with `bpftool feature probe` for `map_type ringbuf` and `program_type tracing`. — [Falco kernel event source docs](https://falco.org/docs/concepts/event-sources/kernel/)
  - Least-privilege capabilities for modern eBPF include CAP_SYS_BPF, CAP_SYS_PERFMON and CAP_SYS_RESOURCE. The kernel module "requires full privileges". The driver table lists the kmod at >= 3.10 on x86_64 and aarch64. — [Falco kernel docs](https://falco.org/docs/concepts/event-sources/kernel/)
- falcosecurity/libs contains libsinsp, libscap, the kernel module and the modern eBPF probe. It is Apache-2.0, but "files in <driver/> ... are dual licensed under the MIT license or the GNU General Public License 2". Releases 0.26.1 and 11.0.1+driver shipped 2026-10-14. — [libs NOTICES](https://github.com/falcosecurity/libs/blob/master/NOTICES); [libs releases](https://github.com/falcosecurity/libs/releases)
- Packaging: Falco ships its own repos rather than distro packages.
  - DEB: `deb [signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] https://download.falco.org/packages/deb stable main`, then `apt-get install -y falco`.
  - RPM: import `https://falco.org/repo/falcosecurity-packages.asc`, then install with yum/dnf on CentOS/RHEL/Fedora/Amazon Linux.
  - The package sets up systemd units and falcoctl rule auto-update. `FALCO_DRIVER_CHOICE=kmod|modern_ebpf|none`, `FALCO_FRONTEND=noninteractive` and `FALCOCTL_ENABLED=no` allow unattended installs. The kmod path needs `dkms make linux-headers-$(uname -r)`.
  - — [Falco packages docs](https://falco.org/docs/setup/packages/)
- No Falco package exists in the Debian/Ubuntu/EPEL/Fedora/Alma/Rocky repos that Repology tracks; only the vendor repo is available. — [Repology falco](https://repology.org/project/falco/versions)
- Rules (falcosecurity/rules) are Apache-2.0. The latest release is falco-rules-5.2.0 (2026-09-07). The main branch on 2026-11-09 had 25 stable rules (`falco_rules.yaml`), 32 incubating and 39 sandbox. Each rule is tagged with maturity, host/container scope and MITRE technique (e.g., "Fileless execution via memfd_create" maps to T1620). — [falco_rules.yaml](https://github.com/falcosecurity/rules/blob/main/rules/falco_rules.yaml); [incubating](https://github.com/falcosecurity/rules/blob/main/rules/falco-incubating_rules.yaml); [sandbox](https://github.com/falcosecurity/rules/blob/main/rules/falco-sandbox_rules.yaml)
- Falco Talon is a "Response Engine for managing threats in your Kubernetes". Its last release is v0.3.0 (2025-02-05), although the repo was still pushed 2026-11-04.
  - Actionners are kubernetes:terminate, label, annotation, networkpolicy, exec, script, log, download, tcpdump, sysdig, cordon, drain and delete, plus calico:networkpolicy, cilium:networkpolicy, aws:lambda and gcp:function.
  - It has no actionner that kills or quarantines a process on a bare host.
  - — [falco-talon repo](https://github.com/falcosecurity/falco-talon); [Talon actionners list](https://falco-talon.github.io/docs/actionners/list/)
- falcosidekick (Apache-2.0, pushed 2026-11-08) forwards Falco events to many outputs, including **Discord** and generic webhooks. — [falcosidekick README](https://github.com/falcosecurity/falcosidekick)

**Tetragon (Cilium/Isovalent)**
- Status: repo SPDX Apache-2.0 and pushed 2026-11-09. The README shows Apache-2.0, BSD-2-Clause and GPL-2.0 license badges (userspace vs BPF code). Releases: v1.8.0 (2026-10-30), v1.9.0-pre.0 (2026-10-30), v1.7.1 (2026-08-25). — [cilium/tetragon](https://github.com/cilium/tetragon); [releases](https://github.com/cilium/tetragon/releases)
- Kernel requirements:
  - It "needs Linux kernel version 4.19 or greater" and is tested on 4.19, 5.4, 5.10, 5.15 and bpf-next.
  - "Not all Tetragon features work with older kernel versions."
  - On arm64 with 4.19/5.4 kernels, exec-argument reading may break, so 5.10+ is recommended there.
  - It needs BTF. It searches `/sys/kernel/btf/vmlinux`, then `/var/lib/tetragon/btf`, and accepts a `--btf` flag.
  - Required config includes `CONFIG_DEBUG_INFO_BTF`, `CONFIG_DEBUG_INFO_BTF_MODULES` and, for enforcement, `CONFIG_BPF_KPROBE_OVERRIDE`.
  - `tetra probe` reports runtime features such as override_return, kprobe_multi, fmodret, signal and lsm.
  - — [Tetragon FAQ](https://tetragon.io/docs/installation/faq/)
- Enforcement has two mechanisms, both documented in the [enforcement docs](https://tetragon.io/docs/concepts/enforcement/):
  - **Override return value**: "the function will never be executed", and an error is returned instead.
  - **Signals**: e.g., SIGKILL. SIGKILL "does not always stop the operation" (a write may still land) but terminates the process synchronously. Combine Signal with Override to guarantee the operation is blocked.
- Policy actions are available in the [TracingPolicy selectors docs](https://tetragon.io/docs/concepts/tracing-policy/selectors/):
  - Available actions include Sigkill, Signal, Override, GetUrl, DnsLookup, Post and NoPost.
  - Override is available for kprobes, uprobes and LSM hooks. It "uses the kernel error injection framework and is only available on kernels compiled with CONFIG_BPF_KPROBE_OVERRIDE". It works only on syscalls and on functions marked `ALLOW_ERROR_INJECTION`. Overriding `security_` hooks is possible from kernel 5.7.
  - The NotifyEnforcer action is a workaround for kernels without multi-kprobe support (kprobe_multi link).
- Events are process_exec, process_exit, process_kprobe, process_tracepoint, process_lsm, process_uprobe and process_loader, exported as JSON with export filters. — [Tetragon events docs](https://tetragon.io/docs/concepts/events/)
- Example policies in the repo cover:
  - `host-changes/monitor-kernel-modules.yaml` and `monitor-signed-kernel-modules.yaml`
  - `process-credentials/*` (creds changed or installed)
  - `tcp-connect.yaml` and `tcp-accept.yaml`
  - `security_bprm_check.yaml`, `lsm_bprm_check.yaml` and `lsm_file_open.yaml`
  - `sys_setuid.yaml`, `sys_ptrace.yaml`, `bpf.yaml` and `killer.yaml`
  - `cves/cve-2024-3094-xz-ssh.yaml`
  - — [tetragon/examples/tracingpolicy](https://github.com/cilium/tetragon/tree/main/examples/tracingpolicy)
- Install on non-Kubernetes hosts uses a release tarball plus `install.sh`, which creates a systemd `tetragon.service` for amd64/arm64. Config lives in `/usr/local/lib/tetragon/tetragon.conf.d/` with drop-ins in `/etc/tetragon/tetragon.conf.d/`. The documented example `systemctl status` shows "Memory: 151.7M". No distro packages exist (Repology). — [Tetragon package install](https://tetragon.io/docs/installation/package/); [Repology tetragon](https://repology.org/project/tetragon/versions)

**Tracee (Aqua Security)**
- Status: repo SPDX Apache-2.0, last push 2026-11-01. The **last release is v0.24.1 (2025-11-19)**, so there has been no release for about 12 months. — [aquasecurity/tracee releases](https://github.com/aquasecurity/tracee/releases)
- Aqua's product page describes Tracee as the eBPF engine behind Aqua Platform capabilities: Dynamic Threat Analysis, container sandbox and CNDR. This comes from a search-result snippet; the page itself was not fetched. — [Aqua Tracee product page](https://www.aquasec.com/products/tracee/)
- Prerequisites:
  - BTF (`/sys/kernel/btf/vmlinux`). BTFHub covers older kernels: CentOS 8 < 4.18.0-193, RHEL 8 <= 4.18.0-147, Debian 10 with 5.10.
  - `/proc/kallsyms` for events like hidden_kernel_module, hooked_syscall and hooked_seq_ops.
  - LTS kernels 5.4, 5.10, 5.15, 6.2 and 6.5, plus the CentOS 8 4.18 kernel.
  - "Regular build" distros: Amazon Linux 2, CentOS 8+, Debian 11+, Fedora 38+, RHEL 8 (newer 4.18)+.
  - Capabilities: CAP_BPF+CAP_PERFMON (>=5.8) or CAP_SYS_ADMIN, plus CAP_SYS_RESOURCE.
  - — [Tracee prerequisites](https://aquasecurity.github.io/tracee/latest/docs/install/prerequisites/)
- Tracee statically embeds libbpf via libbpfgo. — [libbpfgo repo](https://github.com/aquasecurity/libbpfgo)

**KubeArmor**
- Status: userspace Apache-2.0, but the BPF C sources carry `SPDX-License-Identifier: GPL-2.0`. Releases: v1.7.6 (2026-10-23), v1.7.7-rc1 (2026-10-30). — [KubeArmor repo](https://github.com/kubearmor/KubeArmor); [system_monitor.c header](https://github.com/kubearmor/KubeArmor/blob/main/KubeArmor/BPF/system_monitor.c)
- It supports "VM/Bare-Metals ... Kubearmor is deployed in systemd mode", with LSM enforcers "BPFLSM, AppArmor". Separate policy specs exist for Nodes/VMs, including network policies. — [KubeArmor support matrix](https://docs.kubearmor.io/kubearmor/quick-links/support_matrix)
- VM install uses a `.deb` (`apt --no-install-recommends install ./kubearmor_${VER}_linux-amd64.deb`) or a tarball. It runs as a systemd process with the `karmor` CLI. Without BTF, the recommended packages (BCC prerequisites) are needed. — [KubeArmor VM deployment](https://docs.kubearmor.io/kubearmor/quick-links/kubearmor_vm)

**sysdig OSS, bpftrace, Kunai**
- sysdig (CLI): COPYING is Apache-2.0, with "contents of the driver/ subdirectory ... licensed separately". The last release is 0.41.4 (2026-01-29) and the last push 2026-04-13, so it is slowing. Distro packages: Debian 12 0.29.3, Ubuntu 24.04 0.36.0, Ubuntu 26.04 0.40.0. — [draios/sysdig](https://github.com/draios/sysdig); [Repology sysdig](https://repology.org/project/sysdig/versions)
- bpftrace: Apache-2.0, latest v0.27.1 (2026-10-24). It is packaged almost everywhere:
  - Debian 11/12/13: 0.11.3 / 0.17.0 / 0.23.2
  - Ubuntu 20.04/22.04/24.04/26.04: 0.9.4 / 0.14.0 / 0.20.2 / 0.25.0
  - Alma/Rocky 9: 0.24.2; Alma/Rocky 8: 0.16.0
  - CentOS Stream 10: up to 0.26.1; Fedora 43/44: 0.24.2
  - — [bpftrace releases](https://github.com/bpftrace/bpftrace/releases); [Repology bpftrace](https://repology.org/project/bpftrace/versions)
- SigmaHQ ships a rule for bpftrace unsafe-option usage (`proc_creation_lnx_bpftrace_unsafe_option_usage.yml`), i.e., attackers abuse the tool too. — [SigmaHQ rules/linux](https://github.com/SigmaHQ/sigma/tree/master/rules/linux/process_creation)
- Kunai (CIRCL) is GPL-3.0. — [kunai LICENSE](https://github.com/kunai-project/kunai)

**Independent overhead measurements (treat as indicative)**
- GitHub benchmark "EBPF-Runtime-Detection-Benchmark", run 2026-10-25. Setup: Debian 13, kernel 6.12.105, BTF, BPF-LSM enabled, 8 CPUs, 24 attack and 6 benign scenarios, 5 repetitions each. Tool CPU is a median percent of one core under synthetic exec/syscall/fileio workloads.
  - Falco 0.45.0, default/tuned profile: 30% / 60% of a core, 124 / 127 MiB. Median syscall latency +8.2% / +8.9%; `openat` p50 +32–36%. "Cannot block anything." Best out-of-the-box recall (45.8%, tied with Tetragon).
  - Tetragon 1.7.1: about 0.1% median CPU, but about 38% of a core during the exec workload, because probe cost is charged to the monitored processes. Memory 371–436 MiB. With tuned/enforce policies, median syscall latency rose +72% to +84% (`read` p50 about +2,500%, exec throughput −43%). Enforce prevented 22/24 attacks synchronously with no collateral damage. On that Debian kernel `CONFIG_BPF_KPROBE_OVERRIDE` was absent, so only Sigkill was available.
  - Tracee 0.24.1: 145–164% of a core, 153–159 MiB, `openat` +106% to +174%, no blocking.
  - KubeArmor 1.7.5: 21–25% of a core, 310–372 MiB, `openat` about +200%. BPF-LSM enforce prevented 22/24 attacks. It emitted 430k–580k telemetry lines per minute, and its default policies flagged every benign scenario.
  - Kunai 0.6.2: smallest footprint (0.06 core, 92 MiB). Its kill action runs after the event and prevented only 3/24 attacks, and an unscoped kill rule killed dockerd.
  - Pulsar was heaviest (2.7–2.9 cores, 4.5–5.2 GiB).
  - — [sammonsempes/EBPF-Runtime-Detection-Benchmark](https://github.com/sammonsempes/EBPF-Runtime-Detection-Benchmark)
- 2025 peer-reviewed conference paper (SciTePress), Kubernetes testbed with xmrig, container escape and DoS scenarios:
  - Tetragon was the most CPU-efficient: 6.5 millicores baseline, 6.9 under attack, but the highest memory at 634.59 MB.
  - Falco had the lowest memory (397.33 MB) but used 431.5–433.5 millicores.
  - Tracee used 91.6–93.7 millicores and 573 MB.
  - All three tools detected all attacks (DR 100%, FPR 0%).
  - — [Syairozi & Arizal 2025, "Comparative Analysis of eBPF-Based Runtime Security Monitoring Tools"](https://www.scitepress.org/Papers/2025/142727/142727.pdf)
- The two studies disagree on Falco CPU (low in the GitHub benchmark, high in the Kubernetes paper) and on memory figures. Absolute numbers depend heavily on workload, event rate and deployment mode (Kubernetes DaemonSet vs host). — compare [GitHub benchmark](https://github.com/sammonsempes/EBPF-Runtime-Detection-Benchmark) with [SciTePress paper](https://www.scitepress.org/Papers/2025/142727/142727.pdf)

### Inferences
- **Kernel mechanisms in use.** All of these tools attach to raw syscall tracepoints, sched tracepoints, kprobes/fentry, and, where available, LSM hooks.
  - Falco's modern probe relies on tracing programs plus the ring buffer.
  - Tetragon adds kprobe/LSM attachment with in-kernel filtering and actions.
  - KubeArmor relies on BPF-LSM (or AppArmor) for denials.
- **Blocking ability, ranked:** Tetragon (synchronous kill and override) ≈ KubeArmor (LSM deny) > Kunai (asynchronous kill) > Falco/Tracee/sysdig/bpftrace (detect only). Falco Talon does not help on a VPS without Kubernetes.
- **None is "embeddable" in a closed Go binary.**
  - Falco/libs is C++. Embedding it means CGO plus the dual MIT/GPL driver; in practice the integration route is Falco's JSON file/HTTP output (gRPC output was removed in 0.44).
  - Tetragon and KubeArmor are full daemons with their own policy CRDs/YAML.
  - Each is a candidate for "run alongside" (separate process, permissive license, ingest JSON), not for linking.
- **Overhead targets for a VPS product.** Falco's roughly 125 MiB RSS and Tetragon's roughly 370–440 MiB are large for a 1 GB VPS. A purpose-built Go agent that filters in-kernel with a small event set (exec, exit, connect, a short list of file paths, module loads, memfd) should beat these. This needs validation with the same benchmark methodology.
- **Maintenance flags.** Tracee: no release since Nov 2025. sysdig OSS: no push since Apr 2026. Falco Talon: no release since Feb 2025. Falco, Tetragon, KubeArmor and bpftrace are actively released (Sep–Nov 2026).

### Gaps
- No vendor-neutral overhead numbers exist for these tools on small 1–2 vCPU VPS instances. Both studies used 8-CPU or Kubernetes hosts.
- The exact Tetragon license split (userspace Apache-2.0, BPF dual GPL-2.0/BSD-2) was inferred from README badges; the LICENSE files in `bpf/` were not read.
- KubeArmor's CNCF maturity level, AccuKnox's role and RPM availability for systemd mode were not verified.
- Distro defaults for BPF-LSM (`bpf` in the active `lsm=` list) and `CONFIG_BPF_KPROBE_OVERRIDE` across Ubuntu, RHEL and AL2023 were not verified. Only the Debian 13 benchmark host data point is known: BPF-LSM enabled, no KPROBE_OVERRIDE.

---

## 2. Linux audit stack and other non-eBPF interfaces: auditd/audit rules, go-libaudit, Laurel, go-audit, Snoopy, process accounting, proc connector, fanotify vs inotify

### Takeaway
- The audit subsystem gives rich, attributed telemetry with no BTF requirement: execve with args, file watches with pid/uid/auid/exe, module loads. It has the best kernel coverage of any of these interfaces, but it has real pitfalls:
  - The kernel backlog default is 64.
  - Failure modes range from silent loss to panic.
  - Only one process can own the audit netlink.
  - It works only in the initial user namespace, so it is unusable inside unprivileged containers.
- The proc connector is cheap but gives pids only, and only from the initial user and pid namespace.
- fanotify gives pids and can **block** opens and execs with permission events (5.0+).
- inotify gives no process attribution.
- Snoopy and process accounting are weak, bypassable or post-hoc sources.

### Cited Findings
- **auditd/auditctl controls:** `-b backlog` sets the max outstanding audit buffers (kernel default 64). `--backlog_wait_time` defaults to 60*HZ: the kernel waits this long when the backlog is full before queuing more. `-f [0..2]` sets the failure mode (0=silent, 1=printk, 2=panic). `-r rate` sets a messages-per-second limit, and exceeding it consults the failure flag. `--reset-lost` resets the lost-record counter. — [auditctl(8)](https://man7.org/linux/man-pages/man8/auditctl.8.html)
- **Namespace restriction:** kernel `audit_netlink_ok()` returns `-ECONNREFUSED` when `current_user_ns() != &init_user_ns`, with the comment "Only support initial user namespace for now". So audit control is unavailable inside user-namespaced containers (e.g., unprivileged LXC). — [kernel/audit.c (master, 7.4-rc2)](https://github.com/torvalds/linux/blob/master/kernel/audit.c)
- The kernel also multicasts audit records to a read-only netlink group (`AUDIT_NLGRP_READLOG`, in `kauditd_send_multicast_skb`) bound to `init_net`. — [kernel/audit.c](https://github.com/torvalds/linux/blob/master/kernel/audit.c)
- **Packages and versions:**
  - Debian/Ubuntu install `auditd` and `audispd-plugins`; RHEL family installs `audit` and `audispd-plugins`. — [Wazuh FIM advanced settings](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/advanced-settings.html)
  - Upstream is audit-userspace (GPL-2.0), latest audit-4.2.1 (2026-07-29). — [linux-audit/audit-userspace](https://github.com/linux-audit/audit-userspace/releases)
  - Distro versions: Debian 11 3.0, Debian 12 3.0.9, Debian 13 4.0.2; Ubuntu 20.04 2.8.5, 22.04 3.0.7, 24.04 3.1.2, 26.04 4.1.2; Alma/Rocky 8 3.1.2, 9 3.1.5; CentOS Stream 10 up to 4.2.1. — [Repology audit](https://repology.org/project/audit/versions)
- **Coexistence conflicts:**
  - osquery "cannot share access to the Audit subsystem with auditd". — [osquery FIM docs](https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/)
  - osquery warns that throttling "may cause loss of events, since the Audit subsystem backlog buffer could fill up", and exposes `--audit_backlog_limit`. — [osquery process auditing](https://osquery.readthedocs.io/en/stable/deployment/process-auditing/)
  - Wazuh who-data in audit mode needs the af_unix audispd plugin for audit >= 3.1.1, and the default `-a never,task` rule must be removed or no who-data is produced. — [Wazuh FIM advanced settings](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/advanced-settings.html)
- **elastic/go-libaudit:** Apache-2.0, a Go library speaking the audit netlink protocol, with an `auparse` log parser. Its example client says "the system's auditd process should be stopped first". Latest v2.6.2 (2025-03-18); last push 2026-08-11, so it is in maintenance mode but alive. — [go-libaudit README](https://github.com/elastic/go-libaudit); [releases](https://github.com/elastic/go-libaudit/releases)
- **Laurel:**
  - GPL-3.0, an auditd plugin that turns audit events into enriched JSON (decoded EXECVE argv, parent-process info). Latest v0.8.2 (2026-07-17). — [Laurel README](https://github.com/threathunters-io/laurel)
  - On an AWS t2.small running Amazon Linux 2, auditd + dispatcher + Laurel used "about twice" the CPU of plain auditd with `log_format=ENRICHED`. — [Laurel performance](https://github.com/threathunters-io/laurel/blob/master/performance.md)
- **slackhq/go-audit:** MIT, a replacement for the auditd daemon that connects via netlink and outputs JSON. Latest v1.2.2 (2026-06-22). — [go-audit README](https://github.com/slackhq/go-audit); [releases](https://github.com/slackhq/go-audit/releases)
- **Snoopy:**
  - GPL-2.0, a library that logs all program executions; latest 2.5.2 (2024-10-24). Since 2.5.0 there are vendor package repos.
  - Its own README warns: "**Snoopy is not a reliable auditing solution.** Rogue users can easily manipulate environment to avoid their actions being logged".
  - — [Snoopy README](https://github.com/a2o/snoopy)
- **Process accounting:**
  - Records are written "as each process on the system terminates", and the command name is limited (`ACCT_COMM 16`). — [acct(5)](https://man7.org/linux/man-pages/man5/acct.5.html)
  - Packages: `acct` 6.6.4 on Debian 11–13 and Ubuntu 20.04–26.04; `psacct` 6.6.3/6.6.4 on Alma/Rocky 8/9, CentOS Stream 10 and Fedora. — [Repology acct](https://repology.org/project/acct/versions); [Repology psacct](https://repology.org/project/psacct/versions)
- **Netlink proc connector:**
  - Event types: FORK, EXEC, UID, GID, SID, PTRACE, COMM, COREDUMP, EXIT (`PROC_EVENT_*` constants). — [vishvananda/netlink proc_event_linux.go](https://github.com/vishvananda/netlink/blob/main/proc_event_linux.go)
  - The kernel ignores subscription requests unless the requester is in the initial user **and** pid namespace ("Events are reported with respect to the initial pid and user namespaces so ignore requestors from other namespaces"). — [drivers/connector/cn_proc.c](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/connector/cn_proc.c)
  - The connector socket is created only in `init_net`. — [drivers/connector/connector.c](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/connector/connector.c)
  - A 2017 RFC stated "cn_proc is not usable by containers or container runtimes". — [LKML RFC (2017)](https://lkml.iu.edu/1710.1/06353.html)
- **inotify** "provides no information about the user or process that triggered the inotify event". It is not recursive, does not report mmap-based modifications, and cannot monitor /proc or /sys. — [inotify(7)](https://man7.org/linux/man-pages/man7/inotify.7.html)
- inotify caveats in practice: watches are lost when a watched file is deleted, a "modify" fires on every open-for-write, and very large directory trees exhaust watches (default `max_user_watches` 8192). — [osquery FIM docs](https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/)
- **fanotify:**
  - Event metadata carries the `pid` of the process that caused the event. Since Linux 5.13 (and 5.10.220), tunables `/proc/sys/fs/fanotify/max_queued_events` etc. exist. — [fanotify(7)](https://man7.org/linux/man-pages/man7/fanotify.7.html)
  - `FAN_REPORT_FID` since 5.1, `FAN_REPORT_PIDFD` since 5.15 (and 5.10.220). Most classes, including `FAN_CLASS_CONTENT`, require CAP_SYS_ADMIN. — [fanotify_init(2)](https://man7.org/linux/man-pages/man2/fanotify_init.2.html)
  - `FAN_MARK_FILESYSTEM` since 4.20; `FAN_OPEN_EXEC` and **`FAN_OPEN_EXEC_PERM` since 5.0**: a permission event on exec that the listener must allow or deny. `FAN_CREATE`/`FAN_DELETE`/`FAN_MOVED_*` since 5.1. — [fanotify_mark(2)](https://man7.org/linux/man-pages/man2/fanotify_mark.2.html)

### Inferences
- **Audit as Tier-2 sensor.** For kernels without BTF (Ubuntu 20.04 GA, CentOS 7-era) or where eBPF is locked down, audit is the best fallback. Use execve with `-F arch=b64/b32`, `-S init_module,finit_module`, and watches (`-w`) on `/etc/cron*`, `/var/spool/cron`, `/etc/systemd/system`, `/usr/lib/systemd/system`, `~/.ssh/authorized_keys`, `/etc/ld.so.preload` and `/etc/passwd`.
- **Tuning required for audit.** Raise `-b` to 8192 or more, keep `-f 1` (never 2 on customer servers), and set `backlog_wait_time` low to avoid stalling processes.
- **One audit owner.** Only one daemon can own audit configuration. On hosts where customers already run auditd (common on RHEL for compliance), the agent should read the multicast group or tail `audit.log` rather than replace auditd. go-libaudit's multicast client API needs verification (see Gaps).
- **Proc connector is a cheap "exec trigger" only.** It carries no argv, path or cwd, so the agent must race to read `/proc/<pid>/{exe,cmdline,status}`, and short-lived processes such as `curl … | sh` can be missed. It is useless inside OpenVZ/LXC guests.
- **fanotify is the most useful non-eBPF primitive for a VPS EDR.**
  - It provides attributed file events (pid → `/proc` lookup).
  - `FAN_OPEN_EXEC_PERM` lets the policy engine deny exec of known-bad hashes received from the master server (a hash blocklist) on kernels ≥ 5.0 without BPF-LSM.
  - The agent must answer permission events fast, and fail open on timeout, or it can hang the host. This is a design inference.
- **Avoid linking GPL components.** Snoopy (LD_PRELOAD into every process, GPL-2.0, self-declared unreliable) and process accounting (exit-time only, 16-char comm) are not worth shipping. Laurel is GPL-3.0, so only run it as a separate process if at all.

### Gaps
- Quantitative overhead of execve auditing on small VPS was not found, beyond Laurel's relative "about 2x auditd" figure on a t2.small.
- go-libaudit's multicast (read-only) client support was not confirmed from its README in this session.
- Whether OpenVZ/Virtuozzo guests expose fanotify was not verified.

---

## 3. osquery (+ Fleet): EDR-relevant tables, evented vs scheduled, footprint, license, packaging

### Takeaway
osquery is an excellent permissively-licensed (Apache-2.0 option) inventory and forensic engine. It has tables for processes (including `on_disk` for deleted binaries), crontab, systemd units, authorized_keys, packages, kernel modules and YARA. Its evented tables, however, rely on audit (conflicts with auditd) or a BPF publisher (kernel ≥ 4.18), and its watchdog defaults (200 MB, 10% CPU) signal a heavier footprint than a purpose-built sensor. Use it as an optional bundled or alongside "query engine", not as the real-time sensor.

### Cited Findings
- **License:** "SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only. If you're using osquery you are free to choose one of the provided licenses." — [osquery LICENSE](https://github.com/osquery/osquery/blob/master/LICENSE)
- **Status:** latest 5.24.1 (2026-11-04), 5.24.0 (2026-10-21), 5.23.0 (2026-05-05). — [osquery releases](https://github.com/osquery/osquery/releases)
- **Packaging:** "Each osquery tag (stable release) is published to yum and apt repositories ... https://osquery.io/downloads". It is not in Debian/Ubuntu/EPEL repos tracked by Repology. — [osquery Linux install](https://osquery.readthedocs.io/en/stable/installation/install-linux/); [Repology osquery](https://repology.org/project/osquery/versions)
- **Tables present in the specs on 2026-11-09** (Linux/POSIX/cross-platform), from [osquery specs](https://github.com/osquery/osquery/tree/master/specs):
  - Processes and memory: `processes` (has an `on_disk` column), `process_envs`, `process_open_files`, `process_open_sockets`, `process_memory_map`, `process_namespaces`
  - Evented: `process_events`, `socket_events`, `bpf_process_events`, `bpf_socket_events`, `process_file_events`, `file_events`, `seccomp_events`, `selinux_events`, `apparmor_events`
  - Persistence and system state: `crontab`, `systemd_units`, `startup_items`, `authorized_keys`, `user_ssh_keys`, `suid_bin`, `kernel_modules`
  - Packages: `deb_packages`, `rpm_packages`
  - Activity and network: `shell_history`, `last`, `logged_in_users`, `listening_ports`, `iptables`
  - Hashing and YARA: `hash`, `yara`/`yara_events`/`yara_process`/`yara_file`
  - Containers: `docker_*` and `lxd_*`
- **Event sources:**
  - `process_events`/`socket_events` use Audit. `bpf_process_events`/`bpf_socket_events` use BPF on "Linux (kernel 4.18 and newer)". "Enabling any of them may have performance impact."
  - Audit flags: `--disable_audit=false`, `--audit_allow_config=true`, `--audit_allow_process_events=true`, `--audit_allow_sockets`.
  - BPF needs `--disable_events=false --enable_bpf_events=true`. Its memory is `buffer_storage_bytes = memory_pool_count * (bpf_buffer_storage_size * 4096) * possible_cpu_count` plus the perf array.
  - — [osquery process auditing](https://osquery.readthedocs.io/en/stable/deployment/process-auditing/)
- **FIM:** `file_events` uses inotify; `process_file_events` uses Audit. — [osquery FIM docs](https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/)
- **Footprint guardrails:** watchdog level 0 limits memory to "default 200M, restrictive 100M". The CPU limit is 10% sustained for `watchdog_latency_limit` (default 12 s). `--watchdog_delay=60` grants a startup grace period. — [osquery CLI flags](https://osquery.readthedocs.io/en/stable/installation/cli-flags/)
- **Fleet:** the LICENSE is "MIT Expat" except content under `ee/` (its own license) and `docs/` (CC BY-SA 4.0). Latest Fleet v4.94.1 (2026-11-06) and orbit-v1.63.0 (2026-10-30). — [Fleet LICENSE](https://github.com/fleetdm/fleet/blob/main/LICENSE); [Fleet releases](https://github.com/fleetdm/fleet/releases)
- **Wazuh deprecation:** Wazuh 5.0 pre-release docs say osquery references were removed because "this capability is now deprecated" in Wazuh. — [Wazuh 5.0-beta agent migration docs](https://documentation.wazuh.com/5.0-beta/migration-to-5x/wazuh-agents.html)

### Inferences
- **Scheduled queries vs real-time.** Scheduled queries (every N minutes) against `processes WHERE on_disk = 0`, `crontab`, `systemd_units`, `authorized_keys`, `kernel_modules`, `suid_bin`, and `hash` of `/usr/bin` vs `deb_packages`/`rpm_packages` cover most of the incident's persistence artifacts. They are not real-time, so a miner can run and exfiltrate between polls.
- **Licensing makes bundling viable.** The Apache-2.0 option lets the company ship osqueryd as a separate binary and use it as the "investigation backend" for the AI layer (SQL is a safe, read-only query surface). The real-time path should be the company's own eBPF/fanotify sensor.
- **Fleet as a design reference.** Fleet's open core (MIT) is a reference for agent management and enrollment design. Its `ee/` features are proprietary and should not be copied.

### Gaps
- No independent CPU/RAM measurements of osqueryd with BPF events enabled on small VPS were found.
- The exact osquery package names (`osquery`) and repo URLs on pkg.osquery.io were not re-fetched; only the docs pointer was confirmed.

---

## 4. Wazuh in depth, OSSEC status, and realistic build/fork/hybrid options

### Takeaway
Wazuh is a complete open-source HIDS/XDR covering:
- log analysis
- FIM with who-data (audit or eBPF since 4.12)
- rootkit checks
- SCA
- vulnerability detection
- active response
- Docker monitoring

Its agent is light (about 35 MB RAM average), but the server stack is heavy: the indexer needs 4 GB RAM minimum and 16 GB recommended, and all-in-one deployments are sized at 8 GiB. Its licensing is hostile to closed-source embedding:
- GPLv2 covers source and rules/decoders, with a broad "derivative work" definition written into the license.
- The new 5.0 engine is AGPL-3.0.
- Wazuh 5.0 (RC2, Oct 2026) is a breaking re-architecture.

For this product, building a company-owned Go agent beats forking. At most, add an integration that forwards alerts into a customer's existing Wazuh.

### Cited Findings
- **Architecture:** a multi-platform agent plus three central components: Wazuh server, Wazuh indexer and Wazuh dashboard.
  - Ports: agent → server TCP 1514, enrollment 1515/TCP, server API 55000, indexer 9200.
  - Agent messages use AES (128-bit block, 256-bit key) by default.
  - In 4.x the server ships alerts to the indexer via Filebeat.
  - Deployment modes: all-in-one, single-node and multi-node.
  - — [Wazuh architecture](https://documentation.wazuh.com/current/getting-started/architecture.html)
- **Footprint:**
  - All-in-one sizing (90-day retention): 1–25 agents need 4 vCPU, 8 GiB RAM, 50 GB; 26–50 agents need 8 vCPU, 8 GiB, 100 GB; 51–100 agents need 8 vCPU, 8 GiB, 200 GB. — [Wazuh quickstart](https://documentation.wazuh.com/current/quickstart.html)
  - Indexer per node: minimum 4 GB RAM / 2 cores, recommended 16 GB / 8 cores. Supported central-component OSes: Amazon Linux 2/2023, CentOS Stream 10, RHEL 7–10, Ubuntu 16.04–24.04 (Debian is not in the list). — [Wazuh indexer install](https://documentation.wazuh.com/current/installation-guide/wazuh-indexer/index.html)
  - "The Wazuh agent ... requires 35 MB of RAM on average". Agent features: log collector, command execution, FIM, SCA, system inventory, malware detection. — [Wazuh agent](https://documentation.wazuh.com/current/installation-guide/wazuh-agent/index.html)
- **Capabilities** (from the [Wazuh capabilities index](https://documentation.wazuh.com/current/user-manual/capabilities/index.html)):
  - FIM
  - Malware detection: rootkits behavior detection, CDB lists/threat intel, VirusTotal, FIM+YARA, ClamAV logs
  - SCA
  - Active Response
  - Log data collection and analysis (incl. journald)
  - Vulnerability detection
  - Command monitoring
  - Container security ("Using Wazuh to monitor Docker")
  - System inventory (Syscollector)
  - Osquery
  - Monitoring system calls
  - Agentless monitoring
- **FIM who-data:**
  - Audit mode is the default provider.
  - **eBPF mode** "requires a kernel that supports the BPF ring buffer and BTF". Upstream support starts at 5.8, with distro backports "such as RHEL 8.10 (kernel 4.18)".
  - A failed health check falls back to audit.
  - Who-data fields include `audit.process.id/name/ppid`, user, login user and effective user.
  - — [Wazuh FIM advanced settings](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/advanced-settings.html)
  - eBPF who-data arrived in 4.12.0 ("#27956 Added eBPF-based integration to support whodata in FIM"). — [Wazuh 4.12.0 release notes](https://documentation.wazuh.com/current/release-notes/release-4-12-0.html)
- **Active response:**
  - Scripts run on endpoints when an alert of a specific rule ID, level or group fires. Responses are stateless or stateful (reverted after a timeout).
  - Default scripts include `disable-account`, `firewall-drop`, `host-deny`, `ipfw`/`pf`/`npf` variants, `restart.sh`/`restart-wazuh` and `wazuh-slack`.
  - — [Wazuh active response](https://documentation.wazuh.com/current/user-manual/capabilities/active-response/index.html); [default AR scripts](https://documentation.wazuh.com/current/user-manual/capabilities/active-response/default-active-response-scripts.html)
- **Status and versions:**
  - Stable v4.14.10 (2026-11-09) and v4.14.9 (2026-10-15). **v5.0.0-rc2 (2026-10-30)** and rc1 (2026-10-05). — [wazuh/wazuh releases](https://github.com/wazuh/wazuh/releases)
  - The standalone `wazuh/wazuh-ruleset` repo is **archived** (last push 2024-09-19). — [wazuh-ruleset](https://github.com/wazuh/wazuh-ruleset)
- **Wazuh 5.0 RC2 changes** (from the [v5.0.0-rc2 release notes](https://github.com/wazuh/wazuh/releases/tag/v5.0.0-rc2)):
  - An HTTPS agent–manager transport replaces "the legacy MQ/DGRAM-based agent-manager protocol end to end".
  - A new Wazuh Engine (`wazuh-manager-analysisd`) with a new ruleset replaces 4.x analysisd.
  - Cluster-by-default.
  - Enrollment tokens.
  - Removals: Filebeat ("event forwarding now uses native Wazuh server connectivity to the Wazuh Indexer"), the agent-auth tool, the OpenSCAP server-side module and SELinux integration. Rootcheck is simplified.
  - 4.x "cannot be upgraded in place to Wazuh 5.x"; a migration is required. — [Wazuh 5.0 migration guide (RC docs)](https://documentation.wazuh.com/5.0-rc/migration-to-5x/index.html)
  - Agents ≤ 4.14.0 must reach 4.14.x before upgrading to 5.0. — [Wazuh 5.0 RC upgrade docs](https://documentation.wazuh.com/5.0-rc/user-manual/agent/agent-management/upgrade-agents-remotely.html)
- **Licensing** (main branch LICENSE, i.e., 5.x; see [wazuh LICENSE (main)](https://github.com/wazuh/wazuh/blob/main/LICENSE)):
  - The Wazuh engine (`src/engine/`) is under **AGPL-3.0-or-later**.
  - Shared libraries linked by engine, manager and agent are `GPL-2.0-only OR AGPL-3.0-or-later`.
  - "Everything else is licensed under the GNU General Public License (version 2)".
  - The license "applies to the source code, as well as decoders, rules and any other data file included with Wazuh".
  - The LICENSE defines as a "derivative work" anything that "Integrates source code/data files from Wazuh; Includes Wazuh copyrighted material; Includes/integrates Wazuh into a proprietary executable installer; Links to a library or executes a program that does any of the above".
  - The 4.14.10 LICENSE has the same GPLv2 text and derivative-work clause, without the AGPL engine part. — [wazuh LICENSE (v4.14.10)](https://github.com/wazuh/wazuh/blob/v4.14.10/LICENSE)
  - `wazuh-indexer` and `wazuh-dashboard` are Apache-2.0 (OpenSearch forks). The quickstart says components "abide by the GNU General Public License, version 2, and the Apache License, Version 2.0". — [wazuh-indexer](https://github.com/wazuh/wazuh-indexer); [wazuh-dashboard](https://github.com/wazuh/wazuh-dashboard); [quickstart](https://documentation.wazuh.com/current/quickstart.html)
- **OSSEC:** ossec-hids (GPL-2.0) is still released: 4.3.0 (2026-08-25), 4.4.0 (2026-10-05), 4.4.1 (2026-10-18). The 4.4.1 release entry is titled "OSSEC changelog (4.4.1) <support@atomicorp.com>", i.e., Atomicorp-maintained. — [ossec/ossec-hids releases](https://github.com/ossec/ossec-hids/releases)

### Inferences
- **Strengths for VPS fleets:**
  - Mature log-based detection of SSH brute force and auth anomalies.
  - FIM with who-data.
  - Rootcheck for trojaned binaries and hidden processes.
  - SCA/CIS hardening.
  - Vulnerability detection.
  - A tiny agent.
- **Weaknesses for VPS fleets:**
  - A central stack (OpenSearch-based indexer) that costs more RAM than many customer VPS have.
  - Rule-and-decoder detection on logs and FIM rather than kernel process telemetry: no native exec-chain or eBPF process tree. Who-data covers file changes only.
  - Active response is script-based and alert-triggered.
  - 5.0 is a forced migration with protocol and engine changes.
- **Option A, fork Wazuh:** not viable for a closed-source commercial product.
  - GPLv2 and AGPL obligations, plus Wazuh's broad derivative-work interpretation (proprietary installers, "executes a program that does any of the above"), would force source release.
  - It would also mean tracking a 5.0 rewrite.
  - Legal review needed if considered.
- **Option B, build an own Go agent (recommended):** reuse permissive libraries (Section 8), learn from Wazuh's feature set (FIM who-data, rootcheck, SCA, AR model), and ship a light Go master server rather than an OpenSearch-class indexer.
- **Option C, hybrid integration:** the company's agent optionally forwards alerts (syslog/JSON) to a customer's existing Wazuh manager, or reads Wazuh alerts.
  - This keeps the processes separate and avoids bundling Wazuh in the company installer, which Wazuh's own LICENSE text treats as derivative.
  - Do not ship Wazuh rules or decoders in the product.
- **OSSEC:** alive but niche (Atomicorp-maintained). Same GPLv2 lineage, so the same embedding constraints apply.

### Gaps
- Wazuh cloud modules (AWS/Azure/GCP/GitHub/Office 365) and MITRE ATT&CK mapping pages were not re-fetched this session. They were not visible in the capabilities index captured.
- The license of the new 5.0 engine ruleset content (AGPL vs GPLv2) was not confirmed.
- Agent package names and repo paths (packages.wazuh.com, `wazuh-agent`) were not re-verified.
- No official Wazuh 5.0 GA date was found; as of 2026-11-09 only RC2 exists.

---

## 5. Kernel compatibility: BTF/CO-RE by distro, minimum kernels for Falco/Tetragon, and OpenVZ/LXC fallback

### Takeaway
- **BTF availability:** every target distro release from Debian 11, Ubuntu 20.10/22.04+, RHEL/Alma/Rocky 8.2+, Fedora 32+ and AL2023 ships BTF-enabled kernels, so a single CO-RE eBPF object can run there. The exceptions:
  - Ubuntu 20.04 GA/HWE (5.4/5.8) has no BTF and needs BTFHub-style external BTF.
  - Very old RHEL 8.0/8.1 has no BTF.
  - Container-based VPS (OpenVZ/Virtuozzo, LXC/LXD) generally cannot use eBPF, audit or the proc connector at all.
- **Fallback ladder:** eBPF CO-RE → audit netlink → proc connector + fanotify/inotify → /proc polling plus log and integrity scanning.

### Cited Findings
- **BTF and kernels per distro.** BTF here means "kernel compiled with DEBUG_INFO_BTF (/sys/kernel/btf/vmlinux avail)".
  - From [BTFHub supported distros](https://github.com/aquasecurity/btfhub/blob/main/docs/supported-distros.md):
    - Debian 10 (4.19) has no BTF; Debian 11 (5.10.0) has BTF.
    - Ubuntu Focal 20.04 (5.4.0) and Focal HWE (5.8.0) have no BTF. Groovy 20.10 (5.8.0) and later have BTF. "Bionic HWE, Focal and Focal HWE kernels need this HUB."
    - CentOS/RHEL 8.0–8.1 (4.18.0-80/-147) have no BTF. 8.2 (4.18.0-193) and later have BPF and BTF, and "ALL latest CentOS 8 releases have BPF & BTF support enabled". All AlmaLinux releases have BPF and BTF.
    - Fedora 32+ has BTF. CentOS 7 (3.10) has no BTF and very limited eBPF.
  - Debian 13 "trixie" ships the 6.12 kernel series. — [Debian 13 release notes](https://www.debian.org/releases/trixie/release-notes/whats-new.en.html)
  - A Debian 13 host running `6.12.105+deb13-amd64` had BTF; on that kernel `CONFIG_BPF_KPROBE_OVERRIDE` was not set. — [EBPF-Runtime-Detection-Benchmark](https://github.com/sammonsempes/EBPF-Runtime-Detection-Benchmark)
  - Ubuntu 26.04 LTS (released 2026-04-23) ships **Linux 7.0**. — [Canonical announcement](https://canonical.com/blog/2026/04/23/canonical-releases-ubuntu-26-04-lts-resolute-raccoon); [Ubuntu Discourse](https://discourse.ubuntu.com/t/26-04-lts-resolute-raccoon-shipping-with-the-final-7-0-linux-kernel/80838)
  - RHEL kernels: 9.7 `5.14.0-611.5.1.el9_7`, 9.8 `5.14.0-687.5.1.el9_8`; RHEL 10.0 `6.12.0-55.9.1.el10_0`, 10.1 `6.12.0-124.8.1.el10_1`, 10.2 `6.12.0-211.7.1.el10_2`. — [Red Hat: RHEL release dates](https://access.redhat.com/articles/3078)
  - Amazon Linux 2023 "brings the 6.1 kernel", and AWS documentation tables list AL2023 6.1, **6.12** and **6.18** kernels for x86_64 and aarch64. — [AWS: AL2023 vs AL2 kernel](https://docs.aws.amazon.com/linux/al2023/ug/compare-with-al2-kernel.html)
- **Tool minimums:**
  - Falco modern_ebpf needs ring buffer and BTF, "usually ... >=5.8" with possible backports. The Falco kmod needs >= 3.10. — [Falco kernel docs](https://falco.org/docs/concepts/event-sources/kernel/)
  - The RHEL 8.10 4.18 kernel backports the ring buffer and BTF. — [Wazuh FIM advanced settings](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/advanced-settings.html)
  - Tetragon needs ≥ 4.19 plus BTF. — [Tetragon FAQ](https://tetragon.io/docs/installation/faq/)
  - Tracee needs BTF plus kallsyms on LTS kernels or the CentOS 8 4.18 kernel. — [Tracee prerequisites](https://aquasecurity.github.io/tracee/latest/docs/install/prerequisites/)
  - osquery BPF tables need ≥ 4.18. — [osquery process auditing](https://osquery.readthedocs.io/en/stable/deployment/process-auditing/)
  - cilium/ebpf: ">= 4.4 should work but EOL'ed versions are not supported", with CI on kernel.org LTS. — [cilium/ebpf README](https://github.com/cilium/ebpf)
  - BTFHub exists to supply external BTF for kernels released without it, and Tracee uses it to generate small tailored BTFs. — [BTFHub README](https://github.com/aquasecurity/btfhub)
- **Container VPS limits:**
  - Audit control is refused outside the initial user namespace (`-ECONNREFUSED`). — [kernel/audit.c](https://github.com/torvalds/linux/blob/master/kernel/audit.c)
  - cn_proc ignores subscribers outside the initial user and pid namespaces, and the connector lives in `init_net`. — [cn_proc.c](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/connector/cn_proc.c); [connector.c](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/drivers/connector/connector.c)
  - LXD: "LXD's eBPF support is currently restricted to programs managing devices cgroup entries" (bpf syscall interception). — [LXD syscall interception docs](https://documentation.ubuntu.com/lxd/en/latest/syscall-interception/)
  - OpenVZ kernels are branches "based on different kernels", e.g., the RHEL6 2.6.32-based kernel, "EOL: Nov 2019". This wiki page is outdated. — [OpenVZ wiki: Download/kernel](https://wiki.openvz.org/Download/kernel)
  - A 2014 user report shows auditd inside OpenVZ failing with "The audit system is disabled". This is old, forum-quality evidence. — [linux.org.ru forum thread](https://www.linux.org.ru/forum/security/10823803)

### Inferences
- **Practical matrix for the target distros** (BTF data from the cited sources; Ubuntu 22.04 = 5.15 and 24.04 = 6.8 GA kernels are well known but not re-fetched here):

| Distro | Default kernel | BTF (CO-RE) | Notes |
|---|---|---|---|
| Debian 11 | 5.10 | yes | ring buffer OK (≥5.8) |
| Debian 12 | 6.1 (not re-verified) | yes (inferred) | — |
| Debian 13 | 6.12 | yes | KPROBE_OVERRIDE absent → no Tetragon-style override |
| Ubuntu 20.04 | 5.4 GA / 5.8 HWE | **no** | needs external BTF or audit fallback. Later HWE (5.15) likely has BTF, unverified |
| Ubuntu 22.04 / 24.04 / 26.04 | 5.15 / 6.8 / 7.0 | yes | — |
| RHEL/Alma/Rocky 8 | 4.18 (8.2+) | yes | ring buffer backported by 8.10. Older 8.x lacks ring buffer → needs perf-buffer path |
| RHEL/Alma/Rocky 9 | 5.14 | yes | — |
| RHEL/Alma/Rocky 10 | 6.12 | yes | — |
| Fedora (current) | 6.x | yes | — |
| Amazon Linux 2023 | 6.1 (6.12/6.18 options) | yes (inferred from tool support) | — |

- **Sensor design: two eBPF paths.**
  - Ship CO-RE eBPF programs that use the ring buffer when available and fall back to the perf buffer (as osquery does) for 4.18-era RHEL 8 kernels without ring-buffer backports.
  - Embed a small, BTFHub-style BTF set only if Ubuntu 20.04 customers matter (20.04 is past standard support, so this is likely low priority).
- **Fallback ladder** (decided at agent start by probing `/sys/kernel/btf/vmlinux`, `bpf()` availability, audit netlink and namespace identity):
  1. eBPF CO-RE: full telemetry plus in-kernel filtering, optional bpf_send_signal enforcement.
  2. Audit netlink via go-libaudit: exec/argv, file watches, module loads. Read-only/multicast if auditd is present.
  3. Proc connector plus fanotify: exec triggers, attributed file events, exec-permission blocking on ≥ 5.0. inotify if fanotify is unavailable.
  4. /proc polling plus log tailing (auth.log/secure/journald) plus periodic integrity sweeps (package verification and hashes against master-server intel, cron/systemd/authorized_keys/ld.so.preload diffing).
- **OpenVZ/LXC guests land on tier 4 only.** The product must state clearly that container-VPS coverage is "best effort": no kernel telemetry, and polling can miss short-lived processes.
- **Enforcement portability is uneven.**
  - The override_return path needs `CONFIG_BPF_KPROBE_OVERRIDE`, which Debian 13 lacks.
  - BPF-LSM needs `bpf` in the active LSM list.
  - SIGKILL from eBPF or userspace and fanotify exec-deny are the most portable blocking primitives.

### Gaps
- Not verified this session (search budget exhausted):
  - Debian 12 and Ubuntu 22.04/24.04 GA kernel versions.
  - AL2023 BTF and `CONFIG_BPF_LSM`/`CONFIG_BPF_KPROBE_OVERRIDE` settings.
  - Ubuntu and RHEL defaults for BPF-LSM.
- Current OpenVZ 7 / Virtuozzo Hybrid Server kernel base and eBPF/fanotify behavior was not verified; the OpenVZ wiki page found is outdated.
- Whether unprivileged LXC with nesting or privileged LXC exposes audit or bpf to guests depends on host configuration. No authoritative matrix was found.

---

## 6. Detection content ecosystems and their licenses (Falco rules, SigmaHQ/DRL 1.1, Wazuh ruleset, Elastic detection-rules/ELv2, Splunk security_content) and MITRE mapping

### Takeaway
Safe to adapt into a closed commercial product, with attribution: Falco rules and Splunk security_content (Apache-2.0), and SigmaHQ (DRL 1.1).

Not safe to ship without legal review:
- Elastic detection-rules (ELv2). The "hosted or managed service" limitation and notice requirements create risk for a SaaS-backed security product.
- The Wazuh ruleset (GPLv2, with rules and decoders explicitly covered).

### Cited Findings
- **Falco rules:** Apache-2.0, release falco-rules-5.2.0 (2026-09-07). Rules carry `maturity_*` and MITRE tags (e.g., T1059.004, T1620, T1098.004, T1053.003, T1496). — [falcosecurity/rules](https://github.com/falcosecurity/rules)
- **SigmaHQ:**
  - "The rules contained in the SigmaHQ repository ... are released under the Detection Rule License (DRL) 1.1". The Sigma specification is public domain. — [SigmaHQ LICENSE](https://github.com/SigmaHQ/sigma/blob/master/LICENSE)
  - Latest release r2026-07-01 (2026-07-09). — [releases](https://github.com/SigmaHQ/sigma/releases)
  - On 2026-11-09 the repo had 211 Linux rules: process_creation 123, auditd 6 top-level plus execve 28, path 9, syscall 9, service_stop 1, file_event 8, network_connection 5, builtin 15 plus subfolders (sshd, cron, syslog, etc.). — [SigmaHQ rules/linux](https://github.com/SigmaHQ/sigma/tree/master/rules/linux)
- **DRL 1.1 terms:** free to "use, copy, modify, merge, publish, distribute, sublicense, and/or sell".
  - **If you share the Rules** (including modified ones), you must retain author identification, a URI to the rule or rule set where practicable, and an indication that they are DRL-licensed with the license text or link.
  - **If you use the Rules on data, "messages based on matches with the Rules must retain ... identification of the authors(s) ('author' field)"**.
  - — [Detection Rule License 1.1](https://github.com/SigmaHQ/Detection-Rule-License)
- **Elastic detection-rules:**
  - Licensed under the Elastic License 2.0. All 380 Linux rule files on 2026-11-09 declare `license = "Elastic License v2"`. Rules target Elastic data (e.g., `index = ["logs-endpoint.events.process*"]`). Active "dev-v3.0.x" tags (2026-11-05/06). — [elastic/detection-rules](https://github.com/elastic/detection-rules); [LICENSE.txt](https://github.com/elastic/detection-rules/blob/main/LICENSE.txt)
  - ELv2 limitations: "You may not provide the software to third parties as a hosted or managed service, where the service provides users with access to any substantial set of the features or functionality of the software". No circumventing license keys. Keep notices. Mark modifications. Pass the terms to anyone who receives a copy. — [Elastic License 2.0](https://www.elastic.co/licensing/elastic-license)
- **Elastic eBPF sensor code:** in elastic/ebpf, the `GPL/` directory is dual GPLv2 / BSD-2-Clause, while `non-GPL/` (userspace) is ELv2. The repo states that eBPF code "must be GPL-licensed for the kernel to accept and load it". — [elastic/ebpf LICENSE.txt](https://github.com/elastic/ebpf)
- **Wazuh ruleset:** covered by Wazuh's GPLv2 LICENSE ("applies to ... decoders, rules and any other data file"). The standalone ruleset repo was archived in 2024. — [wazuh LICENSE](https://github.com/wazuh/wazuh/blob/v4.14.10/LICENSE); [wazuh-ruleset (archived)](https://github.com/wazuh/wazuh-ruleset)
- **Splunk security_content:** Apache-2.0; v6.10.0 (2026-11-04), weekly cadence. — [splunk/security_content](https://github.com/splunk/security_content)
- **Go Sigma evaluators:** `bradleyjkemp/sigma-go` (MIT) and `markuskont/go-sigma-rule-engine` (Apache-2.0). — [sigma-go](https://github.com/bradleyjkemp/sigma-go); [go-sigma-rule-engine](https://github.com/markuskont/go-sigma-rule-engine)

### Inferences
- **Falco rules (Apache-2.0):** translate into the company's rule DSL, keep the Apache NOTICE and attribution, and preserve MITRE tags. These are the best-structured host rules for exec/file/network behavior.
- **Sigma (DRL 1.1):** commercial use is allowed. Every alert produced by a Sigma-derived rule (Discord message, TUI, dashboard) must carry the rule's `author` field. Rule packages distributed from the master server must keep the author, the rule URI and the DRL notice. Build this into the alert schema.
- **Elastic (ELv2):** use only as reading material or inspiration for behaviors. Do not copy rule text into a product backed by a company-hosted master server, which plausibly falls under the "managed service" restriction. The rules are also tied to Elastic Defend's schema (`logs-endpoint.events.*`), so verbatim reuse has little value anyway. Get legal review.
- **Wazuh rules/decoders (GPLv2):** do not ship them. Wazuh's derivative-work clause makes even data-file reuse risky.
- **Splunk (Apache-2.0):** reusable for detection ideas and ATT&CK mapping, but SPL logic must be re-expressed.
- **Own eBPF programs:** follow the Falco, Tetragon and Elastic pattern. License the kernel-side eBPF C under GPL-2.0 OR BSD-2/MIT dual terms and keep the userspace agent proprietary.

### Gaps
- No legal opinion or case law on ELv2's "managed service" clause as it applies to detection-rule reuse was found.
- Sigma rule-level MITRE tags and Elastic `threat` mappings were not tallied.

---

## 7. Incident-specific detections: how each tool or rule set detects the observed behaviors

### Takeaway
Every behavior in the incident (SSH compromise, miner with watchdog, cron/systemd persistence, replaced binaries) has public detection logic in at least one permissively usable rule set, mostly Falco (Apache-2.0) and Sigma (DRL). Only some of it is "stable":
- Falco's web-shell, reverse-shell and miner rules are in **sandbox** maturity.
- Several Sigma rules are "test" or "experimental".
- "Deleted binary still running" and "chattr +i" have weak public coverage. They are easy to implement natively via `/proc/<pid>/exe` and exec-argument checks.

### Cited Findings
Rule names below were extracted on 2026-11-09 from:
- [Falco stable](https://github.com/falcosecurity/rules/blob/main/rules/falco_rules.yaml), [incubating](https://github.com/falcosecurity/rules/blob/main/rules/falco-incubating_rules.yaml) and [sandbox](https://github.com/falcosecurity/rules/blob/main/rules/falco-sandbox_rules.yaml)
- [SigmaHQ rules/linux](https://github.com/SigmaHQ/sigma/tree/master/rules/linux)
- [Elastic rules/linux](https://github.com/elastic/detection-rules/tree/main/rules/linux) (ELv2, reference only)
- [Tetragon examples](https://github.com/cilium/tetragon/tree/main/examples/tracingpolicy)
- [osquery specs](https://github.com/osquery/osquery/tree/master/specs)

| Incident behavior | Falco rule (maturity) | Sigma rule (title, status, logsource) | Elastic rule (ELv2) | Other tools |
|---|---|---|---|---|
| Web process (php-fpm/nginx/apache/node) spawns a shell | "Web Server Spawned Shell", "Web Server Spawned Suspicious Child Process" (sandbox, T1505.003/T1059) | "Linux Webshell Indicators" (test, process_creation); "Webshell Remote Command Execution" (test, auditd) | — | auditd execve filtered by web-user euid; Tetragon `process_exec` parent fields |
| `curl`/`wget` piped to `sh` | no named rule found | "Suspicious Download and Execute Pattern via Curl/Wget" (experimental, process_creation) | "File Downloaded by Curl/Wget and Piped to Interpreter" | needs pipe/sibling correlation |
| Execution from /tmp, /dev/shm, hidden dirs | "Execution from /dev/shm" (stable, T1059.004); "Create Hidden Files or Directories" (sandbox) | "Process Execution From Shared Memory Directory" (experimental); "Potentially Suspicious Execution From Tmp Folder" (test); `lnx_auditd_hidden_binary_execution` | `defense_evasion_hidden_file_dir_tmp` and others | osquery `processes.path` |
| memfd / fileless exec | "Fileless execution via memfd_create" (stable, T1620) | — | "Potential Fileless Execution via Unusual memfd Create Call" | — |
| Reverse shell | "Reverse Shell from Web Server" (sandbox); "Netcat/Socat Remote Code Execution on Host" (sandbox); "Redirect STDOUT/STDIN to Network Connection in Container" (stable, container-only) | netcat/perl/php/python/ruby/xterm reverse-shell rules (process_creation) | — | Tetragon `tcp-connect` policy |
| Deleted binary still running | none found | none found containing "(deleted)" | only one rule references "(deleted)" (dynamic-linker creation) | osquery `processes.on_disk` column |
| Cron persistence | "Schedule Cron Jobs" (incubating, T1053.003) | "New Cron File Created" (experimental, file_event); `proc_creation_lnx_schedule_task_job_cron`; builtin cron rule | "Cron Job Created or Modified" | osquery `crontab`; auditd `-w /etc/cron*` |
| systemd unit persistence | "Write below etc" (sandbox, generic) | "Systemd Service Creation" (test, auditd) | "Systemd Service Created"; timer, generator and override.conf rules | osquery `systemd_units` |
| authorized_keys added | "Adding ssh keys to authorized_keys" (incubating, T1098.004) | — | `persistence_ssh_key_generation`; `defense_evasion_authorized_keys_file_deletion` | osquery `authorized_keys`; Wazuh FIM who-data |
| /etc/ld.so.preload | "Write below etc" (sandbox, generic) | "Modification of ld.so.preload" (test, auditd); `lnx_ldso_preload_injection` | "Dynamic Linker (ld.so) Creation"; LD_PRELOAD rules | — |
| Kernel module load | "Linux Kernel Module Injection Detected" (stable) | "Loading of Kernel Module via Insmod" (test, auditd) | "Kernel Module Load via Built-in Utility"; tainted / out-of-tree module rules | Tetragon `monitor-kernel-modules.yaml`, `monitor-signed-kernel-modules.yaml`; osquery `kernel_modules` |
| `chattr +i` on persistence files | none found | "Remove Immutable File Attribute" (test; process_creation and auditd) — covers `-i` | "File made Immutable by Chattr" | — |
| Masquerading as kworker/systemd/crond | — | "Masquerading as Linux Crond Process" (test, auditd) | "Executable Masquerading as Kernel Process"; "Suspicious File Creation via Kworker"; kworker netcon / UID-elevation rules | — |
| Cryptominer and pool traffic | "Detect outbound connections to common miner pool ports", "Detect crypto miners using the Stratum protocol", "Known Cryptominer Process Executed" (all sandbox, T1496) | "Linux Crypto Mining Pool Connections" (**stable**, network_connection); "Linux Crypto Mining Indicators" (test); "Possible Coin Miner CPU Priority Param" (test, auditd) | — | — |
| Replaced or modified system binaries | "Write below binary dir", "Modify binary dirs", "Mkdir binary dirs" (sandbox) | — | `execution_system_binary_file_permission_change` | Wazuh "Rootkits behavior detection" (rootcheck) |
| SSH-related | "Disallowed SSH Connection Non Standard Port" (stable) | builtin sshd rule (1) | — | Falco "Backdoored library loaded into SSHD (CVE-2024-3094)" (incubating); Tetragon `cve-2024-3094-xz-ssh.yaml` |
| Other relevant | "BPF Program Not Profiled" (incubating; flags rogue eBPF loads); "PTRACE attached to process" (stable); "Clear Log Activities" (stable); "Delete or rename shell history" (incubating) | — | — | Tetragon `bpf.yaml`, `sys_ptrace.yaml` |

### Inferences
Sensor primitives the company's agent needs, from which each detection above follows:
1. **exec event** with full argv, exe path, cwd, uid/euid/auid/loginuid, parent and grandparent chain, and stdin/stdout fd types (pipe/socket/tty).
   - Web-shell detection: parent ∈ {php-fpm, nginx, apache2/httpd, node, java} and child ∈ shells/LOLBins.
   - curl|sh: `sh`/`bash` with a pipe on stdin whose writer is curl/wget (pipe inode match via `/proc/<pid>/fd`).
   - Reverse shell: stdin/stdout bound to a TCP socket.
   - Execution from writable dirs: exe under `/tmp`, `/var/tmp`, `/dev/shm`, hidden path components, or `memfd:`.
2. **exe-integrity check** at exec time and in periodic sweeps:
   - `/proc/<pid>/exe` ending in ` (deleted)` or pointing to `/memfd:`.
   - A hash of the exe compared with the package manager's database (`dpkg --verify`/`rpm -Va` semantics) and the master-server hash/YARA intel. This catches replaced system binaries.
3. **file-write events** (eBPF LSM/fentry, or fanotify/audit watches) on a short path list with writer attribution:
   - `/etc/cron*`, `/var/spool/cron*`
   - `/etc/systemd/system`, `/usr/lib/systemd/system`, `~/.config/systemd/user`
   - `*/.ssh/authorized_keys`, `/etc/ld.so.preload`
   - `/etc/passwd`, `/etc/shadow`, `/etc/sudoers*`
   - `/usr/bin`, `/usr/sbin`, `/bin`, `/sbin`, `/lib*/`
4. **ioctl/attr changes:** FS_IOC_SETFLAGS (chattr), or exec of `chattr` with `+i`/`-i`.
5. **module load:** init_module/finit_module.
6. **network connect** with process attribution, for miner pool ports, Stratum, and reverse shells.
7. **masquerade heuristic:** a process whose comm looks like `kworker/*`, `kthreadd`, `[...]` or `systemd-*` but has a non-empty `/proc/<pid>/exe`, a non-kthreadd parent, or an exe outside the expected path.
8. **watchdog/respawn correlation:** the same miner hash re-executed by cron, systemd or a parent loop after a kill. Response should kill the whole process tree, remove the persistence artifact, and then hash-block via fanotify exec-deny or an eBPF kill-on-exec.

### Gaps
- Falco and Sigma rules were identified by name and title only. Their condition logic and false-positive behavior on typical LAMP/LEMP/Node VPS were not reviewed.
- No public rule specifically detecting a "miner watchdog" (respawn pattern) was found.

---

## 8. Go libraries for building the company's own sensor: cilium/ebpf, libbpfgo, go-libaudit, fsnotify, proc connector libraries, gopsutil (and others)

### Takeaway
A pure-Go, CGO-free, permissively-licensed stack is available:
- cilium/ebpf (MIT, with bpf2go)
- go-libaudit (Apache-2.0)
- vishvananda/netlink or mdlayher/netlink (Apache-2.0/MIT) for the proc connector
- fsnotify (BSD-3, inotify only)
- gopsutil (BSD) or go-sysinfo (Apache-2.0)
- sigma-go (MIT) for Sigma evaluation

Avoid libbpfgo (CGO plus libbpf), garlic (GPL-3.0, stale) and gobpf (stale, BCC-based).

### Cited Findings
- **cilium/ebpf ("ebpf-go"):**
  - MIT, "pure-Go library to read, modify and load eBPF programs". v0.22.0 (2026-06-29): "Linux 7.1 compat, BPF tokens and vmlinux BTF caching changes". v0.21.0 (2026-03-05). Pushed 2026-11-04, 8k stars.
  - Packages include `link`, `ringbuf`/`perf`, `btf`, `features` ("native Go" equivalent of `bpftool feature probe`) and `rlimit` (lifts RLIMIT_MEMLOCK before 5.11). `cmd/bpf2go` compiles and embeds eBPF C into Go.
  - Requirements: Linux amd64/arm64, ">= 4.4 should work".
  - — [cilium/ebpf](https://github.com/cilium/ebpf); [releases](https://github.com/cilium/ebpf/releases)
- **aquasecurity/libbpfgo:**
  - Apache-2.0. "uses CGO to interop with libbpf". libbpf is either a shared object or vendored and statically linked ("Tracee takes this approach").
  - Latest v0.10.0-libbpf-1.5.1 (2026-05-15); a dev tag for libbpf 1.8 exists (2026-07-29).
  - — [libbpfgo](https://github.com/aquasecurity/libbpfgo)
  - libbpf itself is "LGPL-2.1-only OR BSD-2-Clause", latest v1.8.0. — [libbpf LICENSE](https://github.com/libbpf/libbpf)
- **elastic/go-libaudit:** Apache-2.0, v2.6.2 (2025-03-18), last push 2026-08-11. — [go-libaudit](https://github.com/elastic/go-libaudit)
- **fsnotify:** BSD-3-Clause, v1.10.1 (2026-05-04). It wraps inotify on Linux and inherits inotify's lack of process attribution. — [fsnotify](https://github.com/fsnotify/fsnotify); [inotify(7)](https://man7.org/linux/man-pages/man7/inotify.7.html)
- **Proc connector:**
  - vishvananda/netlink (Apache-2.0, pushed 2026-11-08) defines `CN_IDX_PROC` and the `PROC_EVENT_*` types with typed event structs. — [proc_event_linux.go](https://github.com/vishvananda/netlink/blob/main/proc_event_linux.go)
  - mdlayher/netlink (MIT) gives low-level AF_NETLINK access. — [mdlayher/netlink](https://github.com/mdlayher/netlink)
  - fearful-symmetry/garlic, a dedicated proc-connector library, is **GPL-3.0 and last pushed 2021-06-28**. — [garlic](https://github.com/fearful-symmetry/garlic)
- **System info:**
  - shirou/gopsutil: BSD-style license, monthly releases (v4.26.10, 2026-11-01). — [gopsutil](https://github.com/shirou/gopsutil)
  - elastic/go-sysinfo: Apache-2.0, pushed 2026-07-19. — [go-sysinfo](https://github.com/elastic/go-sysinfo)
- **Others:**
  - DataDog/ebpf-manager: MIT, lifecycle manager on top of cilium/ebpf, pushed 2026-11-06. — [ebpf-manager](https://github.com/DataDog/ebpf-manager)
  - iovisor/gobpf: Apache-2.0, **last push 2023-08-31** (stale). — [gobpf](https://github.com/iovisor/gobpf)
  - elastic/quark: Apache-2.0 C library with Go bindings for process events. It has EBPF and kprobe backends, falls back automatically, and plans audit support. — [elastic/quark](https://github.com/elastic/quark)
- **Sigma in Go:** sigma-go (MIT) and go-sigma-rule-engine (Apache-2.0). — [sigma-go](https://github.com/bradleyjkemp/sigma-go); [go-sigma-rule-engine](https://github.com/markuskont/go-sigma-rule-engine)

### Inferences
- **Recommended stack:**
  - cilium/ebpf plus bpf2go for the CO-RE sensor. The company's own eBPF C is dual GPL-2.0/BSD-2 (or MIT), and the userspace agent is proprietary. It is a static single binary with no CGO, which simplifies multi-distro packaging (.deb/.rpm).
  - go-libaudit for the audit tier.
  - vishvananda/netlink for the proc connector.
  - `golang.org/x/sys/unix` fanotify syscalls for attributed file events and exec-permission blocking.
  - fsnotify only for config hot-reload or the container tier.
  - gopsutil or direct `/proc` parsing for the process table.
  - sigma-go or a company DSL for rules.
- **libbpfgo:** only if libbpf-specific features are needed. CGO complicates cross-builds, but libbpf's BSD-2 option keeps static linking license-safe.
- **quark:** worth evaluating as a reference design for process-tree caching and aggregation. It brings CGO, so it is not a drop-in for a pure-Go agent.

### Gaps
- Maturity metrics (API stability, open-issue counts) for sigma-go and go-sigma-rule-engine were not assessed.
- `golang.org/x/sys/unix` fanotify API coverage (e.g., FAN_REPORT_PIDFD constants) was not checked.

---

## 9. Recommendation: build vs embed vs run alongside for the sensor layer (synthesis)

### Takeaway
**Build** the core sensor in Go, using permissive libraries and company-owned dual-licensed eBPF programs, with a tiered fallback (eBPF → audit → proc connector + fanotify → /proc and log polling). **Embed** only permissive libraries and permissively licensed rule content (Falco Apache-2.0, Sigma DRL with author attribution, Splunk Apache-2.0). **Run alongside** optionally: Falco for richer detection where customers want it, Tetragon for strong in-kernel enforcement on modern kernels, and osquery for scheduled forensic SQL. **Do not fork or embed** Wazuh, OSSEC, Laurel, Snoopy, Elastic rules, or anything with GPL/AGPL/ELv2 terms in the closed binary.

### Cited Findings
Maintenance snapshot, 2026-11-09 (GitHub API and release feeds):

| Project | License | Latest release (date) | Last push | Flag |
|---|---|---|---|---|
| [Falco](https://github.com/falcosecurity/falco) | Apache-2.0 (driver MIT/GPL-2.0) | 0.45.2 (2026-10-29) | 2026-11-09 | active |
| [Falco Talon](https://github.com/falcosecurity/falco-talon) | Apache-2.0 | v0.3.0 (2025-02-05) | 2026-11-04 | slowing; K8s-only |
| [Tetragon](https://github.com/cilium/tetragon) | Apache-2.0 (+BPF GPL/BSD) | v1.8.0 (2026-10-30) | 2026-11-09 | active |
| [Tracee](https://github.com/aquasecurity/tracee) | Apache-2.0 | v0.24.1 (2025-11-19) | 2026-11-01 | release gap ~12 mo |
| [KubeArmor](https://github.com/kubearmor/KubeArmor) | Apache-2.0 (+BPF GPL-2.0) | v1.7.6 (2026-10-23) | 2026-11-08 | active |
| [sysdig OSS](https://github.com/draios/sysdig) | Apache-2.0 (driver separate) | 0.41.4 (2026-01-29) | 2026-04-13 | slowing |
| [bpftrace](https://github.com/bpftrace/bpftrace) | Apache-2.0 | v0.27.1 (2026-10-24) | 2026-11-09 | active |
| [audit-userspace](https://github.com/linux-audit/audit-userspace) | GPL-2.0 | 4.2.1 (2026-07-29) | 2026-11-09 | active |
| [go-libaudit](https://github.com/elastic/go-libaudit) | Apache-2.0 | v2.6.2 (2025-03-18) | 2026-08-11 | maintenance |
| [Laurel](https://github.com/threathunters-io/laurel) | GPL-3.0 | v0.8.2 (2026-07-17) | 2026-11-03 | active |
| [go-audit](https://github.com/slackhq/go-audit) | MIT | v1.2.2 (2026-06-22) | — | low cadence |
| [Snoopy](https://github.com/a2o/snoopy) | GPL-2.0 | 2.5.2 (2024-10-24) | — | slow |
| [osquery](https://github.com/osquery/osquery) | Apache-2.0 OR GPL-2.0 | 5.24.1 (2026-11-04) | — | active |
| [Fleet](https://github.com/fleetdm/fleet) | MIT + proprietary `ee/` | v4.94.1 (2026-11-06) | — | active |
| [Wazuh](https://github.com/wazuh/wazuh) | GPLv2 (+AGPL engine in 5.x) | 4.14.10 (2026-11-09); 5.0.0-rc2 (2026-10-30) | 2026-11-09 | major 5.0 transition |
| [OSSEC](https://github.com/ossec/ossec-hids) | GPL-2.0 | 4.4.1 (2026-10-18) | 2026-11-07 | Atomicorp-maintained |
| [SigmaHQ](https://github.com/SigmaHQ/sigma) | DRL 1.1 | r2026-07-01 (2026-07-09) | 2026-11-09 | active |
| [Elastic detection-rules](https://github.com/elastic/detection-rules) | ELv2 | dev-v3.0.31 (2026-11-06) | 2026-11-09 | active, restrictive |
| [Splunk security_content](https://github.com/splunk/security_content) | Apache-2.0 | v6.10.0 (2026-11-04) | 2026-11-05 | active |
| [cilium/ebpf](https://github.com/cilium/ebpf) | MIT | v0.22.0 (2026-06-29) | 2026-11-04 | active |
| [libbpfgo](https://github.com/aquasecurity/libbpfgo) | Apache-2.0 (CGO) | v0.10.0-libbpf-1.5.1 (2026-05-15) | 2026-10-14 | active |
| [fsnotify](https://github.com/fsnotify/fsnotify) | BSD-3 | v1.10.1 (2026-05-04) | 2026-05-11 | active |
| [gopsutil](https://github.com/shirou/gopsutil) | BSD | v4.26.10 (2026-11-01) | 2026-11-07 | active |
| [garlic](https://github.com/fearful-symmetry/garlic) | GPL-3.0 | — | 2021-06-28 | stale |
| [gobpf](https://github.com/iovisor/gobpf) | Apache-2.0 | — | 2023-08-31 | stale |
| [wazuh-ruleset](https://github.com/wazuh/wazuh-ruleset) | — | — | 2024-09-19 | **archived** |

- Supporting evidence for the recommendation:
  - Falco and Tracee cannot block, and Tetragon and KubeArmor can, based on measured prevention. — [EBPF-Runtime-Detection-Benchmark](https://github.com/sammonsempes/EBPF-Runtime-Detection-Benchmark)
  - Falco Talon is Kubernetes-only. — [Talon actionners](https://falco-talon.github.io/docs/actionners/list/)
  - Wazuh's LICENSE covers rules and treats proprietary installers as derivative. — [wazuh LICENSE](https://github.com/wazuh/wazuh/blob/main/LICENSE)
  - The Wazuh indexer needs 4–16 GB RAM. — [Wazuh indexer](https://documentation.wazuh.com/current/installation-guide/wazuh-indexer/index.html)
  - eBPF code in commercial agents is split out under GPL/BSD while userspace stays non-GPL. — [elastic/ebpf](https://github.com/elastic/ebpf); [falcosecurity/libs NOTICES](https://github.com/falcosecurity/libs/blob/master/NOTICES)

### Inferences
- **BUILD (core):** a Go `fusion-agent` systemd service with these modules:
  - (a) eBPF CO-RE sensor, the company's own minimal program set:
    - sched_process_exec/fork/exit
    - file open-for-write on a watched path set (LSM or fentry)
    - inet connect/accept
    - module load
    - memfd_create plus exec-from-memfd
    - credential changes
    - `bpf()` loads
    - It filters in-kernel to keep events per second low, and can enforce via `bpf_send_signal`, with override and BPF-LSM where the kernel allows.
  - (b) audit tier via go-libaudit.
  - (c) proc connector + fanotify tier, including FAN_OPEN_EXEC_PERM hash-deny.
  - (d) polling and integrity tier for OpenVZ/LXC: /proc, persistence-file diffs, package verification, master-server hashes and YARA.
  - (e) deterministic rule engine. Its own DSL, with importers for Falco (Apache) and Sigma (DRL-attributed) rules.
  - (f) policy-controlled response: kill the process tree, quarantine the binary, remove or disable cron and systemd entries, revert authorized_keys, `chattr -i`, block an IP via nftables, deny exec of a hash.
  - (g) outputs to the master server, with Discord fan-out on the server side.
- **EMBED:** permissive Go libraries only (Section 8). Rule content from Falco, Sigma and Splunk with notices and authors kept. Hashes, YARA rules and IOCs from the company's own intel.
- **RUN ALONGSIDE (optional integrations, separate processes):**
  - Falco via its JSON/HTTP output, or falcosidekick, which already has a Discord output.
  - Tetragon via JSON export or gRPC, for enforcement-heavy customers on modern kernels.
  - osquery under the Apache-2.0 option, as the AI investigator's read-only SQL surface.
  - Coexist with customer-run auditd or Wazuh by reading rather than owning their resources.
- **LEARN FROM:**
  - Wazuh: FIM who-data with eBPF and audit fallback and a health check, rootcheck, SCA, the stateful active-response model.
  - Falco: rule maturity levels, event-drop metrics.
  - Tetragon: in-kernel filtering, Sigkill+Override semantics.
  - Kunai: small footprint, but its async kill is weak prevention and unscoped kill rules killed dockerd, a warning for the response-policy design.
  - BTFHub: external BTF for old kernels.
- **Risk notes:**
  - Permission-event blocking (fanotify) and eBPF kill rules need fail-open timeouts, scoping and a "monitor-only" default.
  - Benchmark the agent against the GitHub benchmark's scenarios to set a credible footprint claim.

### Gaps
- No commercial-licensing alternatives were evaluated, such as paid Falco/Sysdig or Isovalent Tetragon Enterprise licensing for OEM embedding.
- No legal review of GPL/BSD dual-licensed eBPF bytecode distribution obligations was performed. The common industry pattern is documented above, but it is not legal advice.
