# CVE inventory

The curated list of CVEs IAMROOT exploits, with patch status and
module status. Updated as new modules land or as upstream patches
ship.

Status legend:

- 🟢 **WORKING** — module verified to land root on a vulnerable host
- 🟡 **PRIMITIVE** — fires the kernel primitive (trigger + slab groom
  + empirical witness) on a vulnerable host, but stops short of the
  full cred-overwrite / R/W chain. Returns `EXPLOIT_FAIL` honestly;
  useful as a vuln-verification probe and a continuation point for
  full chains. Per-kernel offsets deliberately not shipped.
- 🔵 **DETECT-ONLY** — module fingerprints presence/absence but no
  exploit. (No module is currently in this state — every registered
  module now fires either a full chain or a primitive.)
- ⚪ **PLANNED** — stub exists, work not started
- 🔴 **DEPRECATED** — fully patched everywhere relevant; kept for
  historical reference only

**Counts (v0.1.0):** 🟢 13 · 🟡 7 · 🔵 0 · ⚪ 1 · 🔴 0

## Inventory

| CVE | Name | Class | First patched | IAMROOT module | Status | Notes |
|---|---|---|---|---|---|---|
| CVE-2026-31431 | Copy Fail (algif_aead `authencesn` page-cache write) | LPE (page-cache write → /etc/passwd) | mainline 2026-04-22 | `copy_fail` | 🟢 | Verified on Ubuntu 26.04, Alma 9, Debian 13. Full AppArmor bypass. |
| CVE-2026-43284 (v4) | Dirty Frag — IPv4 xfrm-ESP page-cache write | LPE (same primitive shape as Copy Fail, different trigger) | mainline 2026-05-XX | `dirty_frag_esp` | 🟢 | Full PoC + active-probe scan |
| CVE-2026-43284 (v6) | Dirty Frag — IPv6 xfrm-ESP (`esp6`) | LPE | mainline 2026-05-XX | `dirty_frag_esp6` | 🟢 | V6 STORE shift auto-calibrated per kernel build |
| CVE-2026-43500 | Dirty Frag — RxRPC page-cache write | LPE | mainline 2026-05-XX | `dirty_frag_rxrpc` | 🟢 | |
| (variant, no CVE) | Copy Fail GCM variant — xfrm-ESP `rfc4106(gcm(aes))` page-cache write | LPE | n/a | `copy_fail_gcm` | 🟢 | Sibling primitive, same fix |
| CVE-2022-0847 | Dirty Pipe — pipe `PIPE_BUF_FLAG_CAN_MERGE` write | LPE (arbitrary file write into page cache) | mainline 5.17 (2022-02-23) | `dirty_pipe` | 🟢 | Full detect + exploit + cleanup. Detect: branch-backport ranges + **active sentinel probe** (`--active` fires the primitive against a /tmp probe file and verifies the page cache poisoning lands — catches silent distro backports the version check misses). Exploit: page-cache write into /etc/passwd UID field followed by `su` to drop a root shell. Auto-refuses on patched kernels. Cleanup: drop_caches + POSIX_FADV_DONTNEED. |
| CVE-2023-0458 | EntryBleed — KPTI prefetchnta KASLR bypass | INFO-LEAK (kbase) | mainline (partial mitigations only) | `entrybleed` | 🟢 | Stage-1 leak brick. Working on lts-6.12.86 (verified 2026-05-16 via `iamroot --exploit entrybleed --i-know`). Default `entry_SYSCALL_64` slot offset matches lts-6.12.x; override via `IAMROOT_ENTRYBLEED_OFFSET=0x...`. Other modules can call `entrybleed_leak_kbase_lib()` as a library. x86_64 only. |
| CVE-2026-31402 | NFS replay-cache heap overflow | LPE (NFS server) | mainline 2026-04-03 | — | ⚪ | Candidate. Different audience (NFS servers) — TBD whether in-scope. |
| CVE-2021-4034 | Pwnkit — pkexec argv[0]=NULL → env-injection | LPE (userspace setuid binary) | polkit 0.121 (2022-01-25) | `pwnkit` | 🟢 | Full detect + exploit (canonical Qualys-style: gconv-modules + execve NULL-argv). Detect handles both polkit version formats (legacy "0.105" + modern "126"). Exploit compiles payload via target's gcc → falls back gracefully if no cc available. Cleanup nukes /tmp/iamroot-pwnkit-* workdirs. **First userspace LPE in IAMROOT**. Ships auditd + sigma rules. |
| CVE-2024-1086 | nf_tables — `nft_verdict_init` cross-cache UAF | LPE (kernel arbitrary R/W via slab UAF) | mainline 6.8-rc1 (Jan 2024) | `nf_tables` | 🟡 | Hand-rolled nfnetlink batch builder (no libmnl dep) constructs the NFT_GOTO+NFT_DROP malformed verdict in a pipapo set, fires the double-free, sprays msg_msg in kmalloc-cg-96 and snapshots slabinfo. Stops before the Notselwyn pipapo R/W dance (per-kernel offsets refused). Branch-backport thresholds: 6.7.2 / 6.6.13 / 6.1.74 / 5.15.149 / 5.10.210 / 5.4.269. Also gates on unprivileged user_ns clone availability. |
| CVE-2021-3493 | Ubuntu overlayfs userns file-capability injection | LPE (host root via file caps in userns-mounted overlayfs) | Ubuntu USN-4915-1 (Apr 2021) | `overlayfs` | 🟢 | Full vsh-style exploit (userns+overlayfs mount + xattr file-cap injection + exec). **Ubuntu-specific** (vanilla upstream didn't enable userns-overlayfs-mount until 5.11). Detect parses /etc/os-release for ID=ubuntu, checks unprivileged_userns_clone sysctl, and with `--active` attempts the mount as a fork-isolated probe. Ships auditd rules covering mount(overlay) + setxattr(security.capability). |
| CVE-2022-2588 | net/sched cls_route4 handle-zero dead UAF | LPE (kernel UAF in cls_route4 filter remove) | mainline 5.20 / 5.19.7 (Aug 2022) | `cls_route4` | 🟡 | Userns+netns reach, tc/ip dummy interface + route4 dangling-filter add/del, msg_msg kmalloc-1k spray, UDP classify drive to follow the dangling pointer, slabinfo delta witness. Stops at empirical UAF-fired signal; no leak→cred overwrite (per-kernel offsets refused). Branch backports: 5.4.213 / 5.10.143 / 5.15.69 / 5.18.18 / 5.19.7. |
| CVE-2016-5195 | Dirty COW — COW race via /proc/self/mem + madvise | LPE (page-cache write into root-owned files) | mainline 4.9 (Oct 2016) | `dirty_cow` | 🟢 | Full detect + exploit + cleanup. **Old-systems coverage** — affects RHEL 6/7 (3.10 baseline), Ubuntu 14.04 (3.13), Ubuntu 16.04 (4.4), embedded boxes, IoT. Phil-Oester-style two-thread race: writer thread via `/proc/self/mem` vs madvise(MADV_DONTNEED) thread. Targets /etc/passwd UID flip + `su`. Ships auditd watch on /proc/self/mem + sigma rule for non-root mem-open. Pthread-linked. |
| CVE-2019-13272 | PTRACE_TRACEME → setuid execve → cred escalation | LPE (kernel ptrace race; no exotic preconditions) | mainline 5.1.17 (Jun 2019) | `ptrace_traceme` | 🟢 | Full detect + exploit. Branch backports: 4.4.182 / 4.9.182 / 4.14.131 / 4.19.58 / 5.0.20 / 5.1.17. jannh-style: fork → child `PTRACE_TRACEME` → child sleep+attach → parent `execve` setuid bin (pkexec/su/passwd auto-selected) → child wins stale-ptrace_link → POKETEXT x86_64 shellcode → root sh. x86_64-only; ARM/other return PRECOND_FAIL cleanly. |
| CVE-2022-0492 | cgroup v1 `release_agent` privilege check in wrong namespace | LPE (host root from rootless container or unprivileged userns) | mainline 5.17 (Mar 2022) | `cgroup_release_agent` | 🟢 | Universal structural exploit — no per-kernel offsets, no race. unshare(user|mount|cgroup), mount cgroup v1 RDP controller, write release_agent → ./payload, trigger via notify_on_release. Ships auditd rules covering cgroupfs mount + release_agent writes. Kept as a portable "containers misconfigured" demo. |
| CVE-2023-0386 | overlayfs `copy_up` preserves setuid bit across mount-ns boundary | LPE (host root via setuid carrier from unprivileged mount) | mainline 5.11 / 6.2-rc6 (Jan 2023) | `overlayfs_setuid` | 🟢 | Distro-agnostic — places a setuid binary in an overlay lower, mounts via fuse-overlayfs userns trick, executes from upper to inherit the setuid bit + root euid. Branch backports tracked for 5.10.169 / 5.15.92 / 6.1.11 / 6.2.x. |
| CVE-2021-22555 | iptables xt_compat heap-OOB → cross-cache UAF | LPE (kernel R/W via 4-byte heap OOB write + msg_msg/sk_buff groom) | mainline 5.12 / 5.11.10 (Apr 2021) | `netfilter_xtcompat` | 🟡 | Hand-rolled `ipt_replace` blob + setsockopt(IPT_SO_SET_REPLACE) fires the 4-byte OOB, msg_msg spray in kmalloc-2k + sk_buff sidecar, MSG_COPY scan for cross-cache landing + slabinfo delta. Stops before the leak → modprobe_path overwrite chain (per-kernel offsets refused). Branch backports: 5.11.10 / 5.10.27 / 5.4.110 / 4.19.185 / 4.14.230 / 4.9.266 / 4.4.266. **Bug existed since 2.6.19 (2006).** Andy Nguyen's PGZ disclosure. |
| CVE-2017-7308 | AF_PACKET TPACKET_V3 integer overflow → heap write-where | LPE (CAP_NET_RAW via userns) | mainline 4.11 / 4.10.6 (Mar 2017) | `af_packet` | 🟡 | Konovalov's TPACKET_V3 overflow + 200-skb spray + best-effort cred race. Offset table (Ubuntu 16.04/4.4 + 18.04/4.15) + `IAMROOT_AFPACKET_OFFSETS` env override for other kernels. x86_64-only; ARM returns PRECOND_FAIL. Branch backports: 4.10.6 / 4.9.18 / 4.4.57 / 3.18.49. |
| CVE-2022-0185 | legacy_parse_param fsconfig heap OOB → container-escape | LPE (cross-cache UAF → cred overwrite from rootless container) | mainline 5.16.2 (Jan 2022) | `fuse_legacy` | 🟡 | userns+mountns reach, fsopen("cgroup2") + double fsconfig SET_STRING fires the 4k OOB, msg_msg cross-cache groom in kmalloc-4k, MSG_COPY read-back detects whether the OOB landed in an adjacent neighbour. Stops before the m_ts overflow → MSG_COPY arbitrary read chain (scaffold present, no per-kernel offsets). **Container-escape angle** — relevant to rootless docker/podman/snap. Branch backports: 5.16.2 / 5.15.14 / 5.10.91 / 5.4.171. |
| CVE-2023-3269 | StackRot — maple-tree VMA-split UAF | LPE (kernel R/W via maple node use-after-RCU) | mainline 6.4-rc4 (Jul 2023) | `stackrot` | 🟡 | Two-thread race driver (MAP_GROWSDOWN + mremap rotation vs fork+fault) with cpu pinning + 3 s budget; kmalloc-192 spray for anon_vma/anon_vma_chain; race-iteration + signal breadcrumb. Honest reliability note in module header: **~<1% race-win/run on a vulnerable kernel** — the public PoC averages minutes-to-hours and needs a much wider VMA staging matrix to be reliable. Useful as a "is the maple-tree path reachable here?" probe. Branch backports: 6.4.4 / 6.3.13 / 6.1.37. |
| CVE-2020-14386 | AF_PACKET tpacket_rcv VLAN integer underflow | LPE (heap OOB write via crafted frame) | mainline 5.9 (Sep 2020) | `af_packet2` | 🟡 | Sibling of CVE-2017-7308; tp_reserve underflow + sendmmsg skb spray + slab-delta witness. PRIMITIVE-DEMO scope (no cred overwrite). Branch backports: 5.8.7 / 5.7.16 / 5.4.62 / 4.19.143 / 4.14.197 / 4.9.235. Or Cohen's disclosure. Shares `iamroot-af-packet` audit key with CVE-2017-7308. |
| CVE-TBD | Fragnesia (ESP shared-frag in-place encrypt) | LPE (page-cache write) | mainline TBD | `_stubs/fragnesia_TBD` | ⚪ | Stub. Per `findings/audit_leak_write_modprobe_backups_2026-05-16.md`, requires CAP_NET_ADMIN in userns netns — may or may not be in-scope depending on target environment. |

## Operations supported per module

Symbols: ✓ = supported, — = not applicable / no automated path.

| Module | --scan (detect) | --exploit | --mitigate | --cleanup | --detect-rules |
|---|---|---|---|---|---|
| copy_fail | ✓ | ✓ | ✓ (blacklist algif_aead + AA sysctl) | ✓ (revert mit or evict page cache) | ✓ (auditd + sigma) |
| copy_fail_gcm | ✓ | ✓ | ✓ (same family-wide) | ✓ | ✓ |
| dirty_frag_esp | ✓ | ✓ | ✓ (same family-wide) | ✓ | ✓ |
| dirty_frag_esp6 | ✓ | ✓ | ✓ (same family-wide) | ✓ | ✓ |
| dirty_frag_rxrpc | ✓ | ✓ | ✓ (same family-wide) | ✓ | ✓ |
| dirty_pipe | ✓ | ✓ | — (only fix is upgrade kernel) | ✓ (evict page cache) | ✓ (auditd + sigma) |
| entrybleed | ✓ | ✓ (leak kbase) | — (no canonical patch) | — | ✓ (sigma informational) |
| pwnkit | ✓ | ✓ | — (upgrade polkit) | ✓ (workdir nuke) | ✓ (auditd + sigma) |
| overlayfs | ✓ | ✓ | — (upgrade kernel) | — | ✓ (auditd) |
| dirty_cow | ✓ | ✓ | — (upgrade kernel) | ✓ (evict page cache) | ✓ (auditd + sigma) |
| ptrace_traceme | ✓ | ✓ | — (upgrade kernel) | — | ✓ (auditd) |
| cgroup_release_agent | ✓ | ✓ | — (mount cgroup ns) | — | ✓ (auditd) |
| overlayfs_setuid | ✓ | ✓ | — (upgrade kernel) | — | ✓ (auditd) |
| nf_tables | ✓ | ✓ (primitive) | — (upgrade kernel) | ✓ (queue drain) | ✓ (auditd) |
| cls_route4 | ✓ | ✓ (primitive) | — (upgrade kernel) | ✓ (teardown + log unlink) | ✓ (auditd) |
| netfilter_xtcompat | ✓ | ✓ (primitive) | — (upgrade kernel) | ✓ (log unlink) | ✓ (auditd) |
| af_packet | ✓ | ✓ (primitive) | — (upgrade kernel) | — | ✓ (auditd, shared key) |
| af_packet2 | ✓ | ✓ (primitive) | — (upgrade kernel) | — | ✓ (auditd, shared key) |
| fuse_legacy | ✓ | ✓ (primitive) | — (upgrade kernel) | ✓ (queue drain) | ✓ (auditd) |
| stackrot | ✓ | ✓ (race) | — (upgrade kernel) | ✓ (log unlink) | ✓ (auditd) |

## Pipeline for additions

1. Bug must be **patched in upstream mainline** (we don't bundle
   0-days)
2. Either **CVE-assigned** or has clear advisory/patch reference
3. Affects a kernel version range with realistic deployment footprint
   (we don't bundle exploits for kernels nobody runs)
4. PoC works on at least one distro+kernel in our CI matrix
5. Detection signature(s) shipped alongside the exploit

## Patch-status tracking

Each module's `kernel-range.json` (planned) declares the affected
range. CI verifies the exploit fails on the first-patched version
and succeeds below it. When a distro backports the fix into a kernel
version below the original first-patched, the matrix updates and
the relevant distro drops out of the "WORKING" list for that module.

## Why we exclude some things

- **0-days the maintainer found themselves**: those go through
  responsible disclosure first, then enter IAMROOT after upstream patch
- **kCTF VRP submissions in flight**: same as above; disclosure
  before bundling
- **Hardware-specific side channels** (Spectre/Meltdown variants):
  out of scope; not page-cache or process-isolation primitives
- **Container-escape only**: unless it cleanly chains to host-root,
  out of scope (separate tool space)
