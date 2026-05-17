# CVE inventory

The curated list of CVEs IAMROOT exploits, with patch status and
module status. Updated as new modules land or as upstream patches
ship.

Status legend:

- 🟢 **WORKING** — module verified to land root on a vulnerable host
- 🟡 **PARTIAL** — module detects + exploits on some distros, not all
- 🔵 **DETECT-ONLY** — module fingerprints presence/absence but no
  exploit (yet). Useful for blue teams.
- ⚪ **PLANNED** — stub exists, work not started
- 🔴 **DEPRECATED** — fully patched everywhere relevant; kept for
  historical reference only

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
| CVE-2024-1086 | nf_tables — `nft_verdict_init` cross-cache UAF | LPE (kernel arbitrary R/W via slab UAF) | mainline 6.8-rc1 (Jan 2024) | `nf_tables` | 🔵 | Detect-only. Branch-backport ranges checked (6.7.2 / 6.6.13 / 6.1.74 / 5.15.149 / 5.10.210 / 5.4.269). Also checks unprivileged user_ns clone availability (the exploit's trigger gate) — reports PRECOND_FAIL if userns is locked down even when the kernel is vulnerable. Full Notselwyn-style exploit is the next nf_tables commit. |
| CVE-2021-3493 | Ubuntu overlayfs userns file-capability injection | LPE (host root via file caps in userns-mounted overlayfs) | Ubuntu USN-4915-1 (Apr 2021) | `overlayfs` | 🔵 | Detect-only. **Ubuntu-specific** (vanilla upstream didn't enable userns-overlayfs-mount until 5.11). Detect: parses /etc/os-release for ID=ubuntu, checks unprivileged_userns_clone sysctl, AND with `--active` actually attempts the userns+overlayfs mount as a fork-isolated probe. Reports OK on non-Ubuntu, PRECOND_FAIL if userns locked down. Ships auditd rules covering mount(overlay) + setxattr(security.capability). |
| CVE-2022-2588 | net/sched cls_route4 handle-zero dead UAF | LPE (kernel UAF in cls_route4 filter remove) | mainline 5.20 / 5.19.7 (Aug 2022) | `cls_route4` | 🔵 | Detect-only. Branch-backport thresholds: 5.4.213 / 5.10.143 / 5.15.69 / 5.18.18 / 5.19.7. Bug exists since 2.6.39 — very wide surface. Detect also probes user_ns+net_ns clone availability; locked-down hosts report PRECOND_FAIL. Full exploit (kylebot-style: tc filter add+rm + spray + cred overwrite) follows. |
| CVE-2016-5195 | Dirty COW — COW race via /proc/self/mem + madvise | LPE (page-cache write into root-owned files) | mainline 4.9 (Oct 2016) | `dirty_cow` | 🟢 | Full detect + exploit + cleanup. **Old-systems coverage** — affects RHEL 6/7 (3.10 baseline), Ubuntu 14.04 (3.13), Ubuntu 16.04 (4.4), embedded boxes, IoT. Phil-Oester-style two-thread race: writer thread via `/proc/self/mem` vs madvise(MADV_DONTNEED) thread. Targets /etc/passwd UID flip + `su`. Ships auditd watch on /proc/self/mem + sigma rule for non-root mem-open. Pthread-linked. |
| CVE-2019-13272 | PTRACE_TRACEME → setuid execve → cred escalation | LPE (kernel ptrace race; no exotic preconditions) | mainline 5.1.17 (Jun 2019) | `ptrace_traceme` | 🟢 | Full detect + exploit. Branch backports: 4.4.182 / 4.9.182 / 4.14.131 / 4.19.58 / 5.0.20 / 5.1.17. jannh-style: fork → child `PTRACE_TRACEME` → child sleep+attach → parent `execve` setuid bin (pkexec/su/passwd auto-selected) → child wins stale-ptrace_link → POKETEXT x86_64 shellcode → root sh. x86_64-only; ARM/other return PRECOND_FAIL cleanly. |
| CVE-2021-22555 | iptables xt_compat heap-OOB → cross-cache UAF | LPE (kernel R/W via 4-byte heap OOB write + msg_msg/sk_buff groom) | mainline 5.12 / 5.11.10 (Apr 2021) | `netfilter_xtcompat` | 🔵 | Detect-only. Branch backports: 5.11.10 / 5.10.27 / 5.4.110 / 4.19.185 / 4.14.230 / 4.9.266 / 4.4.266. **Bug existed since 2.6.19 (2006) — 15 years of latent vulnerability**. Andy Nguyen's PGZ disclosure. Needs CAP_NET_ADMIN via user_ns. Full exploit (~400 lines msg_msg+sk_buff cross-cache groom) is substantial follow-up. |
| CVE-2017-7308 | AF_PACKET TPACKET_V3 integer overflow → heap write-where | LPE (CAP_NET_RAW via userns) | mainline 4.11 / 4.10.6 (Mar 2017) | `af_packet` | 🔵 | Detect-only. Andrey Konovalov's research-era classic. Branch backports: 4.10.6 / 4.9.18 (RHEL 7-ish era) / 4.4.57 / 3.18.49. Needs user_ns for CAP_NET_RAW. Full exploit follows. |
| CVE-2022-0185 | legacy_parse_param fsconfig heap OOB → container-escape | LPE (cross-cache UAF → cred overwrite from rootless container) | mainline 5.16.2 (Jan 2022) | `fuse_legacy` | 🔵 | Detect-only. **Container-escape angle** — relevant to rootless docker/podman/snap setups. Branch backports: 5.16.2 / 5.15.14 / 5.10.91 / 5.4.171. Needs user_ns + mount_ns. William Liu / Crusaders-of-Rust PoC reference. |
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
