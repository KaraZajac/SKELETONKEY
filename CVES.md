# CVE inventory

The curated list of CVEs SKELETONKEY exploits, with patch status and
module status. Updated as new modules land or as upstream patches
ship.

Status legend:

- 🟢 **WORKING** — module verified to land root on a vulnerable host
- 🟡 **PRIMITIVE** — fires the kernel primitive (trigger + slab groom
  + empirical witness) on a vulnerable host. By default returns
  `EXPLOIT_FAIL` honestly (no fabricated offsets). Pass `--full-chain`
  to additionally attempt root pop via the shared `modprobe_path`
  finisher (`core/finisher.{c,h}`) — requires kernel offsets via
  env vars / `/proc/kallsyms` / `/boot/System.map`; see
  [`docs/OFFSETS.md`](docs/OFFSETS.md). On success returns
  `EXPLOIT_OK` and drops a root shell; on failure returns
  `EXPLOIT_FAIL` — never claims root without an empirical
  setuid-bash sentinel.
- 🔵 **DETECT-ONLY** — module fingerprints presence/absence but no
  exploit. (No module is currently in this state.)
- ⚪ **PLANNED** — stub exists, work not started
- 🔴 **DEPRECATED** — fully patched everywhere relevant; kept for
  historical reference only

**Counts:** 39 modules total covering 34 CVEs; **28 of 34 CVEs
verified end-to-end in real VMs** via `tools/verify-vm/`. 🔵 0 · ⚪ 0
planned-with-stub · 🔴 0. (One ⚪ row below — CVE-2026-31402 — is a
*candidate* with no module, not counted as a module.)

> **Note on unverified rows:** `vmwgfx` / `dirty_cow` /
> `mutagen_astronomy` / `pintheft` / `vsock_uaf` / `fragnesia` are
> blocked by their target environment (VMware-only, kernel < 4.4,
> mainline panic, kmod not autoloaded, or t64-transition libs),
> not by missing code. See
> [`tools/verify-vm/targets.yaml`](tools/verify-vm/targets.yaml).
>
> All three now have **pinned fix commits and version-based
> `detect()`**:
> - `pack2theroot` reads PackageKit's `VersionMajor/Minor/Micro` over
>   D-Bus and compares against fix release **1.3.5** (commit `76cfb675`).
> - `dirtydecrypt` uses the `kernel_range` model against mainline fix
>   **`a2567217`** (Linux 7.0); kernels < 7.0 predate the vulnerable
>   rxgk code per Debian's tracker.
> - `fragnesia` uses `kernel_range` against mainline **7.0.9**; older
>   Debian-stable branches (5.10/6.1/6.12) are still listed vulnerable
>   on Debian's tracker — backport entries will extend the table as
>   distros publish them.
>
> `--auto` auto-enables active probes (forked per module so a probe
> crash cannot tear down the scan), which lets all three give an
> empirical confirmation on top of the version verdict. See each
> module's `MODULE.md`.

Every module ships a `NOTICE.md` crediting the original CVE
reporter and PoC author. `skeletonkey --dump-offsets` populates the
embedded offset table for new kernel builds — operators with
root on a host can upstream their kernel's offsets via PR.

## Inventory

| CVE | Name | Class | First patched | SKELETONKEY module | Status | Notes |
|---|---|---|---|---|---|---|
| CVE-2026-31431 | Copy Fail (algif_aead `authencesn` page-cache write) | LPE (page-cache write → /etc/passwd) | mainline 2026-04-22 | `copy_fail` | 🟢 | Verified on Ubuntu 26.04, Alma 9, Debian 13. Full AppArmor bypass. |
| CVE-2026-43284 (v4) | Dirty Frag — IPv4 xfrm-ESP page-cache write | LPE (same primitive shape as Copy Fail, different trigger) | mainline 2026-05-XX | `dirty_frag_esp` | 🟢 | Full PoC + active-probe scan |
| CVE-2026-43284 (v6) | Dirty Frag — IPv6 xfrm-ESP (`esp6`) | LPE | mainline 2026-05-XX | `dirty_frag_esp6` | 🟢 | V6 STORE shift auto-calibrated per kernel build |
| CVE-2026-43500 | Dirty Frag — RxRPC page-cache write | LPE | mainline 2026-05-XX | `dirty_frag_rxrpc` | 🟢 | |
| (variant, no CVE) | Copy Fail GCM variant — xfrm-ESP `rfc4106(gcm(aes))` page-cache write | LPE | n/a | `copy_fail_gcm` | 🟢 | Sibling primitive, same fix |
| CVE-2022-0847 | Dirty Pipe — pipe `PIPE_BUF_FLAG_CAN_MERGE` write | LPE (arbitrary file write into page cache) | mainline 5.17 (2022-02-23) | `dirty_pipe` | 🟢 | Full detect + exploit + cleanup. Detect: branch-backport ranges + **active sentinel probe** (`--active` fires the primitive against a /tmp probe file and verifies the page cache poisoning lands — catches silent distro backports the version check misses). Exploit: page-cache write into /etc/passwd UID field followed by `su` to drop a root shell. Auto-refuses on patched kernels. Cleanup: drop_caches + POSIX_FADV_DONTNEED. |
| CVE-2023-0458 | EntryBleed — KPTI prefetchnta KASLR bypass | INFO-LEAK (kbase) | mainline (partial mitigations only) | `entrybleed` | 🟢 | Stage-1 leak brick. Working on lts-6.12.86 (verified 2026-05-16 via `skeletonkey --exploit entrybleed --i-know`). Default `entry_SYSCALL_64` slot offset matches lts-6.12.x; override via `SKELETONKEY_ENTRYBLEED_OFFSET=0x...`. Other modules can call `entrybleed_leak_kbase_lib()` as a library. x86_64 only. |
| CVE-2026-31402 | NFS replay-cache heap overflow | LPE (NFS server) | mainline 2026-04-03 | — | ⚪ | Candidate. Different audience (NFS servers) — TBD whether in-scope. |
| CVE-2021-4034 | Pwnkit — pkexec argv[0]=NULL → env-injection | LPE (userspace setuid binary) | polkit 0.121 (2022-01-25) | `pwnkit` | 🟢 | Full detect + exploit (canonical Qualys-style: gconv-modules + execve NULL-argv). Detect handles both polkit version formats (legacy "0.105" + modern "126"). Exploit compiles payload via target's gcc → falls back gracefully if no cc available. Cleanup nukes /tmp/skeletonkey-pwnkit-* workdirs. **First userspace LPE in SKELETONKEY**. Ships auditd + sigma rules. |
| CVE-2024-1086 | nf_tables — `nft_verdict_init` cross-cache UAF | LPE (kernel arbitrary R/W via slab UAF) | mainline 6.8-rc1 (Jan 2024) | `nf_tables` | 🟡 | Hand-rolled nfnetlink batch builder (no libmnl dep) constructs the NFT_GOTO+NFT_DROP malformed verdict in a pipapo set, fires the double-free, sprays msg_msg in kmalloc-cg-96 and snapshots slabinfo. Stops before the Notselwyn pipapo R/W dance (per-kernel offsets refused). Branch-backport thresholds: 6.7.2 / 6.6.13 / 6.1.74 / 5.15.149 / 5.10.210 / 5.4.269. Also gates on unprivileged user_ns clone availability. |
| CVE-2021-3493 | Ubuntu overlayfs userns file-capability injection | LPE (host root via file caps in userns-mounted overlayfs) | Ubuntu USN-4915-1 (Apr 2021) | `overlayfs` | 🟢 | Full vsh-style exploit (userns+overlayfs mount + xattr file-cap injection + exec). **Ubuntu-specific** (vanilla upstream didn't enable userns-overlayfs-mount until 5.11). Detect parses /etc/os-release for ID=ubuntu, checks unprivileged_userns_clone sysctl, and with `--active` attempts the mount as a fork-isolated probe. Ships auditd rules covering mount(overlay) + setxattr(security.capability). |
| CVE-2022-2588 | net/sched cls_route4 handle-zero dead UAF | LPE (kernel UAF in cls_route4 filter remove) | mainline 5.20 / 5.19.7 (Aug 2022) | `cls_route4` | 🟡 | Userns+netns reach, tc/ip dummy interface + route4 dangling-filter add/del, msg_msg kmalloc-1k spray, UDP classify drive to follow the dangling pointer, slabinfo delta witness. Stops at empirical UAF-fired signal; no leak→cred overwrite (per-kernel offsets refused). Branch backports: 5.4.213 / 5.10.143 / 5.15.69 / 5.18.18 / 5.19.7. |
| CVE-2016-5195 | Dirty COW — COW race via /proc/self/mem + madvise | LPE (page-cache write into root-owned files) | mainline 4.9 (Oct 2016) | `dirty_cow` | 🟢 | Full detect + exploit + cleanup. **Old-systems coverage** — affects RHEL 6/7 (3.10 baseline), Ubuntu 14.04 (3.13), Ubuntu 16.04 (4.4), embedded boxes, IoT. Phil-Oester-style two-thread race: writer thread via `/proc/self/mem` vs madvise(MADV_DONTNEED) thread. Targets /etc/passwd UID flip + `su`. Ships auditd watch on /proc/self/mem + sigma rule for non-root mem-open. Pthread-linked. |
| CVE-2019-13272 | PTRACE_TRACEME → setuid execve → cred escalation | LPE (kernel ptrace race; no exotic preconditions) | mainline 5.1.17 (Jun 2019) | `ptrace_traceme` | 🟢 | Full detect + exploit. Branch backports: 4.4.182 / 4.9.182 / 4.14.131 / 4.19.58 / 5.0.20 / 5.1.17. jannh-style: fork → child `PTRACE_TRACEME` → child sleep+attach → parent `execve` setuid bin (pkexec/su/passwd auto-selected) → child wins stale-ptrace_link → POKETEXT x86_64 shellcode → root sh. x86_64-only; ARM/other return PRECOND_FAIL cleanly. |
| CVE-2022-0492 | cgroup v1 `release_agent` privilege check in wrong namespace | LPE (host root from rootless container or unprivileged userns) | mainline 5.17 (Mar 2022) | `cgroup_release_agent` | 🟢 | Universal structural exploit — no per-kernel offsets, no race. unshare(user|mount|cgroup), mount cgroup v1 RDP controller, write release_agent → ./payload, trigger via notify_on_release. Ships auditd rules covering cgroupfs mount + release_agent writes. Kept as a portable "containers misconfigured" demo. |
| CVE-2023-0386 | overlayfs `copy_up` preserves setuid bit across mount-ns boundary | LPE (host root via setuid carrier from unprivileged mount) | mainline 5.11 / 6.2-rc6 (Jan 2023) | `overlayfs_setuid` | 🟢 | Distro-agnostic — places a setuid binary in an overlay lower, mounts via fuse-overlayfs userns trick, executes from upper to inherit the setuid bit + root euid. Branch backports tracked for 5.10.169 / 5.15.92 / 6.1.11 / 6.2.x. |
| CVE-2021-22555 | iptables xt_compat heap-OOB → cross-cache UAF | LPE (kernel R/W via 4-byte heap OOB write + msg_msg/sk_buff groom) | mainline 5.12 / 5.11.10 (Apr 2021) | `netfilter_xtcompat` | 🟡 | Hand-rolled `ipt_replace` blob + setsockopt(IPT_SO_SET_REPLACE) fires the 4-byte OOB, msg_msg spray in kmalloc-2k + sk_buff sidecar, MSG_COPY scan for cross-cache landing + slabinfo delta. Stops before the leak → modprobe_path overwrite chain (per-kernel offsets refused). Branch backports: 5.11.10 / 5.10.27 / 5.4.110 / 4.19.185 / 4.14.230 / 4.9.266 / 4.4.266. **Bug existed since 2.6.19 (2006).** Andy Nguyen's PGZ disclosure. |
| CVE-2017-7308 | AF_PACKET TPACKET_V3 integer overflow → heap write-where | LPE (CAP_NET_RAW via userns) | mainline 4.11 / 4.10.6 (Mar 2017) | `af_packet` | 🟡 | Konovalov's TPACKET_V3 overflow + 200-skb spray + best-effort cred race. Offset table (Ubuntu 16.04/4.4 + 18.04/4.15) + `SKELETONKEY_AFPACKET_OFFSETS` env override for other kernels. x86_64-only; ARM returns PRECOND_FAIL. Branch backports: 4.10.6 / 4.9.18 / 4.4.57 / 3.18.49. |
| CVE-2022-0185 | legacy_parse_param fsconfig heap OOB → container-escape | LPE (cross-cache UAF → cred overwrite from rootless container) | mainline 5.16.2 (Jan 2022) | `fuse_legacy` | 🟡 | userns+mountns reach, fsopen("cgroup2") + double fsconfig SET_STRING fires the 4k OOB, msg_msg cross-cache groom in kmalloc-4k, MSG_COPY read-back detects whether the OOB landed in an adjacent neighbour. Stops before the m_ts overflow → MSG_COPY arbitrary read chain (scaffold present, no per-kernel offsets). **Container-escape angle** — relevant to rootless docker/podman/snap. Branch backports: 5.16.2 / 5.15.14 / 5.10.91 / 5.4.171. |
| CVE-2023-3269 | StackRot — maple-tree VMA-split UAF | LPE (kernel R/W via maple node use-after-RCU) | mainline 6.4-rc4 (Jul 2023) | `stackrot` | 🟡 | Two-thread race driver (MAP_GROWSDOWN + mremap rotation vs fork+fault) with cpu pinning + 3 s budget; kmalloc-192 spray for anon_vma/anon_vma_chain; race-iteration + signal breadcrumb. Honest reliability note in module header: **~<1% race-win/run on a vulnerable kernel** — the public PoC averages minutes-to-hours and needs a much wider VMA staging matrix to be reliable. Useful as a "is the maple-tree path reachable here?" probe. Branch backports: 6.4.4 / 6.3.13 / 6.1.37. |
| CVE-2020-14386 | AF_PACKET tpacket_rcv VLAN integer underflow | LPE (heap OOB write via crafted frame) | mainline 5.9 (Sep 2020) | `af_packet2` | 🟡 | Sibling of CVE-2017-7308; tp_reserve underflow + sendmmsg skb spray + slab-delta witness. PRIMITIVE-DEMO scope (no cred overwrite). Branch backports: 5.8.7 / 5.7.16 / 5.4.62 / 4.19.143 / 4.14.197 / 4.9.235. Or Cohen's disclosure. Shares `skeletonkey-af-packet` audit key with CVE-2017-7308. |
| CVE-2023-32233 | nf_tables anonymous-set UAF | LPE (kernel UAF in nft_set transaction) | mainline 6.4-rc4 (May 2023) | `nft_set_uaf` | 🟡 | Sondej+Krysiuk. Hand-rolled nfnetlink batch (NEWTABLE → NEWCHAIN → NEWSET(ANON\|EVAL) → NEWRULE(lookup) → DELSET → DELRULE) drives the deactivation skip; cg-512 msg_msg cross-cache spray. Branch backports: 4.19.283 / 5.4.243 / 5.10.180 / 5.15.111 / 6.1.28 / 6.2.15 / 6.3.2. --full-chain forges freed-set with `set->data = kaddr`. |
| CVE-2023-4622 | AF_UNIX garbage-collector race UAF | LPE (slab UAF, plain unprivileged) | mainline 6.6-rc1 (Aug 2023) | `af_unix_gc` | 🟡 | Lin Ma. Two-thread race driver: SCM_RIGHTS cycle vs unix_gc trigger; kmalloc-512 (SLAB_TYPESAFE_BY_RCU) refill via msg_msg. **Widest deployment of any module — bug exists since 2.x.** No userns required. Branch backports: 4.14.326 / 4.19.295 / 5.4.257 / 5.10.197 / 5.15.130 / 6.1.51 / 6.5.0. |
| CVE-2022-25636 | nft_fwd_dup_netdev_offload heap OOB | LPE (kernel R/W via offload action[] OOB) | mainline 5.17 / 5.16.11 (Feb 2022) | `nft_fwd_dup` | 🟡 | Aaron Adams (NCC). NFT_CHAIN_HW_OFFLOAD chain + 16 immediates + fwd writes past action.entries[1]. msg_msg kmalloc-512 spray. Branch backports: 5.4.181 / 5.10.102 / 5.15.25 / 5.16.11. |
| CVE-2023-0179 | nft_payload set-id memory corruption | LPE (regs->data[] OOB R/W) | mainline 6.2-rc4 / 6.1.6 (Jan 2023) | `nft_payload` | 🟡 | Davide Ornaghi. NFTA_SET_DESC variable-length element + NFTA_SET_ELEM_EXPRESSIONS payload-set whose verdict.code drives the OOB. Dual cg-96 + 1k spray. Branch backports: 4.14.302 / 4.19.269 / 5.4.229 / 5.10.163 / 5.15.88 / 6.1.6. |
| CVE-2021-3156 | sudo Baron Samedit — `sudoedit -s` heap overflow | LPE (userspace setuid sudo) | sudo 1.9.5p2 (Jan 2021) | `sudo_samedit` | 🟡 | Qualys Baron Samedit. Heap overflow via `sudoedit -s '\'` escaped-backslash parsing. Affects sudo 1.8.2 ≤ V ≤ 1.9.5p1. Heap-tuned exploit — may crash sudo on a mismatched layout. Ships auditd + sigma rules. |
| CVE-2021-33909 | Sequoia — `seq_file` size_t overflow → kernel stack OOB | LPE (kernel stack OOB write) | mainline 5.13.4 / 5.10.52 / 5.4.134 (Jul 2021) | `sequoia` | 🟡 | Qualys Sequoia. `size_t`-to-`int` conversion in `seq_file` drives an OOB write off the kernel stack via a deeply-nested directory mount. Primitive-only — fires the overflow + records a witness; no portable cred chain. Branch backports: 5.13.4 / 5.10.52 / 5.4.134. Ships auditd rule. |
| CVE-2023-22809 | sudoedit `EDITOR`/`VISUAL` `--` argv escape | LPE (userspace setuid sudoedit) | sudo 1.9.12p2 (Jan 2023) | `sudoedit_editor` | 🟢 | Structural argv-injection — an extra `--` in `EDITOR`/`VISUAL` makes setuid `sudoedit` open an attacker-chosen file as root. No kernel state, no offsets, no race. Affects sudo 1.8.0 ≤ V < 1.9.12p2. Ships auditd + sigma rules. |
| CVE-2023-2008 | vmwgfx DRM buffer-object size-validation OOB | LPE (kernel R/W via kmalloc-512 OOB) | mainline 6.3-rc6 (Apr 2023) | `vmwgfx` | 🟡 | vmwgfx DRM `bo` size-validation gap → OOB write in kmalloc-512. Affects 4.0 ≤ K < 6.3-rc6 on hosts with the `vmwgfx` module loaded (VMware guests). Primitive-only — fires the OOB + slab witness; no cred chain. Branch backports: 6.2.10 / 6.1.23. Ships auditd rule. |
| CVE-2026-31635 | DirtyDecrypt / DirtyCBC — rxgk missing-COW in-place decrypt | LPE (page-cache write into a setuid binary) | mainline Linux 7.0 (commit `a2567217ade970ecc458144b6be469bc015b23e5`) | `dirtydecrypt` | 🟡 | **Ported from the public V12 PoC, exploit body not yet VM-verified.** Sibling of Copy Fail / Dirty Frag in the rxgk (AFS rxrpc encryption) subsystem. `fire()` sliding-window page-cache write, ~256 fires/byte; rewrites the first 120 bytes of `/usr/bin/su` with a setuid-shell ELF. detect() is version-pinned: kernels < 7.0 predate the vulnerable rxgk code (Debian: `<not-affected, vulnerable code not present>` for 5.10/6.1/6.12); kernels ≥ 7.0 have the fix. `--active` probe fires the primitive at a `/tmp` sentinel for empirical override. x86_64. |
| CVE-2026-46300 | Fragnesia — XFRM ESP-in-TCP `skb_try_coalesce` SHARED_FRAG loss | LPE (page-cache write into a setuid binary) | mainline 7.0.9; older Debian-stable branches still unfixed as of 2026-05-22 | `fragnesia` | 🟡 | **Ported from the public V12 PoC, exploit body not yet VM-verified.** Latent bug exposed by the Dirty Frag fix (`f4c50a4034e6`). AF_ALG GCM keystream table + userns/netns + XFRM ESP-in-TCP splice trigger pair; rewrites the first 192 bytes of `/usr/bin/su`. Needs `CONFIG_INET_ESPINTCP` + unprivileged userns (the in-scope question the old `_stubs/fragnesia_TBD` raised — resolved: ships, reports PRECOND_FAIL when the userns gate is closed). detect() is version-pinned at 7.0.9; older branches that haven't backported yet are flagged VULNERABLE on the version check (override empirically via `--active`). PoC's ANSI TUI dropped in the port. x86_64. |
| CVE-2026-41651 | Pack2TheRoot — PackageKit `InstallFiles` TOCTOU | LPE (userspace D-Bus daemon → `.deb` postinst as root) | PackageKit 1.3.5 (commit `76cfb675`, 2026-04-22) | `pack2theroot` | 🟡 | **Ported from the public Vozec PoC, not yet VM-verified.** Two back-to-back `InstallFiles` D-Bus calls — first `SIMULATE` (polkit bypass + queues a GLib idle), then immediately `NONE` + malicious `.deb` (overwrites the cached flags before the idle fires). GLib priority ordering makes the overwrite deterministic, not a race. Disclosure by **Deutsche Telekom security**. Affects PackageKit 1.0.2 → 1.3.4 — default-enabled on Ubuntu Desktop, Debian, Fedora, Rocky/RHEL via Cockpit. `detect()` reads `VersionMajor/Minor/Micro` over D-Bus → high-confidence verdict (vs. precondition-only for dirtydecrypt/fragnesia). Debian-family only (PoC's built-in `.deb` builder). Needs `libglib2.0-dev` at build time; Makefile autodetects via `pkg-config gio-2.0` and falls through to a stub when absent. |

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
| nft_set_uaf | ✓ | ✓ (primitive) | — (upgrade kernel) | ✓ (queue drain) | ✓ (auditd + sigma) |
| af_unix_gc | ✓ | ✓ (race) | — (upgrade kernel) | ✓ (queue drain) | ✓ (auditd) |
| nft_fwd_dup | ✓ | ✓ (primitive) | — (upgrade kernel) | ✓ (queue drain) | ✓ (auditd) |
| nft_payload | ✓ | ✓ (primitive) | — (upgrade kernel) | ✓ (queue drain) | ✓ (auditd + sigma) |
| sudo_samedit | ✓ | ✓ (primitive) | — (upgrade sudo) | ✓ (crumb nuke) | ✓ (auditd + sigma) |
| sequoia | ✓ | ✓ (primitive) | — (upgrade kernel) | ✓ (nested-tree + mount teardown) | ✓ (auditd) |
| sudoedit_editor | ✓ | ✓ | — (upgrade sudo) | ✓ (revert written file) | ✓ (auditd + sigma) |
| vmwgfx | ✓ | ✓ (primitive) | — (upgrade kernel) | ✓ (log unlink) | ✓ (auditd) |
| dirtydecrypt | ✓ (+ `--active`) | ✓ (ported) | — (upgrade kernel) | ✓ (evict page cache) | ✓ (auditd + sigma) |
| fragnesia | ✓ (+ `--active`) | ✓ (ported) | — (upgrade kernel) | ✓ (evict page cache) | ✓ (auditd + sigma) |
| pack2theroot | ✓ (PK version via D-Bus) | ✓ (ported) | — (upgrade PackageKit ≥ 1.3.5) | ✓ (rm /tmp + `dpkg -r`) | ✓ (auditd + sigma) |

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
  responsible disclosure first, then enter SKELETONKEY after upstream patch
- **kCTF VRP submissions in flight**: same as above; disclosure
  before bundling
- **Hardware-specific side channels** (Spectre/Meltdown variants):
  out of scope; not page-cache or process-isolation primitives
- **Container-escape only**: unless it cleanly chains to host-root,
  out of scope (separate tool space)
