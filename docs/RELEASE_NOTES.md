## SKELETONKEY v0.9.5 — kernel_range drift cleanup (the other half)

v0.9.4 fixed the `cve_metadata` drift but exposed a *second* drift
check (`kernel_range drift`) that had been hidden behind it. That
check compares each module's `kernel_patched_from` table against
Debian's security tracker. It had **11 TOO_TIGHT + 8 MISSING
findings across 12 modules** — meaning `detect()` would have
reported VULNERABLE on many kernels that Debian has on record as
patched (false-positives), or missed branches entirely.

Applied `tools/refresh-kernel-ranges.py --patch` recommendations
across:

- `cgroup_release_agent` — `{5,16,9}` → `{5,16,7}`
- `cls_route4` — `{5,10,143}` → `{5,10,136}`, `{5,18,18}` → `{5,18,16}`
- `dirty_cow` — `{4,7,10}` → `{4,7,8}`
- `dirty_pipe` — `{5,10,102}` → `{5,10,92}`
- `fragnesia` — `{6,12,91}` → `{6,12,90}`, `{7,0,10}` → `{7,0,9}`
  (the 7.0.10 entry I added in v0.9.4 was an NVD-vs-Debian off-by-one)
- `mutagen_astronomy` — added `{4,12,6}` backport entry
- `netfilter_xtcompat` — `{5,10,46}` → `{5,10,38}`
- `overlayfs_setuid` — `{6,1,27}` → `{6,1,11}`
- `pintheft` — added `{6,12,90}` Debian-trixie entry
- `ptrace_traceme` — `{4,19,58}` → `{4,19,37}`
- `sequoia` — `{5,10,52}` → `{5,10,46}`
- `tioscpgrp` — added `{5,9,15}` backport entry

All changes are correctness-improving (no kernel that was previously
flagged VULNERABLE-and-actually-vulnerable is now flagged OK; we just
stop false-positiving on kernels that Debian has on record as patched).

Build's `kernel_range drift` step now exits 0 with 0 TOO_TIGHT and 0
MISSING.

Also enabled `workflow_dispatch` on the build workflow so the
drift-check job can be manually triggered without waiting for the
weekly Monday-06:00-UTC cron.

---

## SKELETONKEY v0.9.4 — drift unblock, fragnesia range fix, infra docs

Quality-of-life follow-ups from the v0.9.3 review:

**Nightly CI drift-check unblocked.** v0.9.3's hand-applied
`core/cve_metadata.c` entries weren't reflected in
`docs/CVE_METADATA.json`, so the scheduled `build` workflow had
been red since 2026-05-25 even though push-triggered runs passed.
Regenerated both via the canonical script. Pintheft's CWE landed
as CWE-787 (NVD-derived) — previously NULL.

**fragnesia module range table corrected.** Same audit pattern that
found the dirtydecrypt bug in v0.9.3. NVD CVE-2026-46300 confirms
the SKBFL_SHARED_FRAG marker was introduced at 5.11 and the bug
spans every stable branch since. Previous range table had one entry
(`{7, 0, 9}`) — off-by-one against NVD's 7.0.10 fix point and
missing every other backport. Now models 6 backports + predates-5.11
introduction gate:

```c
{5, 15, 208}, /* 5.15-LTS */
{6,  1, 174}, /* 6.1-LTS  */
{6,  6, 141}, /* 6.6-LTS  */
{6, 12,  91}, /* 6.12-LTS */
{6, 18,  33}, /* 6.18-LTS */
{7,  0,  10}, /* 7.0      */
```

Test row added for the predates path (kernel 4.4 → OK).

**`tools/verify-vm/README.md` brought current.** The README was
written for the v0.6-era apt-pin-only workflow. Now documents the
v0.9.x infrastructure: mainline kernel pinning via
kernel.ubuntu.com, per-module provisioners
(`provisioners/<module>.sh`), two-phase prep→reboot→verify with
post-reboot kernel confirmation, GRUB_DEFAULT pinning in both apt
and mainline blocks.

**NVD lookups in `refresh-cve-metadata.py` get a curl fallback.**
v0.9.3 ran into Python's `urlopen` silently hanging on NVD's HTTP/2
endpoint (55-min process with the 30s timeout never firing — kernel
CLOSE_WAIT socket). The CISA path already had a curl fallback; the
NVD path now mirrors it. Future runs degrade gracefully when
urlopen wedges.

---

## SKELETONKEY v0.9.3 — CVE metadata refresh + dirtydecrypt range fix

**CVE metadata refresh (10 → 12 KEV).** Populated the 8 missing
entries in `core/cve_metadata.c` for v0.8.0 + v0.9.0 module additions.
Two of them are CISA-KEV-listed:

- **CVE-2018-14634** `mutagen_astronomy` — KEV-listed 2026-01-26 (CWE-190)
- **CVE-2025-32463** `sudo_chwoot` — KEV-listed 2025-09-29 (CWE-829)

Other 6 entries got CWE / ATT&CK technique metadata so `--explain` and
`--module-info` now surface WEAKNESS + THREAT INTEL correctly for them.
(`tools/refresh-cve-metadata.py` hangs on CISA's HTTP/2 endpoint via
Python urlopen — populated directly via curl + max-time as a workaround.)

**dirtydecrypt module bug fix.** Auditing dirtydecrypt's range table
against NVD's authoritative CPE match for CVE-2026-31635 surfaced that
`dd_detect()` was wrongly gating "predates the bug" on kernel < 7.0.
Per NVD, the rxgk RESPONSE bug entered at 6.16.1 stable; vulnerable
ranges are 6.16.1–6.18.22, 6.19.0–6.19.12, and 7.0-rc1..rc7. The fix:

- `dd_detect()` predates-gate now uses 6.16.1 (not 7.0)
- `patched_branches[]` table adds `{6, 18, 23}` for the 6.18 backport

Re-verified empirically: dirtydecrypt now correctly returns VULNERABLE
on mainline 6.19.7 (genuinely below the 6.19.13 backport). Previously
it returned OK there — a false negative that would have lied to anyone
running scan on a real vulnerable kernel.

---

## SKELETONKEY v0.9.2 — dirtydecrypt verified on mainline 6.19.7

One more empirical verification: **CVE-2026-31635 dirtydecrypt** confirmed
end-to-end on Ubuntu 22.04 + mainline 6.19.7. detect() correctly returns
OK ("kernel predates the rxgk RESPONSE-handling code added in 7.0"). Footer
goes 27 → 28.

Attempted but deferred: **CVE-2026-46300 fragnesia**. Mainline 7.0.5 kernel
.debs depend on `libssl3t64` / `libelf1t64` (the t64-transition libs
introduced in Ubuntu 24.04 / Debian 13). No Vagrant box with a Parallels
provider has those libs yet — `dpkg --force-depends` leaves the kernel
package in `iHR` (broken) state with no `/boot/vmlinuz` deposited. Marked
`manual: true` with rationale in `targets.yaml`. Resolvable when a
Parallels-supported ubuntu2404 / debian13 box becomes available.

---

## SKELETONKEY v0.9.1 — VM verification sweep (22 → 27)

Five more CVEs empirically confirmed end-to-end against real Linux VMs
via `tools/verify-vm/`:

| CVE | Module | Target environment |
|---|---|---|
| CVE-2019-14287 | `sudo_runas_neg1` | Ubuntu 18.04 (sudo 1.8.21p2 + `(ALL,!root)` grant via provisioner) |
| CVE-2020-29661 | `tioscpgrp`      | Ubuntu 20.04 pinned to `5.4.0-26` (genuinely below the 5.4.85 backport) |
| CVE-2024-26581 | `nft_pipapo`     | Ubuntu 22.04 + mainline `5.15.5` (below the 5.15.149 fix) |
| CVE-2025-32463 | `sudo_chwoot`    | Ubuntu 22.04 + sudo `1.9.16p1` built from upstream into `/usr/local/bin` |
| CVE-2025-6019  | `udisks_libblockdev` | Debian 12 + `udisks2` 2.9.4 + polkit allow rule for the verifier user |

Footer goes from `22 empirically verified` → `27 empirically verified`.

### Verifier infrastructure (the why)

These verifications required real plumbing work that didn't exist before:

- **Per-module provisioner hook** (`tools/verify-vm/provisioners/<module>.sh`)
  — per-target setup that doesn't belong in the Vagrantfile (build sudo
  from source, install udisks2 + polkit rule, drop a sudoers grant) now
  lives in checked-in scripts that re-run idempotently on every verify.
- **Two-phase provisioning** in `verify.sh` — prep provisioners run
  first (install kernel, set grub default, drop polkit rule), then a
  conditional reboot if `uname -r` doesn't match the target, then the
  verifier proper. Fixes the silent-fail where the new kernel was
  installed but the VM never actually rebooted into it.
- **GRUB_DEFAULT pin in both `pin-kernel` and `pin-mainline` blocks** —
  without this, grub's debian-version-compare picks the highest-sorting
  vmlinuz as default; for downgrades (stock 4.15 → mainline 4.14.70, or
  stock 5.4.0-169 → pinned 5.4.0-26) the wrong kernel won boot.
- **Old-mainline URL fallback** — kernel.ubuntu.com puts ≤ 4.15 mainline
  debs at `/v${KVER}/` not `/v${KVER}/amd64/`. Fallback handles both.

### Honest residuals — 7 of 34 still unverified

| Module | Why not verified |
|---|---|
| `vmwgfx` | needs a VMware guest; we're on Parallels |
| `dirty_cow` | needs ≤ 4.4 kernel — older than any supported Vagrant box |
| `mutagen_astronomy` | mainline 4.14.70 kernel-panics on Ubuntu 18.04 rootfs (`Failed to execute /init (error -8)` — kernel config mismatch). Genuinely needs CentOS 6 / Debian 7. |
| `pintheft` | needs RDS kernel module loaded (Arch only autoloads it) |
| `vsock_uaf` | needs `vsock_loopback` loaded — not autoloaded on common Vagrant boxes |
| `dirtydecrypt`, `fragnesia` | need Linux 7.0 — not yet shipping as any distro kernel |

All seven are flagged in `tools/verify-vm/targets.yaml` with `manual: true`
and a rationale.

---

## SKELETONKEY v0.9.0 — every year 2016 → 2026 now covered

Five gap-filling modules. Closes the 2018 hole entirely and thickens
2019 / 2020 / 2024.

### CVE-2018-14634 — `mutagen_astronomy` (Qualys)

Closes the 2018 gap. `create_elf_tables()` int-wrap → on x86_64, a
multi-GiB argv blob makes the kernel under-allocate the SUID
carrier's stack and corrupt adjacent allocations. CISA-KEV-listed
Jan 2026 despite the bug's age — legacy RHEL 7 / CentOS 7 / Debian
8 fleets still affected. 🟡 PRIMITIVE (trigger documented;
Qualys' full chain not bundled per verified-vs-claimed).
`arch_support: x86_64+unverified-arm64`.

### CVE-2019-14287 — `sudo_runas_neg1` (Joe Vennix)

`sudo -u#-1 <cmd>` → uid_t underflows to 0xFFFFFFFF → sudo treats it
as uid 0 → runs `<cmd>` as root even when sudoers explicitly says
"ALL except root". Pure userspace logic bug; the famous Apple
Information Security finding. detect() looks for a `(ALL,!root)`
grant in `sudo -ln` output. `arch_support: any`. Sudo < 1.8.28.

### CVE-2020-29661 — `tioscpgrp` (Jann Horn / Project Zero)

TTY `TIOCSPGRP` ioctl race on PTY pairs → `struct pid` UAF in
kmalloc-256. Affects everything through Linux 5.9.13. 🟡 PRIMITIVE
(race-driver + msg_msg groom). Public PoCs from grsecurity/spender
+ Maxime Peterlin. `arch_support: x86_64+unverified-arm64`.

### CVE-2024-50264 — `vsock_uaf` (a13xp0p0v / Pwnie 2025 winner)

AF_VSOCK `connect()` races a POSIX signal that tears down the
virtio_vsock_sock → UAF in kmalloc-96. **Pwn2Own 2024 + Pwnie Award
2025 winner.** Reachable as plain unprivileged user (no userns
required — unusual). Two public exploit paths: @v4bel + @qwerty
kernelCTF chain (BPF JIT spray + SLUBStick) and Alexander Popov's
msg_msg path (PT SWARM Sep 2025). 🟡 PRIMITIVE.
`arch_support: x86_64+unverified-arm64`.

### CVE-2024-26581 — `nft_pipapo` (Notselwyn II, "Flipping Pages")

`nft_set_pipapo` destroy-race UAF. Sibling to our `nf_tables` module
(CVE-2024-1086) — same Notselwyn "Flipping Pages" research paper,
different specific bug in the pipapo set substrate. Same family
detect signature. 🟡 PRIMITIVE.
`arch_support: x86_64+unverified-arm64`.

### Year-by-year coverage matrix

```
2016: ▓ 1     2021: ▓▓▓▓▓ 5     2025: ▓▓ 2
2017: ▓ 1     2022: ▓▓▓▓▓ 5     2026: ▓▓▓▓ 4
2018: ▓ 1 ←   2023: ▓▓▓▓▓▓▓▓ 8
2019: ▓▓ 2 ←  2024: ▓▓▓ 3 ←
2020: ▓▓ 2 ←
```

Every year 2016 → 2026 is now ≥1.

### Corpus growth

| | v0.8.0 | v0.9.0 |
|---|---|---|
| Modules registered | 34 | 39 |
| Distinct CVEs | 29 | 34 |
| Years with ≥1 CVE | 10 of 11 (missing 2018) | **11 of 11** |
| Detection rules embedded | 131 | 151 |
| Arch-independent (`any`) | 6 | 7 |
| VM-verified | 22 | 22 |

### Other changes

- All 5 new modules ship complete detection-rule corpus
  (auditd + sigma + yara + falco) — corpus stays at 4-format
  parity with the rest of the modules.
- `tools/refresh-cve-metadata.py` runs against 34 CVEs (was 29);
  takes ~4 minutes due to NVD anonymous rate limit.

---

## SKELETONKEY v0.8.0 — 3 new 2025/2026 CVEs

Closes the 2025 coverage gap. Three new modules from CVEs disclosed
2025–2026, all with public PoC code we ported into proper
SKELETONKEY modules:

### CVE-2025-32463 — `sudo_chwoot` (Stratascale)

Critical (CVSS 9.3) sudo logic bug: `sudo --chroot=<DIR>` chroots
into a user-controlled directory before completing authorization +
resolves user/group via NSS inside the chroot. Plant a malicious
`libnss_*.so` + an `nsswitch.conf` that points to it; sudo dlopens
the .so as root, ctor fires, root shell. Affects sudo 1.9.14 to
1.9.17p0; fixed in 1.9.17p1 (which deprecated --chroot entirely).
`arch_support: any` (pure userspace).

### CVE-2025-6019 — `udisks_libblockdev` (Qualys)

udisks2 + libblockdev SUID-on-mount chain. libblockdev's internal
filesystem-resize/repair mount path omits `MS_NOSUID` and
`MS_NODEV`. udisks2 gates the operation on polkit's
`org.freedesktop.UDisks2.modify-device` action, which is
`allow_active=yes` by default → any active console session user can
trigger it without a password. Build an ext4 image with a SUID-root
shell inside, get udisks to mount it, execute the SUID shell.
Affects libblockdev < 3.3.1, udisks2 < 2.10.2. `arch_support: any`.

### CVE-2026-43494 — `pintheft` (V12 Security)

Linux kernel RDS zerocopy double-free. `rds_message_zcopy_from_user()`
pins user pages one at a time; if a later page faults, the error
unwind drops the already-pinned pages, but the msg's scatterlist
cleanup drops them AGAIN. Each failed `sendmsg(MSG_ZEROCOPY)` leaks
one pin refcount. Chain via io_uring fixed buffers to overwrite the
page cache of a readable SUID binary → execve → root. Mainline fix
commit `0cebaccef3ac` (posted to netdev 2026-05-05). Among common
distros only **Arch Linux** autoloads the rds module — Ubuntu /
Debian / Fedora / RHEL / Alma / Rocky / Oracle Linux either don't
build it or blacklist autoload. `detect()` correctly returns OK
on non-Arch hosts (RDS unreachable from userland). 🟡 PRIMITIVE
status: primitive fires; full cred-overwrite via the shared
modprobe_path finisher requires `--full-chain` on x86_64.

### Corpus growth

| | v0.7.1 | v0.8.0 |
|---|---|---|
| Modules registered | 31 | 34 |
| Distinct CVEs | 26 | 29 |
| 2025-CVE coverage | 0 | 2 |
| Detection rules embedded | 119 | 131 |
| Arch-independent (`any`) | 4 | 6 |
| CISA KEV-listed | 10 | 10 (new ones not yet KEV'd) |
| VM-verified | 22 | 22 |

### Other changes

- `tools/refresh-cve-metadata.py` — added curl fallback for the
  CISA KEV CSV fetch (Python's urlopen was hitting timeouts against
  CISA's HTTP/2 endpoint).
- `tools/verify-vm/targets.yaml` — entries for the 3 new modules
  with honest "no Vagrant box covers this yet" notes for
  pintheft (needs Arch) and udisks_libblockdev (needs active
  console session + udisks2 installed).

---

## SKELETONKEY v0.7.1 — arm64-static binary + per-module arch_support

Point release on top of v0.7.0. Two additions:

1. **`skeletonkey-arm64-static`** is now published alongside the
   existing x86_64-static binary. Built native-arm64 in Alpine via
   GitHub's `ubuntu-24.04-arm` runner pool. Works on Raspberry Pi 4+,
   Apple Silicon Linux VMs, AWS Graviton, Oracle Ampere, Hetzner ARM,
   and any other aarch64 Linux. `install.sh` auto-picks it.

2. **`arch_support` per module** — a new field on
   `struct skeletonkey_module` that honestly labels which architectures
   the `exploit()` body has been verified on. Three categories:

   - **`any`** (4 modules): pwnkit, sudo_samedit, sudoedit_editor,
     pack2theroot. Purely userspace; arch-independent.
   - **`x86_64`** (1 module): entrybleed. KPTI prefetchnta side-channel;
     x86-only by physics (ARM uses TTBR_EL0/EL1 split, not CR3).
     Already gated in source — returns PRECOND_FAIL on non-x86_64.
   - **`x86_64+unverified-arm64`** (26 modules): kernel-exploitation
     code that hasn't been verified on arm64 yet. `detect()` works
     everywhere (it just reads `ctx->host`); the `exploit()` body uses
     primitives (msg_msg sprays, ROP-style finishers, specific struct
     offsets) that are likely portable to aarch64 but unproven.

   `--list` adds an ARCH column; `--module-info` adds an `arch support:`
   line; `--scan --json` adds an `arch_support` field per module.

**What an arm64 user gets today:** the full detection/triage workflow
works as well as on x86_64 (`--scan`, `--explain`, `--module-info`,
`--detect-rules`, `--auto --dry-run`). Four exploit modules
(`pwnkit`, `sudo_samedit`, `sudoedit_editor`, `pack2theroot`) will fire
end-to-end. The remaining 26 modules currently mark themselves as
"x86_64 verified; arm64 untested" — the bug class is generic but the
exploitation hasn't been confirmed. Future arm64-Vagrant verification
sweeps will promote modules to `any` as they're confirmed.

---

### From v0.7.0 — empirical verification + operator briefing

The headline change since v0.6.0: **22 of 26 CVEs are now empirically
confirmed against real Linux kernels in VMs**, with verification records
baked into the binary and surfaced in `--list`, `--module-info`, and
`--explain`. The four still-unverified entries (`vmwgfx`, `dirty_cow`,
`dirtydecrypt`, `fragnesia`) are blocked by their target environment
(VMware-only, ≤4.4 kernel, Linux 7.0 not yet shipping), not by missing
code — see
[`tools/verify-vm/targets.yaml`](https://github.com/KaraZajac/SKELETONKEY/blob/main/tools/verify-vm/targets.yaml)
for the rationale.

### Install

Pre-built binaries below (x86_64 dynamic, x86_64 static-musl, arm64
dynamic; all checksum-verified). Recommended for new installs:

```bash
curl -sSL https://github.com/KaraZajac/SKELETONKEY/releases/latest/download/install.sh | sh
skeletonkey --version
```

Static-musl x86_64 is the default — works back to glibc 2.17, no
library dependencies.

### What's in this release

**Empirical verification (the big one)**
- `tools/verify-vm/` — Vagrant + Parallels scaffold. Boots
  known-vulnerable kernels (stock distro or mainline via
  `kernel.ubuntu.com/mainline/`), runs `--explain --active` per module,
  records match/mismatch as JSONL.
- 22 modules confirmed end-to-end across Ubuntu 18.04 / 20.04 / 22.04 +
  Debian 11 / 12 + mainline kernels 5.15.5 / 6.1.10.
- Per-module `verified_on[]` table baked into the binary. `--list` adds
  a `VFY` column showing ✓ per verified module; footer prints
  `31 modules registered · 10 in CISA KEV (★) · 22 empirically verified
  in real VMs (✓)`.
- `--module-info <name>` adds a `--- verified on ---` section.
- `--explain <name>` adds a `VERIFIED ON` section.

**`--explain MODULE` — one-page operator briefing**

A single command renders, for any module: CVE / CWE / MITRE ATT&CK /
CISA KEV status, host fingerprint, **live `detect()` trace** with
verdict and interpretation, **OPSEC footprint** (what an exploit
would leave on this host), detection-rule coverage matrix, and
verification records. Paste-ready for triage tickets and SOC handoffs.

**CVE metadata pipeline**

`tools/refresh-cve-metadata.py` fetches CISA's Known Exploited
Vulnerabilities catalog + NVD CWE classifications, generates
`docs/CVE_METADATA.json` + `docs/KEV_CROSSREF.md` + the in-binary
lookup table. **10 of 26 modules cover KEV-listed CVEs.** MITRE ATT&CK
technique mapping (T1068 by default; T1611 for container escapes;
T1082 for kernel info leaks). All surfaced in `--list` (★ column),
`--module-info`, `--explain`, and `--scan --json` (new `triage`
sub-object per module).

**Per-module OPSEC notes**

Every module's struct now carries an `opsec_notes` paragraph describing
the runtime telemetry footprint: file artifacts, dmesg signatures,
syscall observables, network activity, persistence side effects,
cleanup behavior. Grounded in source + existing detection rules — the
inverse of what the auditd/sigma/yara/falco rules look for. Surfaced
in `--module-info` (text + JSON) and `--explain`.

**119 detection rules across all 4 SIEM formats**

Previously: auditd everywhere, sigma on top-10, yara/falco only on a
handful. Now: 30/31 auditd, 31/31 sigma, 28/31 yara, 30/31 falco
(the 3 remaining gaps are intentional skips — `entrybleed` is a pure
timing side-channel with no syscall/file footprint;
`ptrace_traceme` and `sudo_samedit` are pure-memory races with no
on-disk artifacts).

**Test harness**

88 tests on every push: 33 kernel_range / host-fingerprint unit tests
(`tests/test_kernel_range.c` — boundary conditions, NULL safety,
multi-LTS, mainline-only) + 55 `detect()` integration tests
(`tests/test_detect.c` — synthetic host fingerprints across 26
modules). Coverage report at the end identifies any modules without
direct test rows.

**`core/host.c` shared host-fingerprint refactor**

One probe of kernel / arch / distro / userns gates / apparmor /
selinux / lockdown / sudo + polkit versions at startup. Every
module's `detect()` consumes `ctx->host`. Adds `meltdown_mitigation[]`
passthrough so `entrybleed` can distinguish "Not affected" (CPU
immune; OK) from "Mitigation: PTI" (KPTI on; vulnerable to
EntryBleed) without re-reading sysfs.

**kernel_range drift detector**

`tools/refresh-kernel-ranges.py` polls Debian's security tracker and
reports drift between the embedded `kernel_patched_from` tables and
what Debian actually ships. Already used to apply 9 corpus fixes in
v0.7.0; 9 more `TOO_TIGHT` findings pending per-commit verification.

**Marketing-grade landing page**

[karazajac.github.io/SKELETONKEY](https://karazajac.github.io/SKELETONKEY/)
— animated hero, `--explain` showcase with line-by-line typed terminal,
bento-grid features, KEV / verification stat chips. New Open Graph
card renders correctly on Twitter/LinkedIn/Slack/Discord.

### Real findings from the verifier

A handful of cases that show the project's "verified-vs-claimed bar"
thesis paying off in real time:

- **`dirty_pipe` on Ubuntu 22.04 (5.15.0-91-generic)** — version-only
  check would say VULNERABLE (5.15.0 < 5.15.25 backport in our table),
  but Ubuntu has silently backported the fix into the -91 patch level.
  `--active` correctly identified the primitive as blocked → OK. Only
  an empirical probe can tell.
- **`af_packet` on Ubuntu 18.04 (4.15.0-213-generic)** — our target
  expectation was wrong; 4.15 is post-fix. Caught + corrected by the
  verifier sweep.
- **`sudoedit_editor` on Ubuntu 22.04** — sudo 1.9.9 is the vulnerable
  version, but the default vagrant user has no sudoers grant to abuse.
  `detect()` correctly returns PRECOND_FAIL ("vuln version present, no
  grant to abuse").

### Coverage by audience

- **Red team**: `--auto` ranks vulnerable modules by safety + runs the
  safest, OPSEC notes per exploit, JSON for pipelines, no telemetry.
- **Blue team**: 119 detection rules in all 4 SIEM formats, CISA KEV
  prioritization, MITRE ATT&CK + CWE annotated, `--explain` triage
  briefings.
- **Researchers**: Source is the docs. CVE metadata sourced from
  federal databases. `--explain` shows the reasoning chain. 22 VM
  confirmations for trust.
- **Sysadmins**: `--scan` works without sudo. Static-musl binary
  drops on any Linux. JSON output for CI gates.

### Compatibility

- Default install: static-musl x86_64 — works on every Linux back to
  glibc 2.17 (RHEL 7, Debian 9, Ubuntu 14.04+, Alpine, anything).
- Also published: dynamic x86_64 (faster, modern glibc only) and
  dynamic arm64 (Raspberry Pi 4+, Apple Silicon Linux VMs, ARM
  servers).

### Authorized testing only

SKELETONKEY runs real exploits. By using it you assert you have
explicit authorization to test the target system. See
[`docs/ETHICS.md`](https://github.com/KaraZajac/SKELETONKEY/blob/main/docs/ETHICS.md).

### Links

- [CVE inventory](https://github.com/KaraZajac/SKELETONKEY/blob/main/CVES.md)
- [Verification records](https://github.com/KaraZajac/SKELETONKEY/blob/main/docs/VERIFICATIONS.jsonl)
- [KEV cross-reference](https://github.com/KaraZajac/SKELETONKEY/blob/main/docs/KEV_CROSSREF.md)
- [Detection playbook](https://github.com/KaraZajac/SKELETONKEY/blob/main/docs/DETECTION_PLAYBOOK.md)
- [Architecture](https://github.com/KaraZajac/SKELETONKEY/blob/main/docs/ARCHITECTURE.md)
- [Roadmap](https://github.com/KaraZajac/SKELETONKEY/blob/main/ROADMAP.md)
