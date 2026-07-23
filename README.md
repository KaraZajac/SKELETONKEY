# SKELETONKEY

[![Latest release](https://img.shields.io/github/v/release/KaraZajac/SKELETONKEY?label=release)](https://github.com/KaraZajac/SKELETONKEY/releases/latest)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Modules](https://img.shields.io/badge/CVEs-29%20VM--verified%20%2F%2041-brightgreen.svg)](docs/VERIFICATIONS.jsonl)
[![Platform: Linux](https://img.shields.io/badge/platform-linux-lightgrey.svg)](#)

> **One curated binary. 46 Linux LPE modules covering 41 CVEs from 2016 → 2026.
> Every year 2016 → 2026 covered. 29 confirmed end-to-end against real Linux
> VMs via `tools/verify-vm/`. Detection rules in the box. One command picks
> the safest one and runs it.**

```bash
curl -sSL https://github.com/KaraZajac/SKELETONKEY/releases/latest/download/install.sh | sh \
  && export PATH="$HOME/.local/bin:$PATH" \
  && skeletonkey --auto --i-know
```

> ⚠️ **Authorized testing only.** SKELETONKEY runs real exploits. By
> using it you assert you have explicit authorization to test the
> target system. See [`docs/ETHICS.md`](docs/ETHICS.md).

## Why use this

Most Linux privesc tooling is broken in one of three ways:

- **`linux-exploit-suggester` / `linpeas`** — tell you what *might*
  work, run nothing
- **`auto-root-exploit` / `kernelpop`** — bundle exploits but ship
  no detection signatures and went stale years ago
- **Per-CVE PoC repos** — one author, one distro, abandoned within
  months

SKELETONKEY is one binary, actively maintained, with detection rules
for every CVE in the bundle — same project for red and blue teams.

## Who it's for

| Audience | What you get |
|---|---|
| **Red team / pentesters** | One tested binary. `--auto` ranks vulnerable modules by safety and runs the safest. Honest scope reporting — never claims root it didn't actually get. |
| **Sysadmins** | `skeletonkey --scan` (no sudo needed) tells you which boxes still need patching. Fleet-scan tool included. JSON output for CI gates ([schema](docs/JSON_SCHEMA.md)). |
| **Blue team / SOC** | Auditd + sigma + yara + falco rules for every CVE. `--detect-rules --format=auditd \| sudo tee …` ships SIEM coverage in one command. |
| **CTF / training** | Reproducible LPE environment with public CVEs across a 10-year timeline. Each module documents the bug, the trigger, and the fix. |

## Corpus at a glance

**46 modules covering 41 distinct CVEs** across the 2016 → 2026 LPE
timeline. **29 of the 41 CVEs have been empirically verified** in real
Linux VMs via `tools/verify-vm/`; the 12 still-pending entries are
blocked by their target environment (legacy hypervisor, EOL kernel, or
the t64-transition libc rollout) or are brand-new additions awaiting a
VM sweep, not by missing code.

| Tier | Count | What it means |
|---|---|---|
| 🟢 Full chain | **15** | Lands root (or its canonical capability) end-to-end. No per-kernel offsets needed. |
| 🟡 Primitive | **13** | Fires the kernel primitive + grooms the slab + records a witness. Default returns `EXPLOIT_FAIL` honestly. Pass `--full-chain` to engage the shared `modprobe_path` finisher (needs offsets — see [`docs/OFFSETS.md`](docs/OFFSETS.md)). |

**🟢 Modules that land root on a vulnerable host:**
copy_fail family ×5 · dirty_pipe · dirty_cow · pwnkit · overlayfs
(CVE-2021-3493) · overlayfs_setuid (CVE-2023-0386) ·
cgroup_release_agent · ptrace_traceme · sudoedit_editor · entrybleed
(KASLR leak primitive) · refluxfs (CVE-2026-64600, `--full-chain`:
`/etc/passwd` root pop on a private-extent XFS target)

**🟡 Modules with opt-in `--full-chain`:**
af_packet · af_packet2 · af_unix_gc · cls_route4 · fuse_legacy ·
nf_tables · nft_set_uaf · nft_fwd_dup · nft_payload ·
netfilter_xtcompat · stackrot · sudo_samedit · sequoia · vmwgfx

### Empirical verification (29 of 41 CVEs)

Records in [`docs/VERIFICATIONS.jsonl`](docs/VERIFICATIONS.jsonl) prove
each verdict against a known-target VM. Coverage:

| Distro / kernel | Modules verified |
|---|---|
| Ubuntu 18.04 (4.15.0, sudo 1.8.21p2) | af_packet · ptrace_traceme · sudo_samedit · sudo_runas_neg1 |
| Ubuntu 20.04 (5.4.0-26 pinned + 5.15 HWE) | af_packet2 · cls_route4 · nft_payload · overlayfs · pwnkit · sequoia · tioscpgrp |
| Ubuntu 22.04 (5.15 stock + mainline 5.15.5 / 6.1.10 / 6.19.7) | af_unix_gc · dirty_pipe · dirtydecrypt · entrybleed · nf_tables · nft_set_uaf · nft_pipapo · overlayfs_setuid · stackrot · sudoedit_editor · sudo_chwoot |
| Debian 11 (5.10 stock) | cgroup_release_agent · fuse_legacy · netfilter_xtcompat · nft_fwd_dup |
| Debian 12 (6.1 stock + udisks2 / polkit allow rule) | pack2theroot · udisks_libblockdev |
| Rocky Linux 9.8 (5.14.0-687.10.1.el9_8.0.1, stock XFS + `reflink=1`) | refluxfs |

**Not yet verified (12):** `vmwgfx` (VMware-guest-only — no public Vagrant
box), `dirty_cow` (needs ≤ 4.4 kernel — older than every supported box),
`mutagen_astronomy` (mainline 4.14.70 kernel-panics on Ubuntu 18.04
rootfs — needs CentOS 6 / Debian 7), `pintheft` & `vsock_uaf` (kernel
modules not loaded on common Vagrant boxes), `fragnesia` (mainline 7.0.5
kernel .debs depend on the t64-transition libs from Ubuntu 24.04+/Debian
13+; no Parallels-supported box has those yet), `ptrace_pidfd` (brand-new
2026-05 Qualys disclosure — added this cycle, VM sweep pending), `sudo_host`
(brand-new 2025-06 Stratascale disclosure — added this cycle, VM sweep
pending), `cifswitch` (detect + `add_key` primitive VM-verified; full chain
+ patched-kernel discriminator pending), `nft_catchall` (reconstructed
kernel-UAF trigger, not VM-verified), `bad_epoll` (reconstructed epoll
race trigger — deliberately under-driven, not VM-verified), `ghostlock`
(reconstructed rtmutex/futex-PI stack-UAF trigger — deliberately
under-driven, not VM-verified). All twelve are
flagged in
[`tools/verify-vm/targets.yaml`](tools/verify-vm/targets.yaml) with rationale.

See [`CVES.md`](CVES.md) for per-module CVE, kernel range, and
detection status. Run `skeletonkey --module-info <name>` for the
embedded verification records per module.

## Quickstart

```bash
# Install (x86_64 / arm64; checksum-verified)
curl -sSL https://github.com/KaraZajac/SKELETONKEY/releases/latest/download/install.sh | sh

# What's this box vulnerable to?  (no sudo)
skeletonkey --scan

# One-page operator briefing for a single CVE: CWE / MITRE ATT&CK /
# CISA KEV status, live detect() trace, OPSEC footprint, detection
# coverage. Useful for triage tickets and SOC analyst handoffs.
skeletonkey --explain nf_tables

# Pick the safest LPE and run it
skeletonkey --auto --i-know

# Deploy detection rules (needs sudo to write into /etc/audit/rules.d/)
skeletonkey --detect-rules --format=auditd \
  | sudo tee /etc/audit/rules.d/99-skeletonkey.rules

# Fleet scan — many hosts via SSH, aggregated JSON for SIEM
./tools/skeletonkey-fleet-scan.sh --binary skeletonkey \
  --ssh-key ~/.ssh/id_rsa hosts.txt
```

**SKELETONKEY runs as a normal unprivileged user** — that's the point.
`--scan`, `--audit`, `--exploit`, and `--detect-rules` all work without
`sudo`. Only `--mitigate` and rule-file installation write root-owned
paths.

### Example: unprivileged → root

```text
$ id
uid=1000(kara) gid=1000(kara) groups=1000(kara)

$ skeletonkey --auto --i-know
[*] auto: host=demo distro=ubuntu/24.04 kernel=5.15.0-56-generic arch=x86_64
[*] auto: active probes enabled — brief /tmp file touches and fork-isolated namespace probes
[*] auto: scanning 45 modules for vulnerabilities...
[+] auto: dirty_pipe             VULNERABLE (safety rank 90)
[+] auto: cgroup_release_agent   VULNERABLE (safety rank 98)
[+] auto: pwnkit                 VULNERABLE (safety rank 100)
[ ] auto: copy_fail              patched or not applicable
[ ] auto: nf_tables              precondition not met
...

[*] auto: scan summary — 3 vulnerable, 21 patched/n.a., 7 precondition-fail, 0 indeterminate
[*] auto: 3 vulnerable modules found. Safest is 'pwnkit' (rank 100).
[*] auto: launching --exploit pwnkit...

[+] pwnkit: writing gconv-modules cache + payload.so...
[+] pwnkit: execve(pkexec) with NULL argv + crafted envp...
# id
uid=0(root) gid=0(root) groups=0(root)
```

The safety ranking goes: **structural escapes** (no kernel state
touched) → **page-cache writes** → **userspace cred-races** →
**kernel primitives** → **kernel races** (least predictable). The
goal is to never crash a production box looking for root.

## How it works

Each CVE (or tightly-related family) is a **module** under `modules/`.
Modules export a standard interface (`detect / exploit / mitigate /
cleanup`) plus metadata (kernel range, detection rule text). The
top-level binary dispatches per command:

- `--scan` walks every module's `detect()` against the running host
- `--exploit <name> --i-know` runs the named module's exploit (the
  `--i-know` flag is the authorization gate)
- `--auto --i-know` does the scan, ranks by safety, runs the safest
- `--detect-rules --format=<auditd|sigma|yara|falco>` emits the
  embedded rule corpus
- `--mitigate <name>` / `--cleanup <name>` apply / undo temporary
  mitigations (module-dependent — most kernel modules say "upgrade")
- `--dump-offsets` reads `/proc/kallsyms` + `/boot/System.map` and
  emits a ready-to-paste C entry for the `--full-chain` offset table

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the
module-loader design.

## The verified-vs-claimed bar

Most public PoC repos hardcode offsets for one kernel build and
silently break elsewhere. SKELETONKEY refuses to ship fabricated
offsets. The shared `--full-chain` finisher only returns
`EXPLOIT_OK` after a setuid bash sentinel file *actually appears*;
otherwise modules return `EXPLOIT_FAIL` with a diagnostic. Operators
populate the offset table once per target kernel via
`skeletonkey --dump-offsets` and either set env vars or upstream the
entry via PR ([`CONTRIBUTING.md`](CONTRIBUTING.md)).

## Build from source

```bash
git clone https://github.com/KaraZajac/SKELETONKEY.git
cd SKELETONKEY
make
./skeletonkey --version
```

Builds clean with gcc or clang on any modern Linux. macOS dev builds
also compile (modules with Linux-only headers stub out gracefully).

## Status

**v0.9.14 cut 2026-07-23.** 46 modules across 41 CVEs — **every
year 2016 → 2026 now covered**. Newest: `refluxfs` (CVE-2026-64600,
Qualys TRU's "RefluXFS" — a nine-year TOCTOU race in the XFS **reflink
copy-on-write** path: `xfs_reflink_fill_cow_hole()` drops `ILOCK` to wait
for transaction log space, then re-checks the refcount btree at a
**stale** physical block without re-reading the data fork, so a
direct-I/O writer treats a still-shared block as private and writes to it
in place. The primitive is an arbitrary overwrite of the **on-disk
contents of any readable file** — data, not memory corruption — so there
are **no offsets, no ROP, no KASLR/SMEP/SMAP** to defeat, and SELinux
enforcing, containers and seccomp are all irrelevant. Because the
victim's inode is never written, its `mtime`/`ctime`/size never change
and **file-integrity monitoring cannot see it**. Unprivileged, no userns,
no crafted image — reachable wherever an XFS volume is mounted
`reflink=1`, the installer default on RHEL/CentOS/Rocky/Alma/Oracle 8-10,
Fedora Server ≥ 31 and Amazon Linux 2023. **🟢 VM-verified full chain**:
`--exploit refluxfs --i-know --full-chain` reflink-clones `/etc/passwd`,
races the CoW window, strips root's password on-disk and returns
`EXPLOIT_OK` (`su root`, empty password → uid 0) — confirmed on Rocky 9.8,
every other account preserved, backed up + restorable. One caveat found
in testing: the target's extent must be **private** going in (an
already-shared file isn't attackable; normal `useradd`/`passwd` churn
makes it private). Plain `--exploit` runs only a safe own-files trigger),
`ghostlock` (CVE-2026-43499,
VEGA / Nebula Security's "GhostLock" — a ~15-year rtmutex/futex requeue-PI
use-after-free on **kernel stack** memory where `remove_waiter()` clears
`pi_blocked_on` on the wrong task during the `-EDEADLK` deadlock-rollback,
raced by a sibling-CPU `sched_setattr()` priority walk; reachable by **any
unprivileged user with no user namespace**; VEGA / Nebula kernelCTF public
PoC ($92k, ~97% stable) — shipped as a deliberately under-driven,
reconstructed trigger anchored on a safe `-EDEADLK` reachability witness
with the corpus's lowest `--auto` safety rank), `bad_epoll` (CVE-2026-46242,
Jaeyoung Chung's "Bad Epoll" — a race UAF in `fs/eventpoll.c` reachable by
any unprivileged user with no user namespace; kernelCTF public PoC),
`nft_catchall` (CVE-2026-23111, the nf_tables `nft_map_catchall_activate`
abort-path UAF — an inverted condition frees a chain still referenced by a
catch-all GOTO map element; public reproduction by FuzzingLabs), and
`cifswitch` (CVE-2026-46243, Asim Manizada's "CIFSwitch" — the
`cifs.spnego` key type trusts userspace-forged authority fields, coercing
the root `cifs.upcall` helper into loading an attacker NSS module as root).
v0.9.0 added 5 gap-fillers
(`mutagen_astronomy` / `sudo_runas_neg1` / `tioscpgrp` / `vsock_uaf` /
`nft_pipapo`); v0.8.0 added 3 (`sudo_chwoot` / `udisks_libblockdev` /
`pintheft`). v0.9.1 and v0.9.2 are verification-only sweeps that took
the verified count from 22 → 28 by booting real vulnerable kernels
(Ubuntu mainline 5.4.0-26, 5.15.5, 6.19.7 + provisioner-built sudo
1.9.16p1 + Debian 12 + polkit allow rule for udisks).
**29 empirically verified** against real Linux VMs (Ubuntu 18.04 /
20.04 / 22.04 + Debian 11 / 12 + Rocky Linux 9.8 + mainline kernels
from kernel.ubuntu.com). 88-test unit harness + ASan/UBSan + clang-tidy on
every push. 4 prebuilt binaries (x86_64 + arm64, each in dynamic +
static-musl flavors).

Reliability + accuracy work in v0.7.x:
- Shared **host fingerprint** (`core/host.{h,c}`) populated once at
  startup — kernel/distro/userns gates/sudo+polkit versions — exposed
  to every module via `ctx->host`.
- **Test harness** (`tests/`, `make test`) — 88 tests: 33 kernel_range
  unit tests + 55 detect() integration tests over mocked host
  fingerprints. Runs in CI on every push.
- **VM verifier** (`tools/verify-vm/`) — Vagrant + Parallels scaffold
  that boots known-vulnerable kernels (stock distro + mainline via
  kernel.ubuntu.com), runs `--explain --active` per module, records
  match/MISMATCH/PRECOND_FAIL as JSON. 29 modules confirmed end-to-end.
- **`--explain <module>`** — single-page operator briefing: CVE / CWE
  / MITRE ATT&CK / CISA KEV status, host fingerprint, live detect()
  trace, OPSEC footprint, detection-rule coverage, verified-on
  records. Paste-into-ticket ready.
- **CVE metadata pipeline** (`tools/refresh-cve-metadata.py`) — fetches
  CISA KEV catalog + NVD CWE; 13 of 40 modules cover KEV-listed CVEs.
- **151 detection rules** across auditd / sigma / yara / falco; one
  command exports the corpus to your SIEM.
- `--auto` upgrades: per-detect 15s timeout, fork-isolated detect +
  exploit, structured verdict table, scan summary, `--dry-run`.

Not yet verified (12 of 41 CVEs): `vmwgfx` (VMware-guest only),
`dirty_cow` (needs ≤ 4.4 kernel), `mutagen_astronomy` (mainline
4.14.70 panics on Ubuntu 18.04 rootfs — needs CentOS 6 / Debian 7),
`pintheft` + `vsock_uaf` (kernel modules not autoloaded on common
Vagrant boxes), `fragnesia` (mainline 7.0.5 .debs need t64-transition
libs from Ubuntu 24.04+ / Debian 13+), `ptrace_pidfd` + `sudo_host`
+ `cifswitch` (cifswitch detect + primitive VM-verified; full chain
pending) + `nft_catchall` (reconstructed kernel-UAF trigger, not
VM-verified) + `bad_epoll` (reconstructed epoll race trigger,
deliberately under-driven, not VM-verified) + `ghostlock` (reconstructed
rtmutex/futex-PI stack-UAF trigger, deliberately under-driven, not
VM-verified). Rationale in
[`tools/verify-vm/targets.yaml`](tools/verify-vm/targets.yaml).

See [`ROADMAP.md`](ROADMAP.md) for the next planned modules and
infrastructure work.

## Contributing

PRs welcome for: kernel offsets (run `--dump-offsets` on a target
kernel, paste into `core/offsets.c`), new modules, detection rules,
and CVE-status corrections. See [`CONTRIBUTING.md`](CONTRIBUTING.md).

**Keeping `kernel_range` tables current.** `tools/refresh-kernel-ranges.py`
polls Debian's security tracker and reports drift between each
module's hardcoded `kernel_patched_from` thresholds and the
fixed-versions Debian actually ships. Run periodically (or in CI)
to catch new backports that need to land in the corpus:

```bash
tools/refresh-kernel-ranges.py            # human report
tools/refresh-kernel-ranges.py --json     # machine-readable
tools/refresh-kernel-ranges.py --patch    # proposed C-source edits
```

## Acknowledgments

Each module credits the original CVE reporter and PoC author in its
`NOTICE.md`. SKELETONKEY is the bundling and bookkeeping layer;
the research credit belongs to the people who found the bugs.

## License

MIT — see [`LICENSE`](LICENSE).
