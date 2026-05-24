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
