# SKELETONKEY — launch post

> Copy-pasteable for HN, lobste.rs, mastodon, blog. ~600 words.

---

## SKELETONKEY: a curated Linux LPE corpus with detection rules baked in

The Linux privilege-escalation space is fragmented. Single-CVE PoC
repos go stale within months. `linux-exploit-suggester` tells you
what *might* work but doesn't run anything. `auto-root-exploit` and
`kernelpop` bundle exploits but ship no detection signatures and
haven't been maintained in years.

**SKELETONKEY** is one curated binary that:

1. Fingerprints the host's kernel / distro / sudo / userland.
2. Reports which of 28 bundled CVEs that host is still vulnerable
   to — covering 2016 through 2026.
3. With explicit `--i-know` authorization, runs the safest one and
   gets you root.
4. Ships matching **auditd + sigma rules** for every CVE so blue
   teams get the same coverage when they deploy it.

### One command

```bash
curl -sSL https://github.com/KaraZajac/SKELETONKEY/releases/latest/download/install.sh | sh \
  && export PATH="$HOME/.local/bin:$PATH" \
  && skeletonkey --auto --i-know
```

`--auto` ranks vulnerable modules by **exploit safety** —
structural escapes (no kernel state touched) first, then page-cache
writes, then userspace cred-races, then kernel primitives, then
kernel races last — and runs the safest match. If it fails it falls
back gracefully and tells you the next candidates to try manually.

### What's in the corpus

- **Userspace LPE**: pwnkit (CVE-2021-4034), sudo Baron Samedit
  (CVE-2021-3156), sudoedit EDITOR escape (CVE-2023-22809)
- **Page-cache writes**: dirty_pipe (CVE-2022-0847), dirty_cow
  (CVE-2016-5195), copy_fail family (CVE-2026-31431, 43284, 43500)
- **Container/namespace**: cgroup_release_agent (CVE-2022-0492),
  overlayfs (CVE-2021-3493), overlayfs_setuid (CVE-2023-0386),
  fuse_legacy (CVE-2022-0185)
- **Kernel primitives**: netfilter (4 CVEs from 2022→2024),
  af_packet (CVE-2017-7308, CVE-2020-14386), cls_route4
  (CVE-2022-2588), netfilter_xtcompat (CVE-2021-22555)
- **Kernel races**: stackrot (CVE-2023-3269), af_unix_gc
  (CVE-2023-4622), Sequoia (CVE-2021-33909)
- **Side channels**: EntryBleed kbase leak (CVE-2023-0458)
- **Graphics**: vmwgfx DRM OOB (CVE-2023-2008)
- **Userspace classic**: PTRACE_TRACEME (CVE-2019-13272)

Full inventory at
[CVES.md](https://github.com/KaraZajac/SKELETONKEY/blob/main/CVES.md).

### The verified-vs-claimed bar

Most public PoC repos hardcode offsets for one kernel build and
silently break elsewhere. SKELETONKEY refuses to ship fabricated
offsets. Modules with a kernel primitive but no per-kernel
cred-overwrite chain default to firing the primitive + grooming the
slab + recording an empirical witness, then return
`EXPLOIT_FAIL` honestly. The opt-in `--full-chain` engages the
shared `modprobe_path` finisher with sentinel-arbitrated success
(it only claims root when a setuid bash actually materializes).

When `--full-chain` needs kernel offsets, you populate them once on
a target kernel via `skeletonkey --dump-offsets` (parses
`/proc/kallsyms` or `/boot/System.map`) and either set env vars or
upstream the entry to `core/offsets.c kernel_table[]` via PR.

### For each side of the house

- **Red team**: stop curating broken PoCs. One tested binary, fresh
  releases, honest scope reporting.
- **Sysadmins**: one command, no SaaS, JSON output for CI gates.
  Fleet-scan tool included.
- **Blue team**: `skeletonkey --detect-rules --format=auditd | sudo
  tee /etc/audit/rules.d/99-skeletonkey.rules` and you have coverage
  for every CVE in the bundle. Sigma + YARA + Falco output also
  supported.

### Status + roadmap

v0.5.0 today: 28 modules, all build clean on Debian 13 / kernel
6.12, all refuse-on-patched verified. The embedded offset table is
empty — operator-populated. Next: empirical validation on a
multi-distro vuln-kernel VM matrix, then offset-table community
seeding for common cloud builds.

MIT. Each module credits the original CVE reporter and PoC author
in its `NOTICE.md`. The research credit belongs to the people who
found the bugs; SKELETONKEY is the bundling layer.

**Repo:** https://github.com/KaraZajac/SKELETONKEY
**Release:** https://github.com/KaraZajac/SKELETONKEY/releases/latest

Authorized testing only. Read [docs/ETHICS.md](ETHICS.md) before you
point this at anything you don't own.
