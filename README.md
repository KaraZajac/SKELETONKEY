# SKELETONKEY

> A curated, actively-maintained corpus of Linux kernel LPE exploits —
> bundled with their detection signatures, patch status, and version
> ranges. Run it on a system you own (or are authorized to test) and
> it tells you which historical and recent CVEs that system is still
> vulnerable to, and — with explicit confirmation — gets you root.

> ⚠️ **Authorized testing only.** SKELETONKEY is a research and red-team
> tool. By using it you assert you have explicit authorization to test
> the target system. See [`docs/ETHICS.md`](docs/ETHICS.md).

## Quickstart

```bash
# One-shot install (x86_64 / arm64; checksum-verified)
curl -sSL https://github.com/KaraZajac/SKELETONKEY/releases/latest/download/install.sh | sh
```

**skeletonkey runs as a normal unprivileged user** — that's the whole
point. `--scan`, `--audit`, `--exploit`, and `--detect-rules` all
work without `sudo`. Only `--mitigate` and rule-file installation
write to root-owned paths.

```bash
# What's this box vulnerable to?  (no sudo)
skeletonkey --scan

# Broader system hygiene (setuid binaries, world-writable, capabilities, sudo)
skeletonkey --audit

# Deploy detection rules (needs sudo to write /etc/audit/rules.d/)
skeletonkey --detect-rules --format=auditd | sudo tee /etc/audit/rules.d/99-skeletonkey.rules

# Apply temporary mitigations (needs sudo for modprobe.d + sysctl)
sudo skeletonkey --mitigate copy_fail

# Fleet scan (any-sized host list via SSH; aggregated JSON for SIEM)
./tools/skeletonkey-fleet-scan.sh --binary skeletonkey --ssh-key ~/.ssh/id_rsa hosts.txt
```

### Example: unprivileged → root

```text
$ id
uid=1000(kara) gid=1000(kara) groups=1000(kara)

$ skeletonkey --scan
[+] dirty_pipe       VULNERABLE (kernel 5.15.0-56-generic)
[+] cgroup_release_agent VULNERABLE (kernel 5.15 < 5.17)
[+] pwnkit           VULNERABLE (polkit 0.105-31ubuntu0.1)
[-] copy_fail        not vulnerable (kernel 5.15 < introduction)
[-] dirty_cow        not vulnerable (kernel ≥ 4.9)

$ skeletonkey --exploit dirty_pipe --i-know
[!] dirty_pipe: kernel 5.15.0-56-generic IS vulnerable
[+] dirty_pipe: writing UID=0 into /etc/passwd page cache...
[+] dirty_pipe: spawning su root
# id
uid=0(root) gid=0(root) groups=0(root)
```

`skeletonkey --help` lists every command. See [`CVES.md`](CVES.md) for
the curated CVE inventory and [`docs/DEFENDERS.md`](docs/DEFENDERS.md)
for the blue-team deployment guide.

## What this is

Most Linux LPE references are dead repos, broken PoCs, or single-CVE
deep-dives. **SKELETONKEY is a living corpus**: each CVE that lands here
is empirically verified to work on the kernels it claims to target,
CI-tested across a distro matrix, and ships with the detection
signatures defenders need to spot it in their environment.

The same binary covers offense and defense:

- `skeletonkey --scan` — fingerprint the host, report which bundled CVEs
  apply, and which are blocked by patches/config/LSM
- `skeletonkey --exploit <CVE>` — run the named exploit (with `--i-know`
  authorization gate)
- `skeletonkey --detect-rules` — dump auditd / sigma / yara rules for
  every bundled CVE so blue teams can drop them into their tooling
- `skeletonkey --mitigate` — apply temporary mitigations for CVEs the
  host is vulnerable to (sysctl knobs, module blacklists, etc.)

## Status

**Active — v0.3.0 cut 2026-05-16.** Corpus covers **24 modules**
across the 2016 → 2026 LPE timeline:

- 🟢 **13 modules land root** end-to-end on a vulnerable host
  (copy_fail family ×5, dirty_pipe, entrybleed leak, pwnkit,
  overlayfs CVE-2021-3493, dirty_cow, ptrace_traceme,
  cgroup_release_agent, overlayfs_setuid CVE-2023-0386).
- 🟡 **11 modules fire the kernel primitive** by default and refuse
  to claim root without empirical confirmation. Pass `--full-chain`
  to engage the shared `modprobe_path` finisher and attempt root
  pop — requires kernel offsets via env vars / `/proc/kallsyms` /
  `/boot/System.map`; see [`docs/OFFSETS.md`](docs/OFFSETS.md).
  Modules: af_packet, af_packet2, af_unix_gc, cls_route4,
  fuse_legacy, nf_tables, netfilter_xtcompat, nft_fwd_dup,
  nft_payload, nft_set_uaf, stackrot.
- Detection rules ship inline (auditd / sigma / yara / falco) and
  are exported via `skeletonkey --detect-rules --format=…`.

See [`CVES.md`](CVES.md) for the per-CVE inventory + patch status.
See [`ROADMAP.md`](ROADMAP.md) for the next planned modules.

## Why this exists

The Linux kernel privilege-escalation space is fragmented:

- **`linux-exploit-suggester` / `linpeas`**: suggest applicable
  exploits, don't run them
- **`auto-root-exploit` / `kernelpop`**: bundle exploits, but largely
  stale, no CI, no defensive signatures
- **Per-CVE single-PoC repos**: usually one author, often abandoned
  within months of release, often only one distro

SKELETONKEY's bet is that there's room for a single curated bundle that
(1) actively maintains a small set of high-quality exploits across a
multi-distro matrix, and (2) ships detection rules alongside each
exploit so the same project serves both red and blue teams.

## Architecture

Each CVE (or tightly-related family) is a **module** under `modules/`.
Modules export a standard interface: `detect()`, `exploit()`,
`mitigate()`, `cleanup()`, plus metadata describing affected kernel
ranges, distro coverage, and CI test matrix.

Shared infrastructure (AppArmor bypass, su-exploitation primitives,
fingerprinting, common utilities) lives in `core/`.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the
module-loader design and how to add a new CVE.

## Build & run

```bash
make                          # build all modules
./skeletonkey --scan              # what's this box vulnerable to?  (no sudo)
./skeletonkey --scan --json       # machine-readable output for CI/SOC pipelines
./skeletonkey --detect-rules --format=sigma > rules.yml
./skeletonkey --exploit copy_fail --i-know   # actually run an exploit (starts as $USER)
```

## Acknowledgments

Each module credits the original CVE reporter and PoC author in its
`NOTICE.md`. SKELETONKEY is the bundling and bookkeeping layer; the
research credit belongs to the people who found the bugs.

## License

MIT — see [`LICENSE`](LICENSE).
