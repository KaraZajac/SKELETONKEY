# IAMROOT

> A curated, actively-maintained corpus of Linux kernel LPE exploits —
> bundled with their detection signatures, patch status, and version
> ranges. Run it on a system you own (or are authorized to test) and
> it tells you which historical and recent CVEs that system is still
> vulnerable to, and — with explicit confirmation — gets you root.

```
 ██╗ █████╗ ███╗   ███╗██████╗  ██████╗  ██████╗ ████████╗
 ██║██╔══██╗████╗ ████║██╔══██╗██╔═══██╗██╔═══██╗╚══██╔══╝
 ██║███████║██╔████╔██║██████╔╝██║   ██║██║   ██║   ██║
 ██║██╔══██║██║╚██╔╝██║██╔══██╗██║   ██║██║   ██║   ██║
 ██║██║  ██║██║ ╚═╝ ██║██║  ██║╚██████╔╝╚██████╔╝   ██║
 ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝
```

> ⚠️ **Authorized testing only.** IAMROOT is a research and red-team
> tool. By using it you assert you have explicit authorization to test
> the target system. See [`docs/ETHICS.md`](docs/ETHICS.md).

## Quickstart

```bash
# One-shot install (x86_64 / arm64; checksum-verified)
curl -sSL https://github.com/KaraZajac/IAMROOT/releases/latest/download/install.sh | sh

# What's this box vulnerable to?
sudo iamroot --scan

# Broader system hygiene (setuid binaries, world-writable, capabilities, sudo)
sudo iamroot --audit

# Deploy detection rules across every bundled module
sudo iamroot --detect-rules --format=auditd | sudo tee /etc/audit/rules.d/99-iamroot.rules

# Fleet scan (any-sized host list via SSH; aggregated JSON for SIEM)
./tools/iamroot-fleet-scan.sh --binary iamroot --ssh-key ~/.ssh/id_rsa hosts.txt
```

`iamroot --help` lists every command. See [`CVES.md`](CVES.md) for the
curated CVE inventory and [`docs/DEFENDERS.md`](docs/DEFENDERS.md) for
the blue-team deployment guide.

## What this is

Most Linux LPE references are dead repos, broken PoCs, or single-CVE
deep-dives. **IAMROOT is a living corpus**: each CVE that lands here
is empirically verified to work on the kernels it claims to target,
CI-tested across a distro matrix, and ships with the detection
signatures defenders need to spot it in their environment.

The same binary covers offense and defense:

- `iamroot --scan` — fingerprint the host, report which bundled CVEs
  apply, and which are blocked by patches/config/LSM
- `iamroot --exploit <CVE>` — run the named exploit (with `--i-know`
  authorization gate)
- `iamroot --detect-rules` — dump auditd / sigma / yara rules for
  every bundled CVE so blue teams can drop them into their tooling
- `iamroot --mitigate` — apply temporary mitigations for CVEs the
  host is vulnerable to (sysctl knobs, module blacklists, etc.)

## Status

**Active. Bootstrap phase as of 2026-05-16.** First module
(`copy_fail_family`) absorbed from the standalone DIRTYFAIL project
and is verified working end-to-end on Ubuntu 26.04 + Alma 9 + Debian
13 with full AppArmor bypass + container escape demo + persistent
backdoor mode.

See [`CVES.md`](CVES.md) for the full curated CVE list with patch
status. See [`ROADMAP.md`](ROADMAP.md) for the next planned modules.

## Why this exists

The Linux kernel privilege-escalation space is fragmented:

- **`linux-exploit-suggester` / `linpeas`**: suggest applicable
  exploits, don't run them
- **`auto-root-exploit` / `kernelpop`**: bundle exploits, but largely
  stale, no CI, no defensive signatures
- **Per-CVE single-PoC repos**: usually one author, often abandoned
  within months of release, often only one distro

IAMROOT's bet is that there's room for a single curated bundle that
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
sudo ./iamroot --scan         # what's this box vulnerable to?
sudo ./iamroot --scan --json  # machine-readable output for CI/SOC pipelines
sudo ./iamroot --detect-rules --format=sigma > rules.yml
sudo ./iamroot --exploit copy_fail --i-know  # actually run an exploit
```

## Acknowledgments

Each module credits the original CVE reporter and PoC author in its
`NOTICE.md`. IAMROOT is the bundling and bookkeeping layer; the
research credit belongs to the people who found the bugs.

## License

MIT — see [`LICENSE`](LICENSE).
