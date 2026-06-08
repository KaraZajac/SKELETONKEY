# NOTICE — nft_catchall (CVE-2026-23111)

## Vulnerability

**CVE-2026-23111** — a **use-after-free** in the Linux kernel `nf_tables`
(netfilter) transaction-abort path. `nft_map_catchall_activate()` carries
an **inverted condition** (a stray `!`): during a transaction *abort* it
processes *active* catch-all set elements instead of skipping them. A
catch-all element in an nftables **map** holds a verdict (GOTO/JUMP)
referencing a chain; the wrong (de)activation drives the chain's
use-count to zero, so a following `DELCHAIN` frees the chain while the
catch-all verdict element still references it → UAF.

From an **unprivileged** local user — via **user namespaces + nftables**
(needs `CONFIG_USER_NS` + `CONFIG_NF_TABLES`) — the UAF is escalatable to
root: leak a kernel address, obtain arbitrary R/W, ROP over
`modprobe_path` / `selinux_state`.

NVD class: **CWE-416** (Use After Free). CVSS v3.1 **7.8 HIGH**
(`AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`). Affects current distros (Debian
bookworm/trixie, Ubuntu 22.04/24.04). **Not** in CISA KEV.

The fix removed a single character (the inverted `!`).

## Research credit

- **Fixed upstream** by commit
  `f41c5d151078c5348271ffaf8e7410d96f2d82f8` ("netfilter: nf_tables: fix
  … catch-all … activate"); reported and fixed through the Linux kernel
  security process (NVD lists the source as `kernel.org`; no public
  individual reporter name in the advisory).
- **Public reproduction + analysis** by **FuzzingLabs** —
  <https://fuzzinglabs.com/repro-cve-2026-23111/> — which the module's
  trigger reconstruction is informed by.
- Debian security tracker (authoritative backport versions):
  <https://security-tracker.debian.org/tracker/CVE-2026-23111> —
  bookworm 6.1.164 / trixie 6.12.73 / forky·sid 6.18.10 (bullseye/5.10
  still unfixed at time of writing).

All credit for finding and analysing this bug belongs to the upstream
reporter and to FuzzingLabs for the public write-up. SKELETONKEY is the
bundling and bookkeeping layer only.

## SKELETONKEY role

🟡 **Trigger (reconstructed) — primitive-only, not VM-verified.** This is
one more UAF in the corpus's most-covered subsystem (`nf_tables`,
`nft_set_uaf`, `nft_payload`, `nft_pipapo`, …), shipped on the same
contract as `nf_tables` (CVE-2024-1086): a fork-isolated trigger that
fires the bug class and stops.

`detect()` version-gates against the Debian backports above (upstream
thresholds 6.1.164 / 6.12.73 / 6.18.10; catch-all set elements arrived in
~5.13, so older kernels lack the path) **and** requires unprivileged
user-namespace clone — a vulnerable kernel with userns locked down is
`PRECOND_FAIL`. `exploit()` builds a verdict map with a catch-all GOTO
element and provokes an aborting batch transaction to drive the
abort-path UAF, observes slabinfo, and returns `EXPLOIT_FAIL`. The
per-kernel leak + arbitrary-R/W + `modprobe_path` ROP that lands a root
shell is **not** bundled (per-build offsets refused), and the trigger is
reconstructed from the public analysis rather than VM-verified — it never
claims root it did not get.
