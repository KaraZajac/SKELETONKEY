# NOTICE — cifswitch (CVE-2026-46243, "CIFSwitch")

## Vulnerability

**CVE-2026-46243 "CIFSwitch"** — the Linux kernel's `cifs.spnego`
request-key type (`fs/smb/client/cifs_spnego.c`) accepts key descriptions
created by **userspace** (via `add_key(2)` / `request_key(2)`) without
verifying that the request originated from the in-kernel CIFS client. The
key description carries authority-bearing fields — `pid`, `uid`,
`creduid`, `upcall_target` — that the root-privileged `cifs.upcall`
helper treats as trusted, kernel-originating inputs. An unprivileged
local user forges such a description and, combined with user + mount
namespace manipulation, coerces `cifs.upcall` into loading an
attacker-controlled NSS shared library as root → local privilege
escalation to root.

It is a **~19-year-old** logic flaw — the cifs spnego upcall predates the
key-type origin checks added to the keyrings subsystem later. NVD class:
**CWE-20** (Improper Input Validation). Not in CISA KEV (as of disclosure).

**Preconditions:** the `cifs` kernel module available, `cifs-utils`
installed (so `cifs.upcall` is present), and the `cifs.spnego`
request-key rule active. Default-vulnerable distributions reported
include Linux Mint, CentOS Stream 9, Rocky Linux 9, AlmaLinux 9, Kali
Linux, SLES 15 SP7, and Red Hat Enterprise Linux 6–10.

## Research credit

Discovered, named, and disclosed by **Asim Manizada** on **2026-05-28**,
with a working proof-of-concept published the same day.

- Red Hat advisory (RHSB-2026-005):
  <https://access.redhat.com/security/vulnerabilities/RHSB-2026-005>
- BleepingComputer write-up:
  <https://www.bleepingcomputer.com/news/security/new-cifswitch-linux-flaw-gives-root-on-multiple-distributions/>
- Upstream fix: commit `3da1fdf4efbc490041eb4f836bf596201203f8f2`
  ("smb: client: reject userspace cifs.spnego descriptions"), merged
  7.1-rc5.
- Debian-tracked stable backports: 5.10.257 (bullseye) / 6.1.174
  (bookworm) / 6.12.90 (trixie) / 7.0.10 (forky, sid).

All research credit for finding and analysing this bug belongs to Asim
Manizada. SKELETONKEY is the bundling and bookkeeping layer only.

## SKELETONKEY role

🟡 **Primitive / ported-from-disclosure — not yet VM-verified.**
`detect()` gates on the kernel version (the Debian backport thresholds
above) **and** the presence of the vulnerable userspace path
(`cifs.upcall` / the `cifs.spnego` request-key rule) — a vulnerable
kernel without `cifs-utils` is reported `PRECOND_FAIL`, not `VULNERABLE`.
Override the probe with `SKELETONKEY_CIFS_ASSUME_PRESENT=1` (or `0`).

`exploit()` fires only the reachable, **non-destructive** part of the
primitive: it attempts to register a forged-but-benign `cifs.spnego` key
as the unprivileged user via `add_key(2)` — which instantiates the key
directly and does **not** invoke `cifs.upcall`, so it loads nothing and
spawns no privileged helper — and revokes the key immediately. A clean
accept is the empirical witness that the missing-origin-validation flaw
is present. It then **stops**: the namespace-switch + malicious-NSS-load
chain that actually lands a root shell is target/config-specific and is
**not** bundled until it can be verified end-to-end against a real
vulnerable VM, in keeping with the project's no-fabrication rule.
`exploit()` returns `EXPLOIT_FAIL` unless it can witness euid 0.

`--mitigate` writes `/etc/modprobe.d/skeletonkey-disable-cifs.conf`
(blocklists the `cifs` module — the vendor-recommended runtime
mitigation); `--cleanup` removes it. Architecture-agnostic — keyring and
namespace logic, no shellcode.
