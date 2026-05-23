# NOTICE — pack2theroot

## Vulnerability

**CVE-2026-41651** — Pack2TheRoot. PackageKit TOCTOU local privilege
escalation in `src/pk-transaction.c`: two cooperating bugs allow
`cached_transaction_flags` and `cached_full_paths` to be overwritten
between polkit authorisation and dispatch, and a third bug causes the
dispatcher to read those cached values at fire time rather than at
authorisation time. GLib's D-Bus-vs-idle priority ordering makes the
overwrite deterministic, not a timing race.

CVSS 8.1. Affects PackageKit `1.0.2` through `1.3.4` (over a decade
of releases). Fixed in **PackageKit 1.3.5** (upstream commit
`76cfb675`, 2026-04-22).

## Research credit

Discovered and disclosed by the **Deutsche Telekom security team**.

> Telekom advisory: <https://github.security.telekom.com/2026/04/pack2theroot-linux-local-privilege-escalation.html>
> Upstream advisory: <https://github.com/PackageKit/PackageKit/security/advisories/GHSA-f55j-vvr9-69xv>

The standalone proof-of-concept exploit the SKELETONKEY module is
ported from is by **Vozec**:

> Reference PoC: <https://github.com/Vozec/CVE-2026-41651>

The Vozec repository carries no `LICENSE` file at the time of porting;
the SKELETONKEY-distributed `skeletonkey_modules.c` is original
SKELETONKEY-licensed code (MIT) that reproduces the PoC's deb-builder
(ar / ustar / gzip-stored) and D-Bus call sequence. Independent
research credit belongs to the people above.

A CTF-style lab by **dinosn** (Dockerised PackageKit 1.3.4 build with
the exploit pre-set) is a useful reference bench:

> CTF lab: <https://github.com/dinosn/pack2theroot-lab>

## SKELETONKEY role

`skeletonkey_modules.c` wraps the PoC in the standard
`skeletonkey_module` detect / exploit / cleanup interface, adds the
embedded auditd + sigma rules, and reads PackageKit's
`VersionMajor/Minor/Micro` D-Bus properties so `detect()` can give a
high-confidence verdict (the fix release 1.3.5 is officially pinned —
no version-fabrication caveat).

## Verification status

**Ported, not yet validated end-to-end on a vulnerable host.** See
`MODULE.md` for the recommended verification path (Vozec's Dockerised
PackageKit-1.3.4 bench).
