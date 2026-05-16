# CVE inventory

The curated list of CVEs IAMROOT exploits, with patch status and
module status. Updated as new modules land or as upstream patches
ship.

Status legend:

- 🟢 **WORKING** — module verified to land root on a vulnerable host
- 🟡 **PARTIAL** — module detects + exploits on some distros, not all
- 🔵 **DETECT-ONLY** — module fingerprints presence/absence but no
  exploit (yet). Useful for blue teams.
- ⚪ **PLANNED** — stub exists, work not started
- 🔴 **DEPRECATED** — fully patched everywhere relevant; kept for
  historical reference only

## Inventory

| CVE | Name | Class | First patched | IAMROOT module | Status | Notes |
|---|---|---|---|---|---|---|
| CVE-2026-31431 | Copy Fail (algif_aead `authencesn` page-cache write) | LPE (page-cache write → /etc/passwd) | mainline 2026-04-22 | `copy_fail` | 🟢 | Verified on Ubuntu 26.04, Alma 9, Debian 13. Full AppArmor bypass. |
| CVE-2026-43284 (v4) | Dirty Frag — IPv4 xfrm-ESP page-cache write | LPE (same primitive shape as Copy Fail, different trigger) | mainline 2026-05-XX | `dirty_frag_esp` | 🟢 | Full PoC + active-probe scan |
| CVE-2026-43284 (v6) | Dirty Frag — IPv6 xfrm-ESP (`esp6`) | LPE | mainline 2026-05-XX | `dirty_frag_esp6` | 🟢 | V6 STORE shift auto-calibrated per kernel build |
| CVE-2026-43500 | Dirty Frag — RxRPC page-cache write | LPE | mainline 2026-05-XX | `dirty_frag_rxrpc` | 🟢 | |
| (variant, no CVE) | Copy Fail GCM variant — xfrm-ESP `rfc4106(gcm(aes))` page-cache write | LPE | n/a | `copy_fail_gcm` | 🟢 | Sibling primitive, same fix |
| CVE-2022-0847 | Dirty Pipe — pipe `PIPE_BUF_FLAG_CAN_MERGE` write | LPE (arbitrary file write into page cache) | mainline 5.17 (2022-02-23) | `dirty_pipe` | 🔵 | Detect-only as of 2026-05-16. Verifies kernel version + branch-backport ranges: 5.10.102 / 5.15.25 / 5.16.11 / 5.17+. Exploit deferred to Phase 1.5 (needs shared passwd/su helpers in `core/`). Ships auditd + sigma detection rules. |
| CVE-2023-0458 | EntryBleed — KPTI prefetchnta KASLR bypass | INFO-LEAK (kbase) | mainline (partial mitigations only) | `_stubs/entrybleed_cve_2023_0458` | ⚪ | Stub. Used as STAGE-1 leak brick, not a standalone LPE. Works on lts-6.12.88 (empirical 5/5). |
| CVE-2026-31402 | NFS replay-cache heap overflow | LPE (NFS server) | mainline 2026-04-03 | — | ⚪ | Candidate. Different audience (NFS servers) — TBD whether in-scope. |
| CVE-TBD | Fragnesia (ESP shared-frag in-place encrypt) | LPE (page-cache write) | mainline TBD | `_stubs/fragnesia_TBD` | ⚪ | Stub. Per `findings/audit_leak_write_modprobe_backups_2026-05-16.md`, requires CAP_NET_ADMIN in userns netns — may or may not be in-scope depending on target environment. |

## Pipeline for additions

1. Bug must be **patched in upstream mainline** (we don't bundle
   0-days)
2. Either **CVE-assigned** or has clear advisory/patch reference
3. Affects a kernel version range with realistic deployment footprint
   (we don't bundle exploits for kernels nobody runs)
4. PoC works on at least one distro+kernel in our CI matrix
5. Detection signature(s) shipped alongside the exploit

## Patch-status tracking

Each module's `kernel-range.json` (planned) declares the affected
range. CI verifies the exploit fails on the first-patched version
and succeeds below it. When a distro backports the fix into a kernel
version below the original first-patched, the matrix updates and
the relevant distro drops out of the "WORKING" list for that module.

## Why we exclude some things

- **0-days the maintainer found themselves**: those go through
  responsible disclosure first, then enter IAMROOT after upstream patch
- **kCTF VRP submissions in flight**: same as above; disclosure
  before bundling
- **Hardware-specific side channels** (Spectre/Meltdown variants):
  out of scope; not page-cache or process-isolation primitives
- **Container-escape only**: unless it cleanly chains to host-root,
  out of scope (separate tool space)
