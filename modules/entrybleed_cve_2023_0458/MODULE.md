# EntryBleed — CVE-2023-0458

> ⚪ **PLANNED** stub module. See [`../../ROADMAP.md`](../../ROADMAP.md)
> Phase 3.

## Summary

KPTI's user-space-mapped entry trampoline is detectable via
`prefetchnta` timing, leaking the kernel base address (defeats
KASLR). Universal across modern x86_64 kernels with KPTI; only
partial mitigations have shipped upstream.

## Why this is here

EntryBleed is **not a standalone LPE**. It's a **stage-1 leak
primitive** that future LPE modules can call when they need a kbase.
Bundling it as a module:

1. Lets other modules `#include "core/entrybleed.h"` and call
   `entrybleed_leak_kbase()` when they need KASLR defeat
2. Ships defensive detection rules for prefetchnta-timing-attack
   patterns (useful for hardened environments)
3. Documents the technique with a clear writeup so users
   understand what "stage-1" means in the broader chain

## Empirical status on recent kernels

Verified 2026-05-16: works 5/5 on lts-6.12.88 (no anti-EntryBleed
mitigation configured). See
`security-research/findings/audit_io_uring_2026-05-16_poc_attempt.md`
and the EntryBleed test code at
`SKYFALL/bugs/leak_write_modprobe_2026-05-16/exploit.c` lines ~73-150.

## Upstream patches

There is no single canonical patch. Partial mitigations include:
- `CONFIG_RANDOMIZE_KSTACK_OFFSET` (per-syscall kernel stack jitter)
- Some KPTI hardening discussions on lkml, no merged fix as of
  lts-6.12.88
- The community position remains that "KASLR is best-effort,
  not a security boundary"

## Implementation plan

- Lift the proven EntryBleed code from
  `SKYFALL/bugs/leak_write_modprobe_2026-05-16/exploit.c` into
  `module.c` here
- Expose as both a CLI mode (`iamroot --leak-kbase`) and as a
  library helper (`uint64_t entrybleed_leak_kbase(void)`)
- Detection rules: timing-attack pattern flags, perf-counter
  anomaly detection (informational — these are hard to make precise
  without false positives)

## Not started yet

Phase 3.
