# NOTICE — entrybleed

## Vulnerability

**CVE-2023-0458** — KPTI `prefetchnta` timing side-channel leaks the
kernel base address (KASLR bypass).

## Research credit

Discovered by **Will Findlay**. Formally presented at USENIX Security '23:

> "EntryBleed: A Universal KASLR Bypass against KPTI on Linux"
> Bert Jan Schijf, Cristiano Giuffrida — USENIX Security 2023

Mainline status: no canonical patch — partial mitigations only.

## IAMROOT role

This is a **stage-1 leak primitive**, not a standalone LPE. Other
modules can call `entrybleed_leak_kbase_lib()` to obtain a KASLR
slide and feed it to the offset resolver in `core/offsets.c`. x86_64
only; the `entry_SYSCALL_64` slot offset is configurable via the
`IAMROOT_ENTRYBLEED_OFFSET` env var.
