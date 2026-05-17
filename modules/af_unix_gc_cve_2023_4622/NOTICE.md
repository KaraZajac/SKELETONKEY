# NOTICE — af_unix_gc (CVE-2023-4622)

## Vulnerability

**CVE-2023-4622** — AF_UNIX garbage-collector race against SCM_RIGHTS
fd-passing → `struct unix_sock` freed while still reachable → slab
UAF in `SLAB_TYPESAFE_BY_RCU` kmalloc-512 bucket.

## Research credit

Discovered and disclosed by **Lin Ma** (Zhejiang University),
August 2023.

Writeup: <https://github.com/google/security-research/security/advisories/GHSA-7p7m-3xv8-2pq2>
(disclosure record), plus Lin Ma's public PoC repo.

Upstream fix: mainline 6.6-rc1 (commit `0cabe18a8b80c`, Aug 2023).
Branch backports: 4.14.326 / 4.19.295 / 5.4.257 / 5.10.197 /
5.15.130 / 6.1.51 / 6.5.0.

## IAMROOT role

**Widest deployment of any module in the corpus** — bug present
in every Linux kernel below the fix (back to ~2.0 era).

Two-thread race driver: Thread A cycles SCM_RIGHTS fd-passing
through a socketpair; Thread B triggers unix_gc by closing a socket
in a reference cycle. msg_msg spray refills the freed slot.
CPU-pinned. Bounded budget: 5 s default, 30 s with `--full-chain`.

Bug is reachable as a **plain unprivileged user** — no userns
required, no CAP_* needed. Race-win rate per run is iteration-
dependent; Lin Ma's PoC reports thousands of iterations to first
reclaim. The shared finisher's sentinel timeout handles no-land
outcomes gracefully.
