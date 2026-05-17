# NOTICE — stackrot (CVE-2023-3269)

## Vulnerability

**CVE-2023-3269** — Maple-tree VMA-split UAF (race between mremap and
fork+fault) → kernel R/W via stale anon_vma_chain reference.

## Research credit

Discovered and disclosed by **Ruihan Li** (Peking University),
July 2023.

Original advisory: <https://github.com/lrh2000/StackRot>
Writeup: <https://lkmidas.github.io/posts/20230724-stackrot/>

Upstream fix: mainline 6.5-rc1 (commit `0503ea8f5ba73`, July 2023).
Branch backports: 6.4.4 / 6.3.13 / 6.1.37.

## IAMROOT role

Two-thread race driver (Thread A: mremap rotation on MAP_GROWSDOWN
anchored VMA; Thread B: fork+fault) with cpu pinning. kmalloc-192
spray for anon_vma_chain reclaim. Bounded budget: 3 s default,
30 s with `--full-chain`.

**Honest reliability assessment:** ~<1% race-win per run on a
vulnerable kernel. Ruihan Li's public PoC averages minutes-to-hours
and needs a much wider VMA-staging matrix to be reliable. The
shared finisher's 3 s sentinel timeout handles the overwhelmingly
common no-land outcome gracefully — module returns EXPLOIT_FAIL
honestly rather than claim root on a race that didn't win.
