# NOTICE — nf_tables (CVE-2024-1086)

## Vulnerability

**CVE-2024-1086** — `nft_verdict_init` double-free → cross-cache UAF
→ arbitrary kernel R/W.

## Research credit

Discovered, exploited, and disclosed by **Notselwyn** (Pumpkin),
January 2024.

Original advisory + exploit: <https://pwning.tech/nftables/>
GitHub: <https://github.com/Notselwyn/CVE-2024-1086>

Upstream fix: mainline 6.8-rc1 (commit `f342de4e2f33`, Jan 2024).
Stable backports throughout Q1 2024.

## IAMROOT role

This module fires the malformed-verdict trigger (NFT_GOTO + NFT_DROP
in the same verdict) via a hand-rolled nfnetlink batch — no libmnl
dependency. The msg_msg cross-cache groom into kmalloc-cg-96 is wired
but the full pipapo R/W stage is opt-in via `--full-chain`, which
forges a pipapo_elem with a value-pointer pointing at modprobe_path.
Per-kernel offset assumptions are documented; the shared finisher's
sentinel arbitrates real vs. apparent success.
