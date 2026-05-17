# NOTICE — nft_fwd_dup (CVE-2022-25636)

## Vulnerability

**CVE-2022-25636** — `nft_fwd_dup_netdev_offload` writes
`flow->rule->action.entries[ctx->num_actions]` without bounds-checking
against the allocated array size → heap OOB write in kmalloc-512.

## Research credit

Discovered and disclosed by **Aaron Adams** (NCC Group),
February 2022.

Original writeup:
<https://research.nccgroup.com/2022/03/02/exploit-engineering-attacking-the-linux-kernel/>

Upstream fix: mainline 5.17 (commit `fa54fee62954`, Feb 2022).
Branch backports: 5.16.11 / 5.15.25 / 5.10.102 / 5.4.181.

## IAMROOT role

userns+netns reach. Hand-rolled nfnetlink batch: NEWTABLE →
NEWCHAIN with `NFT_CHAIN_HW_OFFLOAD` → NEWRULE with 16 immediates
+ fwd, overruning `action.entries[1]`. msg_msg cross-cache groom
into kmalloc-512 with `IAMROOT_FWD` tags.

`--full-chain` extends with stride-seeded forged action_entry
overwrite aimed at modprobe_path via the shared finisher.
