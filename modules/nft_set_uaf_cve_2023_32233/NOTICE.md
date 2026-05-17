# NOTICE — nft_set_uaf (CVE-2023-32233)

## Vulnerability

**CVE-2023-32233** — nf_tables anonymous-set deactivation skip →
slab UAF on the freed `nft_set` object exploitable via msg_msg
cross-cache groom in kmalloc-cg-512.

## Research credit

Discovered and disclosed by **Patryk Sondej** and **Piotr Krysiuk**,
May 2023.

Original advisory + writeup distributed via the OSS-Security list
and an accompanying Google Drive PoC.
Follow-up exploit and Crusaders-of-Rust analysis built on the
public trigger.

Upstream fix: mainline 6.4-rc4 (commit `c1592a89942e9`, May 2023).
Branch backports: 6.3.2 / 6.2.15 / 6.1.28 / 5.15.111 / 5.10.180 /
5.4.243 / 4.19.283.

## SKELETONKEY role

Hand-rolled nfnetlink batch: NEWTABLE → NEWCHAIN (base, LOCAL_OUT
hook) → NEWSET (ANON|EVAL|CONSTANT) → NEWRULE (nft_lookup
referencing the set by `NFTA_LOOKUP_SET_ID`) → DELSET → DELRULE
in the same transaction. msg_msg cg-512 spray with `SKELETONKEY_SET`
tags.

`--full-chain` forges a freed-set with `set->data = kaddr` at the
Sondej/Krysiuk reference offset (0x30) and drives a NEWSETELEM with
the modprobe_path payload bytes via the shared finisher.
