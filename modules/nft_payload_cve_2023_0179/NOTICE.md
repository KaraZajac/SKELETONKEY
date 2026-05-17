# NOTICE — nft_payload (CVE-2023-0179)

## Vulnerability

**CVE-2023-0179** — `nft_payload` set/get uses `regs->verdict.code`
as an index into `regs->data[]` without bounds-checking; combined
with the variable-length element extension trick (NFTA_SET_DESC
describing elements larger than the key/data slots), an attacker
walks regs off either end → OOB R/W on adjacent kernel memory.

## Research credit

Discovered and disclosed by **Davide Ornaghi**, January 2023.

Original slides + writeup:
<https://github.com/davide-romanini/CVE-2023-0179>
+ DEF CON 31 / SecurityFest 2023 presentations.

Upstream fix: mainline 6.2-rc4 (commit `696e1a48b1a1`, Jan 2023).
Branch backports: 4.14.302 / 4.19.269 / 5.4.229 / 5.10.163 /
5.15.88 / 6.1.6.

## SKELETONKEY role

userns+netns. Hand-rolled nfnetlink batch: NEWTABLE → NEWCHAIN →
NEWSET with `NFTA_SET_DESC` describing variable-length elements →
NEWSETELEM with `NFTA_SET_ELEM_EXPRESSIONS` carrying a payload-set
whose attacker-controlled `verdict.code` drives the OOB index.

Dual cg-96 + 1k msg_msg spray (covers both common adjacency
scenarios). `--full-chain` extends with kaddr-tagged refire aimed
at modprobe_path via the shared finisher.

Default OOB index `0x100` matches Ornaghi's PoC on a stock 5.15
build; the sentinel post-check correctly reports failure on builds
where regs->data adjacency differs.
