# NOTICE — af_packet2 (CVE-2020-14386)

## Vulnerability

**CVE-2020-14386** — AF_PACKET `tpacket_rcv` VLAN integer underflow
(`maclen = skb_network_offset(skb)` when network header precedes
maclen) → 8-byte heap OOB write at the start of the next slab object.

## Research credit

Discovered and disclosed by **Or Cohen** (Palo Alto Networks),
September 2020.

Original advisory: <https://unit42.paloaltonetworks.com/cve-2020-14386/>

Upstream fix: mainline 5.9 / stable 5.8.7 (Sept 2020).
Branch backports: 5.8.7 / 5.7.16 / 5.4.62 / 4.19.143 / 4.14.197 / 4.9.235.

## SKELETONKEY role

Sibling of CVE-2017-7308; same subsystem, different code path.
Fires the underflow via `tp_reserve` + sendmmsg sk_buff spray.
PRIMITIVE-DEMO scope by default (no cred overwrite). `--full-chain`
attempts the Or-Cohen-style sk_buff data-pointer hijack through
the shared finisher.

Shares the `skeletonkey-af-packet` auditd key with the CVE-2017-7308
module so detection signatures dedupe cleanly.
