# NOTICE — af_packet (CVE-2017-7308)

## Vulnerability

**CVE-2017-7308** — AF_PACKET TPACKET_V3 integer overflow in
`tp_block_size * tp_block_nr` → heap write-where via sendmmsg spray.

## Research credit

Discovered by **Andrey Konovalov** (Google), March 2017. A research-era
classic — Konovalov found multiple AF_PACKET bugs in this campaign.

Original advisory + writeup:
<https://googleprojectzero.blogspot.com/2017/05/exploiting-linux-kernel-via-packet.html>

Upstream fix: mainline 4.11 / stable 4.10.6 (March 2017).
Branch backports: 4.10.6 / 4.9.18 / 4.4.57 / 3.18.49.

## IAMROOT role

x86_64-only. Userns gives CAP_NET_RAW; `socket(AF_PACKET, SOCK_RAW)`
+ TPACKET_V3 with overflowing tp_block_size triggers the integer
overflow + heap spray via 200 raw skbs on lo. Best-effort cred-race
finisher (64 child workers polling geteuid). Offset table covers
Ubuntu 16.04/4.4 and 18.04/4.15; other kernels via the
`IAMROOT_AFPACKET_OFFSETS` env var.

`--full-chain` engages the shared modprobe_path finisher with
stride-seeded sk_buff data-pointer overwrite.
