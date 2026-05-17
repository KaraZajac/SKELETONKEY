# NOTICE — netfilter_xtcompat (CVE-2021-22555)

## Vulnerability

**CVE-2021-22555** — iptables `xt_compat_target_to_user` 4-byte heap
out-of-bounds write → cross-cache UAF → arbitrary kernel R/W.

## Research credit

Discovered, exploited, and disclosed by **Andy Nguyen** (Google
Security Team), April 2021.

Original writeup: "CVE-2021-22555: Turning $00 $00 into 10 million $$$"
<https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html>

Upstream fix: mainline 5.12 / 5.11.10 (April 2021).
**Bug existed since 2.6.19 (2006) — 15 years of latent vulnerability.**
Branch backports: 5.11.10 / 5.10.27 / 5.4.110 / 4.19.185 / 4.14.230 /
4.9.266 / 4.4.266.

## IAMROOT role

Userns+netns reach, hand-rolled `ipt_replace` blob, `setsockopt`
`IPT_SO_SET_REPLACE` fires the 4-byte OOB at heap+0x4. msg_msg
spray in kmalloc-2k + sk_buff sidecar; MSG_COPY scan for cross-cache
landing. `--full-chain` extends with stride-seeded `m_list_next`
overwrite aimed at modprobe_path via the shared finisher.

Detection rules cover unshare + msgsnd + `setsockopt(IPT_SO_SET_REPLACE)`.
