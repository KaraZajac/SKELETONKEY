# NOTICE — cls_route4 (CVE-2022-2588)

## Vulnerability

**CVE-2022-2588** — `net/sched` cls_route4 handle-zero dangling-filter
UAF → kernel R/W via msg_msg cross-cache refill.

## Research credit

Discovered and disclosed by **kylebot** / **xkernel**, August 2022.

Public PoC + writeup: <https://www.willsroot.io/2022/08/lpe-on-mountpoint.html>
(William Liu's analysis built on kylebot's trigger).

Upstream fix: mainline 5.20 / stable 5.19.7 (Aug 2022).
Branch backports: 5.4.213 / 5.10.143 / 5.15.69 / 5.18.18 / 5.19.7.

## IAMROOT role

The module uses `unshare(USER|NET)`, brings up a dummy interface,
creates an htb qdisc + class, adds a `route4` filter, then deletes
it to leave the dangling pointer. msg_msg sprays kmalloc-1k while
a UDP `classify()` walk follows the dangling pointer. `--full-chain`
re-fires with a faked tcf_proto.ops pointer aimed at the
modprobe_path overwrite via the shared finisher.
