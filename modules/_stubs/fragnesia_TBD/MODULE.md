# Fragnesia — CVE pending

> ⚪ **PLANNED** stub. See [`../../ROADMAP.md`](../../ROADMAP.md)
> Phase 7+.

## Summary

ESP shared-frag in-place encrypt path can be coerced into writing
into the page cache of an unrelated file. Same primitive shape as
Dirty Frag, different reach.

## Status

Audit-stage. See
`security-research/findings/audit_leak_write_modprobe_backups_2026-05-16.md`
section on backup primitives. Notably: trigger appears to require
CAP_NET_ADMIN inside a userns netns. On kCTF (shared net_ns) that's
cap-dead, but on host systems where user_ns clone is enabled it's
reachable.

## Decision needed before implementing

Is the unprivileged-userns-netns scenario in scope for SKELETONKEY? If
yes, this module ships. If we restrict to "default Linux user
account, no namespace tricks," this module is out of scope.

## Not started.
