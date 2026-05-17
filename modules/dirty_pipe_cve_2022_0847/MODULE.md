# Dirty Pipe — CVE-2022-0847

> ⚪ **PLANNED** module. See [`../../ROADMAP.md`](../../ROADMAP.md)
> Phase 2.

## Summary

Pipe-buffer `PIPE_BUF_FLAG_CAN_MERGE` was incorrectly inherited by
`copy_page_to_iter_pipe()` and `push_pipe()` paths, allowing an
unprivileged user to write into the page cache of any file readable
by them.

## Affected kernels

- ≤ 5.16.11
- ≤ 5.15.25 LTS
- ≤ 5.10.102 LTS

## Upstream patch

`9d2231c5d74e13b2a0546fee6737ee4446017903` ("lib/iov_iter: initialize
"flags" in new pipe_buffer")

## Why this module is here

Even in 2026, many production deployments still run vulnerable
kernels (RHEL 7/8, older Ubuntu LTS, embedded). Bundling Dirty Pipe
makes SKELETONKEY useful as a "historical sweep" tool on long-tail
systems.

## Implementation plan

- C exploit ported from public PoCs (credit upstream authors in
  `NOTICE.md` when implemented)
- `detect()`: kernel version check + `/proc/version` parse + test
  for fixed-version backports
- `exploit()`: writes `skeletonkey::0:0:dirtypipe:/:/bin/bash` into
  `/etc/passwd`, then `su skeletonkey` — same shape as copy_fail's
  backdoor mode
- Detection rules: auditd on splice() calls + pipe write patterns,
  filesystem audit on `/etc/passwd` modification by non-root

## Not started yet

Pick this up after Phase 1 (module-interface refactor of the
copy_fail family) so this module can use the standard
`skeletonkey_module` shape from the start.
