# NOTICE — dirty_pipe

## Vulnerability

**CVE-2022-0847** — pipe `PIPE_BUF_FLAG_CAN_MERGE` flag inheritance allows
arbitrary file write into the page cache.

## Research credit

Discovered and disclosed by **Max Kellermann** (CM4all GmbH), March 2022.

Original advisory: <https://dirtypipe.cm4all.com/>

Upstream fix: mainline 5.17 (commit `9d2231c5d74e`, Feb 2022).

## IAMROOT role

This module bundles the canonical splice-into-pipe primitive that
writes UID=0 into `/etc/passwd`'s page cache, then drops a root shell
via `su`. Detection covers the splice() syscall against sensitive
files and non-root modifications to passwd/shadow.
