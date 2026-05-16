/*
 * entrybleed_cve_2023_0458 — IAMROOT module registry hook
 */

#ifndef ENTRYBLEED_IAMROOT_MODULES_H
#define ENTRYBLEED_IAMROOT_MODULES_H

#include "../../core/module.h"

extern const struct iamroot_module entrybleed_module;

/* Library entry point for other modules that need a kbase leak.
 * Returns the leaked kernel _text base on success, or 0 on failure
 * (x86_64 only; ARM and other arches return 0). The optional
 * `entry_syscall_slot_offset` is the offset from kbase to
 * entry_SYSCALL_64's 2MiB-aligned slot. Pass 0 for a kernel-default
 * (lts-6.12.x-style; ~0x5600000). */
unsigned long entrybleed_leak_kbase_lib(unsigned long entry_syscall_slot_offset);

#endif
