/*
 * IAMROOT — module registry
 *
 * Global list of registered modules. Each family contributes via
 * register_<family>_modules() called from iamroot main() at startup.
 */

#ifndef IAMROOT_REGISTRY_H
#define IAMROOT_REGISTRY_H

#include "module.h"

void iamroot_register(const struct iamroot_module *m);

size_t iamroot_module_count(void);
const struct iamroot_module *iamroot_module_at(size_t i);

/* Find a module by name. Returns NULL if not found. */
const struct iamroot_module *iamroot_module_find(const char *name);

/* Each module family declares one of these in its public header. The
 * top-level iamroot main() calls them in order at startup. */
void iamroot_register_copy_fail_family(void);
void iamroot_register_dirty_pipe(void);
void iamroot_register_entrybleed(void);
void iamroot_register_pwnkit(void);
void iamroot_register_nf_tables(void);
void iamroot_register_overlayfs(void);
void iamroot_register_cls_route4(void);
void iamroot_register_dirty_cow(void);
void iamroot_register_ptrace_traceme(void);
void iamroot_register_netfilter_xtcompat(void);
void iamroot_register_af_packet(void);
void iamroot_register_fuse_legacy(void);
void iamroot_register_stackrot(void);
void iamroot_register_af_packet2(void);

#endif /* IAMROOT_REGISTRY_H */
