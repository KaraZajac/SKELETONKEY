/*
 * SKELETONKEY — module registry
 *
 * Global list of registered modules. Each family contributes via
 * register_<family>_modules() called from skeletonkey main() at startup.
 */

#ifndef SKELETONKEY_REGISTRY_H
#define SKELETONKEY_REGISTRY_H

#include "module.h"

void skeletonkey_register(const struct skeletonkey_module *m);

size_t skeletonkey_module_count(void);
const struct skeletonkey_module *skeletonkey_module_at(size_t i);

/* Find a module by name. Returns NULL if not found. */
const struct skeletonkey_module *skeletonkey_module_find(const char *name);

/* Each module family declares one of these in its public header. The
 * top-level skeletonkey main() calls them in order at startup. */
void skeletonkey_register_copy_fail_family(void);
void skeletonkey_register_dirty_pipe(void);
void skeletonkey_register_entrybleed(void);
void skeletonkey_register_pwnkit(void);
void skeletonkey_register_nf_tables(void);
void skeletonkey_register_overlayfs(void);
void skeletonkey_register_cls_route4(void);
void skeletonkey_register_dirty_cow(void);
void skeletonkey_register_ptrace_traceme(void);
void skeletonkey_register_netfilter_xtcompat(void);
void skeletonkey_register_af_packet(void);
void skeletonkey_register_fuse_legacy(void);
void skeletonkey_register_stackrot(void);
void skeletonkey_register_af_packet2(void);
void skeletonkey_register_cgroup_release_agent(void);
void skeletonkey_register_overlayfs_setuid(void);
void skeletonkey_register_nft_set_uaf(void);
void skeletonkey_register_af_unix_gc(void);
void skeletonkey_register_nft_fwd_dup(void);
void skeletonkey_register_nft_payload(void);
void skeletonkey_register_sudo_samedit(void);
void skeletonkey_register_sequoia(void);
void skeletonkey_register_sudoedit_editor(void);
void skeletonkey_register_vmwgfx(void);
void skeletonkey_register_dirtydecrypt(void);
void skeletonkey_register_fragnesia(void);
void skeletonkey_register_pack2theroot(void);

#endif /* SKELETONKEY_REGISTRY_H */
