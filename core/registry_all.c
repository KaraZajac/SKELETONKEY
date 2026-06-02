/*
 * SKELETONKEY — canonical "register every module family" enumeration.
 *
 * Kept in its own translation unit so registry.c stays standalone:
 * the kernel_range unit-test binary links registry.c (for the basic
 * register / count / find API) without pulling in every module's
 * symbol. The main binary and detect-integration test link this
 * file too and get the full lineup.
 *
 * Adding a new module is one new register_<family>() declaration in
 * registry.h plus one call below — the integration test picks it up
 * via skeletonkey_register_all_modules() in its main().
 */

#include "registry.h"

void skeletonkey_register_all_modules(void)
{
    skeletonkey_register_copy_fail_family();
    skeletonkey_register_dirty_pipe();
    skeletonkey_register_entrybleed();
    skeletonkey_register_pwnkit();
    skeletonkey_register_nf_tables();
    skeletonkey_register_overlayfs();
    skeletonkey_register_cls_route4();
    skeletonkey_register_dirty_cow();
    skeletonkey_register_ptrace_traceme();
    skeletonkey_register_netfilter_xtcompat();
    skeletonkey_register_af_packet();
    skeletonkey_register_fuse_legacy();
    skeletonkey_register_stackrot();
    skeletonkey_register_af_packet2();
    skeletonkey_register_cgroup_release_agent();
    skeletonkey_register_overlayfs_setuid();
    skeletonkey_register_nft_set_uaf();
    skeletonkey_register_af_unix_gc();
    skeletonkey_register_nft_fwd_dup();
    skeletonkey_register_nft_payload();
    skeletonkey_register_sudo_samedit();
    skeletonkey_register_sequoia();
    skeletonkey_register_sudoedit_editor();
    skeletonkey_register_vmwgfx();
    skeletonkey_register_dirtydecrypt();
    skeletonkey_register_fragnesia();
    skeletonkey_register_pack2theroot();
    skeletonkey_register_sudo_chwoot();
    skeletonkey_register_udisks_libblockdev();
    skeletonkey_register_pintheft();
    skeletonkey_register_mutagen_astronomy();
    skeletonkey_register_sudo_runas_neg1();
    skeletonkey_register_tioscpgrp();
    skeletonkey_register_vsock_uaf();
    skeletonkey_register_nft_pipapo();
    skeletonkey_register_ptrace_pidfd();
    skeletonkey_register_sudo_host();
}
