/*
 * copy_fail_family — IAMROOT module registry hooks
 *
 * The family currently contains five iamroot_module entries:
 *
 *   - copy_fail        (CVE-2026-31431, algif_aead authencesn)
 *   - copy_fail_gcm    (no CVE, rfc4106(gcm(aes)) variant)
 *   - dirty_frag_esp   (CVE-2026-43284 v4)
 *   - dirty_frag_esp6  (CVE-2026-43284 v6)
 *   - dirty_frag_rxrpc (CVE-2026-43500)
 *
 * Defined in iamroot_modules.c, registered into the global registry
 * by iamroot_register_copy_fail_family() (declared in
 * core/registry.h).
 */

#ifndef COPY_FAIL_FAMILY_IAMROOT_MODULES_H
#define COPY_FAIL_FAMILY_IAMROOT_MODULES_H

#include "../../core/module.h"

extern const struct iamroot_module copy_fail_module;
extern const struct iamroot_module copy_fail_gcm_module;
extern const struct iamroot_module dirty_frag_esp_module;
extern const struct iamroot_module dirty_frag_esp6_module;
extern const struct iamroot_module dirty_frag_rxrpc_module;

#endif
