/* sudo_samedit_cve_2021_3156 — STUB pending agent implementation. */
#include "skeletonkey_modules.h"
#include "../../core/registry.h"

static skeletonkey_result_t sudo_samedit_detect(const struct skeletonkey_ctx *ctx)
{ (void)ctx; return SKELETONKEY_PRECOND_FAIL; }

const struct skeletonkey_module sudo_samedit_module = {
    .name = "sudo_samedit",
    .cve = "CVE-2021-3156",
    .summary = "sudo Baron Samedit heap overflow (Qualys) — stub pending implementation",
    .family = "sudo",
    .kernel_range = "sudo 1.8.2 ≤ V ≤ 1.9.5p1 (userspace)",
    .detect = sudo_samedit_detect,
    .exploit = NULL, .mitigate = NULL, .cleanup = NULL,
    .detect_auditd = NULL, .detect_sigma = NULL,
    .detect_yara = NULL,   .detect_falco = NULL,
};

void skeletonkey_register_sudo_samedit(void) { skeletonkey_register(&sudo_samedit_module); }
