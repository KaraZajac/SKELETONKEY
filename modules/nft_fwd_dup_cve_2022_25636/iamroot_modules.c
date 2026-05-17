/* nft_fwd_dup_cve_2022_25636 — STUB pending agent implementation. */
#include "iamroot_modules.h"
#include "../../core/registry.h"

static iamroot_result_t nft_fwd_dup_detect(const struct iamroot_ctx *ctx)
{
    (void)ctx;
    return IAMROOT_PRECOND_FAIL;
}

const struct iamroot_module nft_fwd_dup_module = {
    .name = "nft_fwd_dup",
    .cve = "CVE-2022-25636",
    .summary = "nft_fwd_dup_netdev_offload heap OOB (Aaron Adams) — stub pending implementation",
    .family = "nf_tables",
    .kernel_range = "5.4 ≤ K < 5.18",
    .detect = nft_fwd_dup_detect,
    .exploit = NULL, .mitigate = NULL, .cleanup = NULL,
    .detect_auditd = NULL, .detect_sigma = NULL,
    .detect_yara = NULL,   .detect_falco = NULL,
};

void iamroot_register_nft_fwd_dup(void) { iamroot_register(&nft_fwd_dup_module); }
