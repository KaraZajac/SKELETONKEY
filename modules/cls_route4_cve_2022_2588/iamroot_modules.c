/*
 * cls_route4_cve_2022_2588 — IAMROOT module
 *
 * net/sched cls_route4 dead UAF: when a route4 filter with handle==0
 * is removed, the corresponding hashtable bucket may keep a stale
 * pointer to the freed filter. Subsequent traffic-class lookup
 * follows the dangling pointer → kernel UAF.
 *
 * Discovered by kylebot / xkernel (Aug 2022). Mainline fix
 * 9efd23297cca "net_sched: cls_route: remove from list when handle
 * is 0" (Aug 2022). Bug existed since 2.6.39 — very wide
 * vulnerability surface.
 *
 * STATUS: 🔵 DETECT-ONLY. Public exploits exist; porting is
 * follow-up.
 *
 * Exploitation preconditions:
 *   - cls_route4 module compiled in / loadable (CONFIG_NET_CLS_ROUTE4)
 *   - CAP_NET_ADMIN (usually obtained via user_ns + map-root-to-uid)
 *   - unprivileged_userns_clone=1 if going the userns route
 *
 * Affected kernel ranges (vulnerable < these):
 *   5.4.x  : K < 5.4.213
 *   5.10.x : K < 5.10.143
 *   5.15.x : K < 5.15.69
 *   5.18.x : K < 5.18.18
 *   5.19.x : K < 5.19.7
 *   Mainline 5.20+ / 6.0+ : patched (the fix landed before 5.20-rc)
 */

#include "iamroot_modules.h"
#include "../../core/registry.h"
#include "../../core/kernel_range.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sched.h>
#include <sys/wait.h>

static const struct kernel_patched_from cls_route4_patched_branches[] = {
    {5,  4, 213},
    {5, 10, 143},
    {5, 15,  69},
    {5, 18,  18},
    {5, 19,   7},
    {5, 20,   0},   /* mainline */
};

static const struct kernel_range cls_route4_range = {
    .patched_from = cls_route4_patched_branches,
    .n_patched_from = sizeof(cls_route4_patched_branches) /
                      sizeof(cls_route4_patched_branches[0]),
};

static bool cls_route4_module_available(void)
{
    /* Check /proc/modules for currently-loaded cls_route4. Even when
     * not loaded, autoload may bring it in on first tc qdisc add — we
     * conservatively treat "not loaded now" as "potentially available". */
    FILE *f = fopen("/proc/modules", "r");
    if (!f) return false;
    char line[512];
    bool found = false;
    while (fgets(line, sizeof line, f)) {
        if (strncmp(line, "cls_route4 ", 11) == 0) { found = true; break; }
    }
    fclose(f);
    return found;
}

static int can_unshare_userns(void)
{
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        if (unshare(CLONE_NEWUSER | CLONE_NEWNET) == 0) _exit(0);
        _exit(1);
    }
    int status;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static iamroot_result_t cls_route4_detect(const struct iamroot_ctx *ctx)
{
    struct kernel_version v;
    if (!kernel_version_current(&v)) {
        fprintf(stderr, "[!] cls_route4: could not parse kernel version\n");
        return IAMROOT_TEST_ERROR;
    }

    /* Bug-introduction predates anything we'd reasonably scan; if the
     * kernel is below the oldest LTS we model (5.4), still report
     * vulnerable. */
    bool patched = kernel_range_is_patched(&cls_route4_range, &v);
    if (patched) {
        if (!ctx->json) {
            fprintf(stderr, "[+] cls_route4: kernel %s is patched\n", v.release);
        }
        return IAMROOT_OK;
    }

    /* Module + userns preconditions. */
    bool nft_loaded = cls_route4_module_available();
    int userns_ok = can_unshare_userns();

    if (!ctx->json) {
        fprintf(stderr, "[i] cls_route4: kernel %s in vulnerable range\n", v.release);
        fprintf(stderr, "[i] cls_route4: cls_route4 module currently loaded: %s\n",
                nft_loaded ? "yes" : "no (may autoload)");
        fprintf(stderr, "[i] cls_route4: unprivileged user_ns + net_ns clone: %s\n",
                userns_ok == 1 ? "ALLOWED" :
                userns_ok == 0 ? "DENIED" : "could not test");
    }

    /* If userns is locked down, unprivileged-LPE path is closed.
     * Kernel still needs patching though — report PRECOND_FAIL so the
     * verdict isn't "VULNERABLE" but the issue isn't masked. */
    if (userns_ok == 0) {
        if (!ctx->json) {
            fprintf(stderr, "[+] cls_route4: user_ns denied → unprivileged exploit unreachable\n");
        }
        return IAMROOT_PRECOND_FAIL;
    }

    if (!ctx->json) {
        fprintf(stderr, "[!] cls_route4: VULNERABLE — kernel in range AND user_ns allowed\n");
    }
    return IAMROOT_VULNERABLE;
}

static iamroot_result_t cls_route4_exploit(const struct iamroot_ctx *ctx)
{
    (void)ctx;
    fprintf(stderr,
        "[-] cls_route4: exploit not yet implemented in IAMROOT.\n"
        "    Status: 🔵 DETECT-ONLY. Reference: kylebot's public PoC.\n"
        "    Exploit: tc filter add ... route4 handle 0; then remove;\n"
        "    spray to refill the freed slot; trigger via traffic class\n"
        "    lookup; cred overwrite or modprobe_path hijack.\n");
    return IAMROOT_PRECOND_FAIL;
}

static const char cls_route4_auditd[] =
    "# cls_route4 dead UAF (CVE-2022-2588) — auditd detection rules\n"
    "# Flag tc filter operations with route4 classifier from non-root.\n"
    "# False positives: legitimate traffic-shaping setup. Tune by user.\n"
    "-a always,exit -F arch=b64 -S sendto -F a3=0x10 -k iamroot-cls-route4\n";

const struct iamroot_module cls_route4_module = {
    .name           = "cls_route4",
    .cve            = "CVE-2022-2588",
    .summary        = "net/sched cls_route4 handle-zero dead UAF → kernel R/W",
    .family         = "cls_route4",
    .kernel_range   = "2.6.39 ≤ K, fixed mainline 5.20; backports: 5.4.213 / 5.10.143 / 5.15.69 / 5.18.18 / 5.19.7",
    .detect         = cls_route4_detect,
    .exploit        = cls_route4_exploit,
    .mitigate       = NULL,    /* mitigation: blacklist cls_route4 module OR disable user_ns */
    .cleanup        = NULL,
    .detect_auditd  = cls_route4_auditd,
    .detect_sigma   = NULL,
    .detect_yara    = NULL,
    .detect_falco   = NULL,
};

void iamroot_register_cls_route4(void)
{
    iamroot_register(&cls_route4_module);
}
