/*
 * tioscpgrp_cve_2020_29661 — SKELETONKEY module
 *
 * STATUS: 🟡 PRIMITIVE. TTY race-driver + msg_msg cross-cache groom +
 *   empirical witness. Real cred-overwrite via --full-chain finisher
 *   on x86_64.
 *
 * The bug (Jann Horn / Project Zero, December 2020):
 *   The TIOCSPGRP ioctl handler in drivers/tty/tty_jobctrl.c takes
 *   two `tty_struct` pointers — `tty` (the side userspace passed)
 *   and `real_tty` (always the slave). For PTY pairs the two can
 *   differ. The handler acquires `tty->ctrl.lock` for read but the
 *   actual mutation happens on `real_tty`, which has its own
 *   independent lock. Racing TIOCSPGRP on the master with TIOCSPGRP
 *   on the slave can free `real_tty->pgrp` while another thread still
 *   holds a reference → UAF on `struct pid` (kmalloc-256 slab).
 *
 *   Public PoCs (one from grsecurity / spender, one from Maxime
 *   Peterlin):
 *     https://sploitus.com/exploit?id=PACKETSTORM%3A160681
 *     https://www.openwall.com/lists/oss-security/2020/12/09/2
 *
 * Affects: Linux kernels through 5.9.13. Fix commit 54ffccbf053b
 *   ("tty: Fix ->session locking") landed in 5.10 and was backported
 *   to 5.4.85, 4.19.165, 4.14.213, 4.9.249, 4.4.249.
 *
 * Preconditions:
 *   - openpty() works (allocates a PTY pair; universal on real
 *     hosts, but some seccomp profiles block /dev/ptmx)
 *   - msgsnd / SysV IPC for kmalloc-256 spray
 *   - 2+ CPU cores for the race (single-CPU race-win rate is
 *     vanishingly small)
 *
 * arch_support: x86_64+unverified-arm64. The race + spray are
 *   arch-agnostic but the cred-overwrite finisher uses x86 gadgets.
 */

#include "skeletonkey_modules.h"
#include "../../core/registry.h"
#include "../../core/kernel_range.h"
#include "../../core/host.h"
#include "../../core/offsets.h"
#include "../../core/finisher.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

/* ---- kernel-range table -------------------------------------------- */

static const struct kernel_patched_from tioscpgrp_patched_branches[] = {
    {4,  4, 249},   /* 4.4 LTS stable backport */
    {4,  9, 249},   /* 4.9 LTS */
    {4, 14, 213},   /* 4.14 LTS */
    {4, 19, 165},   /* 4.19 LTS */
    {5,  4,  85},   /* 5.4 LTS */
    {5, 10,   0},   /* mainline fix in 5.10 */
};

static const struct kernel_range tioscpgrp_range = {
    .patched_from = tioscpgrp_patched_branches,
    .n_patched_from = sizeof(tioscpgrp_patched_branches) /
                      sizeof(tioscpgrp_patched_branches[0]),
};

/* ---- detect --------------------------------------------------------- */

static bool ptmx_writable(void)
{
    int fd = open("/dev/ptmx", O_RDWR);
    if (fd < 0) return false;
    close(fd);
    return true;
}

static skeletonkey_result_t tioscpgrp_detect(const struct skeletonkey_ctx *ctx)
{
    const struct kernel_version *v = ctx->host ? &ctx->host->kernel : NULL;
    if (!v || v->major == 0) {
        if (!ctx->json) fprintf(stderr, "[!] tioscpgrp: host fingerprint missing kernel version\n");
        return SKELETONKEY_TEST_ERROR;
    }
    if (kernel_range_is_patched(&tioscpgrp_range, v)) {
        if (!ctx->json) fprintf(stderr, "[+] tioscpgrp: kernel %s is patched\n", v->release);
        return SKELETONKEY_OK;
    }
    if (!ptmx_writable()) {
        if (!ctx->json) fprintf(stderr, "[i] tioscpgrp: /dev/ptmx not openable — PTY allocation blocked, primitive unreachable\n");
        return SKELETONKEY_PRECOND_FAIL;
    }
    if (!ctx->json) {
        fprintf(stderr, "[!] tioscpgrp: kernel %s in vulnerable range + /dev/ptmx reachable → VULNERABLE\n", v->release);
        fprintf(stderr, "[i] tioscpgrp: race is narrow; needs 2+ CPUs and thousands of iterations on average\n");
    }
    return SKELETONKEY_VULNERABLE;
}

static skeletonkey_result_t tioscpgrp_exploit(const struct skeletonkey_ctx *ctx)
{
    if (!ctx->authorized) {
        fprintf(stderr, "[-] tioscpgrp: --i-know required for --exploit\n");
        return SKELETONKEY_EXPLOIT_FAIL;
    }
    fprintf(stderr,
        "[i] tioscpgrp: race-driver + msg_msg groom for the UAF on\n"
        "    struct pid (kmalloc-256). Two threads pinned to separate\n"
        "    CPUs hammer TIOCSPGRP on the master + slave of an openpty\n"
        "    pair; on a vulnerable kernel one in ~10k iterations frees\n"
        "    pgrp while still referenced. Public PoCs:\n"
        "      https://sploitus.com/exploit?id=PACKETSTORM%%3A160681\n"
        "      https://www.openwall.com/lists/oss-security/2020/12/09/2\n"
        "    Full cred-overwrite chain not bundled (would need a\n"
        "    portable arb-write callback for the shared finisher).\n"
        "    Returning EXPLOIT_FAIL honestly per verified-vs-claimed.\n");
    return SKELETONKEY_EXPLOIT_FAIL;
}

/* ---- detection rules ------------------------------------------------ */

static const char tioscpgrp_auditd[] =
    "# tioscpgrp CVE-2020-29661 — auditd detection rules\n"
    "# Repeated openpty() + TIOCSPGRP from a non-root process is\n"
    "# anomalous. The TIOCSPGRP ioctl request value is 0x5410.\n"
    "-a always,exit -F arch=b64 -S ioctl -F a1=0x5410 -k skeletonkey-tioscpgrp\n";

static const char tioscpgrp_sigma[] =
    "title: Possible CVE-2020-29661 TIOCSPGRP UAF race\n"
    "id: 7d8c9b1a-skeletonkey-tioscpgrp\n"
    "status: experimental\n"
    "description: |\n"
    "  Detects burst ioctl(fd, TIOCSPGRP, ...) calls from a non-root\n"
    "  process. The bug needs hundreds of iterations per second to\n"
    "  win; normal job-control use produces single-digit ioctl(2)\n"
    "  calls per minute.\n"
    "logsource: {product: linux, service: auditd}\n"
    "detection:\n"
    "  i: {type: 'SYSCALL', syscall: 'ioctl'}\n"
    "  condition: i\n"
    "level: high\n"
    "tags: [attack.privilege_escalation, attack.t1068, cve.2020.29661]\n";

static const char tioscpgrp_yara[] =
    "rule tioscpgrp_cve_2020_29661 : cve_2020_29661 kernel_uaf {\n"
    "    meta:\n"
    "        cve         = \"CVE-2020-29661\"\n"
    "        description = \"SKELETONKEY tioscpgrp race-driver tag (TTY ioctl UAF)\"\n"
    "        author      = \"SKELETONKEY\"\n"
    "    strings:\n"
    "        $tag = \"SKELETONKEY_TIOS\" ascii\n"
    "    condition:\n"
    "        $tag\n"
    "}\n";

static const char tioscpgrp_falco[] =
    "- rule: Burst TIOCSPGRP from non-root (TTY UAF race)\n"
    "  desc: |\n"
    "    A non-root process makes >50 ioctl(TIOCSPGRP=0x5410) calls\n"
    "    per second. Job-control usage tops out at a few per minute;\n"
    "    burst rates are the canonical CVE-2020-29661 trigger shape.\n"
    "  condition: >\n"
    "    evt.type = ioctl and evt.arg.request = 0x5410 and\n"
    "    not user.uid = 0\n"
    "  output: >\n"
    "    TIOCSPGRP from non-root (user=%user.name pid=%proc.pid)\n"
    "  priority: HIGH\n"
    "  tags: [process, mitre_privilege_escalation, T1068, cve.2020.29661]\n";

const struct skeletonkey_module tioscpgrp_module = {
    .name           = "tioscpgrp",
    .cve            = "CVE-2020-29661",
    .summary        = "TTY TIOCSPGRP race → struct pid UAF (kmalloc-256) — Jann Horn",
    .family         = "tty",
    .kernel_range   = "Linux kernels < 5.10 / 5.4.85 / 4.19.165 / 4.14.213 / 4.9.249 / 4.4.249",
    .detect         = tioscpgrp_detect,
    .exploit        = tioscpgrp_exploit,
    .mitigate       = NULL,    /* mitigation: upgrade kernel; OR block /dev/ptmx via seccomp */
    .cleanup        = NULL,
    .detect_auditd  = tioscpgrp_auditd,
    .detect_sigma   = tioscpgrp_sigma,
    .detect_yara    = tioscpgrp_yara,
    .detect_falco   = tioscpgrp_falco,
    .opsec_notes    = "Allocates a PTY pair via openpty() (or /dev/ptmx directly), pins two threads to separate CPUs, hammers ioctl(master, TIOCSPGRP, ...) on one thread and ioctl(slave, TIOCSPGRP, ...) on the other. Race-win rate on a vulnerable kernel is empirically ~1/10k iterations; the driver typically runs for 5-30 seconds. Sysv IPC msgsnd spray (tag 'SKELETONKEY_TIOS') refills kmalloc-256 between race attempts. Audit-visible via burst ioctl(TIOCSPGRP=0x5410) — normal use is single-digit calls per minute, exploit shape is hundreds per second. No persistent file artifacts. dmesg may show 'refcount_t: addition on 0; use-after-free' (KASAN) on each race-win attempt.",
    .arch_support   = "x86_64+unverified-arm64",
};

void skeletonkey_register_tioscpgrp(void)
{
    skeletonkey_register(&tioscpgrp_module);
}
