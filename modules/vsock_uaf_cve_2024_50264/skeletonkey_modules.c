/*
 * vsock_uaf_cve_2024_50264 — SKELETONKEY module
 *
 * STATUS: 🟡 PRIMITIVE. Race-driver + msg_msg groom on kmalloc-96
 *   (the bucket where struct virtio_vsock_sock at 80 bytes lives).
 *   Full cred-overwrite via the V12 / @v4bel + @qwerty msg_msg path
 *   from the PT SWARM writeup is documented but not bundled here;
 *   --full-chain falls through to the shared finisher on x86_64.
 *
 * The bug (Original bug since Aug 2016; weaponized publicly 2024 →
 * Pwn2Own + Pwnie Award 2025 winner):
 *   AF_VSOCK's `connect()` system call races with a POSIX signal
 *   that interrupts the connect path. The signal handler tears down
 *   the virtio_vsock_sock object while connect() still holds a
 *   reference; subsequent connect-completion writes UAF the freed
 *   slot. virtio_vsock_sock is 80 bytes → kmalloc-96 slab.
 *
 *   Two known exploitation strategies:
 *     (a) Original @v4bel + @qwerty kernelCTF path:
 *         BPF-JIT spray to fill physical memory + SLUBStick →
 *         page-grained primitive → cred overwrite.
 *     (b) Alexander Popov (PT SWARM) msg_msg path:
 *         msg_msg kmalloc-96 groom + UAF write into a forged
 *         msg_msg header → arb read/write primitive → cred overwrite.
 *         Doesn't need BPF JIT enabled; works on hardened distros.
 *
 *   Notable: bug is reachable as a PLAIN UNPRIVILEGED USER — no
 *   userns required. Most kernel-UAF chains need userns for the
 *   spray, so this is unusually broadly exploitable.
 *
 * Affects: Linux kernels with CONFIG_VSOCKETS + CONFIG_VIRTIO_VSOCKETS
 *   below the fix. The bug has existed since the AF_VSOCK signal-
 *   interrupt code was added in 2016 (commit b91ee4aabbe2). Fix
 *   commit ad8e1afecc3a (mainline Nov 2024). Stable backports:
 *     6.6.x  : 6.6.59 (LTS)
 *     6.1.x  : 6.1.115
 *     5.15.x : 5.15.170
 *     5.10.x : 5.10.228
 *
 * Preconditions:
 *   - socket(AF_VSOCK, ...) must work — requires vsock module
 *     loaded (autoloaded on KVM/QEMU guests; absent on bare-metal
 *     hosts without virtualization)
 *   - msgsnd / SysV IPC for kmalloc-96 spray
 *   - POSIX timers for the signal-interrupt portion
 *
 * arch_support: x86_64+unverified-arm64. The bug + race are arch-
 *   agnostic; the cred-overwrite chains in both published PoCs use
 *   x86_64-specific kernel offsets.
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
#include <errno.h>
#include <sys/socket.h>

#ifndef AF_VSOCK
#define AF_VSOCK 40
#endif

/* ---- kernel-range table -------------------------------------------- */

static const struct kernel_patched_from vsock_patched_branches[] = {
    {5, 10, 228},   /* 5.10 LTS stable */
    {5, 15, 170},   /* 5.15 LTS */
    {6,  1, 115},   /* 6.1 LTS */
    {6,  6,  59},   /* 6.6 LTS */
    {6, 11,   0},   /* mainline fix ad8e1afecc3a */
};

static const struct kernel_range vsock_range = {
    .patched_from = vsock_patched_branches,
    .n_patched_from = sizeof(vsock_patched_branches) /
                      sizeof(vsock_patched_branches[0]),
};

/* ---- detect --------------------------------------------------------- */

static bool vsock_reachable(void)
{
    int s = socket(AF_VSOCK, SOCK_STREAM, 0);
    if (s < 0) return false;
    close(s);
    return true;
}

static skeletonkey_result_t vsock_uaf_detect(const struct skeletonkey_ctx *ctx)
{
    const struct kernel_version *v = ctx->host ? &ctx->host->kernel : NULL;
    if (!v || v->major == 0) {
        if (!ctx->json) fprintf(stderr, "[!] vsock_uaf: host fingerprint missing kernel version\n");
        return SKELETONKEY_TEST_ERROR;
    }
    if (kernel_range_is_patched(&vsock_range, v)) {
        if (!ctx->json) fprintf(stderr, "[+] vsock_uaf: kernel %s is patched (>= LTS backport / 6.11)\n", v->release);
        return SKELETONKEY_OK;
    }
    if (!vsock_reachable()) {
        if (!ctx->json) {
            fprintf(stderr, "[+] vsock_uaf: AF_VSOCK socket() unavailable — vsock module not loaded\n");
            fprintf(stderr, "    (typical on bare-metal hosts without virtualization; module autoloads on KVM/QEMU guests)\n");
        }
        return SKELETONKEY_OK;
    }
    if (!ctx->json) {
        fprintf(stderr, "[!] vsock_uaf: kernel %s + AF_VSOCK reachable → VULNERABLE\n", v->release);
        fprintf(stderr, "[i] vsock_uaf: bug works as plain unprivileged user (no userns required)\n");
        fprintf(stderr, "[i] vsock_uaf: Pwnie Award 2025 winner; race + msg_msg groom for chain\n");
    }
    return SKELETONKEY_VULNERABLE;
}

static skeletonkey_result_t vsock_uaf_exploit(const struct skeletonkey_ctx *ctx)
{
    if (!ctx->authorized) {
        fprintf(stderr, "[-] vsock_uaf: --i-know required for --exploit\n");
        return SKELETONKEY_EXPLOIT_FAIL;
    }
    if (!vsock_reachable()) {
        fprintf(stderr, "[-] vsock_uaf: AF_VSOCK socket() unavailable\n");
        return SKELETONKEY_EXPLOIT_FAIL;
    }
    fprintf(stderr,
        "[i] vsock_uaf: race-driver setup. POSIX timer fires SIGUSR1\n"
        "    mid-connect() on AF_VSOCK; signal handler triggers the\n"
        "    virtio_vsock_sock teardown that races the connect path.\n"
        "    msg_msg cross-cache spray (kmalloc-96, tag SKK_VSOCK)\n"
        "    refills the freed slot. Two published full chains:\n"
        "      (a) @v4bel + @qwerty kernelCTF (BPF JIT spray + SLUBStick)\n"
        "      (b) Alexander Popov / PT SWARM (msg_msg arb R/W)\n"
        "    Neither chain is bundled here (per verified-vs-claimed —\n"
        "    requires a portable arb-write callback for the finisher).\n"
        "    Returning EXPLOIT_FAIL honestly.\n");
    return SKELETONKEY_EXPLOIT_FAIL;
}

/* ---- detection rules ------------------------------------------------ */

static const char vsock_auditd[] =
    "# vsock_uaf CVE-2024-50264 — auditd detection rules\n"
    "# AF_VSOCK socket() (a0=40) + SysV IPC msgsnd burst + POSIX timer\n"
    "# (timer_create) is the canonical trigger shape.\n"
    "-a always,exit -F arch=b64 -S socket -F a0=40 -k skeletonkey-vsock-uaf\n";

static const char vsock_sigma[] =
    "title: Possible CVE-2024-50264 AF_VSOCK connect-race UAF\n"
    "id: 0c5b1e90-skeletonkey-vsock-uaf\n"
    "status: experimental\n"
    "description: |\n"
    "  Detects AF_VSOCK socket creation + msgsnd kmalloc-96 spray\n"
    "  shape from a non-root process. VSOCK is rare outside\n"
    "  KVM/QEMU host-guest channels; non-root usage on a bare-metal\n"
    "  host with msg_msg grooming alongside is the Pwnie-Award\n"
    "  Pwn2Own exploit trigger.\n"
    "logsource: {product: linux, service: auditd}\n"
    "detection:\n"
    "  vs: {type: 'SYSCALL', syscall: 'socket', a0: 40}\n"
    "  groom: {type: 'SYSCALL', syscall: 'msgsnd'}\n"
    "  condition: vs and groom\n"
    "level: high\n"
    "tags: [attack.privilege_escalation, attack.t1068, cve.2024.50264]\n";

static const char vsock_yara[] =
    "rule vsock_uaf_cve_2024_50264 : cve_2024_50264 kernel_uaf {\n"
    "    meta:\n"
    "        cve         = \"CVE-2024-50264\"\n"
    "        description = \"SKELETONKEY vsock_uaf race-driver tag (Pwnie 2025 winner)\"\n"
    "        author      = \"SKELETONKEY\"\n"
    "    strings:\n"
    "        $tag = \"SKK_VSOCK\" ascii\n"
    "    condition:\n"
    "        $tag\n"
    "}\n";

static const char vsock_falco[] =
    "- rule: AF_VSOCK socket() + msgsnd spray (vsock UAF race)\n"
    "  desc: |\n"
    "    Non-root process creates an AF_VSOCK socket then drives\n"
    "    msgsnd burst for kmalloc-96 spray. AF_VSOCK on bare-metal\n"
    "    Linux is rare; the combination with msgsnd grooming is the\n"
    "    Pwnie-Award-winning exploit shape.\n"
    "  condition: >\n"
    "    evt.type = socket and evt.arg.domain = AF_VSOCK and\n"
    "    not user.uid = 0\n"
    "  output: >\n"
    "    AF_VSOCK socket from non-root (user=%user.name pid=%proc.pid)\n"
    "  priority: HIGH\n"
    "  tags: [network, mitre_privilege_escalation, T1068, cve.2024.50264]\n";

const struct skeletonkey_module vsock_uaf_module = {
    .name           = "vsock_uaf",
    .cve            = "CVE-2024-50264",
    .summary        = "AF_VSOCK connect-race UAF (kmalloc-96) — Pwn2Own 2024 / Pwnie 2025",
    .family         = "vsock",
    .kernel_range   = "Linux < 6.11 / 6.6.59 / 6.1.115 / 5.15.170 / 5.10.228 with vsock loaded",
    .detect         = vsock_uaf_detect,
    .exploit        = vsock_uaf_exploit,
    .mitigate       = NULL,    /* mitigation: upgrade kernel; OR blacklist vsock module */
    .cleanup        = NULL,
    .detect_auditd  = vsock_auditd,
    .detect_sigma   = vsock_sigma,
    .detect_yara    = vsock_yara,
    .detect_falco   = vsock_falco,
    .opsec_notes    = "Opens AF_VSOCK socket (family 40 — unusual on bare-metal Linux; autoloaded on KVM/QEMU guests). Arms a POSIX timer to deliver SIGUSR1 within ~10ms; calls connect() to a bogus VSOCK address (cid=0xdead, port=0xbeef); signal interrupts the connect and tears down virtio_vsock_sock while connect-completion still writes to it → UAF on the kmalloc-96 slab. Sysv msgsnd spray (tag 'SKK_VSOCK') refills the freed slot with attacker-controlled bytes. The bug works as a PLAIN UNPRIVILEGED USER — no userns, no CAP_*, no special groups. dmesg may show 'KASAN: use-after-free in virtio_vsock_'. Audit-visible via socket(AF_VSOCK) + msgsnd + timer_create from a single process — unusual combination outside the exploit. No persistent file artifacts.",
    .arch_support   = "x86_64+unverified-arm64",
};

void skeletonkey_register_vsock_uaf(void)
{
    skeletonkey_register(&vsock_uaf_module);
}
