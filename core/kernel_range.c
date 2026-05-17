/*
 * SKELETONKEY — kernel_range implementation
 */

#include "kernel_range.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>

static char g_release_buf[128];

bool kernel_version_current(struct kernel_version *out)
{
    if (out == NULL) return false;

    struct utsname u;
    if (uname(&u) < 0) return false;

    /* Stash release string for callers that want to print it. We hold
     * a single static buffer; not threadsafe but skeletonkey is single-
     * threaded today. */
    snprintf(g_release_buf, sizeof(g_release_buf), "%s", u.release);
    out->release = g_release_buf;

    out->major = 0; out->minor = 0; out->patch = 0;
    if (sscanf(u.release, "%d.%d.%d", &out->major, &out->minor, &out->patch) < 2)
        return false;
    return true;
}

bool kernel_range_is_patched(const struct kernel_range *r,
                             const struct kernel_version *v)
{
    if (r == NULL || v == NULL) return false;

    /* If the host's (major, minor) matches an entry AND its patch
     * level is at or above the entry's patch, host is patched. */
    for (size_t i = 0; i < r->n_patched_from; i++) {
        const struct kernel_patched_from *pf = &r->patched_from[i];
        if (v->major == pf->major && v->minor == pf->minor) {
            return v->patch >= pf->patch;
        }
    }

    /* If the host's (major, minor) is GREATER than every entry's
     * (major, minor), it's on a newer branch that has the fix
     * inherited from mainline — patched. */
    for (size_t i = 0; i < r->n_patched_from; i++) {
        const struct kernel_patched_from *pf = &r->patched_from[i];
        /* host strictly newer than this entry's branch */
        if (v->major > pf->major ||
            (v->major == pf->major && v->minor > pf->minor)) {
            /* keep checking — we want to be patched on ALL applicable
             * branches; if any entry is on the host's branch, that's
             * handled above. If we get here for every entry, host
             * is on a branch strictly newer than each — meaning the
             * mainline fix flowed in. */
            continue;
        } else {
            /* host is on a branch strictly older than this entry —
             * not patched via this entry, and no exact-branch match
             * applied above either → vulnerable. */
            return false;
        }
    }
    /* All entries are on branches at or below the host's — host has
     * the fix inherited via mainline progression. */
    return true;
}
