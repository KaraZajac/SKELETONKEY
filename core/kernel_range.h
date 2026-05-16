/*
 * IAMROOT — kernel version range matching
 *
 * Every CVE module needs to answer "is the host kernel in the affected
 * range?". This file centralizes that.
 *
 * The kernel version space is a tree of stable branches: 5.10.x,
 * 5.15.x, 5.16.x, ..., 6.6.x, 6.12.x, etc. A CVE is typically fixed
 * in mainline at some version, then backported into one or more
 * stable branches at branch-specific minor versions. A host with
 * 5.15.50 is patched if the fix was backported to 5.15.42, but a
 * host with 5.15.10 is still vulnerable.
 *
 * We model this with a list of "patched-from" entries per CVE: each
 * entry says "on branch X.Y, the fix is in versions >= X.Y.Z". The
 * host is patched if its branch matches one of these entries AND its
 * patch version is at or above the threshold.
 */

#ifndef IAMROOT_KERNEL_RANGE_H
#define IAMROOT_KERNEL_RANGE_H

#include <stdbool.h>
#include <stddef.h>

struct kernel_version {
    int major;
    int minor;
    int patch;
    /* Original /proc/version-style release string (e.g. "6.12.88-generic")
     * — for reporting; the comparison logic uses the parsed numerics. */
    const char *release;
};

/* Per-branch "patched-from" entry. To say "fix is in mainline 5.17",
 * use {5, 17, 0}. To say "fix backported to 5.15.25", use {5, 15, 25}. */
struct kernel_patched_from {
    int major;
    int minor;
    int patch;
};

struct kernel_range {
    /* List of branches that have the fix backported. If the host's
     * (major, minor) matches a branch AND host.patch >= branch.patch,
     * the host is patched. */
    const struct kernel_patched_from *patched_from;
    size_t n_patched_from;
};

/* Parse uname(2)->release / /proc/version into a kernel_version.
 * Returns true on success. Stores nothing in `out` on failure. */
bool kernel_version_current(struct kernel_version *out);

/* Returns true if a host running `v` is PATCHED according to `r`. */
bool kernel_range_is_patched(const struct kernel_range *r,
                             const struct kernel_version *v);

#endif /* IAMROOT_KERNEL_RANGE_H */
