/*
 * tests/test_kernel_range.c — unit tests for the central kernel
 * version-comparison helpers in core/kernel_range.c and core/host.c.
 *
 * These helpers are the foundation of the host-fingerprint pattern:
 * every module that gates on kernel version routes through
 * skeletonkey_host_kernel_at_least(),
 * skeletonkey_host_kernel_in_range(), or kernel_range_is_patched().
 * A regression in any of them silently mis-classifies entire CVE
 * families. The detect() integration tests in test_detect.c exercise
 * these indirectly via real modules; this file pins them down with
 * direct boundary-condition assertions so failures point at the right
 * file.
 *
 * Cross-platform: pure logic, no Linux syscalls. Runs identically on
 * macOS dev builds and Linux CI.
 */

#include "../core/kernel_range.h"
#include "../core/host.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_pass = 0;
static int g_fail = 0;

#define EXPECT(name, cond) do {                                         \
	if (cond) {                                                     \
		printf("[+] PASS  %s\n", (name));                       \
		g_pass++;                                               \
	} else {                                                        \
		fprintf(stderr, "[-] FAIL  %s\n", (name));              \
		g_fail++;                                               \
	}                                                               \
} while (0)

/* ── kernel_range_is_patched ────────────────────────────────────────── */

static void test_kernel_range_is_patched(void)
{
	/* Common single-branch-plus-mainline table: backport on 5.15.42,
	 * mainline fix at 5.17.0. */
	static const struct kernel_patched_from pf_5_15_5_17[] = {
		{5, 15, 42},
		{5, 17,  0},
	};
	const struct kernel_range r1 = { pf_5_15_5_17, 2 };

	struct kernel_version v;

	v = (struct kernel_version){5, 15, 42, NULL};
	EXPECT("range: exact backport boundary (5.15.42) → patched",
	       kernel_range_is_patched(&r1, &v));

	v = (struct kernel_version){5, 15, 41, NULL};
	EXPECT("range: one below backport (5.15.41) → vulnerable",
	       !kernel_range_is_patched(&r1, &v));

	v = (struct kernel_version){5, 15, 100, NULL};
	EXPECT("range: well above backport on same branch (5.15.100) → patched",
	       kernel_range_is_patched(&r1, &v));

	v = (struct kernel_version){5, 17, 0, NULL};
	EXPECT("range: mainline fix exact (5.17.0) → patched",
	       kernel_range_is_patched(&r1, &v));

	v = (struct kernel_version){5, 16, 0, NULL};
	EXPECT("range: between branches (5.16.0) → vulnerable",
	       !kernel_range_is_patched(&r1, &v));

	v = (struct kernel_version){5, 14, 999, NULL};
	EXPECT("range: branch below all entries (5.14.999) → vulnerable",
	       !kernel_range_is_patched(&r1, &v));

	v = (struct kernel_version){6, 12, 0, NULL};
	EXPECT("range: newer mainline branch (6.12.0) → patched via inheritance",
	       kernel_range_is_patched(&r1, &v));

	/* Mainline-only entry — common pattern for a fresh CVE with no
	 * stable backports yet. */
	static const struct kernel_patched_from pf_7_0_only[] = {
		{7, 0, 0},
	};
	const struct kernel_range r2 = { pf_7_0_only, 1 };

	v = (struct kernel_version){6, 19, 99, NULL};
	EXPECT("mainline-only: kernel below mainline (6.19.99) → vulnerable",
	       !kernel_range_is_patched(&r2, &v));

	v = (struct kernel_version){7, 0, 0, NULL};
	EXPECT("mainline-only: at mainline (7.0.0) → patched",
	       kernel_range_is_patched(&r2, &v));

	v = (struct kernel_version){7, 5, 0, NULL};
	EXPECT("mainline-only: above mainline (7.5.0) → patched",
	       kernel_range_is_patched(&r2, &v));

	/* Multi-LTS table mirroring real af_unix_gc layout. */
	static const struct kernel_patched_from pf_multi[] = {
		{4, 14, 326},
		{4, 19, 295},
		{5,  4, 257},
		{5, 10, 197},
		{5, 15, 130},
		{6,  1,  51},
		{6,  4,  13},
		{6,  5,   0},
	};
	const struct kernel_range r3 = { pf_multi, 8 };

	v = (struct kernel_version){5, 10, 196, NULL};
	EXPECT("multi-LTS: 5.10.196 (one below backport) → vulnerable",
	       !kernel_range_is_patched(&r3, &v));

	v = (struct kernel_version){5, 10, 197, NULL};
	EXPECT("multi-LTS: 5.10.197 (exact backport) → patched",
	       kernel_range_is_patched(&r3, &v));

	v = (struct kernel_version){6,  4, 12, NULL};
	EXPECT("multi-LTS: 6.4.12 (just-added entry, below) → vulnerable",
	       !kernel_range_is_patched(&r3, &v));

	v = (struct kernel_version){6,  4, 13, NULL};
	EXPECT("multi-LTS: 6.4.13 (just-added entry, exact) → patched",
	       kernel_range_is_patched(&r3, &v));

	v = (struct kernel_version){6,  2,  0, NULL};
	EXPECT("multi-LTS: 6.2.0 (between LTS branches, no match) → vulnerable",
	       !kernel_range_is_patched(&r3, &v));

	v = (struct kernel_version){5,  8,  0, NULL};
	EXPECT("multi-LTS: 5.8.0 (between LTS branches) → vulnerable",
	       !kernel_range_is_patched(&r3, &v));

	/* NULL safety. */
	v = (struct kernel_version){5, 15, 42, NULL};
	EXPECT("null safety: NULL range → false",
	       !kernel_range_is_patched(NULL, &v));
	EXPECT("null safety: NULL version → false",
	       !kernel_range_is_patched(&r1, NULL));
}

/* ── skeletonkey_host_kernel_at_least ───────────────────────────────── */

static void test_host_kernel_at_least(void)
{
	struct skeletonkey_host h = {0};
	h.kernel.major = 6; h.kernel.minor = 12; h.kernel.patch = 5;

	EXPECT("at_least: 6.12.5 ≥ 6.12.5 → true (exact)",
	       skeletonkey_host_kernel_at_least(&h, 6, 12, 5));
	EXPECT("at_least: 6.12.5 ≥ 6.12.4 → true",
	       skeletonkey_host_kernel_at_least(&h, 6, 12, 4));
	EXPECT("at_least: 6.12.5 ≥ 6.12.6 → false",
	       !skeletonkey_host_kernel_at_least(&h, 6, 12, 6));
	EXPECT("at_least: 6.12.5 ≥ 6.11.999 → true (lower minor)",
	       skeletonkey_host_kernel_at_least(&h, 6, 11, 999));
	EXPECT("at_least: 6.12.5 ≥ 6.13.0 → false (higher minor)",
	       !skeletonkey_host_kernel_at_least(&h, 6, 13, 0));
	EXPECT("at_least: 6.12.5 ≥ 5.0.0 → true (lower major)",
	       skeletonkey_host_kernel_at_least(&h, 5, 0, 0));
	EXPECT("at_least: 6.12.5 ≥ 7.0.0 → false (higher major)",
	       !skeletonkey_host_kernel_at_least(&h, 7, 0, 0));

	/* NULL host → false (don't crash). */
	EXPECT("at_least: NULL host → false",
	       !skeletonkey_host_kernel_at_least(NULL, 5, 0, 0));

	/* Unpopulated host (major == 0) → false on any positive threshold:
	 * a zero kernel version means we never probed; modules should
	 * fail-safe by treating "unknown" as "below". */
	struct skeletonkey_host h_zero = {0};
	EXPECT("at_least: zeroed host (major=0) → false on any threshold",
	       !skeletonkey_host_kernel_at_least(&h_zero, 5, 0, 0));
}

/* ── skeletonkey_host_kernel_in_range ───────────────────────────────── */

static void test_host_kernel_in_range(void)
{
	struct skeletonkey_host h = {0};

	/* Window [5.8.0, 5.17.0) — the classic mainline introduction/fix
	 * pattern used by dirty_pipe and several others. */

	h.kernel = (struct kernel_version){5, 8, 0, NULL};
	EXPECT("in_range: 5.8.0 in [5.8.0, 5.17.0) → true (lo inclusive)",
	       skeletonkey_host_kernel_in_range(&h, 5, 8, 0, 5, 17, 0));

	h.kernel = (struct kernel_version){5, 16, 999, NULL};
	EXPECT("in_range: 5.16.999 in [5.8.0, 5.17.0) → true (inside)",
	       skeletonkey_host_kernel_in_range(&h, 5, 8, 0, 5, 17, 0));

	h.kernel = (struct kernel_version){5, 17, 0, NULL};
	EXPECT("in_range: 5.17.0 in [5.8.0, 5.17.0) → false (hi exclusive)",
	       !skeletonkey_host_kernel_in_range(&h, 5, 8, 0, 5, 17, 0));

	h.kernel = (struct kernel_version){5, 7, 999, NULL};
	EXPECT("in_range: 5.7.999 below 5.8.0 → false",
	       !skeletonkey_host_kernel_in_range(&h, 5, 8, 0, 5, 17, 0));

	h.kernel = (struct kernel_version){6, 0, 0, NULL};
	EXPECT("in_range: 6.0.0 above 5.17 → false",
	       !skeletonkey_host_kernel_in_range(&h, 5, 8, 0, 5, 17, 0));

	/* NULL host. */
	EXPECT("in_range: NULL host → false",
	       !skeletonkey_host_kernel_in_range(NULL, 5, 8, 0, 5, 17, 0));
}

int main(void)
{
	fprintf(stderr, "=== SKELETONKEY kernel_range unit tests ===\n\n");
	test_kernel_range_is_patched();
	test_host_kernel_at_least();
	test_host_kernel_in_range();
	fprintf(stderr, "\n=== RESULTS: %d passed, %d failed ===\n",
		g_pass, g_fail);
	return g_fail ? 1 : 0;
}
