/*
 * tests/test_detect.c — detect() unit tests
 *
 * Each test builds a synthetic struct skeletonkey_host fingerprint
 * (vulnerable / patched / specific-gate-closed) and asserts each
 * module's detect() returns the expected verdict. Catches regressions
 * in the host-fingerprint-consuming logic across the corpus.
 *
 * Coverage today is the four modules that already consume ctx->host:
 *   - dirtydecrypt   (CVE-2026-31635)
 *   - fragnesia      (CVE-2026-46300)
 *   - pack2theroot   (CVE-2026-41651)
 *   - overlayfs      (CVE-2021-3493)
 * Coverage grows automatically as more modules migrate to ctx->host
 * (see ROADMAP "core/host" follow-up).
 *
 * Why only Linux: every module's real detect() lives inside
 * `#ifdef __linux__`; on non-Linux the stubs unconditionally return
 * PRECOND_FAIL so the tests are tautologies. The harness compiles
 * cross-platform but skips the assertions on non-Linux to keep the
 * macOS dev build green while still preventing bit-rot of the test
 * infrastructure.
 */

#include "../core/module.h"
#include "../core/host.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern const struct skeletonkey_module dirtydecrypt_module;
extern const struct skeletonkey_module fragnesia_module;
extern const struct skeletonkey_module pack2theroot_module;
extern const struct skeletonkey_module overlayfs_module;

static int g_pass = 0;
static int g_fail = 0;

static const char *result_str(skeletonkey_result_t r)
{
	switch (r) {
	case SKELETONKEY_OK:           return "OK";
	case SKELETONKEY_TEST_ERROR:   return "TEST_ERROR";
	case SKELETONKEY_VULNERABLE:   return "VULNERABLE";
	case SKELETONKEY_EXPLOIT_FAIL: return "EXPLOIT_FAIL";
	case SKELETONKEY_PRECOND_FAIL: return "PRECOND_FAIL";
	case SKELETONKEY_EXPLOIT_OK:   return "EXPLOIT_OK";
	}
	return "???";
}

#ifdef __linux__
/* Suppress per-module banner chatter so the test output stays tidy.
 * Modules respect ctx->json to mean "structured output mode; no banners"
 * — see each module's `if (!ctx->json) fprintf(...)` pattern. */
static void run_one(const char *test_name,
		    const struct skeletonkey_module *m,
		    const struct skeletonkey_host *h,
		    skeletonkey_result_t want)
{
	struct skeletonkey_ctx ctx = {0};
	ctx.host = h;
	ctx.json = true;        /* silence per-module log lines */

	skeletonkey_result_t got = m->detect(&ctx);
	if (got == want) {
		printf("[+] PASS  %-40s  %s → %s\n",
		       test_name, m->name, result_str(got));
		g_pass++;
	} else {
		fprintf(stderr,
			"[-] FAIL  %-40s  %s: want %s, got %s\n",
			test_name, m->name,
			result_str(want), result_str(got));
		g_fail++;
	}
}

/* ── fingerprints ────────────────────────────────────────────────── */

/* Linux 6.12.76 (Debian 13), no userns, no D-Bus, not Ubuntu — a
 * deliberately neutered host that lets the host-fingerprint-only
 * gates fire without falling into deeper module logic. */
static const struct skeletonkey_host h_pre7_no_userns_no_dbus = {
	.kernel  = { .major = 6, .minor = 12, .patch = 76,
		     .release = "6.12.76-test" },
	.arch    = "x86_64",
	.nodename = "test",
	.distro_id          = "debian",
	.distro_version_id  = "13",
	.distro_pretty      = "Debian GNU/Linux 13",
	.is_linux           = true,
	.is_debian_family   = true,
	.unprivileged_userns_allowed = false,
	.has_dbus_system    = false,
	.has_systemd        = true,
};

/* Fedora 43, no Debian family, userns allowed. */
static const struct skeletonkey_host h_fedora_no_debian = {
	.kernel  = { .major = 6, .minor = 14, .patch = 0,
		     .release = "6.14.0-fedora" },
	.arch    = "x86_64",
	.nodename = "test",
	.distro_id          = "fedora",
	.distro_version_id  = "43",
	.distro_pretty      = "Fedora 43",
	.is_linux           = true,
	.is_rpm_family      = true,
	.is_debian_family   = false,
	.unprivileged_userns_allowed = true,
	.has_dbus_system    = true,
	.has_systemd        = true,
};

/* Ubuntu 24.04, userns allowed, D-Bus running, Debian family
 * (because Ubuntu has /etc/debian_version). Used as the "fragnesia
 * preconditions OK" baseline — fragnesia should NOT short-circuit
 * on userns/userspace gates here. */
static const struct skeletonkey_host h_ubuntu_24_userns_ok = {
	.kernel  = { .major = 6, .minor = 8, .patch = 0,
		     .release = "6.8.0-ubuntu" },
	.arch    = "x86_64",
	.nodename = "test",
	.distro_id          = "ubuntu",
	.distro_version_id  = "24.04",
	.distro_pretty      = "Ubuntu 24.04 LTS",
	.is_linux           = true,
	.is_debian_family   = true,
	.unprivileged_userns_allowed = true,
	.has_dbus_system    = true,
	.has_systemd        = true,
};
#endif /* __linux__ */

/* ── tests ───────────────────────────────────────────────────────── */

static void run_all(void)
{
#ifdef __linux__
	/* dirtydecrypt: kernel.major < 7 → predates the bug → OK */
	run_one("dirtydecrypt: kernel 6.12 predates 7.0 → OK",
		&dirtydecrypt_module, &h_pre7_no_userns_no_dbus,
		SKELETONKEY_OK);

	run_one("dirtydecrypt: kernel 6.14 (fedora) still predates → OK",
		&dirtydecrypt_module, &h_fedora_no_debian,
		SKELETONKEY_OK);

	run_one("dirtydecrypt: kernel 6.8 (ubuntu) still predates → OK",
		&dirtydecrypt_module, &h_ubuntu_24_userns_ok,
		SKELETONKEY_OK);

	/* fragnesia: userns disabled → XFRM gate closed → PRECOND_FAIL */
	run_one("fragnesia: userns_allowed=false → PRECOND_FAIL",
		&fragnesia_module, &h_pre7_no_userns_no_dbus,
		SKELETONKEY_PRECOND_FAIL);

	/* pack2theroot: not Debian family → PRECOND_FAIL */
	run_one("pack2theroot: is_debian_family=false → PRECOND_FAIL",
		&pack2theroot_module, &h_fedora_no_debian,
		SKELETONKEY_PRECOND_FAIL);

	/* pack2theroot: Debian family but no D-Bus socket → PRECOND_FAIL */
	run_one("pack2theroot: has_dbus_system=false → PRECOND_FAIL",
		&pack2theroot_module, &h_pre7_no_userns_no_dbus,
		SKELETONKEY_PRECOND_FAIL);

	/* overlayfs: distro != ubuntu → bug is Ubuntu-specific → OK */
	run_one("overlayfs: distro=debian → not Ubuntu → OK",
		&overlayfs_module, &h_pre7_no_userns_no_dbus,
		SKELETONKEY_OK);

	run_one("overlayfs: distro=fedora → not Ubuntu → OK",
		&overlayfs_module, &h_fedora_no_debian,
		SKELETONKEY_OK);
#else
	fprintf(stderr, "[i] non-Linux platform: detect() bodies are stubbed; "
			"tests skipped (would tautologically pass).\n");
#endif
}

int main(void)
{
	fprintf(stderr, "=== SKELETONKEY detect() unit tests ===\n\n");
	run_all();
	fprintf(stderr, "\n=== RESULTS: %d passed, %d failed ===\n",
		g_pass, g_fail);
	return g_fail ? 1 : 0;
}
