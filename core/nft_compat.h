/*
 * SKELETONKEY — nf_tables uapi compat shims.
 *
 * Older distro kernel headers (e.g. Ubuntu 20.04's linux-libc-dev ships
 * the 5.4 uapi; Debian 11 ships 5.10) don't define every nft attribute
 * or chain flag the exploits use. The numeric values are stable kernel
 * ABI — the target kernel understands them at runtime regardless of
 * what was present in the build host's uapi headers. Conditionally
 * define them here so modules compile against any reasonable header set.
 *
 * Sources for the numeric values:
 *   include/uapi/linux/netfilter/nf_tables.h in mainline at the kernel
 *   version that introduced each enum.
 *
 * Include AFTER <linux/netfilter/nf_tables.h>.
 */

#ifndef SKELETONKEY_NFT_COMPAT_H
#define SKELETONKEY_NFT_COMPAT_H

#include <linux/netfilter/nf_tables.h>

/* ── chain flags ─────────────────────────────────────────────────── */

/* NFT_CHAIN_HW_OFFLOAD: kernel 5.5 (commit be0b86e0594d). Needed by
 * nft_fwd_dup_cve_2022_25636. */
#ifndef NFT_CHAIN_HW_OFFLOAD
#define NFT_CHAIN_HW_OFFLOAD  0x2
#endif

/* NFT_CHAIN_BINDING: kernel 5.9 (commit d164385ec572). */
#ifndef NFT_CHAIN_BINDING
#define NFT_CHAIN_BINDING     0x4
#endif

/* ── chain attrs ─────────────────────────────────────────────────── */

/* NFTA_CHAIN_FLAGS: kernel 5.7 (commit 65038428b2c6). Ubuntu 18.04's
 * 4.15-era uapi lacks it. Position 10 in the enum
 * (NFTA_CHAIN_TABLE=1..NFTA_CHAIN_USERDATA=9, NFTA_CHAIN_FLAGS=10). */
#ifndef NFTA_CHAIN_FLAGS
#define NFTA_CHAIN_FLAGS      10
#endif

/* NFTA_CHAIN_ID: kernel 5.13 (commit 837830a4b439). */
#ifndef NFTA_CHAIN_ID
#define NFTA_CHAIN_ID         11
#endif

/* ── verdict attrs ──────────────────────────────────────────────── */

/* NFTA_VERDICT_CHAIN_ID: kernel 5.14 (commit 4ed8eb6570a4). Needed by
 * nf_tables_cve_2024_1086. */
#ifndef NFTA_VERDICT_CHAIN_ID
#define NFTA_VERDICT_CHAIN_ID 3   /* CODE=1, CHAIN=2, CHAIN_ID=3 */
#endif

/* ── set attrs ──────────────────────────────────────────────────── */

/* NFTA_SET_DESC_CONCAT: kernel 5.6 (commit 8aeff38e08d2 — concat sets). */
#ifndef NFTA_SET_DESC_CONCAT
#define NFTA_SET_DESC_CONCAT  2   /* DESC_SIZE=1, DESC_CONCAT=2 */
#endif

/* NFTA_SET_EXPR: kernel 5.12 (commit 65038428b2c6 — anon expr on sets). */
#ifndef NFTA_SET_EXPR
#define NFTA_SET_EXPR         13
#endif

/* NFTA_SET_EXPRESSIONS: kernel 5.16 (commit 48b0ae046ed4). */
#ifndef NFTA_SET_EXPRESSIONS
#define NFTA_SET_EXPRESSIONS  14
#endif

/* ── set-element attrs ──────────────────────────────────────────── */

/* NFTA_SET_ELEM_KEY_END: kernel 5.6 (commit 7b225d0b5c5b). */
#ifndef NFTA_SET_ELEM_KEY_END
#define NFTA_SET_ELEM_KEY_END 7
#endif

/* NFTA_SET_ELEM_EXPRESSIONS: kernel 5.16 (commit 48b0ae046ed4). */
#ifndef NFTA_SET_ELEM_EXPRESSIONS
#define NFTA_SET_ELEM_EXPRESSIONS 11
#endif

/* ── data attrs (newer additions tend to be backported uneven) ──── */

/* Make sure NFTA_DATA_VERDICT and friends exist — present since 3.13;
 * here only as a tripwire if a very old header somehow lacks them. */
#ifndef NFTA_DATA_VERDICT
#define NFTA_DATA_VERDICT     2
#endif
#ifndef NFTA_DATA_VALUE
#define NFTA_DATA_VALUE       1
#endif

#endif /* SKELETONKEY_NFT_COMPAT_H */
