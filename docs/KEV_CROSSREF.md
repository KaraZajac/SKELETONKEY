# CISA KEV Cross-Reference

Which SKELETONKEY modules cover CVEs that CISA has observed exploited
in the wild per the Known Exploited Vulnerabilities catalog.
Refreshed via `tools/refresh-cve-metadata.py`.

**13 of 41 modules cover KEV-listed CVEs.**

## In KEV (prioritize patching)

| CVE | Date added to KEV | CWE | Module |
| --- | --- | --- | --- |
| CVE-2019-13272 | 2021-12-10 | ? | `ptrace_traceme_cve_2019_13272` |
| CVE-2016-5195 | 2022-03-03 | CWE-362 | `dirty_cow_cve_2016_5195` |
| CVE-2021-3156 | 2022-04-06 | CWE-193 | `sudo_samedit_cve_2021_3156` |
| CVE-2022-0847 | 2022-04-25 | CWE-665 | `dirty_pipe_cve_2022_0847` |
| CVE-2021-4034 | 2022-06-27 | CWE-787 | `pwnkit_cve_2021_4034` |
| CVE-2021-3493 | 2022-10-20 | CWE-270 | `overlayfs_cve_2021_3493` |
| CVE-2024-1086 | 2024-05-30 | CWE-416 | `nf_tables_cve_2024_1086` |
| CVE-2022-0185 | 2024-08-21 | CWE-190 | `fuse_legacy_cve_2022_0185` |
| CVE-2023-0386 | 2025-06-17 | CWE-282 | `overlayfs_setuid_cve_2023_0386` |
| CVE-2025-32463 | 2025-09-29 | CWE-829 | `sudo_chwoot_cve_2025_32463` |
| CVE-2021-22555 | 2025-10-06 | CWE-787 | `netfilter_xtcompat_cve_2021_22555` |
| CVE-2018-14634 | 2026-01-26 | CWE-190 | `mutagen_astronomy_cve_2018_14634` |
| CVE-2022-0492 | 2026-06-02 | CWE-287 | `cgroup_release_agent_cve_2022_0492` |

## Not in KEV

Not observed exploited per CISA — but several have public PoC code
and are technically reachable. "Not in KEV" is not the same as
"safe to ignore".

| CVE | CWE | Module |
| --- | --- | --- |
| CVE-2017-7308 | CWE-681 | `af_packet_cve_2017_7308` |
| CVE-2019-14287 | CWE-755 | `sudo_runas_neg1_cve_2019_14287` |
| CVE-2020-14386 | CWE-250 | `af_packet2_cve_2020_14386` |
| CVE-2020-29661 | CWE-416 | `tioscpgrp_cve_2020_29661` |
| CVE-2021-33909 | CWE-190 | `sequoia_cve_2021_33909` |
| CVE-2022-25636 | CWE-269 | `nft_fwd_dup_cve_2022_25636` |
| CVE-2022-2588 | CWE-416 | `cls_route4_cve_2022_2588` |
| CVE-2023-0179 | CWE-190 | `nft_payload_cve_2023_0179` |
| CVE-2023-0458 | CWE-476 | `entrybleed_cve_2023_0458` |
| CVE-2023-2008 | CWE-129 | `vmwgfx_cve_2023_2008` |
| CVE-2023-22809 | CWE-269 | `sudoedit_editor_cve_2023_22809` |
| CVE-2023-32233 | CWE-416 | `nft_set_uaf_cve_2023_32233` |
| CVE-2023-3269 | CWE-416 | `stackrot_cve_2023_3269` |
| CVE-2023-4622 | CWE-416 | `af_unix_gc_cve_2023_4622` |
| CVE-2024-26581 | ? | `nft_pipapo_cve_2024_26581` |
| CVE-2024-50264 | CWE-416 | `vsock_uaf_cve_2024_50264` |
| CVE-2025-32462 | CWE-863 | `sudo_host_cve_2025_32462` |
| CVE-2025-6019 | CWE-250 | `udisks_libblockdev_cve_2025_6019` |
| CVE-2026-23111 | CWE-416 | `nft_catchall_cve_2026_23111` |
| CVE-2026-31635 | CWE-130 | `dirtydecrypt_cve_2026_31635` |
| CVE-2026-41651 | CWE-367 | `pack2theroot_cve_2026_41651` |
| CVE-2026-43494 | ? | `pintheft_cve_2026_43494` |
| CVE-2026-43499 | CWE-416 | `ghostlock_cve_2026_43499` |
| CVE-2026-46242 | CWE-416 | `bad_epoll_cve_2026_46242` |
| CVE-2026-46243 | CWE-20 | `cifswitch_cve_2026_46243` |
| CVE-2026-46300 | CWE-787 | `fragnesia_cve_2026_46300` |
| CVE-2026-46333 | CWE-269 | `ptrace_pidfd_cve_2026_46333` |
| CVE-2026-64600 | ? | `refluxfs_cve_2026_64600` |
