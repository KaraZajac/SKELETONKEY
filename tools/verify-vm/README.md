# SKELETONKEY VM verification

Auto-provisions a Parallels Desktop VM with a known-vulnerable kernel,
runs `skeletonkey --explain <module> --active` inside it, and emits a
verification record. Closes the loop between "detect() compiles & passes
unit tests" and "exploit() actually works on a real vulnerable kernel."

## One-time setup

```bash
./tools/verify-vm/setup.sh
```

That installs (if missing): Vagrant via Homebrew, the `vagrant-parallels`
plugin, and pre-downloads ~5 GB of base boxes (Ubuntu 18.04/20.04/22.04
+ Debian 11/12). Idempotent — re-run any time.

To skip boxes you don't need (save disk):

```bash
./tools/verify-vm/setup.sh ubuntu2004 debian11   # only those two
```

## Verify a single module

```bash
./tools/verify-vm/verify.sh nf_tables
```

What that does (two-phase model — install kernel, then verify):

1. Reads `tools/verify-vm/targets.yaml`: finds `nf_tables` → box
   `generic/ubuntu2204` + `mainline_version: 5.15.5`.
2. `vagrant up skk-nf_tables` if not already running (each module gets
   its own machine for isolation).
3. **Prep phase** — runs every prep provisioner that applies:
   - `pin-kernel-<pkg>` if `kernel_pkg` is set (apt install + GRUB_DEFAULT pin)
   - `pin-mainline-<ver>` if `mainline_version` is set (download from
     kernel.ubuntu.com/mainline, dpkg -i, GRUB_DEFAULT pin)
   - `module-provision-<name>` if `provisioners/<name>.sh` exists
     (build vulnerable sudo from source, drop polkit allow rule,
     install udisks2, etc.)
4. **Conditional reboot** — `vagrant reload` if `uname -r` doesn't
   match the target kernel after the prep phase. Confirms post-reboot
   kernel actually landed on the target; warns if it didn't.
5. **Verify phase** — `build-and-verify` provisioner: rsync the source,
   `make`, run `skeletonkey --explain <module> --active`.
6. Parses the `VERDICT:` line, compares against `expect_detect` from
   targets.yaml, appends a JSON verification record to
   `docs/VERIFICATIONS.jsonl`.
7. Suspends the VM (`vagrant suspend`) — instant resume next run.

Lifecycle flags:

```bash
./tools/verify-vm/verify.sh nf_tables --keep      # leave VM running; ssh in to inspect
./tools/verify-vm/verify.sh nf_tables --destroy   # full teardown after run
```

## List every target

```bash
./tools/verify-vm/verify.sh --list
```

Shows the (module, box, target kernel, expected verdict, notes) matrix
for all targets. Modules with `manual: true` are blocked by their
target environment — see the notes field for the reason (VMware-only
guest, EOL kernel needed, t64-transition libs missing, etc.).

## Verification records

`verify.sh` appends one JSON record per run to
`docs/VERIFICATIONS.jsonl`:

```json
{
  "module":        "nf_tables",
  "verified_at":   "2026-05-24T03:24:01Z",
  "host_kernel":   "5.15.5-051505-generic",
  "host_distro":   "Ubuntu 22.04.3 LTS",
  "vm_box":        "generic/ubuntu2204",
  "expect_detect": "VULNERABLE",
  "actual_detect": "VULNERABLE",
  "status":        "match"
}
```

`status: match` means detect() returned what we expected on a known-
vulnerable kernel. Anything else (`MISMATCH`, exit code != 0) means
either:

- The kernel pin didn't take — check `host_kernel` against
  `kernel_version` in targets.yaml. The "post-reboot kernel" line in
  the verify log will say if `vagrant reload` did or didn't land on
  the target.
- The exploit's preconditions aren't met in the default Vagrant image
  (e.g. apparmor blocks unprivileged userns; provisioner needed).
- The module's detect() logic is wrong for this kernel/distro combo
  (a real module bug — fix it, as we did for `dirtydecrypt` after
  cross-checking against NVD).

Run `tools/refresh-verifications.py` after new records land to
regenerate `core/verifications.c` so the binary's `--explain` and
`--list` reflect the latest evidence.

## How it routes module → box

Mapping lives in `tools/verify-vm/targets.yaml`. Each entry has:

- `box` — generic/<distro> (e.g. `ubuntu2204`)
- `kernel_pkg` — apt package for a vulnerable stock-archive kernel,
  if one still exists in the distro's repos
- `mainline_version` — alternative to `kernel_pkg`: pulls a vanilla
  upstream kernel from `kernel.ubuntu.com/mainline/v<ver>/`. Use when
  the apt-archive version has been garbage-collected (Ubuntu drops
  old ABI versions) or when you need a specific point release that
  the distro never packaged.
- `kernel_version` — what `uname -r` should report after install
- `expect_detect` — `VULNERABLE` | `OK` | `PRECOND_FAIL`
- `manual: true` — skip auto verification; explain why in `notes`
- `notes` — full context for why this target was picked

Adding a new module is one block in targets.yaml. If the module needs
per-target setup beyond installing a kernel — for example building
sudo from source, adding a sudoers grant, or dropping a polkit allow
rule — write a shell script at `tools/verify-vm/provisioners/<module>.sh`
and the Vagrantfile will pick it up automatically.

## Module-specific provisioners (`provisioners/<module>.sh`)

When the kernel pin alone doesn't make a host vulnerable — e.g.
the bug is sudo-version-gated, or a polkit "active session" check
blocks the SSH path — drop a shell script at
`tools/verify-vm/provisioners/<module_name>.sh`. The Vagrantfile
runs it as root in the prep phase, before the `vagrant reload`
check. Scripts should be idempotent (apt is no-op if installed,
file overwrites are safe) since they re-run on every verify.

Existing examples:

- `sudo_chwoot.sh` — builds sudo 1.9.16p1 from upstream into
  `/usr/local/bin` so the vulnerable `--chroot` code path is reachable
  on Ubuntu 22.04 (which ships pre-feature 1.9.9).
- `udisks_libblockdev.sh` — installs `udisks2` + drops a polkit rule
  allowing the vagrant user to invoke `loop-setup` / `filesystem-mount`
  (without this, the SSH session is not "active" per polkit and the
  D-Bus call short-circuits).
- `sudo_runas_neg1.sh` — adds `vagrant ALL=(ALL,!root) NOPASSWD: /bin/vi`
  to `/etc/sudoers.d/` so `find_runas_blacklist_grant()` has a grant
  to abuse.

## Pinning kernels: apt vs mainline

`pin-kernel-<pkg>` runs `apt-get install -y <pkg>`. Best when the
target version still lives in the distro's archive (rare for old
point releases — Ubuntu eventually GCs them). Also pins `GRUB_DEFAULT`
to the just-installed kernel so the reboot lands on it instead of
the higher-version stock kernel.

`pin-mainline-<ver>` downloads vanilla mainline debs from
`kernel.ubuntu.com/mainline/v<ver>/`. Tries `/amd64/` first, falls
back to bare `/v<ver>/` for old kernels (≤ ~4.15) where amd64 wasn't
a separate subdir. Accepts both `linux-image-` (older naming) and
`linux-image-unsigned-` (current). Pins `GRUB_DEFAULT` to the
mainline kernel so grub doesn't keep booting the higher-versioned
stock kernel.

## Files

```
tools/verify-vm/
├── README.md         this file
├── setup.sh          one-time bootstrap (Vagrant, plugin, box cache)
├── verify.sh         per-module verifier
├── Vagrantfile       parameterized VM config (driven by SKK_VM_* env vars)
├── targets.yaml      module → box mapping with rationale
├── provisioners/     optional per-module shell hooks
│   ├── sudo_chwoot.sh
│   ├── sudo_runas_neg1.sh
│   └── udisks_libblockdev.sh
└── logs/             per-verification stdout/stderr capture
```

## Why Vagrant + Parallels

You already have Parallels Desktop. `vagrant-parallels` gives a
scriptable per-VM config + a curated public box library + idempotent
`vagrant up/provision/reload/suspend` lifecycle. The Vagrantfile is
parameterized via env vars so a single file drives every target.

Alternative providers (Lima, Multipass) would also work; Vagrant was
chosen for ergonomic continuity with the existing Parallels install.
