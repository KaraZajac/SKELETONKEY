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

What that does:

1. Reads `tools/verify-vm/targets.yaml`: finds `nf_tables` → box
   `generic/ubuntu2204` + kernel pin `linux-image-5.15.0-43-generic`.
2. `vagrant up skk-nf_tables` (provisions on first call, resumes on
   subsequent).
3. Installs the pinned vulnerable kernel via `apt`, reboots.
4. Mounts the local repo at `/vagrant`, runs `make`, then runs
   `skeletonkey --explain nf_tables --active`.
5. Parses the `VERDICT:` line, compares against `expect_detect` from
   targets.yaml, emits a JSON verification record on stdout.
6. Suspends the VM (`vagrant suspend`) — instant resume next run.

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
for all 26 modules. Three are flagged `manual: true` because no
public Vagrant box covers them:

- `vmwgfx` — only reachable on VMware guests; needs a vSphere/Fusion VM
  not Parallels.
- `dirtydecrypt`, `fragnesia` — only present in Linux 7.0+ which isn't
  shipping as a distro kernel yet.

For those, verification needs a hand-built or special-distro VM.

## Verification records

`verify.sh` emits JSON on stdout after each run. Example:

```json
{
  "module":        "nf_tables",
  "verified_at":   "2026-05-23T17:42:11Z",
  "host_kernel":   "5.15.0-43-generic",
  "host_distro":   "Ubuntu 22.04.5 LTS",
  "vm_box":        "generic/ubuntu2204",
  "expect_detect": "VULNERABLE",
  "actual_detect": "VULNERABLE",
  "status":        "match",
  "log":           "tools/verify-vm/logs/verify-nf_tables-20260523-174211.log"
}
```

`status: match` means detect() returned what we expected on a known-
vulnerable kernel. Anything else (`MISMATCH`, status code != 0) means
either:

- The kernel pin didn't take (check `host_kernel` against
  `kernel_version` in targets.yaml).
- The exploit's preconditions aren't met in the default Vagrant image
  (e.g. apparmor blocks unprivileged userns; need to adjust the
  Vagrantfile provisioner).
- The detect() logic is wrong for this kernel/distro combo (a real bug
  — fix it).

Records are intended to feed a per-module `verified_on[]` table (next
project step) so `--list` can show a `✓ verified <date>` column.

## How it routes module → box

Mapping lives in `tools/verify-vm/targets.yaml`. Each entry has:

- `box` — which `boxes/` template (e.g. `ubuntu2204`)
- `kernel_pkg` — apt package name to install if the stock kernel
  is patched (omit / empty if stock is already vulnerable)
- `kernel_version` — what `uname -r` should report after install
- `expect_detect` — `VULNERABLE` | `OK` | `PRECOND_FAIL`
- `notes` — short rationale; comments in the file have the full context

Adding a new module is one block in targets.yaml. The verifier picks
it up automatically.

## Files

```
tools/verify-vm/
├── README.md       this file
├── setup.sh        one-time bootstrap (Vagrant, plugin, box cache)
├── verify.sh       per-module verifier
├── Vagrantfile     parameterized VM config (driven by SKK_VM_* env vars)
├── targets.yaml    module → box mapping with rationale
└── logs/           per-verification stdout/stderr capture
```

## Why Vagrant + Parallels

You already have Parallels Desktop. `vagrant-parallels` gives a
scriptable per-VM config + a curated public box library + idempotent
`vagrant up/provision/reload/suspend` lifecycle. The Vagrantfile is
parameterized via env vars so a single file drives every target.

Alternative providers (Lima, Multipass) would also work; Vagrant was
chosen for ergonomic continuity with the existing Parallels install.
