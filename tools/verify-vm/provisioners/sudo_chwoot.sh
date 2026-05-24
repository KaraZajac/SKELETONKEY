#!/usr/bin/env bash
# CVE-2025-32463 sudo --chroot NSS injection (Stratascale). Vulnerable
# range is sudo [1.9.14, 1.9.17p0]. Ubuntu 22.04 ships 1.9.9 which
# PREDATES the --chroot code path. Build sudo 1.9.16p1 from upstream
# and install to /usr/local (which precedes /usr/bin in Ubuntu's default
# PATH so plain `sudo` resolves to the vulnerable binary).
set -e

export DEBIAN_FRONTEND=noninteractive
apt-get install -y -qq libpam0g-dev libssl-dev wget make gcc >/dev/null

cd /tmp
TARBALL=sudo-1.9.16p1.tar.gz
URL="https://www.sudo.ws/dist/${TARBALL}"

if [ -x /usr/local/bin/sudo ] && /usr/local/bin/sudo --version 2>&1 | head -1 | grep -q "1.9.16p1"; then
    echo "[=] sudo 1.9.16p1 already at /usr/local/bin/sudo"
else
    [ -f "${TARBALL}" ] || wget -q "${URL}"
    rm -rf sudo-1.9.16p1
    tar xzf "${TARBALL}"
    cd sudo-1.9.16p1
    # --sysconfdir=/etc so it honors the existing /etc/sudoers (vagrant's
    # NOPASSWD grant). --disable-shared keeps the build self-contained.
    ./configure --prefix=/usr/local --sysconfdir=/etc \
        --disable-shared --quiet >/dev/null 2>&1
    make -j"$(nproc)" >/tmp/sudo-build.log 2>&1 || { tail -40 /tmp/sudo-build.log; exit 1; }
    make install >/tmp/sudo-install.log 2>&1 || { tail -40 /tmp/sudo-install.log; exit 1; }
fi

# Verify what the unprivileged user's PATH resolves to.
echo "[+] which sudo (root): $(which sudo)"
echo "[+] /usr/local/bin/sudo version: $(/usr/local/bin/sudo --version | head -1)"
sudo -u vagrant bash -c 'echo "[+] vagrant PATH: $PATH"; echo "[+] vagrant sees: $(which sudo)"; sudo --version | head -1'
