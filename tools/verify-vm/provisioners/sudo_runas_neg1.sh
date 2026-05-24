#!/usr/bin/env bash
# CVE-2019-14287 needs a (ALL,!root) grant for find_runas_blacklist_grant()
# to fire. Ubuntu 18.04 ships sudo 1.8.21p2 (in the vulnerable range) but
# Vagrant's default sudoers doesn't include the grant. Add it.
set -e

cat >/etc/sudoers.d/99-skk-runas-neg1 <<'EOF'
vagrant ALL=(ALL,!root) NOPASSWD: /bin/vi
EOF
chmod 0440 /etc/sudoers.d/99-skk-runas-neg1

echo "[+] sudoers grant installed:"
grep . /etc/sudoers.d/99-skk-runas-neg1
echo
echo "[+] sudo -ln -U vagrant tail:"
sudo -ln -U vagrant 2>&1 | tail -10 || true
