#!/usr/bin/env bash
# CVE-2025-6019 udisks/libblockdev SUID-on-mount (Qualys). Debian 12's
# cloud image is server-oriented and doesn't ship udisks2. Install it,
# and drop a polkit rule allowing the vagrant user to invoke the
# affected action.ids — the real-world bug-path is "active console
# user invokes loop-setup", and we don't have a graphical session in
# Vagrant. The polkit rule simulates the trust polkit would give a
# logged-in workstation user.
set -e

export DEBIAN_FRONTEND=noninteractive
apt-get install -y -qq udisks2 libblockdev-utils2 >/dev/null

mkdir -p /etc/polkit-1/rules.d
cat >/etc/polkit-1/rules.d/49-skk-verify.rules <<'EOF'
polkit.addRule(function(action, subject) {
    if (subject.user == "vagrant" &&
        (action.id == "org.freedesktop.UDisks2.loop-setup" ||
         action.id == "org.freedesktop.UDisks2.filesystem-mount" ||
         action.id == "org.freedesktop.UDisks2.filesystem-mount-other-seat" ||
         action.id == "org.freedesktop.UDisks2.modify-device")) {
        return polkit.Result.YES;
    }
});
EOF

systemctl enable udisks2.service >/dev/null 2>&1 || true
systemctl restart udisks2.service
sleep 2

echo "[+] udisks2 status:"
systemctl is-active udisks2.service
echo "[+] udisks2 version: $(dpkg-query -W -f='${Version}' udisks2)"
echo "[+] libblockdev version: $(dpkg-query -W -f='${Version}' libblockdev-utils2)"
