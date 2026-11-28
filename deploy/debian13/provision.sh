#!/bin/sh
# Provision a DEDICATED Debian 13 deployment-candidate image for Vulnix (run as root on
# that image only, never on a shared or running host). Idempotent.
#
#   sh provision.sh ARTIFACT_DIR
#
# ARTIFACT_DIR holds web-linux-arm64.private.tar.gz, backend-linux-arm64.private.tar.gz,
# node-linux-arm64.tar.gz and SHA256SUMS listing all three; every file is checked first.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
art=$(cd "$1" && pwd)
[ "$(id -u)" = 0 ] || { echo 'run as root' >&2; exit 2; }
grep -q '^13' /etc/debian_version || { echo 'Debian 13 only' >&2; exit 2; }
(cd "$art" && sha256sum -c SHA256SUMS)

# 1. packages: nothing Vulnix does not use. python3-jwt stays: cloud-init (provisioning
#    of the image) depends on it; Vulnix never imports it (it uses its vendored packages).
export DEBIAN_FRONTEND=noninteractive
apt-get purge -y curl qemu-utils cloud-image-utils cloud-utils cloud-initramfs-growroot >/dev/null 2>&1 || true
running=$(uname -r)
for pkg in $(dpkg-query -W -f='${Package}\n' 'linux-image-[0-9]*' 2>/dev/null); do
    case "$pkg" in
        "linux-image-$running") ;;                     # never the running kernel
        *) dpkg -s "$pkg" >/dev/null 2>&1 && apt-get purge -y "$pkg" >/dev/null ;;
    esac
done
update-grub >/dev/null 2>&1 || true

# 2. kernel and SSH hardening
rm -f /etc/sysctl.d/90-vulnix-hardening.conf
install -m 0644 "$here/99-zz-vulnix-hardening.conf" /etc/sysctl.d/99-zz-vulnix-hardening.conf
sysctl -q --system
[ "$(sysctl -n kernel.unprivileged_userns_clone)" = 0 ] || { echo 'unprivileged user namespaces are still on' >&2; exit 1; }
install -d -m 0755 /etc/systemd/resolved.conf.d
install -m 0644 "$here/90-vulnix-resolved.conf" /etc/systemd/resolved.conf.d/90-vulnix.conf
systemctl restart systemd-resolved
# container tooling a hypervisor tool may have installed (not a Debian package, not used)
for u in containerd buildkit; do systemctl disable --now "$u" >/dev/null 2>&1 || true; done
install -m 0644 "$here/90-vulnix-sshd.conf" /etc/ssh/sshd_config.d/90-vulnix.conf
sshd -t
systemctl reload ssh

# 3. host firewall (only SSH comes in)
install -d -m 0755 /etc/nftables.d
install -m 0644 "$here/vulnix-host.nft" /etc/nftables.d/vulnix-host.nft
grep -q 'nftables.d/vulnix-host.nft' /etc/nftables.conf || echo 'include "/etc/nftables.d/vulnix-host.nft"' >> /etc/nftables.conf
nft -f /etc/nftables.d/vulnix-host.nft
systemctl enable --quiet nftables

# 4. accounts: the control plane and the web server run as two unprivileged users
id vulnix >/dev/null 2>&1 || useradd --system --home-dir /var/lib/vulnix --no-create-home --shell /usr/sbin/nologin vulnix
id vulnix-web >/dev/null 2>&1 || useradd --system --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin vulnix-web
id vulnix-anchor >/dev/null 2>&1 || useradd --system --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin vulnix-anchor
install -d -m 0755 /usr/local/libexec
install -o root -g root -m 0755 "$here/vulnix-priv" /usr/local/libexec/vulnix-priv
visudo -cqf "$here/vulnix-sudoers"
install -o root -g root -m 0440 "$here/vulnix-sudoers" /etc/sudoers.d/vulnix

# 5. artifacts (root-owned, read-only for the services); data only for vulnix
for d in backend web node; do rm -rf "/opt/vulnix/$d.new"; install -d -m 0755 "/opt/vulnix/$d.new"; done
tar -xzf "$art/backend-linux-arm64.private.tar.gz" -C /opt/vulnix/backend.new --strip-components=1 backend
tar -xzf "$art/web-linux-arm64.private.tar.gz" -C /opt/vulnix/web.new
tar -xzf "$art/node-linux-arm64.tar.gz" -C /opt/vulnix/node.new --strip-components=1
chown -R root:root /opt/vulnix
chmod 0755 /opt/vulnix
chmod -R u+rwX,go+rX,go-w /opt/vulnix/backend.new /opt/vulnix/node.new
# the web server reads its generated server keys; nobody else needs them
chgrp -R vulnix-web /opt/vulnix/web.new && chmod -R u+rwX,g+rX,g-w,o-rwx /opt/vulnix/web.new
for d in backend web node; do rm -rf "/opt/vulnix/$d.old"; [ -d "/opt/vulnix/$d" ] && mv "/opt/vulnix/$d" "/opt/vulnix/$d.old"; mv "/opt/vulnix/$d.new" "/opt/vulnix/$d"; done
install -d -m 0700 -o vulnix -g vulnix /var/lib/vulnix

# 5b. local audit anchor: its own user and copy; the service only reaches its socket
install -d -o root -g root -m 0755 /opt/vulnix-anchor
install -o root -g root -m 0644 /opt/vulnix/backend/aegis/audit_anchor.py /opt/vulnix-anchor/audit_anchor.py
install -d -o root -g root -m 0755 /etc/vulnix
printf 'VULNIX_AUDIT_ANCHOR_SOCKET=/run/vulnix-anchor/anchor.sock\nVULNIX_AUDIT_ANCHOR_UID=%s\nVULNIX_AUDIT_ANCHOR_SOURCE=prod\n' \
    "$(id -u vulnix-anchor)" > /etc/vulnix/anchor.env
chmod 0644 /etc/vulnix/anchor.env

# 6. services
install -m 0644 "$here/vulnix-anchor.service" "$here/vulnix-backend.service" "$here/vulnix-web.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --quiet vulnix-anchor vulnix-backend vulnix-web
systemctl restart vulnix-anchor
systemctl restart vulnix-backend
sleep 3
systemctl restart vulnix-web
echo "provisioned: $(cat "$art/source-sha.txt" 2>/dev/null || echo '(no source-sha.txt)')"
