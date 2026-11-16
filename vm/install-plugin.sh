#!/usr/bin/env bash
# Installs the keyhole daemon and the OPNsense plugin files into the router
# VM the way the plugin package would lay them out, then makes OPNsense
# pick them up. Build the daemon first:
#   CROSS_CONTAINER_ENGINE=podman cross build --release --target x86_64-unknown-freebsd
set -euo pipefail
dir=$(dirname "$0")
root=$dir/..
tarball=$(mktemp)
trap 'rm -f "$tarball"' EXIT

# Plugin src/etc and src/opnsense install under /usr/local.
tar -C "$root/opnsense/src" -czf "$tarball" etc opnsense
"$dir/push.sh" "$tarball" /tmp/keyhole-plugin.tgz
"$dir/push.sh" "$root/target/x86_64-unknown-freebsd/release/keyhole" /tmp/keyhole.new

"$dir/ssh.sh" sh -s <<'EOF'
set -e
if [ -x /usr/local/etc/rc.d/keyhole ]; then /usr/local/etc/rc.d/keyhole onestop || true; fi
pkill -f '^/usr/local/sbin/keyhole' || true
install -m 0755 /tmp/keyhole.new /usr/local/sbin/keyhole
tar -C /usr/local -xzf /tmp/keyhole-plugin.tgz
chmod 0755 /usr/local/etc/rc.d/keyhole
rm -f /tmp/keyhole.new /tmp/keyhole-plugin.tgz /tmp/opnsense_menu_cache.xml /tmp/opnsense_acl_cache.json
service configd restart >/dev/null
configctl template reload OPNsense/Keyhole
echo installed
EOF
