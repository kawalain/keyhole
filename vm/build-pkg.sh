#!/usr/bin/env bash
# Builds the os-keyhole package and a signed pkg repository for it, using
# the router VM's FreeBSD pkg tools: vm/build-pkg.sh OUTPUT-DIR
#
# Needs the release binary (cross build) and the signing key, whose path
# defaults to ~/.config/keyhole/pkg-signing.key (KEYHOLE_PKG_KEY). The key
# is copied into the VM only for the signing step and removed afterwards.
# Package scripts mirror what opnsense/plugins' Mk/plugins.mk generates,
# followed by the plugin's own .pre/.post additions.
set -euo pipefail
dir=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$dir/.." && pwd)
out=${1:?usage: vm/build-pkg.sh OUTPUT-DIR}
key=${KEYHOLE_PKG_KEY:-$HOME/.config/keyhole/pkg-signing.key}
binary=$root/target/x86_64-unknown-freebsd/release/keyhole
[[ -f $key && -x $binary ]] || { echo "need $key and $binary" >&2; exit 1; }

version=$(sed -n 's/^version = "\(.*\)"/\1/p' "$root/Cargo.toml" | head -1)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# Stage the files exactly as installed.
mkdir -p "$work/stage/usr/local/sbin"
cp -R "$root/opnsense/src/." "$work/stage/usr/local/"
install -m 0755 "$binary" "$work/stage/usr/local/sbin/keyhole"
chmod 0755 "$work/stage/usr/local/etc/rc.d/keyhole"
(cd "$work/stage" && find . -type f | sed 's|^\.||' | sort) >"$work/plist"

# Package scripts: plugins.mk's automatic part, then ours.
script() { # name auto-part
    { [[ -f $root/opnsense/$1.pre ]] && cat "$root/opnsense/$1.pre"
      printf '%s' "$2"
      [[ -f $root/opnsense/$1.post ]] && cat "$root/opnsense/$1.post"; } || true
}
configure() {
    echo "if [ -f /usr/local/etc/rc.configure_plugins ]; then echo \"Reloading plugin configuration\"; /usr/local/etc/rc.configure_plugins $1; fi"
}
post_install=$(cat <<EOF
if [ -f /usr/local/etc/rc.d/configd ]; then /usr/local/etc/rc.d/configd restart; fi
if [ -f /usr/local/opnsense/mvc/script/run_migrations.php ]; then /usr/local/opnsense/mvc/script/run_migrations.php OPNsense/Keyhole; fi
$(configure POST_INSTALL)
if [ -f /usr/local/sbin/configctl ]; then echo -n "Reloading template OPNsense/Keyhole: "; /usr/local/sbin/configctl template reload OPNsense/Keyhole; fi
EOF
)
json() { python3 -I -c 'import json,sys; print(json.dumps(sys.stdin.read()))'; }
cat >"$work/manifest" <<EOF
name: os-keyhole
version: "$version"
origin: opnsense/os-keyhole
comment: "$(sed -n 's/^PLUGIN_COMMENT=[[:space:]]*//p' "$root/opnsense/Makefile")"
maintainer: "N/A"
www: "https://github.com/kawalain/keyhole"
prefix: "/usr/local"
licenselogic: "single"
licenses: ["MIT"]
categories: ["net"]
desc: $(json <"$root/opnsense/pkg-descr")
scripts: {
  post-install: $(script +POST_INSTALL "$post_install"$'\n' | json)
  pre-deinstall: $(script +PRE_DEINSTALL "" | json)
  post-deinstall: $(script +POST_DEINSTALL "$(configure POST_DEINSTALL)"$'\n' | json)
}
EOF

tar -C "$work" -czf "$work/pkgsrc.tgz" stage plist manifest
"$dir/push.sh" "$work/pkgsrc.tgz" /tmp/keyhole-pkgsrc.tgz
"$dir/push.sh" "$key" /tmp/keyhole-pkg.key
"$dir/ssh.sh" sh -s <<'EOF'
set -e
trap 'rm -P -f /tmp/keyhole-pkg.key' EXIT
rm -rf /tmp/keyhole-pkg && mkdir -p /tmp/keyhole-pkg && cd /tmp/keyhole-pkg
tar -xzf /tmp/keyhole-pkgsrc.tgz
abi=$(pkg config abi)
mkdir -p "repo/$abi/All"
pkg create -M manifest -p plist -r stage -o "repo/$abi/All"
pkg repo -q "repo/$abi" /tmp/keyhole-pkg.key
tar -C repo -czf /tmp/keyhole-repo.tgz .
echo "built for $abi"
EOF
mkdir -p "$out"
"$dir/ssh.sh" 'cat /tmp/keyhole-repo.tgz' | tar -C "$out" -xzf -
find "$out" -type f | sort
