#!/usr/bin/env bash
# One-time setup of a freshly booted router VM over its serial console:
# installs a dedicated SSH key for root and opens SSH on the WAN side,
# which only the host can reach through QEMU's port forward.
set -euo pipefail
dir=$(dirname "$0")
source "$dir/env.sh"
source "$dir/serial.sh"

key=$VM_DIR/id_ed25519
[[ -f $key ]] || ssh-keygen -q -t ed25519 -N '' -C keyhole-vm -f "$key"

payload=$(sed "s|@PUBKEY@|$(cat "$key.pub")|" "$dir/router-guest-setup.sh" | base64 -w 76)

serial_open "$ROUTER_SERIAL" "$VM_DIR/setup-router.log"
serial_send ''
serial_expect 'login:' 30
serial_send root
serial_expect 'Password:' 10
serial_send opnsense
serial_expect 'Enter an option:' 30
serial_send 8
serial_expect '#' 10
serial_send 'exec /bin/sh'
serial_send 'PS1="guest$ "'
serial_expect 'guest$ ' 10
serial_send "cat > /tmp/setup.b64 <<'EOF'"
while IFS= read -r line; do serial_send "$line"; done <<<"$payload"
serial_send EOF
serial_expect 'guest$ ' 10
serial_send 'b64decode -r < /tmp/setup.b64 > /tmp/setup.sh && sh /tmp/setup.sh; echo "setup-""exit=$?"'
serial_expect 'setup-exit=' 180
serial_expect 'guest$ ' 10
grep -a 'setup-exit=' "$VM_DIR/setup-router.log" | tail -1
serial_send exit
