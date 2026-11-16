#!/usr/bin/env bash
# SSH into the router VM as root: vm/ssh.sh [command...]
set -euo pipefail
source "$(dirname "$0")/env.sh"
exec ssh -i "$VM_DIR/id_ed25519" -p "$ROUTER_SSH_PORT" \
    -o UserKnownHostsFile="$VM_DIR/known_hosts" -o StrictHostKeyChecking=accept-new \
    -o LogLevel=ERROR root@127.0.0.1 "$@"
