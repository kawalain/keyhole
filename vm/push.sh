#!/usr/bin/env bash
# Copies a local file into the router VM: vm/push.sh LOCAL REMOTE-PATH
set -euo pipefail
source "$(dirname "$0")/env.sh"
exec scp -q -i "$VM_DIR/id_ed25519" -P "$ROUTER_SSH_PORT" \
    -o UserKnownHostsFile="$VM_DIR/known_hosts" -o StrictHostKeyChecking=accept-new \
    "$1" "root@127.0.0.1:$2"
