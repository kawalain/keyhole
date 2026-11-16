#!/usr/bin/env bash
# Downloads and verifies the OPNsense nano image and the Alpine client ISO,
# then creates a fresh copy-on-write disk for the router VM.
set -euo pipefail
source "$(dirname "$0")/env.sh"

mkdir -p "$VM_DIR"
cd "$VM_DIR"

fetch() { # url sha256
    local file=${1##*/}
    if [[ ! -f $file ]] || ! echo "$2  $file" | sha256sum -c --quiet; then
        curl -fsSL -o "$file" "$1"
        echo "$2  $file" | sha256sum -c --quiet
    fi
}

fetch "$OPNSENSE_URL" "$OPNSENSE_SHA256"
fetch "$ALPINE_URL" "$ALPINE_SHA256"

base=${OPNSENSE_URL##*/}
base=${base%.bz2}
[[ -f $base ]] || bunzip2 -k "$base.bz2"

# The router disk is a disposable overlay; delete it to start over.
if [[ ! -f opnsense.qcow2 ]]; then
    qemu-img create -q -f qcow2 -F raw -b "$VM_DIR/$base" opnsense.qcow2 8G
fi
echo "ready in $VM_DIR"
