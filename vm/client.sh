#!/usr/bin/env bash
# Runs the Alpine client VM (live ISO, no disk) on the router's LAN, in the
# foreground. Start the router first. The serial console is on
# $CLIENT_SERIAL and logged to client.log.
set -euo pipefail
source "$(dirname "$0")/env.sh"

rm -f "$CLIENT_SERIAL"
exec qemu-system-x86_64 \
    -name keyhole-client \
    -machine q35,accel=kvm -cpu host -smp 1 -m 512 \
    -cdrom "$VM_DIR/${ALPINE_URL##*/}" -boot d \
    -netdev "stream,id=lan,server=off,addr.type=unix,addr.path=$LAN_SOCKET,reconnect-ms=1000" \
    -device virtio-net-pci,netdev=lan,mac=52:54:00:00:01:02 \
    -chardev "socket,id=console,path=$CLIENT_SERIAL,server=on,wait=off,logfile=$VM_DIR/client.log" \
    -serial chardev:console \
    -display none -monitor none
