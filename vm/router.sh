#!/usr/bin/env bash
# Runs the OPNsense router VM in the foreground.
#   vtnet0: LAN, a private link to the client VM
#   vtnet1: WAN, QEMU user-mode NAT through the host's own connection, so
#           traffic meets the real ISP's DPI
# The serial console is on $ROUTER_SERIAL and logged to router.log.
set -euo pipefail
source "$(dirname "$0")/env.sh"

rm -f "$LAN_SOCKET" "$ROUTER_SERIAL"
exec qemu-system-x86_64 \
    -name keyhole-router \
    -machine q35,accel=kvm -cpu host -smp 2 -m 2048 \
    -drive "file=$VM_DIR/opnsense.qcow2,if=virtio,format=qcow2" \
    -netdev "stream,id=lan,server=on,addr.type=unix,addr.path=$LAN_SOCKET" \
    -device virtio-net-pci,netdev=lan,mac=52:54:00:00:01:01 \
    -netdev "user,id=wan,hostfwd=tcp:127.0.0.1:$ROUTER_SSH_PORT-:22" \
    -device virtio-net-pci,netdev=wan,mac=52:54:00:00:02:01 \
    -chardev "socket,id=console,path=$ROUTER_SERIAL,server=on,wait=off,logfile=$VM_DIR/router.log" \
    -serial chardev:console \
    -display none -monitor none
