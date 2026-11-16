# Shared settings for the test VMs. Sourced, not executed.
# shellcheck shell=bash

VM_DIR=${KEYHOLE_VM_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/keyhole-vm}

# Latest stable releases as of 2026-11-17, with checksums from the
# projects' own release files.
OPNSENSE_URL=https://pkg.opnsense.org/releases/26.7/OPNsense-26.7-nano-amd64.img.bz2
OPNSENSE_SHA256=28d5e2f37e40d87468a924e3006ef10e2ddc6de485b85333d9e3958c84d0cb9d
ALPINE_URL=https://dl-cdn.alpinelinux.org/alpine/v3.24/releases/x86_64/alpine-virt-3.24.4-x86_64.iso
ALPINE_SHA256=157d353f8e54252cad2d9812a0d56bb7fa2231fc154a110e1d180d7480ef8b4f

# The LAN is a point-to-point link between the two VMs over a Unix socket;
# nothing on the host network can see it.
LAN_SOCKET=$VM_DIR/lan.sock
ROUTER_SERIAL=$VM_DIR/router.serial
CLIENT_SERIAL=$VM_DIR/client.serial
# Host port forwarded to the router's SSH on its WAN side.
ROUTER_SSH_PORT=${KEYHOLE_ROUTER_SSH_PORT:-2222}
