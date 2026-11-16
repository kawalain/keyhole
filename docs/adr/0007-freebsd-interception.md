# 0007. Interception on FreeBSD: BPF observation, pf table and rdr-to

- Status: proposed
- Date: 2026-11-17

## Context

keyhole must see a few packets to detect blocking, and redirect only the
bypassed connections to its proxy, without touching any other traffic.

## Decision

- Observation: read `/dev/bpf` with a kernel BPF filter that passes only
  outbound TLS ClientHello segments (first payload byte `0x16`), inbound
  resets from port 443, and the first inbound payload from port 80.
  No libpcap.
- Enforcement: keyhole owns a pf table (`<keyhole>`). A pf `rdr-to` rule
  sends TCP 443 for addresses in the table to the local proxy, and a block
  rule rejects UDP 443 to them. keyhole only changes table contents
  (`pfctl -t keyhole -T replace`), never the ruleset.
- The proxy finds the original destination with pf's `DIOCNATLOOK`.
- A Linux adapter (nftables set, `SO_ORIGINAL_DST`, `AF_PACKET`) provides the
  same seams for development.

## Acceptance criteria

These rest on documentation only. Mark accepted once verified on OPNsense:

- the rdr rule can coexist with rules OPNsense generates,
- `DIOCNATLOOK` returns the original destination for redirected LAN traffic,
- the BPF filter matches the intended packets and nothing else.
