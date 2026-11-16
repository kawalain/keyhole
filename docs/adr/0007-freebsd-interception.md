# 0007. Interception on FreeBSD: BPF observation, pf anchor and rdr

- Status: proposed
- Date: 2026-11-17

## Context

keyhole must see a few packets to detect blocking, and redirect only the
bypassed connections to its proxy, without touching any other traffic.

Seen on an OPNsense 26.7 test VM (FreeBSD 15.1-RELEASE-p1), 2026-11-17:

- The generated ruleset (`/tmp/rules.debug`) contains no anchors at all, so
  `pfctl -a <name>` alone loads rules pf never evaluates.
- Plugins add anchors from a `plugins.inc.d/<name>.inc` file whose
  `<name>_firewall(\OPNsense\Firewall\Plugin $fw)` hook calls
  `$fw->registerAnchor($name, $type, $priority, $placement, $quick)`
  (`OPNsense/Firewall/Plugin.php:223`). `filter.inc:407-413` emits
  `nat`/`binat`/`rdr` anchors around the NAT rules and `fw` anchors before
  and after the filter rules.
- With `opnsense/keyhole.inc` installed, `configctl filter reload` emits
  `rdr-anchor "keyhole"` and `anchor "keyhole" quick` (pf rejects `quick`
  on translation anchors). Rules and the `<keyhole>` table loaded with
  `pfctl -a keyhole` survive further filter reloads, and a client's TCP 443
  to a table address is redirected to a listener on `127.0.0.1:8443`.
- keyhole's code cross-built with `cross` (FreeBSD 12.3 ABI) runs there: the
  unit tests and the live probe/proxy tests pass inside the VM, whose WAN
  meets the real KT DPI.

## Decision

- Observation: read `/dev/bpf` with a kernel BPF filter that passes only
  outbound TLS ClientHello segments (first payload byte `0x16`), inbound
  resets from port 443, and the first inbound payload from port 80.
  No libpcap.
- Integration: keyhole ships `plugins.inc.d/keyhole.inc`, which registers an
  `rdr` anchor and a `fw` anchor named `keyhole`, both at the head and quick.
  keyhole loads its own rules into that anchor; the generated ruleset is
  never edited.
- Enforcement: the anchor holds a table `<keyhole>`, an `rdr pass` rule that
  sends LAN TCP 443 for addresses in the table to the local proxy, and a rule
  that rejects UDP 443 to them. At run time keyhole only changes table
  contents (`pfctl -a keyhole -t keyhole -T replace`).
- The proxy finds the original destination with pf's `DIOCNATLOOK`.
- A Linux adapter (nftables set, `SO_ORIGINAL_DST`, `AF_PACKET`) provides the
  same seams for development.

## Acceptance criteria

Mark accepted once verified on the OPNsense test VM:

- ~~the anchors appear in the generated ruleset and survive a filter
  reload~~ (seen 2026-11-17),
- `DIOCNATLOOK` returns the original destination for redirected LAN traffic,
- the BPF filter matches the intended packets and nothing else.
