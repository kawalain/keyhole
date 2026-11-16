# keyhole

keyhole runs on an OPNsense router and works around Korean ISP censorship
for the sites that need it, and only those. It watches the LAN for the
resets and block pages the ISP's filter injects, confirms each suspected
domain with active probes, and sends just the confirmed domains through a
small local proxy that rewrites the first bytes the filter inspects.

It also replaces AdGuard Home's place in the DNS chain: Unbound forwards to
keyhole, which relays every query to the ISP resolver; ad and tracker
blocking moves to Unbound's own blocklist.

```
clients -> Unbound (cache, blocklist) -> keyhole -> ISP resolver
clients -> pf -> keyhole proxy (blocked sites only) -> origin
```

## How it gets past the filter

Measured on a KT line (`docs/kt-filter.md`):

- HTTPS: the filter reassembles TCP but not TLS records, so keyhole splits
  the ClientHello into two TLS records inside the server name.
- Plain HTTP: the filter inspects only the first request in a segment, so
  keyhole sends a harmless `HEAD` for the server's own address in front.
- QUIC is not inspected and is left alone.

Nothing is tunnelled: traffic still goes straight to the origin from the
router's own address.

## Status

Version 0.1.0. Verified in an OPNsense 26.7 virtual machine whose WAN goes
out through a real KT connection; not yet run on a physical router. Korean
ISPs only, IPv4 only. What has not been verified is listed in
`docs/verification-debt.md`.

## Install on OPNsense

See `docs/install.md`: add the signed package repository, then
`pkg install os-keyhole`, and set the upstream DNS server under
Services > keyhole. `docs/adguard-home-migration.md` covers moving from
AdGuard Home.

## Resource use

In the test VM: 4.6 MiB resident, no CPU while idle, a 530 KB binary with no
dependencies beyond libc (ADR 0006).

## Development

- `cargo test`, `cargo test -- --ignored` (live probes, need a Korean ISP
  connection), `cargo clippy --all-targets -- -D warnings`.
- FreeBSD build: `CROSS_CONTAINER_ENGINE=podman cross build --release
  --target x86_64-unknown-freebsd`.
- `vm/` runs a disposable OPNsense router and client with QEMU, without
  root; `CLAUDE.md` describes the workflow.
- Design decisions and their measurements: `docs/adr/`.

## License

MIT
