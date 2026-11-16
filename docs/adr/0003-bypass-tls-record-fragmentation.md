# 0003. Bypass: TLS record fragmentation in a transparent proxy

- Status: accepted for TLS (measured); HTTP bypass remains open
- Date: 2026-11-17

## Context

The ISP's DPI reads the SNI in the ClientHello and the `Host` header of plain
HTTP requests. Candidate transformations of the first payload were measured
with `research/split_probe.py` against `womenhelp.org`, three runs each, from
a LAN host behind the target router.

| Transformation | Success |
|---|---|
| TLS, unchanged | 0/3 (reset) |
| TLS, TCP segments split inside the SNI (50 ms gap) | 0/3 (reset) |
| TLS, ClientHello split into two TLS records inside the SNI | 3/3 |
| TLS, record split and each record in its own TCP segment | 3/3 |
| HTTP, unchanged / lower-case `host:` / trailing-dot host / TCP split | 0/3 |
| HTTP, `HoSt:` mixed case or `Host:` without space | 1/3 |

A later check on `pornhub.com` and `xvideos.com` gave the same picture:
reset when unchanged, handshake completes with the record split. The Rust
prober and proxy reproduce the result (`tests/live.rs`).

The DPI reassembles TCP segments but does not reassemble TLS records. HTTP
header tricks are unreliable, which also hints that more than one DPI box with
different parsers sits on the path.

## Decision

- Blocked TLS connections go through a local transparent proxy that rewrites
  the ClientHello into two TLS records split inside the SNI host name.
- Plain-HTTP bypass is not part of the first version. Blocked sites almost
  always redirect HTTP to HTTPS; once the HTTPS side works, the user lands
  there.
- QUIC (UDP 443) to bypassed addresses is rejected so clients fall back to TCP.

## Consequences

- The proxy needs no raw sockets: it only rewrites the first client payload
  and then relays bytes.
- If the ISP starts reassembling TLS records, the prober's strategy search
  must find a new transformation; strategies are therefore data, not code
  paths hard-wired into the proxy.
