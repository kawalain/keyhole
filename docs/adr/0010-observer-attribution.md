# 0010. Observer: first segments only, names from SNI or recent DNS answers

- Status: accepted (measured)
- Date: 2026-11-17

## Context

ADR 0007 has the observer read the SNI from outbound ClientHello segments
that a BPF filter passes by their first payload byte. Measured on
2026-11-17:

- Chromium's ClientHello is 2017 bytes with the server name at byte 1888
  (`testdata/client-hello-chromium.bin`): Chromium randomises extension
  order and its ML-KEM key share is large, so the name is often in the
  second TCP segment.
- curl with OpenSSL 3.5 sends 1564 bytes in two segments, with the name in
  the first (`testdata/lan-blocked-and-normal.pcap`).

A BPF filter cannot tell a ClientHello's second segment from any other
upload without per-flow state, and passing all outbound 443 payload would
copy every upload to user space.

## Decision

- The BPF filter passes only: outbound segments to 443 starting a TLS
  handshake record, inbound resets and handshake records from 443, outbound
  HTTP requests to 80 and inbound HTTP responses from 80.
- The observer tracks flows from those first segments. A reset from the
  server before any handshake record answers the ClientHello is a signal;
  so is an HTTP response redirecting to `warning.or.kr`.
- A signal names the domain from the SNI or `Host` in the first segment
  when present. Otherwise the daemon takes the domains the resolver
  recently answered with that server address as candidates; each candidate
  is still confirmed by a probe (ADR 0008).
- IPv4 only for now, matching the `inet` pf rules.

## Consequences

- Clients whose name is not in the first segment and that bypass the
  router's DNS (browser DoH) produce no usable signal.
- A shared CDN address can yield several candidates and therefore several
  probes; the daemon caps the candidate count.
