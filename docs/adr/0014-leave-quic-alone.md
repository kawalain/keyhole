# 0014. Leave QUIC to bypassed addresses alone

- Status: accepted (measured)
- Date: 2026-11-17
- Supersedes: the QUIC rule in [0003](0003-bypass-tls-record-fragmentation.md)
  and the filter anchor in [0007](0007-freebsd-interception.md) and
  [0012](0012-opnsense-plugin.md)

## Context

ADR 0003 rejected UDP 443 to bypassed addresses so that clients would fall
back to TCP, which the proxy can rewrite. That assumed the filter inspects
QUIC. Measured on 2026-11-17 (`docs/kt-filter.md`): to a Google address
whose TLS over TCP was reset for `womenhelp.org`, HTTP/3 with the same name
and with `pornhub.com` got the server's own answer every time.

## Decision

- keyhole no longer rejects QUIC; a client that speaks HTTP/3 to a blocked
  site reaches it directly.
- The anchor holds only the table and the `rdr` rule, so the plugin
  registers only the `rdr` anchor. No filter anchor is needed.

## Consequences

- Sites with HTTP/3 load without the proxy; the rest fall back to TCP as
  usual and take the proxy.
- If the filter starts inspecting QUIC, clients lose time before falling
  back to TCP. The measurement covers one path on one KT line; it is listed
  in `docs/verification-debt.md` until other lines are seen.
