# 0011. Plain-HTTP bypass: a decoy request in the same segment

- Status: accepted (measured)
- Date: 2026-11-17
- Supersedes: the plain-HTTP part of [0003](0003-bypass-tls-record-fragmentation.md)

## Context

ADR 0003 left plain HTTP without a bypass because header tricks were
unreliable. A wider measurement on 2026-11-17 (`research/http_probe.py`,
KT line, `womenhelp.org` at 199.58.81.252, five runs each unless noted):

| Request | Got past the filter |
|---|---|
| unchanged, `HoSt:`, `Host:` without space, upper-case value, `Host:` last, LF-only line ends, method in its own segment | 0/5 |
| 1600 bytes of padding before `Host` | 0/5 |
| absolute URI with a harmless `Host` | 0/5 |
| `Host: womenhelp.org:80` | 0/5 |
| `Host:` with a tab | 1/5 (and the server answered 400) |
| split inside the name with a 1 s pause | 1/5 |
| harmless request, its response, then the real request on the same connection | 0/5 |
| `HEAD / HTTP/1.1` with `Host: <server IP>` and the real request in the same segment | 5/5; 10/10 in a second run, where the second response was `womenhelp.org`'s own redirect |

The filter reassembles TCP and inspects the request line and `Host`, but
only of the first request in a segment.

## Decision

- The anchor redirects TCP 80 as well as 443 for bypassed addresses.
- For a plain-HTTP first flight, the proxy sends `HEAD / HTTP/1.1` with the
  server's address as `Host`, followed by the client's bytes, in one write.
  It drops the `HEAD` response (headers only) from the server's stream.
- The prober checks plain HTTP when TLS is not blocked: a block-page
  redirect for the real request, then the decoy. A domain blocked only over
  HTTP gets `Strategy::HttpDecoy`; every bypassed address gets both
  rewrites, chosen per connection by protocol.

## Consequences

- Only the first request of a connection is protected. Further requests on
  a keep-alive connection reach the filter on their own and are blocked
  (measured 0/5 above). Blocked sites usually redirect HTTP to HTTPS on the
  first request, so this is accepted for now.
- A server that closes the connection after the `HEAD` response loses the
  real request; the prober only confirms the decoy for HTTP-only blocks.
