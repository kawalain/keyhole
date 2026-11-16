# 0002. Korean blocking model

- Status: accepted (measured)
- Date: 2026-11-17

## Context

Detection and bypass depend on how the ISP blocks. The model below was
measured on 2026-11-17 from a LAN host behind the target OPNsense router,
using `womenhelp.org` (`199.58.81.252`) as the blocked domain.

| Probe | Result |
|---|---|
| TLS to the real IP, SNI `womenhelp.org` | TCP reset right after ClientHello |
| TLS to the real IP, SNI `example.com` | Handshake completes, `301` |
| HTTP to the real IP, `Host: womenhelp.org` | `302` to `http://warning.or.kr/i6.html` |
| HTTP to the real IP, `Host: example.com` | Normal `301` from the origin |
| System resolver answer vs. Cloudflare DoH | Identical (`199.58.81.252`) |
| TLS with SNI `womenhelp.org` to unrelated IPs | 1.1.1.1 and a Fastly IP completed the handshake; a Cloudflare IP and 8.8.8.8 failed (failure type not captured) |
| TLS to `pornhub.com`, `xvideos.com` on their real IPs | TCP reset right after ClientHello |
| KT (168.126.63.1), SKB (219.250.36.130) and LGU+ (164.124.101.2) resolvers, plain UDP, for the three SNI-blocked domains above | Real addresses, matching Cloudflare DoH; never the block-page address `121.189.57.82` |
| Record-split ClientHellos 0.2 s to 12 s after a blocked one to the same server (`research/residual_probe.py`, three rounds) | All completed: no residual blocking |

The measuring line is on KT (AS4766). `docs/kt-filter.md` describes the
filter in more detail (location, protocols, name matching, coverage).

## Decision

keyhole treats these as the block signatures:

- `SniReset`: a reset that follows a ClientHello carrying the SNI, while the
  same IP accepts a harmless SNI.
- `HttpBlockRedirect`: an HTTP response redirecting to `warning.or.kr`.
- `DnsBlocked`: an ISP-resolver answer that is NXDOMAIN or points at a
  known block-page address while an encrypted resolver returns a real answer.

A verdict is confirmed only by an active control probe (harmless SNI or Host
on the same IP), never by passive evidence alone.

## Consequences

- The IP is not blocked, so the bypass can keep the original destination.
- Blocking may depend on the network path (the mixed results against
  unrelated IPs), so verdicts expire and are re-verified.
- No ISP resolver tampered with answers for SNI-blocked domains. Korean
  blocking is currently done on SNI and `Host`, not in DNS; the `DnsBlocked`
  signature is kept only as a guard against a policy change.
