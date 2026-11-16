# 0004. keyhole is the final DNS upstream behind Unbound

- Status: accepted; the ad-blocking consequence is superseded by [0013](0013-filtering-with-unbound-dnsbl.md)
- Date: 2026-11-17

## Context

The router currently resolves through Unbound → AdGuard Home. AdGuard Home
will be removed once keyhole is ready, so the DNS chain becomes
clients → Unbound (cache) → keyhole → upstream resolvers.

## Decision

- keyhole serves DNS to Unbound on a local address and is its only forwarder.
- Before keyhole returns an answer for a domain with a bypass verdict, it adds
  the answer's addresses to the bypass address table. The client's first
  connection therefore already takes the bypass path, even when the CDN
  rotates addresses.
- Table entries outlive the record TTL by a grace period, because Unbound may
  serve expired records.
- Domain-to-address mapping also comes from observed ClientHello destinations,
  for clients that bypass the router's DNS (browser DoH).

## Consequences

- keyhole sees only Unbound cache misses. That is enough because every
  answer that reaches a client passed through keyhole once per TTL.
- The very first visit to a blocked, not-yet-known domain still fails once:
  detection needs that failure. Probing every new domain in advance would
  cost more than the project's resource budget allows.
- Ad blocking from AdGuard Home is not replaced.
