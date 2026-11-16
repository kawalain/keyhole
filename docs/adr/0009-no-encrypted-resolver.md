# 0009. No encrypted resolver until DNS tampering is observed

- Status: accepted (measured)
- Date: 2026-11-17
- Supersedes: [0005](0005-dns-upstream-policy.md)

## Context

ADR 0005 planned an encrypted resolver (DoT, via rustls) to cross-check
suspicious ISP answers and to resolve DNS-blocked domains. Measurement since
then (ADR 0002) found that the KT, SKB and LGU+ resolvers return real
addresses for every SNI-blocked domain tested. The encrypted path would guard
only against a policy change nobody has observed, at the cost of a TLS stack
in the binary.

## Decision

- keyhole forwards every query to the ISP resolver only. There is no
  encrypted resolver and no TLS library.
- A suspicious ISP answer (NXDOMAIN for a domain that previously resolved,
  or an address in the block-page set) is logged, not acted on.
- The classifier has no DNS layer; it classifies SNI/`Host` blocking only.
- Never route all queries over an encrypted resolver (unchanged from 0005).

## Consequences

- If the logs ever show tampering, a new ADR reintroduces a DNS layer, with
  rustls as the TLS implementation the project already agreed on.
- The binary stays free of a TLS stack.
