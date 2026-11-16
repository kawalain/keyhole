# 0005. DNS upstream policy: ISP resolver first, encrypted only when blocked

- Status: accepted (policy); proposed (detection heuristic)
- Date: 2026-11-17

## Context

Sending every query over DoT avoids DNS tampering without any detection, but
it applies a bypass to everything, contradicting the project's goal, and
loses the ISP resolver's CDN answers that are close to the user.

## Decision

- Every query goes to the ISP resolver by default.
- Sending all queries over DoT is not an option. The encrypted resolver is used
  only to:
  1. cross-check a suspicious ISP answer (NXDOMAIN, or an address in the known
     block-page set), and
  2. resolve domains with a `DnsBlocked` verdict.
- The known block-page set starts from the addresses `warning.or.kr` resolves
  to and grows from confirmed `DnsBlocked` verdicts.

## Consequences

- Encrypted-resolver traffic stays proportional to blocked or suspicious
  domains, not to all browsing.
- A tampered answer that looks ordinary (a real-looking address that is not a
  block page) is not caught by this heuristic. Whether Korean ISP resolvers do
  that has not been measured; the heuristic stays proposed until it has.
