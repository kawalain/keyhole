# 0001. Scope: OPNsense router, Korean ISP censorship only

- Status: accepted
- Date: 2026-11-17

## Context

keyhole detects censorship and applies a bypass only to the domains that need
it. Censorship systems differ per country: Korean ISPs inject resets and block
pages, while Russian TSPU drops packets inline and needs fake-packet tricks
that require raw packet injection.

## Decision

- keyhole runs on an OPNsense (FreeBSD) router and serves the whole LAN.
- It targets Korean ISP censorship only. Russian support is dropped.
- A Linux adapter exists only so the code can be developed and tested on a
  Linux workstation; it is not a supported deployment target.

## Consequences

- No packet-level path (`divert(4)`, fake packets) is needed; a userspace
  transparent proxy is enough (see [0003](0003-bypass-tls-record-fragmentation.md)).
- Detection only has to recognise Korean block signatures
  (see [0002](0002-korean-blocking-model.md)).
