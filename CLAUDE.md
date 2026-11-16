# keyhole

keyhole runs on an OPNsense router, detects Korean ISP censorship (SNI
resets, HTTP block-page redirects) and applies a bypass only to the domains
that need it. It is the final DNS upstream behind Unbound and forwards to the
ISP resolver.

## Read first

- Architecture decisions: `docs/adr/`. Proposed ADRs are not settled; do not
  build on them as fact until their acceptance criteria are measured.
- Unverified behaviour: `docs/verification-debt.md`. Add to it whatever a
  change could not verify; remove an entry once someone has seen it.

## Commands

- `cargo test`: unit tests; loopback sockets only, no external network.
- `cargo test -- --ignored`: live probes against the real network
  (`tests/live.rs`); they need a Korean ISP connection and `curl`.
- `cargo clippy --all-targets -- -D warnings` and `cargo fmt` before
  committing.

## Rules

- Scope is Korean ISP censorship on OPNsense only (ADR 0001). The Linux
  adapters exist for development, not deployment.
- Never route all DNS queries over an encrypted resolver. DNS goes to the ISP
  resolver only; an encrypted resolver comes back only through a new ADR once
  tampering is observed (ADR 0009).
- Resident memory and idle CPU come first. A feature with a measurable cost
  needs numbers before it lands.
- Blocking verdicts come from active probes, never from passive evidence alone
  (ADR 0002, 0008).
- `research/` holds one-off measurement scripts whose results are recorded in
  ADRs. Run them with `python3 -I`.
- Never deploy to or change the router without an explicit request.
