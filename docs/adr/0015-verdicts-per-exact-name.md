# 0015. Verdicts stay per exact name; no registrable-domain generalisation

- Status: accepted (measured)
- Date: 2026-11-17
- Supersedes: the registrable-domain generalisation in [0008](0008-evidence-state-machine.md)

## Context

ADR 0008 planned to generalise verdicts on several subdomains to their
registrable domain (Public Suffix List), on the assumption that the censor
blocks whole domains. Measured on 2026-11-17 (`docs/kt-filter.md`): the KT
filter matches the exact name, case-insensitively and ignoring a trailing
dot, plus its `www.` form. `a.b.womenhelp.org`, `xwomenhelp.org` and
`womenhelp.org.example.com` all pass while `womenhelp.org` and
`www.womenhelp.org` are reset.

## Decision

- The classifier keeps one verdict per exact name, as it does today.
- No Public Suffix List and no generalisation step.

## Consequences

- Subdomains of a blocked name that the censor does not list are never
  bypassed needlessly.
- `www.` and the bare name are probed separately. Each costs one probe the
  first time a client uses it.
