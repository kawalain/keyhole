# 0013. Ad and tracker filtering: OPNsense's Unbound blocklist, not keyhole

- Status: accepted (seen on the OPNsense test VM)
- Date: 2026-11-17
- Supersedes: the "ad blocking is not replaced" consequence of [0004](0004-keyhole-as-dns-upstream.md)

## Context

keyhole is to replace AdGuard Home on the router, including its filter
lists and their automatic updates. OPNsense 26.7 already ships a blocklist
in Unbound (Services > Unbound DNS > Blocklist), seen on the test VM:

- presets including an AdGuard list, EasyList, EasyPrivacy, Steven Black,
  the HaGeZi range (Light to Ultimate, plus targeted lists) and OISD;
- custom list URLs (advanced mode), allowlist, blocklist and wildcard
  domains, per-client-network policies, NXDOMAIN or a chosen address;
- a configd action, "Update Unbound DNSBLs", that the cron page can run on a
  schedule.

Its parser (`scripts/unbound/blocklists/default_bl.py`) reads plain-domain
and hosts-format lines; it does not understand AdGuard rule syntax
(`||domain^`, `@@` exceptions, `$` modifiers).

Unbound sits in front of keyhole (ADR 0004), so a blocked name is answered
by Unbound and never reaches keyhole.

## Decision

- Filtering uses Unbound's blocklist. keyhole adds no filtering code.
- The keyhole settings page points to the blocklist page, and
  `docs/adguard-home-migration.md` describes the move from AdGuard Home.

## Consequences

- keyhole's memory and CPU stay as measured in ADR 0006; the blocklist's
  cost is Unbound's (the HaGeZi Light preset produced a 9.4 MB
  `dnsbl.json`).
- Lists that exist only in AdGuard syntax need a domains or hosts version.
- Seen on the test VM, 2026-11-17: with the HaGeZi Light preset and keyhole
  enabled, a listed domain resolved to `0.0.0.0` for a LAN client while
  keyhole still detected and bypassed `womenhelp.org`. A domain already in
  Unbound's cache kept resolving until the cache entry expired.
