# Moving from AdGuard Home to keyhole and Unbound's blocklist

The router's DNS chain changes from

    clients -> Unbound -> AdGuard Home -> upstream

to

    clients -> Unbound (cache, blocklist) -> keyhole -> ISP resolver

Filtering moves into Unbound's own blocklist (ADR 0013); keyhole forwards
what is left to the ISP resolver and handles censorship (ADR 0004, 0009).

## 1. Note what AdGuard Home does today

Before changing anything, write down from AdGuard Home:

- the filter lists (name and URL) and custom rules,
- allowlisted domains,
- per-client settings, if any,
- the update interval.

## 2. Remove Unbound's forwarding to AdGuard Home

keyhole installs its own catch-all forward (`forward-zone "."`). Unbound
keeps only the first catch-all forward it reads and ignores the next with a
single log line (`duplicate forward zone . ignored`, seen on the test VM).
If the forward to AdGuard Home is read first, keyhole is silently skipped.

Services > Unbound DNS > Query Forwarding: delete the entry that sends all
domains to AdGuard Home, and turn off "Use System Nameservers" there if it
was turned on for AdGuard Home. Do not apply yet if AdGuard Home must keep
serving until keyhole is ready; do steps 2 to 4 together.

## 3. Set up the blocklist

Services > Unbound DNS > Blocklist > Add:

- **Type of DNSBL**: pick presets. "AdGuard List" corresponds to AdGuard
  Home's default filter; the HaGeZi presets (Light to Ultimate) and OISD
  are common replacements for larger lists.
- **URLs of Blocklists** (advanced mode): lists from AdGuard Home that are
  not presets. Use their plain-domain or hosts version: Unbound does not read
  AdGuard rule syntax (`||domain^`, `@@...`, `$...`).
- **Allowlist Domains**: AdGuard Home's allowlist and `@@` rules.
- **Blocklist Domains** / **Wildcard Domains**: custom blocking rules.
- **Source Net(s)**: per-client policies, if AdGuard Home had them.

Save, then Apply.

## 4. Enable keyhole

Services > keyhole:

- **Enable**: on.
- **LAN interface**: the interface clients use.
- **Upstream DNS server**: the ISP resolver, e.g. `168.126.63.1` for KT,
  `219.250.36.130` for SK Broadband, `164.124.101.2` for LG U+.

Apply. keyhole starts, and Unbound forwards to it.

## 5. Update the lists automatically

System > Settings > Cron > Add: command "Update Unbound DNSBLs", for
example daily at an hour outside peak use.

## 6. Check, then remove AdGuard Home

From a LAN client:

- a domain from one of the lists resolves to `0.0.0.0`;
- an ordinary site resolves normally;
- a censored site loads from the second attempt on.

Then stop and uninstall AdGuard Home.

## What does not carry over

- AdGuard rule syntax and `$` modifiers (see step 3).
- AdGuard Home's query log and statistics pages; Unbound's own reporting
  (Reporting > Unbound DNS) covers queries and blocks.
- A newly listed domain that is already in Unbound's cache keeps resolving
  until its cache entry expires.
