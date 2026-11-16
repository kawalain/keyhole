# Verification debt

Behaviour that tests cannot reach yet. Each entry says what was seen and what
still needs a real router, a real ISP path or a real service.

- **Uneven inspection** (`docs/kt-filter.md`): which destinations the
  filter inspects varied between runs on one KT line. Not measured on other
  KT lines, SK Broadband or LG U+.
- **Plain-HTTP keep-alive** ([0011](adr/0011-http-decoy-request.md)): only
  the first request on a proxied connection gets the decoy. Not seen with a
  real browser; needs a browser session against a blocked HTTP-only site.
- **QEMU in front of the WAN** ([0007](adr/0007-freebsd-interception.md)):
  the test VM's WAN is QEMU user-mode NAT, which terminates TCP itself. pf,
  BPF and the bypass were seen working there, but not on a router whose WAN
  faces the ISP directly. Needs the real router.
- **Resource budget on real hardware** ([0006](adr/0006-language-rust.md)):
  measured only in the KVM test VM with light load. Needs numbers from the
  real router under a household's normal browsing.
- **Reaction time**: in the test VM a block was detected, probed and
  bypassed about 1.1 s after the first reset; a connection started in that
  second was still reset. Not measured on the real router.
- **Plugin package** ([0012](adr/0012-opnsense-plugin.md)): the plugin was
  only installed by copying files. Needs a package build in the
  `opnsense/plugins` tree and an install on the real router.
- **Scheduled blocklist updates** ([0013](adr/0013-filtering-with-unbound-dnsbl.md)):
  the blocklist was applied by hand in the test VM; a cron job running
  "Update Unbound DNSBLs" was not seen to run. Needs a scheduled run checked
  on the real router.
- **Migration from AdGuard Home** (`docs/adguard-home-migration.md`): not
  followed on the real router. A duplicate catch-all forward was seen to be
  ignored (not fatal) in the test VM, but which one wins when Query
  Forwarding holds the AdGuard Home entry was not checked.
