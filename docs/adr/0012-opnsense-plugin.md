# 0012. OPNsense plugin: settings page, rc.d service, generated includes

- Status: accepted (seen on the OPNsense test VM); the filter anchor superseded by [0014](0014-leave-quic-alone.md)
- Date: 2026-11-17

## Context

keyhole has to start at boot, and its upstream DNS server and LAN interface
have to be set without a shell. OPNsense plugins follow one layout
(`opnsense/plugins`, e.g. `net/cloudflared`): an MVC model and form, API
controllers, configd actions and templates rendered into the system.

## Decision

`opnsense/` is laid out as an OPNsense plugin (`Makefile`, `pkg-descr`,
`src/` installed under `/usr/local`):

- Settings (Services > keyhole): enable, LAN interface, upstream DNS server
  (IPv4, optional `:port`, default port 53). Stored under
  `//OPNsense/Keyhole`.
- Apply renders two templates and restarts the service, the firewall and
  Unbound:
  - `/etc/rc.conf.d/keyhole`: `keyhole_enable` and `keyhole_options`
    (`--lan <physical interface> --upstream <addr:port>`);
  - `/usr/local/etc/unbound.opnsense.d/keyhole.conf`: the forward to keyhole,
    empty while keyhole is disabled.
- `src/etc/rc.d/keyhole` runs the daemon through daemon(8) with output to
  syslog; stopping it flushes the `keyhole` anchor. OPNsense's boot
  (`rc.freebsd`) starts it when `keyhole_enable` is `YES`.
- `plugins.inc.d/keyhole.inc` registers the pf anchors and lists the service
  only while keyhole is enabled.

## Consequences

Seen on the test VM, 2026-11-17: invalid upstream values are rejected in the
form; Apply starts keyhole and loads the anchors; after a reboot keyhole
starts on its own and bypasses a blocked site; disabling stops it, removes
the anchors and returns Unbound to resolving by itself.

The plugin is installed by copying files (`vm/install-plugin.sh`); building
a package needs the `opnsense/plugins` tree and is not set up yet.
