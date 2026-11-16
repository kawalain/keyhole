# 0016. Distribution: a signed pkg repository on the `pkg` branch

- Status: proposed
- Date: 2026-11-17

## Context

The router has to install, update and remove keyhole without copying files
by hand. OPNsense installs plugins as FreeBSD packages (`os-<name>`) and
accepts extra pkg repositories under `/usr/local/etc/pkg/repos/`.

## Decision

- `vm/build-pkg.sh` stages the daemon and `opnsense/src`, writes a manifest
  whose scripts mirror `opnsense/plugins`' `Mk/plugins.mk` plus the
  plugin's `+*.pre`/`+*.post` files, and runs `pkg create` and `pkg repo`
  in the router VM, which has FreeBSD's pkg tools.
- The repository is signed with an RSA key kept outside the repository
  (`~/.config/keyhole/pkg-signing.key` by default); the public key is
  `opnsense/pkg/keyhole.pub`.
- The repository lives on an orphan branch `pkg`, under the ABI directory
  (`FreeBSD:15:amd64/`), served from `raw.githubusercontent.com`.
  `opnsense/pkg/keyhole.conf` points pkg at it.
- Removing the package also removes the generated Unbound forward and
  restarts Unbound, so DNS survives the removal.

## Acceptance criteria

Mark accepted once the OPNsense test VM, with nothing installed by hand,
installs `os-keyhole` from the published branch with signature checking,
runs keyhole from the settings page, and removes it with DNS still working.

## Consequences

- The public key is served from the same GitHub repository as the
  packages, so the signature protects against tampering with the `pkg`
  branch's files in transit or by the host, not against a compromise of
  the repository itself; the key's fingerprint is published for an
  out-of-band check.
- Each release replaces the branch's contents; old versions are not kept.
