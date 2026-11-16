# Installing keyhole on OPNsense

keyhole is published as the `os-keyhole` package in a signed pkg
repository on this project's `pkg` branch. It is built for OPNsense 26.7
(FreeBSD 15, amd64).

## 1. Add the repository

As root on the router (Console option 8, or SSH):

```sh
fetch -o /usr/local/etc/pkg/repos/keyhole.conf https://raw.githubusercontent.com/kawalain/keyhole/main/opnsense/pkg/keyhole.conf
mkdir -p /usr/local/etc/pkg/keys
fetch -o /usr/local/etc/pkg/keys/keyhole.pub https://raw.githubusercontent.com/kawalain/keyhole/main/opnsense/pkg/keyhole.pub
pkg update -r keyhole
```

pkg checks every package against that public key. Compare
`sha256 /usr/local/etc/pkg/keys/keyhole.pub` with
`6ea53234d917486a32439c7eaf2cb7028141251674d525ec0e4bf18cd578d39e`
(also in `opnsense/pkg/keyhole.pub.sha256`) before going on.

## 2. Install

```sh
pkg install -r keyhole os-keyhole
```

Then, in the web interface, Services > keyhole: enable it, choose the LAN
interface and enter the ISP's DNS server. Coming from AdGuard Home, follow
`docs/adguard-home-migration.md` instead, which includes this step.

## Update

```sh
pkg update -r keyhole && pkg upgrade -r keyhole os-keyhole
```

The package restarts keyhole, the firewall rules and Unbound after an
upgrade.

## Remove

```sh
pkg delete os-keyhole
```

Removing the package stops keyhole, removes its firewall anchor and its
Unbound forward, and restarts Unbound so that DNS keeps working. The
settings stay in the configuration for a later reinstall. Remove the
repository with `rm /usr/local/etc/pkg/repos/keyhole.conf
/usr/local/etc/pkg/keys/keyhole.pub`.
