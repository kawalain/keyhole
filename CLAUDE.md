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
- FreeBSD build: `CROSS_CONTAINER_ENGINE=podman cross build --release
  --target x86_64-unknown-freebsd` (`cross test --no-run` puts test
  executables under `target/x86_64-unknown-freebsd/release/build/`).

## Test VMs

`vm/` runs a disposable OPNsense router VM and an Alpine client VM with QEMU,
without root. Images and disks live in `~/.cache/keyhole-vm/`, never in the
repository. The router's WAN goes out through the host's own connection, so
the real ISP DPI applies; its LAN is a private link to the client VM.

1. `vm/fetch.sh` downloads and verifies the images (delete
   `opnsense.qcow2` to reset the router).
2. `vm/router.sh` (foreground; run it in the background), then
   `vm/setup-router.sh` once per fresh disk to enable key-based SSH.
3. `vm/ssh.sh [command]` logs in as root; the root shell is csh, so pipe
   scripts to `vm/ssh.sh sh -s`.
4. `vm/client.sh` starts the LAN client.
5. `vm/client-exec.sh 'command'` runs a command on the client over its
   serial console.
6. End to end: `vm/install-plugin.sh` copies the release binary and the
   plugin (`opnsense/src`) into the router; enable keyhole under
   Services > keyhole (GUI through `ssh -L 9443:127.0.0.1:443`, login
   root/opnsense), then curl a blocked site from the client twice.
7. `tests/vm.rs` holds FreeBSD-only checks run inside the router VM: copy
   the cross-built test executable over and run it with `--ignored` while
   the client connects.

## Releases

1. Bump the version (SemVer, major 0) in `Cargo.toml` and
   `opnsense/Makefile`.
2. Cross-build, then `vm/build-pkg.sh <dir>` builds and signs the pkg
   repository in the router VM. The signing key stays outside the
   repository (`KEYHOLE_PKG_KEY`, default `~/.config/keyhole/`); never
   commit it.
3. Replace the contents of the orphan `pkg` branch with `<dir>` and push it
   (ADR 0016).

These VMs are test fixtures, not the user's router: changing them needs no
separate request.

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
