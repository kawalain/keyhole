# 0006. Implementation language: Rust

- Status: accepted (measured)
- Date: 2026-11-17

## Context

keyhole runs permanently on a router; resident memory and idle CPU are the
first priority. Go would make FreeBSD cross-compilation trivial but carries a
garbage collector and a larger resident set.

## Decision

- Write keyhole in Rust, pinned to the latest stable toolchain.
- Avoid an async runtime unless measurement shows threads cost more: the
  design needs only a few long-lived threads (observer, resolver, prober,
  proxy).
- Prefer the standard library and `libc` over large dependencies.

## Acceptance criteria

Mark accepted once a prototype on OPNsense measures, at idle and under a
scripted browsing load:

- resident memory below 10 MB,
- idle CPU indistinguishable from zero,
- release binary size.

Record the numbers here.

## Measurements

OPNsense 26.7 test VM (FreeBSD 15.1, 2 vCPU under KVM), keyhole release
build cross-compiled with `cross` 0.2.5, 2026-11-17:

| Condition | Resident memory | CPU time | Threads |
|---|---|---|---|
| Idle for 60 s after start | 4584 KiB | 0 ms in those 60 s (10 ms since start, including one probe) | 6 |
| After 300 DNS queries and 30 proxied HTTPS fetches | 4664 KiB | 55 ms in total | 6 |

Release binary: 529,816 bytes (stripped, LTO). Dependencies: `libc` on
FreeBSD only.
