# 0006. Implementation language: Rust

- Status: proposed
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
