# 0008. Classification is an evidence-driven state machine, not ML

- Status: accepted; the registrable-domain generalisation superseded by [0015](0015-verdicts-per-exact-name.md)
- Date: 2026-11-17

## Context

keyhole has to learn which domains need a bypass. A machine-learned model
would cost memory and CPU, be hard to explain, and still need ground truth,
which an active probe provides directly.

## Decision

- A pure `Classifier` consumes evidence and probe outcomes with an injected
  clock and returns actions (probe, bypass, unbypass).
- Passive evidence only triggers a probe. A verdict comes from a control
  probe plus a strategy probe (see [0002](0002-korean-blocking-model.md)).
- Every verdict has an expiry and is re-verified with exponential backoff;
  verdicts on several subdomains are generalised to the registrable domain
  (Public Suffix List).

## Consequences

- Every bypass can be explained by the evidence and probe that produced it.
- The classifier is tested without a network, a clock or an operating system.
