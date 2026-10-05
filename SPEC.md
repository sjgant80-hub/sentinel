# sentinel — specification

## Purpose

SENTINEL: a structural immune system. A command that is not signed, within budget, at kappa and unseen never becomes a command at all - the signature is verified before the six bytes are parsed. Sealed against a red-team battery; the grown detector re-runs in the browser.

## Contract

- **better** — part of the sentinel public surface; deterministic, total (never throws).
- **check** — part of the sentinel public surface; deterministic, total (never throws).
- **features** — part of the sentinel public surface; deterministic, total (never throws).
- **fingerprint** — part of the sentinel public surface; deterministic, total (never throws).
- **fitness** — part of the sentinel public surface; deterministic, total (never throws).
- **flags** — part of the sentinel public surface; deterministic, total (never throws).
- **foldWitness** — part of the sentinel public surface; deterministic, total (never throws).
- **grade** — part of the sentinel public surface; deterministic, total (never throws).
- **grow** — part of the sentinel public surface; deterministic, total (never throws).
- **normalize** — part of the sentinel public surface; deterministic, total (never throws).
- **pack** — part of the sentinel public surface; deterministic, total (never throws).
- **phantom** — part of the sentinel public surface; deterministic, total (never throws).
- **popcount** — part of the sentinel public surface; deterministic, total (never throws).
- **rng** — part of the sentinel public surface; deterministic, total (never throws).
- **score** — part of the sentinel public surface; deterministic, total (never throws).
- **unpack** — part of the sentinel public surface; deterministic, total (never throws).

## Guarantees

- **Deterministic** — the same input yields the same output on any machine, any run.
- **Total** — hostile or malformed input returns a defined value, never an exception.
- **Zero-dependency** — no third-party runtime code inside the trust boundary.

## Verification

The suite exercises the public surface directly and is mutation-checked: a change to any guarded line makes a
test fail. konomify admits sentinel only when both the structure rubric (acg-assessor) and the behaviour gate
(witness) pass.
