# SENTINEL

**Live: https://sjgant80-hub.github.io/sentinel/**

A structural immune system. A command that is not signed, not within its capability budget, not at κ, and not unseen never becomes a command at all — the signature is verified before the six bytes are ever parsed. Sealed against a red-team battery; the grown detector re-runs in your browser.

## The result

6 of 6 sealed rules held. The gate dropped 72 of 72 attacks it had never seen with 0 of 48 valid packets wrongly dropped, and no forged packet was ever parsed. A detector GROWN against training streams caught 27 of 27 hostile held-out streams against the hand-set baseline's 11, flagging no legit stream.

| Sealed rule | Result | | Predicted |
|---|---|---|---|
| every structural attack is dropped (caught === attacks) | 72 of 72 structural attacks dropped | PASS | pass — the gate is correct by construction, but this proves there is no hole left open |
| no valid packet is dropped (falsePass === 0, valid > 0) | 0 valid packets wrongly dropped (of 48) | PASS | pass |
| no forged or tampered packet is ever parsed — each is judged forged, a verdict only the signature check can reach (parsedForged === 0) | 0 forged packets ever reached unpack | PASS | pass — the gate returns forged for a tampered payload, never off-κ |
| on the held-out streams the grown detector catches more hostile streams than the hand-set baseline | grown caught 27, hand-set baseline 11 (held-out) | PASS | pass, narrowly — the search should find a cut at least as good as the hand-set one; it could tie |
| the grown detector flags no legit held-out stream | no legit stream flagged | PASS | pass — a false pass is death in the fitness, so the grown detector cannot carry one |
| re-running the whole battery from the seal gives the same counts and the same grown detector — CI re-runs it on every push | CI re-runs the whole battery from the seal | PASS | pass |

## What it is

- `sentinel.mjs` — the kernel: the 6-byte Primorial-Fold codec (pack/unpack, the κ-witness), the verify-before-parse gate (check), the honeypot (phantom), and the grown stream detector (features, normalize, score, flags, fitness, grow). Pure and total; witness-gated.
- `streams.mjs` — the seeded hostile and legit streams, shared with the page.
- `tools/redteam.mjs` — the sealed battery: --seal, --run, --verify.

## Honest scope

- The signed-packet gate and one grown detector are measured. The honeypot and per-node quarantine are built and unit-tested as isolated local state.
- The antibody broadcast over LoRa / acoustics / NFC is hardware-dependent and is design only.
- Replay here is exact-bytes-seen; a production mesh needs monotonic counters.

## Credits

- The κ-witness is the primorial fold of Thomas Frumkin's Konomi codec; the capability lattice is the estate's wallet. Powered by the Konomi architecture, created by Thomas Frumkin.
- Code: MIT.
