// streams.mjs — the synthetic hostile and legit STREAMS the grown detector is evolved and measured on. Nothing secret:
// each stream is a window of individually-valid commands, seeded, so the browser and CI grow the same detector. Shared by
// the red-team harness and inlined verbatim into the live page.
import { rng } from './sentinel.mjs';

// a reasonable hand-set detector to beat: flag a wide fan-out or a large budget draw (over normalized features)
export const BASELINE = { weights: [0, 1, 1, 0, 0], threshold: 0.4 };

export function streams(cfg, seed, n) {
  const sources = (cfg && cfg.sources) || 4;
  const r = rng(seed);
  const d = (k) => Math.floor(r() * k);
  const out = [];
  for (let i = 0; i < n; i++) {
    const attack = d(2) === 0;
    const w = [];
    if (attack) {
      const shape = d(3);
      if (shape === 0) { const src = d(sources); const m = 6 + d(8); for (let k = 0; k < m; k++) w.push({ source: src, target: d(16), resources: 1 << d(6), budget: 1 + d(20) }); }        // scan: one source, many targets
      else if (shape === 1) { const src = d(sources); const m = 1 + d(3); for (let k = 0; k < m; k++) w.push({ source: src, target: d(16), resources: 0b00111111, budget: 20000 + d(40000) }); } // drain: a huge budget draw
      else { const src = d(sources); const m = 14 + d(12); for (let k = 0; k < m; k++) w.push({ source: src, target: d(3), resources: 1 << d(6), budget: 1 + d(10) }); }                     // burst: a high packet rate
    } else {
      const src = d(sources); const m = 1 + d(4); const tgt = d(16);
      for (let k = 0; k < m; k++) w.push({ source: src, target: tgt + (d(2) ? 0 : 1), resources: 1 << d(2), budget: 1 + d(50) });
    }
    out.push({ attack, window: w });
  }
  return out;
}
