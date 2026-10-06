// bes-verify.mjs — re-derive the held-out generalization on GitHub's runner from the seeded operator and
// the two UNSEEN attack families, using the mutation-gated bes.mjs. This is the honest answer to flag3:
// the grown two-class detector overfit its clean margin; this one-class model, calibrated on the OPERATOR
// alone, is measured against attack families it never saw. Deterministic (seeded) → byte-identical here.
//   node bes-verify.mjs           → derive + print
//   node bes-verify.mjs --check   → derive + check bes.predictions.json (CI)
import { readFileSync } from 'node:fs';
import { windows, operatorWindow, scriptedWindow, randomWindow, CONFIG } from './behavior.mjs';
import { baseline, calibrate, evaluate } from './bes.mjs';

export function derive() {
  const base = baseline(windows(operatorWindow, CONFIG.trainSeed, CONFIG.trainCount, CONFIG.n));
  const r = evaluate(base,
    windows(operatorWindow, CONFIG.opHeldSeed, CONFIG.opHeldCount, CONFIG.n),
    windows(scriptedWindow, CONFIG.scriptSeed, CONFIG.scriptCount, CONFIG.n),
    windows(randomWindow, CONFIG.randSeed, CONFIG.randCount, CONFIG.n));
  const r4 = (x) => Math.round(x * 10000) / 10000;
  return {
    devMean: r4(base.devMean), devStd: r4(base.devStd), trainN: base.n,
    opN: r.operator.n, opFalse: r.operator.falseFlags, opFpRate: r.operator.fpRate,
    scriptN: r.scripted.n, scriptCaught: r.scripted.caught, scriptDetect: r.scripted.detect,
    randN: r.random.n, randCaught: r.random.caught, randDetect: r.random.detect,
    // the GENERALIZES judgment lives here, not in the kernel: operator FP ≤ 0.1 AND each unseen family ≥ 0.9
    generalizes: r.operator.fpRate <= 0.1 && r.scripted.detect >= 0.9 && r.random.detect >= 0.9,
  };
}

if (typeof process !== 'undefined' && process.argv && process.argv[1] && process.argv[1].endsWith('bes-verify.mjs')) {
  const m = derive();
  console.log(JSON.stringify(m));
  if (process.argv.includes('--check')) {
    const preds = JSON.parse(readFileSync(new URL('./bes.predictions.json', import.meta.url), 'utf8'));
    let fail = 0;
    for (const [k, v] of Object.entries(preds.expected)) if (m[k] !== v) { console.error(`MISMATCH ${k}: expected ${v}, got ${m[k]}`); fail++; }
    const holds = (e) => { const { devMean, devStd, trainN, opN, opFalse, opFpRate, scriptN, scriptCaught, scriptDetect, randN, randCaught, randDetect, generalizes } = m; try { return !!eval(e); } catch { return false; } };
    for (const c of preds.claims) if (!holds(c.check)) { console.error(`CLAIM FAIL ${c.id}: ${c.check}`); fail++; }
    if (fail) { console.error(`\n${fail} mismatch(es).`); process.exit(1); }
    console.log('✓ held-out generalization re-derived; all', preds.claims.length, 'claims hold.');
  }
}
