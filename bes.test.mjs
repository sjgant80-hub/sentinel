// bes.test.mjs — behavior tests for the one-class Behavioral Entropy Signatures gate. Exercises the
// entropy math, the per-domain KL deviation, the GEP decision ladder at every boundary, and the held-out
// generalization, so the witness mutation gate catches a flipped operator.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { shannon, histogram, profile, klDiv, baseline, deviation, calibrate, decide, score, evaluate } from './bes.mjs';
import { windows, operatorWindow, scriptedWindow, randomWindow, CONFIG } from './behavior.mjs';

const approx = (a, b, eps = 1e-6) => Math.abs(a - b) < eps;

// ---------------- entropy ----------------
test('shannon: uniform two-state = ln2; a spike = 0; garbage = 0', () => {
  assert.ok(approx(shannon([0.5, 0.5]), Math.log(2)));
  assert.equal(shannon([1, 0]), 0);
  assert.equal(shannon([]), 0);
  assert.equal(shannon(null), 0);
});

test('histogram: aligns to the fixed vocab, smoothed, sums to ~1; unknown keys ignored; hours binned', () => {
  const w = [{ region: 'LON' }, { region: 'LON' }, { region: 'NW' }, { region: 'ZZZ' }];
  const h = histogram(w, 'region');
  assert.equal(h.length, 8);                              // REGIONS vocab size
  assert.ok(approx(h.reduce((a, b) => a + b, 0), 1, 1e-3));
  assert.ok(h[0] > h[1]);                                 // LON (idx 0) weightier than NW (idx 1)
  const hb = histogram([{ hour: 1 }, { hour: 2 }, { hour: 4 }], 'hour');
  assert.equal(hb.length, 8);                             // 8 three-hour bins
  assert.ok(hb[0] > hb[2]);                               // bin0 (hrs 0-2) got two, bin1 (3-5) got one
});

test('klDiv: identical distributions = 0; divergent > 0; length mismatch = 0', () => {
  assert.equal(klDiv([0.5, 0.5], [0.5, 0.5]), 0);
  assert.ok(klDiv([0.9, 0.1], [0.5, 0.5]) > 0);
  assert.equal(klDiv([1], [1, 0]), 0);
  assert.equal(klDiv(null, null), 0);
  assert.equal(klDiv([1], null), 0);        // one bad arg → 0, never touches .length (kills the guard || → &&)
  assert.equal(klDiv(null, [1]), 0);
  assert.doesNotThrow(() => klDiv([1], null));
});

test('klDiv: a zero in p is skipped (not NaN); a zero in q is skipped (not Infinity)', () => {
  assert.ok(approx(klDiv([0, 1], [0.5, 0.5]), Math.log(2)));      // p0=0 skipped → 1·ln(1/0.5)=ln2 (kills pi>0 → >=)
  assert.ok(approx(klDiv([0.9, 0.1], [0.5, 0]), 0.9 * Math.log(0.9 / 0.5))); // q1=0 skipped (kills qi>0 → >=)
});

test('profile: four aligned domain distributions', () => {
  const p = profile([{ region: 'LON', command: 'read', hour: 9, priv: 'user' }]);
  for (const f of ['region', 'command', 'hour', 'priv']) assert.ok(Array.isArray(p[f]) && p[f].length > 0);
});

// ---------------- baseline + deviation ----------------
test('baseline: aggregates operator windows; dev stats are a mean and a std, not sums; empty → n 0', () => {
  const b = baseline(windows(operatorWindow, 7, 20, 40));
  assert.equal(b.n, 20);
  assert.ok(Number.isFinite(b.devMean) && Number.isFinite(b.devStd) && b.devMean > 0);
  assert.ok(b.devMean < 1, `devMean ${b.devMean} — a mean, not a sum (kills the /n divisor on mean)`);
  assert.ok(b.devStd < 0.15, `devStd ${b.devStd} — a per-window std (~0.06), not sqrt(sum) (kills the /n divisor on variance)`);
  assert.equal(baseline([]).n, 0);
  assert.equal(baseline('nope').n, 0);
});

test('deviation: an operator window sits near baseline; an attack window sits far above it', () => {
  const b = baseline(windows(operatorWindow, 11, 40, 40));
  const op = deviation(operatorWindow((() => { let s = 99; return () => (s = (s * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff; })(), 40), b);
  const sc = deviation(scriptedWindow(() => 0, 40), b);
  assert.ok(sc.unified > op.unified);                     // the attack is more surprising under the operator baseline
  for (const k of ['net', 'beh', 'auth', 'unified']) assert.ok(Number.isFinite(sc[k]));
  assert.doesNotThrow(() => deviation([{ region: 'LON' }], null));  // a null base must not deref .profile (kills the && → ||)
});

// ---------------- calibrate + the decision ladder (every boundary) ----------------
test('calibrate: bands strictly ordered allow < block < isolate; tiny std falls back to a floor band', () => {
  const t = calibrate({ devMean: 0.2, devStd: 0.05 });
  assert.ok(t.allow < t.block && t.block < t.isolate);
  assert.ok(calibrate(null).allow >= 0);                  // garbage → safe bands, no throw
  // std at/below the 1e-9 guard uses the floor band max(mean·0.25, 0.05), not the vanishing std (kills > → >=)
  assert.ok(approx(calibrate({ devMean: 0.2, devStd: 1e-9 }).allow, 0.25));
});

const TH = { allow: 0.3, block: 0.5, isolate: 0.8 };
test('decide: below allow → ALLOW; AT allow → not ALLOW (kills the allow boundary)', () => {
  assert.equal(decide({ unified: 0.29, net: 0.29, beh: 0, auth: 0 }, TH).verdict, 'ALLOW');
  assert.equal(decide({ unified: 0.30, net: 0.30, beh: 0, auth: 0 }, TH).verdict, 'THROTTLE'); // u>=allow
});
test('decide: deviation band splits THROTTLE vs STEP-UP by authorization dominance (incl. ties)', () => {
  assert.equal(decide({ unified: 0.4, net: 0.4, beh: 0.0, auth: 0.0 }, TH).verdict, 'THROTTLE'); // net-dominant
  assert.equal(decide({ unified: 0.4, net: 0.1, beh: 0.1, auth: 0.4 }, TH).verdict, 'STEP-UP');  // auth-dominant
  assert.equal(decide({ unified: 0.4, net: 0.4, beh: 0.1, auth: 0.4 }, TH).verdict, 'STEP-UP');  // auth==net tie → STEP-UP (kills auth>=net → >)
  assert.equal(decide({ unified: 0.4, net: 0.1, beh: 0.4, auth: 0.4 }, TH).verdict, 'STEP-UP');  // auth==beh tie → STEP-UP (kills auth>=beh → >)
  assert.equal(decide({ unified: 0.4, net: 0.0, beh: 0.0, auth: 0.0 }, TH).verdict, 'THROTTLE'); // auth==0 → not escalation (kills auth>0 → >=)
});
test('decide: AT block → BLOCK (kills the block boundary); just below stays in the deviation band', () => {
  assert.equal(decide({ unified: 0.50, net: 0.2, beh: 0.2, auth: 0.1 }, TH).verdict, 'BLOCK');   // u>=block
  assert.equal(decide({ unified: 0.49, net: 0.2, beh: 0.2, auth: 0.1 }, TH).verdict, 'THROTTLE');
});
test('decide: AT isolate across ALL domains → ISOLATE; with ANY zero domain it is only BLOCK', () => {
  assert.equal(decide({ unified: 0.80, net: 0.3, beh: 0.3, auth: 0.2 }, TH).verdict, 'ISOLATE');  // all>0 and u>=isolate
  assert.equal(decide({ unified: 0.80, net: 0.5, beh: 0.3, auth: 0.0 }, TH).verdict, 'BLOCK');    // auth=0 → not all domains (kills auth>0 → >=)
  assert.equal(decide({ unified: 0.80, net: 0.0, beh: 0.4, auth: 0.4 }, TH).verdict, 'BLOCK');    // net=0 → not all domains (kills net>0 → >=)
  assert.equal(decide({ unified: 0.80, net: 0.4, beh: 0.0, auth: 0.4 }, TH).verdict, 'BLOCK');    // beh=0 → not all domains (kills beh>0 → >=)
  assert.equal(decide({ unified: 0.79, net: 0.3, beh: 0.3, auth: 0.2 }, TH).verdict, 'BLOCK');    // just below isolate (kills isolate >= → >)
});
test('decide: E rises with deviation, bounded in [0,1]; garbage → ALLOW, never throws', () => {
  assert.ok(decide({ unified: 0.1 }, TH).E < decide({ unified: 2 }, TH).E);
  assert.ok(decide({ unified: 10 }, TH).E < 1 && decide({ unified: 10 }, TH).E > 0.99);
  assert.ok(decide({ unified: 0 }, TH).E === 0);
  assert.equal(decide({ unified: NaN }, TH).E, 0);      // num() zeros NaN before E (kills num's && → ||)
  assert.doesNotThrow(() => decide(null, null));
  assert.equal(decide(null, null).verdict, 'ALLOW');
});

// ---------------- score + evaluate ----------------
test('score: ALLOW/THROTTLE are allowed; STEP-UP/BLOCK/ISOLATE are flagged', () => {
  const b = baseline(windows(operatorWindow, 5, 40, 40));
  assert.equal(score(operatorWindow((() => { let s = 3; return () => (s = (s * 48271) % 0x7fffffff) / 0x7fffffff; })(), 40), b).flagged, false);
  assert.equal(score(scriptedWindow(() => 0, 40), b).flagged, true);
});

test('evaluate: held-out — operator FP low, BOTH unseen attack families caught, generalizes true', () => {
  const base = baseline(windows(operatorWindow, CONFIG.trainSeed, CONFIG.trainCount, CONFIG.n));
  const r = evaluate(base,
    windows(operatorWindow, CONFIG.opHeldSeed, CONFIG.opHeldCount, CONFIG.n),
    windows(scriptedWindow, CONFIG.scriptSeed, CONFIG.scriptCount, CONFIG.n),
    windows(randomWindow, CONFIG.randSeed, CONFIG.randCount, CONFIG.n));
  assert.ok(r.operator.fpRate <= 0.1, `operator FP ${r.operator.fpRate}`);
  assert.ok(r.scripted.detect >= 0.9 && r.random.detect >= 0.9);
  assert.ok(r.operator.n > 0 && r.scripted.n > 0 && r.random.n > 0);
});

test('evaluate: garbage inputs → zeros, never throws', () => {
  assert.doesNotThrow(() => evaluate(null, null, null, null));
  const r = evaluate({ devMean: 0.2, devStd: 0.05 }, [], [], []);
  assert.equal(r.operator.n, 0);
  assert.equal(r.operator.fpRate, 0);
});
