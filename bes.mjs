// bes.mjs — Behavioral Entropy Signatures: the ONE-CLASS answer to flag3 (the grown two-class stream
// detector overfit its clean margin and did not transfer under distribution shift). Instead of learning
// where attacks sit, model the OPERATOR's own behavioral entropy across three domains and flag deviation
// from the operator's OWN baseline — so an attack family the model never saw is caught by construction.
//
// ⚑⚑ CREDIT: a faithful implementation of Gary W. Floyd — Lumiea Systems Research Division, ThunderStruck
// Service LLC — "GEP-Based Security: Behavioral Entropy Signatures for Cybersecurity and DevOps" (2025):
// three entropy domains (network H_net / behavioral H_beh / authorization H_auth), a unified entropy state
// S = w_n·H_net + w_b·H_beh + w_a·H_auth, and the GEP security decision function E(t)/A(t)/ΔS → the ladder
// ALLOW / THROTTLE / STEP-UP / BLOCK / ISOLATE. "Identity is insufficient. Behavior is authoritative."
// "Credential validity does not override entropy violation." Honest scope (Gary §8): this performs STABILITY
// REGULATION — are you behaving like yourself — NOT morality, intent, or malware classification.
//
// Pure and total: garbage in → a safe structured result, never a throw. No I/O, no clock.
import { REGIONS, COMMANDS, PRIV } from './behavior.mjs';

const isArr = Array.isArray;
const isObj = (v) => v && typeof v === 'object' && !isArr(v);
const num = (v) => (typeof v === 'number' && Number.isFinite(v) ? v : 0);
const EPS = 1e-6; // Laplace-ish smoothing so KL stays finite (the §3 zero-collapse guard, in spirit).

// the three domains' vocabularies (fixed supports so distributions align for KL). hour → 8 three-hour bins.
const HOURBINS = 8;
const VOCAB = { region: REGIONS, command: COMMANDS, priv: PRIV, hour: Array.from({ length: HOURBINS }, (_, i) => i) };
// 24 hours → 8 three-hour bins. ((x%24)+24)%24 ∈ [0,24) so /3 ∈ [0,8) and floor ∈ 0..7 — always in range.
const hourbin = (h) => Math.floor((((num(h) % 24) + 24) % 24) / 3);

/** Shannon entropy of a probability vector, in nats. */
export function shannon(probs) {
  if (!isArr(probs)) return 0;
  let h = 0;
  for (const p of probs) { const q = num(p); if (q > 0) h -= q * Math.log(q); }
  return h;
}

/** histogram of one field over its fixed vocabulary → smoothed probability vector (aligned, sums to 1). */
export function histogram(events, field) {
  const vocab = VOCAB[field] || [];
  const idx = new Map(vocab.map((v, i) => [String(v), i]));
  const counts = new Array(vocab.length).fill(0);
  let n = 0;
  for (const e of (isArr(events) ? events : [])) {
    if (!isObj(e)) continue;
    const key = field === 'hour' ? String(hourbin(e.hour)) : String(e[field]);
    const i = idx.get(key);
    if (i !== undefined) { counts[i] += 1; n += 1; }
  }
  const probs = counts.map((c) => (c + EPS) / (n + EPS * vocab.length));
  return probs;
}

/** the profile of a window: one smoothed distribution per field. */
export function profile(window) {
  return { region: histogram(window, 'region'), command: histogram(window, 'command'), hour: histogram(window, 'hour'), priv: histogram(window, 'priv') };
}

/** KL(p ‖ q) in nats — how surprising p is under the baseline q. Both are aligned smoothed vectors. */
export function klDiv(p, q) {
  if (!isArr(p) || !isArr(q) || p.length !== q.length) return 0;
  const d = p.reduce((acc, pv, i) => { const pi = num(pv), qi = num(q[i]); return (pi > 0 && qi > 0) ? acc + pi * Math.log(pi / qi) : acc; }, 0);
  return Math.max(0, d); // KL ≥ 0 for proper distributions; the max is a defensive floor (no branch to mutate)
}

const WEIGHTS = Object.freeze({ net: 1, beh: 1, auth: 1 }); // domain weights for the unified deviation.

/** average a set of profiles into one baseline profile (the operator's signature). */
export function baseline(trainWindows) {
  const wins = (isArr(trainWindows) ? trainWindows : []).filter(isArr);
  const fields = ['region', 'command', 'hour', 'priv'];
  const acc = {}; for (const f of fields) acc[f] = new Array(VOCAB[f].length).fill(0);
  for (const w of wins) { const pr = profile(w); for (const f of fields) for (let i = 0; i < acc[f].length; i++) acc[f][i] += pr[f][i]; }
  const k = wins.length || 1;
  const prof = {}; for (const f of fields) prof[f] = acc[f].map((s) => s / k);
  // operator self-deviation stats, computed ONLY on operator windows — the threshold is set from the
  // operator alone, never from any attack. This is why held-out attack families generalize.
  const devs = wins.map((w) => deviation(w, { profile: prof }).unified);
  const mean = devs.reduce((a, b) => a + b, 0) / (devs.length || 1);
  const variance = devs.reduce((a, b) => a + (b - mean) * (b - mean), 0) / (devs.length || 1);
  const std = Math.sqrt(variance);
  return { profile: prof, devMean: mean, devStd: std, n: wins.length };
}

/** per-domain KL deviation of a window from the baseline profile, mapped to Gary's three domains:
 *  net = where+when (region + hour), beh = what (command), auth = privilege. */
export function deviation(window, base) {
  const bp = isObj(base) && isObj(base.profile) ? base.profile : {};
  const p = profile(window);
  const safe = (f) => (isArr(bp[f]) ? bp[f] : p[f].map(() => 1 / p[f].length));
  const net = klDiv(p.region, safe('region')) + klDiv(p.hour, safe('hour'));
  const beh = klDiv(p.command, safe('command'));
  const auth = klDiv(p.priv, safe('priv'));
  const unified = WEIGHTS.net * net + WEIGHTS.beh * beh + WEIGHTS.auth * auth;
  return { net, beh, auth, unified };
}

/** calibrate the gate's thresholds from the operator baseline alone (mean + k·std bands). Three bands map
 *  onto Gary's decision table: below `allow` = normal; `allow`..`block` = deviation; ≥`block` = violation;
 *  ≥`isolate` across all domains = critical anomaly. The thresholds come from the operator ONLY. */
export function calibrate(base) {
  const m = num(base && base.devMean), s = num(base && base.devStd);
  const band = s > 1e-9 ? s : Math.max(m * 0.25, 0.05);
  return { allow: m + 1 * band, block: m + 3 * band, isolate: m + 5 * band };
}

/** GEP security decision (Gary §3 table). The unified deviation is the instability field E(t):
 *   below `allow` → ALLOW; in the deviation band → STEP-UP when the deviation is AUTHORIZATION-dominant
 *   (a privilege/escalation signal — "step up auth"), else THROTTLE; at/above `block` → BLOCK (entropy
 *   violation); at/above `isolate` AND deviating across ALL three domains → ISOLATE (critical anomaly).
 *   Credential validity never enters — only the entropy state. Returns verdict + E + the three domains. */
export function decide(dev, th) {
  const t = isObj(th) ? th : calibrate();
  const u = num(dev && dev.unified);
  const net = num(dev && dev.net), beh = num(dev && dev.beh), auth = num(dev && dev.auth);
  const E = 1 - Math.exp(-u); // bounded instability pressure in [0,1): rises with deviation.
  let verdict;
  if (u >= t.isolate && net > 0 && beh > 0 && auth > 0) verdict = 'ISOLATE';
  else if (u >= t.block) verdict = 'BLOCK';
  else if (u >= t.allow) verdict = (auth >= net && auth >= beh && auth > 0) ? 'STEP-UP' : 'THROTTLE';
  else verdict = 'ALLOW';
  return { verdict, E, unified: u, net, beh, auth };
}

/** score one window against a calibrated baseline. allowed = ALLOW/THROTTLE pass; flagged otherwise. */
export function score(window, base, th) {
  const dev = deviation(window, base);
  const t = th || calibrate(base);
  const d = decide(dev, t);
  const allowed = d.verdict === 'ALLOW' || d.verdict === 'THROTTLE'; // flagged is its negation — one expression, one truth
  return { ...d, allowed, flagged: !allowed };
}

/** evaluate held-out generalization: operator false-positive rate + detection of each UNSEEN attack family.
 *  The gate was calibrated on operator windows only; these attack families were never used to set it. */
export function evaluate(base, heldOperator, scripted, random) {
  const th = calibrate(base);
  const run = (wins) => { const w = (isArr(wins) ? wins : []).filter(isArr); let flagged = 0; for (const x of w) if (score(x, base, th).flagged) flagged += 1; return { n: w.length, flagged }; };
  const op = run(heldOperator), sc = run(scripted), rd = run(random);
  const r3 = (x) => Math.round(x * 1000) / 1000;
  // raw held-out metrics only. The GENERALIZES judgment (operator FP ≤ 0.1, each attack family ≥ 0.9)
  // is a sealed CLAIM in bes.predictions.json, not a kernel field — keeps the kernel a measurement.
  return {
    thresholds: th,
    operator: { n: op.n, falseFlags: op.flagged, fpRate: op.n ? r3(op.flagged / op.n) : 0 },
    scripted: { n: sc.n, caught: sc.flagged, detect: sc.n ? r3(sc.flagged / sc.n) : 0 },
    random: { n: rd.n, caught: rd.flagged, detect: rd.n ? r3(rd.flagged / rd.n) : 0 },
  };
}
