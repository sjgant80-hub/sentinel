// behavior.mjs — the seeded operator and the held-out attack families, shared with the page (the way
// streams.mjs is shared). Deterministic (a seeded PRNG, no clock, no Math.random), so bes-verify re-derives
// byte-identically on the runner. The operator has STRUCTURED variance — irregular hours, a couple of home
// regions, a working command set, rare privilege elevations — exactly the kind of operator Gary W. Floyd's
// GEP-BES is built for ("high variance, but structured, not random").
//
// CREDIT: the behavioral-entropy model this feeds is Gary W. Floyd's — Lumiea Systems Research Division,
// ThunderStruck Service LLC — "GEP-Based Security: Behavioral Entropy Signatures for Cybersecurity and
// DevOps" (2025). Three domains (network / behavioral / authorization), one-class: model the operator,
// flag deviation from the operator's OWN baseline. Attackers fail by being overly regular (scripted) or
// randomly variant uncorrelated with the operator.

export const REGIONS = ['LON', 'NW', 'SE', 'SW', 'NE', 'EU', 'US', 'ASIA'];
export const COMMANDS = ['read', 'test', 'deploy', 'config', 'grant', 'revoke', 'scan', 'exfil'];
export const PRIV = ['user', 'elevated', 'root'];
export const HOURS = 24;

// mulberry32 — a tiny deterministic PRNG. Same one the estate's seeded generators use.
export function rng(seed) {
  let a = seed >>> 0;
  return function () { a |= 0; a = (a + 0x6d2b79f5) | 0; let t = Math.imul(a ^ (a >>> 15), 1 | a); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
}
// weighted pick from a {key: weight} map, deterministic given r ∈ [0,1).
function pick(r, weights) {
  let total = 0; for (const k in weights) total += weights[k];
  let x = r * total;
  for (const k in weights) { x -= weights[k]; if (x < 0) return k; }
  return Object.keys(weights)[0];
}
// the operator's own distributions — structured, not uniform, not a single spike.
const OP_REGION = { LON: 0.46, NW: 0.3, SE: 0.14, SW: 0.05, NE: 0.03, EU: 0.02 };
const OP_CMD = { read: 0.35, test: 0.25, deploy: 0.2, config: 0.14, grant: 0.05, revoke: 0.01 };
const OP_PRIV = { user: 0.93, elevated: 0.06, root: 0.01 };
// circadian hour weight: active 8–23 with an evening lift, a thin overnight tail (irregular but structured).
function opHourWeight() { const w = {}; for (let h = 0; h < 24; h++) w[h] = h >= 8 && h <= 23 ? (h >= 18 ? 1.6 : 1.0) : 0.12; return w; }

/** one operator session window of n events — a fresh structured sample of the same process each time. */
export function operatorWindow(r, n = 40) {
  const hw = opHourWeight(); const ev = [];
  for (let i = 0; i < n; i++) ev.push({ region: pick(r(), OP_REGION), command: pick(r(), OP_CMD), hour: Number(pick(r(), hw)), priv: pick(r(), OP_PRIV) });
  return ev;
}
/** SCRIPTED attack — overly regular: one foreign region, a narrow repeated command pair, a fixed off-hour,
 *  constant elevated privilege. Low behavioral entropy, wrong distribution. */
export function scriptedWindow(r, n = 40) {
  const ev = [];
  for (let i = 0; i < n; i++) ev.push({ region: 'US', command: i % 2 === 0 ? 'scan' : 'read', hour: 3, priv: 'elevated' });
  return ev;
}
/** RANDOM attack — uncorrelated: uniform over the whole vocabulary. High entropy, flat, no operator peaks. */
export function randomWindow(r, n = 40) {
  const ev = [];
  for (let i = 0; i < n; i++) ev.push({ region: REGIONS[Math.floor(r() * REGIONS.length)], command: COMMANDS[Math.floor(r() * COMMANDS.length)], hour: Math.floor(r() * 24), priv: PRIV[Math.floor(r() * PRIV.length)] });
  return ev;
}
/** a set of `count` windows from a generator, deterministic from a seed. */
export function windows(gen, seed, count, n = 40) { const r = rng(seed); const out = []; for (let i = 0; i < count; i++) out.push(gen(r, n)); return out; }

export const CONFIG = Object.freeze({ n: 40, trainSeed: 1001, trainCount: 80, opHeldSeed: 2002, opHeldCount: 50, scriptSeed: 3003, scriptCount: 40, randSeed: 4004, randCount: 40 });
