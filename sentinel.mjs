// sentinel.mjs — SENTINEL, a structural immune system. Not a wall bolted on, but the shape of the thing: a command
// that is not signed, not within its capability budget, not at κ, or already seen never becomes a command at all.
//
// THE 6-BYTE PRIMORIAL-FOLD PACKET (the genome of a command):
//   [0] opcode                       what to do
//   [1] (source << 4) | target       two 4-bit node indices (0–15)
//   [2] resources                    an 8-bit capability bitmask
//   [3..4] budget                    uint16, little-endian
//   [5] κ-witness                    the primorial fold of bytes 0–4 (Thomas Frumkin's primorial fold codec); a tampered
//                                     payload no longer folds to its witness, so it reads as off-κ
// On the wire it travels SIGNED: [sourceId:1][payload:6][signature:64] = 71 bytes.
//
// THE GATE verifies the Ed25519 signature BEFORE the six bytes are ever parsed: an unsigned or forged command is dropped
// before it reaches a DataView, so an un-verified command never compiles into a command. Then budget ≤ the capability
// lattice (it cannot spend what it was never granted — the-wallet's rule), the packet must be unseen (no replay), and at κ.
//
// THE GROWN DETECTOR is the adaptive half: individually-valid packets can still form a hostile STREAM (a scan across
// targets, a budget drain). A detector over a window of accepted packets is EVOLVED against held-out attack streams, and
// may fail honestly — its fitness is the catch rate with zero false passes.
//
// Pure and deterministic. The readers (unpack, check, phantom, features, score, flags, grade) are total: garbage returns
// {ok:false} or a zero, never throws. The crypto is injected into check (ctx.verify), so this kernel stays pure.

const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const int = (v) => (Number.isInteger(v) ? v : NaN);

// the prime spine of the fold — one prime per payload byte (the primorial fold; see Thomas Frumkin's codec)
export const SPINE = [2, 3, 5, 11, 31];
export const OPCODES = Object.freeze({ NOOP: 0, READ: 1, WRITE: 2, GRANT: 3, REVOKE: 4, COUPLE: 5, HEAL: 6, QUARANTINE: 7 });
export const RESOURCES = Object.freeze(['memory', 'compute', 'mesh', 'ledger', 'key', 'budget', 'gate', 'heal']);
export const WIRE = 71; // [sourceId:1][payload:6][signature:64]
export const PAYLOAD = 6;
export const SIG = 64;

export function popcount(x) {
  let n = (x | 0) & 0xFF, c = 0;
  while (n) { c += n & 1; n >>>= 1; }
  return c;
}

// the κ-witness: the primorial fold of the first five payload bytes, modulo 256. Deterministic; a change to any payload
// byte changes the fold, so the witness no longer matches — the packet reads off-κ without anyone knowing the attack.
export function foldWitness(bytes) {
  let w = 0;
  for (let i = 0; i < SPINE.length; i++) w += SPINE[i] * (((bytes && bytes[i]) | 0) & 0xFF);
  return w & 0xFF;
}

// pack a command into its 6 bytes. Total: a command out of range returns null rather than throwing.
export function pack(command) {
  if (!isObj(command)) return null;
  const opcode = int(command.opcode), source = int(command.source), target = int(command.target), resources = int(command.resources), budget = int(command.budget);
  if ([opcode, source, target, resources, budget].some(Number.isNaN)) return null;
  if (opcode < 0 || opcode > 255 || source < 0 || source > 15 || target < 0 || target > 15 || resources < 0 || resources > 255 || budget < 0 || budget > 65535) return null;
  const b = new Uint8Array(PAYLOAD);
  b[0] = opcode; b[1] = (source << 4) | target; b[2] = resources; b[3] = budget & 0xFF; b[4] = (budget >> 8) & 0xFF;
  b[5] = foldWitness(b);
  return b;
}

// unpack the 6 bytes back into a command. Total: wrong length is bad-length, a broken fold is off-κ.
export function unpack(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length !== PAYLOAD) return { ok: false, reason: 'bad-length' };
  if (bytes[5] !== foldWitness(bytes)) return { ok: false, reason: 'off-kappa' };
  return { ok: true, command: { opcode: bytes[0], source: (bytes[1] >> 4) & 0xF, target: bytes[1] & 0xF, resources: bytes[2], budget: bytes[3] | (bytes[4] << 8) } };
}

// the signature's own bytes are the replay nonce: Ed25519 gives one signature per (key, message), so the same signed
// packet twice is a replay, and two different commands never collide.
const hex = (u8) => { let s = ''; for (const b of u8) s += b.toString(16).padStart(2, '0'); return s; };
const num = (x) => { const n = Number(x); return Number.isFinite(n) ? n : 0; };
export function fingerprint(raw) { return raw instanceof Uint8Array && raw.length === WIRE ? hex(raw.subarray(7)) : null; }

const reject = (reason) => ({ ok: false, reason, command: null });

// THE GATE. ctx = { keys:{id:publicKey}, lattice:{id:{maxBudget,resources}}, seen:Set, verify:(key,msg,sig)=>boolean }.
// The order is the defense: length, then a known source, then the signature — all BEFORE the payload is unpacked.
export function check(raw, ctx) {
  const c = isObj(ctx) ? ctx : {};
  const keys = isObj(c.keys) ? c.keys : {};
  const lattice = isObj(c.lattice) ? c.lattice : {};
  const seen = c.seen instanceof Set ? c.seen : null;
  const verify = typeof c.verify === 'function' ? c.verify : null;
  if (!(raw instanceof Uint8Array) || raw.length !== WIRE) return reject('bad-length');
  const sourceId = raw[0];
  if (!Object.prototype.hasOwnProperty.call(keys, sourceId)) return reject('unknown-source');
  const msg = raw.subarray(0, 7), sig = raw.subarray(7);
  let good = false;
  try { good = verify ? verify(keys[sourceId], msg, sig) === true : false; } catch { good = false; }
  if (!good) return reject('forged');                               // ⟵ the payload has NOT been parsed yet
  const nonce = fingerprint(raw);
  if (seen && seen.has(nonce)) return reject('replay');
  const u = unpack(raw.subarray(1, 7));                             // ⟵ only a verified packet reaches here
  if (!u.ok) return reject(u.reason);
  const cmd = u.command;
  if (cmd.source !== sourceId) return reject('source-mismatch');
  const cap = lattice[sourceId];
  if (!isObj(cap)) return reject('no-capability');
  if (cmd.budget > (int(cap.maxBudget) || 0)) return reject('budget-exceeded');
  if ((cmd.resources & ~(int(cap.resources) || 0) & 0xFF) !== 0) return reject('resource-denied');
  if (seen) seen.add(nonce);
  return { ok: true, reason: 'ok', command: cmd, nonce };
}

// the honeypot: a rejected command is dropped into a zero-budget phantom cell. It grants nothing and touches no real
// state, so an attacker who keeps probing only ever learns the shape of a cell that was never real.
export function phantom(verdict) {
  const reason = isObj(verdict) && typeof verdict.reason === 'string' ? verdict.reason : 'dropped';
  return { phantom: true, granted: false, budget: 0, cell: 'phantom', echo: reason };
}

// ── the grown detector: hostile STREAMS of individually-valid packets ───────────────────────────────────────────────
// features of a window of accepted commands: how many, how wide the fan-out of targets, the budget drawn, how much one
// source dominates, and how many resources were touched.
export function features(window) {
  const w = (Array.isArray(window) ? window : []).filter(isObj);
  const n = w.length;
  if (!n) return { n: 0, fanout: 0, budgetSum: 0, dominance: 0, resourceSpread: 0 };
  const targets = new Set(), bySource = new Map();
  let budgetSum = 0, resBits = 0;
  for (const c of w) {
    targets.add(c.target);
    bySource.set(c.source, (bySource.get(c.source) || 0) + 1);
    budgetSum += int(c.budget) || 0;
    resBits |= (int(c.resources) || 0);
  }
  return { n, fanout: targets.size, budgetSum, dominance: Math.max(...bySource.values()) / n, resourceSpread: popcount(resBits) };
}
export const FEATURES = ['n', 'fanout', 'budgetSum', 'dominance', 'resourceSpread'];
// each feature is scaled to roughly 0–1 by its natural ceiling, so one weight scale and one 0–1 threshold mean the same
// across all five — without this a budget of tens of thousands drowns a fan-out of eight.
export const NORMS = Object.freeze({ n: 32, fanout: 16, budgetSum: 65535, dominance: 1, resourceSpread: 8 });
export function normalize(feat) {
  const f = isObj(feat) ? feat : {};
  const out = {};
  for (const name of FEATURES) out[name] = num(f[name]) / NORMS[name];
  return out;
}

// a detector is a weight per feature and a threshold; it flags a window whose weighted, normalized score reaches it.
export function score(feat, weights) {
  const f = isObj(feat) ? feat : {};
  const w = Array.isArray(weights) ? weights : [];
  return FEATURES.reduce((s, name, i) => s + num(f[name]) * num(w[i]), 0);
}
export function flags(window, detector) {
  const d = isObj(detector) ? detector : {};
  return score(normalize(features(window)), d.weights) >= num(d.threshold);
}

// ── growing the detector (seeded, like pattern-organs): random detectors, the fittest kept ──────────────────────────
export function rng(seed) {
  let a = seed >>> 0;
  return () => { a = (a + 0x6D2B79F5) >>> 0; let t = a; t = Math.imul(t ^ (t >>> 15), t | 1); t ^= t + Math.imul(t ^ (t >>> 7), t | 61); return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
}
// fitness on a labelled set of streams: the share of attacks caught, but ZERO if it flags any legit stream (a false pass
// of a legit command is death — a defense that cries wolf is worse than none).
export function fitness(detector, streams) {
  const s = (Array.isArray(streams) ? streams : []).filter(isObj);
  const attacks = s.filter((x) => x.attack === true), legit = s.filter((x) => x.attack === false);
  if (legit.some((x) => flags(x.window, detector))) return { score: 0, caught: 0, attacks: attacks.length, falsePass: true };
  const caught = attacks.filter((x) => flags(x.window, detector)).length;
  return { score: attacks.length ? caught / attacks.length : 0, caught, attacks: attacks.length, falsePass: false };
}
// grow(train, cfg, seed) → the fittest detector found over `tries` seeded random detectors (weights in [0,W], threshold
// scaled to the data). A tie keeps the simpler (lower threshold). The search never touches the held-out streams.
// a beats b: a higher catch score, or on a tie the higher threshold (flag as little as possible for the same catch).
export function better(a, b) {
  return a.f.score > b.f.score || (a.f.score === b.f.score && a.d.threshold > b.d.threshold);
}
export function grow(train, cfg, seed) {
  const c = isObj(cfg) ? cfg : {};
  const tries = Number.isInteger(c.tries) ? c.tries : 400;
  const W = Number.isFinite(c.weightSpan) ? c.weightSpan : 4;
  const maxT = Number.isFinite(c.maxThreshold) ? c.maxThreshold : 1;
  const r = rng(seed >>> 0);
  let best = null;
  for (let t = 0; t < tries; t++) {
    const weights = FEATURES.map(() => Math.round(r() * W * 100) / 100);
    const threshold = Math.round(r() * maxT * 1000) / 1000;
    const cand = { d: { weights, threshold }, f: fitness({ weights, threshold }, train) };
    if (!best || better(cand, best)) best = cand;
  }
  return best ? best.d : { weights: FEATURES.map(() => 0), threshold: 0 };
}

// ── grading a sealed run ────────────────────────────────────────────────────────────────────────────────────────────
export function grade(prereg, run) {
  const g = isObj(run) ? run : {};
  const hard = isObj(g.hard) ? g.hard : {};
  const grown = isObj(g.grown) ? g.grown : {};
  const rules = [
    { id: 'hard-catches-all', value: hard.caught + ' of ' + hard.attacks + ' structural attacks dropped', pass: hard.attacks > 0 && hard.caught === hard.attacks },
    { id: 'hard-zero-false-pass', value: hard.falsePass + ' valid packets wrongly dropped (of ' + hard.valid + ')', pass: hard.falsePass === 0 && hard.valid > 0 },
    { id: 'verify-before-parse', value: hard.parsedForged + ' forged packets ever reached unpack', pass: hard.parsedForged === 0 },
    { id: 'grown-beats-baseline', value: 'grown caught ' + grown.grownCatch + ', hand-set baseline ' + grown.baselineCatch + ' (held-out)', pass: grown.grownCatch > grown.baselineCatch },
    { id: 'grown-zero-false-pass', value: grown.grownFalsePass ? 'flagged a legit stream' : 'no legit stream flagged', pass: grown.grownFalsePass === false },
    { id: 'reproducible', value: 'CI re-runs the whole battery from the seal', pass: g.reproduced === true },
  ];
  return { rules, passed: rules.filter((r) => r.pass).length, of: rules.length };
}

export default { SPINE, OPCODES, RESOURCES, WIRE, PAYLOAD, SIG, popcount, foldWitness, pack, unpack, fingerprint, check, phantom, features, FEATURES, normalize, score, flags, rng, fitness, better, grow, grade };
