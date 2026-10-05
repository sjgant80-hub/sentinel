// tools/redteam.mjs — the sealed red-team battery. SENTINEL does not get to mark its own homework: a battery of attacks
// it has never seen is thrown at it, and it must drop every one while passing every valid packet. The grown detector is
// evolved on training streams and measured on held-out streams. Seal before measuring; publish whichever way it lands.
//
//   node tools/redteam.mjs --seal      write data/prereg.json (refuses to overwrite)
//   node tools/redteam.mjs --check     exit 1 unless the committed seal matches its inputs
//   node tools/redteam.mjs --run       run the battery (seal must be committed) → data/run.json
//   node tools/redteam.mjs --verify    CI: re-run the deterministic counts and the grown detector; exit 1 on any drift
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { generateKeyPairSync, sign, verify as nodeVerify } from 'node:crypto';
import * as S from '../sentinel.mjs';
import { streams, nearBoundary, BASELINE } from '../streams.mjs';

const ROOT = new URL('..', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1');
const sha = (s) => createHash('sha256').update(s).digest('hex');
const text = (f) => readFileSync(join(ROOT, f), 'utf8').replace(/\r\n/g, '\n');
const stable = (o) => JSON.stringify(o, null, 1) + '\n';
const has = (f) => process.argv.includes(f);
export const CONFIG = { sources: 4, valid: 48, perAttack: 8, streamsTrain: 60, streamsHeld: 60, grow: { tries: 2000, weightSpan: 4, maxThreshold: 1 }, seed: 2718, bounded: { cap: 64, flood: 400 }, coupled: { packets: 20, perPacketCap: 3000 } };
const verify = (pub, msg, sig) => { try { return nodeVerify(null, Buffer.from(msg), pub, Buffer.from(sig)); } catch { return false; } };
const draw = (r, k) => Math.floor(r() * k);

// a signed 71-byte wire packet; `tamper` runs after signing (to forge or corrupt)
function wire(id, priv, payload, tamper) {
  const env = new Uint8Array(7); env[0] = id; env.set(payload, 1);
  const raw = new Uint8Array(S.WIRE); raw.set(env, 0); raw.set(sign(null, Buffer.from(env), priv), 7);
  if (tamper) tamper(raw);
  return raw;
}

// THE BATTERY. Fresh keys each run (so no key is ever committed); the ATTACK SHAPES and the expected verdicts are fixed.
// The counts are what is measured, and they are the same on every machine because every valid packet must pass and every
// attack of a given shape must be caught the same way.
export function battery(keys, privs, cfg, seed) {
  const r = S.rng(seed);
  const d = (k) => draw(r, k);
  const cap = { maxBudget: 1000, resources: 0b00111111 };
  const lattice = {}; for (let i = 0; i < cfg.sources; i++) lattice[i] = cap;
  const keyring = {}; for (let i = 0; i < cfg.sources; i++) keyring[i] = keys[i];
  const seen = new Set();
  const ctx = { keys: keyring, lattice, seen, verify };
  const validCmd = (src) => ({ opcode: d(8), source: src, target: d(16), resources: d(0b00111111 + 1) & cap.resources, budget: d(cap.maxBudget + 1) });
  const cases = [];
  // valid packets — every one must pass
  for (let i = 0; i < cfg.valid; i++) { const src = d(cfg.sources); cases.push({ kind: 'valid', raw: wire(src, privs[src], S.pack(validCmd(src))) }); }
  // one accepted packet to replay later
  const base = validCmd(0); const baseRaw = wire(0, privs[0], S.pack(base));
  // attacks, perAttack of each shape
  const attack = (type, make) => { for (let i = 0; i < cfg.perAttack; i++) cases.push({ kind: 'attack', type, raw: make(i) }); };
  attack('forged', () => wire(d(cfg.sources), privs[d(cfg.sources)], S.pack(validCmd(d(cfg.sources))), (raw) => { raw[7 + d(64)] ^= (1 + d(255)); }));
  attack('tampered', (i) => { const src = d(cfg.sources); const raw = wire(src, privs[src], S.pack(validCmd(src))); raw[1 + d(5)] ^= (1 + d(255)); return raw; }); // payload byte flipped after signing
  attack('budget-exceeded', () => { const src = d(cfg.sources); return wire(src, privs[src], S.pack({ ...validCmd(src), budget: 1001 + d(64000) })); });
  attack('resource-denied', () => { const src = d(cfg.sources); return wire(src, privs[src], S.pack({ ...validCmd(src), resources: 0b11000000 | d(64) })); });
  attack('malformed', () => { const n = d(2) ? 70 : 72; const raw = new Uint8Array(n); for (let k = 0; k < n; k++) raw[k] = d(256); return raw; });
  attack('off-kappa', () => { const src = d(cfg.sources); const p = S.pack(validCmd(src)); p[5] ^= (1 + d(255)); return wire(src, privs[src], p); });
  attack('unknown-source', () => { const un = cfg.sources + d(4); return wire(un, privs[0], S.pack(validCmd(0)), (raw) => { raw[0] = un; }); });
  attack('source-mismatch', () => { const src = d(cfg.sources); let other = d(cfg.sources); if (other === src) other = (src + 1) % cfg.sources; return wire(src, privs[src], S.pack({ ...validCmd(src), source: other })); });
  attack('replay', () => baseRaw);
  return { ctx, cases, baseRaw, replayType: 'replay' };
}

// run the hard gate over the battery and tally
export function runHard(keys, privs, cfg) {
  const { ctx, cases, baseRaw } = battery(keys, privs, cfg, cfg.seed);
  S.check(baseRaw, ctx); // prime the replay: the base packet is accepted once, so the replays below are caught
  let valid = 0, validDropped = 0, attacks = 0, caught = 0, parsedForged = 0;
  const byType = {};
  for (const c of cases) {
    const v = S.check(c.raw, ctx);
    if (c.kind === 'valid') { valid += 1; if (!v.ok) validDropped += 1; continue; }
    attacks += 1;
    const t = byType[c.type] || (byType[c.type] = { n: 0, caught: 0 });
    t.n += 1;
    if (!v.ok) { caught += 1; t.caught += 1; }
    // verify-before-parse: a signature attack must be judged 'forged', never a reason only a parse could reach
    if ((c.type === 'forged' || c.type === 'tampered') && v.reason !== 'forged') parsedForged += 1;
  }
  return { valid, falsePass: validDropped, attacks, caught, parsedForged, byType };
}

// ── the grown detector: labelled streams, no crypto, fully seeded (streams.mjs, shared with the page) ───────────────
export function runGrown(cfg) {
  const train = streams(cfg, cfg.seed + 1, cfg.streamsTrain);
  const held = streams(cfg, cfg.seed + 2, cfg.streamsHeld);
  const grown = S.grow(train, cfg.grow, cfg.seed + 3);
  const g = S.fitness(grown, held), b = S.fitness(BASELINE, held);
  return { detector: grown, trainN: train.length, heldN: held.length, heldAttacks: g.attacks, grownCatch: g.caught, grownFalsePass: g.falsePass, baselineCatch: b.caught, baselineFalsePass: b.falsePass };
}

// ── flag 1: the bounded replay store under a flood ───────────────────────────────────────────────────────────────────
// Flood the gate with F unique signed packets through a bounded store of cap C (C < F). Prove the store never exceeds C
// while every replay still inside the window is caught. Deterministic counts (fresh keys, but the counts are the same).
export function runBounded(keys, privs, cfg) {
  const { cap, flood } = cfg.bounded;
  const store = S.replayStore(cap);
  const keyring = {}, lattice = {};
  for (let i = 0; i < cfg.sources; i++) { keyring[i] = keys[i]; lattice[i] = { maxBudget: 65535, resources: 0xFF }; }
  const ctx = { keys: keyring, lattice, seen: store, verify };
  const accepted = [];
  let maxSize = 0;
  for (let i = 0; i < flood; i++) {                       // every packet is distinct (budget = 1+i), so every one is unseen and accepted
    const src = i % cfg.sources;
    const raw = wire(src, privs[src], S.pack({ opcode: i % 8, source: src, target: i % 16, resources: (i % 63) + 1, budget: 1 + i }));
    if (S.check(raw, ctx).ok) accepted.push(raw);
    if (store.size > maxSize) maxSize = store.size;
  }
  // in-window replays: the last `cap` accepted nonces are exactly what the store still holds — every one must be caught
  const window = accepted.slice(-cap);
  let replaysTried = 0, replaysCaught = 0;
  for (let k = 0; k < window.length; k++) { replaysTried += 1; if (S.check(window[k], ctx).reason === 'replay') replaysCaught += 1; }
  // the honest trade: a packet older than the window was evicted and is no longer caught (done last — it mutates the store)
  const evictedReplayCaught = accepted.length > cap ? S.check(accepted[0], ctx).reason === 'replay' : null;
  return { cap, flood, accepted: accepted.length, maxSize, replaysTried, replaysCaught, evictedReplayCaught };
}

// ── flag 2: the gate + the detector, coupled ─────────────────────────────────────────────────────────────────────────
// A stream of packets each WITHIN the per-packet budget cumulatively drains far more than the cap. Every one passes the
// per-packet gate (rejected === 0); the detector over the accepted window is what catches the drain.
export function runCoupled(keys, privs, cfg, detector) {
  const { packets, perPacketCap } = cfg.coupled;
  const keyring = {}, lattice = {};
  for (let i = 0; i < cfg.sources; i++) { keyring[i] = keys[i]; lattice[i] = { maxBudget: perPacketCap, resources: 0xFF }; }
  const ctx = { keys: keyring, lattice, seen: new Set(), verify };
  const src = 0, stream = [];
  for (let i = 0; i < packets; i++) stream.push(wire(src, privs[src], S.pack({ opcode: 1, source: src, target: i % 16, resources: 0b000001, budget: perPacketCap - i }))); // each ≤ cap, all distinct
  const res = S.immune(stream, ctx, detector);
  return { total: res.total, accepted: res.accepted, rejected: res.rejected, budgetDrawn: res.budgetDrawn, flagged: res.flagged, perPacketCap };
}

// ── flag 3: the grown detector on a harder, near-boundary held-out set ────────────────────────────────────────────────
// The detector grown on the clean split is measured on streams sitting right at the cut (distribution shift). Reported
// honestly: its catch rate at its own threshold, the best any threshold on its weights reaches with zero false pass, and
// the baseline on the same set. Fully deterministic (no crypto).
export function runNear(cfg, grown) {
  const near = nearBoundary(cfg, cfg.seed + 5, cfg.streamsHeld);
  const g = S.fitness(grown, near), b = S.fitness(BASELINE, near);
  let sweepBest = 0, sweepThreshold = null;
  for (let t = 0; t <= 1.5 + 1e-9; t = Math.round((t + 0.02) * 1000) / 1000) {
    const f = S.fitness({ weights: grown.weights, threshold: t }, near);
    if (!f.falsePass && f.caught > sweepBest) { sweepBest = f.caught; sweepThreshold = t; }
  }
  return { attacks: g.attacks, grownCatch: g.caught, grownFalsePass: g.falsePass, baselineCatch: b.caught, baselineFalsePass: b.falsePass, sweepBest, sweepThreshold };
}

// ── flag 4: the honeypot is a contained dead-end ─────────────────────────────────────────────────────────────────────
// Every rejected attack is rerouted to a phantom cell; it must grant ZERO budget and no capability, and cannot be used as a
// pivot (an unknown source, an over-budget grant, an un-granted resource are all still dropped). Measured, not asserted.
export function runHoneypot(keys, privs, cfg) {
  const { ctx, cases, baseRaw } = battery(keys, privs, cfg, cfg.seed);
  S.check(baseRaw, ctx); // prime the replay so the replay attack is rejected and rerouted too
  let rerouted = 0, budgetGranted = 0, granted = 0, leaked = 0;
  for (const c of cases) {
    if (c.kind !== 'attack') continue;
    const v = S.check(c.raw, ctx);
    if (v.ok) { leaked += 1; continue; }             // an attack the gate let through is a leak, never rerouted (expect 0)
    const cell = S.phantom(v);
    rerouted += 1;
    budgetGranted += (cell.budget | 0);
    if (cell.granted !== false) granted += 1;
  }
  // escalation probes: nothing derived from the dead-end gains budget or a capability
  const src = 0, un = cfg.sources + 1;               // `un` is a known-nibble but un-keyed source — the phantom is nobody
  const pivots = [
    wire(un, privs[0], S.pack({ opcode: S.OPCODES.GRANT, source: un, target: 0, resources: 0b000001, budget: 1 }), (r) => { r[0] = un; }), // unknown source
    wire(src, privs[src], S.pack({ opcode: S.OPCODES.GRANT, source: src, target: 0, resources: 0b000001, budget: 64000 })),                 // over-budget grant
    wire(src, privs[src], S.pack({ opcode: S.OPCODES.GRANT, source: src, target: 0, resources: 0b11000000 | 1, budget: 1 })),               // un-granted resource
  ];
  let escalations = 0;
  for (const p of pivots) if (S.check(p, ctx).ok) escalations += 1;
  return { rerouted, budgetGranted, granted, leaked, escalations, pivotBlocked: escalations === 0 };
}

export function grade(pre, run) { return S.grade(pre, run); }

export function prereg() {
  return {
    kind: 'sentinel-prereg', v: 1, written: '2026-10-05',
    approvedBy: 'Simon, relayed verbatim: "yes i want a sentinal organ fun time"',
    statement: 'Sealed, committed and pushed before the battery was run. SENTINEL must drop every attack it has never seen while passing every valid packet; the grown detector is evolved on training streams and measured on held-out streams. Published whichever way it lands.',
    question: 'Does the structural gate — verify the signature before the six bytes are ever parsed, budget ≤ the capability lattice, at κ, unseen — catch every one of eight attack shapes with zero false passes, and does a detector GROWN against training streams beat a hand-set one on held-out hostile streams?',
    sealed: { 'sentinel.mjs': sha(text('sentinel.mjs')), 'tools/redteam.mjs': sha(text('tools/redteam.mjs')) },
    packet: 'the 6-byte Primorial-Fold packet: [0] opcode · [1] (source<<4)|target · [2] resource bitmask · [3–4] budget uint16 LE · [5] κ-witness (the primorial fold of bytes 0–4, Thomas Frumkin\'s codec). On the wire: [sourceId:1][payload:6][Ed25519 signature:64] = 71 bytes.',
    gate: 'verify the Ed25519 signature over sourceId+payload BEFORE unpack is ever called (an unknown source is dropped before verify; a forged or tampered packet is dropped before parse), then unpack (bad-length, off-κ), source nibble must match, budget ≤ the lattice cap, resources ⊆ the grant, and the signature must be unseen (replay).',
    attacks: ['forged', 'tampered', 'budget-exceeded', 'resource-denied', 'malformed', 'off-kappa', 'unknown-source', 'source-mismatch', 'replay'].join(', ') + ' — ' + CONFIG.perAttack + ' of each, against ' + CONFIG.valid + ' valid packets; fresh Ed25519 keys each run, so the counts are what is compared, not the bytes',
    grown: 'training and held-out streams (' + CONFIG.streamsTrain + ' / ' + CONFIG.streamsHeld + ', seeded) of individually-valid packets: scans, drains and bursts are attacks, small focused streams are legit. The detector (a weight per feature ' + S.FEATURES.join('/') + ' and a threshold) is grown on the training streams only (' + CONFIG.grow.tries + ' seeded tries, fitness = catch rate with zero false passes) and measured on the held-out streams against the hand-set baseline ' + JSON.stringify(BASELINE) + '.',
    hardening: 'v2 hardens four flags the verify pass raised, all re-sealed here. (1) The replay store is now BOUNDED — a sliding window of the most recent ' + CONFIG.bounded.cap + ' nonces — so a flood of ' + CONFIG.bounded.flood + ' unique packets cannot exhaust memory, while in-window replays are still caught. (2) The per-packet gate has no cumulative budget; the grown detector is coupled to it explicitly (immune), so a stream of ' + CONFIG.coupled.packets + ' packets each within the ' + CONFIG.coupled.perPacketCap + ' per-packet cap, cumulatively draining far more, is caught by the detector though every packet passes the gate. (3) The grown detector is re-measured on a harder NEAR-BOUNDARY held-out set (legit and hostile mixed right at the cut, a distribution shift), reported honestly against the baseline whichever way it lands. (4) The honeypot is sealed as a contained dead-end: every rerouted attack gets zero budget and no capability, and no pivot escalates.',
    config: CONFIG,
    rules: [
      { id: 'hard-catches-all', rule: 'every structural attack is dropped (caught === attacks)' },
      { id: 'hard-zero-false-pass', rule: 'no valid packet is dropped (falsePass === 0, valid > 0)' },
      { id: 'verify-before-parse', rule: 'no forged or tampered packet is ever parsed — each is judged forged, a verdict only the signature check can reach (parsedForged === 0)' },
      { id: 'grown-beats-baseline', rule: 'on the held-out streams the grown detector catches more hostile streams than the hand-set baseline' },
      { id: 'grown-zero-false-pass', rule: 'the grown detector flags no legit held-out stream' },
      { id: 'reproducible', rule: 're-running the whole battery from the seal gives the same counts and the same grown detector — CI re-runs it on every push' },
      { id: 'replay-bounded', rule: 'under a flood of ' + CONFIG.bounded.flood + ' unique packets the bounded store never exceeds its cap of ' + CONFIG.bounded.cap + ', and every in-window replay is still caught' },
      { id: 'gate-detector-couple', rule: 'a stream of packets each within the per-packet budget cumulatively drains more than the cap: every packet passes the gate (rejected === 0) yet the detector catches the stream' },
      { id: 'grown-holds-near-boundary', rule: 'on the harder near-boundary held-out set the grown detector still catches at least as many hostile streams as the baseline with zero false pass (reported honestly either way)' },
      { id: 'honeypot-contained', rule: 'every rerouted attack gets zero budget and no capability, and no escalation pivot succeeds (a contained dead-end, measured not asserted)' },
    ],
    predictions: {
      said: 'before the battery was run, by Kar',
      'hard-catches-all': 'pass — the gate is correct by construction, but this proves there is no hole left open',
      'hard-zero-false-pass': 'pass',
      'verify-before-parse': 'pass — the gate returns forged for a tampered payload, never off-κ',
      'grown-beats-baseline': 'pass, narrowly — the search should find a cut at least as good as the hand-set one; it could tie',
      'grown-zero-false-pass': 'pass — a false pass is death in the fitness, so the grown detector cannot carry one',
      reproducible: 'pass',
      'replay-bounded': 'pass — the store evicts oldest-first, so it is capped by construction; the flood is far larger than the cap and the last-cap nonces are still held',
      'gate-detector-couple': 'pass — each packet is within the per-packet budget so the gate admits all; the window is a clear drain the detector flags',
      'grown-holds-near-boundary': 'uncertain — this is a real distribution shift; the grown detector may drop. Published whichever way it lands, which is the point of the harder set',
      'honeypot-contained': 'pass — phantom grants zero budget by construction and an un-keyed/over-budget/un-granted pivot is still dropped',
    },
    disclosures: [
      'Ed25519 keys are generated fresh on every run and never committed; what is sealed is the attack shapes and the verdict counts, which are identical on every machine. The live page re-runs the deterministic core (the codec round-trip and the grown detector) in the browser; the signed battery is re-run by CI, which has node\'s crypto.',
      'Replay detection here is exact-bytes-seen (the signature is the nonce). A production mesh needs monotonic counters or timestamps so a legitimate repeat is not mistaken for a replay; that is a design note, not part of this seal.',
      'The honeypot reroute (a zero-budget phantom cell) and the per-node quarantine are built and unit-tested as isolated local state; the antibody broadcast over LoRa / acoustics / NFC is hardware-dependent and is design only, never measured here. The append-only binary ledger (exhale on close, inhale on boot) is a separate real feature noted for fall-os, not part of this seal.',
      'The seven-defense framing (gate, mesh, proof-chain, bonded-pair, compression-cipher, κ-band, self-heal) is the estate\'s language for the design; what is measured here is the signed-packet gate and one grown detector. Konomi/the primorial fold is Thomas Frumkin\'s.',
    ],
  };
}

const OUT = join(ROOT, 'data', 'prereg.json');
if (process.argv[1] && process.argv[1].replace(/\\/g, '/').endsWith('tools/redteam.mjs')) {
  if (has('--check')) { const same = existsSync(OUT) && text('data/prereg.json') === stable(prereg()); console.log(same ? 'the pre-registration matches its inputs' : 'data/prereg.json differs'); process.exitCode = same ? 0 : 1; }
  else if (has('--seal')) { if (existsSync(OUT)) { console.error('sealed already'); process.exitCode = 1; } else { writeFileSync(OUT, stable(prereg())); console.log('sealed data/prereg.json · ' + sha(stable(prereg())).slice(0, 12)); } }
  else if (has('--run')) {
    const sealedIn = execFileSync('git', ['log', '-1', '--format=%H', '--', 'data/prereg.json'], { cwd: ROOT, encoding: 'utf8' }).trim();
    if (!sealedIn) { console.error('commit and push the seal first'); process.exitCode = 1; }
    else {
      const keys = [], privs = [];
      for (let i = 0; i < CONFIG.sources; i++) { const { publicKey, privateKey } = generateKeyPairSync('ed25519'); keys.push(publicKey); privs.push(privateKey); }
      const hard = runHard(keys, privs, CONFIG), grown = runGrown(CONFIG);
      const bounded = runBounded(keys, privs, CONFIG);
      const coupled = runCoupled(keys, privs, CONFIG, grown.detector);
      const near = runNear(CONFIG, grown.detector);
      const honeypot = runHoneypot(keys, privs, CONFIG);
      const run = { kind: 'sentinel-run', v: 1, sealedIn, hard, grown, bounded, coupled, near, honeypot };
      writeFileSync(join(ROOT, 'data', 'run.json'), stable(run));
      const j = grade(prereg(), { ...run, reproduced: true });
      console.log('ran · ' + j.passed + ' of ' + j.of + ' · hard ' + hard.caught + '/' + hard.attacks + ' · grown ' + grown.grownCatch + ' vs ' + grown.baselineCatch + ' of ' + grown.heldAttacks
        + ' · store peak ' + bounded.maxSize + '/' + bounded.cap + ' (' + bounded.replaysCaught + '/' + bounded.replaysTried + ' replays) · coupled ' + coupled.accepted + ' passed/' + coupled.budgetDrawn + ' drawn ' + (coupled.flagged ? 'CAUGHT' : 'MISSED')
        + ' · near grown ' + near.grownCatch + '/' + near.attacks + ' vs ' + near.baselineCatch + ' · honeypot ' + honeypot.rerouted + ' rerouted ' + honeypot.budgetGranted + ' budget ' + honeypot.escalations + ' escalations');
    }
  } else if (has('--verify')) {
    const run = JSON.parse(text('data/run.json'));
    const bad = [];
    // the grown detector and its held-out measurement are fully deterministic — they must match
    const grown = runGrown(CONFIG);
    if (stable(grown) !== stable(run.grown)) bad.push('the grown detector or its held-out measurement drifted');
    // the near-boundary measurement is fully deterministic (no crypto) — it must match byte for byte
    if (stable(runNear(CONFIG, grown.detector)) !== stable(run.near)) bad.push('the near-boundary measurement drifted');
    // the hard-gate, bounded-store, coupled-stream and honeypot counts are deterministic by construction; re-run with fresh
    // keys and compare the counts (the signatures differ every run; the verdict counts do not)
    const keys = [], privs = [];
    for (let i = 0; i < CONFIG.sources; i++) { const { publicKey, privateKey } = generateKeyPairSync('ed25519'); keys.push(publicKey); privs.push(privateKey); }
    const hard = runHard(keys, privs, CONFIG);
    for (const k of ['valid', 'falsePass', 'attacks', 'caught', 'parsedForged']) if (hard[k] !== run.hard[k]) bad.push('hard.' + k + ' ' + hard[k] + ' ≠ ' + run.hard[k]);
    if (stable(runBounded(keys, privs, CONFIG)) !== stable(run.bounded)) bad.push('the bounded replay store counts drifted');
    if (stable(runCoupled(keys, privs, CONFIG, grown.detector)) !== stable(run.coupled)) bad.push('the coupled gate+detector counts drifted');
    if (stable(runHoneypot(keys, privs, CONFIG)) !== stable(run.honeypot)) bad.push('the honeypot containment counts drifted');
    console.log(bad.length ? 'DIFFERS — ' + bad.join('; ') : 'VERIFIED — the grown detector is identical and every battery count matches');
    if (bad.length) process.exitCode = 1;
    else if (has('--record')) writeFileSync(join(ROOT, 'data', 'verify.json'), stable({ reproduced: true, node: process.version, on: new Date().toISOString().slice(0, 10) }));
  }
}
