// sentinel.test.mjs — the immune kernel, line by line. Real Ed25519 (node:crypto) drives the gate; the grown detector is
// tested on small made-up streams (the real battery is the sealed red-team run, never a test).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign, verify as nodeVerify } from 'node:crypto';
import * as S from './sentinel.mjs';

// a real Ed25519 identity, and a verify the gate can call
function identity() { return generateKeyPairSync('ed25519'); }
const verify = (pub, msg, sig) => nodeVerify(null, Buffer.from(msg), pub, Buffer.from(sig));
// a signed 71-byte wire packet from source `id`, signed by `priv`, over a payload (re-folded unless raw payload given)
function wire(id, priv, command, { payload, tamper } = {}) {
  const pay = payload || S.pack(command);
  const env = new Uint8Array(7); env[0] = id; env.set(pay, 1);
  let sig = sign(null, Buffer.from(env), priv);
  const raw = new Uint8Array(S.WIRE); raw.set(env, 0); raw.set(sig, 7);
  if (tamper) tamper(raw);
  return raw;
}
const CMD = { opcode: S.OPCODES.READ, source: 1, target: 2, resources: 0b0011, budget: 100 };

test('foldWitness: the primorial fold of the five payload bytes, mod 256; total on garbage', () => {
  assert.equal(S.foldWitness([1, 0, 0, 0, 0]), 2);
  assert.equal(S.foldWitness([0, 1, 0, 0, 0]), 3);
  assert.equal(S.foldWitness([0, 0, 1, 0, 0]), 5);
  assert.equal(S.foldWitness([0, 0, 0, 1, 0]), 11);
  assert.equal(S.foldWitness([0, 0, 0, 0, 1]), 31);
  assert.equal(S.foldWitness([255, 255, 255, 255, 255]), (255 * (2 + 3 + 5 + 11 + 31)) & 0xFF);
  assert.equal(S.foldWitness([]), 0);
  assert.equal(S.foldWitness(null), 0);
  assert.equal(S.foldWitness([1.5, 'x', {}, undefined, 2]), (2 * 1 + 31 * 2) & 0xFF);
  assert.deepEqual(S.SPINE, [2, 3, 5, 11, 31]);
});

test('pack: six bytes with the witness last; out of range or non-object is null', () => {
  const b = S.pack(CMD);
  assert.ok(b instanceof Uint8Array && b.length === 6);
  assert.deepEqual([...b.slice(0, 5)], [1, (1 << 4) | 2, 0b0011, 100, 0]);
  assert.equal(b[5], S.foldWitness(b));
  assert.equal(S.pack({ ...CMD, budget: 0x0102 }).slice(3, 5).join(','), '2,1', 'little-endian');
  assert.equal(S.pack(null), null);
  assert.equal(S.pack('x'), null);
  assert.equal(S.pack([]), null);
  assert.equal(S.pack({ ...CMD, source: 16 }), null);
  assert.equal(S.pack({ ...CMD, source: -1 }), null);
  assert.equal(S.pack({ ...CMD, target: 16 }), null);
  assert.equal(S.pack({ ...CMD, opcode: 256 }), null);
  assert.equal(S.pack({ ...CMD, resources: 256 }), null);
  assert.equal(S.pack({ ...CMD, budget: 65536 }), null);
  assert.equal(S.pack({ ...CMD, budget: 1.5 }), null);
  assert.equal(S.pack({ opcode: 1, source: 1, target: 1, resources: 1 }), null, 'a missing field is null');
  // the top of every range is valid (the boundary is inclusive)
  assert.ok(S.pack({ opcode: 255, source: 15, target: 15, resources: 255, budget: 65535 }) instanceof Uint8Array);
  assert.ok(S.pack({ ...CMD, opcode: 0, source: 0, target: 0, resources: 0, budget: 0 }) instanceof Uint8Array);
});

test('unpack: the inverse of pack; wrong length is bad-length, a broken fold is off-κ', () => {
  const b = S.pack(CMD);
  assert.deepEqual(S.unpack(b), { ok: true, command: CMD });
  assert.deepEqual(S.unpack(new Uint8Array(5)), { ok: false, reason: 'bad-length' });
  assert.deepEqual(S.unpack(new Uint8Array(7)), { ok: false, reason: 'bad-length' });
  assert.deepEqual(S.unpack([0, 0, 0, 0, 0, 0]), { ok: false, reason: 'bad-length' }, 'a plain array is not a packet');
  assert.deepEqual(S.unpack(null), { ok: false, reason: 'bad-length' });
  const t = b.slice(); t[2] ^= 1;
  assert.deepEqual(S.unpack(t), { ok: false, reason: 'off-kappa' }, 'a flipped payload byte no longer folds to its witness');
  const w = b.slice(); w[5] ^= 1;
  assert.deepEqual(S.unpack(w), { ok: false, reason: 'off-kappa' }, 'a flipped witness is off-κ');
  for (let i = 0; i < 1000; i += 7) { const r = S.unpack(S.pack({ opcode: i % 256, source: i % 16, target: (i + 1) % 16, resources: i % 256, budget: i * 7 % 65536 })); assert.equal(r.ok, true); }
});

test('fingerprint: the signature bytes as hex, or null on a non-packet', () => {
  const { privateKey } = identity();
  const raw = wire(1, privateKey, CMD);
  const fp = S.fingerprint(raw);
  assert.equal(typeof fp, 'string');
  assert.equal(fp.length, 128);
  assert.equal(fp, S.fingerprint(raw), 'deterministic');
  assert.equal(S.fingerprint(new Uint8Array(70)), null);
  assert.equal(S.fingerprint([]), null);
  assert.equal(S.fingerprint(null), null);
});

test('the gate accepts a well-formed, signed, in-budget, at-κ, unseen packet', () => {
  const { publicKey, privateKey } = identity();
  const ctx = { keys: { 1: publicKey }, lattice: { 1: { maxBudget: 200, resources: 0xFF } }, seen: new Set(), verify };
  const v = S.check(wire(1, privateKey, CMD), ctx);
  assert.equal(v.ok, true);
  assert.equal(v.reason, 'ok');
  assert.deepEqual(v.command, CMD);
  assert.equal(ctx.seen.size, 1, 'an accepted packet is remembered');
});

test('the gate drops the bad length, the unknown source, and the forged signature — before any parse', () => {
  const { publicKey, privateKey } = identity();
  let verifyCalls = 0;
  const spy = (k, m, s) => { verifyCalls += 1; return verify(k, m, s); };
  const ctx = { keys: { 1: publicKey }, lattice: { 1: { maxBudget: 200, resources: 0xFF } }, seen: new Set(), verify: spy };
  assert.deepEqual(S.check(new Uint8Array(70), ctx), { ok: false, reason: 'bad-length', command: null });
  assert.deepEqual(S.check([], ctx), { ok: false, reason: 'bad-length', command: null });
  const raw = wire(1, privateKey, CMD);
  // an unknown source is dropped WITHOUT ever calling verify
  const other = raw.slice(); other[0] = 5;
  assert.equal(S.check(other, ctx).reason, 'unknown-source');
  assert.equal(verifyCalls, 0, 'verify is never called for an unknown source');
  // a tampered payload with its OLD signature is forged — and the forged verdict comes back though the payload is now off-κ,
  // which only unpack could have found: the signature is checked before the payload is parsed
  const tampered = wire(1, privateKey, CMD, { tamper: (r) => { r[3] ^= 0xFF; } });
  assert.equal(S.check(tampered, ctx).reason, 'forged');
  assert.ok(verifyCalls > 0);
});

test('the gate drops replay, budget-exceeded, resource-denied, source-mismatch, off-κ, and the un-granted', () => {
  const { publicKey, privateKey } = identity();
  const seen = new Set();
  const ctx = { keys: { 1: publicKey }, lattice: { 1: { maxBudget: 150, resources: 0b0011 } }, seen, verify };
  const raw = wire(1, privateKey, CMD);
  assert.equal(S.check(raw, ctx).ok, true);
  assert.equal(S.check(raw, ctx).reason, 'replay', 'the same signed packet twice is a replay');
  assert.equal(S.check(wire(1, privateKey, { ...CMD, budget: 150 }), ctx).ok, true, 'budget exactly at the cap is allowed');
  assert.equal(S.check(wire(1, privateKey, { ...CMD, budget: 151 }), ctx).reason, 'budget-exceeded');
  assert.equal(S.check(wire(1, privateKey, { ...CMD, resources: 0b0111 }), ctx).reason, 'resource-denied');
  // envelope says source 1, payload says source 2, signed consistently over the envelope → the nibble mismatch is caught
  const mism = wire(1, privateKey, { ...CMD, source: 2 });
  assert.equal(S.check(mism, ctx).reason, 'source-mismatch');
  // a valid signature over an off-κ payload still fails the fold
  const badFold = S.pack(CMD).slice(); badFold[5] ^= 1;
  assert.equal(S.check(wire(1, privateKey, null, { payload: badFold }), ctx).reason, 'off-kappa');
  // known key, no capability in the lattice
  const ctx2 = { keys: { 1: publicKey }, lattice: {}, seen: new Set(), verify };
  assert.equal(S.check(wire(1, privateKey, CMD), ctx2).reason, 'no-capability');
});

test('the gate is total: no context, no verify, hostile inputs never throw', () => {
  assert.equal(S.check(new Uint8Array(71), {}).reason, 'unknown-source', 'empty ctx: source 0 is unknown');
  assert.equal(S.check(new Uint8Array(71), null).reason, 'unknown-source');
  const ctx = { keys: { 0: 'k' }, lattice: {}, seen: new Set(), verify: () => { throw new Error('boom'); } };
  assert.equal(S.check(new Uint8Array(71), ctx).reason, 'forged', 'a throwing verify is a failed verify');
  assert.equal(S.check('x', ctx).reason, 'bad-length');
  assert.equal(S.check(new Uint8Array(71), { keys: { 0: 'k' }, verify: () => 'truthy-not-true' }).reason, 'forged', 'verify must return exactly true');
});

test('phantom: a rejected command gets a zero-budget, isolated decoy', () => {
  assert.deepEqual(S.phantom({ reason: 'forged' }), { phantom: true, granted: false, budget: 0, cell: 'phantom', echo: 'forged' });
  assert.deepEqual(S.phantom(null), { phantom: true, granted: false, budget: 0, cell: 'phantom', echo: 'dropped' });
  assert.deepEqual(S.phantom({ reason: 7 }), { phantom: true, granted: false, budget: 0, cell: 'phantom', echo: 'dropped' });
  assert.equal(S.phantom({ reason: 'x' }).budget, 0);
});

test('features: the shape of a window of accepted packets', () => {
  assert.deepEqual(S.features([]), { n: 0, fanout: 0, budgetSum: 0, dominance: 0, resourceSpread: 0 });
  assert.deepEqual(S.features('x'), { n: 0, fanout: 0, budgetSum: 0, dominance: 0, resourceSpread: 0 });
  const w = [{ source: 1, target: 2, resources: 0b0001, budget: 10 }, { source: 1, target: 3, resources: 0b0010, budget: 20 }, { source: 4, target: 2, resources: 0b0001, budget: 30 }];
  assert.deepEqual(S.features(w), { n: 3, fanout: 2, budgetSum: 60, dominance: 2 / 3, resourceSpread: 2 });
  assert.deepEqual(S.features([null, 'x', { source: 1, target: 1, resources: 1, budget: 5 }]), { n: 1, fanout: 1, budgetSum: 5, dominance: 1, resourceSpread: 1 });
  assert.equal(S.features([{ source: 1, target: 1, resources: 'x', budget: 'y' }]).budgetSum, 0);
  assert.deepEqual(S.FEATURES, ['n', 'fanout', 'budgetSum', 'dominance', 'resourceSpread']);
});

test('normalize: each feature scaled toward 0–1 by its ceiling', () => {
  assert.deepEqual(S.normalize({ n: 32, fanout: 16, budgetSum: 65535, dominance: 1, resourceSpread: 8 }), { n: 1, fanout: 1, budgetSum: 1, dominance: 1, resourceSpread: 1 });
  assert.deepEqual(S.normalize({ n: 16, fanout: 8, budgetSum: 0, dominance: 0.5, resourceSpread: 4 }), { n: 0.5, fanout: 0.5, budgetSum: 0, dominance: 0.5, resourceSpread: 0.5 });
  assert.deepEqual(S.normalize(null), { n: 0, fanout: 0, budgetSum: 0, dominance: 0, resourceSpread: 0 });
  assert.deepEqual(S.NORMS, { n: 32, fanout: 16, budgetSum: 65535, dominance: 1, resourceSpread: 8 });
});

test('score and flags: a weighted sum of normalized features over a threshold', () => {
  const f = { n: 2, fanout: 3, budgetSum: 10, dominance: 1, resourceSpread: 4 };
  assert.equal(S.score(f, [1, 0, 0, 0, 0]), 2, 'score is over whatever feature object it is given');
  assert.equal(S.score(f, [1, 1, 1, 1, 1]), 20);
  assert.equal(S.score(f, [0, 0, 0.5, 0, 0]), 5);
  assert.equal(S.score(null, [1]), 0);
  assert.equal(S.score(f, null), 0);
  assert.equal(S.score(f, [1]), 2, 'missing weights are zero');
  // a window of eight distinct targets → normalized fanout 0.5; flags uses the NORMALIZED features
  const scan = Array.from({ length: 8 }, (_, k) => ({ source: 1, target: k, resources: 1, budget: 1 }));
  assert.equal(S.flags(scan, { weights: [0, 1, 0, 0, 0], threshold: 0.25 }), true);
  assert.equal(S.flags(scan, { weights: [0, 1, 0, 0, 0], threshold: 0.6 }), false);
  assert.equal(S.flags(scan, { weights: [0, 1, 0, 0, 0], threshold: 0.5 }), true, 'the threshold is inclusive');
  assert.equal(S.flags([], null), true, 'score 0 ≥ threshold 0');
  assert.equal(S.flags([], { threshold: 0.1 }), false);
});

// a labelled set: attack streams drain or scan; legit streams are small and focused
const scan = { attack: true, window: Array.from({ length: 8 }, (_, k) => ({ source: 1, target: k % 15, resources: 0b0001, budget: 1 })) };
const drain = { attack: true, window: [{ source: 2, target: 1, resources: 0xFF, budget: 60000 }] };
const legitA = { attack: false, window: [{ source: 1, target: 2, resources: 0b0001, budget: 10 }, { source: 1, target: 2, resources: 0b0001, budget: 12 }] };
const legitB = { attack: false, window: [{ source: 3, target: 4, resources: 0b0010, budget: 5 }] };
const STREAMS = [scan, drain, legitA, legitB];

test('fitness: catch rate, but zero the moment a legit stream is flagged', () => {
  const catchAll = { weights: [0, 0, 0, 0, 0], threshold: -1 };
  assert.deepEqual(S.fitness(catchAll, STREAMS), { score: 0, caught: 0, attacks: 2, falsePass: true }, 'flagging everything flags legit → death');
  const byBudget = { weights: [0, 0, 1, 0, 0], threshold: 0.5 };
  assert.deepEqual(S.fitness(byBudget, STREAMS), { score: 0.5, caught: 1, attacks: 2, falsePass: false }, 'catches the drain (normalized budget ≈0.92), not the scan, no false pass');
  const byFanout = { weights: [0, 1, 0, 0, 0], threshold: 0.25 };
  assert.equal(S.fitness(byFanout, STREAMS).caught, 1, 'catches the scan (normalized fan-out 0.5)');
  const both = { weights: [0, 1, 1, 0, 0], threshold: 0.4 };
  assert.deepEqual(S.fitness(both, STREAMS), { score: 1, caught: 2, attacks: 2, falsePass: false }, 'fan-out and budget together catch both, no false pass');
  assert.deepEqual(S.fitness({ weights: [1, 0, 0, 0, 0], threshold: 0 }, []), { score: 0, caught: 0, attacks: 0, falsePass: false });
  assert.equal(S.fitness(null, STREAMS).falsePass, true, 'a null detector scores 0 ≥ threshold 0, so it flags everything, including legit');
  assert.equal(S.fitness({ weights: [1], threshold: 999999 }, STREAMS).score, 0, 'catching nothing is score 0, not a false pass');
});

test('better: a higher catch wins; on a tie the higher threshold wins; equal is not strictly better', () => {
  const at = (score, threshold) => ({ f: { score }, d: { threshold } });
  assert.equal(S.better(at(0.8, 1), at(0.5, 9)), true, 'higher score beats even a higher threshold');
  assert.equal(S.better(at(0.5, 9), at(0.8, 1)), false);
  assert.equal(S.better(at(0.5, 9), at(0.5, 1)), true, 'a tie keeps the higher threshold');
  assert.equal(S.better(at(0.5, 1), at(0.5, 9)), false);
  assert.equal(S.better(at(0.5, 5), at(0.5, 5)), false, 'equal is not strictly better');
});

test('grow: the fittest detector over a seeded search, deterministic, never on the held-out', () => {
  const cfg = { tries: 600, weightSpan: 4, maxThreshold: 1 };
  const d = S.grow(STREAMS, cfg, 7);
  assert.ok(Array.isArray(d.weights) && d.weights.length === 5);
  assert.equal(typeof d.threshold, 'number');
  const f = S.fitness(d, STREAMS);
  assert.equal(f.falsePass, false, 'a grown detector never flags a legit stream');
  assert.ok(f.score > 0, 'it catches at least one attack');
  assert.deepEqual(S.grow(STREAMS, cfg, 7), d, 'same seed, same detector');
  assert.notDeepEqual(S.grow(STREAMS, cfg, 8), d);
  const none = S.grow([], { tries: 10 }, 1);
  assert.ok(Array.isArray(none.weights) && none.weights.length === 5 && typeof none.threshold === 'number', 'an empty set still returns a well-formed detector');
  assert.deepEqual(S.grow([], { tries: 0 }, 1), { weights: [0, 0, 0, 0, 0], threshold: 0 }, 'no tries at all is the zero detector');
});

test('grade: the six sealed rules from a run record', () => {
  const run = { hard: { caught: 50, attacks: 50, falsePass: 0, valid: 20, parsedForged: 0 }, grown: { grownCatch: 8, baselineCatch: 5, grownFalsePass: false }, reproduced: true };
  const j = S.grade({}, run);
  assert.equal(j.passed, 6);
  assert.equal(j.of, 6);
  assert.deepEqual(j.rules.map((r) => r.id), ['hard-catches-all', 'hard-zero-false-pass', 'verify-before-parse', 'grown-beats-baseline', 'grown-zero-false-pass', 'reproducible']);
  assert.equal(S.grade({}, { ...run, hard: { ...run.hard, caught: 49 } }).passed, 5);
  assert.equal(S.grade({}, { ...run, hard: { ...run.hard, attacks: 0, caught: 0 } }).rules.find((r) => r.id === 'hard-catches-all').pass, false, 'catching all of zero attacks proves nothing');
  assert.equal(S.grade({}, { ...run, hard: { ...run.hard, valid: 0 } }).rules.find((r) => r.id === 'hard-zero-false-pass').pass, false, 'zero valid packets tested proves no clean pass');
  assert.equal(S.grade({}, { ...run, hard: { ...run.hard, parsedForged: 1 } }).rules.find((r) => r.id === 'verify-before-parse').pass, false);
  assert.equal(S.grade({}, { ...run, grown: { grownCatch: 5, baselineCatch: 5, grownFalsePass: false } }).rules.find((r) => r.id === 'grown-beats-baseline').pass, false);
  assert.equal(S.grade({}, { ...run, grown: { ...run.grown, grownFalsePass: true } }).rules.find((r) => r.id === 'grown-zero-false-pass').pass, false);
  assert.equal(S.grade({}, { ...run, reproduced: false }).rules.find((r) => r.id === 'reproducible').pass, false);
  assert.equal(S.grade(null, null).passed, 0);
});

test('popcount counts the low eight bits', () => {
  assert.equal(S.popcount(0), 0);
  assert.equal(S.popcount(0xFF), 8);
  assert.equal(S.popcount(0b1011), 3);
  assert.equal(S.popcount(256), 0, 'only the low byte');
  assert.equal(S.popcount(-1), 8);
});
