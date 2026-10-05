// streams.near.test.mjs — the near-boundary generator (flag 3). Deterministic, seeded, mixed legit and hostile right at
// the cut. Not the kernel (witness mutates sentinel.mjs), but exercised here so it is never dead and so `node --test` proves
// it behaves. The real measurement is the sealed red-team run, never a test.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { nearBoundary } from './streams.mjs';

test('nearBoundary: deterministic, seeded, both classes present, well-formed', () => {
  const cfg = { sources: 4 };
  const a = nearBoundary(cfg, 123, 40);
  assert.equal(a.length, 40);
  assert.deepEqual(a, nearBoundary(cfg, 123, 40), 'same seed, same set');
  assert.notDeepEqual(a, nearBoundary(cfg, 124, 40), 'a different seed differs');
  const attacks = a.filter((s) => s.attack), legit = a.filter((s) => !s.attack);
  assert.ok(attacks.length > 0 && legit.length > 0, 'both legit and hostile are present');
  for (const s of a) {
    assert.equal(typeof s.attack, 'boolean');
    assert.ok(Array.isArray(s.window) && s.window.length > 0, 'a non-empty window');
    for (const c of s.window) {
      assert.ok(c.source >= 0 && c.source < 4, 'source within the node range');
      assert.ok(c.target >= 0 && c.target < 16, 'target within the node range');
      assert.ok(c.budget >= 1, 'a real budget');
      assert.ok(c.resources >= 1, 'a real resource bit');
    }
  }
});

test('nearBoundary is genuinely harder than the clean split — the classes overlap in size', () => {
  const a = nearBoundary({ sources: 4 }, 777, 120);
  const size = (s) => s.window.length;
  const attackSizes = a.filter((s) => s.attack).map(size);
  const legitSizes = a.filter((s) => !s.attack).map(size);
  const maxLegit = Math.max(...legitSizes), minAttack = Math.min(...attackSizes);
  assert.ok(minAttack <= maxLegit, 'the smallest hostile stream is no bigger than the largest legit one — they overlap at the cut');
});
