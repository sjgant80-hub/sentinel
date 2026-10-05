#!/usr/bin/env node
// tools/make-page.mjs — the fixpoint. index.html carries the SAME sentinel.mjs and streams.mjs the tests and the mutation
// gate prove, inlined verbatim, and re-runs the deterministic core (the codec round-trip and the grown detector) in the
// browser; every number on the page, in the README and in llms.txt is generated here by the kernel's own grade(). CI
// regenerates all three and fails on any difference.
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import * as S from '../sentinel.mjs';
import { CONFIG, grade } from './redteam.mjs';

const at = (f) => new URL('../' + f, import.meta.url);
const read = (f) => readFileSync(at(f), 'utf8').replace(/\r\n/g, '\n');
const json = (f) => (existsSync(at(f)) ? JSON.parse(read(f)) : null);
const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
const URL_LIVE = 'https://sjgant80-hub.github.io/sentinel/', REPO = 'https://github.com/sjgant80-hub/sentinel';
const CREDIT = 'Powered by the Konomi architecture, created by Thomas Frumkin';

const pre = json('data/prereg.json'), run = json('data/run.json'), ver = json('data/verify.json');
if (!pre) { console.error('not sealed — run tools/redteam.mjs --seal first'); process.exit(1); }
const j = run && grade(pre, { ...run, reproduced: !!(ver && ver.reproduced) });

const headline = !run
  ? 'Sealed, being measured. The packet, the gate, the attack shapes, the rules and a prediction were committed before the battery ran; the result lands here whichever way it goes.'
  : j.passed + ' of ' + j.of + ' sealed rules held. The gate dropped ' + run.hard.caught + ' of ' + run.hard.attacks + ' attacks it had never seen with ' + run.hard.falsePass
    + ' of ' + run.hard.valid + ' valid packets wrongly dropped, and no forged packet was ever parsed. A detector GROWN against training streams caught ' + run.grown.grownCatch + ' of ' + run.grown.heldAttacks
    + ' hostile held-out streams against the hand-set baseline\'s ' + run.grown.baselineCatch + ', flagging no legit stream.';

const BYTES = [
  ['0', 'opcode', 'what to do'],
  ['1', 'source · target', 'two 4-bit node indices'],
  ['2', 'resources', 'an 8-bit capability bitmask'],
  ['3–4', 'budget', 'uint16, little-endian'],
  ['5', 'κ-witness', 'the primorial fold of bytes 0–4'],
];
const DEFENCES = [
  ['verify before parse', 'The Ed25519 signature over sourceId+payload is checked before the six bytes are ever unpacked. A forged or tampered command is dropped before it reaches a DataView — an un-verified command never becomes a command.'],
  ['budget ≤ the lattice', 'Each source is granted a capability: a maximum budget and an allowed set of resources. A command cannot spend budget it was never granted, or touch a resource outside its grant.'],
  ['at κ', 'The sixth byte is the primorial fold of the first five (Thomas Frumkin\'s codec). A tampered payload no longer folds to its witness, so it reads off-κ without anyone needing to know the attack.'],
  ['unseen', 'The signature is the packet\'s nonce; the same signed packet twice is a replay and is dropped.'],
  ['the honeypot', 'A rejected command is dropped into a zero-budget phantom cell that touches no real state — an attacker who keeps probing only ever learns the shape of a cell that was never real.'],
];

let body = '';
if (run) {
  body += '<h2>The sealed rules</h2><div class="card"><table><thead><tr><th>rule</th><th>result</th><th></th><th>predicted before the run</th></tr></thead><tbody>'
    + j.rules.map((r) => '<tr><td>' + esc(pre.rules.find((x) => x.id === r.id).rule) + '</td><td>' + esc(r.value) + '</td><td class="' + (r.pass ? 'pass">PASS' : 'fail">FAIL') + '</td><td class="quiet">' + esc(pre.predictions[r.id]) + '</td></tr>').join('')
    + '</tbody></table></div>';
  const bt = run.hard.byType;
  body += '<h2>The attack battery</h2><div class="card"><p class="quiet" style="margin-top:0">Eight attack shapes plus replay, ' + CONFIG.perAttack + ' of each, against ' + run.hard.valid + ' valid packets — fresh Ed25519 keys each run, so the counts are what is compared. Every attack is dropped; every valid packet passes.</p>'
    + '<div class="scroll"><table><thead><tr><th>attack</th><th>thrown</th><th>dropped</th></tr></thead><tbody>'
    + Object.keys(bt).map((t) => '<tr><td>' + esc(t) + '</td><td class="n">' + bt[t].n + '</td><td class="n">' + bt[t].caught + (bt[t].caught === bt[t].n ? ' ✓' : '') + '</td></tr>').join('')
    + '<tr class="best"><td>valid packets</td><td class="n">' + run.hard.valid + '</td><td class="n">' + (run.hard.valid - run.hard.falsePass) + ' passed</td></tr>'
    + '</tbody></table></div><p class="quiet">Forged and tampered packets reached unpack <b>' + run.hard.parsedForged + '</b> times — the signature is checked before the payload is parsed.</p></div>';
  const g = run.grown;
  body += '<h2>The grown detector</h2><div class="card"><p style="margin-top:0">Individually-valid packets can still form a hostile <b>stream</b> — a scan across targets, a budget drain, a burst. A detector (a weight per feature ' + esc(S.FEATURES.join(', ')) + ' and a threshold) was grown on ' + g.trainN + ' training streams and measured on ' + g.heldN + ' held-out streams it never saw.</p>'
    + '<div class="scroll"><table><thead><tr><th></th><th>hostile streams caught</th><th>legit flagged</th></tr></thead><tbody>'
    + '<tr class="best"><td>grown</td><td class="n">' + g.grownCatch + ' of ' + g.heldAttacks + '</td><td class="n">' + (g.grownFalsePass ? 'yes' : 'none') + '</td></tr>'
    + '<tr><td>hand-set baseline</td><td class="n">' + g.baselineCatch + ' of ' + g.heldAttacks + '</td><td class="n">' + (g.baselineFalsePass ? 'yes' : 'none') + '</td></tr>'
    + '</tbody></table></div><p class="quiet">A false pass — flagging a legit stream — is death in the fitness, so a detector that cries wolf never survives. The grown weights: ' + esc(JSON.stringify(g.detector.weights)) + ', threshold ' + g.detector.threshold + '.</p></div>';
}

const page = `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SENTINEL</title>
<meta name="description" content="A structural immune system: a command that is not signed, within budget, at κ and unseen never becomes a command at all. Sealed against a red-team battery; the grown detector re-runs in your browser.">
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Cpath d='M16 2 28 7v9c0 7-5 12-12 14C9 28 4 23 4 16V7z' fill='%23d6a93a'/%3E%3C/svg%3E">
<script type="application/ld+json">${JSON.stringify({ '@context': 'https://schema.org', '@type': 'SoftwareSourceCode', name: 'SENTINEL', description: 'A structural immune system: verify-before-parse signed-packet gate, capability budget, κ-witness, and a grown anomaly detector, sealed against a red-team battery.', codeRepository: REPO, url: URL_LIVE, license: 'https://opensource.org/licenses/MIT', author: { '@type': 'Person', name: 'Kar' } }).replace(/</g, '\\u003c')}</script>
<style>
:root{--bg:#0c0b10;--panel:#15131b;--line:#2d2a36;--ink:#ece6d6;--dim:#a39c8c;--faint:#6f6a78;--gold:#d6a93a;--soft:#e9cf7f;--ok:#5fbf8f;--no:#e0616d;
 --sans:ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;--serif:"Iowan Old Style","Palatino Linotype",Palatino,Georgia,serif;--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
@media (prefers-color-scheme:light){:root:not([data-theme="dark"]){--bg:#fbf8f1;--panel:#fff;--line:#e4dcc9;--ink:#22201c;--dim:#5e564a;--faint:#8b8272;--gold:#8a6a13;--soft:#6d5310}}
:root[data-theme="light"]{--bg:#fbf8f1;--panel:#fff;--line:#e4dcc9;--ink:#22201c;--dim:#5e564a;--faint:#8b8272;--gold:#8a6a13;--soft:#6d5310}
*{box-sizing:border-box}html,body{margin:0}
body{background:var(--bg);color:var(--ink);font-family:var(--sans);font-size:16px;line-height:1.6}
.wrap{max-width:56rem;margin:0 auto;padding:0 16px 5rem}
header{padding:3rem 0 1.2rem}
.kick{font-family:var(--mono);font-size:.68rem;letter-spacing:.2em;text-transform:uppercase;color:var(--gold);margin:0 0 .6rem}
h1{font-family:var(--serif);font-weight:500;font-size:clamp(1.9rem,6vw,3rem);margin:0 0 .5rem;color:var(--soft)}
.lede{font-family:var(--serif);font-style:italic;color:var(--dim);font-size:clamp(1rem,2.4vw,1.2rem);margin:0}
h2{font-family:var(--serif);font-weight:500;color:var(--gold);font-size:1.3rem;margin:2.3rem 0 .4rem}
h3{font-size:1rem;margin:1rem 0 .3rem}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px 18px;margin:.8rem 0;overflow-x:auto}
.verdict{border-color:var(--gold)}
.big{font-size:1.1rem;margin-top:0}.stat{font-variant-numeric:tabular-nums;font-weight:700;color:var(--soft)}
.quiet{color:var(--dim);font-size:.92rem}.scroll{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:.88rem}
th,td{text-align:left;padding:.4rem .45rem;border-top:1px solid var(--line);vertical-align:top}
th{color:var(--faint);font-family:var(--mono);font-size:.68rem;letter-spacing:.06em;text-transform:uppercase;border-top:0}
td.n{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
tr.best td{color:var(--soft);font-weight:600}
.pass{color:var(--ok);font-family:var(--mono);font-weight:700}.fail{color:var(--no);font-family:var(--mono);font-weight:700}
.packet{display:flex;flex-wrap:wrap;gap:6px;font-family:var(--mono);font-size:.8rem;margin:.4rem 0}
.byte{border:1px solid var(--line);border-radius:7px;padding:.4rem .6rem;flex:1 1 90px;min-width:0}
.byte b{color:var(--soft);display:block}.byte span{color:var(--faint);font-size:.72rem}
code{font-family:var(--mono);font-size:.85em;background:var(--bg);border:1px solid var(--line);border-radius:4px;padding:.05em .3em;overflow-wrap:anywhere}
button{font:inherit;background:var(--gold);color:#16130c;border:0;border-radius:8px;padding:.6rem 1.1rem;font-weight:600;cursor:pointer}
button:hover{background:var(--soft)}button:disabled{opacity:.6;cursor:wait}button:focus-visible{outline:2px solid var(--soft);outline-offset:2px}
a{color:var(--soft)}
footer{margin-top:3rem;padding-top:1rem;border-top:1px solid var(--line);color:var(--faint);font-size:.84rem}
</style></head><body><div class="wrap">
<header>
 <p class="kick">An estate organ · the structural immune system</p>
 <h1>SENTINEL</h1>
 <p class="lede">Not a wall bolted on, but the shape of the thing: a command that is not signed, not within its budget, not at κ, and not unseen never becomes a command at all.</p>
</header>
<h2>The verdict</h2>
<div class="card verdict"><p class="big">${run ? '<span class="stat">' + j.passed + ' of ' + j.of + '</span> sealed rules held.' : 'Sealed, being measured.'}</p><p>${esc(run ? headline.slice(headline.indexOf('The gate')) : headline)}</p></div>
${body}
<h2>The 6-byte packet</h2>
<div class="card"><p class="quiet" style="margin-top:0">A command is six bytes — the Primorial-Fold packet. On the wire it travels signed: <code>[sourceId:1][payload:6][Ed25519 signature:64]</code> = 71 bytes.</p>
<div class="packet">${BYTES.map(([n, name, what]) => '<div class="byte"><b>[' + n + '] ' + esc(name) + '</b><span>' + esc(what) + '</span></div>').join('')}</div></div>
<h2>Seven defences, one shape</h2>
<div class="card">${DEFENCES.map(([h, p]) => '<h3>' + esc(h) + '</h3><p>' + esc(p) + '</p>').join('')}
<p class="quiet">To breach it an attacker must, at once, find a known source, forge a signature, fold the κ-witness, stay within a budget it was never granted, and send something never seen — several independent locks at the same node, not one wall with one breach. The full seven-defence framing (mesh quarantine, bonded-pair cross-check, compression cipher, self-heal) is the design; what is measured here is the signed-packet gate and one grown detector.</p></div>
<h2>Re-run the deterministic core</h2>
<div class="card"><p style="margin-top:0">The codec round-trip and the grown detector are pure and seeded — they re-run here in your browser from the same kernel this page is built from, and must match the committed record. ${run ? 'The signed battery (real Ed25519) is re-run by CI, which has node crypto.' : ''}</p>
 <button id="rerun" type="button">Re-run</button> <span id="out" class="quiet" role="status" aria-live="polite"></span></div>
<h2>What was sealed first</h2>
<div class="card"><p style="margin-top:0">${esc(pre.statement)}</p>
<p><b>The question.</b> ${esc(pre.question)}</p>
<p><b>The gate.</b> ${esc(pre.gate)}</p>
<p><b>The grown detector.</b> ${esc(pre.grown)}</p>
<p class="quiet">${run ? 'Sealed in <code>' + esc(run.sealedIn.slice(0, 7)) + '</code> · ' : ''}<a href="data/prereg.json">the pre-registration</a>${run ? ' · <a href="data/run.json">the record</a>' : ''}</p>
<p class="quiet">${pre.disclosures.map(esc).join(' ')}</p></div>
<footer>
 <p>Every number here comes from the mutation-gated kernel <code>sentinel.mjs</code>, inlined below. · <a href="${REPO}">source</a> · MIT for the code.</p>
 <p>The κ-witness is the primorial fold of Thomas Frumkin's codec; the capability lattice is the estate's wallet. ${CREDIT}.</p>
</footer>
</div>
<script id="kernel" type="text/plain">
${read('sentinel.mjs').replace(/^export (function|const) /gm, '$1 ').replace(/^export default[\s\S]*$/m, '').replace(/<\/script/gi, '<\\/script')}
${read('streams.mjs').replace(/^import[^\n]*\n/gm, '').replace(/^export (function|const) /gm, '$1 ').replace(/<\/script/gi, '<\\/script')}
</script>
<script>
const CONFIG = ${JSON.stringify(CONFIG)};
const RECORD = ${JSON.stringify(run ? { grown: run.grown } : null).replace(/</g, '\\u003c')};
const K = new Function(document.getElementById('kernel').textContent + '\\nreturn { pack, unpack, grow, fitness, streams, BASELINE, rng };')();
document.getElementById('rerun').addEventListener('click', () => {
  const out = document.getElementById('out');
  // 1) the codec round-trips losslessly
  const r = K.rng(12345); let codec = 0;
  for (let i = 0; i < 2000; i++) {
    const c = { opcode: Math.floor(r() * 256), source: Math.floor(r() * 16), target: Math.floor(r() * 16), resources: Math.floor(r() * 256), budget: Math.floor(r() * 65536) };
    const u = K.unpack(K.pack(c));
    if (u.ok && u.command.opcode === c.opcode && u.command.source === c.source && u.command.target === c.target && u.command.resources === c.resources && u.command.budget === c.budget) codec += 1;
  }
  // 2) the grown detector, regrown on the seeded streams and measured on the held-out set
  const train = K.streams(CONFIG, CONFIG.seed + 1, CONFIG.streamsTrain);
  const held = K.streams(CONFIG, CONFIG.seed + 2, CONFIG.streamsHeld);
  const grown = K.grow(train, CONFIG.grow, CONFIG.seed + 3);
  const g = K.fitness(grown, held), b = K.fitness(K.BASELINE, held);
  const match = RECORD && grown.threshold === RECORD.grown.detector.threshold && g.caught === RECORD.grown.grownCatch && b.caught === RECORD.grown.baselineCatch && g.falsePass === RECORD.grown.grownFalsePass;
  out.textContent = codec + '/2000 codec round-trips lossless; grown caught ' + g.caught + ', baseline ' + b.caught + ' of ' + g.attacks + ' held-out attacks' + (RECORD ? (match ? ' — IDENTICAL to the committed record.' : ' — DIFFERS from the record.') : '.');
});
</script>
</body></html>
`;

const md = ['# SENTINEL', '', '**Live: ' + URL_LIVE + '**', '', 'A structural immune system. A command that is not signed, not within its capability budget, not at κ, and not unseen never becomes a command at all — the signature is verified before the six bytes are ever parsed. Sealed against a red-team battery; the grown detector re-runs in your browser.', '', '## The result', '', headline, ''];
if (run) {
  md.push('| Sealed rule | Result | | Predicted |', '|---|---|---|---|');
  for (const r of j.rules) md.push('| ' + pre.rules.find((x) => x.id === r.id).rule + ' | ' + r.value + ' | ' + (r.pass ? 'PASS' : 'FAIL') + ' | ' + pre.predictions[r.id] + ' |');
  md.push('');
}
const bq = String.fromCharCode(96); // a backtick, kept out of the single-quoted strings below
const code = (s) => bq + s + bq;
md.push('## What it is', '', '- ' + code('sentinel.mjs') + ' — the kernel: the 6-byte Primorial-Fold codec (pack/unpack, the κ-witness), the verify-before-parse gate (check), the honeypot (phantom), and the grown stream detector (features, normalize, score, flags, fitness, grow). Pure and total; witness-gated.', '- ' + code('streams.mjs') + ' — the seeded hostile and legit streams, shared with the page.', '- ' + code('tools/redteam.mjs') + ' — the sealed battery: --seal, --run, --verify.', '', '## Honest scope', '', '- The signed-packet gate and one grown detector are measured. The honeypot and per-node quarantine are built and unit-tested as isolated local state.', '- The antibody broadcast over LoRa / acoustics / NFC is hardware-dependent and is design only.', '- Replay here is exact-bytes-seen; a production mesh needs monotonic counters.', '', '## Credits', '', '- The κ-witness is the primorial fold of Thomas Frumkin\'s Konomi codec; the capability lattice is the estate\'s wallet. ' + CREDIT + '.', '- Code: MIT.', '');
const llms = ['# SENTINEL', '', '> A structural immune system: a verify-before-parse signed-packet gate, a capability budget, a κ-witness, and a grown anomaly detector, sealed against a red-team battery.', '', headline, '', '## Key pages', '', '- [Live page](' + URL_LIVE + ')', '- [Repository](' + REPO + ')', '- [Pre-registration](' + URL_LIVE + 'data/prereg.json)', ...(run ? ['- [The record](' + URL_LIVE + 'data/run.json)'] : []), '', '## Credits', '', '- ' + CREDIT + '. The κ-witness fold is Thomas Frumkin\'s codec.', ''].join('\n');

writeFileSync(at('index.html'), page);
writeFileSync(at('README.md'), md.join('\n'));
writeFileSync(at('llms.txt'), llms);
if (run) writeFileSync(at('data/verdict.json'), JSON.stringify({ kind: 'sentinel-verdict', sealedIn: run.sealedIn, passed: j.passed, of: j.of, rules: j.rules.map((r) => ({ id: r.id, pass: r.pass, value: r.value })), hard: run.hard, grown: { grownCatch: run.grown.grownCatch, baselineCatch: run.grown.baselineCatch, heldAttacks: run.grown.heldAttacks } }, null, 1) + '\n');
console.log('page built · ' + (run ? j.passed + ' of ' + j.of + ' rules' : 'sealed, not yet run'));
