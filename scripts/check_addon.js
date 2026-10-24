// Offline checks of the add-on's pure functions (no Google services needed).
// Run from the repository root: node scripts/check_addon.js
const assert = require('assert');
const fs = require('fs');
const vm = require('vm');

const context = {};
vm.createContext(context);
for (const file of ['addon/Cards.gs', 'addon/Api.gs']) {
  vm.runInContext(fs.readFileSync(file, 'utf8'), context, { filename: file });
}

assert.strictEqual(
  context.escapeHtml('<a href="x">&</a>'),
  '&lt;a href=&quot;x&quot;&gt;&amp;&lt;/a&gt;',
);

// Score scale: a 20-segment line labelled 0 / 30 / 70 / 100 with one ● marker at the score.
for (const [score, markerAt] of [[0, 0], [35, 7], [100, 19]]) {
  const plain = context.scoreBar(score).replace(/<[^>]+>/g, '');
  const segments = plain.replace(/[^━●]/g, '');
  assert.strictEqual(segments.length, 20, `score ${score}`);
  assert.strictEqual(segments.indexOf('●'), markerAt, `score ${score}`);
  assert.strictEqual(segments.split('●').length, 2, `one marker for score ${score}`);
  assert.ok(/^0 .*30.*70.*100$/.test(plain), plain);
}

const valid = { verdict: 'safe', score: 5, findings: [], advice: [], facts: [], notices: [], coverage: {} };
assert.strictEqual(context.validateResult(valid), valid);
const invalid = [
  null,
  { ...valid, verdict: 'bad' },
  { ...valid, score: 101 },
  { ...valid, score: 1.5 },
  { ...valid, findings: 'x' },
  { ...valid, coverage: null },
];
for (const bad of invalid) {
  assert.throws(() => context.validateResult(bad), (err) => err.kind === 'invalid_response');
}
console.log('add-on checks passed');
