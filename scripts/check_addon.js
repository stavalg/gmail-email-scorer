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

// Score scale: 20 cells of 5 points, separators at 30 and 70, filled cells up to the score.
const filledCells = (html) => (html.match(/■/g) || []).length;
for (const [score, filled] of [[0, 0], [35, 7], [100, 20]]) {
  const bar = context.scoreBar(score);
  assert.strictEqual(filledCells(bar), filled, `score ${score}`);
  assert.strictEqual((bar.match(/■|□/g) || []).length, 20);
  assert.strictEqual((bar.match(/│/g) || []).length, 2);
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
