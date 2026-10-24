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

// Score scale: one unbroken half-height bar "0 ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ 100" of 20 cells (5 points each),
// filled up to the score in strong zone colors (green <30, orange 30-69, red 70+), the rest pale.
const ZONES = vm.runInContext('ZONE_COLORS', context);  // top-level const isn't a property of the context
const zone = (cell) => (cell * 5 >= 70 ? 'malicious' : cell * 5 >= 30 ? 'suspicious' : 'safe');
for (const [score, filled] of [[0, 0], [35, 7], [100, 20]]) {
  const cells = context.scoreBarCells(score);
  assert.strictEqual(cells.length, 20, `score ${score}`);
  cells.forEach((color, cell) => {
    const expected = cell < filled ? ZONES[zone(cell)].strong : ZONES[zone(cell)].pale;
    assert.strictEqual(color, expected, `score ${score}, cell ${cell}`);
  });
  const plain = context.scoreBar(score).replace(/<[^>]+>/g, '');
  assert.strictEqual(plain, '0 ' + '▄'.repeat(20) + ' 100');
}

const valid = { verdict: 'safe', score: 5, findings: [], facts: [], notices: [], coverage: {} };
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
