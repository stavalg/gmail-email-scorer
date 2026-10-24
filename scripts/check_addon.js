// Offline checks of the add-on's pure functions (no Google services needed).
// Run from the repository root: node scripts/check_addon.js
const assert = require('assert');
const fs = require('fs');
const vm = require('vm');

const context = {};
vm.createContext(context);
for (const file of ['addon/Cards.gs', 'addon/Api.gs', 'addon/Extract.gs']) {
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
// A cell is filled when the score reaches its start, so 30 shows orange and 70 shows red.
for (const [score, filled] of [[0, 0], [29, 6], [30, 7], [35, 8], [69, 14], [70, 15], [100, 20]]) {
  const cells = context.scoreBarCells(score);
  assert.strictEqual(cells.length, 20, `score ${score}`);
  cells.forEach((color, cell) => {
    const expected = cell < filled ? ZONES[zone(cell)].strong : ZONES[zone(cell)].pale;
    assert.strictEqual(color, expected, `score ${score}, cell ${cell}`);
  });
  const plain = context.scoreBar(score).replace(/<[^>]+>/g, '');
  assert.strictEqual(plain, '0 ' + '▄'.repeat(20) + ' 100');
}

// Truncation must never split an emoji (a UTF-16 surrogate pair): the backend rejects half a character.
assert.deepStrictEqual(context.truncate('abc', 5), { text: 'abc', cut: false });
assert.deepStrictEqual(context.truncate('abcdef', 3), { text: 'abc', cut: true });
assert.deepStrictEqual(context.truncate('a😀b', 2), { text: 'a', cut: true });
assert.deepStrictEqual(context.truncate('', 3), { text: '', cut: false });
assert.deepStrictEqual(context.truncate(null, 3), { text: '', cut: false });

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
