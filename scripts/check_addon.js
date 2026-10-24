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
