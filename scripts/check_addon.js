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
  const barText = context.scoreBar(score).replace(/<[^>]+>/g, '');
  assert.strictEqual(barText, '0 ' + '▄'.repeat(20) + ' 100');
}

// Truncation must never split an emoji (a UTF-16 surrogate pair): the backend rejects half a character.
// (plain() copies the sandbox's object so Node compares values, not object origins.)
const plain = (value) => JSON.parse(JSON.stringify(value));
assert.deepStrictEqual(plain(context.truncate('abc', 5)), { text: 'abc', cut: false });
assert.deepStrictEqual(plain(context.truncate('abcdef', 3)), { text: 'abc', cut: true });
assert.deepStrictEqual(plain(context.truncate('a😀b', 2)), { text: 'a', cut: true });
assert.deepStrictEqual(plain(context.truncate('', 3)), { text: '', cut: false });
assert.deepStrictEqual(plain(context.truncate(null, 3)), { text: '', cut: false });

// Redaction: secrets meant for the reader are removed in Gmail, so the backend never sees them.
// Each pair is [what the email says, what the backend receives].
const redactionCases = [
  // A parameter whose name looks sensitive loses its value; harmless parameters stay.
  ['https://example.com/reset?token=abc&lang=en', 'https://example.com/reset?token=REDACTED&lang=en'],
  ['https://example.com/cb?Access_Token=x1&sig=y2', 'https://example.com/cb?Access_Token=REDACTED&sig=REDACTED'],
  // An unknown name with a random-looking value is hidden too.
  ['https://example.com/r?t=Zx8kP2qLm9Vb4Nw7Rt', 'https://example.com/r?t=REDACTED'],
  // A value that is itself a web address keeps its domain (for redirect checks), cleaned the same way.
  ['https://www.google.com/url?q=https://evil.xyz/login?token=abc',
    'https://www.google.com/url?q=https://evil.xyz/login?token=REDACTED'],
  ['https://t.example/r?u=https%3A%2F%2Fevil.xyz%2Fa%3Fcode%3D99',
    'https://t.example/r?u=https%3A%2F%2Fevil.xyz%2Fa%3Fcode%3DREDACTED'],
  ['https://t.example/r?next=evil-login-2026.xyz', 'https://t.example/r?next=evil-login-2026.xyz'],
  // The part after # is dropped: login systems put tokens there.
  ['https://app.example.com/cb#access_token=xyz', 'https://app.example.com/cb'],
  // A long random piece of the path is hidden; ordinary words stay.
  ['https://example.com/reset/8f3k2Lq9ZxP0vB7nM4tR', 'https://example.com/reset/REDACTED'],
  ['https://example.com/blog/how-to-spot-phishing-emails', 'https://example.com/blog/how-to-spot-phishing-emails'],
  // In HTML, &amp; separates parameters.
  ['<a href="https://x.com/a?lang=en&amp;code=123456">Open</a>',
    '<a href="https://x.com/a?lang=en&amp;code=REDACTED">Open</a>'],
  // Passwords: the word stays (rules look for it), the value goes.
  ['Your password: hunter2', 'Your password: [hidden]'],
  ['Your temporary password is Xy7!pq', 'Your temporary password is [hidden]'],
  ['PIN: 4821', 'PIN: [hidden]'],
  ['Make sure your password is correct', 'Make sure your password is correct'],
  ['Please verify your password within 24 hours.', 'Please verify your password within 24 hours.'],
  // One-time codes, also when the email wraps them in formatting.
  ['Your verification code is 482913', 'Your verification code is [code]'],
  ['<p>Your OTP: <b>7731</b></p>', '<p>Your OTP: <b>[code]</b></p>'],
  ['Act within 24 hours', 'Act within 24 hours'],
];
for (const [input, expected] of redactionCases) {
  assert.strictEqual(context.redactSecrets(input), expected, input);
}
assert.strictEqual(context.redactSecrets(''), '');
assert.strictEqual(context.redactSecrets(null), '');

// The phishing sample keeps everything the rules read: link hosts and the warning phrases.
const phishing = JSON.parse(fs.readFileSync('backend/samples/phishing.json', 'utf8'));
assert.strictEqual(context.redactSecrets(phishing.body_html), phishing.body_html);

// A confirmed reason carries no points, so it says "Confirmed" instead of "+0".
assert.strictEqual(context.findingLabel({ points: 30, confirmed: false, category: 'links' }), '+30 · links');
assert.strictEqual(context.findingLabel({ points: 0, confirmed: true, category: 'reputation' }),
  'Confirmed · reputation');

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
