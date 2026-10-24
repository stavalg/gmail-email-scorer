/** All user interface cards. Every string that came from the email or the backend is escaped. */

const VERDICT_STYLES = {
  safe: { icon: '🟢', label: 'SAFE', color: '#188038' },
  suspicious: { icon: '🟠', label: 'SUSPICIOUS', color: '#e37400' },
  malicious: { icon: '🔴', label: 'MALICIOUS', color: '#d93025' },
};
const COVERAGE_LABELS = { rules: 'Rules', virustotal: 'VirusTotal', llm: 'AI' };
const STATUS_TEXT = {
  ok: '✓', partial: 'partial', skipped: 'skipped / not configured', error: 'failed',
  timeout: 'timed out', rate_limited: 'rate-limited',
};
const ERROR_MESSAGES = {
  unauthorized: "You're not authorized to use this service.",
  invalid_response: 'The analysis service returned an unexpected answer.',
};

/** Makes any text safe to show on a card: tags and quotes are displayed, never interpreted. */
function escapeHtml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/** Shown when no email is open. */
function buildHomepageCard() {
  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle('Email Security Check'))
    .addSection(textSection(null, ['Open an email to analyze it.']))
    .build();
}

/** Shown when an email is opened: explains the tool and offers the Analyze button. */
function buildStartCard() {
  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle('Email Security Check'))
    .addSection(textSection(null, [
      'Check this email for phishing and malware signals.',
      '🔒 Nothing is sent until you click Analyze.',
    ]).addWidget(analyzeButton('Analyze this email')))
    .build();
}

/**
 * Clean at a glance: verdict, score scale and any warnings are visible;
 * the reasons and the analyst details open on demand.
 */
function buildResultCard(result) {
  const style = VERDICT_STYLES[result.verdict];
  const isSafe = result.verdict === 'safe';

  // The verdict and its scale sit together at the top (a card header can't hold colors).
  const verdict = '<font color="' + style.color + '"><b>' + style.icon + ' ' + style.label
    + ' · ' + result.score + ' / 100</b></font><br>' + scoreBar(result.score);
  const summary = ['<font color="' + style.color + '"><b>' + escapeHtml(result.summary) + '</b></font>']
    .concat(result.notices.map((n) => '⚠️ ' + escapeHtml(n)))
    .concat(isSafe ? result.facts.map((f) => '✅ ' + escapeHtml(f)) : []);

  const card = CardService.newCardBuilder()
    .addSection(textSection(null, [verdict]))
    .addSection(textSection(null, summary));
  if (result.findings.length) card.addSection(findingsSection(result.findings));
  card.addSection(detailsSection(result, !isSafe));
  card.addSection(CardService.newCardSection().addWidget(analyzeButton('Analyze again')));
  return card.build();
}

const ZONE_COLORS = {
  safe: { strong: '#188038', pale: '#ceead6' },
  suspicious: { strong: '#e37400', pale: '#fde2c4' },
  malicious: { strong: '#d93025', pale: '#fad2cf' },
};

/**
 * Color of each of the 20 cells (5 points each): strong once the score reaches the cell's
 * start, pale otherwise — so a score of 30 shows orange and 70 shows red, like the verdict.
 */
function scoreBarCells(score) {
  const cells = [];
  for (let cell = 0; cell < 20; cell++) {
    const zone = cell * 5 >= 70 ? 'malicious' : cell * 5 >= 30 ? 'suspicious' : 'safe';
    const filled = score > 0 && cell * 5 <= score;
    cells.push(filled ? ZONE_COLORS[zone].strong : ZONE_COLORS[zone].pale);
  }
  return cells;
}

/** One unbroken, half-height progress bar drawn with text (cards can't draw graphics). */
function scoreBar(score) {
  const bar = scoreBarCells(score).map((color) => '<font color="' + color + '">▄</font>').join('');
  return '<font color="#9aa0a6">0 </font>' + bar + '<font color="#9aa0a6"> 100</font>';
}

/** Shown when the analysis could not be completed; offers Retry. */
function buildErrorCard(kind) {
  const message = ERROR_MESSAGES[kind] || "Couldn't reach the analysis service. Please try again.";
  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle('Email Security Check'))
    .addSection(textSection(null, ['⚠️ ' + escapeHtml(message)]).addWidget(analyzeButton('Retry')))
    .build();
}

/** A card section with an optional header and lines of (already escaped) text. */
function textSection(header, lines) {
  const section = CardService.newCardSection();
  if (header) section.setHeader(header);
  return section.addWidget(CardService.newTextParagraph().setText(lines.join('<br>')));
}

/** A button that runs the analysis (used for Analyze, Analyze again and Retry). */
function analyzeButton(label) {
  return CardService.newTextButton()
    .setText(label)
    .setTextButtonStyle(CardService.TextButtonStyle.FILLED)
    .setOnClickAction(CardService.newAction().setFunctionName('onAnalyze'));
}

/** Collapsed by default: the header shows how many reasons there are; tap to expand. */
function findingsSection(findings) {
  const section = CardService.newCardSection()
    .setHeader('🔍 Why? (' + findings.length + (findings.length === 1 ? ' reason)' : ' reasons)'))
    .setCollapsible(true)
    .setNumUncollapsibleWidgets(0);
  findings.forEach((finding) => {
    section.addWidget(CardService.newDecoratedText()
      .setTopLabel('+' + Number(finding.points) + ' · ' + String(finding.category))
      .setText('<b>' + escapeHtml(finding.title) + '</b><br>' + escapeHtml(finding.evidence))
      .setWrapText(true));
  });
  return section;
}

/** One 'Details' line saying whether an analyzer ran, e.g. 'VirusTotal: ✓ (2 of 2 checked)'. */
function describeCoverage(name, item) {
  let text = (COVERAGE_LABELS[name] || name) + ': ' + (STATUS_TEXT[item.status] || item.status);
  if (item.checked !== null && item.checked !== undefined && item.total) {
    text += ' (' + item.checked + ' of ' + item.total + ' checked)';
  }
  return text;
}

/** Collapsed analyst view: verified facts (when not already shown), coverage and technical data. */
function detailsSection(result, includeFacts) {
  const details = result.details || {};
  const lines = (includeFacts ? result.facts.map((f) => '✅ ' + escapeHtml(f)) : [])
    .concat(Object.keys(result.coverage)
      .map((name) => '📊 ' + escapeHtml(describeCoverage(name, result.coverage[name]))))
    .concat(Object.keys(details).map((key) =>
      '<b>' + escapeHtml(key) + ':</b> ' + escapeHtml(JSON.stringify(details[key]))));
  return CardService.newCardSection()
    .setHeader('Details')
    .setCollapsible(true)
    .setNumUncollapsibleWidgets(0)
    .addWidget(CardService.newTextParagraph().setText(lines.join('<br>') || 'None'));
}
