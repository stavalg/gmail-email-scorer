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

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function buildHomepageCard() {
  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle('Email Security Check'))
    .addSection(textSection(null, ['Open an email to analyze it.']))
    .build();
}

function buildStartCard() {
  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle('Email Security Check'))
    .addSection(textSection(null, [
      'Check this email for phishing and malware signals.',
      '🔒 Nothing is sent until you click Analyze.',
    ]).addWidget(analyzeButton('Analyze this email')))
    .build();
}

function buildResultCard(result) {
  const style = VERDICT_STYLES[result.verdict];
  const card = CardService.newCardBuilder().setHeader(CardService.newCardHeader()
    .setTitle(style.icon + ' ' + style.label + ' · ' + result.score + ' / 100')
    .setSubtitle('Email Security Check'));

  const headline = '<font color="' + style.color + '"><b>' + escapeHtml(result.summary) + '</b></font>';
  card.addSection(textSection(null, [headline].concat(result.notices.map((n) => '⚠️ ' + escapeHtml(n)))));
  card.addSection(textSection('✋ What should I do?', result.advice.map((a) => '• ' + escapeHtml(a))));
  card.addSection(findingsSection(result.findings));
  if (result.facts.length) {
    card.addSection(textSection('✅ Verified facts', result.facts.map((f) => '• ' + escapeHtml(f))));
  }
  card.addSection(textSection('📊 Analysis coverage', Object.keys(result.coverage)
    .map((name) => escapeHtml(describeCoverage(name, result.coverage[name])))));
  card.addSection(detailsSection(result.details || {}));
  card.addSection(textSection(null, [
    'Score: 0–29 Safe · 30–69 Suspicious · 70–100 Malicious',
    '<i>Automated assessment — it may be wrong.</i>',
  ]).addWidget(analyzeButton('Analyze again')));
  return card.build();
}

function buildErrorCard(kind) {
  const message = ERROR_MESSAGES[kind] || "Couldn't reach the analysis service. Please try again.";
  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle('Email Security Check'))
    .addSection(textSection(null, ['⚠️ ' + escapeHtml(message)]).addWidget(analyzeButton('Retry')))
    .build();
}

function textSection(header, lines) {
  const section = CardService.newCardSection();
  if (header) section.setHeader(header);
  return section.addWidget(CardService.newTextParagraph().setText(lines.join('<br>')));
}

function analyzeButton(label) {
  return CardService.newTextButton()
    .setText(label)
    .setTextButtonStyle(CardService.TextButtonStyle.FILLED)
    .setOnClickAction(CardService.newAction().setFunctionName('onAnalyze'));
}

function findingsSection(findings) {
  const section = CardService.newCardSection().setHeader('🔍 Why? (strongest first)');
  if (!findings.length) {
    return section.addWidget(CardService.newTextParagraph().setText('No warning signs found.'));
  }
  findings.forEach((finding) => {
    section.addWidget(CardService.newDecoratedText()
      .setTopLabel('+' + Number(finding.points) + ' · ' + String(finding.category))
      .setText('<b>' + escapeHtml(finding.title) + '</b><br>' + escapeHtml(finding.evidence))
      .setWrapText(true));
  });
  return section;
}

function describeCoverage(name, item) {
  let text = (COVERAGE_LABELS[name] || name) + ': ' + (STATUS_TEXT[item.status] || item.status);
  if (item.checked !== null && item.checked !== undefined && item.total) {
    text += ' (' + item.checked + ' of ' + item.total + ' checked)';
  }
  return text;
}

function detailsSection(details) {
  const lines = Object.keys(details).map((key) =>
    '<b>' + escapeHtml(key) + ':</b> ' + escapeHtml(JSON.stringify(details[key])));
  return CardService.newCardSection()
    .setHeader('Technical details (for analysts)')
    .setCollapsible(true)
    .setNumUncollapsibleWidgets(0)
    .addWidget(CardService.newTextParagraph().setText(lines.join('<br>') || 'None'));
}
