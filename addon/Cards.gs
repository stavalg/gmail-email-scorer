/** All user interface cards. Every string that came from an email is passed through escapeHtml. */

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
    .addSection(CardService.newCardSection()
      .addWidget(CardService.newTextParagraph().setText('Open an email to analyze it.')))
    .build();
}

function buildStartCard() {
  const analyze = CardService.newAction().setFunctionName('onAnalyze');
  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle('Email Security Check'))
    .addSection(CardService.newCardSection()
      .addWidget(CardService.newTextParagraph()
        .setText('Check this email for phishing and malware signals.'))
      .addWidget(CardService.newTextParagraph()
        .setText('🔒 Nothing is sent until you click Analyze.'))
      .addWidget(CardService.newTextButton()
        .setText('Analyze this email')
        .setTextButtonStyle(CardService.TextButtonStyle.FILLED)
        .setOnClickAction(analyze)))
    .build();
}

// TEMPORARY (replaced in Task 15): shows the stub answer.
function buildResultCard(result) {
  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle('Result (stub)'))
    .addSection(CardService.newCardSection()
      .addWidget(CardService.newTextParagraph().setText(
        escapeHtml(result.verdict) + ' · ' + escapeHtml(result.score) + '<br>' + escapeHtml(result.summary))))
    .build();
}

const ERROR_MESSAGES = {
  unauthorized: "You're not authorized to use this service.",
  invalid_response: 'The analysis service returned an unexpected answer.',
};

function buildErrorCard(kind) {
  const message = ERROR_MESSAGES[kind] || "Couldn't reach the analysis service. Please try again.";
  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle('Email Security Check'))
    .addSection(CardService.newCardSection()
      .addWidget(CardService.newTextParagraph().setText('⚠️ ' + escapeHtml(message)))
      .addWidget(CardService.newTextButton()
        .setText('Retry')
        .setOnClickAction(CardService.newAction().setFunctionName('onAnalyze'))))
    .build();
}
