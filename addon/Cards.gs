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
  const analyze = CardService.newAction().setFunctionName('onProbe');
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
