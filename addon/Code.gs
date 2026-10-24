/** Entry points called by Gmail. */

function onHomepage() {
  return buildHomepageCard();
}

function onGmailMessageOpen() {
  return buildStartCard();
}

/** Gives the script access to the one message the user opened (and only that one). */
function getOpenedMessage(e) {
  GmailApp.setCurrentMessageAccessToken(e.gmail.accessToken);
  return GmailApp.getMessageById(e.gmail.messageId);
}

// TEMPORARY (removed in Task 4): checks the two risky capabilities from the spec.
function onProbe(e) {
  const raw = getOpenedMessage(e).getRawContent();
  const token = ScriptApp.getIdentityToken();
  const claims = token ? decodeJwtPayload(token) : null;
  const lines = [
    'Raw message length: ' + raw.length,
    'Has Google Authentication-Results: ' + /^Authentication-Results: mx\.google\.com/m.test(raw),
    'Identity token: ' + (token ? 'yes' : 'NO'),
    'Token audience (aud): ' + (claims ? claims.aud : '-'),
    'Token email: ' + (claims ? claims.email : '-'),
  ];
  const card = CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle('Probe results'))
    .addSection(CardService.newCardSection()
      .addWidget(CardService.newTextParagraph().setText(lines.map(escapeHtml).join('<br>'))))
    .build();
  return CardService.newActionResponseBuilder()
    .setNavigation(CardService.newNavigation().updateCard(card))
    .build();
}

function decodeJwtPayload(token) {
  const part = token.split('.')[1];
  const padded = part + '='.repeat((4 - (part.length % 4)) % 4);
  return JSON.parse(Utilities.newBlob(Utilities.base64DecodeWebSafe(padded)).getDataAsString());
}
