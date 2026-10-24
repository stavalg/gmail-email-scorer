/** Entry points called by Gmail. */

/** Gmail calls this when the add-on is opened without an email selected. */
function onHomepage() {
  return buildHomepageCard();
}

/** Gmail calls this when the user opens an email. */
function onGmailMessageOpen() {
  return buildStartCard();
}

/** Gives the script access to the one message the user opened (and only that one). */
function getOpenedMessage(e) {
  GmailApp.setCurrentMessageAccessToken(e.gmail.accessToken);
  return GmailApp.getMessageById(e.gmail.messageId);
}

/** Runs when Analyze is clicked: collect the email, call the backend, show the result or an error. */
function onAnalyze(e) {
  let card;
  try {
    const result = callBackend(extractEmail(getOpenedMessage(e)));
    card = buildResultCard(result);
  } catch (err) {
    // Log only the kind of error, never email content.
    console.error('Analysis failed: ' + (err.kind || err.name));
    card = buildErrorCard(err.kind);
  }
  return CardService.newActionResponseBuilder()
    .setNavigation(CardService.newNavigation().updateCard(card))
    .build();
}
