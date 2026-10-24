"""Content checks: pressure tactics and requests for sensitive data (English phrases only)."""
import re

from app.analyzers.rules.common import RuleOutput, make_finding
from app.analyzers.rules.data import CREDENTIAL_PHRASES, URGENCY_PHRASES
from app.context import EmailContext

MOSTLY_IMAGES_MAX_TEXT = 200


def _compile(phrases):
    """Prepares whole-word, case-insensitive patterns for a list of phrases."""
    return [(phrase, re.compile(rf"\b{re.escape(phrase)}\b")) for phrase in phrases]


_URGENCY = _compile(URGENCY_PHRASES)
_CREDENTIALS = _compile(CREDENTIAL_PHRASES)


def check(ctx: EmailContext) -> RuleOutput:
    """Rule: flags urgency/threat wording and requests for passwords or payment details."""
    out = RuleOutput()
    text = " ".join(f"{ctx.headers.subject}\n{ctx.body.text}".lower().split())

    urgency = [phrase for phrase, pattern in _URGENCY if pattern.search(text)]
    if urgency:
        out.findings.append(make_finding(
            "urgency_language", "content", "Urgency or threat language", _describe(urgency)))
    credentials = [phrase for phrase, pattern in _CREDENTIALS if pattern.search(text)]
    if credentials:
        out.findings.append(make_finding(
            "credential_request", "content", "Asks for passwords or payment details",
            _describe(credentials)))

    body_text = ctx.body.text.strip()
    if not body_text:
        out.facts.append("The email has no readable text.")
    elif ctx.body.image_count and len(body_text) < MOSTLY_IMAGES_MAX_TEXT:
        out.facts.append("The email is mostly images, so text analysis is limited.")
    return out


def _describe(found: list[str]) -> str:
    """Evidence text: the first matched phrase and how many more were found."""
    more = f" (+{len(found) - 1} more)" if len(found) > 1 else ""
    return f'Phrases like "{found[0]}"{more}.'
