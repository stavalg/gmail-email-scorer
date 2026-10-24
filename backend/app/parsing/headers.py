"""Reads the email's header block.

Everything in it is written by the sender (so possibly an attacker), except the
Authentication-Results header that Google's own server adds at the very top.
"""
import re
from dataclasses import dataclass
from email.message import Message
from email.parser import HeaderParser
from email.policy import default as default_policy
from email.utils import getaddresses

from app.parsing.domains import registrable_domain

TRUSTED_AUTHSERV_ID = "mx.google.com"
# RFC 8601: "authserv-id; method=result (comment) property=value; ..."
_QUOTED = re.compile(r'"(?:[^"\\]|\\.)*"')
_COMMENT = re.compile(r"\([^()]*\)")
_CLAUSE_RESULT = re.compile(r"^\s*(spf|dkim|dmarc)\s*=\s*([a-z]+)\b", re.IGNORECASE)


@dataclass(frozen=True)
class Address:
    """One email address: the display name, the address and its registrable domain."""
    display_name: str
    address: str  # lowercased
    domain: str   # registrable domain, '' if unknown


@dataclass(frozen=True)
class ParsedHeaders:
    """What we use from the headers: sender, Reply-To, subject and Google's auth results."""
    sender: Address | None
    reply_to: Address | None
    subject: str
    auth: dict[str, str] | None  # e.g. {"spf": "pass", "dkim": "fail", "dmarc": "fail"}


def parse_headers(raw: str) -> ParsedHeaders:
    """Reads From, Reply-To, Subject and the trusted Authentication-Results header."""
    message = HeaderParser(policy=default_policy).parsestr(raw)
    return ParsedHeaders(
        sender=_first_address(message, "From"),
        reply_to=_first_address(message, "Reply-To"),
        subject=_header_text(message, "Subject"),
        auth=_trusted_auth_results(message),
    )


def _header_text(message: Message, name: str) -> str:
    """A header's decoded text, or '' if it is missing or malformed."""
    try:
        value = message.get(name)
        return str(value).strip() if value is not None else ""
    except Exception:  # noqa: BLE001 - a malformed header is treated as missing
        return ""


def _first_address(message: Message, name: str) -> Address | None:
    """The first email address in a header, or None if it has no valid address."""
    value = _header_text(message, name)
    if not value:
        return None
    pairs = getaddresses([value])
    if not pairs:
        return None
    display_name, address = pairs[0]
    address = address.strip().lower()
    if "@" not in address:
        return None
    return Address(
        display_name=display_name.strip(),
        address=address,
        domain=registrable_domain(address.rpartition("@")[2]),
    )


def _trusted_auth_results(message: Message) -> dict[str, str] | None:
    """Only the topmost Authentication-Results header, and only if Google wrote it."""
    try:
        headers = message.get_all("Authentication-Results") or []
    except Exception:  # noqa: BLE001
        return None
    if not headers:
        return None
    top = " ".join(str(headers[0]).split())
    # Google echoes attacker-chosen text (e.g. the envelope sender) inside quoted strings and
    # comments; drop them, then read only the "method=result" that starts each clause.
    top = _QUOTED.sub('""', top)
    while _COMMENT.search(top):
        top = _COMMENT.sub(" ", top)
    authserv_id, *clauses = top.split(";")
    if authserv_id.strip().lower() != TRUSTED_AUTHSERV_ID:
        return None
    results: dict[str, str] = {}
    for clause in clauses:
        match = _CLAUSE_RESULT.match(clause)
        if match:
            results.setdefault(match.group(1).lower(), match.group(2).lower())
    return results
