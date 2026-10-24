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
_AUTH_RESULT = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-z]+)", re.IGNORECASE)


@dataclass(frozen=True)
class Address:
    display_name: str
    address: str  # lowercased
    domain: str   # registrable domain, '' if unknown


@dataclass(frozen=True)
class ParsedHeaders:
    sender: Address | None
    reply_to: Address | None
    subject: str
    auth: dict[str, str] | None  # e.g. {"spf": "pass", "dkim": "fail", "dmarc": "fail"}


def parse_headers(raw: str) -> ParsedHeaders:
    message = HeaderParser(policy=default_policy).parsestr(raw)
    return ParsedHeaders(
        sender=_first_address(message, "From"),
        reply_to=_first_address(message, "Reply-To"),
        subject=_header_text(message, "Subject"),
        auth=_trusted_auth_results(message),
    )


def _header_text(message: Message, name: str) -> str:
    try:
        value = message.get(name)
        return str(value).strip() if value is not None else ""
    except Exception:  # noqa: BLE001 - a malformed header is treated as missing
        return ""


def _first_address(message: Message, name: str) -> Address | None:
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
    if not top.lower().startswith(TRUSTED_AUTHSERV_ID):
        return None
    results: dict[str, str] = {}
    for method, result in _AUTH_RESULT.findall(top):
        results.setdefault(method.lower(), result.lower())
    return results
