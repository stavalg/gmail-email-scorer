"""Sender checks: who the email claims to be from vs. who actually sent it."""
import re

from app.analyzers.rules.common import RuleOutput, make_finding
from app.analyzers.rules.data import BRANDS, Brand
from app.context import EmailContext
from app.parsing.domains import defang, registrable_domain, split_host
from app.parsing.headers import Address

_EMAIL_IN_TEXT = re.compile(r"[\w.+-]+@([\w-]+(?:\.[\w-]+)+)")
# Characters attackers swap for look-alikes, mapped back to what they imitate.
_HOMOGLYPHS = (("rn", "m"), ("vv", "w"), ("0", "o"), ("1", "l"), ("3", "e"), ("5", "s"))


def check(ctx: EmailContext) -> RuleOutput:
    out = RuleOutput()
    sender = ctx.headers.sender
    if sender is None:
        out.findings.append(make_finding(
            "malformed_sender", "sender", "Malformed sender address",
            "The From address could not be read, so sender checks were skipped."))
        return out
    _brand_in_display_name(sender, out)
    _lookalike_domain(sender, out)
    _address_in_display_name(sender, out)
    _reply_to_mismatch(sender, ctx.headers.reply_to, out)
    return out


def find_brand_in_text(text: str) -> Brand | None:
    lowered = text.lower()
    for brand in BRANDS:
        if any(re.search(rf"\b{re.escape(keyword)}\b", lowered) for keyword in brand.keywords):
            return brand
    return None


def find_lookalike_brand(domain: str) -> Brand | None:
    """'paypa1.com' -> PayPal. A brand's own domains and exact-name variants are not lookalikes."""
    label = split_host(domain)[1]
    normalized = label
    for fake, real in _HOMOGLYPHS:
        normalized = normalized.replace(fake, real)
    for brand in BRANDS:
        if domain in brand.domains:
            continue
        for token in brand.domain_tokens:
            if label == token or len(token) < 5:
                continue
            if normalized == token or (len(token) >= 6 and edit_distance(label, token) == 1):
                return brand
    return None


def edit_distance(a: str, b: str) -> int:
    """How many single-letter edits turn a into b (Levenshtein distance)."""
    previous = list(range(len(b) + 1))
    for i, char_a in enumerate(a, start=1):
        current = [i]
        for j, char_b in enumerate(b, start=1):
            current.append(min(previous[j] + 1, current[j - 1] + 1,
                               previous[j - 1] + (char_a != char_b)))
        previous = current
    return previous[-1]


def _brand_in_display_name(sender: Address, out: RuleOutput) -> None:
    brand = find_brand_in_text(sender.display_name)
    if brand and sender.domain not in brand.domains:
        out.findings.append(make_finding(
            "brand_display_name", "sender", "Sender name impersonates a brand",
            f'The name says "{brand.name}" but the email comes from '
            f"{defang(sender.domain or sender.address)}."))


def _lookalike_domain(sender: Address, out: RuleOutput) -> None:
    if not sender.domain:
        return
    brand = find_lookalike_brand(sender.domain)
    if brand:
        out.findings.append(make_finding(
            "lookalike_domain", "sender", "Lookalike domain",
            f"{defang(sender.domain)} imitates {brand.name} ({defang(brand.domains[0])})."))


def _address_in_display_name(sender: Address, out: RuleOutput) -> None:
    match = _EMAIL_IN_TEXT.search(sender.display_name)
    if not match:
        return
    shown_domain = registrable_domain(match.group(1))
    if shown_domain and shown_domain != sender.domain:
        out.findings.append(make_finding(
            "display_name_address", "sender", "Sender name shows a different address",
            f"The name shows {defang(match.group(0).lower())} but the real sender is "
            f"{defang(sender.address)}."))


def _reply_to_mismatch(sender: Address, reply_to: Address | None, out: RuleOutput) -> None:
    if reply_to and reply_to.domain and sender.domain and reply_to.domain != sender.domain:
        out.findings.append(make_finding(
            "reply_to_mismatch", "sender", "Replies go to a different domain",
            f"Replies would go to {defang(reply_to.domain)}, not {defang(sender.domain)}."))
