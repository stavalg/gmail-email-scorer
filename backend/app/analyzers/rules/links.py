"""Link checks. Links are only ever read as text: never visited."""
import re
from collections import defaultdict
from urllib.parse import urlsplit

from app.analyzers.rules.common import RuleOutput, make_finding, summarize
from app.analyzers.rules.data import ABUSED_TLDS, BRANDS, SHORTENERS, Brand
from app.context import EmailContext
from app.parsing.body import Link
from app.parsing.domains import defang, is_ip, registrable_domain, split_host, web_host

SCRIPT_SCHEMES = {"javascript", "data", "vbscript"}
_LOOKS_LIKE_ADDRESS = re.compile(
    r"^(?:https?://)?(?:[a-z0-9-]+\.)+[a-z]{2,}(?:[/:?#]\S*)?$", re.IGNORECASE)
TITLES = {
    "link_text_mismatch": "Link text doesn't match its destination",
    "brand_in_subdomain": "Brand name hidden in a link address",
    "punycode_link": "Disguised characters in a link address",
    "script_link": "Script or data link",
    "ip_link": "Link to a raw IP address",
    "shortener_link": "Shortened link hides its destination",
    "abused_tld": "Link to a frequently abused domain ending",
}


def check(ctx: EmailContext) -> RuleOutput:
    hits: dict[str, list[str]] = defaultdict(list)  # finding id -> one example per link
    for link in ctx.body.links:
        _inspect(link, hits)
    out = RuleOutput()
    for finding_id, examples in hits.items():
        evidence = summarize(examples)
        if len(examples) > 1:
            evidence = f"{len(examples)} link(s): {evidence}"
        out.findings.append(make_finding(finding_id, "links", TITLES[finding_id], evidence))
    return out


def _inspect(link: Link, hits: dict[str, list[str]]) -> None:
    scheme, separator, _ = link.href.strip().partition(":")
    if separator and scheme.lower() in SCRIPT_SCHEMES:
        hits["script_link"].append(f"{scheme.lower()}: link")
        return

    host = web_host(link.href)
    if not host:
        return  # mailto:, tel:, relative, anchors and malformed URLs have no web destination
    if is_ip(host):
        hits["ip_link"].append(defang(host))
        return

    domain = registrable_domain(host)
    subdomain, label, suffix = split_host(host)
    if not host.isascii() or any(part.startswith("xn--") for part in host.split(".")):
        hits["punycode_link"].append(defang(host))
    if domain in SHORTENERS:
        hits["shortener_link"].append(defang(domain))
    if suffix and suffix.rsplit(".", 1)[-1] in ABUSED_TLDS:
        hits["abused_tld"].append(defang(domain or host))
    if find_hidden_brand(subdomain, label, domain):
        hits["brand_in_subdomain"].append(defang(host))

    shown = _shown_domain(link.text)
    if shown and domain and shown != domain:
        hits["link_text_mismatch"].append(f"shows {defang(shown)} but goes to {defang(domain)}")


def find_hidden_brand(subdomain: str, label: str, domain: str) -> Brand | None:
    """'paypal.com.secure-login.xyz' or 'paypal-verify.com': a brand inside a domain it doesn't own.
    An exact brand label on another ending (paypal.de) is treated as a regional site."""
    tokens = set(re.split(r"[.-]", subdomain)) | set(label.split("-"))
    for brand in BRANDS:
        if domain in brand.domains:
            continue
        if any(token in tokens and token != label for token in brand.domain_tokens):
            return brand
    return None


def _shown_domain(text: str) -> str:
    """The domain the link text *claims*, if the text looks like an address at all."""
    candidate = text.strip().lower()
    if not _LOOKS_LIKE_ADDRESS.match(candidate):
        return ""
    if "://" not in candidate:
        candidate = "http://" + candidate
    try:
        return registrable_domain(urlsplit(candidate).hostname or "")
    except ValueError:
        return ""
