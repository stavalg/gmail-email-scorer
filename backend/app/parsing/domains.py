"""Domain helpers. They only look at text: nothing here ever connects to a host."""
import ipaddress
from urllib.parse import urlsplit

import tldextract

# Bundled copy of the Public Suffix List: no network download and no cache files at runtime.
_extract = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)


def _normalize(host: str) -> str:
    return host.strip().lower().rstrip(".")


def registrable_domain(host: str) -> str:
    """The part of a host that someone actually registered: 'login.paypal.co.uk' -> 'paypal.co.uk'."""
    return _extract(_normalize(host)).top_domain_under_public_suffix


def split_host(host: str) -> tuple[str, str, str]:
    """'a.b.paypal.co.uk' -> ('a.b', 'paypal', 'co.uk')."""
    parts = _extract(_normalize(host))
    return parts.subdomain, parts.domain, parts.suffix


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def web_host(href: str) -> str:
    """Host of an http(s) link, lowercased. '' for other schemes, relative or malformed links."""
    href = href.strip()
    if href.startswith("//"):
        href = "https:" + href  # protocol-relative links open as web links
    if not href.lower().startswith(("http://", "https://")):
        return ""
    try:
        return (urlsplit(href).hostname or "").lower()
    except ValueError:
        return ""


def defang(value: str) -> str:
    """'http://evil.com' -> 'hxxp://evil[.]com': readable for people, never clickable."""
    return value.replace("http", "hxxp").replace(".", "[.]")
