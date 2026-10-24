"""Domain helpers. They only look at text: nothing here ever connects to a host."""
import ipaddress
import re
from urllib.parse import urlsplit

import tldextract

# Bundled copy of the Public Suffix List: no network download and no cache files at runtime.
_extract = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)

_IGNORED_IN_URLS = re.compile(r"[\t\r\n]")
_WEB_PREFIX = re.compile(r"^(https?:|[\\/]{2})", re.IGNORECASE)


def _normalize(host: str) -> str:
    """Lowercase, trimmed, without a trailing dot."""
    return host.strip().lower().rstrip(".")


def registrable_domain(host: str) -> str:
    """The part of a host that someone actually registered: 'login.paypal.co.uk' -> 'paypal.co.uk'."""
    return _extract(_normalize(host)).top_domain_under_public_suffix


def split_host(host: str) -> tuple[str, str, str]:
    """'a.b.paypal.co.uk' -> ('a.b', 'paypal', 'co.uk')."""
    parts = _extract(_normalize(host))
    return parts.subdomain, parts.domain, parts.suffix


def is_ip(host: str) -> bool:
    """True if the host is a raw IP address instead of a domain name."""
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def browser_href(href: str) -> str:
    """The link as a browser reads it (WHATWG URL rules): tabs and newlines are removed and,
    for web links, backslashes count as slashes. Python's urlsplit does neither, so without
    this 'https://evil.xyz\\@paypal.com' would look like paypal.com while browsers open evil.xyz."""
    href = _IGNORED_IN_URLS.sub("", href).strip()
    if _WEB_PREFIX.match(href):
        href = href.replace("\\", "/")
    return href


def web_host(href: str) -> str:
    """Host a browser would open for an http(s) link, lowercased. '' for other schemes,
    relative or malformed links."""
    href = browser_href(href)
    if href.startswith("//"):
        href = "https:" + href  # protocol-relative links open as web links
    scheme = re.match(r"^(https?):/*", href, re.IGNORECASE)  # browsers accept http:/x and http:///x
    if not scheme:
        return ""
    href = f"{scheme.group(1).lower()}://{href[scheme.end():]}"
    try:
        return (urlsplit(href).hostname or "").lower()
    except ValueError:
        return ""


def defang(value: str) -> str:
    """'http://evil.com' -> 'hxxp://evil[.]com': readable for people, never clickable."""
    return value.replace("http", "hxxp").replace(".", "[.]")
