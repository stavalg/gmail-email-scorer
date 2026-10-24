"""Extracts readable text and links from the email body.

HTML is only parsed as data with Python's built-in parser: nothing is rendered, executed or fetched.
"""
import re
from dataclasses import dataclass
from html.parser import HTMLParser

MAX_ANALYZED_TEXT_CHARS = 100_000
MAX_LINKS = 200

_PLAIN_URL = re.compile(r"https?://[^\s<>\"')\]]+", re.IGNORECASE)
_BLOCK_TAGS = {"br", "p", "div", "tr", "li", "table", "h1", "h2", "h3"}


@dataclass(frozen=True)
class Link:
    href: str
    text: str  # visible text of the link; '' for URLs written as plain text


@dataclass(frozen=True)
class ParsedBody:
    text: str
    links: tuple[Link, ...]
    image_count: int
    text_truncated: bool
    links_truncated: bool
    html_parse_failed: bool = False


class _HtmlCollector(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.text_parts: list[str] = []
        self.links: list[Link] = []
        self.image_count = 0
        self._skip_depth = 0
        self._href: str | None = None
        self._link_text: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self._skip_depth += 1
        elif tag == "img":
            self.image_count += 1
        elif tag == "a":
            self._finish_link()
            self._href = (dict(attrs).get("href") or "").strip()
        if tag in _BLOCK_TAGS:
            self.text_parts.append("\n")

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self._skip_depth:
            self._skip_depth -= 1
        elif tag == "a":
            self._finish_link()

    def handle_data(self, data):
        if self._skip_depth:
            return
        self.text_parts.append(data)
        if self._href is not None:
            self._link_text.append(data)

    def close(self):
        super().close()
        self._finish_link()

    def _finish_link(self):
        if self._href is not None:
            text = " ".join("".join(self._link_text).split())
            self.links.append(Link(href=self._href, text=text))
        self._href = None
        self._link_text = []


def parse_body(body_html: str, body_text: str) -> ParsedBody:
    collector = _HtmlCollector()
    html_parse_failed = False
    try:
        collector.feed(body_html)
        collector.close()
    except Exception:  # noqa: BLE001 - a parser bug on hostile HTML must not stop the analysis
        html_parse_failed = True
        collector._finish_link()  # keep the links collected before the failure

    text = body_text if body_text.strip() else "".join(collector.text_parts)
    anchor_hrefs = {link.href for link in collector.links}
    plain_links = [
        Link(href=match.group(0).rstrip(".,;:!?"), text="")
        for match in _PLAIN_URL.finditer(text)
    ]
    plain_links = [link for link in plain_links if link.href not in anchor_hrefs]
    links = list(dict.fromkeys(collector.links + plain_links))  # de-duplicate, keep order

    return ParsedBody(
        text=text[:MAX_ANALYZED_TEXT_CHARS],
        links=tuple(links[:MAX_LINKS]),
        image_count=collector.image_count,
        text_truncated=len(text) > MAX_ANALYZED_TEXT_CHARS,
        links_truncated=len(links) > MAX_LINKS,
        html_parse_failed=html_parse_failed,
    )
