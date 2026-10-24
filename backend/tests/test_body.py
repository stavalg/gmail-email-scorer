import time

import app.parsing.body as body_module
from app.parsing.body import MAX_ANALYZED_TEXT_CHARS, MAX_LINKS, Link, parse_body


def test_extracts_anchor_links_with_visible_text():
    body = parse_body('<p>Hi</p><a href="https://evil.xyz/x">  www.paypal.com </a>', "")
    assert body.links == (Link(href="https://evil.xyz/x", text="www.paypal.com"),)


def test_script_and_style_are_not_text():
    body = parse_body("<style>.a{}</style><script>alert(1)</script><p>Hello</p>", "")
    assert "alert" not in body.text and "Hello" in body.text


def test_plain_text_urls_are_extracted_without_trailing_punctuation():
    body = parse_body("", "Go to https://bit.ly/abc. Thanks")
    assert Link(href="https://bit.ly/abc", text="") in body.links


def test_duplicate_links_are_collapsed():
    html = '<a href="https://a.com">x</a>' * 3
    assert len(parse_body(html, "").links) == 1


def test_plain_text_copy_of_an_anchor_is_not_duplicated():
    body = parse_body('<a href="https://a.com/x">click</a>', "click https://a.com/x")
    assert len(body.links) == 1


def test_link_hidden_after_padding_is_still_found():
    html = "<p>" + "harmless " * 25_000 + '</p><a href="http://evil.xyz/login">click</a>'
    body = parse_body(html, "")
    assert Link(href="http://evil.xyz/login", text="click") in body.links
    assert body.text_truncated


def test_text_comes_from_html_when_plain_text_is_empty():
    assert "Hello" in parse_body("<p>Hello</p>", "  ").text


def test_plain_text_is_preferred_when_present():
    assert parse_body("<p>html</p>", "plain").text == "plain"


def test_long_text_is_truncated():
    body = parse_body("", "a" * (MAX_ANALYZED_TEXT_CHARS + 10))
    assert len(body.text) == MAX_ANALYZED_TEXT_CHARS and body.text_truncated


def test_link_limit():
    html = "".join(f'<a href="https://a{i}.com">x</a>' for i in range(MAX_LINKS + 5))
    body = parse_body(html, "")
    assert len(body.links) == MAX_LINKS and body.links_truncated


def test_counts_images():
    assert parse_body('<img src="a.png"><img src="b.png"/>', "").image_count == 2


def test_empty_body():
    body = parse_body("", "")
    assert body.text == "" and body.links == () and not body.text_truncated


def test_html_parser_crash_degrades_to_plain_text(monkeypatch):
    # Older Pythons' HTMLParser raises on inputs like "<![<![": never let that kill the analysis.
    def crash(self, data):
        raise AssertionError("parser bug")
    monkeypatch.setattr(body_module._HtmlCollector, "feed", crash)
    body = parse_body("<p>anything</p>", "plain fallback https://evil.xyz/x")
    assert body.html_parse_failed
    assert body.text == "plain fallback https://evil.xyz/x"
    assert Link(href="https://evil.xyz/x", text="") in body.links


def test_known_pathological_html_is_fast():
    # CPython's HTMLParser was quadratic on these (28 s on 3.12.10); fixed in the Python we pin.
    for html in ("</" * 250_000, "<![<![ hello" * 1000, "<!--" * 125_000):
        started = time.perf_counter()
        parse_body(html, "")
        assert time.perf_counter() - started < 2, html[:12]


def test_huge_malformed_html_is_fast_and_safe():
    html = ('<a href="x"><b>unclosed <div><<<>>> &bogus; ' * 12_000)[:500_000]
    started = time.perf_counter()
    parse_body(html, "")
    assert time.perf_counter() - started < 2
