from app.analyzers.rules import links
from tests.helpers import ids, make_context


def findings(html):
    return links.check(make_context(body_html=html)).findings


def run(html):
    return ids(findings(html))


def test_text_shows_one_domain_but_goes_to_another():
    assert "link_text_mismatch" in run('<a href="http://evil-login.xyz/a">www.paypal.com</a>')


def test_same_registrable_domain_is_not_a_mismatch():
    assert run('<a href="https://click.paypal.com/x">paypal.com</a>') == set()


def test_normal_link_text_is_fine():
    assert run('<a href="https://shop.example.com/x">Click here</a>') == set()


def test_raw_ip_link():
    assert run('<a href="http://45.13.2.9/login">Login</a>') == {"ip_link"}


def test_punycode_link():
    assert "punycode_link" in run('<a href="http://xn--pypal-4ve.com/">x</a>')


def test_unicode_lookalike_host():
    assert "punycode_link" in run('<a href="http://pаypal.com/">x</a>')  # Cyrillic 'а'


def test_brand_hidden_in_subdomain():
    found = run('<a href="http://paypal.com.secure-login.xyz/">x</a>')
    assert {"brand_in_subdomain", "abused_tld"} <= found


def test_brand_hidden_with_hyphen():
    assert "brand_in_subdomain" in run('<a href="http://paypal-verify.com/">x</a>')


def test_regional_brand_domain_is_not_flagged():
    assert run('<a href="https://www.paypal.de/">x</a>') == set()


def test_each_signal_counts_once_with_count_in_evidence():
    html = "".join(f'<a href="https://bit.ly/{c}">x</a>' for c in "abc")
    result = findings(html)
    assert [f.id for f in result] == ["shortener_link"]
    assert result[0].evidence.startswith("3 link(s)")


def test_non_web_links_are_ignored():
    html = ('<a href="mailto:a@b.com">m</a><a href="tel:123">t</a>'
            '<a href="#top">top</a><a href="/relative">r</a>')
    assert run(html) == set()


def test_javascript_link():
    assert run('<a href="javascript:alert(1)">x</a>') == {"script_link"}


def test_malformed_url_does_not_crash():
    assert run('<a href="http://[broken">x</a>') == set()


def test_protocol_relative_and_uppercase_links():
    result = findings('<a href="//evil.top/x">a</a><a href="HTTP://Evil.Top/y">b</a>')
    assert [f.id for f in result] == ["abused_tld"]
    assert result[0].evidence == "2 link(s): evil[.]top"


def test_backslash_trick_is_analyzed_as_the_host_browsers_open():
    found = run('<a href="https://evil.xyz\\@paypal.com/login">paypal.com</a>')
    assert {"link_text_mismatch", "abused_tld"} <= found


def test_userinfo_trick_uses_real_host():
    result = findings('<a href="http://paypal.com@evil.xyz/login">Login</a>')
    assert ids(result) == {"abused_tld"}
    assert "evil[.]xyz" in result[0].evidence
