from app.parsing.domains import defang, is_ip, registrable_domain, split_host, web_host


def test_registrable_domain_handles_multi_part_suffixes():
    assert registrable_domain("login.paypal.co.uk") == "paypal.co.uk"
    assert registrable_domain("Mail.PayPal.com.") == "paypal.com"


def test_registrable_domain_is_empty_for_ips_and_garbage():
    assert registrable_domain("192.168.1.1") == ""
    assert registrable_domain("localhost") == ""
    assert registrable_domain("") == ""


def test_split_host():
    assert split_host("a.b.paypal.co.uk") == ("a.b", "paypal", "co.uk")


def test_is_ip():
    assert is_ip("45.13.2.9")
    assert is_ip("[::1]")
    assert not is_ip("example.com")


def test_web_host():
    assert web_host("HTTPS://Login.Example.com/path") == "login.example.com"
    assert web_host("//cdn.example.com/x") == "cdn.example.com"
    assert web_host("mailto:a@example.com") == ""
    assert web_host("/relative/path") == ""
    assert web_host("http://[broken") == ""


def test_defang_makes_addresses_unclickable():
    assert defang("http://evil.com/login") == "hxxp://evil[.]com/login"
    assert defang("paypa1.com") == "paypa1[.]com"
