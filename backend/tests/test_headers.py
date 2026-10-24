from app.parsing.headers import parse_headers

GOOGLE_FAIL = (
    "Authentication-Results: mx.google.com;\r\n"
    "       dkim=pass header.i=@paypa1.com;\r\n"
    "       spf=softfail smtp.mailfrom=paypa1.com;\r\n"
    "       dmarc=fail (p=NONE) header.from=paypal.com"
)


def test_parses_sender_reply_to_and_subject():
    parsed = parse_headers(
        'From: "PayPal Support" <Security@Mail.Paypa1.com>\r\n'
        "Reply-To: help@other.xyz\r\n"
        "Subject: Urgent notice"
    )
    assert parsed.sender.display_name == "PayPal Support"
    assert parsed.sender.address == "security@mail.paypa1.com"
    assert parsed.sender.domain == "paypa1.com"
    assert parsed.reply_to.domain == "other.xyz"
    assert parsed.subject == "Urgent notice"


def test_reads_google_auth_results_including_softfail():
    parsed = parse_headers(GOOGLE_FAIL + "\r\nFrom: a@paypa1.com")
    assert parsed.auth == {"dkim": "pass", "spf": "softfail", "dmarc": "fail"}


def test_forged_header_below_google_is_ignored():
    forged = "Authentication-Results: mx.google.com; dkim=pass; spf=pass; dmarc=pass"
    parsed = parse_headers(GOOGLE_FAIL + "\r\n" + forged + "\r\nFrom: a@paypa1.com")
    assert parsed.auth["dmarc"] == "fail"


def test_non_google_top_header_is_not_trusted():
    parsed = parse_headers("Authentication-Results: evil.example; dmarc=pass\r\nFrom: a@b.com")
    assert parsed.auth is None


def test_no_auth_header_means_none():
    assert parse_headers("From: me@gmail.com").auth is None


def test_real_gmail_header_block_with_arc_and_forgery():
    raw = (
        "Delivered-To: me@gmail.com\r\n"
        "ARC-Authentication-Results: i=1; mx.google.com;\r\n"
        "       dkim=pass; spf=pass; dmarc=pass\r\n"
        "Return-Path: <x@evil.xyz>\r\n"
        "Authentication-Results: mx.google.com;\r\n"
        "       dkim=fail header.i=@evil.xyz;\r\n"
        "       spf=fail (google.com: domain of x@evil.xyz does not designate 1.2.3.4) smtp.mailfrom=x@evil.xyz;\r\n"
        "       dmarc=fail (p=REJECT sp=REJECT dis=NONE) header.from=paypal.com\r\n"
        "Authentication-Results: mx.google.com; dkim=pass; spf=pass; dmarc=pass\r\n"
        "From: PayPal <service@paypal.com>\r\n"
        "Subject: Hello"
    )
    parsed = parse_headers(raw)
    assert parsed.auth == {"dkim": "fail", "spf": "fail", "dmarc": "fail"}


def test_missing_from_gives_no_sender():
    assert parse_headers("Subject: hi").sender is None


def test_malformed_from_gives_no_sender():
    assert parse_headers("From: not an address").sender is None


def test_decodes_hebrew_display_name():
    parsed = parse_headers("From: =?UTF-8?B?16nXnNeV150=?= <a@example.com>\r\nSubject: =?UTF-8?B?16nXnNeV150=?=")
    assert parsed.sender.display_name == "שלום"
    assert parsed.subject == "שלום"


def test_empty_headers_do_not_crash():
    parsed = parse_headers("")
    assert parsed.sender is None and parsed.auth is None and parsed.subject == ""


def test_attacker_text_inside_googles_header_cannot_fake_a_result():
    # The envelope sender is attacker-chosen and Google echoes it inside the spf clause.
    raw = ("Authentication-Results: mx.google.com;\r\n"
           "       spf=pass (google.com: domain of dmarc=pass@evil.com designates 1.2.3.4 as permitted sender)"
           ' smtp.mailfrom="dmarc=pass@evil.com";\r\n'
           "       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=paypal.com\r\n"
           "From: PayPal <service@paypal.com>")
    assert parse_headers(raw).auth == {"spf": "pass", "dmarc": "fail"}


def test_lookalike_authserv_id_is_not_trusted():
    raw = "Authentication-Results: mx.google.com.evil.net; dmarc=pass\r\nFrom: a@b.com"
    assert parse_headers(raw).auth is None

