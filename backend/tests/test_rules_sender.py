from app.analyzers.rules import sender
from tests.helpers import ids, make_context


def run(headers):
    return ids(sender.check(make_context(headers_raw=headers)).findings)


def test_brand_name_from_unrelated_domain():
    assert "brand_display_name" in run("From: PayPal Support <help@random-shop.com>")


def test_real_brand_domain_is_clean():
    assert run("From: PayPal <service@paypal.com>") == set()


def test_brand_subdomain_is_clean():
    assert run("From: PayPal <service@mail.paypal.com>") == set()


def test_lookalike_with_digit():
    assert "lookalike_domain" in run("From: Support <x@paypa1.com>")


def test_lookalike_with_rn_for_m():
    assert "lookalike_domain" in run("From: Support <x@rnicrosoft.com>")


def test_brand_inside_another_word_is_not_a_match():
    assert run("From: Pineapple Shop <shop@pineapple.com>") == set()


def test_address_hidden_in_display_name():
    found = run('From: "support@paypal.com" <x@evil.ru>')
    assert "display_name_address" in found


def test_reply_to_other_domain():
    assert "reply_to_mismatch" in run("From: a@shop.com\r\nReply-To: b@elsewhere.xyz")


def test_reply_to_same_domain_is_fine():
    assert run("From: a@shop.com\r\nReply-To: b@mail.shop.com") == set()


def test_missing_from_is_malformed():
    assert run("Subject: hi") == {"malformed_sender"}


def test_hebrew_display_name_has_no_findings():
    assert run("From: =?UTF-8?B?16nXnNeV150=?= <a@example.com>") == set()


def test_edit_distance():
    assert sender.edit_distance("gooogle", "google") == 1
    assert sender.edit_distance("paypal", "paypal") == 0
