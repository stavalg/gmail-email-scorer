from app.analyzers.rules import authentication
from tests.helpers import ids, make_context


def auth_header(spf="pass", dkim="pass", dmarc="pass"):
    return (f"Authentication-Results: mx.google.com; dkim={dkim} header.i=@example.com; "
            f"spf={spf} smtp.mailfrom=example.com; dmarc={dmarc} header.from=example.com\r\n"
            "From: Alice <alice@example.com>")


def test_dmarc_fail_gets_full_points():
    out = authentication.check(make_context(headers_raw=auth_header(dmarc="fail")))
    assert [(f.id, f.points) for f in out.findings] == [("dmarc_fail", 30)]


def test_softfail_gets_half_points():
    out = authentication.check(make_context(headers_raw=auth_header(spf="softfail")))
    assert [(f.id, f.points) for f in out.findings] == [("spf_fail", 7)]


def test_all_pass_is_a_fact_not_a_bonus():
    out = authentication.check(make_context(headers_raw=auth_header()))
    assert out.findings == []
    assert any("passed for example[.]com" in fact for fact in out.facts)


def test_neutral_results_are_facts_without_points():
    out = authentication.check(make_context(headers_raw=auth_header(dmarc="none")))
    assert out.findings == []
    assert "DMARC result: none (no penalty)." in out.facts


def test_missing_auth_header_is_not_penalized():
    out = authentication.check(make_context(headers_raw="From: me@gmail.com"))
    assert ids(out.findings) == set()
    assert len(out.facts) == 1
