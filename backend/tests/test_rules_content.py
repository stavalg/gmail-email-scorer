from app.analyzers.rules import content
from tests.helpers import ids, make_context


def run(**kwargs):
    return content.check(make_context(**kwargs))


def test_urgency_in_subject():
    out = run(headers_raw="From: a@b.com\r\nSubject: URGENT: account will be suspended")
    assert ids(out.findings) == {"urgency_language"}
    assert out.findings[0].evidence == 'Phrases like "urgent" (+1 more).'


def test_credential_request_in_body():
    assert "credential_request" in ids(run(body_text="Please verify your password here").findings)


def test_phrases_match_across_line_breaks():
    assert "urgency_language" in ids(run(body_text="reply within\n 24   hours").findings)


def test_ordinary_email_has_no_findings():
    assert run(body_text="Are we still on for lunch on Thursday?").findings == []


def test_empty_email_is_a_fact():
    assert run().facts == ["The email has no readable text."]


def test_mostly_images_is_a_fact():
    out = run(body_html='<img src="a.png"><p>Hi</p>')
    assert out.facts == ["The email is mostly images, so text analysis is limited."]
