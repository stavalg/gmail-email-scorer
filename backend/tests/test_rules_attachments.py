from app.analyzers.rules import attachments
from app.models import AttachmentIn
from tests.helpers import ids, make_context


def check(*files, body_text=""):
    items = [AttachmentIn(name=name, content_type=ctype, size=size)
             for name, ctype, size in files]
    return attachments.check(make_context(attachments=items, body_text=body_text))


def run(*files, body_text=""):
    return ids(check(*files, body_text=body_text).findings)


def test_double_extension():
    assert run(("invoice.pdf.exe", "", 10)) == {"double_extension", "executable_attachment"}


def test_right_to_left_trick():
    out = check(("invoice‮fdp.exe", "", 10))
    assert ids(out.findings) == {"disguised_filename", "executable_attachment"}
    assert "‮" not in out.findings[0].evidence


def test_uppercase_extension():
    assert run(("SETUP.EXE", "", 10)) == {"executable_attachment"}


def test_trailing_dots_and_spaces_are_removed():
    assert run(("report.pdf .exe. ", "", 10)) == {"double_extension", "executable_attachment"}


def test_html_attachment():
    assert run(("login.html", "text/html", 10)) == {"html_attachment"}


def test_nameless_attachment_uses_content_type():
    assert run(("", "text/html; charset=utf-8", 10)) == {"html_attachment"}


def test_macro_document():
    assert run(("salary.xlsm", "", 10)) == {"macro_attachment"}


def test_archive():
    assert run(("files.zip", "", 10)) == {"archive_attachment"}


def test_archive_with_password_in_body():
    assert run(("files.zip", "", 10), body_text="The password is 1234") == {"archive_with_password"}


def test_large_attachment_notice():
    out = check(("video.mp4", "", 11 * 1024 * 1024))
    assert out.notices == ["1 attachment(s) larger than 10 MB could not be fingerprinted."]


def test_normal_pdf_is_fine():
    assert run(("report.pdf", "application/pdf", 10)) == set()
