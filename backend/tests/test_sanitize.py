from app.sanitize import clean_text


def test_removes_text_direction_and_control_characters():
    assert clean_text("invoice‮fdp.exe\x00") == "invoicefdp.exe"


def test_keeps_normal_text_and_newlines():
    assert clean_text("Hello\nשלום") == "Hello\nשלום"


def test_caps_length_with_ellipsis():
    result = clean_text("a" * 500)
    assert len(result) == 200 and result.endswith("…")
