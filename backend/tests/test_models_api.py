from app.models import MAX_ATTACHMENTS, MAX_HEADERS_CHARS, MAX_REQUEST_BYTES

VALID_HASH = "a" * 64


def test_minimal_request_is_accepted(authed_client):
    assert authed_client.post("/v1/analyze", json={}).status_code == 200


def test_full_request_is_accepted(authed_client):
    body = {
        "headers_raw": "From: a@example.com",
        "body_html": "<p>hi</p>",
        "body_text": "hi",
        "attachments": [{"name": "a.pdf", "content_type": "application/pdf", "size": 10, "sha256": VALID_HASH}],
        "truncated": False,
    }
    assert authed_client.post("/v1/analyze", json=body).status_code == 200


def test_unknown_field_is_rejected_without_echo(authed_client):
    response = authed_client.post("/v1/analyze", json={"surprise": "secret-content-123"})
    assert response.status_code == 422
    assert response.json() == {"error": "invalid_request"}
    assert "secret-content-123" not in response.text


def test_too_long_headers_are_rejected(authed_client):
    response = authed_client.post("/v1/analyze", json={"headers_raw": "x" * (MAX_HEADERS_CHARS + 1)})
    assert response.status_code == 422


def test_bad_hash_is_rejected(authed_client):
    attachment = {"name": "a", "content_type": "", "size": 1, "sha256": "not-a-hash"}
    assert authed_client.post("/v1/analyze", json={"attachments": [attachment]}).status_code == 422


def test_negative_size_is_rejected(authed_client):
    attachment = {"name": "a", "content_type": "", "size": -1, "sha256": None}
    assert authed_client.post("/v1/analyze", json={"attachments": [attachment]}).status_code == 422


def test_too_many_attachments_are_rejected(authed_client):
    attachments = [{"name": "a", "content_type": "", "size": 1, "sha256": None}] * (MAX_ATTACHMENTS + 1)
    assert authed_client.post("/v1/analyze", json={"attachments": attachments}).status_code == 422


def test_oversized_request_is_rejected_before_parsing(authed_client):
    big = b'{"body_text": "' + b"x" * MAX_REQUEST_BYTES + b'"}'
    response = authed_client.post("/v1/analyze", content=big, headers={"content-type": "application/json"})
    assert response.status_code == 413
