import pytest
from fastapi.testclient import TestClient

import app.auth as auth
from app.config import get_settings
from app.main import app

client = TestClient(app)
GOOD_CLAIMS = {"email": "Me@Gmail.com", "email_verified": True}


def fake_verifier(claims):
    def verify(token, audience):
        assert audience == "test-client-id"
        if token != "good-token":
            raise ValueError("bad token")
        return claims
    return verify


def post(headers=None):
    return client.post("/v1/analyze", json={}, headers=headers or {})


def test_missing_token_is_rejected():
    assert post().status_code == 401


def test_wrong_scheme_is_rejected():
    assert post({"Authorization": "Basic abc"}).status_code == 401


def test_invalid_token_is_rejected(monkeypatch):
    monkeypatch.setattr(auth, "verify_google_token", fake_verifier(GOOD_CLAIMS))
    assert post({"Authorization": "Bearer forged"}).status_code == 401


def test_allowed_user_gets_through(monkeypatch):
    monkeypatch.setattr(auth, "verify_google_token", fake_verifier(GOOD_CLAIMS))
    assert post({"Authorization": "Bearer good-token"}).status_code == 200


def test_other_user_is_forbidden(monkeypatch):
    monkeypatch.setattr(auth, "verify_google_token",
                        fake_verifier({"email": "stranger@gmail.com", "email_verified": True}))
    assert post({"Authorization": "Bearer good-token"}).status_code == 403


def test_unverified_email_is_forbidden(monkeypatch):
    monkeypatch.setattr(auth, "verify_google_token",
                        fake_verifier({"email": "me@gmail.com", "email_verified": False}))
    assert post({"Authorization": "Bearer good-token"}).status_code == 403


def test_missing_client_id_fails_closed(set_env, monkeypatch):
    # An empty audience would make the library skip the audience check: we must refuse instead.
    set_env(OAUTH_CLIENT_ID="")
    monkeypatch.setattr(auth, "verify_google_token", fake_verifier(GOOD_CLAIMS))
    assert post({"Authorization": "Bearer good-token"}).status_code == 503


def test_dev_skip_auth_works_locally(set_env):
    set_env(DEV_SKIP_AUTH="true")
    assert post().status_code == 200


def test_token_check_tolerates_small_clock_differences(monkeypatch):
    # A token minted a second "in the future" by Google's clock must not fail at random.
    seen = {}

    def fake_verify(token, request, audience=None, clock_skew_in_seconds=0):
        seen["skew"] = clock_skew_in_seconds
        return GOOD_CLAIMS
    monkeypatch.setattr(auth.id_token, "verify_oauth2_token", fake_verify)
    assert post({"Authorization": "Bearer any"}).status_code == 200
    assert seen["skew"] == 10


def test_api_keys_are_stripped_of_pasted_whitespace(set_env):
    # Secrets created from a terminal often end with a newline, which breaks HTTP headers.
    set_env(VIRUSTOTAL_API_KEY="abc123\r\n", GEMINI_API_KEY="  xyz\n")
    settings = get_settings()
    assert (settings.virustotal_api_key, settings.gemini_api_key) == ("abc123", "xyz")


def test_default_ai_model_is_one_available_to_new_keys():
    # gemini-2.5-flash was retired for new users (HTTP 404); 3.1-flash-lite answered in 1-4 s.
    assert get_settings().gemini_model == "gemini-3.1-flash-lite"


def test_dev_skip_auth_refused_on_cloud_run(set_env):
    set_env(DEV_SKIP_AUTH="true", K_SERVICE="email-scorer")
    with pytest.raises(RuntimeError):
        get_settings()
