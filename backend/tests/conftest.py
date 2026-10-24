import pytest
from fastapi.testclient import TestClient

from app.auth import require_user
from app.config import get_settings
from app.main import app

ENV_KEYS = (
    "OAUTH_CLIENT_ID", "ALLOWED_EMAILS", "DEV_SKIP_AUTH",
    "VIRUSTOTAL_API_KEY", "GEMINI_API_KEY", "GEMINI_MODEL", "K_SERVICE",
)


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    """Every test starts from the same known settings; real API keys are never used."""
    for key in ENV_KEYS:
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("OAUTH_CLIENT_ID", "test-client-id")
    monkeypatch.setenv("ALLOWED_EMAILS", "me@gmail.com")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
def set_env(monkeypatch):
    def _set(**values):
        for key, value in values.items():
            monkeypatch.setenv(key, value)
        get_settings.cache_clear()
    return _set


@pytest.fixture
def authed_client():
    """A client that skips token checks (auth itself is tested in test_auth.py)."""
    app.dependency_overrides[require_user] = lambda: "me@gmail.com"
    yield TestClient(app)
    app.dependency_overrides.clear()
