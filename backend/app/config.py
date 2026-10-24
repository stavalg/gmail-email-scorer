"""Runtime settings, read from environment variables (secrets arrive this way from Secret Manager)."""
import os
from dataclasses import dataclass
from functools import lru_cache


@dataclass(frozen=True)
class Settings:
    """All runtime settings, read from environment variables (API keys come from Secret Manager)."""
    oauth_client_id: str
    allowed_emails: frozenset[str]
    dev_skip_auth: bool
    virustotal_api_key: str
    gemini_api_key: str
    gemini_model: str


def _load() -> Settings:
    """Reads the settings from the environment; refuses the local-only auth bypass on Cloud Run."""
    dev_skip_auth = os.environ.get("DEV_SKIP_AUTH", "").lower() == "true"
    if dev_skip_auth and os.environ.get("K_SERVICE"):
        # Cloud Run always sets K_SERVICE: the local-only bypass must never run there.
        raise RuntimeError("DEV_SKIP_AUTH must not be used on Cloud Run")
    emails = os.environ.get("ALLOWED_EMAILS", "")
    return Settings(
        oauth_client_id=os.environ.get("OAUTH_CLIENT_ID", ""),
        allowed_emails=frozenset(e.strip().lower() for e in emails.split(",") if e.strip()),
        dev_skip_auth=dev_skip_auth,
        # Keys pasted into a terminal often carry a trailing newline, which breaks HTTP headers.
        virustotal_api_key=os.environ.get("VIRUSTOTAL_API_KEY", "").strip(),
        gemini_api_key=os.environ.get("GEMINI_API_KEY", "").strip(),
        gemini_model=os.environ.get("GEMINI_MODEL", "gemini-3.1-flash-lite"),
    )


@lru_cache
def get_settings() -> Settings:
    """The settings, read once and then reused."""
    return _load()
