"""Runtime settings, read from environment variables (secrets arrive this way from Secret Manager)."""
import os
from dataclasses import dataclass
from functools import lru_cache


@dataclass(frozen=True)
class Settings:
    oauth_client_id: str
    allowed_emails: frozenset[str]
    dev_skip_auth: bool
    virustotal_api_key: str
    gemini_api_key: str
    gemini_model: str


def _load() -> Settings:
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
        gemini_model=os.environ.get("GEMINI_MODEL", "gemini-2.5-flash"),
    )


@lru_cache
def get_settings() -> Settings:
    return _load()
