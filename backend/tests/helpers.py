"""Small builders shared by the tests."""
from dataclasses import replace

from app.config import Settings
from app.context import build_context
from app.models import AnalyzeRequest

BASE_SETTINGS = Settings(
    oauth_client_id="test-client-id",
    allowed_emails=frozenset({"me@gmail.com"}),
    dev_skip_auth=False,
    virustotal_api_key="",
    gemini_api_key="",
    gemini_model="gemini-test",
)


def make_context(headers_raw="", body_html="", body_text="", attachments=None, truncated=False):
    return build_context(AnalyzeRequest(
        headers_raw=headers_raw,
        body_html=body_html,
        body_text=body_text,
        attachments=attachments or [],
        truncated=truncated,
    ))


def make_settings(**overrides) -> Settings:
    return replace(BASE_SETTINGS, **overrides)


def ids(findings) -> set[str]:
    return {finding.id for finding in findings}
