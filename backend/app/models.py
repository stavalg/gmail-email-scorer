"""The exact shapes of requests and responses.

Pydantic rejects anything that doesn't match (unknown fields, wrong types, values over the
limits) before any of our analysis code sees it.
"""
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

MAX_HEADERS_CHARS = 65_536
MAX_HTML_CHARS = 500_000
MAX_TEXT_CHARS = 100_000
MAX_ATTACHMENTS = 50
MAX_REQUEST_BYTES = 4_000_000

Verdict = Literal["safe", "suspicious", "malicious"]


class AttachmentIn(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = Field(default="", max_length=1024)
    content_type: str = Field(default="", max_length=255)
    size: int = Field(default=0, ge=0)
    sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")


class AnalyzeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    headers_raw: str = Field(default="", max_length=MAX_HEADERS_CHARS)
    body_html: str = Field(default="", max_length=MAX_HTML_CHARS)
    body_text: str = Field(default="", max_length=MAX_TEXT_CHARS)
    attachments: list[AttachmentIn] = Field(default_factory=list, max_length=MAX_ATTACHMENTS)
    truncated: bool = False  # the add-on had to cut something before sending


class FindingOut(BaseModel):
    id: str
    category: str
    title: str
    evidence: str
    points: int = Field(ge=0)


class CoverageItem(BaseModel):
    status: str
    checked: int | None = None
    total: int | None = None


class AnalyzeResponse(BaseModel):
    score: int = Field(ge=0, le=100)
    verdict: Verdict
    summary: str
    findings: list[FindingOut]
    facts: list[str]
    coverage: dict[str, CoverageItem]
    notices: list[str]
    details: dict
