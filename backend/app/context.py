"""Everything the analyzers need, parsed once per request."""
from dataclasses import dataclass

from app.models import AnalyzeRequest, AttachmentIn
from app.parsing.body import ParsedBody, parse_body
from app.parsing.headers import ParsedHeaders, parse_headers


@dataclass(frozen=True)
class EmailContext:
    headers: ParsedHeaders
    body: ParsedBody
    attachments: tuple[AttachmentIn, ...]
    input_truncated: bool


def build_context(request: AnalyzeRequest) -> EmailContext:
    return EmailContext(
        headers=parse_headers(request.headers_raw),
        body=parse_body(request.body_html, request.body_text),
        attachments=tuple(request.attachments),
        input_truncated=request.truncated,
    )
