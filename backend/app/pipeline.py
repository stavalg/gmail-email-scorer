"""Runs the full analysis of one email."""
import logging

from app.analyzers.base import AnalyzerResult
from app.analyzers.rules.runner import run_rules
from app.config import Settings
from app.context import EmailContext, build_context
from app.models import AnalyzeRequest, AnalyzeResponse
from app.parsing.domains import defang
from app.scoring import score_results

logger = logging.getLogger(__name__)


async def analyze_email(request: AnalyzeRequest, settings: Settings) -> AnalyzeResponse:
    ctx = build_context(request)
    results = [run_rules(ctx), *await run_optional_analyzers(ctx, settings)]
    return score_results(results, input_notices(ctx), technical_details(ctx))


async def run_optional_analyzers(ctx: EmailContext, settings: Settings) -> list[AnalyzerResult]:
    """External services (VirusTotal, AI). Added in Tasks 16-17."""
    return []


def input_notices(ctx: EmailContext) -> list[str]:
    notices = []
    if ctx.input_truncated or ctx.body.text_truncated:
        notices.append("This email is very large — only the first part was analyzed.")
    if ctx.body.links_truncated:
        notices.append("Only the first 200 links were checked.")
    return notices


def technical_details(ctx: EmailContext) -> dict:
    sender = ctx.headers.sender
    return {
        "from_domain": defang(sender.domain) if sender and sender.domain else "",
        "auth_results": ctx.headers.auth or {},
        "links_found": len(ctx.body.links),
        "attachment_hashes": [a.sha256 for a in ctx.attachments if a.sha256],
    }
