"""Runs the full analysis of one email."""
import asyncio
import functools
import logging
import ssl

import certifi
import httpx

from app.analyzers import llm, virustotal
from app.analyzers.base import AnalyzerResult
from app.analyzers.rules.runner import run_rules
from app.config import Settings
from app.context import EmailContext, build_context
from app.models import AnalyzeRequest, AnalyzeResponse
from app.parsing.domains import defang
from app.scoring import score_results

logger = logging.getLogger(__name__)

HTTP_TIMEOUT_SECONDS = 6.0     # per network wait; measured AI answers: 1.2-3.8 s
OPTIONAL_TIMEOUT_SECONDS = 8.0  # per analyzer; they run in parallel, so 8 s total (budget: 15 s)


async def analyze_email(request: AnalyzeRequest, settings: Settings) -> AnalyzeResponse:
    # Parsing and rules are CPU work: run them off the event loop so one heavy email can't
    # stall other requests (or health checks) on this server instance.
    """Full analysis of one email: parse, run the rules and the optional analyzers, score."""
    ctx = await asyncio.to_thread(build_context, request)
    rules = await asyncio.to_thread(run_rules, ctx)
    if ctx.body.html_parse_failed:
        rules.status = "partial"  # the rules only saw part of the email: never a silent "Safe"
    results = [rules, *await run_optional_analyzers(ctx, settings)]
    return score_results(results, input_notices(ctx), technical_details(ctx))


async def run_optional_analyzers(ctx: EmailContext, settings: Settings) -> list[AnalyzerResult]:
    """External services. Each is optional (skipped without an API key), time-boxed, runs in
    parallel with the others, and can never break the analysis: a failure becomes a status."""
    keys = {"virustotal": settings.virustotal_api_key, "llm": settings.gemini_api_key}
    if not any(keys.values()):
        return [AnalyzerResult(name=name, status="skipped") for name in keys]
    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_SECONDS, verify=_tls_context()) as client:
        jobs = [
            ("virustotal", keys["virustotal"],
             lambda: virustotal.analyze(ctx, keys["virustotal"], client)),
            ("llm", keys["llm"],
             lambda: llm.analyze(ctx, keys["llm"], settings.gemini_model, client)),
        ]
        return list(await asyncio.gather(*(_guarded(name, key, start) for name, key, start in jobs)))


@functools.cache
def _tls_context() -> ssl.SSLContext:
    """Loading the trusted certificates takes ~0.4 s, so do it once, not per email."""
    return ssl.create_default_context(cafile=certifi.where())


async def _guarded(name: str, api_key: str, start) -> AnalyzerResult:
    """Runs one optional analyzer with a time limit; turns any failure into a status."""
    if not api_key:
        return AnalyzerResult(name=name, status="skipped")
    try:
        return await asyncio.wait_for(start(), OPTIONAL_TIMEOUT_SECONDS)
    except (TimeoutError, httpx.TimeoutException):
        return AnalyzerResult(name=name, status="timeout")
    except Exception as exc:  # noqa: BLE001 - an optional analyzer must never break the analysis
        logger.warning("%s failed: %s", name, type(exc).__name__)
        return AnalyzerResult(name=name, status="error")


def input_notices(ctx: EmailContext) -> list[str]:
    """Warnings about the input itself: truncated, too many links, or unreadable HTML."""
    notices = []
    if ctx.input_truncated or ctx.body.text_truncated:
        notices.append("This email is very large — only the first part was analyzed.")
    if ctx.body.links_truncated:
        notices.append("Only the first 200 links were checked.")
    if ctx.body.html_parse_failed:
        notices.append("Part of this email's formatting could not be read; "
                       "its plain text was analyzed instead.")
    return notices


def technical_details(ctx: EmailContext) -> dict:
    """Analyst data for the 'Details' section of the card."""
    sender = ctx.headers.sender
    return {
        "from_domain": defang(sender.domain) if sender and sender.domain else "",
        "auth_results": ctx.headers.auth or {},
        "links_found": len(ctx.body.links),
        "attachment_hashes": [a.sha256 for a in ctx.attachments if a.sha256],
    }
