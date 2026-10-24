"""Runs every rule check in isolation.

If one check crashes on a strange email, the others still run, and the result says so —
a crash must never turn into a silent 'Safe'.
"""
import logging
from collections.abc import Callable, Sequence

from app.analyzers.base import AnalyzerResult
from app.analyzers.rules import attachments, authentication, content, links, sender
from app.analyzers.rules.common import RuleOutput
from app.context import EmailContext

logger = logging.getLogger(__name__)

RuleCheck = Callable[[EmailContext], RuleOutput]

CHECKS: tuple[RuleCheck, ...] = (
    authentication.check, sender.check, links.check, content.check, attachments.check,
)


def run_rules(ctx: EmailContext, checks: Sequence[RuleCheck] | None = None) -> AnalyzerResult:
    result = AnalyzerResult(name="rules", status="ok")
    failed = 0
    for check in CHECKS if checks is None else checks:
        try:
            output = check(ctx)
        except Exception as exc:  # noqa: BLE001 - isolation is the point
            failed += 1
            # Log the type only: exception messages can contain email content.
            logger.error("Rule check %s failed: %s", check.__module__, type(exc).__name__)
            continue
        result.findings.extend(output.findings)
        result.facts.extend(output.facts)
        result.notices.extend(output.notices)
    if failed:
        result.status = "partial"
        result.notices.append(f"{failed} check(s) could not run on this email.")
    return result
