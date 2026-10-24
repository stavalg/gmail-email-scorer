"""Turns analyzer results into one score, verdict and explanation."""
from collections.abc import Iterable

from app.analyzers.base import DEGRADED_STATUSES, AnalyzerResult
from app.models import AnalyzeResponse, CoverageItem, FindingOut
from app.sanitize import clean_text

MAX_SCORE = 100
SUSPICIOUS_MIN = 30
MALICIOUS_MIN = 70
KNOWN_MALICIOUS_FLOOR = 90
CAUTION_NOTICE = "Some checks did not complete — treat 'Safe' with caution."

SUMMARIES = {
    "safe": "No significant warning signs were found in this email.",
    "suspicious": "This email has some warning signs. Treat it with caution.",
    "malicious": "This email shows strong signs of phishing or malware.",
}

ADVICE = {
    "safe": (
        "No action needed.",
        "Still be careful with unexpected requests for passwords or payments — no tool is perfect.",
    ),
    "suspicious": (
        "Don't click links or open attachments until you've verified the sender.",
        "Contact the sender through a channel you already trust — not by replying.",
        "If it claims to be from a company, go to their website directly instead of using the links.",
    ),
    "malicious": (
        "Don't click any links or open any attachments.",
        "Don't reply or share any information.",
        "Report it: in Gmail open ⋮ (More) → Report phishing, then delete it.",
    ),
}


def verdict_for(score: int) -> str:
    if score >= MALICIOUS_MIN:
        return "malicious"
    if score >= SUSPICIOUS_MIN:
        return "suspicious"
    return "safe"


def score_results(results: list[AnalyzerResult], notices: Iterable[str] = (),
                  details: dict | None = None) -> AnalyzeResponse:
    findings = sorted((f for r in results for f in r.findings), key=lambda f: f.points, reverse=True)
    score = min(MAX_SCORE, sum(f.points for f in findings))
    if any(r.known_malicious for r in results):
        score = max(score, KNOWN_MALICIOUS_FLOOR)  # confirmed evidence beats guesses
    verdict = verdict_for(score)

    all_notices = [*notices, *(n for r in results for n in r.notices)]
    if verdict == "safe" and any(r.status in DEGRADED_STATUSES for r in results):
        all_notices.append(CAUTION_NOTICE)

    return AnalyzeResponse(
        score=score,
        verdict=verdict,
        summary=SUMMARIES[verdict],
        advice=list(ADVICE[verdict]),
        findings=[
            FindingOut(id=f.id, category=f.category, title=clean_text(f.title),
                       evidence=clean_text(f.evidence), points=f.points)
            for f in findings
        ],
        facts=[clean_text(fact) for r in results for fact in r.facts],
        coverage={r.name: CoverageItem(status=r.status, checked=r.checked, total=r.total)
                  for r in results},
        notices=[clean_text(notice) for notice in all_notices],
        details={**(details or {}), **{r.name: r.details for r in results if r.details}},
    )
