"""Helpers shared by the rule checks."""
from dataclasses import dataclass, field

from app.analyzers.base import Finding
from app.analyzers.rules.data import WEIGHTS


@dataclass
class RuleOutput:
    """What one rule check returns: findings (points), facts (good news) and notices (warnings)."""
    findings: list[Finding] = field(default_factory=list)
    facts: list[str] = field(default_factory=list)
    notices: list[str] = field(default_factory=list)


def make_finding(finding_id: str, category: str, title: str, evidence: str,
                 points: int | None = None) -> Finding:
    """Builds a finding; points come from WEIGHTS unless given explicitly."""
    return Finding(id=finding_id, category=category, title=title, evidence=evidence,
                   points=WEIGHTS[finding_id] if points is None else points)


def summarize(examples: list[str], limit: int = 3) -> str:
    """'a, b, c (+2 more)' — de-duplicated, order kept."""
    unique = list(dict.fromkeys(examples))
    more = f" (+{len(unique) - limit} more)" if len(unique) > limit else ""
    return ", ".join(unique[:limit]) + more
