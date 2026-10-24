"""The shape every analyzer returns, so the scorer never needs to know who produced what."""
from dataclasses import dataclass, field

DEGRADED_STATUSES = frozenset({"partial", "error", "timeout", "rate_limited"})


@dataclass(frozen=True)
class Finding:
    id: str
    category: str   # authentication | sender | links | content | attachments | reputation | ai
    title: str
    evidence: str
    points: int


@dataclass
class AnalyzerResult:
    name: str
    status: str  # ok | partial | skipped | error | timeout | rate_limited
    findings: list[Finding] = field(default_factory=list)
    facts: list[str] = field(default_factory=list)     # positive information, never changes the score
    notices: list[str] = field(default_factory=list)   # warnings about the analysis itself
    details: dict = field(default_factory=dict)        # technical data for the analyst section
    checked: int | None = None
    total: int | None = None
    known_malicious: bool = False
