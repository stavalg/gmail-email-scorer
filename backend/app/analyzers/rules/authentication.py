"""SPF / DKIM / DMARC, as reported by Google in the trusted Authentication-Results header."""
from app.analyzers.rules.common import RuleOutput, make_finding
from app.analyzers.rules.data import WEIGHTS
from app.context import EmailContext
from app.parsing.domains import defang

METHODS = ("dmarc", "spf", "dkim")
LABELS = {"dmarc": "DMARC", "spf": "SPF", "dkim": "DKIM"}
MEANING = {
    "dmarc": "the visible From address may be forged",
    "spf": "the sending server was not authorized by the sender's domain",
    "dkim": "the message signature is invalid or the content was changed",
}


def check(ctx: EmailContext) -> RuleOutput:
    out = RuleOutput()
    auth = ctx.headers.auth
    if auth is None:
        out.facts.append("No authentication results from Gmail for this message "
                         "(normal for your own sent mail); these checks were skipped.")
        return out

    passed = []
    for method in METHODS:
        result = auth.get(method, "missing")
        label = LABELS[method]
        if result == "fail":
            out.findings.append(make_finding(
                f"{method}_fail", "authentication", f"{label} check failed",
                f"Gmail reports {label}=fail: {MEANING[method]}."))
        elif result == "softfail":
            out.findings.append(make_finding(
                f"{method}_fail", "authentication", f"{label} soft failure",
                f"Gmail reports {label}=softfail: {MEANING[method]}.",
                points=WEIGHTS[f"{method}_fail"] // 2))
        elif result == "pass":
            passed.append(label)
        else:
            out.facts.append(f"{label} result: {result} (no penalty).")

    if passed:
        # Proves who sent it, not that they are trustworthy: passes never lower the score.
        sender = ctx.headers.sender
        domain = defang(sender.domain) if sender and sender.domain else "the sender's domain"
        out.facts.append(f"Sender verified: {domain} ({'/'.join(passed)} passed).")
    return out
