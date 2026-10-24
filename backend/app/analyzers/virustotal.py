"""VirusTotal reputation lookups.

Privacy: only registrable domains and SHA-256 hashes are sent — never full links (they can
contain private tokens) and never file contents. Free API: 4 requests/minute, so at most
3 lookups per email.
"""
import re

import httpx

from app.analyzers.base import AnalyzerResult, Finding
from app.analyzers.rules.data import COMMON_SAFE_DOMAINS
from app.context import EmailContext
from app.parsing.domains import defang, registrable_domain, web_host

VT_API = "https://www.virustotal.com/api/v3"
MAX_LOOKUPS = 3
MALICIOUS_VENDOR_THRESHOLD = 2
_SAFE_DOMAIN = re.compile(r"^[a-z0-9.-]+$")  # only plain ASCII domains go into a URL path


def pick_targets(ctx: EmailContext) -> tuple[list[tuple[str, str]], int]:
    """Attachment hashes first (strongest evidence), then link domains, then the sender domain."""
    targets = [("files", a.sha256) for a in ctx.attachments if a.sha256]
    hosts = [web_host(link.href) for link in ctx.body.links]
    if ctx.headers.sender:
        hosts.append(ctx.headers.sender.domain)
    for host in hosts:
        domain = registrable_domain(host) if host else ""
        if domain and domain not in COMMON_SAFE_DOMAINS and _SAFE_DOMAIN.match(domain):
            targets.append(("domains", domain))
    unique = list(dict.fromkeys(targets))
    return unique[:MAX_LOOKUPS], len(unique)


def malicious_vendor_count(payload: object) -> int:
    """Reads data.attributes.last_analysis_stats.malicious and rejects anything unexpected."""
    try:
        value = payload["data"]["attributes"]["last_analysis_stats"]["malicious"]
    except (KeyError, TypeError) as exc:
        raise ValueError("Unexpected VirusTotal response") from exc
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError("Unexpected VirusTotal response")
    return value


async def analyze(ctx: EmailContext, api_key: str, client: httpx.AsyncClient) -> AnalyzerResult:
    """Looks up attachment hashes and link/sender domains on VirusTotal (at most 3 per email)."""
    targets, total = pick_targets(ctx)
    result = AnalyzerResult(name="virustotal", status="ok", checked=0, total=total)
    lookups = []
    for kind, value in targets:
        response = await client.get(f"{VT_API}/{kind}/{value}", headers={"x-apikey": api_key})
        if response.status_code == 429:
            result.status = "rate_limited"
            break
        label = _label(kind, value)
        if response.status_code == 404:  # never seen by VirusTotal
            vendors = 0
        else:
            response.raise_for_status()  # other errors: the pipeline reports status "error"
            vendors = malicious_vendor_count(response.json())
        result.checked += 1
        lookups.append({"item": label, "malicious_vendors": vendors})
        if vendors >= MALICIOUS_VENDOR_THRESHOLD and not result.findings:
            result.findings.append(Finding(
                id="known_malicious", category="reputation", title="Known malicious (VirusTotal)",
                evidence=f"{label} is flagged by {vendors} security vendors.",
                points=0, confirmed=True))
    if result.checked and not result.findings:
        result.facts.append(
            f"VirusTotal: no known threats among the {result.checked} item(s) checked.")
    result.details = {"lookups": lookups}
    return result


def _label(kind: str, value: str) -> str:
    """How a looked-up item is shown to the user (domains are defanged)."""
    return f"Attachment (SHA-256 {value[:12]}…)" if kind == "files" else defang(value)
