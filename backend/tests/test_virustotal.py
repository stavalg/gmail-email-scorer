import asyncio

import httpx
import pytest

from app.analyzers import virustotal
from app.models import AttachmentIn
from tests.helpers import make_context

HASH = "a" * 64


def stats(malicious):
    return {"data": {"attributes": {"last_analysis_stats": {"malicious": malicious}}}}


def analyze(ctx, handler):
    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await virustotal.analyze(ctx, "key", client)
    return asyncio.run(go())


def test_known_malicious_domain_and_privacy():
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(200, json=stats(5))

    ctx = make_context(body_html='<a href="http://evil-login.xyz/reset?token=secret-token">x</a>')
    result = analyze(ctx, handler)
    assert result.known_malicious and result.findings[0].id == "known_malicious"
    assert (result.checked, result.total) == (1, 1)
    assert seen[0].url.path == "/api/v3/domains/evil-login.xyz"
    assert seen[0].headers["x-apikey"] == "key"
    assert "secret-token" not in str(seen[0].url)


def test_unknown_item_is_ok_without_findings():
    result = analyze(make_context(body_html='<a href="http://new-site.xyz">x</a>'),
                     lambda request: httpx.Response(404))
    assert result.status == "ok" and result.findings == [] and result.checked == 1
    assert result.facts == ["VirusTotal: no known threats among the 1 item(s) checked."]


def test_rate_limit_is_reported():
    result = analyze(make_context(body_html='<a href="http://new-site.xyz">x</a>'),
                     lambda request: httpx.Response(429))
    assert result.status == "rate_limited" and result.checked == 0


def test_unexpected_payload_is_rejected():
    with pytest.raises(ValueError):
        analyze(make_context(body_html='<a href="http://new-site.xyz">x</a>'),
                lambda request: httpx.Response(200, json={"data": {}}))


def test_targets_prioritize_hashes_skip_common_domains_and_cap_at_three():
    links = "".join(f'<a href="http://{d}/">x</a>' for d in ("google.com", "a.xyz", "b.xyz", "c.xyz"))
    ctx = make_context(body_html=links,
                       attachments=[AttachmentIn(name="f.pdf", size=1, sha256=HASH)])
    targets, total = virustotal.pick_targets(ctx)
    assert targets == [("files", HASH), ("domains", "a.xyz"), ("domains", "b.xyz")]
    assert total == 4


def test_sender_domain_is_a_target():
    targets, _ = virustotal.pick_targets(make_context(headers_raw="From: x@evil-sender.xyz"))
    assert targets == [("domains", "evil-sender.xyz")]
