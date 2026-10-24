import json
from pathlib import Path

import app.analyzers.rules.runner as runner
import app.pipeline as pipeline
from app.scoring import CAUTION_NOTICE

SAMPLES = Path(__file__).parent.parent / "samples"


def sample(name):
    return json.loads((SAMPLES / f"{name}.json").read_text(encoding="utf-8"))


def analyze(client, body):
    response = client.post("/v1/analyze", json=body)
    assert response.status_code == 200, response.text
    return response.json()


def test_phishing_sample_is_malicious(authed_client):
    result = analyze(authed_client, sample("phishing"))
    assert (result["score"], result["verdict"]) == (100, "malicious")
    found = {f["id"] for f in result["findings"]}
    assert {"dmarc_fail", "lookalike_domain", "brand_in_subdomain",
            "link_text_mismatch", "double_extension"} <= found
    points = [f["points"] for f in result["findings"]]
    assert points == sorted(points, reverse=True)
    assert result["coverage"]["rules"] == {"status": "ok", "checked": None, "total": None}


def test_safe_sample_is_safe(authed_client):
    result = analyze(authed_client, sample("safe"))
    assert (result["score"], result["verdict"]) == (0, "safe")
    assert any("passed" in fact for fact in result["facts"])


def test_crashing_rule_never_looks_silently_safe(authed_client, monkeypatch):
    def boom(ctx):
        raise RuntimeError("bug")
    monkeypatch.setattr(runner, "CHECKS", (boom,))
    result = analyze(authed_client, sample("safe"))
    assert result["coverage"]["rules"]["status"] == "partial"
    assert CAUTION_NOTICE in result["notices"]


def test_total_failure_is_an_error_without_details(authed_client, monkeypatch):
    def explode(request):
        raise ValueError("secret-content-123")
    monkeypatch.setattr(pipeline, "build_context", explode)
    response = authed_client.post("/v1/analyze", json=sample("safe"))
    assert response.status_code == 500
    assert "secret-content-123" not in response.text


def test_padded_email_still_finds_late_link(authed_client):
    body = {"body_html": "<p>" + "harmless " * 25_000 + '</p><a href="http://evil.top/x">x</a>'}
    result = analyze(authed_client, body)
    assert "abused_tld" in {f["id"] for f in result["findings"]}
    assert any("very large" in notice for notice in result["notices"])


def test_truncation_by_the_addon_is_disclosed(authed_client):
    result = analyze(authed_client, {"body_text": "hello", "truncated": True})
    assert any("very large" in notice for notice in result["notices"])
