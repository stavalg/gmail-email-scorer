import asyncio

import app.pipeline as pipeline
from app.analyzers import virustotal
from app.models import AnalyzeRequest
from app.scoring import CAUTION_NOTICE
from tests.helpers import make_settings

REQUEST = AnalyzeRequest(headers_raw="From: Dana <dana@example.com>", body_text="hello")


def run(settings):
    return asyncio.run(pipeline.analyze_email(REQUEST, settings))


def test_timeouts_fit_the_15_second_budget():
    # Gemini's free tier sometimes needs 5-10 s; Gmail kills the add-on at ~30 s; budget is 15 s.
    assert pipeline.HTTP_TIMEOUT_SECONDS == 10.0
    assert pipeline.OPTIONAL_TIMEOUT_SECONDS == 12.0
    assert pipeline.HTTP_TIMEOUT_SECONDS <= pipeline.OPTIONAL_TIMEOUT_SECONDS <= 15.0


def test_unconfigured_analyzers_are_skipped():
    result = run(make_settings())
    assert result.coverage["virustotal"].status == "skipped"
    assert result.coverage["llm"].status == "skipped"
    assert CAUTION_NOTICE not in result.notices


def test_no_http_client_when_nothing_is_configured(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("an HTTP client must not be created without any API key")
    monkeypatch.setattr(pipeline.httpx, "AsyncClient", forbidden)
    assert run(make_settings()).coverage["virustotal"].status == "skipped"


def test_slow_analyzer_times_out_but_analysis_completes(monkeypatch):
    async def slow(*args):
        await asyncio.sleep(1)
    monkeypatch.setattr(virustotal, "analyze", slow)
    monkeypatch.setattr(pipeline, "OPTIONAL_TIMEOUT_SECONDS", 0.05)
    result = run(make_settings(virustotal_api_key="k"))
    assert result.coverage["virustotal"].status == "timeout"
    assert result.verdict == "safe" and CAUTION_NOTICE in result.notices


def test_crashing_analyzer_becomes_error_status(monkeypatch):
    async def broken(*args):
        raise RuntimeError("down")
    monkeypatch.setattr(virustotal, "analyze", broken)
    result = run(make_settings(virustotal_api_key="k"))
    assert result.coverage["virustotal"].status == "error"
