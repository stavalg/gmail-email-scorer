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
    # Measured on Cloud Run: every successful AI answer arrived in 1.2-3.8 s, and nothing arrived
    # between 5 and 10 s, so a longer wait only delays the card. Budget is 15 s (Gmail: ~30 s).
    assert pipeline.HTTP_TIMEOUT_SECONDS == 6.0
    assert pipeline.OPTIONAL_TIMEOUT_SECONDS == 8.0
    assert pipeline.HTTP_TIMEOUT_SECONDS <= pipeline.OPTIONAL_TIMEOUT_SECONDS <= 15.0


def test_parsing_and_rules_run_off_the_event_loop(monkeypatch):
    # CPU-heavy parsing must not block other requests on the same server instance.
    import threading
    seen = {}
    original = pipeline.build_context

    def spy(request):
        seen["thread"] = threading.get_ident()
        return original(request)
    monkeypatch.setattr(pipeline, "build_context", spy)

    async def caller():
        seen["loop"] = threading.get_ident()
        return await pipeline.analyze_email(REQUEST, make_settings())
    asyncio.run(caller())
    assert seen["thread"] != seen["loop"]


def test_unreadable_html_marks_rules_partial_and_warns(monkeypatch):
    import app.parsing.body as body_module

    def crash(self, data):
        raise AssertionError("parser bug")
    monkeypatch.setattr(body_module._HtmlCollector, "feed", crash)
    request = AnalyzeRequest(body_html="<p>x</p>", body_text="hello")
    result = asyncio.run(pipeline.analyze_email(request, make_settings()))
    assert result.coverage["rules"].status == "partial"
    assert any("could not be read" in notice for notice in result.notices)
    assert CAUTION_NOTICE in result.notices


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
