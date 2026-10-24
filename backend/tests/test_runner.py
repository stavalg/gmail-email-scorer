from app.analyzers.base import Finding
from app.analyzers.rules.common import RuleOutput
from app.analyzers.rules.runner import run_rules
from tests.helpers import make_context

FINDING = Finding(id="x", category="content", title="X", evidence="e", points=10)


def ok_check(ctx):
    return RuleOutput(findings=[FINDING], facts=["fact"])


def broken_check(ctx):
    raise KeyError("boom")


def test_runs_checks_and_collects_output():
    result = run_rules(make_context(), checks=[ok_check])
    assert result.status == "ok"
    assert result.findings == [FINDING] and result.facts == ["fact"]


def test_a_failing_check_is_isolated_and_reported():
    result = run_rules(make_context(), checks=[broken_check, ok_check])
    assert result.status == "partial"
    assert result.findings == [FINDING]
    assert result.notices == ["1 check(s) could not run on this email."]


def test_default_check_list_runs():
    assert run_rules(make_context()).name == "rules"
