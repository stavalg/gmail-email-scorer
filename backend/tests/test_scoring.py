import pytest

from app.analyzers.base import AnalyzerResult, Finding
from app.scoring import CAUTION_NOTICE, score_results, verdict_for


def finding(points, finding_id="x", evidence="e"):
    return Finding(id=finding_id, category="content", title="T", evidence=evidence, points=points)


def rules(*findings, status="ok"):
    return AnalyzerResult(name="rules", status=status, findings=list(findings))


def test_no_findings_is_safe_zero():
    response = score_results([rules()])
    assert (response.score, response.verdict) == (0, "safe")
    assert response.notices == []


def test_score_is_capped_at_100():
    assert score_results([rules(finding(60), finding(60))]).score == 100


@pytest.mark.parametrize("score, verdict", [(29, "safe"), (30, "suspicious"),
                                            (69, "suspicious"), (70, "malicious")])
def test_verdict_boundaries(score, verdict):
    assert verdict_for(score) == verdict


def test_known_malicious_sets_floor():
    vt = AnalyzerResult(name="virustotal", status="ok", known_malicious=True)
    response = score_results([rules(), vt])
    assert (response.score, response.verdict) == (90, "malicious")


def test_findings_are_sorted_strongest_first():
    response = score_results([rules(finding(10, "a"), finding(30, "b"), finding(20, "c"))])
    assert [f.id for f in response.findings] == ["b", "c", "a"]


def test_safe_with_failed_check_gets_caution_notice():
    response = score_results([rules(status="partial")])
    assert response.verdict == "safe" and CAUTION_NOTICE in response.notices


def test_no_caution_notice_when_not_safe():
    response = score_results([rules(finding(40), status="partial")])
    assert CAUTION_NOTICE not in response.notices


def test_evidence_is_cleaned_and_capped():
    response = score_results([rules(finding(10, evidence="a‮b" + "x" * 300))])
    evidence = response.findings[0].evidence
    assert "‮" not in evidence and len(evidence) == 200


def test_coverage_and_details_are_reported():
    vt = AnalyzerResult(name="virustotal", status="timeout", checked=1, total=4,
                        details={"lookups": []})
    response = score_results([rules(), vt], notices=["n"], details={"from_domain": "a[.]com"})
    assert response.coverage["virustotal"].status == "timeout"
    assert response.coverage["virustotal"].checked == 1
    assert response.details == {"from_domain": "a[.]com", "virustotal": {"lookups": []}}
    assert response.notices[0] == "n"


def test_advice_is_one_sentence_and_safe_has_none():
    assert score_results([rules()]).advice == []
    for points in (40, 80):
        assert len(score_results([rules(finding(points))]).advice) == 1
