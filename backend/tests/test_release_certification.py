from __future__ import annotations

from common.release_certification import GATES, ReleaseDecision, certify_release


def _all_pass():
    return {gate.name: True for gate in GATES}


def test_all_gates_pass_is_go() -> None:
    result = certify_release(evidence=_all_pass())
    assert result["decision"] == ReleaseDecision.GO.value
    assert result["score"] == 100
    assert result["autonomous_production_allowed"] is True


def test_any_critical_failure_is_no_go() -> None:
    evidence = _all_pass()
    evidence["security_tests"] = False
    result = certify_release(evidence=evidence)
    assert result["decision"] == ReleaseDecision.NO_GO.value
    assert "security_tests" in result["critical_failures"]
    assert result["autonomous_production_allowed"] is False


def test_noncritical_failure_can_be_conditional_go() -> None:
    evidence = _all_pass()
    evidence["connector_certification"] = False
    evidence["load_performance_certification"] = False
    result = certify_release(evidence=evidence)
    assert result["decision"] == ReleaseDecision.CONDITIONAL_GO.value
    assert result["score"] == 84 or result["decision"] == ReleaseDecision.NO_GO.value


def test_missing_critical_evidence_fails_closed() -> None:
    evidence = _all_pass()
    del evidence["chaos_recovery_certification"]
    result = certify_release(evidence=evidence)
    assert result["decision"] == ReleaseDecision.NO_GO.value
    assert "chaos_recovery_certification" in result["missing_evidence"]


def test_structured_certification_evidence_is_supported() -> None:
    evidence = _all_pass()
    evidence["immutable_audit_verification"] = {"valid": True}
    evidence["chaos_recovery_certification"] = {"certified": True}
    evidence["slo_certification"] = {"passed": True}
    result = certify_release(evidence=evidence)
    assert result["decision"] == ReleaseDecision.GO.value
