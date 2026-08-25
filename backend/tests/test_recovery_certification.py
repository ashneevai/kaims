from __future__ import annotations

from common.recovery_certification import SafeTerminalState, certify_incident_recovery


def _certify(**overrides):
    values = {
        "incident_id": "inc-1",
        "terminal_state": "RECOVERED",
        "action_execution_count": 1,
        "expected_max_action_execution_count": 1,
        "event_loss_detected": False,
        "duplicate_execution_detected": False,
        "audit_chain_valid": True,
        "replay_guard_valid": True,
        "validation_evidence_present": True,
        "unresolved_processing_lease": False,
    }
    values.update(overrides)
    return certify_incident_recovery(**values)


def test_recovered_incident_can_be_certified() -> None:
    result = _certify()
    assert result.certified is True
    assert result.terminal_state == SafeTerminalState.RECOVERED


def test_hitl_is_safe_terminal_state_without_recovery_claim() -> None:
    result = _certify(terminal_state="HITL", validation_evidence_present=False)
    assert result.certified is True
    assert result.terminal_state == SafeTerminalState.HITL


def test_unknown_terminal_state_fails_certification() -> None:
    result = _certify(terminal_state="OPEN")
    assert result.certified is False
    assert "UNSAFE_OR_MISSING_TERMINAL_STATE" in result.failures


def test_duplicate_execution_fails_certification() -> None:
    result = _certify(duplicate_execution_detected=True, action_execution_count=2)
    assert result.certified is False
    assert "DUPLICATE_EXECUTION_DETECTED" in result.failures
    assert "ACTION_EXECUTION_BUDGET_EXCEEDED" in result.failures


def test_event_loss_and_broken_audit_fail_certification() -> None:
    result = _certify(event_loss_detected=True, audit_chain_valid=False)
    assert "EVENT_LOSS_DETECTED" in result.failures
    assert "AUDIT_CHAIN_INVALID" in result.failures


def test_recovered_requires_validation_evidence() -> None:
    result = _certify(validation_evidence_present=False)
    assert result.certified is False
    assert "TERMINAL_VALIDATION_EVIDENCE_MISSING" in result.failures


def test_orphaned_replay_lease_fails_certification() -> None:
    result = _certify(unresolved_processing_lease=True)
    assert result.certified is False
    assert "ORPHANED_PROCESSING_LEASE" in result.failures
