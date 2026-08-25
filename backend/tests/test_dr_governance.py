from __future__ import annotations

from common.dr_governance import RecoveryDecision, authorize_dlq_replay, evaluate_recovery_readiness


def test_recovery_objectives_allow_verified_restore() -> None:
    result = evaluate_recovery_readiness(
        component="database",
        observed_rpo_seconds=30,
        observed_rto_seconds=120,
        integrity_verified=True,
    )
    assert result["decision"] == RecoveryDecision.ALLOW.value


def test_recovery_blocks_integrity_failure() -> None:
    result = evaluate_recovery_readiness(
        component="audit_ledger",
        observed_rpo_seconds=0,
        observed_rto_seconds=30,
        integrity_verified=False,
    )
    assert result["decision"] == RecoveryDecision.BLOCK.value
    assert result["reason"] == "RECOVERY_INTEGRITY_UNVERIFIED"


def test_recovery_blocks_rpo_and_rto_breach() -> None:
    assert evaluate_recovery_readiness(
        component="database", observed_rpo_seconds=61, observed_rto_seconds=100, integrity_verified=True
    )["reason"] == "RPO_BREACH"
    assert evaluate_recovery_readiness(
        component="database", observed_rpo_seconds=30, observed_rto_seconds=301, integrity_verified=True
    )["reason"] == "RTO_BREACH"


def test_production_dlq_replay_requires_independent_approval() -> None:
    event = {"failed_topic": "resolution-events", "payload": {"event_id": "evt-1"}}
    held = authorize_dlq_replay(
        failed_event=event,
        requested_by="operator-a",
        approved_by=None,
        tenant_id="tenant-a",
        production=True,
        chain_integrity_verified=True,
    )
    assert held.decision == RecoveryDecision.HOLD
    blocked = authorize_dlq_replay(
        failed_event=event,
        requested_by="operator-a",
        approved_by="operator-a",
        tenant_id="tenant-a",
        production=True,
        chain_integrity_verified=True,
    )
    assert blocked.reason == "DLQ_REPLAY_SEPARATION_OF_DUTIES_REQUIRED"


def test_dlq_replay_requires_verified_audit_chain() -> None:
    result = authorize_dlq_replay(
        failed_event={"failed_topic": "remediation-events", "payload": {"event_id": "evt-2"}},
        requested_by="operator-a",
        approved_by="operator-b",
        tenant_id="tenant-a",
        production=True,
        chain_integrity_verified=False,
    )
    assert result.decision == RecoveryDecision.BLOCK
    assert result.reason == "AUDIT_CHAIN_NOT_VERIFIED"


def test_dlq_replay_authorized_with_separation_of_duties() -> None:
    result = authorize_dlq_replay(
        failed_event={"failed_topic": "remediation-events", "payload": {"event_id": "evt-2"}},
        requested_by="operator-a",
        approved_by="operator-b",
        tenant_id="tenant-a",
        production=True,
        chain_integrity_verified=True,
    )
    assert result.decision == RecoveryDecision.ALLOW
    assert result.replay_key == "dlq-replay:tenant-a:remediation-events:evt-2"
