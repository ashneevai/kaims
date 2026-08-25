from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class SafeTerminalState(StrEnum):
    RECOVERED = "RECOVERED"
    ROLLED_BACK = "ROLLED_BACK"
    HITL = "HITL"
    QUARANTINED = "QUARANTINED"


@dataclass(frozen=True)
class RecoveryCertification:
    certified: bool
    terminal_state: SafeTerminalState | None
    failures: tuple[str, ...]
    evidence: dict[str, Any]


def certify_incident_recovery(
    *,
    incident_id: str,
    terminal_state: str | None,
    action_execution_count: int,
    expected_max_action_execution_count: int,
    event_loss_detected: bool,
    duplicate_execution_detected: bool,
    audit_chain_valid: bool,
    replay_guard_valid: bool,
    validation_evidence_present: bool,
    unresolved_processing_lease: bool = False,
) -> RecoveryCertification:
    failures: list[str] = []
    state: SafeTerminalState | None = None
    try:
        state = SafeTerminalState(str(terminal_state or "").strip().upper())
    except ValueError:
        failures.append("UNSAFE_OR_MISSING_TERMINAL_STATE")

    if event_loss_detected:
        failures.append("EVENT_LOSS_DETECTED")
    if duplicate_execution_detected:
        failures.append("DUPLICATE_EXECUTION_DETECTED")
    if int(action_execution_count) > int(expected_max_action_execution_count):
        failures.append("ACTION_EXECUTION_BUDGET_EXCEEDED")
    if not audit_chain_valid:
        failures.append("AUDIT_CHAIN_INVALID")
    if not replay_guard_valid:
        failures.append("REPLAY_GUARD_INVALID")
    if unresolved_processing_lease:
        failures.append("ORPHANED_PROCESSING_LEASE")
    if state in {SafeTerminalState.RECOVERED, SafeTerminalState.ROLLED_BACK} and not validation_evidence_present:
        failures.append("TERMINAL_VALIDATION_EVIDENCE_MISSING")

    return RecoveryCertification(
        certified=not failures,
        terminal_state=state,
        failures=tuple(failures),
        evidence={
            "incident_id": str(incident_id),
            "action_execution_count": int(action_execution_count),
            "expected_max_action_execution_count": int(expected_max_action_execution_count),
            "event_loss_detected": bool(event_loss_detected),
            "duplicate_execution_detected": bool(duplicate_execution_detected),
            "audit_chain_valid": bool(audit_chain_valid),
            "replay_guard_valid": bool(replay_guard_valid),
            "validation_evidence_present": bool(validation_evidence_present),
            "unresolved_processing_lease": bool(unresolved_processing_lease),
        },
    )


CHAOS_SCENARIOS: tuple[dict[str, Any], ...] = (
    {"id": "pod-kill-context", "fault": "terminate context-agent during evidence collection", "must_preserve": ["event", "trace"]},
    {"id": "pod-kill-remediation", "fault": "terminate remediation-engine during execution", "must_preserve": ["idempotency", "lock", "audit"]},
    {"id": "redis-outage", "fault": "make Redis unavailable", "must_preserve": ["fail_closed", "no_duplicate_execution"]},
    {"id": "rabbitmq-partition", "fault": "interrupt RabbitMQ delivery", "must_preserve": ["durable_event", "replay"]},
    {"id": "kafka-rebalance", "fault": "force Kafka consumer rebalance", "must_preserve": ["offset", "idempotency"]},
    {"id": "database-failover", "fault": "fail primary database during lifecycle persistence", "must_preserve": ["rpo", "rto", "integrity"]},
    {"id": "executor-timeout", "fault": "timeout native remediation connector", "must_preserve": ["abort", "validation", "hitl"]},
    {"id": "duplicate-delivery", "fault": "deliver same remediation event twice", "must_preserve": ["exactly_once_effect"]},
    {"id": "audit-chain-tamper", "fault": "alter one immutable audit record", "must_preserve": ["detect", "block_recovery"]},
    {"id": "network-partition", "fault": "partition lifecycle controller from event bus", "must_preserve": ["no_event_loss", "eventual_recovery"]},
)
