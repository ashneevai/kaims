from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


class RecoveryDecision(StrEnum):
    ALLOW = "ALLOW"
    HOLD = "HOLD"
    BLOCK = "BLOCK"


@dataclass(frozen=True)
class RecoveryObjective:
    component: str
    rpo_seconds: int
    rto_seconds: int
    fail_closed: bool


@dataclass(frozen=True)
class DlqReplayDecision:
    decision: RecoveryDecision
    reason: str
    replay_key: str | None = None


CRITICAL_RECOVERY_OBJECTIVES: dict[str, RecoveryObjective] = {
    "database": RecoveryObjective("database", rpo_seconds=60, rto_seconds=300, fail_closed=True),
    "redis": RecoveryObjective("redis", rpo_seconds=0, rto_seconds=120, fail_closed=True),
    "rabbitmq": RecoveryObjective("rabbitmq", rpo_seconds=0, rto_seconds=180, fail_closed=True),
    "kafka": RecoveryObjective("kafka", rpo_seconds=0, rto_seconds=180, fail_closed=True),
    "audit_ledger": RecoveryObjective("audit_ledger", rpo_seconds=0, rto_seconds=300, fail_closed=True),
}


def evaluate_recovery_readiness(
    *,
    component: str,
    observed_rpo_seconds: int | float | None,
    observed_rto_seconds: int | float | None,
    integrity_verified: bool,
) -> dict[str, Any]:
    name = str(component or "").strip().lower()
    objective = CRITICAL_RECOVERY_OBJECTIVES.get(name)
    if objective is None:
        return {"decision": RecoveryDecision.HOLD.value, "reason": "RECOVERY_OBJECTIVE_UNDEFINED", "component": name}
    if not integrity_verified:
        return {"decision": RecoveryDecision.BLOCK.value, "reason": "RECOVERY_INTEGRITY_UNVERIFIED", "component": name}
    if observed_rpo_seconds is None or observed_rto_seconds is None:
        return {"decision": RecoveryDecision.HOLD.value, "reason": "RECOVERY_MEASUREMENT_MISSING", "component": name}
    if float(observed_rpo_seconds) > objective.rpo_seconds:
        return {"decision": RecoveryDecision.BLOCK.value, "reason": "RPO_BREACH", "component": name}
    if float(observed_rto_seconds) > objective.rto_seconds:
        return {"decision": RecoveryDecision.BLOCK.value, "reason": "RTO_BREACH", "component": name}
    return {
        "decision": RecoveryDecision.ALLOW.value,
        "reason": "RECOVERY_OBJECTIVES_MET",
        "component": name,
        "rpo_seconds": objective.rpo_seconds,
        "rto_seconds": objective.rto_seconds,
    }


def authorize_dlq_replay(
    *,
    failed_event: dict[str, Any],
    requested_by: str,
    approved_by: str | None,
    tenant_id: str,
    production: bool,
    chain_integrity_verified: bool,
) -> DlqReplayDecision:
    requester = str(requested_by or "").strip()
    approver = str(approved_by or "").strip()
    tenant = str(tenant_id or "").strip()
    failed_topic = str(failed_event.get("failed_topic") or "").strip()
    payload = failed_event.get("payload") if isinstance(failed_event.get("payload"), dict) else {}
    identity = str(
        payload.get("event_id")
        or (payload.get("event_contract") or {}).get("event_id") if isinstance(payload.get("event_contract"), dict) else ""
    ).strip()

    if not tenant or not requester or not failed_topic:
        return DlqReplayDecision(RecoveryDecision.BLOCK, "DLQ_REPLAY_IDENTITY_INCOMPLETE")
    if not chain_integrity_verified:
        return DlqReplayDecision(RecoveryDecision.BLOCK, "AUDIT_CHAIN_NOT_VERIFIED")
    if production and not approver:
        return DlqReplayDecision(RecoveryDecision.HOLD, "DLQ_REPLAY_APPROVAL_REQUIRED")
    if production and approver == requester:
        return DlqReplayDecision(RecoveryDecision.BLOCK, "DLQ_REPLAY_SEPARATION_OF_DUTIES_REQUIRED")
    replay_key = f"dlq-replay:{tenant}:{failed_topic}:{identity or 'unknown'}"
    return DlqReplayDecision(RecoveryDecision.ALLOW, "DLQ_REPLAY_AUTHORIZED", replay_key)


def build_recovery_evidence(*, component: str, region: str, restored_from: str, integrity: dict[str, Any]) -> dict[str, Any]:
    return {
        "component": str(component).strip().lower(),
        "region": str(region).strip(),
        "restored_from": str(restored_from).strip(),
        "integrity": integrity,
        "verified_at": datetime.now(UTC).isoformat(),
        "contract_version": "1.0",
    }
