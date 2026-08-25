from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from common.models import RemediationAction


class ExecutionSafetyDecision(StrEnum):
    ALLOW = "ALLOW"
    DUPLICATE = "DUPLICATE"
    LOCKED = "LOCKED"
    BLOCK = "BLOCK"


@dataclass(frozen=True)
class ExecutionStage:
    name: str
    percent: int
    requires_health_gate: bool = True


@dataclass(frozen=True)
class ExecutionSafetyAssessment:
    decision: ExecutionSafetyDecision
    reason: str
    idempotency_key: str
    lock_key: str
    snapshot_hash: str
    stages: tuple[ExecutionStage, ...] = field(default_factory=tuple)

    @property
    def allowed(self) -> bool:
        return self.decision == ExecutionSafetyDecision.ALLOW

    def as_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision.value,
            "reason": self.reason,
            "idempotency_key": self.idempotency_key,
            "lock_key": self.lock_key,
            "snapshot_hash": self.snapshot_hash,
            "stages": [
                {
                    "name": stage.name,
                    "percent": stage.percent,
                    "requires_health_gate": stage.requires_health_gate,
                }
                for stage in self.stages
            ],
        }


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def immutable_pre_execution_snapshot(action: RemediationAction) -> dict[str, Any]:
    parameters = action.parameters if isinstance(action.parameters, dict) else {}
    return {
        "incident_id": str(action.incident_id),
        "approval_id": str(action.approval_id) if action.approval_id else None,
        "action_type": str(action.action_type),
        "target": str(action.target),
        "capability_id": parameters.get("capability_id"),
        "capability_version": parameters.get("capability_version"),
        "plan_id": parameters.get("plan_id"),
        "plan_revision": parameters.get("plan_revision"),
        "plan_hash": parameters.get("plan_hash"),
        "target_version": parameters.get("target_version"),
        "environment": parameters.get("environment"),
        "execution_strategy": parameters.get("execution_strategy"),
        "pre_action_state": (
            parameters.get("rollback_plan", {}).get("pre_action_state", {})
            if isinstance(parameters.get("rollback_plan"), dict)
            else {}
        ),
        "parameters": {
            key: value
            for key, value in parameters.items()
            if key not in {"credentials", "password", "secret", "token", "api_key"}
        },
    }


def snapshot_hash(snapshot: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical(snapshot).encode("utf-8")).hexdigest()


def execution_idempotency_key(action: RemediationAction) -> str:
    parameters = action.parameters if isinstance(action.parameters, dict) else {}
    identity = {
        "incident_id": str(action.incident_id),
        "plan_id": parameters.get("plan_id"),
        "plan_revision": parameters.get("plan_revision"),
        "plan_hash": parameters.get("plan_hash"),
        "capability_id": parameters.get("capability_id"),
        "target": str(action.target),
        "target_version": parameters.get("target_version"),
    }
    return "kaiops:remediation:idempotency:" + hashlib.sha256(_canonical(identity).encode("utf-8")).hexdigest()


def execution_lock_key(action: RemediationAction) -> str:
    normalized_target = hashlib.sha256(str(action.target).encode("utf-8")).hexdigest()[:24]
    return f"kaiops:remediation:lock:{normalized_target}"


def execution_stages(action: RemediationAction) -> tuple[ExecutionStage, ...]:
    strategy = str(action.parameters.get("execution_strategy") or "SINGLE").upper()
    if strategy == "CANARY":
        return (
            ExecutionStage("canary", 5, True),
            ExecutionStage("expand", 25, True),
            ExecutionStage("complete", 100, True),
        )
    if strategy == "PROGRESSIVE":
        return (
            ExecutionStage("stage-1", 10, True),
            ExecutionStage("stage-2", 25, True),
            ExecutionStage("stage-3", 50, True),
            ExecutionStage("complete", 100, True),
        )
    return (ExecutionStage("single", 100, True),)


def detect_recursive_rollback(action: RemediationAction) -> bool:
    if "rollback" not in str(action.action_type or "").lower():
        return False
    parameters = action.parameters if isinstance(action.parameters, dict) else {}
    lineage = parameters.get("rollback_lineage")
    lineage = lineage if isinstance(lineage, list) else []
    prior_rollback_count = sum(1 for item in lineage if "rollback" in str(item).lower())
    return prior_rollback_count >= 1


def build_execution_safety_assessment(action: RemediationAction) -> ExecutionSafetyAssessment:
    snapshot = immutable_pre_execution_snapshot(action)
    digest = snapshot_hash(snapshot)
    idem = execution_idempotency_key(action)
    lock = execution_lock_key(action)

    if action.action_type == "unsupported_capability":
        return ExecutionSafetyAssessment(
            ExecutionSafetyDecision.BLOCK,
            "action already blocked by remediation governance",
            idem,
            lock,
            digest,
        )

    if detect_recursive_rollback(action):
        return ExecutionSafetyAssessment(
            ExecutionSafetyDecision.BLOCK,
            "ROLLBACK_CHAIN_BLOCKED: rollback-of-rollback requires explicit human recovery plan",
            idem,
            lock,
            digest,
        )

    if not str(action.parameters.get("plan_hash") or "").strip():
        return ExecutionSafetyAssessment(
            ExecutionSafetyDecision.BLOCK,
            "EXECUTION_SNAPSHOT_UNBOUND: plan_hash is required before execution",
            idem,
            lock,
            digest,
        )

    if not action.parameters.get("validation_plan"):
        return ExecutionSafetyAssessment(
            ExecutionSafetyDecision.BLOCK,
            "EXECUTION_HEALTH_GATE_MISSING: validation plan is required",
            idem,
            lock,
            digest,
        )

    return ExecutionSafetyAssessment(
        ExecutionSafetyDecision.ALLOW,
        "execution safety contract satisfied",
        idem,
        lock,
        digest,
        execution_stages(action),
    )
