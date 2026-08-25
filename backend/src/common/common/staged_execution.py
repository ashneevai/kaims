from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class StageGateDecision(StrEnum):
    ADVANCE = "ADVANCE"
    HOLD = "HOLD"
    ABORT = "ABORT"


@dataclass(frozen=True)
class StageGateResult:
    decision: StageGateDecision
    reason: str
    failed_checks: tuple[str, ...] = ()

    @property
    def can_advance(self) -> bool:
        return self.decision == StageGateDecision.ADVANCE

    def as_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision.value,
            "reason": self.reason,
            "failed_checks": list(self.failed_checks),
        }


def evaluate_stage_health_gate(observation: dict[str, Any] | None) -> StageGateResult:
    payload = observation if isinstance(observation, dict) else {}
    mode = str(payload.get("mode") or "").upper()
    evidence_ids = payload.get("evidence_ids")
    evidence_ids = evidence_ids if isinstance(evidence_ids, list) else []

    if mode not in {"LIVE", "DEGRADED"}:
        return StageGateResult(
            StageGateDecision.HOLD,
            "stage health evidence is not production-usable",
            ("EVIDENCE_MODE",),
        )
    if not evidence_ids:
        return StageGateResult(
            StageGateDecision.HOLD,
            "stage health evidence lacks provenance",
            ("EVIDENCE_PROVENANCE",),
        )

    abort_flags = {
        "new_critical_alert": bool(payload.get("new_critical_alert")),
        "error_rate_regression": bool(payload.get("error_rate_regression")),
        "dependency_regression": bool(payload.get("dependency_regression")),
        "slo_regression": bool(payload.get("slo_regression")),
        "data_loss_signal": bool(payload.get("data_loss_signal")),
    }
    failed_abort = tuple(name for name, active in abort_flags.items() if active)
    if failed_abort:
        return StageGateResult(
            StageGateDecision.ABORT,
            "stage regression detected; stop further rollout",
            failed_abort,
        )

    required_checks = payload.get("required_checks")
    required_checks = required_checks if isinstance(required_checks, dict) else {}
    missing_or_failed = tuple(
        str(name)
        for name, passed in required_checks.items()
        if passed is not True
    )
    if missing_or_failed:
        return StageGateResult(
            StageGateDecision.HOLD,
            "required stage health checks are not all healthy",
            missing_or_failed,
        )

    if not required_checks:
        return StageGateResult(
            StageGateDecision.HOLD,
            "no required health checks were supplied for the stage",
            ("REQUIRED_CHECKS_MISSING",),
        )

    return StageGateResult(
        StageGateDecision.ADVANCE,
        "live stage evidence is healthy; rollout may advance",
    )


def next_stage_index(
    *,
    current_index: int,
    total_stages: int,
    gate: StageGateResult,
) -> int:
    if total_stages < 1:
        raise ValueError("total_stages must be at least 1")
    if current_index < 0 or current_index >= total_stages:
        raise ValueError("current_index is outside stage range")
    if not gate.can_advance:
        return current_index
    return min(current_index + 1, total_stages - 1)
