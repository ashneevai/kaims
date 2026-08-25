from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class AutonomyMode(StrEnum):
    AUTONOMOUS = "AUTONOMOUS"
    GUIDED = "GUIDED"
    HITL_ONLY = "HITL_ONLY"
    KILL_SWITCH = "KILL_SWITCH"


@dataclass(frozen=True)
class PlatformSlo:
    name: str
    target: float
    direction: str
    critical: bool = False


PLATFORM_SLOS: tuple[PlatformSlo, ...] = (
    PlatformSlo("alert_to_triage_p95_seconds", 30.0, "lte"),
    PlatformSlo("triage_to_rca_p95_seconds", 180.0, "lte"),
    PlatformSlo("approval_wait_p95_seconds", 600.0, "lte"),
    PlatformSlo("remediation_to_validation_p95_seconds", 300.0, "lte"),
    PlatformSlo("event_processing_success_rate", 0.999, "gte", True),
    PlatformSlo("audit_chain_valid_rate", 1.0, "gte", True),
    PlatformSlo("duplicate_production_effect_rate", 0.0, "lte", True),
    PlatformSlo("unsafe_action_escape_rate", 0.0, "lte", True),
    PlatformSlo("autonomous_recovery_success_rate", 0.95, "gte"),
    PlatformSlo("validation_evidence_coverage", 0.99, "gte", True),
)


def _passes(value: float, slo: PlatformSlo) -> bool:
    return value <= slo.target if slo.direction == "lte" else value >= slo.target


def evaluate_autonomy_mode(
    *,
    metrics: dict[str, float | int | None],
    manual_kill_switch: bool = False,
    critical_dependency_unavailable: bool = False,
    audit_chain_broken: bool = False,
) -> dict[str, Any]:
    if manual_kill_switch:
        return {"mode": AutonomyMode.KILL_SWITCH.value, "score": 0, "reasons": ["MANUAL_KILL_SWITCH"]}
    if audit_chain_broken:
        return {"mode": AutonomyMode.HITL_ONLY.value, "score": 0, "reasons": ["AUDIT_CHAIN_BROKEN"]}
    if critical_dependency_unavailable:
        return {"mode": AutonomyMode.HITL_ONLY.value, "score": 0, "reasons": ["CRITICAL_DEPENDENCY_UNAVAILABLE"]}

    failures: list[str] = []
    critical_failures: list[str] = []
    evaluated = 0
    passed = 0
    for slo in PLATFORM_SLOS:
        raw = metrics.get(slo.name)
        if raw is None:
            failures.append(f"{slo.name}:MISSING")
            if slo.critical:
                critical_failures.append(f"{slo.name}:MISSING")
            continue
        evaluated += 1
        if _passes(float(raw), slo):
            passed += 1
        else:
            failures.append(f"{slo.name}:BREACH")
            if slo.critical:
                critical_failures.append(f"{slo.name}:BREACH")

    score = round((passed / len(PLATFORM_SLOS)) * 100) if PLATFORM_SLOS else 0
    if critical_failures:
        mode = AutonomyMode.HITL_ONLY
    elif failures or score < 95:
        mode = AutonomyMode.GUIDED
    else:
        mode = AutonomyMode.AUTONOMOUS
    return {
        "mode": mode.value,
        "score": score,
        "evaluated_slos": evaluated,
        "total_slos": len(PLATFORM_SLOS),
        "reasons": failures,
        "critical_failures": critical_failures,
    }


def action_allowed_for_mode(*, mode: str, requires_approval: bool, is_read_only: bool = False) -> bool:
    resolved = AutonomyMode(str(mode).strip().upper())
    if resolved == AutonomyMode.KILL_SWITCH:
        return False
    if is_read_only:
        return True
    if resolved == AutonomyMode.HITL_ONLY:
        return bool(requires_approval)
    if resolved == AutonomyMode.GUIDED:
        return bool(requires_approval)
    return True
