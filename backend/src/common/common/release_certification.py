from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class ReleaseDecision(StrEnum):
    GO = "GO"
    CONDITIONAL_GO = "CONDITIONAL_GO"
    NO_GO = "NO_GO"


@dataclass(frozen=True)
class CertificationGate:
    name: str
    weight: int
    critical: bool = False


GATES: tuple[CertificationGate, ...] = (
    CertificationGate("unit_integration_tests", 10, True),
    CertificationGate("architecture_contract_tests", 8, True),
    CertificationGate("security_tests", 12, True),
    CertificationGate("tenant_isolation_tests", 10, True),
    CertificationGate("immutable_audit_verification", 10, True),
    CertificationGate("chaos_recovery_certification", 12, True),
    CertificationGate("connector_certification", 8, False),
    CertificationGate("slo_certification", 10, True),
    CertificationGate("load_performance_certification", 8, False),
    CertificationGate("rollback_recovery_scenarios", 7, True),
    CertificationGate("autonomous_resolution_scenarios", 5, False),
)


def certify_release(*, evidence: dict[str, Any]) -> dict[str, Any]:
    score = 0
    failures: list[str] = []
    critical_failures: list[str] = []
    missing: list[str] = []
    details: dict[str, Any] = {}

    for gate in GATES:
        value = evidence.get(gate.name)
        passed = False
        if isinstance(value, bool):
            passed = value
        elif isinstance(value, dict):
            passed = bool(value.get("passed") or value.get("certified") or value.get("valid"))
        elif isinstance(value, (int, float)):
            passed = float(value) >= 1.0
        elif value is None:
            missing.append(gate.name)
        details[gate.name] = {"passed": passed, "weight": gate.weight, "critical": gate.critical}
        if passed:
            score += gate.weight
        else:
            failures.append(gate.name)
            if gate.critical:
                critical_failures.append(gate.name)

    if critical_failures:
        decision = ReleaseDecision.NO_GO
    elif score >= 95:
        decision = ReleaseDecision.GO
    elif score >= 85:
        decision = ReleaseDecision.CONDITIONAL_GO
    else:
        decision = ReleaseDecision.NO_GO

    return {
        "decision": decision.value,
        "score": score,
        "max_score": sum(g.weight for g in GATES),
        "failures": failures,
        "critical_failures": critical_failures,
        "missing_evidence": missing,
        "gates": details,
        "autonomous_production_allowed": decision == ReleaseDecision.GO and not critical_failures,
    }
