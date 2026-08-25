from __future__ import annotations

from dataclasses import dataclass

from common.capability_registry import CapabilityDefinition
from common.resolution_models import RemediationPlan, RiskAssessment


_RISK_CLASS_SCORE = {
    "low": 0.15,
    "medium": 0.35,
    "high": 0.65,
    "critical": 0.90,
}


@dataclass(slots=True)
class RiskEngine:
    """Deterministic compatibility risk engine for structured remediation plans."""

    def assess(
        self,
        *,
        plan: RemediationPlan,
        capability: CapabilityDefinition,
        environment_criticality: float,
        target_criticality: float,
        blast_radius_fraction: float,
        previous_failure_risk: float = 0.0,
    ) -> RiskAssessment:
        capability_risk = _RISK_CLASS_SCORE.get(capability.risk_class.lower(), 0.75)
        rca_uncertainty = 1.0 - min(max(plan.rca_confidence, 0.0), 1.0)
        rollback_available = bool(plan.rollback_plan and plan.rollback_plan.available)
        rollback_difficulty = 0.15 if rollback_available else 0.85

        weighted = (
            (0.24 * capability_risk)
            + (0.16 * min(max(environment_criticality, 0.0), 1.0))
            + (0.18 * min(max(blast_radius_fraction, 0.0), 1.0))
            + (0.16 * rca_uncertainty)
            + (0.12 * min(max(target_criticality, 0.0), 1.0))
            + (0.08 * rollback_difficulty)
            + (0.06 * min(max(previous_failure_risk, 0.0), 1.0))
        )
        score = min(max(weighted, 0.0), 1.0)
        if score >= 0.75:
            risk_class = "critical"
        elif score >= 0.55:
            risk_class = "high"
        elif score >= 0.30:
            risk_class = "medium"
        else:
            risk_class = "low"

        reasons = [
            f"capability={capability.capability_id}:{capability.risk_class}",
            f"rca_uncertainty={rca_uncertainty:.2f}",
            f"blast_radius={blast_radius_fraction:.2f}",
            f"rollback_available={rollback_available}",
        ]
        return RiskAssessment(
            risk_score=score,
            risk_class=risk_class,
            capability_risk=capability_risk,
            environment_criticality=min(max(environment_criticality, 0.0), 1.0),
            blast_radius_risk=min(max(blast_radius_fraction, 0.0), 1.0),
            rca_uncertainty=rca_uncertainty,
            target_criticality=min(max(target_criticality, 0.0), 1.0),
            rollback_difficulty=rollback_difficulty,
            previous_failure_risk=min(max(previous_failure_risk, 0.0), 1.0),
            reasons=reasons,
        )
