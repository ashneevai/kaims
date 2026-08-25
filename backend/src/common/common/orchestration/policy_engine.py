from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from common.config import Settings, get_settings
from common.models import AlertSeverity
from common.orchestration.config_loader import load_orchestration_config


@dataclass(slots=True)
class PolicyDecision:
    risk_tier: str
    requires_approval: bool
    execution_mode: str
    reason: str


@dataclass(slots=True)
class PolicyEngine:
    settings: Settings = field(default_factory=get_settings)
    policies: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.policies:
            self.policies = load_orchestration_config(self.settings)

    def _risk_tier_for_severity(self, severity: AlertSeverity) -> str:
        risk_map = self.policies.get("risk_tiers_by_severity", {})
        if isinstance(risk_map, dict):
            mapped = str(risk_map.get(severity.value) or "").strip().lower()
            if mapped:
                return mapped
        if severity in {AlertSeverity.CRITICAL, AlertSeverity.HIGH}:
            return "high"
        if severity == AlertSeverity.WARNING:
            return "medium"
        return "low"

    def evaluate(self, *, severity: AlertSeverity, confidence: float | None = None) -> PolicyDecision:
        """Compatibility policy that fails closed before the full PDP/OPA migration.

        Incident severity remains only a compatibility input here. The next policy
        layer consumes the structured remediation plan, capability, target, blast
        radius, rollback/validation availability and authenticated identity. Until
        that richer decision is available, missing confidence and high risk require
        human approval instead of silently enabling guided/automatic execution.
        """
        risk_tier = self._risk_tier_for_severity(severity)
        if severity.value in self.policies.get("approval_severities", set()) or risk_tier == "high":
            return PolicyDecision(
                risk_tier=risk_tier,
                requires_approval=True,
                execution_mode="human-approval",
                reason="high-risk or severity policy requires human approval",
            )

        if confidence is None:
            return PolicyDecision(
                risk_tier=risk_tier,
                requires_approval=True,
                execution_mode="human-approval",
                reason="confidence unavailable; fail closed to human approval",
            )

        auto_threshold = float(self.policies.get("confidence_auto_execute_threshold", 0.9))
        guided_threshold = float(self.policies.get("confidence_guided_execute_threshold", 0.75))
        if guided_threshold > auto_threshold:
            guided_threshold = auto_threshold

        if confidence < guided_threshold:
            return PolicyDecision(
                risk_tier=risk_tier,
                requires_approval=True,
                execution_mode="human-approval",
                reason="confidence below guided threshold",
            )
        if confidence < auto_threshold:
            return PolicyDecision(
                risk_tier=risk_tier,
                requires_approval=True,
                execution_mode="human-approval",
                reason="guided confidence range remains HITL until structured policy migration is complete",
            )
        return PolicyDecision(
            risk_tier=risk_tier,
            requires_approval=False,
            execution_mode="auto-execute",
            reason="confidence above compatibility auto threshold and risk tier is not high",
        )

    def requires_approval(self, *, severity: AlertSeverity, confidence: float | None = None) -> bool:
        return self.evaluate(severity=severity, confidence=confidence).requires_approval
