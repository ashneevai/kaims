from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from ai_workbench_common.agentic import AgentContext, BaseAgent
from common.models import RemediationAction, ResolutionReport


class ValidationEvidenceProvider(Protocol):
    async def collect(self, action: RemediationAction) -> dict[str, Any]: ...


@dataclass(slots=True)
class NullValidationEvidenceProvider:
    """Fail closed when no live post-action validation provider is configured."""

    async def collect(self, action: RemediationAction) -> dict[str, Any]:
        return {
            "status": "VALIDATION_DATA_UNAVAILABLE",
            "evidence": [],
            "reason": "No live validation evidence provider is configured",
            "incident_id": str(action.incident_id),
        }


class ClosureValidationAgent(BaseAgent):
    name = "validation-agent"

    def __init__(self, provider: ValidationEvidenceProvider | None = None) -> None:
        self.provider = provider or NullValidationEvidenceProvider()

    async def can_execute(self, context: AgentContext) -> bool:
        return "remediation-action" in context.previous_agent_results

    async def execute(self, context: AgentContext) -> ResolutionReport:
        action_payload = context.previous_agent_results.get("remediation-action")
        if not isinstance(action_payload, dict):
            raise ValueError("AgentContext.previous_agent_results['remediation-action'] is required")
        report = await self.validate(RemediationAction.model_validate(action_payload))
        context.set_result(self.name, report.model_dump(mode="json"))
        return report

    async def validate(self, action: RemediationAction) -> ResolutionReport:
        """Validate recovery independently from executor success.

        A successful command/API call is only execution evidence. Recovery requires
        explicit live post-action evidence and all mandatory validation checks.
        """
        collected = await self.provider.collect(action)
        evidence = collected.get("evidence") if isinstance(collected.get("evidence"), list) else []
        checks = collected.get("checks") if isinstance(collected.get("checks"), dict) else {}
        status = str(collected.get("status") or "VALIDATION_DATA_UNAVAILABLE").strip().upper()

        required_checks = {
            "original_alert_cleared",
            "service_health_restored",
            "error_rate_recovered",
        }
        required_present = required_checks.issubset(checks.keys())
        required_passed = required_present and all(bool(checks.get(name)) for name in required_checks)
        has_live_evidence = bool(evidence) and status not in {
            "VALIDATION_DATA_UNAVAILABLE",
            "UNAVAILABLE",
            "SIMULATION",
        }
        restored = bool(
            has_live_evidence
            and required_passed
            and status in {"RECOVERED", "VALIDATION_SUCCEEDED"}
        )

        validation = {
            **checks,
            "validation_status": status,
            "evidence_count": len(evidence),
            "independent_validation": True,
            "required_checks_present": required_present,
        }
        action_taken = action.output or action.action_type
        reason = str(collected.get("reason") or "")

        if restored:
            knowledge_entry = (
                f"Incident {action.incident_id} recovery verified independently after {action.action_type}. "
                f"Validation evidence count={len(evidence)}."
            )
            lessons = ["Recovery was confirmed using independent post-action evidence."]
        else:
            knowledge_entry = (
                f"Incident {action.incident_id} remediation attempt is not verified as recovered. "
                f"Validation status={status}; evidence_count={len(evidence)}; reason={reason or 'none'}."
            )
            lessons = [
                "Execution success must not be treated as recovery.",
                "Collect live post-action telemetry before closure or positive learning.",
            ]

        return ResolutionReport(
            incident_id=action.incident_id,
            remediation_action_id=action.id,
            root_cause=action.parameters.get("root_cause", "Unconfirmed"),
            impact=action.parameters.get("impact", "Unconfirmed"),
            action_taken=action_taken,
            validation=validation,
            alerts_cleared=bool(checks.get("original_alert_cleared")) if has_live_evidence else False,
            health_restored=restored,
            knowledge_base_entry=knowledge_entry,
            lessons_learned=lessons,
        )
