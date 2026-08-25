from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from ai_workbench_common.agentic import AgentContext, BaseAgent
from common.models import RemediationAction, ResolutionReport
from common.resolution_models import ValidationOutcome, ValidationPlan
from common.validation_models import ValidationAssessment

from closure_service.engine import NullValidationEvidenceProvider, ValidationEngine, ValidationEvidenceProvider


class ClosureValidationAgent(BaseAgent):
    name = "validation-agent"

    def __init__(
        self,
        provider: ValidationEvidenceProvider | None = None,
        *,
        sleep: Callable[[float], Awaitable[None]] | None = None,
    ) -> None:
        engine_kwargs: dict[str, Any] = {"provider": provider or NullValidationEvidenceProvider()}
        if sleep is not None:
            engine_kwargs["sleep"] = sleep
        self.engine = ValidationEngine(**engine_kwargs)

    async def can_execute(self, context: AgentContext) -> bool:
        return "remediation-action" in context.previous_agent_results

    async def execute(self, context: AgentContext) -> ResolutionReport:
        action_payload = context.previous_agent_results.get("remediation-action")
        if not isinstance(action_payload, dict):
            raise ValueError("AgentContext.previous_agent_results['remediation-action'] is required")
        report = await self.validate(RemediationAction.model_validate(action_payload))
        context.set_result(self.name, report.model_dump(mode="json"))
        return report

    @staticmethod
    def _extract_validation_plan(action: RemediationAction) -> ValidationPlan | None:
        metadata = action.metadata if isinstance(action.metadata, dict) else {}
        candidates: list[Any] = [
            metadata.get("validation_plan"),
            action.parameters.get("validation_plan"),
        ]
        for container in (metadata.get("remediation_plan"), action.parameters.get("remediation_plan")):
            if isinstance(container, dict):
                candidates.append(container.get("validation_plan"))
        for candidate in candidates:
            if isinstance(candidate, dict):
                return ValidationPlan.model_validate(candidate)
        return None

    @staticmethod
    def _tenant_id(action: RemediationAction) -> str | None:
        metadata = action.metadata if isinstance(action.metadata, dict) else {}
        value = action.parameters.get("tenant_id") or metadata.get("tenant_id")
        return str(value).strip() if value else None

    async def validate(self, action: RemediationAction) -> ResolutionReport:
        """Independently prove recovery using a pre-existing validation plan.

        Execution success is never used as proof of recovery. Missing plans, missing
        evidence, simulation-only evidence, and incomplete mandatory checks all fail
        closed and leave the incident open for further workflow handling.
        """
        plan = self._extract_validation_plan(action)
        plan_missing = plan is None
        plan = plan or ValidationPlan(checks=[])
        assessment = await self.engine.validate(action, plan, tenant_id=self._tenant_id(action))
        if plan_missing:
            assessment = assessment.model_copy(
                update={
                    "validation_plan_id": None,
                    "reason": "PLAN_MISSING: remediation did not carry a pre-execution ValidationPlan",
                    "next_action": "HOLD_OPEN_VALIDATION_PLAN_REQUIRED",
                }
            )
        return self._build_report(action, assessment, plan_missing=plan_missing)

    @staticmethod
    def _build_report(
        action: RemediationAction,
        assessment: ValidationAssessment,
        *,
        plan_missing: bool,
    ) -> ResolutionReport:
        recovered = assessment.outcome == ValidationOutcome.RECOVERED
        windows_with_data = sum(1 for window in assessment.windows if window.data_available)
        observations = [
            observation
            for window in assessment.windows
            for observation in window.observations
        ]
        alert_observations = [
            observation
            for observation in observations
            if "alert" in observation.check_id.lower()
        ]
        alerts_cleared = bool(
            recovered
            and alert_observations
            and all(observation.passed is True for observation in alert_observations)
        )

        validation = {
            "independent_validation": True,
            "validation_plan_present": not plan_missing,
            "validation_data_available": windows_with_data > 0,
            "required_consecutive_windows_met": (
                assessment.consecutive_successes_achieved >= assessment.required_consecutive_successes
            ),
            "validation_succeeded": recovered,
            "regression_detected": assessment.outcome == ValidationOutcome.WORSE,
        }
        action_taken = action.output or action.action_type

        if recovered:
            knowledge_entry = (
                f"Incident {action.incident_id} recovery independently verified after {action.action_type}; "
                f"healthy_windows={assessment.consecutive_successes_achieved}, "
                f"evidence_count={len(assessment.evidence_ids)}."
            )
            lessons = ["Recovery was confirmed using independent multi-window post-action evidence."]
        else:
            knowledge_entry = (
                f"Incident {action.incident_id} is not verified as recovered. "
                f"Validation outcome={assessment.outcome.value}; reason={assessment.reason}."
            )
            lessons = [
                "Execution success must not be treated as recovery.",
                "Only independently verified consecutive healthy windows may close an incident automatically.",
            ]

        return ResolutionReport(
            incident_id=action.incident_id,
            remediation_action_id=action.id,
            root_cause=action.parameters.get("root_cause", "Unconfirmed"),
            impact=action.parameters.get("impact", "Unconfirmed"),
            action_taken=action_taken,
            validation=validation,
            alerts_cleared=alerts_cleared,
            health_restored=recovered,
            knowledge_base_entry=knowledge_entry,
            lessons_learned=lessons,
            metadata={
                "validation_status": assessment.outcome.value,
                "validation_outcome": assessment.outcome.value,
                "validation_reason": assessment.reason,
                "validation_next_action": assessment.next_action,
                "validation_assessment": assessment.model_dump(mode="json"),
                "validation_evidence_count": len(assessment.evidence_ids),
                "validation_evidence_ids": assessment.evidence_ids,
                "validation_windows_completed": len(assessment.windows),
                "validation_windows_with_data": windows_with_data,
                "required_consecutive_successes": assessment.required_consecutive_successes,
                "consecutive_successes_achieved": assessment.consecutive_successes_achieved,
            },
        )
