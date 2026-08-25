from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, Protocol

from common.models import RemediationAction
from common.resolution_models import EvidenceMode, ValidationOutcome, ValidationPlan
from common.validation_models import ValidationAssessment, ValidationObservation, ValidationWindowResult


class ValidationEvidenceProvider(Protocol):
    async def collect(
        self,
        action: RemediationAction,
        plan: ValidationPlan,
        window_index: int,
    ) -> dict[str, Any]: ...


@dataclass(slots=True)
class NullValidationEvidenceProvider:
    """Fail closed when no live post-action validation provider is configured."""

    async def collect(
        self,
        action: RemediationAction,
        plan: ValidationPlan,
        window_index: int,
    ) -> dict[str, Any]:
        return {
            "status": ValidationOutcome.VALIDATION_DATA_UNAVAILABLE.value,
            "mode": EvidenceMode.UNAVAILABLE.value,
            "evidence": [],
            "observations": [],
            "reason": "No live validation evidence provider is configured",
            "incident_id": str(action.incident_id),
            "validation_plan_id": str(plan.plan_id),
            "window_index": window_index,
        }


SleepFn = Callable[[float], Awaitable[None]]


@dataclass(slots=True)
class ValidationEngine:
    provider: ValidationEvidenceProvider
    sleep: SleepFn = asyncio.sleep

    async def validate(self, action: RemediationAction, plan: ValidationPlan, *, tenant_id: str | None = None) -> ValidationAssessment:
        if not plan.checks:
            return self._assessment(
                action=action,
                plan=plan,
                tenant_id=tenant_id,
                outcome=ValidationOutcome.VALIDATION_DATA_UNAVAILABLE,
                windows=[],
                consecutive=0,
                reason="Validation plan has no checks; recovery cannot be proven",
            )

        if plan.stabilization_period_seconds:
            await self.sleep(float(plan.stabilization_period_seconds))

        max_windows = max(1, plan.max_validation_window_seconds // plan.validation_interval_seconds)
        windows: list[ValidationWindowResult] = []
        consecutive = 0
        best_outcome = ValidationOutcome.INCONCLUSIVE

        for window_index in range(1, max_windows + 1):
            collected = await self.provider.collect(action, plan, window_index)
            window = self._evaluate_window(plan, window_index, collected)
            windows.append(window)

            if window.status == ValidationOutcome.WORSE:
                return self._assessment(
                    action=action,
                    plan=plan,
                    tenant_id=tenant_id,
                    outcome=ValidationOutcome.WORSE,
                    windows=windows,
                    consecutive=0,
                    reason="Post-action validation detected a regression",
                )

            if window.status == ValidationOutcome.VALIDATION_DATA_UNAVAILABLE:
                consecutive = 0
                best_outcome = ValidationOutcome.VALIDATION_DATA_UNAVAILABLE
            elif window.all_required_passed:
                consecutive += 1
                best_outcome = ValidationOutcome.RECOVERED
                if consecutive >= plan.required_consecutive_successes:
                    return self._assessment(
                        action=action,
                        plan=plan,
                        tenant_id=tenant_id,
                        outcome=ValidationOutcome.RECOVERED,
                        windows=windows,
                        consecutive=consecutive,
                        reason=(
                            f"Recovery independently verified across {consecutive} consecutive validation windows"
                        ),
                    )
            else:
                consecutive = 0
                best_outcome = self._prefer_non_recovered(best_outcome, window.status)

            if window_index < max_windows:
                await self.sleep(float(plan.validation_interval_seconds))

        final_outcome = self._final_outcome(windows, best_outcome)
        return self._assessment(
            action=action,
            plan=plan,
            tenant_id=tenant_id,
            outcome=final_outcome,
            windows=windows,
            consecutive=consecutive,
            reason=self._final_reason(final_outcome, plan, consecutive),
        )

    @staticmethod
    def _evaluate_window(
        plan: ValidationPlan,
        window_index: int,
        collected: dict[str, Any],
    ) -> ValidationWindowResult:
        provider_mode = str(collected.get("mode") or EvidenceMode.LIVE.value).upper()
        try:
            default_mode = EvidenceMode(provider_mode)
        except ValueError:
            default_mode = EvidenceMode.UNAVAILABLE

        raw_observations = collected.get("observations")
        observations: list[ValidationObservation] = []
        if isinstance(raw_observations, list):
            for raw in raw_observations:
                if not isinstance(raw, dict):
                    continue
                payload = dict(raw)
                payload.setdefault("provider", str(collected.get("provider") or "unknown"))
                payload.setdefault("mode", default_mode.value)
                observations.append(ValidationObservation.model_validate(payload))

        legacy_checks = collected.get("checks")
        evidence = collected.get("evidence") if isinstance(collected.get("evidence"), list) else []
        if not observations and isinstance(legacy_checks, dict):
            for check in plan.checks:
                if check.check_id not in legacy_checks:
                    continue
                raw_value = legacy_checks[check.check_id]
                passed = bool(raw_value.get("passed")) if isinstance(raw_value, dict) else bool(raw_value)
                regression = bool(raw_value.get("regression")) if isinstance(raw_value, dict) else False
                observations.append(
                    ValidationObservation(
                        check_id=check.check_id,
                        provider=check.provider,
                        resource_id=check.resource_id,
                        mode=default_mode,
                        value=raw_value.get("value") if isinstance(raw_value, dict) else raw_value,
                        baseline_value=raw_value.get("baseline_value") if isinstance(raw_value, dict) else None,
                        passed=passed,
                        regression=regression,
                        evidence_id=(str(evidence[0].get("evidence_id")) if evidence and isinstance(evidence[0], dict) and evidence[0].get("evidence_id") else None),
                    )
                )

        usable = [observation for observation in observations if observation.usable_for_production_validation]
        by_check = {observation.check_id: observation for observation in usable}
        required = [check for check in plan.checks if check.required]
        required_present = [check for check in required if check.check_id in by_check]
        required_passed = [check for check in required_present if by_check[check.check_id].passed is True]
        any_regression = any(observation.regression for observation in usable)
        data_available = bool(usable) and bool(evidence or any(observation.evidence_id for observation in usable))

        explicit_status = str(collected.get("status") or "").upper()
        if any_regression or explicit_status == ValidationOutcome.WORSE.value:
            status = ValidationOutcome.WORSE
        elif not data_available:
            status = ValidationOutcome.VALIDATION_DATA_UNAVAILABLE
        elif len(required_present) != len(required):
            status = ValidationOutcome.INCONCLUSIVE
        elif len(required_passed) == len(required) and required:
            status = ValidationOutcome.RECOVERED
        elif required_passed:
            status = ValidationOutcome.PARTIALLY_RECOVERED
        else:
            status = ValidationOutcome.UNCHANGED

        return ValidationWindowResult(
            window_index=window_index,
            observations=observations,
            required_checks=len(required),
            required_passed=len(required_passed),
            all_required_passed=bool(required) and len(required_passed) == len(required),
            any_regression=any_regression,
            data_available=data_available,
            status=status,
        )

    @staticmethod
    def _prefer_non_recovered(current: ValidationOutcome, candidate: ValidationOutcome) -> ValidationOutcome:
        priority = {
            ValidationOutcome.VALIDATION_DATA_UNAVAILABLE: 0,
            ValidationOutcome.INCONCLUSIVE: 1,
            ValidationOutcome.UNCHANGED: 2,
            ValidationOutcome.PARTIALLY_RECOVERED: 3,
            ValidationOutcome.RECOVERED: 4,
            ValidationOutcome.WORSE: 5,
        }
        return candidate if priority[candidate] >= priority[current] else current

    @staticmethod
    def _final_outcome(
        windows: list[ValidationWindowResult],
        best_outcome: ValidationOutcome,
    ) -> ValidationOutcome:
        if not windows or all(not window.data_available for window in windows):
            return ValidationOutcome.VALIDATION_DATA_UNAVAILABLE
        if any(window.status == ValidationOutcome.WORSE for window in windows):
            return ValidationOutcome.WORSE
        if any(window.status == ValidationOutcome.PARTIALLY_RECOVERED for window in windows):
            return ValidationOutcome.PARTIALLY_RECOVERED
        if all(window.status == ValidationOutcome.UNCHANGED for window in windows if window.data_available):
            return ValidationOutcome.UNCHANGED
        if best_outcome == ValidationOutcome.RECOVERED:
            return ValidationOutcome.INCONCLUSIVE
        return best_outcome

    @staticmethod
    def _next_action(outcome: ValidationOutcome) -> str:
        return {
            ValidationOutcome.RECOVERED: "CLOSE",
            ValidationOutcome.PARTIALLY_RECOVERED: "REASSESS",
            ValidationOutcome.UNCHANGED: "REINVESTIGATE",
            ValidationOutcome.WORSE: "ROLLBACK_REQUIRED",
            ValidationOutcome.INCONCLUSIVE: "EXTEND_VALIDATION_OR_HITL",
            ValidationOutcome.VALIDATION_DATA_UNAVAILABLE: "HOLD_OPEN_TELEMETRY_REQUIRED",
        }[outcome]

    @classmethod
    def _assessment(
        cls,
        *,
        action: RemediationAction,
        plan: ValidationPlan,
        tenant_id: str | None,
        outcome: ValidationOutcome,
        windows: list[ValidationWindowResult],
        consecutive: int,
        reason: str,
    ) -> ValidationAssessment:
        evidence_ids = sorted(
            {
                observation.evidence_id
                for window in windows
                for observation in window.observations
                if observation.evidence_id
            }
        )
        return ValidationAssessment(
            tenant_id=tenant_id,
            incident_id=action.incident_id,
            remediation_action_id=action.id,
            validation_plan_id=plan.plan_id,
            outcome=outcome,
            stabilization_period_seconds=plan.stabilization_period_seconds,
            validation_interval_seconds=plan.validation_interval_seconds,
            required_consecutive_successes=plan.required_consecutive_successes,
            consecutive_successes_achieved=consecutive,
            windows=windows,
            evidence_ids=evidence_ids,
            reason=reason,
            next_action=cls._next_action(outcome),
        )

    @staticmethod
    def _final_reason(outcome: ValidationOutcome, plan: ValidationPlan, consecutive: int) -> str:
        if outcome == ValidationOutcome.INCONCLUSIVE:
            return (
                "Healthy observations were seen but the required consecutive-window threshold was not met; "
                f"achieved={consecutive}, required={plan.required_consecutive_successes}"
            )
        return {
            ValidationOutcome.PARTIALLY_RECOVERED: "Some required recovery checks passed while others remain unhealthy",
            ValidationOutcome.UNCHANGED: "Live validation evidence shows no required recovery checks have recovered",
            ValidationOutcome.WORSE: "Live validation evidence shows post-action regression",
            ValidationOutcome.VALIDATION_DATA_UNAVAILABLE: "Independent live validation evidence is unavailable",
            ValidationOutcome.RECOVERED: "Recovery independently verified",
        }[outcome]
