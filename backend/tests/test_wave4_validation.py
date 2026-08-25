from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest
from closure_service import ClosureValidationAgent
from common.models import RemediationAction, RemediationStatus
from common.resolution_models import ValidationCheck, ValidationPlan


async def _no_sleep(_: float) -> None:
    return None


@dataclass
class SequenceProvider:
    windows: list[dict[str, Any]]
    calls: int = 0

    async def collect(
        self,
        action: RemediationAction,
        plan: ValidationPlan,
        window_index: int,
    ) -> dict[str, Any]:
        del action, plan
        self.calls += 1
        return self.windows[min(window_index - 1, len(self.windows) - 1)]


def _plan(*, consecutive: int = 2, max_window: int = 3) -> ValidationPlan:
    return ValidationPlan(
        stabilization_period_seconds=0,
        validation_interval_seconds=1,
        max_validation_window_seconds=max_window,
        required_consecutive_successes=consecutive,
        checks=[
            ValidationCheck(
                check_id="original_alert_cleared",
                provider="prometheus",
                signal='ALERTS{alertname="CheckoutFailure",alertstate="firing"}',
                operator="==",
                expected_value=0,
            ),
            ValidationCheck(
                check_id="service_health_restored",
                provider="prometheus",
                signal='up{service="checkout"}',
                operator="==",
                expected_value=1,
            ),
            ValidationCheck(
                check_id="checkout_slo_recovered",
                provider="prometheus",
                signal='checkout:error_rate:ratio5m',
                operator="<",
                expected_value=0.01,
            ),
        ],
    )


def _action(plan: ValidationPlan, *, status: RemediationStatus = RemediationStatus.SUCCEEDED) -> RemediationAction:
    return RemediationAction(
        incident_id="11111111-1111-1111-1111-111111111111",
        action_type="kubernetes.rollback_deployment",
        target="kai://workload/checkout",
        status=status,
        metadata={"validation_plan": plan.model_dump(mode="json"), "tenant_id": "tenant-a"},
    )


def _window(*, alert: bool, health: bool, slo: bool, regression: bool = False) -> dict[str, Any]:
    values = {
        "original_alert_cleared": alert,
        "service_health_restored": health,
        "checkout_slo_recovered": slo,
    }
    observations = []
    evidence = []
    for check_id, passed in values.items():
        evidence_id = f"evidence:{check_id}:{int(passed)}"
        observations.append(
            {
                "check_id": check_id,
                "provider": "prometheus",
                "mode": "LIVE",
                "passed": passed,
                "regression": regression and check_id == "checkout_slo_recovered",
                "evidence_id": evidence_id,
            }
        )
        evidence.append({"evidence_id": evidence_id})
    return {
        "status": "OBSERVED",
        "mode": "LIVE",
        "provider": "prometheus",
        "observations": observations,
        "evidence": evidence,
    }


@pytest.mark.asyncio
async def test_recovery_requires_consecutive_healthy_windows() -> None:
    plan = _plan(consecutive=2, max_window=3)
    provider = SequenceProvider([_window(alert=True, health=True, slo=True)] * 2)

    report = await ClosureValidationAgent(provider=provider, sleep=_no_sleep).validate(_action(plan))

    assert report.health_restored is True
    assert report.metadata["validation_outcome"] == "RECOVERED"
    assert report.metadata["consecutive_successes_achieved"] == 2
    assert provider.calls == 2


@pytest.mark.asyncio
async def test_successful_execution_with_active_alert_is_not_recovered() -> None:
    plan = _plan(consecutive=1, max_window=1)
    provider = SequenceProvider([_window(alert=False, health=True, slo=True)])

    report = await ClosureValidationAgent(provider=provider, sleep=_no_sleep).validate(_action(plan))

    assert report.health_restored is False
    assert report.metadata["validation_outcome"] == "PARTIALLY_RECOVERED"


@pytest.mark.asyncio
async def test_successful_execution_with_slo_breach_is_not_recovered() -> None:
    plan = _plan(consecutive=1, max_window=1)
    provider = SequenceProvider([_window(alert=True, health=True, slo=False)])

    report = await ClosureValidationAgent(provider=provider, sleep=_no_sleep).validate(_action(plan))

    assert report.health_restored is False
    assert report.metadata["validation_outcome"] == "PARTIALLY_RECOVERED"


@pytest.mark.asyncio
async def test_worsening_telemetry_requires_rollback() -> None:
    plan = _plan(consecutive=2, max_window=3)
    provider = SequenceProvider([_window(alert=False, health=False, slo=False, regression=True)])

    report = await ClosureValidationAgent(provider=provider, sleep=_no_sleep).validate(_action(plan))

    assert report.health_restored is False
    assert report.metadata["validation_outcome"] == "WORSE"
    assert report.metadata["validation_next_action"] == "ROLLBACK_REQUIRED"
    assert provider.calls == 1


@pytest.mark.asyncio
async def test_execution_failure_can_still_be_independently_recovered() -> None:
    plan = _plan(consecutive=1, max_window=1)
    provider = SequenceProvider([_window(alert=True, health=True, slo=True)])

    report = await ClosureValidationAgent(provider=provider, sleep=_no_sleep).validate(
        _action(plan, status=RemediationStatus.FAILED)
    )

    assert report.health_restored is True
    assert report.metadata["validation_outcome"] == "RECOVERED"


@pytest.mark.asyncio
async def test_missing_validation_evidence_never_claims_recovery() -> None:
    plan = _plan(consecutive=1, max_window=1)
    provider = SequenceProvider(
        [
            {
                "status": "VALIDATION_DATA_UNAVAILABLE",
                "mode": "UNAVAILABLE",
                "evidence": [],
                "observations": [],
            }
        ]
    )

    report = await ClosureValidationAgent(provider=provider, sleep=_no_sleep).validate(_action(plan))

    assert report.health_restored is False
    assert report.metadata["validation_outcome"] == "VALIDATION_DATA_UNAVAILABLE"
    assert report.validation["validation_data_available"] is False


@pytest.mark.asyncio
async def test_healthy_window_then_failure_resets_consecutive_success() -> None:
    plan = _plan(consecutive=2, max_window=3)
    provider = SequenceProvider(
        [
            _window(alert=True, health=True, slo=True),
            _window(alert=True, health=False, slo=True),
            _window(alert=True, health=True, slo=True),
        ]
    )

    report = await ClosureValidationAgent(provider=provider, sleep=_no_sleep).validate(_action(plan))

    assert report.health_restored is False
    assert report.metadata["validation_outcome"] == "PARTIALLY_RECOVERED"
    assert report.metadata["consecutive_successes_achieved"] == 1


@pytest.mark.asyncio
async def test_missing_pre_execution_validation_plan_fails_closed() -> None:
    action = RemediationAction(
        incident_id="11111111-1111-1111-1111-111111111111",
        action_type="kubernetes.rollback_deployment",
        target="kai://workload/checkout",
        status=RemediationStatus.SUCCEEDED,
    )

    report = await ClosureValidationAgent(sleep=_no_sleep).validate(action)

    assert report.health_restored is False
    assert report.metadata["validation_outcome"] == "VALIDATION_DATA_UNAVAILABLE"
    assert report.metadata["validation_reason"].startswith("PLAN_MISSING")
