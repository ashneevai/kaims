from __future__ import annotations

from collections.abc import Awaitable
from typing import Any

import pytest

from closure_service import ClosureValidationAgent
from common.models import RemediationAction
from common.resolution_models import ValidationCheck, ValidationOutcome, ValidationPlan


class SequenceValidationProvider:
    def __init__(self, windows: list[dict[str, Any]]) -> None:
        self.windows = windows
        self.calls: list[int] = []

    async def collect(
        self,
        action: RemediationAction,
        plan: ValidationPlan,
        window_index: int,
    ) -> dict[str, Any]:
        self.calls.append(window_index)
        return self.windows[min(window_index - 1, len(self.windows) - 1)]


class SleepRecorder:
    def __init__(self) -> None:
        self.calls: list[float] = []

    async def __call__(self, seconds: float) -> None:
        self.calls.append(seconds)


def _plan(*, required_successes: int = 3, stabilization: int = 60, interval: int = 30, max_window: int = 120) -> ValidationPlan:
    return ValidationPlan(
        stabilization_period_seconds=stabilization,
        validation_interval_seconds=interval,
        max_validation_window_seconds=max_window,
        required_consecutive_successes=required_successes,
        checks=[
            ValidationCheck(
                check_id="original_alert_cleared",
                provider="prometheus",
                signal="ALERTS{alertname='CheckoutHigh5xx'}",
                operator="==",
                expected_value=0,
                required=True,
            ),
            ValidationCheck(
                check_id="service_health_restored",
                provider="prometheus",
                signal="up{service='checkout'}",
                operator="==",
                expected_value=1,
                required=True,
            ),
            ValidationCheck(
                check_id="error_rate_recovered",
                provider="prometheus",
                signal="checkout_http_5xx_rate",
                operator="<",
                expected_value=0.01,
                required=True,
            ),
        ],
    )


def _action(plan: ValidationPlan | None = None) -> RemediationAction:
    parameters: dict[str, Any] = {
        "tenant_id": "tenant-a",
        "environment": "production",
        "root_cause": "bad deployment",
        "impact": "checkout errors",
    }
    if plan is not None:
        parameters["validation_plan"] = plan.model_dump(mode="json")
    return RemediationAction(
        incident_id="11111111-1111-1111-1111-111111111111",
        action_type="kubernetes.rollback_deployment",
        target="kai://workload/checkout",
        parameters=parameters,
        output="execution completed",
    )


def _window(
    *,
    alert: bool | None = True,
    health: bool | None = True,
    error_rate: bool | None = True,
    regression: bool = False,
    mode: str = "LIVE",
    evidence: bool = True,
) -> dict[str, Any]:
    values = {
        "original_alert_cleared": alert,
        "service_health_restored": health,
        "error_rate_recovered": error_rate,
    }
    observations = []
    evidence_rows = []
    for index, (check_id, passed) in enumerate(values.items(), start=1):
        if passed is None:
            continue
        evidence_id = f"evidence-{check_id}"
        observations.append(
            {
                "check_id": check_id,
                "provider": "prometheus",
                "mode": mode,
                "value": 1 if passed else 0,
                "passed": passed,
                "regression": regression and check_id == "error_rate_recovered",
                "evidence_id": evidence_id if evidence else None,
            }
        )
        if evidence:
            evidence_rows.append({"evidence_id": evidence_id})
    return {
        "status": "OBSERVED",
        "mode": mode,
        "provider": "prometheus",
        "observations": observations,
        "evidence": evidence_rows,
    }


@pytest.mark.asyncio
async def test_recovery_requires_stabilization_and_three_consecutive_healthy_windows() -> None:
    plan = _plan(required_successes=3, stabilization=60, interval=30, max_window=120)
    provider = SequenceValidationProvider([_window(), _window(), _window()])
    sleep = SleepRecorder()

    report = await ClosureValidationAgent(provider=provider, sleep=sleep).validate(_action(plan))

    assert report.health_restored is True
    assert report.alerts_cleared is True
    assert report.metadata["validation_outcome"] == ValidationOutcome.RECOVERED.value
    assert report.metadata["consecutive_successes_achieved"] == 3
    assert report.metadata["validation_windows_completed"] == 3
    assert provider.calls == [1, 2, 3]
    assert sleep.calls == [60.0, 30.0, 30.0]


@pytest.mark.asyncio
async def test_healthy_window_then_failure_resets_consecutive_success_count() -> None:
    plan = _plan(required_successes=2, stabilization=0, interval=10, max_window=40)
    provider = SequenceValidationProvider(
        [
            _window(),
            _window(error_rate=False),
            _window(),
            _window(),
        ]
    )
    sleep = SleepRecorder()

    report = await ClosureValidationAgent(provider=provider, sleep=sleep).validate(_action(plan))

    assert report.health_restored is True
    assert report.metadata["validation_outcome"] == ValidationOutcome.RECOVERED.value
    assert report.metadata["validation_windows_completed"] == 4
    assert report.metadata["consecutive_successes_achieved"] == 2
    assert sleep.calls == [10.0, 10.0, 10.0]


@pytest.mark.asyncio
async def test_partial_recovery_does_not_close_incident() -> None:
    plan = _plan(required_successes=2, stabilization=0, interval=10, max_window=20)
    provider = SequenceValidationProvider(
        [
            _window(error_rate=False),
            _window(error_rate=False),
        ]
    )

    report = await ClosureValidationAgent(provider=provider, sleep=SleepRecorder()).validate(_action(plan))

    assert report.health_restored is False
    assert report.metadata["validation_outcome"] == ValidationOutcome.PARTIALLY_RECOVERED.value
    assert report.metadata["validation_next_action"] == "REASSESS"
    assert report.validation["validation_succeeded"] is False


@pytest.mark.asyncio
async def test_regression_returns_worse_immediately_and_requests_rollback() -> None:
    plan = _plan(required_successes=3, stabilization=0, interval=10, max_window=50)
    provider = SequenceValidationProvider([_window(regression=True), _window(), _window()])
    sleep = SleepRecorder()

    report = await ClosureValidationAgent(provider=provider, sleep=sleep).validate(_action(plan))

    assert report.health_restored is False
    assert report.metadata["validation_outcome"] == ValidationOutcome.WORSE.value
    assert report.metadata["validation_next_action"] == "ROLLBACK_REQUIRED"
    assert report.validation["regression_detected"] is True
    assert provider.calls == [1]
    assert sleep.calls == []


@pytest.mark.asyncio
async def test_missing_required_check_is_inconclusive_not_recovered() -> None:
    plan = _plan(required_successes=1, stabilization=0, interval=10, max_window=10)
    provider = SequenceValidationProvider([_window(error_rate=None)])

    report = await ClosureValidationAgent(provider=provider, sleep=SleepRecorder()).validate(_action(plan))

    assert report.health_restored is False
    assert report.metadata["validation_outcome"] == ValidationOutcome.INCONCLUSIVE.value
    assert report.metadata["validation_next_action"] == "EXTEND_VALIDATION_OR_HITL"


@pytest.mark.asyncio
async def test_simulation_evidence_cannot_prove_production_recovery() -> None:
    plan = _plan(required_successes=1, stabilization=0, interval=10, max_window=10)
    provider = SequenceValidationProvider([_window(mode="SIMULATION")])

    report = await ClosureValidationAgent(provider=provider, sleep=SleepRecorder()).validate(_action(plan))

    assert report.health_restored is False
    assert report.metadata["validation_outcome"] == ValidationOutcome.VALIDATION_DATA_UNAVAILABLE.value
    assert report.validation["validation_data_available"] is False


@pytest.mark.asyncio
async def test_live_observations_without_provenance_cannot_prove_recovery() -> None:
    plan = _plan(required_successes=1, stabilization=0, interval=10, max_window=10)
    provider = SequenceValidationProvider([_window(evidence=False)])

    report = await ClosureValidationAgent(provider=provider, sleep=SleepRecorder()).validate(_action(plan))

    assert report.health_restored is False
    assert report.metadata["validation_outcome"] == ValidationOutcome.VALIDATION_DATA_UNAVAILABLE.value
    assert report.metadata["validation_evidence_count"] == 0


@pytest.mark.asyncio
async def test_missing_pre_execution_validation_plan_fails_closed_without_waiting() -> None:
    sleep = SleepRecorder()

    report = await ClosureValidationAgent(sleep=sleep).validate(_action())

    assert report.health_restored is False
    assert report.validation["validation_plan_present"] is False
    assert report.metadata["validation_outcome"] == ValidationOutcome.VALIDATION_DATA_UNAVAILABLE.value
    assert report.metadata["validation_next_action"] == "HOLD_OPEN_VALIDATION_PLAN_REQUIRED"
    assert "PLAN_MISSING" in report.metadata["validation_reason"]
    assert sleep.calls == []
