from __future__ import annotations

from uuid import uuid4

import pytest

from common.models import RemediationAction, RemediationStatus
from remediation_engine.staged_executor import NativeStagedExecutor


class FakeNativePlugin:
    action_type = "restart_pod"

    def __init__(self, observations: list[dict]) -> None:
        self.observations = observations
        self.executed: list[int] = []
        self.aborted: list[int] = []
        self.finalized = False

    async def prepare(self, action: RemediationAction) -> RemediationAction:
        action.status = RemediationStatus.RUNNING
        action.parameters["prepared"] = True
        return action

    async def execute_stage(self, action: RemediationAction, *, stage_index: int, stage: dict) -> RemediationAction:
        self.executed.append(stage_index)
        action.status = RemediationStatus.RUNNING
        return action

    async def observe_stage(self, action: RemediationAction, *, stage_index: int, stage: dict) -> dict:
        return self.observations[stage_index]

    async def abort(self, action: RemediationAction, *, stage_index: int, stage: dict, reason: str) -> RemediationAction:
        self.aborted.append(stage_index)
        action.parameters["abort_reason"] = reason
        return action

    async def finalize(self, action: RemediationAction) -> RemediationAction:
        self.finalized = True
        action.status = RemediationStatus.SUCCEEDED
        return action


class LegacyPlugin:
    action_type = "restart_pod"

    async def execute(self, action: RemediationAction) -> RemediationAction:
        action.status = RemediationStatus.SUCCEEDED
        return action


def _action() -> RemediationAction:
    return RemediationAction(
        incident_id=uuid4(),
        action_type="restart_pod",
        target="orders-api",
        parameters={
            "execution_strategy": "CANARY",
            "execution_stages": [
                {"name": "canary-5", "percent": 5, "requires_health_gate": True},
                {"name": "canary-25", "percent": 25, "requires_health_gate": True},
                {"name": "canary-100", "percent": 100, "requires_health_gate": True},
            ],
        },
    )


def _healthy(stage: int) -> dict:
    return {
        "mode": "LIVE",
        "evidence_ids": [f"metric:{stage}"],
        "required_checks": {"error_rate": True, "availability": True},
        "new_critical_alert": False,
        "error_rate_regression": False,
        "dependency_regression": False,
        "slo_regression": False,
        "data_loss_signal": False,
    }


@pytest.mark.asyncio
async def test_executes_all_native_stages_and_finalizes() -> None:
    plugin = FakeNativePlugin([_healthy(0), _healthy(1), _healthy(2)])
    result = await NativeStagedExecutor().execute(plugin=plugin, action=_action())

    assert result.action.status == RemediationStatus.SUCCEEDED
    assert result.completed_stages == 3
    assert result.aborted is False
    assert plugin.executed == [0, 1, 2]
    assert plugin.finalized is True
    assert result.action.parameters["staged_execution_completed"] is True


@pytest.mark.asyncio
async def test_aborts_on_stage_regression_and_never_executes_later_stage() -> None:
    regression = _healthy(1)
    regression["error_rate_regression"] = True
    plugin = FakeNativePlugin([_healthy(0), regression, _healthy(2)])

    result = await NativeStagedExecutor().execute(plugin=plugin, action=_action())

    assert result.aborted is True
    assert result.action.status == RemediationStatus.FAILED
    assert plugin.executed == [0, 1]
    assert plugin.aborted == [1]
    assert plugin.finalized is False


@pytest.mark.asyncio
async def test_holds_when_health_evidence_has_no_provenance() -> None:
    missing = _healthy(0)
    missing["evidence_ids"] = []
    plugin = FakeNativePlugin([missing, _healthy(1), _healthy(2)])

    result = await NativeStagedExecutor().execute(plugin=plugin, action=_action())

    assert result.aborted is True
    assert result.action.status == RemediationStatus.SKIPPED
    assert plugin.executed == [0]
    assert plugin.aborted == [0]


@pytest.mark.asyncio
async def test_legacy_plugin_cannot_fake_canary_execution() -> None:
    result = await NativeStagedExecutor().execute(plugin=LegacyPlugin(), action=_action())

    assert result.action.status == RemediationStatus.SKIPPED
    assert result.action.error == "NATIVE_STAGED_EXECUTOR_UNAVAILABLE"
    assert result.action.parameters["staged_execution_blocked"] is True
