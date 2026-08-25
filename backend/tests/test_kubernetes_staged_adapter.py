from __future__ import annotations

from uuid import uuid4

import pytest

from common.models import RemediationAction, RemediationStatus
from remediation_engine.kubernetes_staged import KubernetesNativeStagedPlugin
from remediation_engine.staged_executor import NativeStagedExecutor


def _action() -> RemediationAction:
    return RemediationAction(
        incident_id=uuid4(),
        action_type="restart_pod",
        target="orders",
        status=RemediationStatus.RUNNING,
        parameters={
            "environment": "prod",
            "execution_strategy": "CANARY",
            "execution_stages": [
                {"name": "canary-5", "percent": 5, "requires_health_gate": True},
                {"name": "canary-25", "percent": 25, "requires_health_gate": True},
                {"name": "full", "percent": 100, "requires_health_gate": True},
            ],
            "kubernetes_staged": {
                "enabled": True,
                "context": "prod-us-east",
                "namespace": "orders-prod",
                "operation": "rollout_restart",
                "stage_targets": {
                    "canary-5": ["orders-canary-a"],
                    "canary-25": ["orders-canary-a", "orders-canary-b"],
                    "full": ["orders"],
                },
            },
        },
    )


@pytest.mark.asyncio
async def test_native_kubernetes_executes_explicit_targets_per_stage() -> None:
    calls: list[list[str]] = []

    async def runner(command: list[str], _: float) -> tuple[int, str, str]:
        calls.append(command)
        return 0, "ok", ""

    async def observer(action: RemediationAction, stage: dict) -> dict:
        return {
            "mode": "LIVE",
            "evidence_ids": [f"prometheus:orders:{stage['name']}"],
            "required_checks": {"availability": True, "error_rate": True},
        }

    plugin = KubernetesNativeStagedPlugin(command_runner=runner, health_observer=observer)
    result = await NativeStagedExecutor().execute(plugin=plugin, action=_action())

    assert result.aborted is False
    assert result.completed_stages == 3
    assert result.action.status == RemediationStatus.SUCCEEDED
    assert [command[-1] for command in calls] == [
        "deployment/orders-canary-a",
        "deployment/orders-canary-a",
        "deployment/orders-canary-b",
        "deployment/orders",
    ]
    assert all(command[1:5] == ["--context", "prod-us-east", "-n", "orders-prod"] for command in calls)


@pytest.mark.asyncio
async def test_kubernetes_stage_regression_aborts_before_next_stage() -> None:
    calls: list[list[str]] = []
    observations = 0

    async def runner(command: list[str], _: float) -> tuple[int, str, str]:
        calls.append(command)
        return 0, "ok", ""

    async def observer(action: RemediationAction, stage: dict) -> dict:
        nonlocal observations
        observations += 1
        return {
            "mode": "LIVE",
            "evidence_ids": [f"prometheus:orders:{stage['name']}"],
            "required_checks": {"availability": False},
            "error_rate_regression": True,
        }

    plugin = KubernetesNativeStagedPlugin(command_runner=runner, health_observer=observer)
    result = await NativeStagedExecutor().execute(plugin=plugin, action=_action())

    assert result.aborted is True
    assert result.completed_stages == 0
    assert observations == 1
    assert len(calls) == 1
    assert result.action.status == RemediationStatus.FAILED
    assert result.action.parameters["kubernetes_stage_abort"]["automatic_rollback_performed"] is False


@pytest.mark.asyncio
async def test_kubernetes_staging_requires_explicit_cluster_scope() -> None:
    action = _action()
    action.parameters["kubernetes_staged"]["context"] = ""

    plugin = KubernetesNativeStagedPlugin()
    result = await NativeStagedExecutor().execute(plugin=plugin, action=action)

    assert result.completed_stages == 0
    assert result.action.status == RemediationStatus.SKIPPED
    assert "explicit context and namespace" in str(result.action.error)


@pytest.mark.asyncio
async def test_kubernetes_staging_never_infers_missing_stage_targets() -> None:
    action = _action()
    action.parameters["kubernetes_staged"]["stage_targets"].pop("canary-25")

    async def runner(command: list[str], _: float) -> tuple[int, str, str]:
        return 0, "ok", ""

    async def observer(action: RemediationAction, stage: dict) -> dict:
        return {
            "mode": "LIVE",
            "evidence_ids": [f"prometheus:orders:{stage['name']}"],
            "required_checks": {"availability": True},
        }

    plugin = KubernetesNativeStagedPlugin(command_runner=runner, health_observer=observer)
    result = await NativeStagedExecutor().execute(plugin=plugin, action=action)

    assert result.aborted is True
    assert result.completed_stages == 1
    assert result.action.status == RemediationStatus.FAILED
    assert "KUBERNETES_STAGE_TARGETS_EMPTY" in str(result.action.error)
