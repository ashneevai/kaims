from __future__ import annotations

from uuid import uuid4

import pytest

from common.models import RemediationAction, RemediationStatus
from remediation_engine.jenkins_staged import JenkinsNativeStagedPlugin
from remediation_engine.staged_executor import NativeStagedExecutor


def _action() -> RemediationAction:
    return RemediationAction(
        incident_id=uuid4(),
        action_type="rollback_deployment",
        target="orders",
        status=RemediationStatus.RUNNING,
        parameters={
            "execution_strategy": "CANARY",
            "execution_stages": [
                {"name": "canary-5", "percent": 5, "requires_health_gate": True},
                {"name": "canary-25", "percent": 25, "requires_health_gate": True},
                {"name": "full", "percent": 100, "requires_health_gate": True},
            ],
            "jenkins_staged": {
                "enabled": True,
                "base_url": "https://jenkins.example",
                "job": "orders-rollback",
                "stage_targets": {
                    "canary-5": ["orders-canary-a"],
                    "canary-25": ["orders-canary-a", "orders-canary-b"],
                    "full": ["orders"],
                },
            },
        },
    )


@pytest.mark.asyncio
async def test_jenkins_executes_explicit_targets_stage_by_stage() -> None:
    calls: list[tuple[str, list[str]]] = []

    async def trigger(action, stage, targets):
        calls.append((str(stage["name"]), list(targets)))
        return {"ok": True, "queue_url": "queue://1"}

    async def health(action, stage):
        return {
            "mode": "LIVE",
            "evidence_ids": [f"jenkins:{stage['name']}"],
            "required_checks": {"job_success": True, "service_health": True},
        }

    plugin = JenkinsNativeStagedPlugin(trigger=trigger, health_observer=health)
    result = await NativeStagedExecutor().execute(plugin=plugin, action=_action())
    assert result.action.status == RemediationStatus.SUCCEEDED
    assert calls == [
        ("canary-5", ["orders-canary-a"]),
        ("canary-25", ["orders-canary-a", "orders-canary-b"]),
        ("full", ["orders"]),
    ]


@pytest.mark.asyncio
async def test_jenkins_regression_aborts_before_next_stage() -> None:
    calls: list[str] = []

    async def trigger(action, stage, targets):
        calls.append(str(stage["name"]))
        return {"ok": True}

    async def health(action, stage):
        return {
            "mode": "LIVE",
            "evidence_ids": ["jenkins:evidence"],
            "required_checks": {"job_success": True},
            "slo_regression": stage["name"] == "canary-5",
        }

    plugin = JenkinsNativeStagedPlugin(trigger=trigger, health_observer=health)
    result = await NativeStagedExecutor().execute(plugin=plugin, action=_action())
    assert result.aborted is True
    assert calls == ["canary-5"]
    assert result.action.parameters["jenkins_stage_abort"]["automatic_rollback_performed"] is False


@pytest.mark.asyncio
async def test_jenkins_requires_explicit_stage_targets() -> None:
    action = _action()
    action.parameters["jenkins_staged"]["stage_targets"] = {}
    plugin = JenkinsNativeStagedPlugin()
    prepared = await plugin.prepare(action)
    assert prepared.status == RemediationStatus.SKIPPED
    assert prepared.error == "JENKINS_STAGE_TARGETS_MISSING"
