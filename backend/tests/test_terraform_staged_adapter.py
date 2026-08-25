from __future__ import annotations

import hashlib
from pathlib import Path
from uuid import uuid4

import pytest

from common.models import RemediationAction, RemediationStatus
from remediation_engine.staged_executor import NativeStagedExecutor
from remediation_engine.terraform_staged import TerraformNativeStagedPlugin


def _action(tmp_path: Path) -> RemediationAction:
    return RemediationAction(
        incident_id=uuid4(),
        action_type="terraform_rollback",
        target="network-stack",
        status=RemediationStatus.RUNNING,
        parameters={
            "execution_strategy": "PROGRESSIVE",
            "execution_stages": [
                {"name": "canary-10", "percent": 10, "requires_health_gate": True},
                {"name": "canary-50", "percent": 50, "requires_health_gate": True},
                {"name": "full", "percent": 100, "requires_health_gate": True},
            ],
            "terraform_staged": {
                "enabled": True,
                "working_dir": str(tmp_path),
                "workspace": "prod",
                "stage_targets": {
                    "canary-10": ["module.net.aws_route_table.canary"],
                    "canary-50": ["module.net.aws_route_table.canary", "module.net.aws_nat_gateway.secondary"],
                    "full": ["module.net"],
                },
                "approved_plan_hashes": {},
                "require_preapproved_plan_hash": False,
            },
        },
    )


@pytest.mark.asyncio
async def test_terraform_executes_explicit_targets_and_hashes_plan(tmp_path: Path) -> None:
    calls: list[list[str]] = []

    async def runner(command, cwd, timeout):
        calls.append(list(command))
        if command[:2] == ["terraform", "plan"]:
            plan_path = Path(command[command.index("-out") + 1])
            plan_path.write_bytes("approved-plan".encode())
        return 0, "ok", ""

    async def observer(action, stage):
        return {
            "mode": "LIVE",
            "evidence_ids": [f"tf:{stage['name']}"],
            "required_checks": {"state_consistent": True, "no_unexpected_drift": True},
        }

    action = _action(tmp_path)
    plugin = TerraformNativeStagedPlugin(command_runner=runner, state_observer=observer)
    result = await NativeStagedExecutor().execute(plugin=plugin, action=action)
    assert result.action.status == RemediationStatus.SUCCEEDED
    assert result.completed_stages == 3
    plans = result.action.parameters["terraform_stage_plans"]
    assert plans["canary-10"]["plan_hash"] == hashlib.sha256(b"approved-plan").hexdigest()
    first_plan = next(cmd for cmd in calls if cmd[:2] == ["terraform", "plan"])
    assert "module.net.aws_route_table.canary" in first_plan


@pytest.mark.asyncio
async def test_terraform_plan_hash_mismatch_blocks_apply(tmp_path: Path) -> None:
    calls: list[list[str]] = []

    async def runner(command, cwd, timeout):
        calls.append(list(command))
        if command[:2] == ["terraform", "plan"]:
            plan_path = Path(command[command.index("-out") + 1])
            plan_path.write_bytes(b"different-plan")
        return 0, "ok", ""

    action = _action(tmp_path)
    action.parameters["terraform_staged"]["require_preapproved_plan_hash"] = True
    action.parameters["terraform_staged"]["approved_plan_hashes"] = {"canary-10": hashlib.sha256(b"expected-plan").hexdigest()}
    plugin = TerraformNativeStagedPlugin(command_runner=runner)
    result = await NativeStagedExecutor().execute(plugin=plugin, action=action)
    assert result.action.status == RemediationStatus.SKIPPED
    assert "TERRAFORM_PLAN_HASH_MISMATCH" in result.action.error
    assert not any(cmd[:2] == ["terraform", "apply"] for cmd in calls)


@pytest.mark.asyncio
async def test_terraform_unexpected_drift_aborts_progression(tmp_path: Path) -> None:
    stage_calls: list[str] = []

    async def runner(command, cwd, timeout):
        if command[:2] == ["terraform", "plan"]:
            plan_path = Path(command[command.index("-out") + 1])
            plan_path.write_bytes(b"plan")
            stage_calls.append("plan")
        elif command[:2] == ["terraform", "apply"]:
            stage_calls.append("apply")
        return 0, "ok", ""

    async def observer(action, stage):
        return {
            "mode": "LIVE",
            "evidence_ids": ["tf:drift"],
            "required_checks": {"state_consistent": True},
            "dependency_regression": stage["name"] == "canary-10",
        }

    action = _action(tmp_path)
    plugin = TerraformNativeStagedPlugin(command_runner=runner, state_observer=observer)
    result = await NativeStagedExecutor().execute(plugin=plugin, action=action)
    assert result.aborted is True
    assert result.action.parameters["terraform_stage_abort"]["requires_hitl"] is True
    assert stage_calls == ["plan", "apply"]


@pytest.mark.asyncio
async def test_terraform_requires_workspace_and_targets(tmp_path: Path) -> None:
    action = _action(tmp_path)
    action.parameters["terraform_staged"]["workspace"] = ""
    plugin = TerraformNativeStagedPlugin()
    prepared = await plugin.prepare(action)
    assert prepared.status == RemediationStatus.SKIPPED
    assert "TERRAFORM_STAGE_SCOPE_MISSING" in prepared.error
