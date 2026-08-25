from __future__ import annotations

import asyncio
import hashlib
import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Awaitable, Callable

from common.models import RemediationAction, RemediationStatus


CommandRunner = Callable[[list[str], str, float], Awaitable[tuple[int, str, str]]]
StateObserver = Callable[[RemediationAction, dict[str, Any]], Awaitable[dict[str, Any]]]


async def _default_command_runner(command: list[str], cwd: str, timeout_seconds: float) -> tuple[int, str, str]:
    process = await asyncio.create_subprocess_exec(
        *command,
        cwd=cwd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=os.environ.copy(),
    )
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout_seconds)
    except asyncio.TimeoutError:
        process.kill()
        await process.wait()
        return 124, "", f"command timed out after {timeout_seconds:g}s"
    return (
        int(process.returncode or 0),
        stdout.decode("utf-8", errors="replace").strip(),
        stderr.decode("utf-8", errors="replace").strip(),
    )


async def _default_state_observer(action: RemediationAction, stage: dict[str, Any]) -> dict[str, Any]:
    config = action.parameters.get("terraform_health")
    config = config if isinstance(config, dict) else {}
    required_checks = config.get("required_checks")
    required_checks = required_checks if isinstance(required_checks, dict) else {}
    drift_detected = bool(config.get("unexpected_drift", False))
    if not required_checks:
        return {
            "mode": "UNAVAILABLE",
            "evidence_ids": [],
            "required_checks": {},
            "reason": "Terraform staged execution requires explicit state/drift checks",
        }
    evidence_ids = [
        f"terraform:{action.id}:{stage.get('name') or stage.get('percent')}:{name}"
        for name in required_checks
    ]
    return {
        "mode": str(config.get("mode") or "LIVE").upper(),
        "evidence_ids": evidence_ids,
        "required_checks": {str(name): value is True for name, value in required_checks.items()},
        "dependency_regression": drift_detected,
        "error_rate_regression": False,
        "slo_regression": False,
        "new_critical_alert": False,
        "data_loss_signal": bool(config.get("data_loss_signal", False)),
        "unexpected_drift": drift_detected,
    }


@dataclass
class TerraformNativeStagedPlugin:
    """Progressive Terraform adapter with plan-hash binding and drift gates."""

    action_type: str = "terraform_rollback"
    command_runner: CommandRunner = _default_command_runner
    state_observer: StateObserver = _default_state_observer

    @staticmethod
    def _config(action: RemediationAction) -> dict[str, Any]:
        value = action.parameters.get("terraform_staged")
        return value if isinstance(value, dict) else {}

    @staticmethod
    def _targets(config: dict[str, Any], stage: dict[str, Any]) -> list[str]:
        mapping = config.get("stage_targets")
        mapping = mapping if isinstance(mapping, dict) else {}
        for key in (str(stage.get("name") or ""), str(stage.get("percent") or "")):
            value = mapping.get(key)
            if isinstance(value, list):
                return [str(item).strip() for item in value if str(item).strip()]
        return []

    @staticmethod
    def _stage_key(stage_index: int, stage: dict[str, Any]) -> str:
        return str(stage.get("name") or stage.get("percent") or stage_index)

    async def prepare(self, action: RemediationAction) -> RemediationAction:
        config = self._config(action)
        working_dir = str(config.get("working_dir") or "").strip()
        workspace = str(config.get("workspace") or "").strip()
        if not bool(config.get("enabled")):
            action.status = RemediationStatus.SKIPPED
            action.error = "TERRAFORM_STAGED_CONNECTOR_DISABLED"
            return action
        if not working_dir or not workspace:
            action.status = RemediationStatus.SKIPPED
            action.error = "TERRAFORM_STAGE_SCOPE_MISSING: working_dir and workspace are required"
            return action
        path = Path(working_dir).expanduser().resolve()
        if not path.is_dir():
            action.status = RemediationStatus.SKIPPED
            action.error = f"TERRAFORM_WORKING_DIR_INVALID: {path}"
            return action
        stage_targets = config.get("stage_targets")
        if not isinstance(stage_targets, dict) or not stage_targets:
            action.status = RemediationStatus.SKIPPED
            action.error = "TERRAFORM_STAGE_TARGETS_MISSING"
            return action

        timeout = float(config.get("command_timeout_seconds") or 120.0)
        init_cmd = ["terraform", "init", "-input=false"]
        code, stdout, stderr = await self.command_runner(init_cmd, str(path), timeout)
        if code != 0:
            action.status = RemediationStatus.FAILED
            action.error = f"TERRAFORM_INIT_FAILED: {stderr or stdout}"
            return action
        select_cmd = ["terraform", "workspace", "select", workspace]
        code, stdout, stderr = await self.command_runner(select_cmd, str(path), timeout)
        if code != 0:
            action.status = RemediationStatus.FAILED
            action.error = f"TERRAFORM_WORKSPACE_SELECT_FAILED: {stderr or stdout}"
            return action

        action.parameters["terraform_stage_working_dir"] = str(path)
        action.parameters["terraform_stage_workspace"] = workspace
        action.parameters["terraform_stage_prepared"] = True
        action.parameters.setdefault("terraform_stage_plans", {})
        action.status = RemediationStatus.RUNNING
        return action

    async def execute_stage(self, action: RemediationAction, *, stage_index: int, stage: dict[str, Any]) -> RemediationAction:
        config = self._config(action)
        working_dir = str(action.parameters.get("terraform_stage_working_dir") or "")
        targets = self._targets(config, stage)
        if not targets:
            action.status = RemediationStatus.FAILED
            action.error = f"TERRAFORM_STAGE_TARGETS_EMPTY: stage={self._stage_key(stage_index, stage)}"
            return action

        timeout = float(config.get("command_timeout_seconds") or 120.0)
        stage_key = self._stage_key(stage_index, stage)
        plan_path = Path(tempfile.gettempdir()) / f"kaims-{action.id}-{stage_index}.tfplan"
        plan_cmd = ["terraform", "plan", "-input=false", "-out", str(plan_path)]
        for target in targets:
            plan_cmd.extend(["-target", target])
        code, stdout, stderr = await self.command_runner(plan_cmd, working_dir, timeout)
        if code != 0:
            action.status = RemediationStatus.FAILED
            action.error = f"TERRAFORM_PLAN_FAILED: stage={stage_key}: {stderr or stdout}"
            return action

        if plan_path.exists():
            plan_bytes = plan_path.read_bytes()
        else:
            plan_bytes = stdout.encode("utf-8")
        plan_hash = hashlib.sha256(plan_bytes).hexdigest()
        plan_record = {
            "stage_index": stage_index,
            "stage": dict(stage),
            "targets": targets,
            "plan_path": str(plan_path),
            "plan_hash": plan_hash,
            "plan_stdout": stdout,
        }
        action.parameters.setdefault("terraform_stage_plans", {})[stage_key] = plan_record

        approved_hashes = config.get("approved_plan_hashes")
        approved_hashes = approved_hashes if isinstance(approved_hashes, dict) else {}
        expected_hash = str(approved_hashes.get(stage_key) or "").strip()
        require_preapproved_hash = bool(config.get("require_preapproved_plan_hash", True))
        if require_preapproved_hash and not expected_hash:
            action.status = RemediationStatus.SKIPPED
            action.error = f"TERRAFORM_PLAN_HASH_APPROVAL_MISSING: stage={stage_key}"
            return action
        if expected_hash and expected_hash != plan_hash:
            action.status = RemediationStatus.SKIPPED
            action.error = f"TERRAFORM_PLAN_HASH_MISMATCH: stage={stage_key}"
            return action

        if not plan_path.exists():
            action.status = RemediationStatus.FAILED
            action.error = f"TERRAFORM_PLAN_ARTIFACT_MISSING: stage={stage_key}"
            return action

        apply_cmd = ["terraform", "apply", "-input=false", "-auto-approve", str(plan_path)]
        code, stdout, stderr = await self.command_runner(apply_cmd, working_dir, timeout)
        action.parameters.setdefault("terraform_stage_results", []).append(
            {
                "stage_index": stage_index,
                "stage": dict(stage),
                "targets": targets,
                "plan_hash": plan_hash,
                "returncode": code,
                "stdout": stdout,
                "stderr": stderr,
            }
        )
        if code != 0:
            action.status = RemediationStatus.FAILED
            action.error = f"TERRAFORM_APPLY_FAILED: stage={stage_key}: {stderr or stdout}"
            return action
        action.status = RemediationStatus.RUNNING
        return action

    async def observe_stage(self, action: RemediationAction, *, stage_index: int, stage: dict[str, Any]) -> dict[str, Any]:
        observation = await self.state_observer(action, stage)
        observation["stage_index"] = stage_index
        observation["terraform_workspace"] = action.parameters.get("terraform_stage_workspace")
        observation["terraform_working_dir"] = action.parameters.get("terraform_stage_working_dir")
        return observation

    async def abort(self, action: RemediationAction, *, stage_index: int, stage: dict[str, Any], reason: str) -> RemediationAction:
        action.parameters["terraform_stage_abort"] = {
            "stage_index": stage_index,
            "stage": dict(stage),
            "reason": reason,
            "automatic_rollback_performed": False,
            "requires_hitl": True,
        }
        action.output = "Terraform progressive apply stopped; HITL required before further infrastructure changes"
        return action

    async def finalize(self, action: RemediationAction) -> RemediationAction:
        action.status = RemediationStatus.SUCCEEDED
        action.output = json.dumps(
            {
                "executor": "terraform-native-staged",
                "workspace": action.parameters.get("terraform_stage_workspace"),
                "completed": True,
            },
            sort_keys=True,
        )
        return action
