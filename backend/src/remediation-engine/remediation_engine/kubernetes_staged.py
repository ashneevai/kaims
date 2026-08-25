from __future__ import annotations

import asyncio
import json
import os
from dataclasses import dataclass
from typing import Any, Awaitable, Callable

import httpx

from common.models import RemediationAction, RemediationStatus


CommandRunner = Callable[[list[str], float], Awaitable[tuple[int, str, str]]]
HealthObserver = Callable[[RemediationAction, dict[str, Any]], Awaitable[dict[str, Any]]]


async def _default_command_runner(command: list[str], timeout_seconds: float) -> tuple[int, str, str]:
    process = await asyncio.create_subprocess_exec(
        *command,
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


async def _default_health_observer(action: RemediationAction, stage: dict[str, Any]) -> dict[str, Any]:
    config = action.parameters.get("kubernetes_health")
    config = config if isinstance(config, dict) else {}
    prometheus_url = str(config.get("prometheus_url") or "").strip().rstrip("/")
    required_queries = config.get("required_queries")
    required_queries = required_queries if isinstance(required_queries, dict) else {}
    evidence_prefix = str(config.get("evidence_prefix") or "prometheus").strip() or "prometheus"

    if not prometheus_url or not required_queries:
        return {
            "mode": "UNAVAILABLE",
            "evidence_ids": [],
            "required_checks": {},
            "reason": "Kubernetes staged execution requires explicit Prometheus health queries",
        }

    timeout_seconds = float(config.get("timeout_seconds") or 8.0)
    checks: dict[str, bool] = {}
    evidence_ids: list[str] = []
    raw: dict[str, Any] = {}
    async with httpx.AsyncClient(timeout=timeout_seconds) as client:
        for name, spec_value in required_queries.items():
            spec = spec_value if isinstance(spec_value, dict) else {"query": spec_value}
            query = str(spec.get("query") or "").strip()
            if not query:
                checks[str(name)] = False
                continue
            response = await client.get(f"{prometheus_url}/api/v1/query", params={"query": query})
            response.raise_for_status()
            payload = response.json()
            data = payload.get("data", {}) if isinstance(payload, dict) else {}
            results = data.get("result") if isinstance(data, dict) else []
            results = results if isinstance(results, list) else []
            values: list[float] = []
            for row in results:
                value = row.get("value") if isinstance(row, dict) else None
                if isinstance(value, list) and len(value) > 1:
                    try:
                        values.append(float(value[1]))
                    except (TypeError, ValueError):
                        pass
            operator = str(spec.get("operator") or "lte").lower()
            threshold = float(spec.get("threshold") or 0.0)
            actual = max(values) if values else None
            if actual is None:
                passed = False
            elif operator == "gte":
                passed = actual >= threshold
            elif operator == "eq":
                passed = actual == threshold
            else:
                passed = actual <= threshold
            checks[str(name)] = passed
            raw[str(name)] = {"query": query, "actual": actual, "operator": operator, "threshold": threshold}
            evidence_ids.append(f"{evidence_prefix}:{name}:stage-{stage.get('name') or stage.get('percent')}")

    regression_names = set(str(item) for item in config.get("regression_checks", []))
    return {
        "mode": "LIVE",
        "evidence_ids": evidence_ids,
        "required_checks": checks,
        "error_rate_regression": any(not checks.get(name, False) for name in regression_names if "error" in name.lower()),
        "dependency_regression": any(not checks.get(name, False) for name in regression_names if "dependency" in name.lower()),
        "slo_regression": any(not checks.get(name, False) for name in regression_names if "slo" in name.lower()),
        "new_critical_alert": bool(config.get("new_critical_alert", False)),
        "data_loss_signal": bool(config.get("data_loss_signal", False)),
        "raw_observations": raw,
    }


@dataclass
class KubernetesNativeStagedPlugin:
    """Native staged Kubernetes adapter.

    Stage percentages are governance labels only. Physical execution is bound to
    explicit stage target lists supplied by the approved plan/onboarding data.
    The adapter never derives arbitrary replica percentages or traffic routing.
    """

    action_type: str = "restart_pod"
    command_runner: CommandRunner = _default_command_runner
    health_observer: HealthObserver = _default_health_observer

    @staticmethod
    def _config(action: RemediationAction) -> dict[str, Any]:
        value = action.parameters.get("kubernetes_staged")
        return value if isinstance(value, dict) else {}

    @staticmethod
    def _targets_for_stage(config: dict[str, Any], stage: dict[str, Any]) -> list[str]:
        mappings = config.get("stage_targets")
        mappings = mappings if isinstance(mappings, dict) else {}
        keys = [str(stage.get("name") or ""), str(stage.get("percent") or "")]
        for key in keys:
            value = mappings.get(key)
            if isinstance(value, list):
                return [str(item).strip() for item in value if str(item).strip()]
        return []

    async def prepare(self, action: RemediationAction) -> RemediationAction:
        config = self._config(action)
        namespace = str(config.get("namespace") or action.parameters.get("environment") or "").strip()
        context = str(config.get("context") or "").strip()
        stage_targets = config.get("stage_targets")
        if not bool(config.get("enabled")):
            action.status = RemediationStatus.SKIPPED
            action.error = "KUBERNETES_STAGED_CONNECTOR_DISABLED"
            return action
        if not namespace or not context:
            action.status = RemediationStatus.SKIPPED
            action.error = "KUBERNETES_STAGE_SCOPE_MISSING: explicit context and namespace are required"
            return action
        if not isinstance(stage_targets, dict) or not stage_targets:
            action.status = RemediationStatus.SKIPPED
            action.error = "KUBERNETES_STAGE_TARGETS_MISSING: explicit per-stage targets are required"
            return action
        action.parameters["kubernetes_stage_context"] = context
        action.parameters["kubernetes_stage_namespace"] = namespace
        action.parameters["kubernetes_stage_prepared"] = True
        action.status = RemediationStatus.RUNNING
        return action

    async def execute_stage(
        self,
        action: RemediationAction,
        *,
        stage_index: int,
        stage: dict[str, Any],
    ) -> RemediationAction:
        config = self._config(action)
        context = str(config.get("context"))
        namespace = str(config.get("namespace") or action.parameters.get("environment"))
        targets = self._targets_for_stage(config, stage)
        if not targets:
            action.status = RemediationStatus.FAILED
            action.error = f"KUBERNETES_STAGE_TARGETS_EMPTY: stage={stage.get('name') or stage_index}"
            return action

        operation = str(config.get("operation") or "rollout_restart").strip().lower()
        timeout_seconds = float(config.get("command_timeout_seconds") or 120.0)
        results: list[dict[str, Any]] = []
        for target in targets:
            if operation == "rollout_undo":
                command = ["kubectl", "--context", context, "-n", namespace, "rollout", "undo", f"deployment/{target}"]
            else:
                command = ["kubectl", "--context", context, "-n", namespace, "rollout", "restart", f"deployment/{target}"]
            returncode, stdout, stderr = await self.command_runner(command, timeout_seconds)
            results.append({"target": target, "command": command, "returncode": returncode, "stdout": stdout, "stderr": stderr})
            if returncode != 0:
                action.status = RemediationStatus.FAILED
                action.error = f"KUBERNETES_STAGE_EXECUTION_FAILED: target={target}: {stderr or stdout}"
                action.parameters.setdefault("kubernetes_stage_results", []).append({"stage_index": stage_index, "results": results})
                return action

        action.parameters.setdefault("kubernetes_stage_results", []).append({"stage_index": stage_index, "stage": dict(stage), "results": results})
        action.status = RemediationStatus.RUNNING
        return action

    async def observe_stage(
        self,
        action: RemediationAction,
        *,
        stage_index: int,
        stage: dict[str, Any],
    ) -> dict[str, Any]:
        observation = await self.health_observer(action, stage)
        observation["stage_index"] = stage_index
        observation["kubernetes_context"] = action.parameters.get("kubernetes_stage_context")
        observation["namespace"] = action.parameters.get("kubernetes_stage_namespace")
        return observation

    async def abort(
        self,
        action: RemediationAction,
        *,
        stage_index: int,
        stage: dict[str, Any],
        reason: str,
    ) -> RemediationAction:
        config = self._config(action)
        action.parameters["kubernetes_stage_abort"] = {
            "stage_index": stage_index,
            "stage": dict(stage),
            "reason": reason,
            "automatic_rollback_performed": False,
        }
        if bool(config.get("abort_requires_manual_recovery", True)):
            action.output = "staged Kubernetes rollout stopped; manual recovery/approved rollback required"
        return action

    async def finalize(self, action: RemediationAction) -> RemediationAction:
        action.status = RemediationStatus.SUCCEEDED
        action.output = json.dumps(
            {
                "executor": "kubernetes-native-staged",
                "context": action.parameters.get("kubernetes_stage_context"),
                "namespace": action.parameters.get("kubernetes_stage_namespace"),
                "completed": True,
            },
            sort_keys=True,
        )
        return action
