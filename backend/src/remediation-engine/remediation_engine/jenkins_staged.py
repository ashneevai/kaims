from __future__ import annotations

import asyncio
import json
import os
from dataclasses import dataclass
from typing import Any, Awaitable, Callable
from urllib.parse import quote

import httpx

from common.models import RemediationAction, RemediationStatus


JenkinsTrigger = Callable[[RemediationAction, dict[str, Any], list[str]], Awaitable[dict[str, Any]]]
HealthObserver = Callable[[RemediationAction, dict[str, Any]], Awaitable[dict[str, Any]]]


async def _default_jenkins_trigger(
    action: RemediationAction,
    stage: dict[str, Any],
    targets: list[str],
) -> dict[str, Any]:
    config = action.parameters.get("jenkins_staged")
    config = config if isinstance(config, dict) else {}
    base_url = str(config.get("base_url") or "").strip().rstrip("/")
    job = str(config.get("job") or "").strip()
    token = str(config.get("api_token") or os.getenv(str(config.get("api_token_env") or "JENKINS_API_TOKEN"), "")).strip()
    username = str(config.get("username") or os.getenv(str(config.get("username_env") or "JENKINS_USERNAME"), "")).strip()
    if not base_url or not job or not token or not username:
        return {"ok": False, "reason": "JENKINS_CONNECTION_INCOMPLETE"}

    parameters = config.get("parameters")
    parameters = dict(parameters) if isinstance(parameters, dict) else {}
    parameters.update(
        {
            "KAIMS_STAGE": str(stage.get("name") or stage.get("percent") or "stage"),
            "KAIMS_STAGE_PERCENT": str(stage.get("percent") or ""),
            "KAIMS_TARGETS": ",".join(targets),
            "KAIMS_INCIDENT_ID": str(action.incident_id),
            "KAIMS_ACTION_ID": str(action.id),
        }
    )
    timeout = float(config.get("timeout_seconds") or 15.0)
    async with httpx.AsyncClient(timeout=timeout, auth=(username, token)) as client:
        response = await client.post(
            f"{base_url}/job/{quote(job, safe='')}/buildWithParameters",
            data=parameters,
        )
        if response.status_code not in {200, 201, 202}:
            return {"ok": False, "reason": f"JENKINS_TRIGGER_FAILED:{response.status_code}", "body": response.text[:1000]}
        queue_url = response.headers.get("Location")
        return {"ok": True, "queue_url": queue_url, "status_code": response.status_code}


async def _default_health_observer(action: RemediationAction, stage: dict[str, Any]) -> dict[str, Any]:
    config = action.parameters.get("jenkins_health")
    config = config if isinstance(config, dict) else {}
    checks = config.get("required_checks")
    checks = checks if isinstance(checks, dict) else {}
    evidence_ids = [
        f"jenkins:{action.id}:{stage.get('name') or stage.get('percent')}:{name}"
        for name in checks
    ]
    if not checks:
        return {
            "mode": "UNAVAILABLE",
            "evidence_ids": [],
            "required_checks": {},
            "reason": "Jenkins staged execution requires explicit health checks",
        }
    return {
        "mode": str(config.get("mode") or "LIVE").upper(),
        "evidence_ids": evidence_ids,
        "required_checks": {str(name): value is True for name, value in checks.items()},
        "new_critical_alert": bool(config.get("new_critical_alert", False)),
        "error_rate_regression": bool(config.get("error_rate_regression", False)),
        "dependency_regression": bool(config.get("dependency_regression", False)),
        "slo_regression": bool(config.get("slo_regression", False)),
        "data_loss_signal": bool(config.get("data_loss_signal", False)),
    }


@dataclass
class JenkinsNativeStagedPlugin:
    """Native Jenkins adapter for explicitly staged deployment jobs."""

    action_type: str = "rollback_deployment"
    trigger: JenkinsTrigger = _default_jenkins_trigger
    health_observer: HealthObserver = _default_health_observer

    @staticmethod
    def _config(action: RemediationAction) -> dict[str, Any]:
        value = action.parameters.get("jenkins_staged")
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

    async def prepare(self, action: RemediationAction) -> RemediationAction:
        config = self._config(action)
        if not bool(config.get("enabled")):
            action.status = RemediationStatus.SKIPPED
            action.error = "JENKINS_STAGED_CONNECTOR_DISABLED"
            return action
        if not str(config.get("base_url") or "").strip() or not str(config.get("job") or "").strip():
            action.status = RemediationStatus.SKIPPED
            action.error = "JENKINS_STAGE_SCOPE_MISSING: base_url and job are required"
            return action
        if not isinstance(config.get("stage_targets"), dict) or not config.get("stage_targets"):
            action.status = RemediationStatus.SKIPPED
            action.error = "JENKINS_STAGE_TARGETS_MISSING"
            return action
        action.parameters["jenkins_stage_prepared"] = True
        action.status = RemediationStatus.RUNNING
        return action

    async def execute_stage(self, action: RemediationAction, *, stage_index: int, stage: dict[str, Any]) -> RemediationAction:
        config = self._config(action)
        targets = self._targets(config, stage)
        if not targets:
            action.status = RemediationStatus.FAILED
            action.error = f"JENKINS_STAGE_TARGETS_EMPTY: stage={stage.get('name') or stage_index}"
            return action
        result = await self.trigger(action, stage, targets)
        action.parameters.setdefault("jenkins_stage_results", []).append(
            {"stage_index": stage_index, "stage": dict(stage), "targets": targets, "trigger": result}
        )
        if not bool(result.get("ok")):
            action.status = RemediationStatus.FAILED
            action.error = str(result.get("reason") or "JENKINS_STAGE_EXECUTION_FAILED")
            return action
        action.status = RemediationStatus.RUNNING
        return action

    async def observe_stage(self, action: RemediationAction, *, stage_index: int, stage: dict[str, Any]) -> dict[str, Any]:
        observation = await self.health_observer(action, stage)
        observation["stage_index"] = stage_index
        observation["jenkins_job"] = self._config(action).get("job")
        return observation

    async def abort(self, action: RemediationAction, *, stage_index: int, stage: dict[str, Any], reason: str) -> RemediationAction:
        action.parameters["jenkins_stage_abort"] = {
            "stage_index": stage_index,
            "stage": dict(stage),
            "reason": reason,
            "automatic_rollback_performed": False,
        }
        action.output = "Jenkins staged rollout stopped; approved recovery action required"
        return action

    async def finalize(self, action: RemediationAction) -> RemediationAction:
        action.status = RemediationStatus.SUCCEEDED
        action.output = json.dumps(
            {"executor": "jenkins-native-staged", "job": self._config(action).get("job"), "completed": True},
            sort_keys=True,
        )
        return action
