from __future__ import annotations

from typing import Any

from common.config import get_settings
from common.execution_safety import (
    ExecutionSafetyDecision,
    build_execution_safety_assessment,
    immutable_pre_execution_snapshot,
)
from common.models import Approval, RemediationAction, RemediationStatus
from common.rollback_governance import apply_rollback_governance
from remediation_engine.execution_coordinator import build_execution_coordinator
from remediation_engine.kubernetes_staged import KubernetesNativeStagedPlugin
from remediation_engine.safe_engine import SafeRemediationEngine
from remediation_engine.staged_executor import NativeStagedExecutor


class GovernedRemediationEngine(SafeRemediationEngine):
    """Safe remediation engine with rollback/change and execution-safety enforcement."""

    def __init__(
        self,
        *args: Any,
        execution_coordinator: Any | None = None,
        staged_executor: NativeStagedExecutor | None = None,
        staged_plugins: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(*args, **kwargs)
        self._settings = get_settings()
        self.execution_coordinator = execution_coordinator or build_execution_coordinator(self._settings)
        self.staged_executor = staged_executor or NativeStagedExecutor()
        self.staged_plugins = staged_plugins or {
            "restart_pod": KubernetesNativeStagedPlugin(action_type="restart_pod"),
            "scale_deployment": KubernetesNativeStagedPlugin(action_type="scale_deployment"),
        }

    def build_action(self, approval: Approval) -> RemediationAction:
        action = super().build_action(approval)
        if action.action_type == "unsupported_capability":
            return action
        return apply_rollback_governance(approval=approval, action=action)

    @staticmethod
    def _block_execution(action: RemediationAction, reason: str) -> RemediationAction:
        action.status = RemediationStatus.SKIPPED
        action.error = reason
        action.output = "remediation blocked by execution safety controller"
        action.parameters["execution_safety_block_reason"] = reason
        return action

    async def _execute_with_strategy(self, action: RemediationAction) -> RemediationAction:
        stages = action.parameters.get("execution_stages")
        stages = [item for item in stages if isinstance(item, dict)] if isinstance(stages, list) else []
        strategy = str(action.parameters.get("execution_strategy") or "SINGLE").strip().upper()
        multi_stage = strategy in {"CANARY", "PROGRESSIVE"} or len(stages) > 1

        if not multi_stage:
            return await super().execute(action)

        action_type = str(action.action_type or "").strip().lower()
        plugin = self.staged_plugins.get(action_type)
        if plugin is None:
            plugin = self.plugins.get(action_type)
        if plugin is None:
            return self._block_execution(
                action,
                f"NATIVE_STAGED_EXECUTOR_UNAVAILABLE: no plugin registered for {action.action_type}",
            )

        result = await self.staged_executor.execute(plugin=plugin, action=action)
        return result.action

    async def execute(self, action: RemediationAction) -> RemediationAction:
        assessment = build_execution_safety_assessment(action)
        action.parameters["pre_execution_snapshot"] = immutable_pre_execution_snapshot(action)
        action.parameters["pre_execution_snapshot_hash"] = assessment.snapshot_hash
        action.parameters["execution_idempotency_key"] = assessment.idempotency_key
        action.parameters["execution_lock_key"] = assessment.lock_key
        action.parameters["execution_stages"] = [
            {
                "name": stage.name,
                "percent": stage.percent,
                "requires_health_gate": stage.requires_health_gate,
            }
            for stage in assessment.stages
        ]
        action.parameters.setdefault(
            "execution_abort_policy",
            {
                "abort_on_health_gate_failure": True,
                "abort_on_new_critical_alert": True,
                "abort_on_error_rate_regression": True,
                "abort_on_dependency_regression": True,
                "require_manual_recovery_after_rollback_failure": True,
            },
        )

        if assessment.decision == ExecutionSafetyDecision.BLOCK:
            return self._block_execution(action, assessment.reason)

        coordination = await self.execution_coordinator.acquire(
            lock_key=assessment.lock_key,
            idempotency_key=assessment.idempotency_key,
            ttl_seconds=int(action.parameters.get("execution_lock_ttl_seconds") or 600),
        )
        if not coordination.acquired:
            reason = (
                "IDEMPOTENT_DUPLICATE: execution already completed"
                if coordination.duplicate
                else f"EXECUTION_LOCK_UNAVAILABLE: {coordination.reason}"
            )
            return self._block_execution(action, reason)

        success = False
        try:
            action.parameters["execution_coordination"] = {
                "lock_acquired": True,
                "distributed": self._settings.environment.lower() not in {
                    "local",
                    "dev",
                    "development",
                    "test",
                    "testing",
                    "simulation",
                },
                "reason": coordination.reason,
            }
            action = await self._execute_with_strategy(action)
            success = action.status == RemediationStatus.SUCCEEDED
            return action
        finally:
            await self.execution_coordinator.complete(
                lock_key=assessment.lock_key,
                idempotency_key=assessment.idempotency_key,
                success=success,
            )
