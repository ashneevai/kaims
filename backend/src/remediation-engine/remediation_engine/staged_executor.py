from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from common.models import RemediationAction, RemediationStatus, utc_now
from common.staged_execution import StageGateDecision, evaluate_stage_health_gate


@runtime_checkable
class NativeStagedPlugin(Protocol):
    action_type: str

    async def prepare(self, action: RemediationAction) -> RemediationAction: ...

    async def execute_stage(
        self,
        action: RemediationAction,
        *,
        stage_index: int,
        stage: dict[str, Any],
    ) -> RemediationAction: ...

    async def observe_stage(
        self,
        action: RemediationAction,
        *,
        stage_index: int,
        stage: dict[str, Any],
    ) -> dict[str, Any]: ...

    async def abort(
        self,
        action: RemediationAction,
        *,
        stage_index: int,
        stage: dict[str, Any],
        reason: str,
    ) -> RemediationAction: ...

    async def finalize(self, action: RemediationAction) -> RemediationAction: ...


@dataclass(frozen=True)
class StagedExecutionResult:
    action: RemediationAction
    completed_stages: int
    aborted: bool
    abort_reason: str | None = None


class NativeStagedExecutor:
    """Physically enforces staged rollout for plugins implementing NativeStagedPlugin.

    A multi-stage action is never downgraded to the legacy single-shot plugin API.
    Every stage must execute independently, produce live provenance-bearing health
    evidence, and pass its health gate before the next stage can run.
    """

    @staticmethod
    def supports(plugin: Any) -> bool:
        return isinstance(plugin, NativeStagedPlugin)

    @staticmethod
    def _stages(action: RemediationAction) -> list[dict[str, Any]]:
        stages = action.parameters.get("execution_stages")
        return [dict(item) for item in stages if isinstance(item, dict)] if isinstance(stages, list) else []

    @staticmethod
    def _record(action: RemediationAction, row: dict[str, Any]) -> None:
        history = action.parameters.setdefault("stage_execution_history", [])
        if isinstance(history, list):
            history.append(row)

    async def execute(self, *, plugin: Any, action: RemediationAction) -> StagedExecutionResult:
        stages = self._stages(action)
        if len(stages) < 2:
            raise ValueError("native staged execution requires at least two execution stages")
        if not self.supports(plugin):
            action.status = RemediationStatus.SKIPPED
            action.error = "NATIVE_STAGED_EXECUTOR_UNAVAILABLE"
            action.output = "multi-stage remediation blocked because plugin lacks native stage support"
            action.parameters["staged_execution_blocked"] = True
            action.completed_at = utc_now()
            return StagedExecutionResult(action=action, completed_stages=0, aborted=False)

        action = await plugin.prepare(action)
        if action.status in {RemediationStatus.FAILED, RemediationStatus.SKIPPED}:
            action.completed_at = utc_now()
            return StagedExecutionResult(action=action, completed_stages=0, aborted=False)

        completed = 0
        for index, stage in enumerate(stages):
            action.parameters["current_execution_stage"] = index
            action = await plugin.execute_stage(action, stage_index=index, stage=stage)
            if action.status == RemediationStatus.FAILED:
                self._record(action, {"stage_index": index, "stage": stage, "decision": "EXECUTION_FAILED"})
                action.completed_at = utc_now()
                return StagedExecutionResult(
                    action=action,
                    completed_stages=completed,
                    aborted=True,
                    abort_reason="stage execution failed",
                )

            observation = await plugin.observe_stage(action, stage_index=index, stage=stage)
            gate = evaluate_stage_health_gate(observation)
            self._record(
                action,
                {
                    "stage_index": index,
                    "stage": stage,
                    "observation": observation,
                    "gate": gate.as_dict(),
                },
            )

            if gate.decision != StageGateDecision.ADVANCE:
                reason = gate.reason
                action = await plugin.abort(
                    action,
                    stage_index=index,
                    stage=stage,
                    reason=reason,
                )
                action.status = RemediationStatus.FAILED if gate.decision == StageGateDecision.ABORT else RemediationStatus.SKIPPED
                action.error = reason
                action.parameters["staged_execution_aborted"] = True
                action.parameters["staged_execution_abort_reason"] = reason
                action.completed_at = utc_now()
                return StagedExecutionResult(
                    action=action,
                    completed_stages=completed,
                    aborted=True,
                    abort_reason=reason,
                )

            completed += 1

        action = await plugin.finalize(action)
        action.parameters["staged_execution_completed"] = True
        action.parameters["staged_execution_completed_stages"] = completed
        action.completed_at = utc_now()
        return StagedExecutionResult(action=action, completed_stages=completed, aborted=False)
