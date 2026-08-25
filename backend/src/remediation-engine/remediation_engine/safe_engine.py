from __future__ import annotations

from typing import Any

from common.models import Approval, RemediationAction
from remediation_engine.plugins import RemediationEngine as LegacyRemediationEngine


class SafeRemediationEngine(LegacyRemediationEngine):
    """Compatibility wrapper that removes the legacy unknown-action rollback fallback.

    Legacy inference is retained for currently supported explicit operations, but a
    rollback is only accepted when the approved text/plan actually requests a rollback.
    Unknown or ambiguous operations become ``unsupported_capability`` and are blocked
    by the existing allowlist before any executor is invoked.
    """

    _ROLLBACK_TERMS = (
        "rollback",
        "roll back",
        "revert deployment",
        "restore previous deployment",
        "previous revision",
    )

    @staticmethod
    def _text(value: Any) -> str:
        return str(value or "").strip().lower()

    def _approval_intent(self, approval: Approval) -> str:
        metadata = approval.metadata if isinstance(approval.metadata, dict) else {}
        execution_plan = metadata.get("execution_plan") if isinstance(metadata.get("execution_plan"), dict) else {}
        values: list[Any] = [
            approval.modified_action,
            approval.comment,
            metadata.get("recommended_action"),
            metadata.get("capability_id"),
            metadata.get("recommended_capability"),
        ]
        for key in ("commands", "scripts", "queries"):
            items = execution_plan.get(key) if isinstance(execution_plan.get(key), list) else []
            values.extend(items)
        return " | ".join(self._text(value) for value in values if self._text(value))

    def build_action(self, approval: Approval) -> RemediationAction:
        action = super().build_action(approval)
        if action.action_type != "rollback_deployment":
            return action

        intent = self._approval_intent(approval)
        explicit_rollback = any(term in intent for term in self._ROLLBACK_TERMS)
        if explicit_rollback:
            return action

        action.action_type = "unsupported_capability"
        action.parameters["safety_block_reason"] = (
            "Legacy action inference could not map the approved request to a registered capability; "
            "unknown actions never default to rollback."
        )
        return action
