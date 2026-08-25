from __future__ import annotations

from typing import Any

from common.capability_registry import CapabilityRegistry, LEGACY_ACTION_CAPABILITIES
from common.models import Approval, RemediationAction
from remediation_engine.plugins import RemediationEngine as LegacyRemediationEngine


class SafeRemediationEngine(LegacyRemediationEngine):
    """Compatibility bridge from legacy action inference to registered capabilities.

    This wrapper intentionally does not make the legacy inference path authoritative.
    It blocks ambiguous operations, records a canonical capability id for explicit
    supported legacy actions, and requires the capability to exist in the registry.
    """

    _ROLLBACK_TERMS = (
        "rollback",
        "roll back",
        "revert deployment",
        "restore previous deployment",
        "previous revision",
    )

    def __init__(self, *args: Any, capability_registry: CapabilityRegistry | None = None, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.capability_registry = capability_registry or CapabilityRegistry()

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

    def _block_unsupported(self, action: RemediationAction, reason: str) -> RemediationAction:
        action.action_type = "unsupported_capability"
        action.parameters["safety_block_reason"] = reason
        action.parameters.pop("capability_id", None)
        return action

    def _bind_registered_capability(self, action: RemediationAction) -> RemediationAction:
        capability_id = LEGACY_ACTION_CAPABILITIES.get(str(action.action_type or "").strip().lower())
        if not capability_id:
            return self._block_unsupported(
                action,
                f"Legacy action '{action.action_type}' has no registered capability mapping.",
            )
        definition = self.capability_registry.get(capability_id)
        if definition is None:
            return self._block_unsupported(
                action,
                f"UNSUPPORTED_CAPABILITY: {capability_id}",
            )
        action.parameters["capability_id"] = definition.capability_id
        action.parameters["capability_version"] = definition.version
        action.parameters["capability_risk_class"] = definition.risk_class
        action.parameters["capability_trust_level"] = definition.trust_level.value
        action.parameters["validation_required"] = definition.validation_required
        return action

    def build_action(self, approval: Approval) -> RemediationAction:
        action = super().build_action(approval)

        if action.action_type == "rollback_deployment":
            intent = self._approval_intent(approval)
            explicit_rollback = any(term in intent for term in self._ROLLBACK_TERMS)
            if not explicit_rollback:
                return self._block_unsupported(
                    action,
                    "Legacy action inference could not map the approved request to a registered capability; "
                    "unknown actions never default to rollback.",
                )

        return self._bind_registered_capability(action)
