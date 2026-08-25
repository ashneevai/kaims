from __future__ import annotations

from typing import Any

from common.capability_registry import CapabilityRegistry, LEGACY_ACTION_CAPABILITIES
from common.models import Approval, RemediationAction
from common.resolution_models import PlanSnapshot, RemediationPlan
from remediation_engine.plugins import RemediationEngine as LegacyRemediationEngine


CAPABILITY_LEGACY_ACTIONS: dict[str, str] = {
    capability_id: action_type for action_type, capability_id in LEGACY_ACTION_CAPABILITIES.items()
}


class SafeRemediationEngine(LegacyRemediationEngine):
    """Compatibility bridge from structured remediation plans to deterministic executors.

    Structured `RemediationPlan` metadata is authoritative when present. Legacy text
    inference remains only for backward compatibility and is prevented from mapping
    ambiguous requests to rollback.
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
            return self._block_unsupported(action, f"UNSUPPORTED_CAPABILITY: {capability_id}")
        action.parameters["capability_id"] = definition.capability_id
        action.parameters["capability_version"] = definition.version
        action.parameters["capability_risk_class"] = definition.risk_class
        action.parameters["capability_trust_level"] = definition.trust_level.value
        action.parameters["validation_required"] = definition.validation_required
        action.parameters["planning_contract"] = "legacy-compatibility"
        return action

    def _build_from_structured_plan(self, approval: Approval, plan_payload: dict[str, Any]) -> RemediationAction:
        try:
            plan = RemediationPlan.model_validate(plan_payload)
        except Exception as exc:
            action = RemediationAction(
                incident_id=approval.incident_id,
                approval_id=approval.id,
                action_type="unsupported_capability",
                target=str(approval.incident_id),
            )
            return self._block_unsupported(action, f"INVALID_REMEDIATION_PLAN: {exc}")

        if plan.incident_id != approval.incident_id:
            action = RemediationAction(
                incident_id=approval.incident_id,
                approval_id=approval.id,
                action_type="unsupported_capability",
                target=plan.target_resource_id,
            )
            return self._block_unsupported(action, "PLAN_INCIDENT_MISMATCH")

        definition = self.capability_registry.get(plan.recommended_capability)
        if definition is None:
            action = RemediationAction(
                incident_id=approval.incident_id,
                approval_id=approval.id,
                action_type="unsupported_capability",
                target=plan.target_resource_id,
            )
            return self._block_unsupported(
                action,
                f"UNSUPPORTED_CAPABILITY: {plan.recommended_capability}",
            )

        legacy_action_type = CAPABILITY_LEGACY_ACTIONS.get(definition.capability_id)
        if not legacy_action_type:
            action = RemediationAction(
                incident_id=approval.incident_id,
                approval_id=approval.id,
                action_type="unsupported_capability",
                target=plan.target_resource_id,
            )
            return self._block_unsupported(
                action,
                f"Capability '{definition.capability_id}' has no certified executor bridge yet.",
            )

        snapshot = PlanSnapshot.from_plan(plan)
        metadata = approval.metadata if isinstance(approval.metadata, dict) else {}
        approved_hash = str(metadata.get("plan_hash") or "").strip()
        approved_revision = metadata.get("plan_revision")
        if approved_hash and approved_hash != snapshot.plan_hash:
            action = RemediationAction(
                incident_id=approval.incident_id,
                approval_id=approval.id,
                action_type="unsupported_capability",
                target=plan.target_resource_id,
            )
            return self._block_unsupported(action, "STALE_OR_MODIFIED_PLAN: plan hash mismatch")
        if approved_revision is not None and int(approved_revision) != plan.revision:
            action = RemediationAction(
                incident_id=approval.incident_id,
                approval_id=approval.id,
                action_type="unsupported_capability",
                target=plan.target_resource_id,
            )
            return self._block_unsupported(action, "STALE_OR_MODIFIED_PLAN: plan revision mismatch")

        parameters = {
            **plan.parameters,
            "capability_id": definition.capability_id,
            "capability_version": definition.version,
            "capability_risk_class": definition.risk_class,
            "capability_trust_level": definition.trust_level.value,
            "validation_required": definition.validation_required,
            "plan_id": str(plan.plan_id),
            "plan_revision": plan.revision,
            "plan_hash": snapshot.plan_hash,
            "target_version": plan.target_version,
            "connector_id": plan.connector_id,
            "preconditions": plan.preconditions,
            "expected_effect": plan.expected_effect,
            "blast_radius": plan.blast_radius,
            "dry_run_required": plan.dry_run_required,
            "execution_strategy": plan.execution_strategy.value,
            "validation_plan": plan.validation_plan.model_dump(mode="json"),
            "rollback_plan": plan.rollback_plan.model_dump(mode="json") if plan.rollback_plan else None,
            "risk_assessment": plan.risk_assessment.model_dump(mode="json") if plan.risk_assessment else None,
            "preflight_assessment": (
                plan.preflight_assessment.model_dump(mode="json") if plan.preflight_assessment else None
            ),
            "evidence_ids": plan.evidence_ids,
            "root_cause": plan.root_cause,
            "root_cause_confidence": plan.rca_confidence,
            "evidence_confidence": plan.evidence_confidence,
            "autonomy_recommendation": plan.autonomy_recommendation.value,
            "planning_contract": "structured-remediation-plan-v1",
        }
        return RemediationAction(
            incident_id=approval.incident_id,
            approval_id=approval.id,
            action_type=legacy_action_type,
            target=plan.target_resource_id,
            parameters=parameters,
        )

    def build_action(self, approval: Approval) -> RemediationAction:
        metadata = approval.metadata if isinstance(approval.metadata, dict) else {}
        plan_payload = metadata.get("remediation_plan")
        if isinstance(plan_payload, dict):
            return self._build_from_structured_plan(approval, plan_payload)

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
