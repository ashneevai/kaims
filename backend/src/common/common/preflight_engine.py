from __future__ import annotations

from dataclasses import dataclass

from common.capability_registry import CapabilityDefinition
from common.resolution_models import PreflightAssessment, RemediationPlan
from common.target_resolution import ResolvedTarget


@dataclass(slots=True)
class PreflightInputs:
    connector_available: bool
    credentials_valid: bool
    permissions_sufficient: bool
    preconditions_hold: bool
    incident_still_active: bool = True
    conflicting_remediation: bool = False
    change_freeze_active: bool = False


class PreflightEngine:
    """Deterministic gate executed before policy/approval or autonomous execution."""

    def assess(
        self,
        *,
        plan: RemediationPlan,
        capability: CapabilityDefinition,
        target: ResolvedTarget,
        inputs: PreflightInputs,
    ) -> PreflightAssessment:
        failures: list[str] = []

        environment_allowed = target.environment.lower() in {
            value.lower() for value in capability.allowed_environments
        }
        resource_type_supported = target.resource_type.lower() in {
            value.lower() for value in capability.supported_resource_types
        }
        target_version_current = not plan.target_version or plan.target_version == target.current_version
        rollback_available = bool(plan.rollback_plan and plan.rollback_plan.available)
        validation_available = bool(plan.validation_plan and plan.validation_plan.checks)

        if not target.resource_id.startswith("kai://") or target.confidence < 0.9:
            failures.append("TARGET_IDENTITY_UNCERTAIN")
        if not target_version_current:
            failures.append("STALE_PLAN")
        if not inputs.connector_available:
            failures.append("CONNECTOR_UNAVAILABLE")
        if not inputs.credentials_valid:
            failures.append("CREDENTIALS_INVALID")
        if not inputs.permissions_sufficient:
            failures.append("PERMISSION_INSUFFICIENT")
        if not resource_type_supported:
            failures.append("CAPABILITY_RESOURCE_MISMATCH")
        if not environment_allowed:
            failures.append("CAPABILITY_ENVIRONMENT_DENIED")
        if not inputs.preconditions_hold:
            failures.append("PRECONDITION_FAILED")
        if not inputs.incident_still_active:
            failures.append("INCIDENT_NO_LONGER_ACTIVE")
        if inputs.conflicting_remediation:
            failures.append("CONFLICTING_REMEDIATION")
        if inputs.change_freeze_active:
            failures.append("CHANGE_FREEZE_ACTIVE")
        if capability.validation_required and not validation_available:
            failures.append("VALIDATION_UNAVAILABLE")
        if capability.risk_class.lower() in {"high", "critical"} and capability.reversible and not rollback_available:
            failures.append("ROLLBACK_UNAVAILABLE")

        return PreflightAssessment(
            passed=not failures,
            target_identity_verified=target.resource_id.startswith("kai://") and target.confidence >= 0.9,
            connector_available=inputs.connector_available,
            credentials_valid=inputs.credentials_valid,
            permissions_sufficient=inputs.permissions_sufficient,
            capability_supported=resource_type_supported and environment_allowed,
            preconditions_hold=inputs.preconditions_hold,
            rollback_available=rollback_available,
            validation_available=validation_available,
            incident_still_active=inputs.incident_still_active,
            target_version_current=target_version_current,
            environment_allowed=environment_allowed,
            resource_type_supported=resource_type_supported,
            conflicting_remediation=inputs.conflicting_remediation,
            change_freeze_active=inputs.change_freeze_active,
            failures=failures,
        )
