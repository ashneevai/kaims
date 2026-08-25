from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class CapabilityTrust(StrEnum):
    EXPERIMENTAL = "EXPERIMENTAL"
    HITL_ONLY = "HITL_ONLY"
    TRUSTED = "TRUSTED"
    AUTONOMOUS = "AUTONOMOUS"


@dataclass(frozen=True, slots=True)
class CapabilityDefinition:
    capability_id: str
    version: str
    provider: str
    risk_class: str
    supported_resource_types: tuple[str, ...]
    required_permissions: tuple[str, ...] = ()
    input_schema: dict[str, Any] = field(default_factory=dict)
    preconditions: tuple[str, ...] = ()
    dry_run_supported: bool = False
    validation_required: bool = True
    rollback_capability: str | None = None
    allowed_environments: tuple[str, ...] = ("development", "test", "staging", "production")
    maximum_blast_radius: int = 1
    trust_level: CapabilityTrust = CapabilityTrust.HITL_ONLY
    required_approval: bool = True


class CapabilityRegistry:
    """Authoritative allowlist for deterministic operational capabilities."""

    def __init__(self) -> None:
        self._definitions: dict[str, CapabilityDefinition] = {}
        self._register_defaults()

    def register(self, definition: CapabilityDefinition) -> None:
        capability_id = str(definition.capability_id or "").strip().lower()
        if not capability_id:
            raise ValueError("capability_id is required")
        if capability_id in self._definitions:
            raise ValueError(f"capability already registered: {capability_id}")
        self._definitions[capability_id] = definition

    def get(self, capability_id: str) -> CapabilityDefinition | None:
        return self._definitions.get(str(capability_id or "").strip().lower())

    def require(self, capability_id: str) -> CapabilityDefinition:
        definition = self.get(capability_id)
        if definition is None:
            raise ValueError(f"UNSUPPORTED_CAPABILITY: {capability_id}")
        return definition

    def is_registered(self, capability_id: str) -> bool:
        return self.get(capability_id) is not None

    def list(self) -> list[CapabilityDefinition]:
        return list(self._definitions.values())

    def _register_defaults(self) -> None:
        defaults = (
            CapabilityDefinition(
                capability_id="kubernetes.restart_workload",
                version="1",
                provider="kubernetes",
                risk_class="medium",
                supported_resource_types=("workload", "deployment", "statefulset"),
                required_permissions=("kubernetes.workloads.restart",),
                dry_run_supported=True,
                maximum_blast_radius=1,
            ),
            CapabilityDefinition(
                capability_id="kubernetes.rollback_deployment",
                version="1",
                provider="kubernetes",
                risk_class="high",
                supported_resource_types=("deployment",),
                required_permissions=("kubernetes.deployments.rollback",),
                dry_run_supported=True,
                maximum_blast_radius=1,
            ),
            CapabilityDefinition(
                capability_id="kubernetes.scale_workload",
                version="1",
                provider="kubernetes",
                risk_class="medium",
                supported_resource_types=("workload", "deployment", "statefulset"),
                required_permissions=("kubernetes.workloads.scale",),
                dry_run_supported=True,
                maximum_blast_radius=1,
            ),
            CapabilityDefinition(
                capability_id="linux.restart_service",
                version="1",
                provider="ansible",
                risk_class="medium",
                supported_resource_types=("host", "vm", "service"),
                required_permissions=("linux.services.restart",),
                maximum_blast_radius=1,
            ),
            CapabilityDefinition(
                capability_id="application.invoke_recovery_endpoint",
                version="1",
                provider="api",
                risk_class="medium",
                supported_resource_types=("application", "service", "endpoint"),
                required_permissions=("application.recovery.invoke",),
                maximum_blast_radius=1,
            ),
            CapabilityDefinition(
                capability_id="database.collect_diagnostics",
                version="1",
                provider="database",
                risk_class="low",
                supported_resource_types=("database", "database_instance"),
                required_permissions=("database.diagnostics.read",),
                dry_run_supported=False,
                validation_required=False,
                required_approval=False,
                trust_level=CapabilityTrust.TRUSTED,
            ),
            CapabilityDefinition(
                capability_id="database.failover",
                version="1",
                provider="database",
                risk_class="critical",
                supported_resource_types=("database", "database_instance"),
                required_permissions=("database.failover",),
                maximum_blast_radius=1,
                trust_level=CapabilityTrust.HITL_ONLY,
                required_approval=True,
            ),
            CapabilityDefinition(
                capability_id="jenkins.rollback_deployment",
                version="1",
                provider="jenkins",
                risk_class="high",
                supported_resource_types=("application", "service", "deployment"),
                required_permissions=("jenkins.deployment.rollback",),
                dry_run_supported=True,
                maximum_blast_radius=1,
            ),
            CapabilityDefinition(
                capability_id="terraform.rollback",
                version="1",
                provider="terraform",
                risk_class="critical",
                supported_resource_types=("infrastructure", "cloud_resource"),
                required_permissions=("terraform.rollback",),
                dry_run_supported=True,
                maximum_blast_radius=1,
                trust_level=CapabilityTrust.HITL_ONLY,
                required_approval=True,
            ),
        )
        for definition in defaults:
            self.register(definition)


LEGACY_ACTION_CAPABILITIES: dict[str, str] = {
    "restart_pod": "kubernetes.restart_workload",
    "scale_deployment": "kubernetes.scale_workload",
    "rollback_deployment": "jenkins.rollback_deployment",
    "restart_service": "linux.restart_service",
    "api_execution": "application.invoke_recovery_endpoint",
    "terraform_rollback": "terraform.rollback",
    "failover_database": "database.failover",
}
