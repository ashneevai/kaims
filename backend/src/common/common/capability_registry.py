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
    description: str = ""
    required_permissions: tuple[str, ...] = ()
    input_schema: dict[str, Any] = field(default_factory=dict)
    preconditions: tuple[str, ...] = ()
    dry_run_supported: bool = False
    validation_required: bool = True
    validation_template: dict[str, Any] = field(default_factory=dict)
    rollback_capability: str | None = None
    reversible: bool = False
    allowed_environments: tuple[str, ...] = ("development", "test", "staging", "production")
    maximum_blast_radius: int = 1
    trust_level: CapabilityTrust = CapabilityTrust.HITL_ONLY
    required_approval: bool = True
    execution_timeout_seconds: int = 300
    retry_strategy: str = "none"
    idempotency_strategy: str = "tenant-incident-plan-target"
    max_concurrency_per_target: int = 1


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
        if definition.maximum_blast_radius < 1:
            raise ValueError("maximum_blast_radius must be >= 1")
        if definition.max_concurrency_per_target < 1:
            raise ValueError("max_concurrency_per_target must be >= 1")
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

    def validate_for_target(self, capability_id: str, *, resource_type: str, environment: str) -> CapabilityDefinition:
        definition = self.require(capability_id)
        normalized_resource = str(resource_type or "").strip().lower()
        normalized_environment = str(environment or "").strip().lower()
        supported = {item.lower() for item in definition.supported_resource_types}
        allowed = {item.lower() for item in definition.allowed_environments}
        if normalized_resource not in supported:
            raise ValueError(
                f"CAPABILITY_RESOURCE_MISMATCH: {definition.capability_id} does not support {resource_type}"
            )
        if normalized_environment not in allowed:
            raise ValueError(
                f"CAPABILITY_ENVIRONMENT_DENIED: {definition.capability_id} is not allowed in {environment}"
            )
        return definition

    def _register_defaults(self) -> None:
        defaults = (
            CapabilityDefinition(
                capability_id="kubernetes.restart_workload",
                version="1",
                provider="kubernetes",
                risk_class="medium",
                description="Restart a Kubernetes workload through a deterministic connector operation.",
                supported_resource_types=("workload", "deployment", "statefulset"),
                required_permissions=("kubernetes.workloads.restart",),
                dry_run_supported=True,
                validation_template={"checks": ["workload_ready", "original_alert_cleared"]},
                reversible=False,
                maximum_blast_radius=1,
            ),
            CapabilityDefinition(
                capability_id="kubernetes.rollback_deployment",
                version="1",
                provider="kubernetes",
                risk_class="high",
                description="Rollback a Kubernetes deployment to a verified prior revision.",
                supported_resource_types=("deployment",),
                required_permissions=("kubernetes.deployments.rollback",),
                dry_run_supported=True,
                validation_template={"checks": ["deployment_ready", "service_health", "original_alert_cleared"]},
                rollback_capability="kubernetes.rollback_deployment",
                reversible=True,
                maximum_blast_radius=1,
            ),
            CapabilityDefinition(
                capability_id="kubernetes.scale_workload",
                version="1",
                provider="kubernetes",
                risk_class="medium",
                description="Adjust workload replicas within policy and blast-radius limits.",
                supported_resource_types=("workload", "deployment", "statefulset"),
                required_permissions=("kubernetes.workloads.scale",),
                input_schema={"replicas": {"type": "integer", "minimum": 0}},
                dry_run_supported=True,
                validation_template={"checks": ["desired_replicas_ready", "service_health"]},
                reversible=True,
                maximum_blast_radius=1,
            ),
            CapabilityDefinition(
                capability_id="linux.restart_service",
                version="1",
                provider="ansible",
                risk_class="medium",
                description="Restart an operating-system service through a governed automation connector.",
                supported_resource_types=("host", "vm", "service"),
                required_permissions=("linux.services.restart",),
                validation_template={"checks": ["service_active", "original_alert_cleared"]},
                maximum_blast_radius=1,
            ),
            CapabilityDefinition(
                capability_id="application.invoke_recovery_endpoint",
                version="1",
                provider="api",
                risk_class="medium",
                description="Invoke a pre-registered application recovery endpoint.",
                supported_resource_types=("application", "service", "endpoint"),
                required_permissions=("application.recovery.invoke",),
                validation_template={"checks": ["health_endpoint", "original_alert_cleared"]},
                maximum_blast_radius=1,
            ),
            CapabilityDefinition(
                capability_id="database.collect_diagnostics",
                version="1",
                provider="database",
                risk_class="low",
                description="Collect read-only database diagnostics.",
                supported_resource_types=("database", "database_instance"),
                required_permissions=("database.diagnostics.read",),
                dry_run_supported=False,
                validation_required=False,
                required_approval=False,
                trust_level=CapabilityTrust.TRUSTED,
                retry_strategy="bounded-read-retry",
            ),
            CapabilityDefinition(
                capability_id="database.failover",
                version="1",
                provider="database",
                risk_class="critical",
                description="Fail over a database using provider-specific deterministic controls.",
                supported_resource_types=("database", "database_instance"),
                required_permissions=("database.failover",),
                validation_template={"checks": ["primary_reachable", "replication_healthy", "application_connectivity"]},
                reversible=False,
                maximum_blast_radius=1,
                trust_level=CapabilityTrust.HITL_ONLY,
                required_approval=True,
            ),
            CapabilityDefinition(
                capability_id="jenkins.rollback_deployment",
                version="1",
                provider="jenkins",
                risk_class="high",
                description="Trigger a pre-registered Jenkins deployment rollback job.",
                supported_resource_types=("application", "service", "deployment"),
                required_permissions=("jenkins.deployment.rollback",),
                dry_run_supported=True,
                validation_template={"checks": ["deployment_completed", "service_health"]},
                reversible=True,
                maximum_blast_radius=1,
            ),
            CapabilityDefinition(
                capability_id="terraform.rollback",
                version="1",
                provider="terraform",
                risk_class="critical",
                description="Apply a governed infrastructure rollback plan from an approved state transition.",
                supported_resource_types=("infrastructure", "cloud_resource"),
                required_permissions=("terraform.rollback",),
                dry_run_supported=True,
                validation_template={"checks": ["plan_matches_expected_state", "resource_health"]},
                reversible=True,
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
