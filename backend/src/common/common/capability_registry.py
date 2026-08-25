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

    def validate_parameters(self, capability_id: str, parameters: dict[str, Any]) -> None:
        """Small deterministic schema gate; connectors remain responsible for full validation."""
        definition = self.require(capability_id)
        schema = definition.input_schema if isinstance(definition.input_schema, dict) else {}
        for name, rule in schema.items():
            if not isinstance(rule, dict):
                continue
            required = bool(rule.get("required"))
            if required and name not in parameters:
                raise ValueError(f"CAPABILITY_PARAMETER_REQUIRED: {name}")
            if name not in parameters:
                continue
            value = parameters[name]
            expected = rule.get("type")
            if expected == "integer" and (not isinstance(value, int) or isinstance(value, bool)):
                raise ValueError(f"CAPABILITY_PARAMETER_INVALID: {name} must be integer")
            if expected == "string" and not isinstance(value, str):
                raise ValueError(f"CAPABILITY_PARAMETER_INVALID: {name} must be string")
            if expected == "boolean" and not isinstance(value, bool):
                raise ValueError(f"CAPABILITY_PARAMETER_INVALID: {name} must be boolean")
            if isinstance(value, (int, float)):
                if "minimum" in rule and value < rule["minimum"]:
                    raise ValueError(f"CAPABILITY_PARAMETER_INVALID: {name} below minimum")
                if "maximum" in rule and value > rule["maximum"]:
                    raise ValueError(f"CAPABILITY_PARAMETER_INVALID: {name} above maximum")

    @staticmethod
    def _definition(
        capability_id: str,
        provider: str,
        risk_class: str,
        resource_types: tuple[str, ...],
        description: str,
        permission: str,
        checks: tuple[str, ...],
        **kwargs: Any,
    ) -> CapabilityDefinition:
        return CapabilityDefinition(
            capability_id=capability_id,
            version="1",
            provider=provider,
            risk_class=risk_class,
            supported_resource_types=resource_types,
            description=description,
            required_permissions=(permission,),
            validation_template={"checks": list(checks)},
            **kwargs,
        )

    def _register_defaults(self) -> None:
        d = self._definition
        defaults = (
            d("kubernetes.restart_workload", "kubernetes", "medium", ("workload", "deployment", "statefulset"), "Restart a Kubernetes workload through a deterministic connector operation.", "kubernetes.workloads.restart", ("workload_ready", "original_alert_cleared"), dry_run_supported=True),
            d("kubernetes.rollback_deployment", "kubernetes", "high", ("deployment",), "Rollback a Kubernetes deployment to a verified prior revision.", "kubernetes.deployments.rollback", ("deployment_ready", "service_health", "original_alert_cleared"), input_schema={"revision": {"type": "string", "required": True}}, dry_run_supported=True, rollback_capability="kubernetes.rollback_deployment", reversible=True),
            d("kubernetes.scale_workload", "kubernetes", "medium", ("workload", "deployment", "statefulset"), "Adjust workload replicas within policy and blast-radius limits.", "kubernetes.workloads.scale", ("desired_replicas_ready", "service_health"), input_schema={"replicas": {"type": "integer", "minimum": 0, "required": True}}, dry_run_supported=True, reversible=True),
            d("linux.restart_service", "ansible", "medium", ("host", "vm", "service"), "Restart an operating-system service through governed automation.", "linux.services.restart", ("service_active", "original_alert_cleared"), input_schema={"service_name": {"type": "string", "required": True}}),
            d("windows.restart_service", "powershell", "medium", ("host", "vm", "service"), "Restart a Windows service through a governed connector.", "windows.services.restart", ("service_running", "original_alert_cleared"), input_schema={"service_name": {"type": "string", "required": True}}),
            d("application.invoke_recovery_endpoint", "api", "medium", ("application", "service", "endpoint"), "Invoke a pre-registered application recovery endpoint.", "application.recovery.invoke", ("health_endpoint", "original_alert_cleared")),
            d("database.collect_diagnostics", "database", "low", ("database", "database_instance"), "Collect read-only database diagnostics.", "database.diagnostics.read", (), validation_required=False, required_approval=False, trust_level=CapabilityTrust.TRUSTED, retry_strategy="bounded-read-retry"),
            d("database.kill_session", "database", "high", ("database", "database_instance"), "Terminate a verified database session after policy approval.", "database.sessions.kill", ("session_absent", "database_health"), input_schema={"session_id": {"type": "string", "required": True}}, reversible=False),
            d("database.failover", "database", "critical", ("database", "database_instance"), "Fail over a database using provider-specific deterministic controls.", "database.failover", ("primary_reachable", "replication_healthy", "application_connectivity"), reversible=False, trust_level=CapabilityTrust.HITL_ONLY, required_approval=True),
            d("kafka.restart_consumer", "kafka", "medium", ("consumer", "consumer_group", "application", "service"), "Restart a registered Kafka consumer workload.", "kafka.consumers.restart", ("consumer_running", "lag_recovering"), dry_run_supported=True),
            d("kafka.rebalance", "kafka", "high", ("consumer_group", "topic"), "Trigger a governed Kafka consumer rebalance.", "kafka.consumer_groups.rebalance", ("assignments_stable", "lag_recovering"), dry_run_supported=True),
            d("airflow.retry_task", "airflow", "medium", ("task", "task_instance", "pipeline", "dag"), "Retry a failed Airflow task instance.", "airflow.tasks.retry", ("task_succeeded", "downstream_healthy"), input_schema={"dag_id": {"type": "string", "required": True}, "task_id": {"type": "string", "required": True}}),
            d("airflow.restart_dag", "airflow", "high", ("pipeline", "dag"), "Restart a governed Airflow DAG run.", "airflow.dags.restart", ("dag_running", "critical_tasks_healthy"), input_schema={"dag_id": {"type": "string", "required": True}}),
            d("cloud.restart_vm", "cloud", "high", ("vm",), "Restart a verified cloud virtual machine.", "cloud.vm.restart", ("vm_running", "service_health", "original_alert_cleared"), dry_run_supported=True),
            d("cloud.scale_instance_group", "cloud", "high", ("instance_group", "autoscaling_group"), "Adjust a registered cloud instance group within policy limits.", "cloud.instance_groups.scale", ("desired_capacity_healthy", "service_health"), input_schema={"capacity": {"type": "integer", "minimum": 0, "required": True}}, dry_run_supported=True, reversible=True),
            d("cache.invalidate_keyspace", "cache", "high", ("cache", "redis", "keyspace"), "Invalidate an explicitly scoped registered cache keyspace; never performs unrestricted FLUSHDB.", "cache.keyspace.invalidate", ("application_health",), input_schema={"keyspace": {"type": "string", "required": True}}, reversible=False),
            d("jenkins.rollback_deployment", "jenkins", "high", ("application", "service", "deployment"), "Trigger a pre-registered Jenkins deployment rollback job.", "jenkins.deployment.rollback", ("deployment_completed", "service_health"), input_schema={"job": {"type": "string", "required": True}, "revision": {"type": "string", "required": True}}, dry_run_supported=True, reversible=True),
            d("terraform.rollback", "terraform", "critical", ("infrastructure", "cloud_resource"), "Apply a governed infrastructure rollback plan from an approved state transition.", "terraform.rollback", ("plan_matches_expected_state", "resource_health"), input_schema={"approved_plan_ref": {"type": "string", "required": True}}, dry_run_supported=True, reversible=True, trust_level=CapabilityTrust.HITL_ONLY, required_approval=True),
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
