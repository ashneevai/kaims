from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class EvidenceMode(StrEnum):
    LIVE = "LIVE"
    SIMULATION = "SIMULATION"
    DEGRADED = "DEGRADED"
    UNAVAILABLE = "UNAVAILABLE"


class EvidenceType(StrEnum):
    ALERT = "ALERT"
    METRIC = "METRIC"
    LOG = "LOG"
    TRACE = "TRACE"
    SLO = "SLO"
    SYNTHETIC = "SYNTHETIC"
    TOPOLOGY = "TOPOLOGY"
    CHANGE = "CHANGE"
    DEPLOYMENT = "DEPLOYMENT"
    CODE = "CODE"
    TICKET = "TICKET"
    RUNBOOK = "RUNBOOK"
    PAST_INCIDENT = "PAST_INCIDENT"
    DATABASE = "DATABASE"
    KUBERNETES = "KUBERNETES"
    CLOUD = "CLOUD"
    NETWORK = "NETWORK"
    BUSINESS_SIGNAL = "BUSINESS_SIGNAL"


class EvidenceTrust(StrEnum):
    VERIFIED = "VERIFIED"
    DISCOVERED = "DISCOVERED"
    CORRELATED = "CORRELATED"
    INFERRED = "INFERRED"
    UNTRUSTED = "UNTRUSTED"


class HypothesisStatus(StrEnum):
    PROPOSED = "PROPOSED"
    SUPPORTED = "SUPPORTED"
    WEAKENED = "WEAKENED"
    CONTRADICTED = "CONTRADICTED"
    FALSIFIED = "FALSIFIED"
    CONFIRMED = "CONFIRMED"
    UNRESOLVED = "UNRESOLVED"


class InvestigationStatus(StrEnum):
    INVESTIGATING = "INVESTIGATING"
    EVIDENCE_INCOMPLETE = "EVIDENCE_INCOMPLETE"
    DIAGNOSED = "DIAGNOSED"
    INCONCLUSIVE = "INCONCLUSIVE"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"


class InvestigationConclusionStatus(StrEnum):
    CONFIRMED = "CONFIRMED"
    LIKELY = "LIKELY"
    INCONCLUSIVE = "INCONCLUSIVE"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"


class Evidence(BaseModel):
    """Canonical, provenance-bearing observation used by investigation and RCA."""

    model_config = ConfigDict(extra="forbid")

    evidence_id: UUID = Field(default_factory=uuid4)
    tenant_id: str
    incident_id: UUID
    resource_id: str | None = None
    provider: str
    evidence_type: EvidenceType
    source_uri: str | None = None
    query: str | None = None
    observed_at: datetime
    retrieved_at: datetime = Field(default_factory=utc_now)
    freshness_seconds: int = Field(default=0, ge=0)
    quality_score: float = Field(default=1.0, ge=0.0, le=1.0)
    trust_level: EvidenceTrust = EvidenceTrust.DISCOVERED
    mode: EvidenceMode = EvidenceMode.LIVE
    content_hash: str
    summary: str
    raw_reference: str | None = None
    access_classification: str = "INTERNAL"
    metadata: dict[str, Any] = Field(default_factory=dict)

    @staticmethod
    def hash_content(content: Any) -> str:
        canonical = json.dumps(content, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    @property
    def usable_for_production_rca(self) -> bool:
        return self.mode in {EvidenceMode.LIVE, EvidenceMode.DEGRADED} and self.trust_level != EvidenceTrust.UNTRUSTED


class EvidenceAssessment(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evidence_id: UUID
    supports: bool = False
    contradicts: bool = False
    relevance: float = Field(default=0.0, ge=0.0, le=1.0)
    explanation: str


class CausalRelationship(BaseModel):
    model_config = ConfigDict(extra="forbid")

    relationship_id: UUID = Field(default_factory=uuid4)
    source_resource_id: str
    target_resource_id: str
    relationship: str
    evidence_ids: list[UUID] = Field(default_factory=list)
    observed: bool = False
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    contradicting_evidence_ids: list[UUID] = Field(default_factory=list)


class Hypothesis(BaseModel):
    model_config = ConfigDict(extra="forbid")

    hypothesis_id: UUID = Field(default_factory=uuid4)
    incident_id: UUID
    statement: str
    status: HypothesisStatus = HypothesisStatus.PROPOSED
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    supporting_evidence_ids: list[UUID] = Field(default_factory=list)
    contradicting_evidence_ids: list[UUID] = Field(default_factory=list)
    affected_resource_ids: list[str] = Field(default_factory=list)
    causal_path: list[CausalRelationship] = Field(default_factory=list)
    recommended_next_diagnostic: str | None = None
    data_gaps: list[str] = Field(default_factory=list)


class InvestigationIteration(BaseModel):
    model_config = ConfigDict(extra="forbid")

    iteration: int = Field(ge=1)
    started_at: datetime = Field(default_factory=utc_now)
    completed_at: datetime | None = None
    evidence_ids_added: list[UUID] = Field(default_factory=list)
    hypothesis_ids_evaluated: list[UUID] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class InvestigationConclusion(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: InvestigationConclusionStatus
    primary_hypothesis_id: UUID | None = None
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    supporting_evidence_ids: list[UUID] = Field(default_factory=list)
    contradicting_evidence_ids: list[UUID] = Field(default_factory=list)
    alternative_hypothesis_ids: list[UUID] = Field(default_factory=list)
    data_gaps: list[str] = Field(default_factory=list)
    rationale: str


class Investigation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    investigation_id: UUID = Field(default_factory=uuid4)
    tenant_id: str
    incident_id: UUID
    status: InvestigationStatus = InvestigationStatus.INVESTIGATING
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    evidence_ids: list[UUID] = Field(default_factory=list)
    hypotheses: list[Hypothesis] = Field(default_factory=list)
    iterations: list[InvestigationIteration] = Field(default_factory=list)
    conclusion: InvestigationConclusion | None = None
    max_iterations: int = Field(default=6, ge=1)
    max_connector_queries: int = Field(default=30, ge=1)
    max_llm_calls: int = Field(default=12, ge=1)
    max_cost_usd: float = Field(default=1.0, ge=0.0)


class AutonomyRecommendation(StrEnum):
    OBSERVE_ONLY = "OBSERVE_ONLY"
    RECOMMEND = "RECOMMEND"
    HITL_REQUIRED = "HITL_REQUIRED"
    AUTO_EXECUTE = "AUTO_EXECUTE"


class ValidationOutcome(StrEnum):
    RECOVERED = "RECOVERED"
    PARTIALLY_RECOVERED = "PARTIALLY_RECOVERED"
    UNCHANGED = "UNCHANGED"
    WORSE = "WORSE"
    INCONCLUSIVE = "INCONCLUSIVE"
    VALIDATION_DATA_UNAVAILABLE = "VALIDATION_DATA_UNAVAILABLE"


class ExecutionStrategy(StrEnum):
    SINGLE = "SINGLE"
    CANARY = "CANARY"
    PROGRESSIVE = "PROGRESSIVE"
    BATCH = "BATCH"
    FULL = "FULL"


class ValidationCheck(BaseModel):
    model_config = ConfigDict(extra="forbid")

    check_id: str
    provider: str
    signal: str
    operator: str
    expected_value: Any
    resource_id: str | None = None
    required: bool = True


class ValidationPlan(BaseModel):
    model_config = ConfigDict(extra="forbid")

    plan_id: UUID = Field(default_factory=uuid4)
    baseline_window_seconds: int = Field(default=300, ge=0)
    stabilization_period_seconds: int = Field(default=60, ge=0)
    validation_interval_seconds: int = Field(default=30, ge=1)
    max_validation_window_seconds: int = Field(default=300, ge=1)
    required_consecutive_successes: int = Field(default=3, ge=1)
    checks: list[ValidationCheck] = Field(default_factory=list)


class RollbackPlan(BaseModel):
    model_config = ConfigDict(extra="forbid")

    plan_id: UUID = Field(default_factory=uuid4)
    capability_id: str | None = None
    target_resource_id: str | None = None
    parameters: dict[str, Any] = Field(default_factory=dict)
    pre_action_state: dict[str, Any] = Field(default_factory=dict)
    available: bool = False


class RiskAssessment(BaseModel):
    model_config = ConfigDict(extra="forbid")

    assessment_id: UUID = Field(default_factory=uuid4)
    risk_score: float = Field(ge=0.0, le=1.0)
    risk_class: str
    capability_risk: float = Field(default=0.0, ge=0.0, le=1.0)
    environment_criticality: float = Field(default=0.0, ge=0.0, le=1.0)
    blast_radius_risk: float = Field(default=0.0, ge=0.0, le=1.0)
    rca_uncertainty: float = Field(default=0.0, ge=0.0, le=1.0)
    target_criticality: float = Field(default=0.0, ge=0.0, le=1.0)
    rollback_difficulty: float = Field(default=0.0, ge=0.0, le=1.0)
    previous_failure_risk: float = Field(default=0.0, ge=0.0, le=1.0)
    data_loss_risk: float = Field(default=0.0, ge=0.0, le=1.0)
    privilege_risk: float = Field(default=0.0, ge=0.0, le=1.0)
    reasons: list[str] = Field(default_factory=list)


class PreflightAssessment(BaseModel):
    model_config = ConfigDict(extra="forbid")

    assessment_id: UUID = Field(default_factory=uuid4)
    passed: bool
    target_identity_verified: bool = False
    connector_available: bool = False
    credentials_valid: bool = False
    permissions_sufficient: bool = False
    capability_supported: bool = False
    preconditions_hold: bool = False
    rollback_available: bool = False
    validation_available: bool = False
    incident_still_active: bool = True
    target_version_current: bool = True
    environment_allowed: bool = False
    resource_type_supported: bool = False
    conflicting_remediation: bool = False
    change_freeze_active: bool = False
    failures: list[str] = Field(default_factory=list)


class RemediationPlan(BaseModel):
    model_config = ConfigDict(extra="forbid")

    plan_id: UUID = Field(default_factory=uuid4)
    revision: int = Field(default=1, ge=1)
    incident_id: UUID
    hypothesis_id: str | None = None
    root_cause: str
    rca_confidence: float = Field(ge=0.0, le=1.0)
    evidence_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    affected_resource_ids: list[str] = Field(default_factory=list)
    recommended_capability: str
    target_resource_id: str
    target_version: str | None = None
    connector_id: str
    parameters: dict[str, Any] = Field(default_factory=dict)
    preconditions: list[str] = Field(default_factory=list)
    expected_effect: str
    blast_radius: dict[str, Any] = Field(default_factory=dict)
    dry_run_required: bool = True
    execution_strategy: ExecutionStrategy = ExecutionStrategy.SINGLE
    validation_plan: ValidationPlan
    rollback_plan: RollbackPlan | None = None
    risk_assessment: RiskAssessment | None = None
    preflight_assessment: PreflightAssessment | None = None
    evidence_ids: list[str] = Field(default_factory=list)
    autonomy_recommendation: AutonomyRecommendation = AutonomyRecommendation.HITL_REQUIRED

    def canonical_payload(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude_none=False)

    def canonical_json(self) -> str:
        return json.dumps(
            self.canonical_payload(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )

    def plan_hash(self) -> str:
        return hashlib.sha256(self.canonical_json().encode("utf-8")).hexdigest()


class PlanSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid")

    plan_id: UUID
    plan_revision: int
    plan_hash: str
    canonical_plan: dict[str, Any]

    @classmethod
    def from_plan(cls, plan: RemediationPlan) -> "PlanSnapshot":
        return cls(
            plan_id=plan.plan_id,
            plan_revision=plan.revision,
            plan_hash=plan.plan_hash(),
            canonical_plan=plan.canonical_payload(),
        )

    def verifies(self, plan: RemediationPlan) -> bool:
        return (
            self.plan_id == plan.plan_id
            and self.plan_revision == plan.revision
            and self.plan_hash == plan.plan_hash()
        )
