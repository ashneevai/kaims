from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

from common.resolution_models import EvidenceMode, ValidationOutcome


def utc_now() -> datetime:
    return datetime.now(UTC)


class ValidationObservation(BaseModel):
    """One independently collected post-action validation observation."""

    model_config = ConfigDict(extra="forbid")

    observation_id: UUID = Field(default_factory=uuid4)
    check_id: str
    provider: str
    source_uri: str | None = None
    resource_id: str | None = None
    observed_at: datetime = Field(default_factory=utc_now)
    retrieved_at: datetime = Field(default_factory=utc_now)
    mode: EvidenceMode = EvidenceMode.LIVE
    value: Any = None
    baseline_value: Any = None
    passed: bool | None = None
    regression: bool = False
    evidence_id: str | None = None
    content_hash: str | None = None
    reason: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def usable_for_production_validation(self) -> bool:
        return self.mode in {EvidenceMode.LIVE, EvidenceMode.DEGRADED}


class ValidationWindowResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    window_index: int = Field(ge=1)
    observed_at: datetime = Field(default_factory=utc_now)
    observations: list[ValidationObservation] = Field(default_factory=list)
    required_checks: int = Field(default=0, ge=0)
    required_passed: int = Field(default=0, ge=0)
    all_required_passed: bool = False
    any_regression: bool = False
    data_available: bool = False
    status: ValidationOutcome = ValidationOutcome.INCONCLUSIVE


class ValidationAssessment(BaseModel):
    """Immutable-style result of a complete stabilization/validation cycle."""

    model_config = ConfigDict(extra="forbid")

    assessment_id: UUID = Field(default_factory=uuid4)
    tenant_id: str | None = None
    incident_id: UUID
    remediation_action_id: UUID
    validation_plan_id: UUID | None = None
    outcome: ValidationOutcome
    started_at: datetime = Field(default_factory=utc_now)
    completed_at: datetime = Field(default_factory=utc_now)
    stabilization_period_seconds: int = Field(default=0, ge=0)
    validation_interval_seconds: int = Field(default=1, ge=1)
    required_consecutive_successes: int = Field(default=1, ge=1)
    consecutive_successes_achieved: int = Field(default=0, ge=0)
    windows: list[ValidationWindowResult] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    reason: str
    next_action: str

    @property
    def recovered(self) -> bool:
        return self.outcome == ValidationOutcome.RECOVERED
