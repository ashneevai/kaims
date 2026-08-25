from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


DEFAULT_MAX_REASSESSMENT_ATTEMPTS = 3


def normalize_action_signature(value: Any) -> str:
    """Normalize an action/capability into a stable comparison signature."""
    return re.sub(r"[^a-z0-9]+", ".", str(value or "").strip().lower()).strip(".")


def _nested(payload: Any, *keys: str) -> Any:
    current = payload
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def _dedupe(values: list[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        token = str(value or "").strip()
        if not token or token in seen:
            continue
        seen.add(token)
        result.append(token)
    return result


def _route_payload(lifecycle_event: dict[str, Any]) -> dict[str, Any]:
    payload = lifecycle_event.get("payload")
    return payload if isinstance(payload, dict) else lifecycle_event


def _source_event(lifecycle_event: dict[str, Any]) -> dict[str, Any]:
    route_payload = _route_payload(lifecycle_event)
    source = route_payload.get("source_payload")
    if isinstance(source, dict):
        return source
    source = lifecycle_event.get("source_event")
    return source if isinstance(source, dict) else {}


@dataclass(frozen=True)
class ReassessmentConstraints:
    incident_id: str
    attempt: int
    max_attempts: int
    excluded_action_signatures: tuple[str, ...]
    rejected_hypotheses: tuple[str, ...]
    previous_remediation_action_ids: tuple[str, ...]
    required_evidence_domains: tuple[str, ...]
    trace_id: str
    correlation_id: str | None
    flow_id: str

    @property
    def exhausted(self) -> bool:
        return self.attempt > self.max_attempts

    def as_dict(self) -> dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "attempt": self.attempt,
            "max_attempts": self.max_attempts,
            "excluded_action_signatures": list(self.excluded_action_signatures),
            "rejected_hypotheses": list(self.rejected_hypotheses),
            "previous_remediation_action_ids": list(self.previous_remediation_action_ids),
            "required_evidence_domains": list(self.required_evidence_domains),
            "trace_id": self.trace_id,
            "correlation_id": self.correlation_id,
            "flow_id": self.flow_id,
        }


def build_reassessment_constraints(
    lifecycle_event: dict[str, Any],
    *,
    prior_attempts: int = 0,
    max_attempts: int = DEFAULT_MAX_REASSESSMENT_ATTEMPTS,
) -> ReassessmentConstraints:
    if not isinstance(lifecycle_event, dict):
        raise ValueError("lifecycle_event must be a mapping")
    if max_attempts < 1:
        raise ValueError("max_attempts must be at least 1")

    route_payload = _route_payload(lifecycle_event)
    incident_id = str(
        lifecycle_event.get("incident_id") or route_payload.get("incident_id") or ""
    ).strip()
    if not incident_id:
        raise ValueError("incident_id is required for reassessment")

    source_event = _source_event(lifecycle_event)
    remediation = source_event.get("remediation_action")
    remediation = remediation if isinstance(remediation, dict) else {}
    report = source_event.get("report")
    report = report if isinstance(report, dict) else {}

    action_candidates = [
        remediation.get("action_type"),
        _nested(remediation, "metadata", "capability"),
        _nested(remediation, "parameters", "recommended_capability"),
        _nested(remediation, "parameters", "recommended_action"),
    ]
    excluded = _dedupe(
        [normalize_action_signature(item) for item in action_candidates if normalize_action_signature(item)]
    )

    root_cause_candidates = [
        report.get("root_cause"),
        _nested(remediation, "parameters", "root_cause"),
        _nested(source_event, "event_contract", "metadata", "root_cause"),
    ]
    rejected_hypotheses = _dedupe([str(item or "").strip() for item in root_cause_candidates])

    previous_action_ids = _dedupe(
        [
            str(route_payload.get("remediation_action_id") or "").strip(),
            str(remediation.get("id") or "").strip(),
        ]
    )

    attempt = max(0, int(prior_attempts)) + 1
    return ReassessmentConstraints(
        incident_id=incident_id,
        attempt=attempt,
        max_attempts=max_attempts,
        excluded_action_signatures=tuple(excluded),
        rejected_hypotheses=tuple(rejected_hypotheses),
        previous_remediation_action_ids=tuple(previous_action_ids),
        required_evidence_domains=(
            "current_metrics",
            "current_logs",
            "current_traces",
            "recent_changes",
            "dependency_health",
            "previous_incident_history",
            "failed_remediation_effect",
        ),
        trace_id=str(route_payload.get("trace_id") or ""),
        correlation_id=str(route_payload.get("correlation_id") or "").strip() or None,
        flow_id=str(route_payload.get("flow_id") or incident_id),
    )


def action_is_excluded(action: Any, constraints: dict[str, Any] | ReassessmentConstraints | None) -> bool:
    if constraints is None:
        return False
    if isinstance(constraints, ReassessmentConstraints):
        excluded = constraints.excluded_action_signatures
    elif isinstance(constraints, dict):
        excluded = tuple(str(item) for item in constraints.get("excluded_action_signatures", []))
    else:
        return False
    signature = normalize_action_signature(action)
    if not signature:
        return False
    return signature in {normalize_action_signature(item) for item in excluded}
