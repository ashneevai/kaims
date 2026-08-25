from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


class TargetResolutionError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class ResolvedTarget:
    resource_id: str
    tenant_id: str
    project_id: str
    application_id: str
    environment: str
    provider: str
    account_id: str | None
    region: str | None
    resource_type: str
    resource_name: str
    resource_uid: str
    current_version: str | None
    connector_id: str
    confidence: float
    relationship_source: str = "verified"
    metadata: dict[str, Any] = field(default_factory=dict)


class ResourceLookup(Protocol):
    def get_resource(self, resource_id: str) -> dict[str, Any] | None: ...


@dataclass(slots=True)
class DictResourceLookup:
    resources: dict[str, dict[str, Any]]

    def get_resource(self, resource_id: str) -> dict[str, Any] | None:
        value = self.resources.get(resource_id)
        return dict(value) if isinstance(value, dict) else None


class TargetResolver:
    """Fail-closed resolver for execution-grade stable resource identities.

    Display names and free-form command text are never accepted as execution identity.
    The initial implementation uses an injected lookup; the Operational Digital Twin
    repository can satisfy the same interface as it is migrated in.
    """

    def __init__(self, lookup: ResourceLookup) -> None:
        self.lookup = lookup

    def resolve(self, *, resource_id: str, connector_id: str, expected_version: str | None = None) -> ResolvedTarget:
        token = str(resource_id or "").strip()
        if not token.startswith("kai://"):
            raise TargetResolutionError("TARGET_IDENTITY_UNCERTAIN: stable kai:// resource id is required")
        payload = self.lookup.get_resource(token)
        if not payload:
            raise TargetResolutionError(f"TARGET_NOT_FOUND: {token}")

        source_type = str(payload.get("source_type") or payload.get("relationship_source") or "verified").strip().lower()
        confidence = float(payload.get("confidence") or 0.0)
        stale = bool(payload.get("stale"))
        if source_type in {"inferred", "unknown"} or confidence < 0.9 or stale:
            raise TargetResolutionError("TARGET_IDENTITY_UNCERTAIN: target is inferred, stale, or low confidence")

        current_version = str(payload.get("current_version") or payload.get("version") or "").strip() or None
        if expected_version and current_version != str(expected_version):
            raise TargetResolutionError("STALE_PLAN: target version changed after planning")

        required = {
            "tenant_id": payload.get("tenant_id"),
            "project_id": payload.get("project_id"),
            "application_id": payload.get("application_id"),
            "environment": payload.get("environment"),
            "provider": payload.get("provider"),
            "resource_type": payload.get("resource_type"),
            "resource_name": payload.get("resource_name"),
            "resource_uid": payload.get("resource_uid"),
        }
        missing = [name for name, value in required.items() if not str(value or "").strip()]
        if missing:
            raise TargetResolutionError(f"TARGET_IDENTITY_UNCERTAIN: missing {', '.join(missing)}")

        configured_connector = str(payload.get("connector_id") or "").strip()
        if configured_connector and configured_connector != str(connector_id or "").strip():
            raise TargetResolutionError("TARGET_CONNECTOR_MISMATCH")

        return ResolvedTarget(
            resource_id=token,
            tenant_id=str(required["tenant_id"]),
            project_id=str(required["project_id"]),
            application_id=str(required["application_id"]),
            environment=str(required["environment"]),
            provider=str(required["provider"]),
            account_id=str(payload.get("account_id") or "").strip() or None,
            region=str(payload.get("region") or "").strip() or None,
            resource_type=str(required["resource_type"]),
            resource_name=str(required["resource_name"]),
            resource_uid=str(required["resource_uid"]),
            current_version=current_version,
            connector_id=str(connector_id),
            confidence=confidence,
            relationship_source=source_type,
            metadata={key: value for key, value in payload.items() if key not in required},
        )
