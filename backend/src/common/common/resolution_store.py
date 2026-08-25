from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from common.resolution_models import Evidence, Investigation, PlanSnapshot, RemediationPlan
from common.validation_models import ValidationAssessment


def _utc_iso() -> str:
    return datetime.now(UTC).isoformat()


def _json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


@dataclass(slots=True)
class CanonicalResolutionStore:
    """Durable system-of-record adapter for canonical resolution lifecycle objects."""

    session: AsyncSession

    async def ensure_schema(self) -> None:
        await self.session.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS canonical_resolution_objects (
                    object_type VARCHAR(64) NOT NULL,
                    object_id VARCHAR(128) NOT NULL,
                    tenant_id VARCHAR(128) NOT NULL,
                    incident_id VARCHAR(128),
                    revision INTEGER NOT NULL DEFAULT 1,
                    content_hash VARCHAR(128),
                    payload TEXT NOT NULL,
                    created_at VARCHAR(64) NOT NULL,
                    updated_at VARCHAR(64) NOT NULL,
                    PRIMARY KEY (object_type, object_id, revision)
                )
                """
            )
        )
        await self.session.execute(
            text(
                "CREATE INDEX IF NOT EXISTS idx_resolution_incident "
                "ON canonical_resolution_objects (tenant_id, incident_id, object_type)"
            )
        )

    async def _put(
        self,
        *,
        object_type: str,
        object_id: str,
        tenant_id: str,
        incident_id: str | None,
        payload: dict[str, Any],
        revision: int = 1,
        content_hash: str | None = None,
    ) -> None:
        if not str(tenant_id or "").strip():
            raise ValueError("TENANT_CONTEXT_MISSING")
        await self.ensure_schema()
        now = _utc_iso()
        existing = await self.session.execute(
            text(
                "SELECT created_at FROM canonical_resolution_objects "
                "WHERE object_type=:object_type AND object_id=:object_id AND revision=:revision"
            ),
            {"object_type": object_type, "object_id": object_id, "revision": revision},
        )
        row = existing.first()
        if row:
            await self.session.execute(
                text(
                    "UPDATE canonical_resolution_objects SET tenant_id=:tenant_id, incident_id=:incident_id, "
                    "content_hash=:content_hash, payload=:payload, updated_at=:updated_at "
                    "WHERE object_type=:object_type AND object_id=:object_id AND revision=:revision"
                ),
                {
                    "tenant_id": tenant_id,
                    "incident_id": incident_id,
                    "content_hash": content_hash,
                    "payload": _json(payload),
                    "updated_at": now,
                    "object_type": object_type,
                    "object_id": object_id,
                    "revision": revision,
                },
            )
        else:
            await self.session.execute(
                text(
                    "INSERT INTO canonical_resolution_objects "
                    "(object_type, object_id, tenant_id, incident_id, revision, content_hash, payload, created_at, updated_at) "
                    "VALUES (:object_type, :object_id, :tenant_id, :incident_id, :revision, :content_hash, :payload, :created_at, :updated_at)"
                ),
                {
                    "object_type": object_type,
                    "object_id": object_id,
                    "tenant_id": tenant_id,
                    "incident_id": incident_id,
                    "revision": revision,
                    "content_hash": content_hash,
                    "payload": _json(payload),
                    "created_at": now,
                    "updated_at": now,
                },
            )

    async def save_evidence(self, evidence: Evidence) -> None:
        await self._put(
            object_type="evidence",
            object_id=str(evidence.evidence_id),
            tenant_id=evidence.tenant_id,
            incident_id=str(evidence.incident_id),
            payload=evidence.model_dump(mode="json"),
            content_hash=evidence.content_hash,
        )

    async def save_investigation(self, investigation: Investigation) -> None:
        await self._put(
            object_type="investigation",
            object_id=str(investigation.investigation_id),
            tenant_id=investigation.tenant_id,
            incident_id=str(investigation.incident_id),
            payload=investigation.model_dump(mode="json"),
        )

    async def save_plan(self, *, tenant_id: str, plan: RemediationPlan, snapshot: PlanSnapshot) -> None:
        if snapshot.plan_id != plan.plan_id or not snapshot.verifies(plan):
            raise ValueError("PLAN_SNAPSHOT_MISMATCH")
        await self._put(
            object_type="remediation_plan",
            object_id=str(plan.plan_id),
            tenant_id=tenant_id,
            incident_id=str(plan.incident_id),
            revision=plan.revision,
            content_hash=snapshot.plan_hash,
            payload=plan.model_dump(mode="json"),
        )
        await self._put(
            object_type="plan_snapshot",
            object_id=str(snapshot.plan_id),
            tenant_id=tenant_id,
            incident_id=str(plan.incident_id),
            revision=snapshot.plan_revision,
            content_hash=snapshot.plan_hash,
            payload=snapshot.model_dump(mode="json"),
        )

    async def save_validation_assessment(self, assessment: ValidationAssessment) -> None:
        tenant_id = str(assessment.tenant_id or "").strip()
        if not tenant_id:
            raise ValueError("TENANT_CONTEXT_MISSING: validation assessment requires tenant scope")
        await self._put(
            object_type="validation_assessment",
            object_id=str(assessment.assessment_id),
            tenant_id=tenant_id,
            incident_id=str(assessment.incident_id),
            payload=assessment.model_dump(mode="json"),
        )

    async def load_latest_plan(self, *, tenant_id: str, plan_id: UUID | str) -> RemediationPlan | None:
        await self.ensure_schema()
        result = await self.session.execute(
            text(
                "SELECT payload FROM canonical_resolution_objects "
                "WHERE object_type='remediation_plan' AND object_id=:object_id AND tenant_id=:tenant_id "
                "ORDER BY revision DESC"
            ),
            {"object_id": str(plan_id), "tenant_id": tenant_id},
        )
        row = result.first()
        if not row:
            return None
        return RemediationPlan.model_validate(json.loads(row[0]))

    async def list_incident_objects(
        self,
        *,
        tenant_id: str,
        incident_id: UUID | str,
        object_type: str | None = None,
    ) -> list[dict[str, Any]]:
        await self.ensure_schema()
        query = (
            "SELECT object_type, object_id, revision, content_hash, payload, created_at, updated_at "
            "FROM canonical_resolution_objects WHERE tenant_id=:tenant_id AND incident_id=:incident_id"
        )
        params: dict[str, Any] = {"tenant_id": tenant_id, "incident_id": str(incident_id)}
        if object_type:
            query += " AND object_type=:object_type"
            params["object_type"] = object_type
        query += " ORDER BY created_at, revision"
        result = await self.session.execute(text(query), params)
        return [
            {
                "object_type": row[0],
                "object_id": row[1],
                "revision": row[2],
                "content_hash": row[3],
                "payload": json.loads(row[4]),
                "created_at": row[5],
                "updated_at": row[6],
            }
            for row in result.fetchall()
        ]
