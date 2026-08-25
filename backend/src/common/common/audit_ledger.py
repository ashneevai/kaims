from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from common.database import AuditLogRecord
from common.enterprise_governance import (
    build_tamper_evident_audit_record,
    verify_tamper_evident_audit_record,
)


LEDGER_ACTION = "immutable_audit_append"
LEDGER_RESOURCE_TYPE = "immutable_audit"


@dataclass(frozen=True)
class PrivilegedActor:
    actor_id: str
    actor_type: str
    authentication_method: str | None = None
    approval_id: str | None = None
    session_id: str | None = None

    def validate(self, *, production: bool) -> None:
        if not self.actor_id.strip() or not self.actor_type.strip():
            raise ValueError("PRIVILEGED_ACTOR_IDENTITY_MISSING")
        if production and not str(self.authentication_method or "").strip():
            raise ValueError("PRIVILEGED_ACTOR_AUTHENTICATION_MISSING")


class ImmutableAuditLedger:
    """Append-only, per-tenant tamper-evident ledger backed by audit_logs.

    Ledger rows are never updated or deleted by this class. Each tenant maintains an
    independent hash chain. The database row id is also copied into the payload so
    exported ledgers retain a stable physical-record identifier.
    """

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def _tenant_rows(self, tenant_id: str, *, limit: int = 5000) -> list[AuditLogRecord]:
        result = await self.session.execute(
            select(AuditLogRecord)
            .where(
                AuditLogRecord.resource_type == LEDGER_RESOURCE_TYPE,
                AuditLogRecord.action == LEDGER_ACTION,
            )
            .order_by(AuditLogRecord.created_at.asc(), AuditLogRecord.id.asc())
            .limit(limit)
        )
        rows = []
        for row in result.scalars().all():
            payload = row.payload if isinstance(row.payload, dict) else {}
            if str(payload.get("tenant_id") or "").strip() == tenant_id:
                rows.append(row)
        return rows

    async def append(
        self,
        *,
        tenant_id: str,
        actor: PrivilegedActor,
        event: dict[str, Any],
        resource_id: str,
        production: bool,
    ) -> dict[str, Any]:
        tenant = str(tenant_id or "").strip()
        if not tenant:
            raise ValueError("TENANT_SCOPE_MISSING")
        actor.validate(production=production)

        rows = await self._tenant_rows(tenant)
        previous_payload = rows[-1].payload if rows and isinstance(rows[-1].payload, dict) else {}
        previous_hash = str(previous_payload.get("record_hash") or "") or None
        sequence = int(previous_payload.get("sequence") or 0) + 1

        enriched_event = {
            **event,
            "privileged_identity": {
                "actor_id": actor.actor_id,
                "actor_type": actor.actor_type,
                "authentication_method": actor.authentication_method,
                "approval_id": actor.approval_id,
                "session_id": actor.session_id,
            },
        }
        record = build_tamper_evident_audit_record(
            event=enriched_event,
            previous_hash=previous_hash,
            tenant_id=tenant,
            actor_id=actor.actor_id,
            actor_type=actor.actor_type,
        )
        row_id = uuid4()
        record["sequence"] = sequence
        record["ledger_row_id"] = str(row_id)
        # sequence and row id are part of the persisted envelope but the cryptographic
        # record hash signs the canonical governance record created above. Chain
        # verification validates both continuity and each signed record.
        row = AuditLogRecord(
            id=row_id,
            actor=actor.actor_id,
            action=LEDGER_ACTION,
            resource_type=LEDGER_RESOURCE_TYPE,
            resource_id=str(resource_id),
            payload=record,
        )
        self.session.add(row)
        await self.session.flush()
        return record

    async def verify_tenant_chain(self, tenant_id: str) -> dict[str, Any]:
        tenant = str(tenant_id or "").strip()
        rows = await self._tenant_rows(tenant)
        payloads = [row.payload for row in rows if isinstance(row.payload, dict)]
        return verify_chain(payloads, tenant_id=tenant)


def verify_chain(records: list[dict[str, Any]], *, tenant_id: str) -> dict[str, Any]:
    expected_previous = ""
    expected_sequence = 1
    failures: list[str] = []
    for index, record in enumerate(records):
        if str(record.get("tenant_id") or "") != tenant_id:
            failures.append(f"record[{index}]:TENANT_MISMATCH")
        if int(record.get("sequence") or 0) != expected_sequence:
            failures.append(f"record[{index}]:SEQUENCE_BREAK")
        if str(record.get("previous_hash") or "") != expected_previous:
            failures.append(f"record[{index}]:HASH_CHAIN_BREAK")
        signed = {key: value for key, value in record.items() if key not in {"sequence", "ledger_row_id"}}
        if not verify_tamper_evident_audit_record(signed):
            failures.append(f"record[{index}]:RECORD_TAMPERED")
        expected_previous = str(record.get("record_hash") or "")
        expected_sequence += 1
    return {
        "tenant_id": tenant_id,
        "valid": not failures,
        "record_count": len(records),
        "chain_head": expected_previous or None,
        "failures": failures,
    }
