from __future__ import annotations

from typing import Any

from common.audit_ledger import ImmutableAuditLedger, PrivilegedActor
from common.models import RemediationAction


async def append_privileged_remediation_audit(
    *,
    ledger: ImmutableAuditLedger,
    action: RemediationAction,
    production: bool,
) -> dict[str, Any]:
    params = action.parameters if isinstance(action.parameters, dict) else {}
    governance = params.get("enterprise_governance")
    governance = governance if isinstance(governance, dict) else {}
    tenant_id = str(governance.get("tenant_id") or params.get("tenant_id") or "").strip()

    actor_id = str(
        params.get("approved_by")
        or params.get("actor_id")
        or ("system-auto-approval" if params.get("auto_approved") else "automation-agent")
    ).strip()
    actor_type = str(params.get("actor_type") or ("human" if params.get("approved_by") else "service")).strip()
    authentication_method = str(
        params.get("actor_authentication_method")
        or params.get("authentication_method")
        or ""
    ).strip() or None

    actor = PrivilegedActor(
        actor_id=actor_id,
        actor_type=actor_type,
        authentication_method=authentication_method,
        approval_id=str(action.approval_id) if action.approval_id else None,
        session_id=str(params.get("actor_session_id") or "").strip() or None,
    )
    event = {
        "event_type": "incident.remediation.privileged_action",
        "incident_id": str(action.incident_id),
        "action_id": str(action.id),
        "approval_id": str(action.approval_id) if action.approval_id else None,
        "action_type": action.action_type,
        "target": action.target,
        "status": action.status.value,
        "plan_id": params.get("plan_id"),
        "plan_revision": params.get("plan_revision"),
        "plan_hash": params.get("plan_hash"),
        "pre_execution_snapshot_hash": params.get("pre_execution_snapshot_hash"),
        "execution_idempotency_key": params.get("execution_idempotency_key"),
        "execution_strategy": params.get("execution_strategy"),
        "capability_id": params.get("capability_id"),
        "secret_ref": governance.get("secret_ref"),
        "output": action.output,
        "error": action.error,
    }
    return await ledger.append(
        tenant_id=tenant_id,
        actor=actor,
        event=event,
        resource_id=str(action.id),
        production=production,
    )
