from __future__ import annotations

from uuid import uuid4

import pytest

from common.audit_ledger import PrivilegedActor
from common.models import RemediationAction, RemediationStatus
from common.remediation_audit import append_privileged_remediation_audit


class FakeLedger:
    def __init__(self) -> None:
        self.calls = []

    async def append(self, **kwargs):
        actor = kwargs["actor"]
        actor.validate(production=kwargs["production"])
        self.calls.append(kwargs)
        return {
            "tenant_id": kwargs["tenant_id"],
            "record_hash": "hash-1",
            "event": kwargs["event"],
        }


def _action(*, auth: str | None = "oidc-mfa") -> RemediationAction:
    return RemediationAction(
        incident_id=uuid4(),
        approval_id=uuid4(),
        action_type="restart_pod",
        target="orders",
        status=RemediationStatus.SUCCEEDED,
        output="completed",
        parameters={
            "approved_by": "reviewer@example.com",
            "actor_type": "human",
            "actor_authentication_method": auth,
            "tenant_id": "tenant-a",
            "enterprise_governance": {
                "tenant_id": "tenant-a",
                "secret_ref": "vault://kaims/prod/orders",
            },
            "plan_hash": "plan-hash",
            "pre_execution_snapshot_hash": "snapshot-hash",
            "execution_idempotency_key": "idem-1",
            "execution_strategy": "CANARY",
        },
    )


@pytest.mark.asyncio
async def test_privileged_remediation_binds_tenant_actor_and_execution_evidence() -> None:
    ledger = FakeLedger()
    record = await append_privileged_remediation_audit(
        ledger=ledger,
        action=_action(),
        production=True,
    )
    assert record["tenant_id"] == "tenant-a"
    call = ledger.calls[0]
    assert call["actor"].actor_id == "reviewer@example.com"
    assert call["actor"].authentication_method == "oidc-mfa"
    assert call["event"]["plan_hash"] == "plan-hash"
    assert call["event"]["pre_execution_snapshot_hash"] == "snapshot-hash"
    assert call["event"]["execution_idempotency_key"] == "idem-1"


@pytest.mark.asyncio
async def test_production_remediation_without_authenticated_actor_fails_closed() -> None:
    ledger = FakeLedger()
    with pytest.raises(ValueError, match="PRIVILEGED_ACTOR_AUTHENTICATION_MISSING"):
        await append_privileged_remediation_audit(
            ledger=ledger,
            action=_action(auth=None),
            production=True,
        )
