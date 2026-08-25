from __future__ import annotations

from uuid import uuid4

import pytest

from common.models import RemediationAction, RemediationStatus
from remediation_engine.governed_engine import GovernedRemediationEngine


class FakeAutonomyStore:
    def __init__(self, mode: str) -> None:
        self.mode = mode

    async def get(self, tenant_id: str):
        return {"mode": self.mode, "score": 100, "evaluated_at": "now", "reasons": []}


class FakeCoordinator:
    async def acquire(self, **kwargs):
        class Result:
            acquired = True
            duplicate = False
            reason = "ok"
        return Result()

    async def complete(self, **kwargs):
        return None


def _action(*, approved: bool) -> RemediationAction:
    return RemediationAction(
        incident_id=uuid4(),
        approval_id=uuid4() if approved else None,
        action_type="restart_pod",
        target="orders",
        status=RemediationStatus.PENDING,
        parameters={
            "tenant_id": "tenant-a",
            "authorized_tenant_id": "tenant-a",
            "secret_ref": "vault://kaims/orders",
        },
    )


@pytest.mark.asyncio
async def test_kill_switch_blocks_even_approved_action() -> None:
    engine = GovernedRemediationEngine(autonomy_store=FakeAutonomyStore("KILL_SWITCH"), execution_coordinator=FakeCoordinator())
    action = _action(approved=True)
    result = await engine.execute(action)
    assert result.status == RemediationStatus.SKIPPED
    assert result.error == "AUTONOMY_KILL_SWITCH_ACTIVE"


@pytest.mark.asyncio
async def test_guided_blocks_unapproved_mutation() -> None:
    engine = GovernedRemediationEngine(autonomy_store=FakeAutonomyStore("GUIDED"), execution_coordinator=FakeCoordinator())
    result = await engine.execute(_action(approved=False))
    assert result.status == RemediationStatus.SKIPPED
    assert result.error == "AUTONOMY_MODE_REQUIRES_APPROVAL:GUIDED"


@pytest.mark.asyncio
async def test_hitl_allows_explicitly_approved_mutation_to_reach_later_safety_gates() -> None:
    engine = GovernedRemediationEngine(autonomy_store=FakeAutonomyStore("HITL_ONLY"), execution_coordinator=FakeCoordinator())
    action = _action(approved=True)
    result = await engine._apply_autonomy_governance(action)
    assert result is None
    assert action.parameters["autonomy_governance"]["mode"] == "HITL_ONLY"


@pytest.mark.asyncio
async def test_autonomous_allows_unapproved_low_level_action_to_reach_later_gates() -> None:
    engine = GovernedRemediationEngine(autonomy_store=FakeAutonomyStore("AUTONOMOUS"), execution_coordinator=FakeCoordinator())
    action = _action(approved=False)
    result = await engine._apply_autonomy_governance(action)
    assert result is None
