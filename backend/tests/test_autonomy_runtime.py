from __future__ import annotations

import pytest

from common.autonomy_control import AutonomyMode, PLATFORM_SLOS
from common.autonomy_runtime import AutonomyRuntimeStore


def _healthy():
    return {s.name: (s.target if s.direction == "gte" else s.target * 0.5) for s in PLATFORM_SLOS}


@pytest.mark.asyncio
async def test_local_store_defaults_fail_closed_and_can_be_evaluated() -> None:
    store = AutonomyRuntimeStore("redis://127.0.0.1:1/0", environment="test")
    initial = await store.get("tenant-a")
    assert initial["mode"] == AutonomyMode.HITL_ONLY.value
    state = await store.evaluate_and_set(tenant_id="tenant-a", metrics=_healthy())
    assert state["mode"] == AutonomyMode.AUTONOMOUS.value
    await store.close()


@pytest.mark.asyncio
async def test_kill_switch_requires_actor_and_reason() -> None:
    store = AutonomyRuntimeStore("redis://127.0.0.1:1/0", environment="test")
    with pytest.raises(ValueError):
        await store.set_kill_switch(tenant_id="tenant-a", enabled=True, actor_id="", reason="")
    await store.close()


@pytest.mark.asyncio
async def test_kill_switch_persists_and_disable_returns_hitl_not_autonomous() -> None:
    store = AutonomyRuntimeStore("redis://127.0.0.1:1/0", environment="test")
    enabled = await store.set_kill_switch(tenant_id="tenant-a", enabled=True, actor_id="ops-1", reason="incident")
    assert enabled["mode"] == AutonomyMode.KILL_SWITCH.value
    disabled = await store.set_kill_switch(tenant_id="tenant-a", enabled=False, actor_id="ops-2", reason="incident stabilized")
    assert disabled["mode"] == AutonomyMode.HITL_ONLY.value
    await store.close()
