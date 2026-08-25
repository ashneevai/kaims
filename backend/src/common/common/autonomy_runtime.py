from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from redis.asyncio import Redis

from common.autonomy_control import AutonomyMode, evaluate_autonomy_mode


class AutonomyRuntimeStore:
    def __init__(self, redis_url: str, *, environment: str, key_prefix: str = "kaims:autonomy") -> None:
        self.production = str(environment).lower() not in {"local", "dev", "development", "test", "testing", "simulation"}
        self.redis = Redis.from_url(redis_url, decode_responses=True)
        self.key_prefix = key_prefix
        self._local: dict[str, Any] = {}

    def _key(self, tenant_id: str) -> str:
        return f"{self.key_prefix}:{tenant_id or 'default'}"

    async def get(self, tenant_id: str = "default") -> dict[str, Any]:
        key = self._key(tenant_id)
        try:
            raw = await self.redis.get(key)
            if raw:
                return json.loads(raw)
        except Exception:
            if self.production:
                return {"mode": AutonomyMode.HITL_ONLY.value, "score": 0, "reasons": ["AUTONOMY_STORE_UNAVAILABLE"]}
        return self._local.get(key, {"mode": AutonomyMode.HITL_ONLY.value, "score": 0, "reasons": ["AUTONOMY_STATE_UNINITIALIZED"]})

    async def evaluate_and_set(
        self,
        *,
        tenant_id: str,
        metrics: dict[str, float | int | None],
        manual_kill_switch: bool = False,
        critical_dependency_unavailable: bool = False,
        audit_chain_broken: bool = False,
    ) -> dict[str, Any]:
        current = await self.get(tenant_id)
        decision = evaluate_autonomy_mode(
            metrics=metrics,
            manual_kill_switch=manual_kill_switch,
            critical_dependency_unavailable=critical_dependency_unavailable,
            audit_chain_broken=audit_chain_broken,
        )
        state = {
            **decision,
            "tenant_id": tenant_id,
            "previous_mode": current.get("mode"),
            "evaluated_at": datetime.now(UTC).isoformat(),
            "manual_kill_switch": bool(manual_kill_switch),
        }
        key = self._key(tenant_id)
        try:
            await self.redis.set(key, json.dumps(state, sort_keys=True))
        except Exception:
            if self.production:
                return {**state, "mode": AutonomyMode.HITL_ONLY.value, "reasons": [*state.get("reasons", []), "AUTONOMY_STORE_WRITE_FAILED"]}
            self._local[key] = state
        return state

    async def set_kill_switch(self, *, tenant_id: str, enabled: bool, actor_id: str, reason: str) -> dict[str, Any]:
        if not str(actor_id or "").strip() or not str(reason or "").strip():
            raise ValueError("KILL_SWITCH_ACTOR_AND_REASON_REQUIRED")
        current = await self.get(tenant_id)
        state = {
            **current,
            "tenant_id": tenant_id,
            "mode": AutonomyMode.KILL_SWITCH.value if enabled else AutonomyMode.HITL_ONLY.value,
            "manual_kill_switch": bool(enabled),
            "kill_switch_actor": actor_id,
            "kill_switch_reason": reason,
            "evaluated_at": datetime.now(UTC).isoformat(),
        }
        key = self._key(tenant_id)
        try:
            await self.redis.set(key, json.dumps(state, sort_keys=True))
        except Exception:
            if self.production:
                raise RuntimeError("AUTONOMY_STORE_UNAVAILABLE")
            self._local[key] = state
        return state

    async def close(self) -> None:
        await self.redis.aclose()
