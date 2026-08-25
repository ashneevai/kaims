from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class CoordinationResult:
    acquired: bool
    duplicate: bool = False
    reason: str = ""


class InMemoryExecutionCoordinator:
    """Deterministic coordinator for local/test use only."""

    def __init__(self) -> None:
        self._locks: set[str] = set()
        self._completed: set[str] = set()
        self._guard = asyncio.Lock()

    async def acquire(self, *, lock_key: str, idempotency_key: str, ttl_seconds: int = 300) -> CoordinationResult:
        del ttl_seconds
        async with self._guard:
            if idempotency_key in self._completed:
                return CoordinationResult(False, True, "idempotent execution already completed")
            if lock_key in self._locks:
                return CoordinationResult(False, False, "target already has an active remediation lock")
            self._locks.add(lock_key)
            return CoordinationResult(True, False, "lock acquired")

    async def complete(self, *, lock_key: str, idempotency_key: str, success: bool) -> None:
        async with self._guard:
            self._locks.discard(lock_key)
            if success:
                self._completed.add(idempotency_key)

    async def release(self, *, lock_key: str) -> None:
        async with self._guard:
            self._locks.discard(lock_key)


class RedisExecutionCoordinator:
    """Cross-worker remediation lock and idempotency coordinator backed by Redis."""

    def __init__(self, redis_url: str) -> None:
        try:
            from redis.asyncio import from_url
        except ImportError as exc:  # pragma: no cover - dependency/runtime guard
            raise RuntimeError("redis package is required for distributed execution coordination") from exc
        self._redis = from_url(redis_url, encoding="utf-8", decode_responses=True)

    async def acquire(self, *, lock_key: str, idempotency_key: str, ttl_seconds: int = 300) -> CoordinationResult:
        if await self._redis.exists(idempotency_key):
            return CoordinationResult(False, True, "idempotent execution already completed")
        acquired = await self._redis.set(lock_key, idempotency_key, nx=True, ex=max(30, ttl_seconds))
        if not acquired:
            return CoordinationResult(False, False, "target already has an active remediation lock")
        if await self._redis.exists(idempotency_key):
            await self._safe_release(lock_key, idempotency_key)
            return CoordinationResult(False, True, "idempotent execution already completed")
        return CoordinationResult(True, False, "distributed lock acquired")

    async def complete(self, *, lock_key: str, idempotency_key: str, success: bool) -> None:
        if success:
            await self._redis.set(idempotency_key, "completed", nx=True, ex=7 * 24 * 60 * 60)
        await self._safe_release(lock_key, idempotency_key)

    async def release(self, *, lock_key: str) -> None:
        await self._redis.delete(lock_key)

    async def _safe_release(self, lock_key: str, token: str) -> None:
        script = """
        if redis.call('get', KEYS[1]) == ARGV[1] then
            return redis.call('del', KEYS[1])
        end
        return 0
        """
        await self._redis.eval(script, 1, lock_key, token)


class FailClosedExecutionCoordinator:
    async def acquire(self, *, lock_key: str, idempotency_key: str, ttl_seconds: int = 300) -> CoordinationResult:
        del lock_key, idempotency_key, ttl_seconds
        return CoordinationResult(False, False, "distributed execution coordinator unavailable")

    async def complete(self, *, lock_key: str, idempotency_key: str, success: bool) -> None:
        del lock_key, idempotency_key, success

    async def release(self, *, lock_key: str) -> None:
        del lock_key


def build_execution_coordinator(settings: Any) -> Any:
    environment = str(getattr(settings, "environment", "local") or "local").lower()
    if environment in {"local", "dev", "development", "test", "testing", "simulation"}:
        return InMemoryExecutionCoordinator()
    redis_url = str(getattr(settings, "redis_url", "") or "").strip()
    if not redis_url:
        return FailClosedExecutionCoordinator()
    try:
        return RedisExecutionCoordinator(redis_url)
    except Exception:
        return FailClosedExecutionCoordinator()
