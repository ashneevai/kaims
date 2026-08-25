from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Any

from redis.asyncio import Redis

from common.message_processing import ProcessedMessageCache


_LOCAL_ENVIRONMENTS = {"local", "dev", "development", "test", "testing", "simulation"}


@dataclass(frozen=True)
class ReplayClaim:
    acquired: bool
    duplicate: bool
    token: str | None = None
    reason: str = ""


class MessageReplayGuard:
    async def claim(self, identity: str | None) -> ReplayClaim:
        raise NotImplementedError

    async def complete(self, identity: str | None, token: str | None, *, success: bool) -> None:
        raise NotImplementedError

    async def close(self) -> None:
        return None


class InMemoryReplayGuard(MessageReplayGuard):
    def __init__(self) -> None:
        self._processed = ProcessedMessageCache(ttl_seconds=86400, max_entries=50000)
        self._inflight: set[str] = set()

    async def claim(self, identity: str | None) -> ReplayClaim:
        key = str(identity or "").strip()
        if not key:
            return ReplayClaim(True, False, None, "message has no durable identity")
        if self._processed.contains(key) or key in self._inflight:
            return ReplayClaim(False, True, None, "duplicate message")
        token = secrets.token_hex(16)
        self._inflight.add(key)
        return ReplayClaim(True, False, token, "in-memory claim acquired")

    async def complete(self, identity: str | None, token: str | None, *, success: bool) -> None:
        key = str(identity or "").strip()
        if not key:
            return
        self._inflight.discard(key)
        if success:
            self._processed.mark(key)


class RedisReplayGuard(MessageReplayGuard):
    """Distributed replay/idempotency guard for active-active consumers.

    A short processing lease prevents concurrent execution. Successful completion
    replaces the lease with a long-lived DONE marker. Failed handlers release the
    lease so broker redelivery can retry safely.
    """

    def __init__(
        self,
        redis: Redis,
        *,
        namespace: str,
        lease_seconds: int = 300,
        completed_ttl_seconds: int = 7 * 24 * 3600,
    ) -> None:
        self.redis = redis
        self.namespace = namespace.strip().replace(" ", "-") or "kaiops"
        self.lease_seconds = max(30, int(lease_seconds))
        self.completed_ttl_seconds = max(self.lease_seconds, int(completed_ttl_seconds))

    def _key(self, identity: str) -> str:
        return f"kaiops:replay:{self.namespace}:{identity}"

    async def claim(self, identity: str | None) -> ReplayClaim:
        message_id = str(identity or "").strip()
        if not message_id:
            return ReplayClaim(True, False, None, "message has no durable identity")
        token = secrets.token_hex(16)
        value = f"PROCESSING:{token}"
        acquired = await self.redis.set(self._key(message_id), value, nx=True, ex=self.lease_seconds)
        if acquired:
            return ReplayClaim(True, False, token, "distributed processing lease acquired")
        existing = await self.redis.get(self._key(message_id))
        text = existing.decode("utf-8", errors="replace") if isinstance(existing, bytes) else str(existing or "")
        return ReplayClaim(False, True, None, f"duplicate/replayed message ({text.split(':', 1)[0] or 'claimed'})")

    async def complete(self, identity: str | None, token: str | None, *, success: bool) -> None:
        message_id = str(identity or "").strip()
        if not message_id or not token:
            return
        key = self._key(message_id)
        expected = f"PROCESSING:{token}"
        # Compare-and-set/delete via Lua so one worker cannot complete another
        # worker's expired-and-reacquired lease.
        if success:
            script = """
            if redis.call('GET', KEYS[1]) == ARGV[1] then
              return redis.call('SET', KEYS[1], 'DONE', 'EX', ARGV[2])
            end
            return nil
            """
            await self.redis.eval(script, 1, key, expected, self.completed_ttl_seconds)
        else:
            script = """
            if redis.call('GET', KEYS[1]) == ARGV[1] then
              return redis.call('DEL', KEYS[1])
            end
            return 0
            """
            await self.redis.eval(script, 1, key, expected)

    async def close(self) -> None:
        await self.redis.aclose()


async def build_replay_guard(settings: Any, *, namespace: str) -> MessageReplayGuard:
    environment = str(getattr(settings, "environment", "local") or "local").strip().lower()
    if environment in _LOCAL_ENVIRONMENTS:
        return InMemoryReplayGuard()

    redis_url = str(getattr(settings, "redis_url", "") or "").strip()
    if not redis_url:
        raise RuntimeError("HA_REPLAY_GUARD_UNAVAILABLE: REDIS_URL is required outside local/test environments")
    client = Redis.from_url(redis_url, decode_responses=False)
    try:
        await client.ping()
    except Exception:
        await client.aclose()
        raise RuntimeError("HA_REPLAY_GUARD_UNAVAILABLE: Redis replay guard is not reachable")
    return RedisReplayGuard(
        client,
        namespace=namespace,
        lease_seconds=int(getattr(settings, "message_replay_lease_seconds", 300) or 300),
        completed_ttl_seconds=int(getattr(settings, "message_replay_completed_ttl_seconds", 604800) or 604800),
    )
