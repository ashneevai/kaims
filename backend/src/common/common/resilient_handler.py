from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from common.message_processing import extract_message_identity
from common.replay_guard import MessageReplayGuard, build_replay_guard


Handler = Callable[[dict[str, Any]], Awaitable[None]]


async def build_resilient_handler(
    settings: Any,
    *,
    namespace: str,
    handler: Handler,
) -> tuple[Handler, MessageReplayGuard]:
    """Wrap a broker handler with distributed replay protection.

    Production handlers require Redis-backed claims. A failed handler releases its
    lease so RabbitMQ/Kafka retry/DLQ behavior remains authoritative. Successful
    handlers leave a durable DONE marker so pod restarts and broker replays cannot
    repeat privileged side effects.
    """

    guard = await build_replay_guard(settings, namespace=namespace)

    async def resilient(payload: dict[str, Any]) -> None:
        identity = extract_message_identity(payload)
        claim = await guard.claim(identity)
        if claim.duplicate:
            return
        if not claim.acquired:
            raise RuntimeError(f"HA_REPLAY_CLAIM_FAILED: {claim.reason}")
        success = False
        try:
            await handler(payload)
            success = True
        finally:
            await guard.complete(identity, claim.token, success=success)

    return resilient, guard
