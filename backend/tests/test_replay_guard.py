from __future__ import annotations

import pytest

from common.replay_guard import InMemoryReplayGuard
from common.resilient_handler import build_resilient_handler


@pytest.mark.asyncio
async def test_inmemory_guard_blocks_duplicate_after_success() -> None:
    guard = InMemoryReplayGuard()
    first = await guard.claim("evt-1")
    assert first.acquired is True
    await guard.complete("evt-1", first.token, success=True)
    second = await guard.claim("evt-1")
    assert second.duplicate is True


@pytest.mark.asyncio
async def test_failed_handler_releases_claim_for_retry() -> None:
    guard = InMemoryReplayGuard()
    first = await guard.claim("evt-2")
    assert first.acquired is True
    await guard.complete("evt-2", first.token, success=False)
    retry = await guard.claim("evt-2")
    assert retry.acquired is True


@pytest.mark.asyncio
async def test_inflight_duplicate_is_blocked() -> None:
    guard = InMemoryReplayGuard()
    first = await guard.claim("evt-3")
    assert first.acquired is True
    duplicate = await guard.claim("evt-3")
    assert duplicate.duplicate is True


@pytest.mark.asyncio
async def test_resilient_handler_executes_once_for_same_event(monkeypatch) -> None:
    import common.resilient_handler as resilient_handler

    guard = InMemoryReplayGuard()

    async def fake_build(settings, *, namespace):
        return guard

    monkeypatch.setattr(resilient_handler, "build_replay_guard", fake_build)
    calls: list[str] = []

    async def handler(payload):
        calls.append(payload["event_id"])

    wrapped, _ = await build_resilient_handler(object(), namespace="test", handler=handler)
    payload = {"event_id": "evt-4"}
    await wrapped(payload)
    await wrapped(payload)
    assert calls == ["evt-4"]


@pytest.mark.asyncio
async def test_resilient_handler_allows_retry_after_failure(monkeypatch) -> None:
    import common.resilient_handler as resilient_handler

    guard = InMemoryReplayGuard()

    async def fake_build(settings, *, namespace):
        return guard

    monkeypatch.setattr(resilient_handler, "build_replay_guard", fake_build)
    attempts = 0

    async def handler(payload):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise RuntimeError("temporary")

    wrapped, _ = await build_resilient_handler(object(), namespace="test", handler=handler)
    with pytest.raises(RuntimeError):
        await wrapped({"event_id": "evt-5"})
    await wrapped({"event_id": "evt-5"})
    assert attempts == 2
