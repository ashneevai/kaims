from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Coroutine
from typing import Any

from common.config import get_settings
from common.kafka import KafkaConsumer, consume_forever as consume_kafka_forever
from common.lifecycle_controller import build_dispatch_from_closure_event
from common.rabbitmq import RabbitMQConsumer, consume_forever as consume_rabbitmq_forever
from common.service import create_app
from common.telemetry import EVENTS_PROCESSED
from common.topics import CLOSURE_EVENTS
from fastapi import FastAPI

settings = get_settings()
settings.service_name = "lifecycle-controller"
tasks: list[asyncio.Task] = []

ConsumeRunner = Callable[[Any, Callable[[dict], Awaitable[None]]], Coroutine[Any, Any, None]]


async def startup(app: FastAPI) -> None:
    workers = max(1, int(getattr(settings, "message_bus_worker_count", 1) or 1))
    consumers: list[tuple[str, Any, ConsumeRunner]] = []
    for worker in range(workers):
        consumers.append(
            (
                f"rabbitmq-w{worker + 1}",
                RabbitMQConsumer(settings, CLOSURE_EVENTS),
                consume_rabbitmq_forever,
            )
        )
    if settings.kafka_enabled:
        for worker in range(workers):
            consumers.insert(
                worker,
                (
                    f"kafka-w{worker + 1}",
                    KafkaConsumer(settings, CLOSURE_EVENTS),
                    consume_kafka_forever,
                ),
            )

    async def handle(payload: dict) -> None:
        dispatch = build_dispatch_from_closure_event(payload)
        if dispatch.destination_topic is None:
            EVENTS_PROCESSED.labels(settings.service_name, CLOSURE_EVENTS, "complete").inc()
            return

        await app.state.producer.publish(
            dispatch.destination_topic,
            dispatch.as_dict(),
            key=dispatch.incident_id,
        )
        EVENTS_PROCESSED.labels(
            settings.service_name,
            dispatch.destination_topic,
            "routed",
        ).inc()

    for source, consumer, consume_forever in consumers:
        task = asyncio.create_task(
            consume_forever(consumer, handle),
            name=f"lifecycle-controller-{source}-consumer",
        )
        tasks.append(task)


async def shutdown(_: FastAPI) -> None:
    for task in tasks:
        task.cancel()


app = create_app(
    title="KaiMS Lifecycle Controller",
    settings=settings,
    startup=startup,
    shutdown=shutdown,
)


@app.post("/route")
async def route_closure(payload: dict) -> dict:
    """Expose deterministic routing for diagnostics and contract testing."""

    return build_dispatch_from_closure_event(payload).as_dict()
