from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Coroutine
from typing import Any

from common.config import get_settings
from common.kafka import KafkaConsumer, consume_forever as consume_kafka_forever
from common.models import Alert, Incident
from common.rabbitmq import RabbitMQConsumer, consume_forever as consume_rabbitmq_forever
from common.reassessment import build_reassessment_constraints
from common.repository import IncidentRepository
from common.service import create_app
from common.telemetry import EVENTS_PROCESSED
from common.topics import HITL_REVIEW_EVENTS, ORCHESTRATION_EVENTS, REASSESSMENT_EVENTS
from fastapi import FastAPI

settings = get_settings()
settings.service_name = "reassessment-service"
tasks: list[asyncio.Task] = []

ConsumeRunner = Callable[[Any, Callable[[dict], Awaitable[None]]], Coroutine[Any, Any, None]]


def _hitl_payload(*, event: dict[str, Any], reason: str, incident_id: str) -> dict[str, Any]:
    route_payload = event.get("payload") if isinstance(event.get("payload"), dict) else event
    return {
        "incident_id": incident_id,
        "route_action": "REQUEST_HITL",
        "route_reason": reason,
        "flow_id": str(route_payload.get("flow_id") or incident_id),
        "trace_id": str(route_payload.get("trace_id") or ""),
        "correlation_id": str(route_payload.get("correlation_id") or "") or None,
        "source": "reassessment-service",
        "source_event": event,
    }


def _build_orchestration_payload(
    *,
    incident: Incident,
    constraints: dict[str, Any],
) -> dict[str, Any]:
    tenant_id = str((incident.metadata or {}).get("tenant_id") or "").strip()
    trace_id = str(constraints.get("trace_id") or incident.trace_id or "")
    correlation_id = str(constraints.get("correlation_id") or "") or None
    alert = Alert(
        source="closure-reassessment",
        name="PostRemediationReassessment",
        service=incident.service,
        environment=incident.environment,
        severity=incident.severity,
        description=(
            "Post-remediation validation did not prove sustained recovery. "
            "Collect fresh evidence and evaluate an alternative root-cause hypothesis and remediation."
        ),
        trace_id=trace_id or None,
        correlation_id=correlation_id,
        labels={
            "workflow": "reassessment",
            "reassessment_attempt": str(constraints.get("attempt") or 1),
        },
        metadata={
            "tenant_id": tenant_id,
            "reassessment": True,
            "reassessment_constraints": constraints,
        },
    )
    return {
        "alert": alert.model_dump(mode="json"),
        "incident": incident.model_dump(mode="json"),
        "decision": {
            "workflow": "REASSESSMENT",
            "flow_id": str(constraints.get("flow_id") or incident.id),
            "trace_id": trace_id,
            "correlation_id": correlation_id,
            "requires_approval": True,
            "message_bus_provider": str(getattr(settings, "event_bus_provider", "rabbitmq") or "rabbitmq"),
            "policy_version": "closed-loop-reassessment-v1",
            "policy_reason": "post-remediation validation requires a fresh diagnosis and alternative action",
            "reassessment_constraints": constraints,
        },
    }


async def _prior_reassessment_attempts(repo: IncidentRepository, incident_id: str) -> int:
    try:
        stage = await repo.get_incident_stage_completeness(incident_id)
    except Exception:
        return 0
    if not isinstance(stage, dict):
        return 0
    counts = stage.get("counts") if isinstance(stage.get("counts"), dict) else {}
    completed_actions = max(0, int(counts.get("actions") or 0))
    return max(0, completed_actions - 1)


async def _handle(app: FastAPI, event: dict[str, Any]) -> None:
    incident_id = str(event.get("incident_id") or "").strip()
    if not incident_id:
        raise ValueError("reassessment event requires incident_id")

    session_factory = getattr(app.state, "session_factory", None)
    if not settings.database_enabled or session_factory is None:
        await app.state.producer.publish(
            HITL_REVIEW_EVENTS,
            _hitl_payload(
                event=event,
                incident_id=incident_id,
                reason="reassessment requires persisted incident history; database unavailable",
            ),
            key=incident_id,
        )
        return

    async with session_factory() as session:
        repo = IncidentRepository(session)
        incident_payload = await repo.get_incident(incident_id)
        if not isinstance(incident_payload, dict):
            await app.state.producer.publish(
                HITL_REVIEW_EVENTS,
                _hitl_payload(
                    event=event,
                    incident_id=incident_id,
                    reason="persisted incident not found for reassessment",
                ),
                key=incident_id,
            )
            return
        prior_attempts = await _prior_reassessment_attempts(repo, incident_id)

    constraints = build_reassessment_constraints(event, prior_attempts=prior_attempts)
    if constraints.exhausted:
        await app.state.producer.publish(
            HITL_REVIEW_EVENTS,
            _hitl_payload(
                event=event,
                incident_id=incident_id,
                reason=(
                    f"reassessment retry budget exhausted: attempt {constraints.attempt} "
                    f"exceeds maximum {constraints.max_attempts}"
                ),
            ),
            key=incident_id,
        )
        return

    incident = Incident.model_validate(incident_payload)
    payload = _build_orchestration_payload(
        incident=incident,
        constraints=constraints.as_dict(),
    )
    await app.state.producer.publish(ORCHESTRATION_EVENTS, payload, key=incident.service)


async def startup(app: FastAPI) -> None:
    workers = max(1, int(getattr(settings, "message_bus_worker_count", 1) or 1))
    consumers: list[tuple[str, Any, ConsumeRunner]] = []
    for worker in range(workers):
        consumers.append(
            (
                f"rabbitmq-w{worker + 1}",
                RabbitMQConsumer(settings, REASSESSMENT_EVENTS),
                consume_rabbitmq_forever,
            )
        )
    if settings.kafka_enabled:
        for worker in range(workers):
            consumers.insert(
                worker,
                (
                    f"kafka-w{worker + 1}",
                    KafkaConsumer(settings, REASSESSMENT_EVENTS),
                    consume_kafka_forever,
                ),
            )

    async def handle(payload: dict) -> None:
        await _handle(app, payload)
        EVENTS_PROCESSED.labels(settings.service_name, REASSESSMENT_EVENTS, "ok").inc()

    for source, consumer, consume_forever in consumers:
        tasks.append(
            asyncio.create_task(
                consume_forever(consumer, handle),
                name=f"reassessment-service-{source}-consumer",
            )
        )


async def shutdown(_: FastAPI) -> None:
    for task in tasks:
        task.cancel()


app = create_app(
    title="KaiMS Reassessment Service",
    settings=settings,
    startup=startup,
    shutdown=shutdown,
)


@app.post("/reassess")
async def reassess(payload: dict) -> dict:
    await _handle(app, payload)
    return {"accepted": True, "incident_id": str(payload.get("incident_id") or "")}
