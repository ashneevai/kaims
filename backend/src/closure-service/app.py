from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Coroutine
from datetime import datetime, timezone
from typing import Any

from closure_service import ClosureValidationAgent
from common.config import get_settings
from common.event_publishers import build_agent_event_contract, build_event_envelope
from common.kafka import KafkaConsumer, consume_forever as consume_kafka_forever
from common.models import Incident, IncidentStatus, RemediationAction, ResolutionReport
from common.rabbitmq import RabbitMQConsumer, consume_forever as consume_rabbitmq_forever
from common.repository import IncidentRepository
from common.service import create_app
from common.telemetry import EVENTS_PROCESSED
from common.topics import CLOSURE_EVENTS, REMEDIATION_EVENTS
from fastapi import FastAPI

settings = get_settings()
settings.service_name = "closure-service"
agent = ClosureValidationAgent()
tasks: list[asyncio.Task] = []

ConsumeRunner = Callable[[Any, Callable[[dict], Awaitable[None]]], Coroutine[Any, Any, None]]


def _extract_remediation_action_payload(payload: dict[str, Any]) -> dict[str, Any]:
    action = payload.get("remediation_action") if isinstance(payload, dict) else None
    if isinstance(action, dict):
        return action
    return payload


def _build_closure_event_payload(
    *,
    action: RemediationAction,
    report: ResolutionReport,
    source_payload: dict[str, Any],
) -> dict[str, Any]:
    incident_id = str(action.incident_id)
    source_contract = source_payload.get("event_contract", {}) if isinstance(source_payload.get("event_contract"), dict) else {}
    flow_id = str(source_contract.get("flow_id") or incident_id)
    trace_id = str(source_contract.get("trace_id") or "")
    correlation_id = str(source_contract.get("correlation_id") or "") or None

    event_contract = build_agent_event_contract(
        flow_id=flow_id,
        incident_id=incident_id,
        trace_id=trace_id,
        correlation_id=correlation_id,
        agent="closure-service",
        payload={
            "action_taken": report.action_taken,
            "health_restored": report.health_restored,
            "alerts_cleared": report.alerts_cleared,
            "topic": CLOSURE_EVENTS,
        },
        metadata={
            "root_cause": report.root_cause,
            "impact": report.impact,
        },
        confidence=1.0 if report.health_restored else 0.0,
        reasoning="closure validation derived from independent post-action evidence",
        citations=[f"report://{report.id}"],
        evidence_ids=[f"action:{action.id}", f"incident:{incident_id}"],
    )
    return {
        "report": report,
        "remediation_action": action,
        "event_contract": event_contract,
    }


def _resolve_closure_service_name(action: RemediationAction, incident_payload: dict[str, Any] | None) -> str:
    payload = incident_payload if isinstance(incident_payload, dict) else {}
    service = str(payload.get("service") or "").strip()
    if service:
        return service
    return str(action.target or "unknown").strip() or "unknown"


def _resolve_required_scope(
    action: RemediationAction,
    incident_payload: dict[str, Any],
    recommendation: dict[str, Any],
) -> tuple[str, str]:
    action_metadata = action.metadata if isinstance(action.metadata, dict) else {}
    tenant_id = str(
        incident_payload.get("tenant_id")
        or action.parameters.get("tenant_id")
        or action_metadata.get("tenant_id")
        or recommendation.get("tenant_id")
        or ""
    ).strip()
    environment = str(
        incident_payload.get("environment")
        or action.parameters.get("environment")
        or action_metadata.get("environment")
        or recommendation.get("environment")
        or ""
    ).strip()

    deployment_mode = str(getattr(settings, "environment", "local") or "local").strip().lower()
    development_mode = deployment_mode in {"local", "dev", "development", "test", "testing", "simulation"}
    if not tenant_id and development_mode:
        tenant_id = "local"
    if not environment and development_mode:
        environment = deployment_mode or "local"

    if not tenant_id:
        raise ValueError("tenant scope is required for closure; refusing tenant 'default' fallback")
    if not environment:
        raise ValueError("environment scope is required for closure; refusing 'prod' fallback")
    return tenant_id, environment


def _build_final_incident_payload(
    *,
    action: RemediationAction,
    report: ResolutionReport,
    incident_payload: dict[str, Any] | None,
    recommendation: dict[str, Any] | None,
    source_contract: dict[str, Any] | None,
    environment: str,
) -> dict[str, Any]:
    incident_payload_map = incident_payload if isinstance(incident_payload, dict) else {}
    recommendation_map = recommendation if isinstance(recommendation, dict) else {}
    source_contract_map = source_contract if isinstance(source_contract, dict) else {}
    service_name = _resolve_closure_service_name(action, incident_payload_map)
    final_payload = {
        "id": str(action.incident_id),
        "service": service_name,
        "environment": environment,
        "severity": str(incident_payload_map.get("severity") or recommendation_map.get("severity") or "warning").lower(),
        "status": IncidentStatus.CLOSED.value if report.health_restored else IncidentStatus.FAILED.value,
        "title": str(incident_payload_map.get("title") or f"Incident {action.incident_id}"),
        "summary": str(incident_payload_map.get("summary") or ""),
        "owner_team": incident_payload_map.get("owner_team"),
        "ticket_id": incident_payload_map.get("ticket_id"),
        "closed_at": datetime.now(timezone.utc).isoformat() if report.health_restored else incident_payload_map.get("closed_at"),
        "trace_id": str(
            incident_payload_map.get("trace_id")
            or source_contract_map.get("trace_id")
            or recommendation_map.get("trace_id")
            or ""
        ) or None,
    }
    final_payload["alert_ids"] = incident_payload_map.get("alert_ids") if isinstance(incident_payload_map.get("alert_ids"), list) else []
    return final_payload


async def _persist_closure_event(
    *,
    app: FastAPI,
    action: RemediationAction,
    report: ResolutionReport,
    source_payload: dict[str, Any],
) -> None:
    if not settings.database_enabled or getattr(app.state, "session_factory", None) is None:
        return
    source_contract = source_payload.get("event_contract", {}) if isinstance(source_payload.get("event_contract"), dict) else {}
    source_recommendation = source_payload.get("source_payload", {}).get("recommendation") if isinstance(source_payload.get("source_payload"), dict) else {}
    recommendation = source_recommendation if isinstance(source_recommendation, dict) else {}
    status = "closed" if bool(report.health_restored) else "validation_failed"

    async with app.state.session_factory() as session:
        repo = IncidentRepository(session)
        incident_payload = await repo.get_incident(str(action.incident_id)) or {}
        tenant_id, environment = _resolve_required_scope(action, incident_payload, recommendation)
        final_incident_payload = _build_final_incident_payload(
            action=action,
            report=report,
            incident_payload=incident_payload,
            recommendation=recommendation,
            source_contract=source_contract,
            environment=environment,
        )
        service_name = str(final_incident_payload.get("service") or "unknown")
        await repo.save_incident(Incident.model_validate(final_incident_payload))
        await repo.save_incident_event(
            build_event_envelope(
                event_type="incident.closure.completed",
                identity={
                    "incident_id": str(action.incident_id),
                    "alert_id": None,
                    "trace_id": str(source_contract.get("trace_id") or recommendation.get("trace_id") or ""),
                    "correlation_id": str(source_contract.get("correlation_id") or recommendation.get("correlation_id") or "") or None,
                    "causation_id": None,
                    "parent_event_id": None,
                },
                scope={
                    "tenant_id": tenant_id,
                    "service": service_name,
                    "environment": environment,
                    "region": None,
                    "team": None,
                },
                state={
                    "severity": str(recommendation.get("severity") or "warning").lower(),
                    "status": status,
                    "owner": None,
                },
                policy={
                    "risk_tier": "unknown",
                    "execution_mode": "unknown",
                    "requires_approval": None,
                    "policy_version": None,
                    "policy_reason": "independent closure validation completed",
                },
                transport={
                    "provider": "unknown",
                    "channel": CLOSURE_EVENTS,
                    "partition": None,
                    "offset": None,
                    "delivery_tag": None,
                },
                payload={
                    "report_id": str(report.id),
                    "remediation_action_id": str(action.id),
                    "action_taken": report.action_taken,
                    "health_restored": report.health_restored,
                    "alerts_cleared": report.alerts_cleared,
                    "validation_status": (
                        report.metadata.get("validation_status") if isinstance(report.metadata, dict) else None
                    ),
                },
            )
        )
        await session.commit()


async def startup(app: FastAPI) -> None:
    workers = max(1, int(getattr(settings, "message_bus_worker_count", 1) or 1))
    consumers: list[tuple[str, Any, ConsumeRunner]] = []
    for worker in range(workers):
        consumers.append(
            (f"rabbitmq-w{worker + 1}", RabbitMQConsumer(settings, REMEDIATION_EVENTS), consume_rabbitmq_forever)
        )
    if settings.kafka_enabled:
        for worker in range(workers):
            consumers.insert(
                worker,
                (f"kafka-w{worker + 1}", KafkaConsumer(settings, REMEDIATION_EVENTS), consume_kafka_forever),
            )

    async def handle(payload: dict) -> None:
        action = RemediationAction.model_validate(_extract_remediation_action_payload(payload))
        report = await _validate_and_store(action)
        await _persist_closure_event(app=app, action=action, report=report, source_payload=payload)
        payload_out = _build_closure_event_payload(action=action, report=report, source_payload=payload)
        await app.state.producer.publish(CLOSURE_EVENTS, payload_out, key=str(action.incident_id))
        EVENTS_PROCESSED.labels(settings.service_name, REMEDIATION_EVENTS, "ok").inc()

    for source, consumer, consume_forever in consumers:
        task = asyncio.create_task(consume_forever(consumer, handle), name=f"closure-service-{source}-consumer")
        tasks.append(task)


async def shutdown(_: FastAPI) -> None:
    for task in tasks:
        task.cancel()


app = create_app(title="KaiMS Closure Service", settings=settings, startup=startup, shutdown=shutdown)


async def _validate_and_store(action: RemediationAction) -> ResolutionReport:
    report = await agent.validate(action)
    if settings.database_enabled:
        async with app.state.session_factory() as session:
            repo = IncidentRepository(session)
            await repo.save_report(report)
            validation = report.validation if isinstance(report.validation, dict) else {}
            metadata = report.metadata if isinstance(report.metadata, dict) else {}
            independently_verified = bool(
                report.health_restored
                and validation.get("independent_validation") is True
                and int(metadata.get("validation_evidence_count") or 0) > 0
                and str(metadata.get("validation_status") or "").upper() in {"RECOVERED", "VALIDATION_SUCCEEDED"}
            )
            if independently_verified:
                await repo.save_knowledge_base(report)
            await session.commit()
    return report


@app.post("/validate", response_model=ResolutionReport)
async def validate(action: RemediationAction) -> ResolutionReport:
    report = await _validate_and_store(action)
    await _persist_closure_event(app=app, action=action, report=report, source_payload={})
    return report
