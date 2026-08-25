from __future__ import annotations

import asyncio
import os
from collections.abc import Awaitable, Callable, Coroutine
from typing import Any

from ai_workbench_common.models import Context
from common.config import get_settings
from common.event_publishers import build_agent_event_contract, build_event_envelope
from common.kafka import KafkaConsumer, consume_forever as consume_kafka_forever
from common.models import Incident, Recommendation
from common.rabbitmq import RabbitMQConsumer, consume_forever as consume_rabbitmq_forever
from common.repository import IncidentRepository
from common.resolution_models import PlanSnapshot, RemediationPlan
from common.resolution_store import CanonicalResolutionStore
from common.service import create_app
from common.telemetry import EVENTS_PROCESSED
from common.topics import CONTEXT_EVENTS, RESOLUTION_EVENTS
from fastapi import FastAPI
from resolution_agent import ResolutionIntelligenceAgent

settings = get_settings()
settings.service_name = "resolution-agent"
agent = ResolutionIntelligenceAgent()
tasks: list[asyncio.Task] = []
MESSAGE_BUS_DUAL_CONSUME_ENABLED = str(
    os.getenv("MESSAGE_BUS_DUAL_CONSUME_ENABLED", "false")
).strip().lower() in {"1", "true", "yes", "on"}

ConsumeRunner = Callable[[Any, Callable[[dict], Awaitable[None]]], Coroutine[Any, Any, None]]


def _context_scope(context: Context) -> tuple[str | None, str | None]:
    context_metadata = context.metadata if isinstance(context.metadata, dict) else {}
    alert_metadata = context.alert.metadata if isinstance(context.alert.metadata, dict) else {}
    tenant_id = str(
        context_metadata.get("tenant_id")
        or alert_metadata.get("tenant_id")
        or ""
    ).strip() or None
    environment = str(
        context.alert.environment
        or context_metadata.get("environment")
        or alert_metadata.get("environment")
        or ""
    ).strip() or None
    return tenant_id, environment


def _build_resolution_event_payload(
    *,
    context: Context,
    incident: Incident,
    recommendation: Recommendation,
    decision_payload: dict[str, Any],
) -> dict[str, Any]:
    flow_id = str(decision_payload.get("flow_id") or incident.id)
    event_contract = build_agent_event_contract(
        flow_id=flow_id,
        incident_id=str(incident.id),
        trace_id=str(incident.trace_id or context.alert.trace_id or ""),
        correlation_id=str(context.alert.correlation_id or "") or None,
        agent="resolution-agent",
        payload={
            "recommended_action": recommendation.recommended_action,
            "recommended_capability": recommendation.metadata.get("recommended_capability"),
            "plan_hash": recommendation.metadata.get("plan_hash"),
            "plan_revision": recommendation.metadata.get("plan_revision"),
            "planning_status": recommendation.metadata.get("planning_status"),
            "risk": recommendation.risk,
            "topic": RESOLUTION_EVENTS,
        },
        metadata={
            "policy_version": recommendation.metadata.get("policy_version"),
            "policy_reason": recommendation.metadata.get("policy_reason"),
            "workflow": decision_payload.get("workflow"),
        },
        confidence=float(recommendation.confidence),
        reasoning=str(recommendation.metadata.get("reasoning") or recommendation.rationale or ""),
        citations=list(recommendation.metadata.get("citations", [])),
        evidence_ids=list(recommendation.metadata.get("evidence_ids", [])),
    )
    return {
        "recommendation": recommendation,
        "context": context,
        "incident": incident,
        "decision": decision_payload,
        "event_contract": event_contract,
    }


async def _persist_structured_plan(*, session: Any, context: Context, recommendation: Recommendation) -> None:
    metadata = recommendation.metadata if isinstance(recommendation.metadata, dict) else {}
    plan_payload = metadata.get("remediation_plan")
    if not isinstance(plan_payload, dict):
        return
    tenant_id, _ = _context_scope(context)
    if not tenant_id:
        raise ValueError("TENANT_CONTEXT_MISSING: cannot persist remediation plan without tenant scope")
    plan = RemediationPlan.model_validate(plan_payload)
    snapshot = PlanSnapshot.from_plan(plan)
    approved_hash = str(metadata.get("plan_hash") or "").strip()
    approved_revision = metadata.get("plan_revision")
    if approved_hash != snapshot.plan_hash or int(approved_revision or 0) != snapshot.plan_revision:
        raise ValueError("PLAN_SNAPSHOT_MISMATCH")
    store = CanonicalResolutionStore(session)
    await store.save_plan(tenant_id=tenant_id, plan=plan, snapshot=snapshot)


async def _persist_resolution_event(
    *,
    app: FastAPI,
    context: Context,
    incident: Incident,
    recommendation: Recommendation,
    decision_payload: dict[str, Any],
) -> None:
    if not settings.database_enabled or getattr(app.state, "session_factory", None) is None:
        return
    metadata = recommendation.metadata if isinstance(recommendation.metadata, dict) else {}
    orchestration = (
        metadata.get("orchestration_decision")
        if isinstance(metadata.get("orchestration_decision"), dict)
        else {}
    )
    requires_approval = decision_payload.get("requires_approval")
    if requires_approval is None:
        requires_approval = orchestration.get("requires_approval")
    status = "awaiting_approval" if bool(requires_approval) else "remediating"
    provider = (
        decision_payload.get("message_bus_provider")
        or orchestration.get("message_bus_provider")
        or "unknown"
    )
    tenant_id, environment = _context_scope(context)
    if not tenant_id:
        raise ValueError("TENANT_CONTEXT_MISSING: resolution event persistence requires tenant scope")
    if not environment:
        raise ValueError("ENVIRONMENT_CONTEXT_MISSING: resolution event persistence requires environment")
    async with app.state.session_factory() as session:
        repo = IncidentRepository(session)
        await repo.save_incident_event(
            build_event_envelope(
                event_type="incident.recommendation.generated",
                identity={
                    "incident_id": str(incident.id),
                    "alert_id": str(context.alert.id),
                    "trace_id": str(incident.trace_id or context.alert.trace_id or ""),
                    "correlation_id": str(context.alert.correlation_id or "") or None,
                    "causation_id": None,
                    "parent_event_id": None,
                },
                scope={
                    "tenant_id": tenant_id,
                    "service": str(context.alert.service or "unknown"),
                    "environment": environment,
                    "region": None,
                    "team": str(context.alert.metadata.get("owner_team") or "") or None,
                },
                state={
                    "severity": str(getattr(context.alert.severity, "value", context.alert.severity) or "warning").lower(),
                    "status": status,
                    "owner": None,
                },
                policy={
                    "risk_tier": str(decision_payload.get("risk_tier") or orchestration.get("risk_tier") or "unknown"),
                    "execution_mode": str(decision_payload.get("execution_mode") or orchestration.get("execution_mode") or "unknown"),
                    "requires_approval": requires_approval,
                    "policy_version": decision_payload.get("policy_version") or orchestration.get("policy_version") or metadata.get("policy_version"),
                    "policy_reason": decision_payload.get("policy_reason") or orchestration.get("policy_reason") or metadata.get("policy_reason"),
                },
                transport={
                    "provider": str(provider),
                    "channel": RESOLUTION_EVENTS,
                    "partition": None,
                    "offset": None,
                    "delivery_tag": None,
                },
                ai={
                    "confidence": float(recommendation.confidence),
                    "model_provider": str((metadata.get("model_usage") or [{}])[0].get("provider") if isinstance(metadata.get("model_usage"), list) and metadata.get("model_usage") else "") or None,
                    "model_name": str((metadata.get("model_usage") or [{}])[0].get("model") if isinstance(metadata.get("model_usage"), list) and metadata.get("model_usage") else "") or None,
                    "fallback_reason": None,
                },
                payload={
                    "recommendation_id": str(recommendation.id),
                    "recommended_action": recommendation.recommended_action,
                    "recommended_capability": metadata.get("recommended_capability"),
                    "plan_hash": metadata.get("plan_hash"),
                    "plan_revision": metadata.get("plan_revision"),
                    "planning_status": metadata.get("planning_status"),
                    "root_cause": recommendation.root_cause,
                    "impact": recommendation.impact,
                    "risk": recommendation.risk,
                },
            )
        )
        await _persist_structured_plan(session=session, context=context, recommendation=recommendation)
        await session.commit()


async def startup(app: FastAPI) -> None:
    workers = max(1, int(getattr(settings, "message_bus_worker_count", 1) or 1))
    consumers: list[tuple[str, Any, ConsumeRunner]] = []
    for worker in range(workers):
        consumers.append((f"rabbitmq-w{worker + 1}", RabbitMQConsumer(settings, CONTEXT_EVENTS), consume_rabbitmq_forever))
    if settings.kafka_enabled and MESSAGE_BUS_DUAL_CONSUME_ENABLED:
        for worker in range(workers):
            consumers.insert(
                worker,
                (f"kafka-w{worker + 1}", KafkaConsumer(settings, CONTEXT_EVENTS), consume_kafka_forever),
            )

    async def handle(payload: dict) -> None:
        context = Context.model_validate(payload["context"])
        incident = Incident.model_validate(payload["incident"])
        decision_payload = payload.get("decision", {}) if isinstance(payload.get("decision"), dict) else {}
        recommendation = await agent.resolve_with_runtime(context)
        recommendation.trace_id = str(incident.trace_id or context.alert.trace_id or "") or None
        recommendation.metadata["rag_documents"] = context.metadata.get("rag_documents", 0)
        recommendation.metadata["rag_matches"] = context.metadata.get("rag_matches", [])
        recommendation.metadata["rag_top_similarity"] = context.metadata.get("rag_top_similarity", 0.0)
        recommendation.metadata["rag_service_tagged_match"] = context.metadata.get("rag_service_tagged_match", False)
        recommendation.metadata["discovery_report"] = context.metadata.get("discovery_report", {})
        recommendation.metadata["discovery_evidence"] = context.metadata.get("discovery_evidence", {})
        recommendation.metadata["runbook_found"] = bool(context.runbook)
        policy_version = str(decision_payload.get("policy_version") or "").strip()
        policy_reason = str(decision_payload.get("policy_reason") or "").strip()
        if policy_version:
            recommendation.metadata["policy_version"] = policy_version
        if policy_reason:
            recommendation.metadata["policy_reason"] = policy_reason
        if decision_payload:
            recommendation.metadata["orchestration_decision"] = {
                "workflow": decision_payload.get("workflow"),
                "requires_approval": decision_payload.get("requires_approval"),
                "message_bus_provider": decision_payload.get("message_bus_provider"),
                "stream_count": decision_payload.get("stream_count"),
                "stream_threshold": decision_payload.get("stream_threshold"),
            }
        if settings.database_enabled:
            async with app.state.session_factory() as session:
                repo = IncidentRepository(session)
                await repo.save_recommendation_as_audit(recommendation)
                await session.commit()
        await _persist_resolution_event(
            app=app,
            context=context,
            incident=incident,
            recommendation=recommendation,
            decision_payload=decision_payload,
        )
        payload_out = _build_resolution_event_payload(
            context=context,
            incident=incident,
            recommendation=recommendation,
            decision_payload=decision_payload,
        )
        await app.state.producer.publish(RESOLUTION_EVENTS, payload_out, key=str(context.incident_id))
        EVENTS_PROCESSED.labels(settings.service_name, CONTEXT_EVENTS, "ok").inc()

    for source, consumer, consume_forever in consumers:
        task = asyncio.create_task(consume_forever(consumer, handle), name=f"resolution-agent-{source}-consumer")
        tasks.append(task)


async def shutdown(_: FastAPI) -> None:
    for task in tasks:
        task.cancel()


app = create_app(title="KaiMS Resolution Intelligence Agent", settings=settings, startup=startup, shutdown=shutdown)


@app.post("/resolve", response_model=Recommendation)
async def resolve(context: Context) -> Recommendation:
    recommendation = await agent.resolve_with_runtime(context)
    recommendation.trace_id = str(context.alert.trace_id or "") or None
    recommendation.metadata["rag_documents"] = context.metadata.get("rag_documents", 0)
    recommendation.metadata["rag_matches"] = context.metadata.get("rag_matches", [])
    recommendation.metadata["rag_top_similarity"] = context.metadata.get("rag_top_similarity", 0.0)
    recommendation.metadata["rag_service_tagged_match"] = context.metadata.get("rag_service_tagged_match", False)
    recommendation.metadata["discovery_report"] = context.metadata.get("discovery_report", {})
    recommendation.metadata["discovery_evidence"] = context.metadata.get("discovery_evidence", {})
    recommendation.metadata["runbook_found"] = bool(context.runbook)
    synthetic_incident = Incident(
        id=context.incident_id,
        service=context.alert.service,
        severity=context.alert.severity,
        title=f"{context.alert.service}: {context.alert.name}",
    )
    payload_out = _build_resolution_event_payload(
        context=context,
        incident=synthetic_incident,
        recommendation=recommendation,
        decision_payload={},
    )
    await app.state.producer.publish(RESOLUTION_EVENTS, payload_out)
    return recommendation
