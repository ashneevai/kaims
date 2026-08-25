from __future__ import annotations

import asyncio
from time import perf_counter
from uuid import UUID

from common.audit_ledger import ImmutableAuditLedger
from common.config import get_settings
from common.logging import get_logger
from common.models import MonitoringAuditEvent, RemediationAction
from common.rabbitmq import RabbitMQConsumer, consume_forever as consume_rabbitmq_forever
from common.remediation_audit import append_privileged_remediation_audit
from common.repository import IncidentRepository
from common.service import create_app
from common.topics import (
    APPLICATION_DASHBOARD_CREATED,
    APPLICATION_DISCOVERY_COMPLETED,
    APPLICATION_METRICS_VALIDATED,
    APPLICATION_ONBOARD_REQUESTED,
    APPLICATION_PROMETHEUS_UPDATED,
    APPLICATION_RULES_GENERATED,
    APPLICATION_VALIDATION_COMPLETED,
    REMEDIATION_EVENTS,
)
from fastapi import FastAPI, HTTPException, Query

settings = get_settings()
settings.service_name = "audit-service"
logger = get_logger(__name__)
tasks: list[asyncio.Task] = []


def _production() -> bool:
    return settings.environment.lower() not in {
        "local", "dev", "development", "test", "testing", "simulation"
    }


def _resolve_identity(payload: dict) -> tuple[UUID | None, str]:
    application_id = payload.get("application_id") or payload.get("id")
    if application_id:
        try:
            return UUID(str(application_id)), str(payload.get("tenant_id") or "default")
        except ValueError:
            return None, str(payload.get("tenant_id") or "default")
    return None, str(payload.get("tenant_id") or "default")


def _extract_remediation_action(payload: dict) -> RemediationAction | None:
    candidate = payload.get("remediation_action") if isinstance(payload, dict) else None
    if isinstance(candidate, RemediationAction):
        return candidate
    if isinstance(candidate, dict):
        return RemediationAction.model_validate(candidate)
    return None


async def startup(app: FastAPI) -> None:
    async def handle_factory(event_type: str):
        async def handle(payload: dict) -> None:
            started = perf_counter()
            application_id, tenant_id = _resolve_identity(payload)
            if application_id is None:
                return
            session_factory = getattr(app.state, "session_factory", None)
            if session_factory is None:
                return
            async with session_factory() as session:
                repo = IncidentRepository(session)
                await repo.save_monitoring_audit(
                    MonitoringAuditEvent(
                        application_id=application_id,
                        tenant_id=tenant_id,
                        event_type=event_type,
                        actor="system",
                        agent="audit-service",
                        decision="recorded",
                        execution_time_ms=(perf_counter() - started) * 1000.0,
                        input=payload,
                        output={"stored": True},
                    )
                )
                await session.commit()
        return handle

    async def handle_remediation(payload: dict) -> None:
        action = _extract_remediation_action(payload)
        if action is None:
            logger.error("immutable_ledger_remediation_payload_invalid")
            if _production():
                raise ValueError("REMEDIATION_ACTION_MISSING_FOR_IMMUTABLE_LEDGER")
            return
        session_factory = getattr(app.state, "session_factory", None)
        if session_factory is None:
            if _production():
                raise RuntimeError("IMMUTABLE_LEDGER_DATABASE_UNAVAILABLE")
            return
        async with session_factory() as session:
            ledger = ImmutableAuditLedger(session)
            record = await append_privileged_remediation_audit(
                ledger=ledger,
                action=action,
                production=_production(),
            )
            verification = await ledger.verify_tenant_chain(str(record.get("tenant_id") or ""))
            if not verification.get("valid"):
                await session.rollback()
                logger.critical(
                    "immutable_audit_chain_broken",
                    extra={"tenant_id": record.get("tenant_id"), "failures": verification.get("failures")},
                )
                raise RuntimeError("IMMUTABLE_AUDIT_CHAIN_VERIFICATION_FAILED")
            await session.commit()

    for topic in [
        APPLICATION_ONBOARD_REQUESTED,
        APPLICATION_DISCOVERY_COMPLETED,
        APPLICATION_METRICS_VALIDATED,
        APPLICATION_RULES_GENERATED,
        APPLICATION_PROMETHEUS_UPDATED,
        APPLICATION_VALIDATION_COMPLETED,
        APPLICATION_DASHBOARD_CREATED,
    ]:
        consumer = RabbitMQConsumer(settings, topic)
        tasks.append(asyncio.create_task(consume_rabbitmq_forever(consumer, await handle_factory(topic)), name=f"audit-{topic}"))

    remediation_consumer = RabbitMQConsumer(settings, REMEDIATION_EVENTS)
    tasks.append(
        asyncio.create_task(
            consume_rabbitmq_forever(remediation_consumer, handle_remediation),
            name="audit-remediation-immutable-ledger",
        )
    )


async def shutdown(_: FastAPI) -> None:
    for task in tasks:
        task.cancel()


app = create_app(title="KaiOps Audit Service", settings=settings, startup=startup, shutdown=shutdown)


@app.get("/ledger/{tenant_id}/verify")
async def verify_tenant_ledger(
    tenant_id: str,
    fail_on_broken_chain: bool = Query(default=False),
) -> dict:
    tenant = str(tenant_id or "").strip()
    if not tenant:
        raise HTTPException(status_code=400, detail="tenant_id is required")
    session_factory = getattr(app.state, "session_factory", None)
    if session_factory is None:
        raise HTTPException(status_code=503, detail="audit ledger database is unavailable")
    async with session_factory() as session:
        result = await ImmutableAuditLedger(session).verify_tenant_chain(tenant)
    if fail_on_broken_chain and not result.get("valid"):
        raise HTTPException(status_code=409, detail=result)
    return result
