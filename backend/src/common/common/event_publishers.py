from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from abc import ABC, abstractmethod
from typing import Any
from uuid import uuid4

from aiokafka import AIOKafkaProducer
from pydantic import BaseModel

from common.config import Settings, get_settings
from common.logging import get_logger
from common.models import AgentEventContractV1
from common.rabbitmq import RabbitMQProducer
from common.resilience import retry_async
from common.servicebus import AzureServiceBusProducer

logger = get_logger(__name__)


def normalize_payload(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, dict):
        return {key: normalize_payload(item) for key, item in value.items()}
    if isinstance(value, list):
        return [normalize_payload(item) for item in value]
    return value


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def build_event_envelope(
    *,
    event_type: str,
    identity: dict[str, Any],
    scope: dict[str, Any],
    state: dict[str, Any],
    policy: dict[str, Any],
    transport: dict[str, Any],
    payload: dict[str, Any],
    ai: dict[str, Any] | None = None,
    idempotency: dict[str, Any] | None = None,
    schema_version: str = "1.0",
) -> dict[str, Any]:
    identity_map = identity if isinstance(identity, dict) else {}
    incident_id = str(identity_map.get("incident_id") or "").strip()
    if not incident_id:
        raise ValueError("identity.incident_id is required for event envelope")

    envelope: dict[str, Any] = {
        "event_id": str(uuid4()),
        "event_type": str(event_type or "incident.event"),
        "schema_version": schema_version,
        "produced_at": _iso_now(),
        "identity": identity_map,
        "scope": scope if isinstance(scope, dict) else {},
        "state": state if isinstance(state, dict) else {},
        "policy": policy if isinstance(policy, dict) else {},
        "transport": transport if isinstance(transport, dict) else {},
        "idempotency": idempotency if isinstance(idempotency, dict) else {},
        "payload": payload if isinstance(payload, dict) else {},
    }
    envelope["incident_id"] = incident_id
    envelope["trace_id"] = str(identity_map.get("trace_id") or "")
    envelope["flow_id"] = str(scope.get("flow_id") if isinstance(scope, dict) else "")
    envelope["agent"] = str(scope.get("agent") if isinstance(scope, dict) else "")
    envelope["version"] = schema_version
    envelope["timestamp"] = envelope["produced_at"]
    envelope["confidence"] = float((ai or {}).get("confidence") or 0.0)
    if isinstance(ai, dict) and ai:
        envelope["ai"] = ai

    if not envelope["idempotency"].get("idempotency_key"):
        envelope["idempotency"]["idempotency_key"] = f"{envelope['event_type']}:{incident_id}"
    return envelope


def build_agent_event_contract(
    *,
    flow_id: str,
    incident_id: str,
    trace_id: str,
    agent: str,
    payload: dict[str, Any],
    metadata: dict[str, Any] | None = None,
    confidence: float = 0.0,
    reasoning: str = "",
    citations: list[str] | None = None,
    evidence_ids: list[str] | None = None,
    correlation_id: str | None = None,
    version: str = "v1",
) -> dict[str, Any]:
    event = AgentEventContractV1(
        flow_id=flow_id,
        incident_id=incident_id,
        trace_id=trace_id,
        correlation_id=correlation_id,
        agent=agent,
        version=version,
        payload=payload,
        metadata=metadata or {},
        confidence=confidence,
        reasoning=reasoning,
        citations=citations or [],
        evidence_ids=evidence_ids or [],
    )
    return event.model_dump(mode="json")


def _metadata(value: Any) -> dict[str, Any]:
    raw = getattr(value, "metadata", None)
    return raw if isinstance(raw, dict) else {}


def _labels(value: Any) -> dict[str, Any]:
    raw = getattr(value, "labels", None)
    return raw if isinstance(raw, dict) else {}


def _first_scope_value(*values: Any) -> str:
    for value in values:
        token = str(value or "").strip()
        if token:
            return token
    return ""


def _resolve_required_scope(alert: Any, incident: Any) -> tuple[str, str]:
    settings = get_settings()
    alert_metadata = _metadata(alert)
    incident_metadata = _metadata(incident)
    alert_labels = _labels(alert)

    tenant_id = _first_scope_value(
        getattr(alert, "tenant_id", None),
        getattr(incident, "tenant_id", None),
        alert_metadata.get("tenant_id"),
        incident_metadata.get("tenant_id"),
        alert_labels.get("tenant_id"),
    )
    environment = _first_scope_value(
        getattr(alert, "environment", None),
        getattr(incident, "environment", None),
        alert_metadata.get("environment"),
        incident_metadata.get("environment"),
        alert_labels.get("environment"),
    )

    deployment_mode = str(getattr(settings, "environment", "local") or "local").strip().lower()
    development_mode = deployment_mode in {"local", "dev", "development", "test", "testing", "simulation"}
    if not tenant_id and development_mode:
        tenant_id = "local"
    if not environment and development_mode:
        environment = deployment_mode or "local"

    if not tenant_id:
        raise ValueError("tenant scope is required; production events must not default to tenant 'default'")
    if not environment:
        raise ValueError("environment scope is required; production events must not default to 'prod'")
    return tenant_id, environment


def build_orchestration_envelope(
    *,
    alert: Any,
    incident: Any,
    decision: dict[str, Any],
    transport_provider: str,
    channel: str,
) -> dict[str, Any]:
    alert_id = str(getattr(alert, "id", "") or "")
    incident_id = str(getattr(incident, "id", "") or "")
    trace_id = str(getattr(incident, "trace_id", None) or getattr(alert, "trace_id", "") or "")
    correlation_id = str(getattr(alert, "correlation_id", "") or "")
    service = str(getattr(alert, "service", "") or getattr(incident, "service", "") or "unknown")
    tenant_id, environment = _resolve_required_scope(alert, incident)
    severity = str(getattr(alert, "severity", "") or getattr(incident, "severity", "") or "")
    if hasattr(getattr(alert, "severity", None), "value"):
        severity = str(getattr(alert.severity, "value", severity))

    return build_event_envelope(
        event_type="incident.workflow.selected",
        identity={
            "incident_id": incident_id,
            "alert_id": alert_id,
            "trace_id": trace_id,
            "correlation_id": correlation_id or None,
            "causation_id": None,
            "parent_event_id": None,
        },
        scope={
            "tenant_id": tenant_id,
            "service": service,
            "environment": environment,
            "region": None,
            "team": None,
        },
        state={
            "severity": severity,
            "status": "investigating",
            "owner": None,
        },
        policy={
            "risk_tier": str(decision.get("risk_tier") or "unknown"),
            "execution_mode": str(decision.get("execution_mode") or "unknown"),
            "requires_approval": bool(decision.get("requires_approval", False)),
            "policy_version": str(decision.get("policy_version") or "policy-v1"),
            "policy_reason": str(decision.get("policy_reason") or ""),
        },
        transport={
            "provider": str(transport_provider or "unknown"),
            "channel": str(channel or ""),
            "partition": None,
            "offset": None,
            "delivery_tag": None,
        },
        ai={
            "confidence": None,
            "model_provider": str(decision.get("planner_model") or "") or None,
            "model_name": str(decision.get("planner_model") or "") or None,
            "fallback_reason": str(decision.get("planner_reason") or "") or None,
        },
        idempotency={
            "idempotency_key": f"incident.workflow.selected:{incident_id}",
            "fingerprint": correlation_id or None,
        },
        payload={
            "workflow": str(decision.get("workflow") or ""),
            "next_action": str(decision.get("next_action") or ""),
            "downstream_agents": decision.get("downstream_agents", []),
        },
    )


class EventPublisher(ABC):
    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    async def start(self) -> None:
        return None

    async def stop(self) -> None:
        return None

    @abstractmethod
    async def publish(self, topic: str, event: BaseModel | dict[str, Any], key: str | None = None) -> None:
        raise NotImplementedError


class NoOpPublisher(EventPublisher):
    async def publish(self, topic: str, event: BaseModel | dict[str, Any], key: str | None = None) -> None:
        logger.info("event publisher disabled; event logged", extra={"topic": topic, "payload": normalize_payload(event), "key": key})


class KafkaPublisher(EventPublisher):
    def __init__(self, settings: Settings) -> None:
        super().__init__(settings)
        self._producer: AIOKafkaProducer | None = None

    async def start(self) -> None:
        if not self._settings.kafka_enabled:
            return
        last_error: Exception | None = None
        for attempt in range(1, self._settings.kafka_startup_attempts + 1):
            producer = AIOKafkaProducer(
                bootstrap_servers=self._settings.kafka_bootstrap_servers,
                value_serializer=lambda value: json.dumps(value, default=str).encode("utf-8"),
            )
            try:
                await producer.start()
                self._producer = producer
                logger.info("connected kafka publisher", extra={"bootstrap": self._settings.kafka_bootstrap_servers})
                return
            except Exception as exc:
                last_error = exc
                await producer.stop()
                logger.warning(
                    "kafka publisher not ready; retrying",
                    extra={
                        "attempt": attempt,
                        "attempts": self._settings.kafka_startup_attempts,
                        "bootstrap": self._settings.kafka_bootstrap_servers,
                        "error": str(exc),
                    },
                )
                await asyncio.sleep(self._settings.kafka_startup_retry_seconds)
        assert last_error is not None
        raise last_error

    async def stop(self) -> None:
        if self._producer is not None:
            await self._producer.stop()

    async def publish(self, topic: str, event: BaseModel | dict[str, Any], key: str | None = None) -> None:
        payload = normalize_payload(event)
        if self._producer is None:
            logger.info("kafka publisher unavailable; event logged", extra={"topic": topic, "payload": payload})
            return

        async def send() -> None:
            assert self._producer is not None
            await self._producer.send_and_wait(topic, payload, key=key.encode("utf-8") if key else None)

        await retry_async(send)


class RabbitMQPublisher(NoOpPublisher):
    def __init__(self, settings: Settings) -> None:
        super().__init__(settings)
        self._producer = RabbitMQProducer(settings)

    async def start(self) -> None:
        await self._producer.start()

    async def stop(self) -> None:
        await self._producer.stop()

    async def publish(self, topic: str, event: BaseModel | dict[str, Any], key: str | None = None) -> None:
        await self._producer.publish(topic, event, key=key)


class AzureServiceBusPublisher(NoOpPublisher):
    def __init__(self, settings: Settings) -> None:
        super().__init__(settings)
        self._producer = AzureServiceBusProducer(settings)

    async def start(self) -> None:
        await self._producer.start()

    async def stop(self) -> None:
        await self._producer.stop()

    async def publish(self, topic: str, event: BaseModel | dict[str, Any], key: str | None = None) -> None:
        await self._producer.publish(topic, event, key=key)


class RestPublisher(NoOpPublisher):
    pass


def build_event_publisher(settings: Settings) -> EventPublisher:
    provider = getattr(settings, "event_bus_provider", "kafka").strip().lower()
    if not settings.kafka_enabled and provider == "kafka":
        return NoOpPublisher(settings)
    if provider == "noop":
        return NoOpPublisher(settings)
    if provider == "rabbitmq":
        return RabbitMQPublisher(settings)
    if provider in {"azure", "azure-service-bus", "servicebus"}:
        return AzureServiceBusPublisher(settings)
    if provider == "rest":
        return RestPublisher(settings)
    return KafkaPublisher(settings)
