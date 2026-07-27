from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest
from common.event_publishers import build_event_envelope
from common.models import (
    Alert,
    AlertSeverity,
    Approval,
    ApprovalDecision,
    Incident,
    Recommendation,
    RemediationAction,
    ResolutionReport,
)
from orchestrator.message_bus import publish_orchestration_event
from context_agent import ContextIntelligenceAgent

_CONTEXT_APP_PATH = Path(__file__).resolve().parents[2] / "ai-workbench" / "src" / "context-agent" / "app.py"
_CONTEXT_SPEC = importlib.util.spec_from_file_location("context_agent_app", _CONTEXT_APP_PATH)
assert _CONTEXT_SPEC is not None and _CONTEXT_SPEC.loader is not None
context_agent_app = importlib.util.module_from_spec(_CONTEXT_SPEC)
_CONTEXT_SPEC.loader.exec_module(context_agent_app)

_RESOLUTION_APP_PATH = Path(__file__).resolve().parents[2] / "ai-workbench" / "src" / "resolution-agent" / "app.py"
_RESOLUTION_SPEC = importlib.util.spec_from_file_location("resolution_agent_app", _RESOLUTION_APP_PATH)
assert _RESOLUTION_SPEC is not None and _RESOLUTION_SPEC.loader is not None
resolution_agent_app = importlib.util.module_from_spec(_RESOLUTION_SPEC)
_RESOLUTION_SPEC.loader.exec_module(resolution_agent_app)

_APPROVAL_APP_PATH = Path(__file__).resolve().parents[1] / "src" / "approval-service" / "app.py"
_APPROVAL_SPEC = importlib.util.spec_from_file_location("approval_service_app", _APPROVAL_APP_PATH)
assert _APPROVAL_SPEC is not None and _APPROVAL_SPEC.loader is not None
approval_service_app = importlib.util.module_from_spec(_APPROVAL_SPEC)
_APPROVAL_SPEC.loader.exec_module(approval_service_app)

_REMEDIATION_APP_PATH = Path(__file__).resolve().parents[1] / "src" / "remediation-engine" / "app.py"
_REMEDIATION_SPEC = importlib.util.spec_from_file_location("remediation_engine_app", _REMEDIATION_APP_PATH)
assert _REMEDIATION_SPEC is not None and _REMEDIATION_SPEC.loader is not None
remediation_engine_app = importlib.util.module_from_spec(_REMEDIATION_SPEC)
_REMEDIATION_SPEC.loader.exec_module(remediation_engine_app)

_CLOSURE_APP_PATH = Path(__file__).resolve().parents[1] / "src" / "closure-service" / "app.py"
_CLOSURE_SPEC = importlib.util.spec_from_file_location("closure_service_app", _CLOSURE_APP_PATH)
assert _CLOSURE_SPEC is not None and _CLOSURE_SPEC.loader is not None
closure_service_app = importlib.util.module_from_spec(_CLOSURE_SPEC)
_CLOSURE_SPEC.loader.exec_module(closure_service_app)

_MONITORING_APP_PATH = Path(__file__).resolve().parents[1] / "src" / "monitoring-adapter" / "app.py"
_MONITORING_SPEC = importlib.util.spec_from_file_location("monitoring_adapter_app", _MONITORING_APP_PATH)
assert _MONITORING_SPEC is not None and _MONITORING_SPEC.loader is not None
monitoring_adapter_app = importlib.util.module_from_spec(_MONITORING_SPEC)
_MONITORING_SPEC.loader.exec_module(monitoring_adapter_app)

_API_GATEWAY_APP_PATH = Path(__file__).resolve().parents[1] / "src" / "api-gateway" / "app.py"
_API_GATEWAY_SPEC = importlib.util.spec_from_file_location("api_gateway_app", _API_GATEWAY_APP_PATH)
assert _API_GATEWAY_SPEC is not None and _API_GATEWAY_SPEC.loader is not None
api_gateway_app = importlib.util.module_from_spec(_API_GATEWAY_SPEC)
_API_GATEWAY_SPEC.loader.exec_module(api_gateway_app)


def test_jira_adf_description_is_normalized_before_discovery() -> None:
    payload = {
        "webhookEvent": "jira:issue_updated",
        "issue": {
            "id": "10001",
            "key": "KAN-1",
            "fields": {
                "summary": "kaiops-core1 endpoint unavailable",
                "description": {
                    "type": "doc",
                    "version": 1,
                    "content": [
                        {
                            "type": "heading",
                            "attrs": {"level": 2},
                            "content": [{"type": "text", "text": "Initial hypothesis"}],
                        },
                        {
                            "type": "paragraph",
                            "content": [
                                {
                                    "type": "text",
                                    "text": "The endpoint is experiencing connectivity issues.",
                                }
                            ],
                        },
                        {
                            "type": "bulletList",
                            "content": [
                                {
                                    "type": "listItem",
                                    "content": [
                                        {
                                            "type": "paragraph",
                                            "content": [{"type": "text", "text": "Service: kaiops-core1"}],
                                        }
                                    ],
                                }
                            ],
                        },
                    ],
                },
                "project": {"key": "KAN"},
                "priority": {"name": "Highest"},
            },
        },
    }

    alert, issue_key = monitoring_adapter_app._jira_payload_to_alert_payload(payload)

    assert issue_key == "KAN-1"
    assert alert["description"] == (
        "Initial hypothesis\n"
        "The endpoint is experiencing connectivity issues.\n"
        "- Service: kaiops-core1"
    )
    assert alert["annotations"]["description"] == alert["description"]
    assert "{'type': 'doc'" not in alert["description"]


def test_build_event_envelope_exposes_contract_friendly_fields() -> None:
    envelope = build_event_envelope(
        event_type="incident.workflow.selected",
        identity={"incident_id": "inc-1", "trace_id": "tr-1"},
        scope={"flow_id": "flow-1", "agent": "orchestrator"},
        state={"status": "investigating"},
        policy={"risk_tier": "high"},
        transport={"provider": "rabbitmq"},
        payload={"workflow": "critical-auto-remediation"},
        ai={"confidence": 0.87},
    )

    assert envelope["incident_id"] == "inc-1"
    assert envelope["trace_id"] == "tr-1"
    assert envelope["flow_id"] == "flow-1"
    assert envelope["agent"] == "orchestrator"
    assert envelope["confidence"] == 0.87


class FakePublisher:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    async def publish(self, topic: str, payload: dict, key: str | None = None) -> None:
        self.calls.append({"topic": topic, "payload": payload, "key": key})


@pytest.mark.asyncio
async def test_publish_orchestration_event_emits_event_contract() -> None:
    alert = Alert(
        source="prometheus",
        name="PaymentsLatencyHigh",
        service="payments",
        severity=AlertSeverity.CRITICAL,
        description="latency increased",
    )
    incident = Incident(service="payments", severity=AlertSeverity.CRITICAL, title="payments latency")
    decision = {
        "workflow": "critical-auto-remediation",
        "next_action": "collect-context",
        "policy_version": "policy-v1",
        "policy_reason": "critical severity",
        "message_bus_provider": "rabbitmq",
        "execution_mode": "human-approval",
        "risk_tier": "high",
        "planner_reason": "deterministic",
    }

    publisher = FakePublisher()
    provider_used = await publish_orchestration_event(
        producer=publisher,
        publishers={"rabbitmq": publisher},
        topic="orchestration-events",
        alert=alert,
        incident=incident,
        decision=decision,
    )

    assert provider_used == "rabbitmq"
    assert len(publisher.calls) == 1
    payload = publisher.calls[0]["payload"]
    assert "event_envelope" in payload
    assert "event_contract" in payload
    assert payload["event_contract"]["version"] == "v1"
    assert payload["event_contract"]["agent"] == "orchestrator"
    assert payload["event_contract"]["incident_id"] == str(incident.id)


@pytest.mark.asyncio
async def test_context_event_payload_includes_event_contract() -> None:
    alert = Alert(
        source="prometheus",
        name="PaymentsLatencyHigh",
        service="payments",
        severity=AlertSeverity.CRITICAL,
        description="latency increased",
    )
    incident = Incident(service="payments", severity=AlertSeverity.CRITICAL, title="payments latency")
    context = await ContextIntelligenceAgent().collect(alert, incident)

    payload = context_agent_app._build_context_event_payload(
        alert=alert,
        incident=incident,
        context=context,
        decision={"workflow": "critical-auto-remediation", "requires_approval": True},
        provider_used="rabbitmq",
    )

    assert "event_contract" in payload
    assert payload["event_contract"]["agent"] == "context-agent"
    assert payload["event_contract"]["incident_id"] == str(incident.id)


@pytest.mark.asyncio
async def test_resolution_event_payload_includes_event_contract() -> None:
    alert = Alert(
        source="prometheus",
        name="PaymentsLatencyHigh",
        service="payments",
        severity=AlertSeverity.CRITICAL,
        description="latency increased",
    )
    incident = Incident(service="payments", severity=AlertSeverity.CRITICAL, title="payments latency")
    context = await ContextIntelligenceAgent().collect(alert, incident)
    recommendation = Recommendation(
        incident_id=context.incident_id,
        root_cause="Deployment 2.5",
        confidence=0.91,
        impact="Payments latency",
        recommended_action="Rollback deployment",
        severity=context.alert.severity,
        rationale="Deployment correlation and runbook guidance",
        commands=["rollback:payments-api"],
        risk="high",
        metadata={
            "reasoning": "Deployment timeline overlaps alert onset",
            "citations": ["runbook://payments", "incident://history"],
            "evidence_ids": ["ev-1", "ev-2"],
        },
    )

    payload = resolution_agent_app._build_resolution_event_payload(
        context=context,
        incident=incident,
        recommendation=recommendation,
        decision_payload={"workflow": "critical-auto-remediation"},
    )

    assert "event_contract" in payload
    assert payload["event_contract"]["agent"] == "resolution-agent"
    assert payload["event_contract"]["incident_id"] == str(incident.id)


def test_approval_event_payload_includes_event_contract() -> None:
    approval = Approval(
        incident_id="11111111-1111-1111-1111-111111111111",
        recommendation_id="22222222-2222-2222-2222-222222222222",
        decision=ApprovalDecision.APPROVED,
        approver="alice",
        channel="web",
        comment="approved",
    )
    approval_service_app.PENDING_INCIDENTS[str(approval.incident_id)] = {
        "recommendation": {"id": str(approval.recommendation_id)},
        "decision": {"flow_id": "flow-approval-1"},
    }

    payload = approval_service_app._build_approval_event_payload(approval)

    assert "approval" in payload
    assert "event_contract" in payload
    assert payload["event_contract"]["agent"] == "approval-service"
    assert payload["event_contract"]["incident_id"] == str(approval.incident_id)


def test_remediation_payload_builder_and_approval_extractor_compatibility() -> None:
    approval_payload = {
        "approval": {
            "incident_id": "11111111-1111-1111-1111-111111111111",
            "recommendation_id": "22222222-2222-2222-2222-222222222222",
            "decision": "approved",
            "approver": "alice",
            "channel": "web",
        }
    }
    extracted = remediation_engine_app._extract_approval_payload(approval_payload)
    assert extracted["incident_id"] == "11111111-1111-1111-1111-111111111111"

    action = RemediationAction(
        incident_id="11111111-1111-1111-1111-111111111111",
        action_type="restart_pod",
        target="payments",
        output="ok",
    )
    payload = remediation_engine_app._build_remediation_event_payload(
        action=action,
        source_payload={"decision": {"flow_id": "flow-remediation-1"}},
        source="approval-events",
    )

    assert "remediation_action" in payload
    assert "event_contract" in payload
    assert payload["event_contract"]["agent"] == "remediation-engine"
    assert payload["event_contract"]["incident_id"] == str(action.incident_id)


def test_closure_payload_builder_and_action_extractor_compatibility() -> None:
    raw = {
        "remediation_action": {
            "incident_id": "11111111-1111-1111-1111-111111111111",
            "action_type": "restart_pod",
            "target": "payments",
            "status": "succeeded",
            "output": "ok",
        }
    }
    extracted = closure_service_app._extract_remediation_action_payload(raw)
    assert extracted["action_type"] == "restart_pod"

    action = RemediationAction.model_validate(extracted)
    report = ResolutionReport(
        incident_id=action.incident_id,
        root_cause="Deployment regression",
        impact="Payment latency",
        action_taken="restart_pod",
        health_restored=True,
        alerts_cleared=True,
        knowledge_base_entry="kb://entry",
    )
    payload = closure_service_app._build_closure_event_payload(
        action=action,
        report=report,
        source_payload={"event_contract": {"flow_id": "flow-close-1", "trace_id": "trace-close-1"}},
    )

    assert "report" in payload
    assert "event_contract" in payload
    assert payload["event_contract"]["agent"] == "closure-service"
    assert payload["event_contract"]["incident_id"] == str(action.incident_id)


def test_closure_service_name_prefers_incident_service_over_action_target() -> None:
    action = RemediationAction(
        incident_id="11111111-1111-1111-1111-111111111111",
        action_type="validate_pipeline",
        target="11111111-1111-1111-1111-111111111111",
        output="health check failed",
    )

    assert closure_service_app._resolve_closure_service_name(action, {"service": "orders-pipeline"}) == "orders-pipeline"
    assert closure_service_app._resolve_closure_service_name(action, {}) == str(action.target)


def test_closure_final_incident_payload_ignores_ui_approval_fields() -> None:
    action = RemediationAction(
        incident_id="11111111-1111-1111-1111-111111111111",
        action_type="script_execution",
        target="mysql",
        status="succeeded",
        output="health restored",
        parameters={"environment": "prod"},
    )
    report = ResolutionReport(
        incident_id=action.incident_id,
        remediation_action_id=action.id,
        root_cause="Alert table growth",
        impact="DB pressure",
        action_taken="script_execution",
        health_restored=True,
        alerts_cleared=True,
        knowledge_base_entry="resolved",
    )
    payload = closure_service_app._build_final_incident_payload(
        action=action,
        report=report,
        incident_payload={
            "service": "mysql",
            "environment": "prod",
            "severity": "high",
            "title": "mysql: row count high",
            "state": "remediating",
            "approval_status": "remediating",
            "approval": {"decision": "approved"},
        },
        recommendation={"trace_id": "trace-closure"},
        source_contract={},
    )

    assert payload["status"] == "closed"
    assert payload["service"] == "mysql"
    assert payload["trace_id"] == "trace-closure"
    assert "state" not in payload
    assert "approval" not in payload
    assert "approval_status" not in payload
    Incident.model_validate(payload)


def test_monitoring_raw_alert_payload_includes_event_contract() -> None:
    alert = Alert(
        source="prometheus",
        name="DatabaseReplicaLag",
        service="orders-db",
        severity=AlertSeverity.HIGH,
        description="replica lag increased",
    )

    payload = monitoring_adapter_app._build_raw_alert_event_payload(alert)

    assert "alert" in payload
    assert "event_contract" in payload
    assert payload["event_contract"]["agent"] == "monitoring-adapter"
    assert payload["event_contract"]["payload"]["topic"] == "raw-alerts"


def test_api_gateway_audit_contract_builder() -> None:
    event = api_gateway_app.GatewayAuditEvent(
        trace_id="trace-123",
        method="GET",
        path="/alerts/recent",
        target_url="http://monitoring-adapter:8000/alerts/recent",
        status_code=200,
        latency_ms=12.4,
    )

    contract = api_gateway_app._build_gateway_audit_contract(event)

    assert contract["agent"] == "api-gateway"
    assert contract["trace_id"] == "trace-123"
    assert contract["payload"]["path"] == "/alerts/recent"
