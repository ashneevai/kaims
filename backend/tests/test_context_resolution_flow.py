import json

import pytest
from ai_workbench_common.models import Context
from ai_workbench_common.memory_store import InMemoryStore
from common.models import Alert, AlertSeverity, Incident
from context_agent import ContextIntelligenceAgent
from context_agent.connectors import DiscoveryMCPConnector, VectorDBConnector
from model_router import ModelRouter
from model_router.router import ModelProvider, ModelResponse, build_usage
from resolution_agent import ResolutionIntelligenceAgent


class StaticProvider(ModelProvider):
    async def generate(self, prompt: str, payload: dict) -> ModelResponse:
        self._ensure_available()
        self.breaker.record_success()
        return ModelResponse(
            content=f"{self.name}:{prompt}:{payload.get('summary', payload.get('service', 'incident'))}",
            usage=build_usage(
                provider=self.name,
                model=f"{self.name}-model",
                input_tokens=100,
                output_tokens=50,
                input_cost_per_million=1.0,
                output_cost_per_million=2.0,
            ),
        )


class FallbackGateway:
    async def generate(self, request) -> dict:
        content = {
            "title": "Identify the most likely root cause using only",
            "summary": "Generic fallback RCA draft",
            "content": "Generic fallback content that should not be used as trusted RCA.",
            "commands": [],
            "scripts": [],
            "queries": [],
            "metadata": {
                "fallback": True,
                "fallback_reason": "gemini unavailable; gpt-4o unavailable; gpt-5 unavailable",
            },
        }
        return {
            "model": "heuristic-fallback",
            "content": json.dumps(content),
            "usage": {
                "provider": "heuristic-fallback",
                "model": "heuristic-fallback",
                "task": request.task,
                "estimated": True,
                "fallback": True,
            },
        }


def test_discovery_promotes_application_errors_into_report_findings() -> None:
    rows = [
        {
            "evidence_id": "LOG-timeout",
            "source": "log",
            "service": "recommendation",
            "container": "telemetry-recommendation",
            "uri": "docker://telemetry-recommendation#L1",
            "snippet": "2026-07-26T06:18:49Z Failed to export metrics: Deadline Exceeded",
            "diagnostic_signals": ["timeout", "error"],
        },
        {
            "evidence_id": "LOG-summary",
            "source": "log",
            "signal_type": "log_diagnosis",
            "snippet": "Structured log diagnosis",
            "diagnostic_signals": ["timeout"],
        },
    ]

    findings = DiscoveryMCPConnector._detected_errors(rows)

    assert len(findings) == 1
    assert findings[0]["service"] == "recommendation"
    assert findings[0]["evidence_id"] == "LOG-timeout"
    assert findings[0]["signals"] == ["timeout", "error"]


def static_router() -> ModelRouter:
    return ModelRouter(
        providers={
            "gpt-5": StaticProvider("gpt-5"),
            "gpt-4o": StaticProvider("gpt-4o"),
            "claude": StaticProvider("claude"),
            "local-llama": StaticProvider("local-llama"),
        }
    )


def test_resolution_agent_extracts_values_from_fenced_json_with_introductory_text() -> None:
    content = """Given the evidence, here is the result:
```json
{"root_cause":"Collector endpoint is unreachable","confidence_score":0.72}
```"""

    parsed = ResolutionIntelligenceAgent._extract_model_text(
        content,
        keys=("root_cause", "summary"),
        fallback_text="fallback",
    )

    assert parsed == "Collector endpoint is unreachable"


def test_vector_db_connector_loads_rag_documents() -> None:
    connector = VectorDBConnector()

    assert connector.documents
    assert any(doc["kind"] == "runbook" for doc in connector.documents)
    assert any(doc["kind"] == "incident" for doc in connector.documents)
    assert any(doc["kind"] == "dependency" for doc in connector.documents)


@pytest.mark.asyncio
async def test_context_agent_returns_requested_shape() -> None:
    alert = Alert(
        source="prometheus",
        name="PaymentLatencyHigh",
        service="payments",
        severity=AlertSeverity.CRITICAL,
        description="payment latency after deployment",
        labels={"deployment": "payments-api"},
    )
    incident = Incident(service="payments", severity=AlertSeverity.CRITICAL, title="payments latency")

    context = await ContextIntelligenceAgent().collect(alert, incident)

    assert context.deployment == "Deployment 2.5"
    assert context.runbook
    assert set(context.dependency_services) >= {"checkout", "ledger", "fraud", "postgres-primary"}
    assert context.recent_changes
    assert context.metadata["rag_documents"] >= 1
    assert any(match["kind"] == "runbook" for match in context.metadata["rag_matches"])
    assert context.metadata["rag_index"]["vector_store"]["provider"] == "file-backed-memory"
    assert context.metadata["rag_index"]["embedding_model"]["model"] == "hashing-token-counter-v1"
    assert context.metadata["context_graph"] == {
        "enabled": True,
        "stages": ["validate_event", "collect_connector_evidence", "assemble_context"],
        "connector_count": 8,
    }


@pytest.mark.asyncio
async def test_context_agent_persists_multi_source_evidence_manifest() -> None:
    alert = Alert(
        source="prometheus",
        name="TelemetryCollectorUnavailable",
        service="otel-collector",
        severity=AlertSeverity.CRITICAL,
        description="Prometheus cannot scrape collector metrics endpoint",
        labels={"project_name": "Telemetry", "application": "Telemetry"},
    )
    incident = Incident(service="otel-collector", severity=AlertSeverity.CRITICAL, title="collector unavailable")

    context = await ContextIntelligenceAgent().collect(alert, incident)

    assert set(context.metadata["context_sources"]) >= {"logs", "tickets", "code", "rag"}
    assert all(context.metadata["context_sources"][source]["attempted"] is True for source in ("logs", "tickets", "code", "rag"))
    assert context.metadata["context_sources"]["rag"]["result_count"] == len(context.metadata["rag_matches"])
    assert set(context.metadata["context_evidence"]) >= {"logs", "tickets", "code", "rag"}
    assert context.metadata["context_evidence"]["rag"]


@pytest.mark.asyncio
async def test_resolution_agent_generates_recommendation() -> None:
    alert = Alert(
        source="prometheus",
        name="PaymentLatencyHigh",
        service="payments",
        severity=AlertSeverity.CRITICAL,
        description="payment latency after deployment",
        labels={"deployment": "payments-api"},
    )
    incident = Incident(service="payments", severity=AlertSeverity.CRITICAL, title="payments latency")
    context = await ContextIntelligenceAgent().collect(alert, incident)

    recommendation = await ResolutionIntelligenceAgent(model_router=static_router()).resolve(context)

    assert recommendation.root_cause == "Deployment 2.5"
    assert recommendation.confidence >= 0.9
    assert recommendation.impact == "Payments latency"
    assert recommendation.recommended_action == "Rollback deployment"


@pytest.mark.asyncio
async def test_resolution_agent_clamps_all_model_fallback_confidence() -> None:
    alert = Alert(
        source="prometheus",
        name="KaiOpsServiceDown",
        service="kaiops-platform",
        severity=AlertSeverity.CRITICAL,
        description="KaiOps platform service is not reachable by Prometheus for more than 1 minute.",
    )
    incident = Incident(service="kaiops-platform", severity=AlertSeverity.CRITICAL, title="kaiops service down")
    context = await ContextIntelligenceAgent().collect(alert, incident)

    recommendation = await ResolutionIntelligenceAgent(model_gateway=FallbackGateway()).resolve(context)

    assert recommendation.confidence <= 0.49
    assert not recommendation.root_cause.startswith("{")
    assert recommendation.metadata["fallback_used"] is True
    assert recommendation.metadata["quality_gate"]["requires_human_review"] is True
    assert recommendation.metadata["quality_gate"]["trusted_for_auto_execution"] is False


@pytest.mark.asyncio
async def test_resolution_agent_uses_external_knowledge_when_local_rca_is_ungrounded() -> None:
    alert = Alert(
        source="prometheus",
        name="QueueBacklogHigh",
        service="checkout-worker",
        severity=AlertSeverity.HIGH,
        description="queue backlog rose rapidly after release",
    )
    context = Context(
        incident_id="11111111-1111-4111-8111-111111111111",
        alert=alert,
        metadata={
            "discovery_report": {
                "report": {
                    "external_knowledge_used": True,
                    "external_knowledge_eligible": True,
                    "hypotheses": [
                        {
                            "cause": "Worker throughput dropped after rollout due to unbounded downstream retry latency.",
                            "confidence": 0.58,
                        }
                    ],
                    "citations": ["external-knowledge://sre/retry-storm-pattern"],
                },
                "evidence": [],
            }
        },
    )

    recommendation = await ResolutionIntelligenceAgent(model_gateway=FallbackGateway()).resolve(context)

    assert recommendation.root_cause.startswith("Worker throughput dropped after rollout")
    assert "external-knowledge://sre/retry-storm-pattern" in recommendation.metadata["rca_analysis"]["evidence_used"]
    assert recommendation.metadata["rca_analysis"]["external_knowledge_used"] is True


@pytest.mark.asyncio
async def test_resolution_agent_grounds_mysql_exporter_privilege_rca_in_raw_alert() -> None:
    alert = Alert(
        source="logs",
        name="[WARNING] mysql-exporter: Error from scraper",
        service="mysql-exporter",
        severity=AlertSeverity.HIGH,
        description=(
            'level=ERROR msg="Error from scraper" scraper=slave_status target=mysql:3306 '
            'err="Error 1227 (42000): Access denied; you need (at least one of) the SUPER, '
            'REPLICATION CLIENT privilege(s) for this operation"'
        ),
        labels={
            "source_event_id": "mysql-exporter-log-1",
            "log_source_path": "opensearch://otel-*/mysql-exporter-log-1",
        },
    )
    incident = Incident(service="mysql-exporter", severity=AlertSeverity.HIGH, title="exporter scrape failure")
    context = Context(
        incident_id=incident.id,
        alert=alert,
        metadata={
            "discovery_report": {
                "report": {
                    "external_knowledge_eligible": True,
                    "external_knowledge_used": True,
                    "external_tools_used": ["external.search"],
                },
                "evidence": [],
            }
        },
    )

    recommendation = await ResolutionIntelligenceAgent(model_gateway=FallbackGateway()).resolve(context)

    assert "lacks the REPLICATION CLIENT privilege" in recommendation.root_cause
    assert "loss of replication-health visibility" in recommendation.impact
    assert recommendation.recommended_action.startswith("Verify the exporter account")
    assert "alert:mysql-exporter-log-1" in recommendation.metadata["rca_analysis"]["evidence_used"]
    assert "opensearch://otel-*/mysql-exporter-log-1" in recommendation.metadata["citations"]
    assert recommendation.metadata["external_knowledge_used"] is True
    assert recommendation.metadata["external_tools_used"] == ["external.search"]


@pytest.mark.asyncio
async def test_resolution_agent_runtime_persists_reflection_memory() -> None:
    alert = Alert(
        source="prometheus",
        name="PaymentLatencyHigh",
        service="payments",
        severity=AlertSeverity.CRITICAL,
        description="payment latency after deployment",
        labels={"deployment": "payments-api"},
    )
    incident = Incident(service="payments", severity=AlertSeverity.CRITICAL, title="payments latency")
    context = await ContextIntelligenceAgent().collect(alert, incident)
    memory = InMemoryStore()

    recommendation = await ResolutionIntelligenceAgent(model_router=static_router(), memory_store=memory).resolve_with_runtime(context)

    assert recommendation.metadata.get("runtime", {}).get("status") == "succeeded"
    assert recommendation.metadata.get("runtime", {}).get("reflection", {}).get("agent") == "resolution-agent"
    entries = await memory.recent("incident-memory", limit=5)
    assert entries
    assert entries[-1]["incident_id"] == str(context.incident_id)
