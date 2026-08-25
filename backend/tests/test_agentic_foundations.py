from ai_workbench_common.agentic import AgentContext
from common.config import Settings
from common.event_publishers import KafkaPublisher, NoOpPublisher, build_event_publisher
from ai_workbench_common.model_gateway import GenerationRequest, MockProvider
from common.models import Alert, AlertSeverity, Incident, IncidentStatus
from common.orchestration import AgentOrchestrator, PolicyEngine, WorkflowEngine, WorkflowState, WorkflowStateMachine
from alert_intelligence import AlertIntelligenceAgent
from context_agent import ContextIntelligenceAgent
from orchestrator.workflow import OrchestratorAgent
from unittest.mock import patch


def make_alert() -> Alert:
    return Alert(
        source="prometheus",
        name="DatabaseReplicaLag",
        service="orders-db",
        severity=AlertSeverity.CRITICAL,
        description="orders database replica lag above threshold",
        labels={"team": "database-sre", "deployment": "orders-postgres"},
    )


def make_incident() -> Incident:
    return Incident(
        service="orders-db",
        severity=AlertSeverity.CRITICAL,
        status=IncidentStatus.INVESTIGATING,
        title="orders-db: DatabaseReplicaLag",
    )


def test_alert_agent_implements_agent_context_execution() -> None:
    agent = AlertIntelligenceAgent()
    context = AgentContext(alert=make_alert())

    result = __import__("asyncio").run(agent.execute(context))

    assert result["alert"].correlation_id is not None
    assert result["incident"].service == "orders-db"
    assert context.incident is not None
    assert "alert-intelligence-agent" in context.previous_agent_results


def test_policy_engine_requires_approval_for_high_and_critical() -> None:
    engine = PolicyEngine()

    assert engine.requires_approval(severity=AlertSeverity.CRITICAL) is True
    assert engine.requires_approval(severity=AlertSeverity.HIGH) is True
    assert engine.requires_approval(severity=AlertSeverity.WARNING, confidence=0.95) is False


def test_policy_engine_fails_closed_until_structured_policy_migration() -> None:
    engine = PolicyEngine()

    low_confidence = engine.evaluate(severity=AlertSeverity.WARNING, confidence=0.70)
    guided_confidence = engine.evaluate(severity=AlertSeverity.WARNING, confidence=0.80)
    missing_confidence = engine.evaluate(severity=AlertSeverity.WARNING, confidence=None)
    high_confidence = engine.evaluate(severity=AlertSeverity.WARNING, confidence=0.96)

    assert low_confidence.requires_approval is True
    assert low_confidence.execution_mode == "human-approval"
    assert low_confidence.risk_tier == "medium"

    assert guided_confidence.requires_approval is True
    assert guided_confidence.execution_mode == "human-approval"

    assert missing_confidence.requires_approval is True
    assert missing_confidence.execution_mode == "human-approval"

    assert high_confidence.requires_approval is False
    assert high_confidence.execution_mode == "auto-execute"


def test_workflow_engine_selects_enterprise_workflow_steps() -> None:
    selection = WorkflowEngine().select(severity=AlertSeverity.CRITICAL)

    assert selection.definition.name == "critical-auto-remediation"
    assert "knowledge-agent" in selection.definition.steps
    assert "notification-agent" in selection.definition.steps
    assert selection.requires_approval is True
    assert selection.message_bus_provider == "rabbitmq"
    assert selection.stream_count == 0
    assert selection.stream_threshold == 500


def test_workflow_engine_routes_to_kafka_when_streams_exceed_threshold() -> None:
    selection = WorkflowEngine().select(severity=AlertSeverity.HIGH, stream_count=501)

    assert selection.message_bus_provider == "kafka"
    assert selection.stream_count == 501
    assert selection.stream_threshold == 500


def test_orchestrator_agent_auto_routes_message_bus_from_alert_stream_count() -> None:
    alert = make_alert()
    alert.labels["stream_count"] = "650"

    decision = OrchestratorAgent().decide_workflow(alert, make_incident())

    assert decision.message_bus_provider == "kafka"
    assert decision.stream_count == 650
    assert decision.stream_threshold == 500
    assert decision.policy_version == "policy-v1"
    assert decision.policy_reason


def test_state_machine_allows_expected_progression() -> None:
    machine = WorkflowStateMachine()

    assert machine.can_transition(WorkflowState.NEW, WorkflowState.INVESTIGATING) is True
    assert machine.can_transition(WorkflowState.EXECUTING, WorkflowState.VALIDATING) is True
    assert machine.can_transition(WorkflowState.CLOSED, WorkflowState.NEW) is False


def test_event_publisher_factory_supports_abstraction() -> None:
    noop_settings = Settings(EVENT_BUS_PROVIDER="noop", KAFKA_ENABLED="false")
    kafka_settings = Settings(EVENT_BUS_PROVIDER="kafka", KAFKA_ENABLED="true")

    assert isinstance(build_event_publisher(noop_settings), NoOpPublisher)
    assert isinstance(build_event_publisher(kafka_settings), KafkaPublisher)


def test_mock_model_gateway_generates_response() -> None:
    gateway = MockProvider()

    response = __import__("asyncio").run(
        gateway.generate(
            GenerationRequest(
                severity=AlertSeverity.WARNING,
                task="general",
                prompt="Summarize incident",
                payload={"service": "payments"},
            )
        )
    )

    assert response["model"] == "mock"
    assert response["usage"]["provider"] == "mock"


def test_orchestrator_agent_preserves_legacy_decision_shape() -> None:
    decision = OrchestratorAgent().decide_workflow(make_alert(), make_incident())

    assert decision.workflow == "critical-auto-remediation"
    assert decision.next_action == "collect-context"
    assert "context-agent" in decision.downstream_agents
    assert decision.requires_approval is True
    assert decision.message_bus_provider == "rabbitmq"
    assert decision.policy_version == "policy-v1"
    assert isinstance(decision.policy_reason, str)
    assert decision.risk_tier in {"high", "medium", "low"}
    assert decision.execution_mode in {"human-approval", "guided-auto", "auto-execute"}
    assert isinstance(decision.execution_plan, dict)
    assert isinstance(decision.execution_plan.get("connection"), dict)
    assert isinstance(decision.execution_plan.get("playbook"), dict)
    playbook_steps = decision.execution_plan.get("playbook", {}).get("steps", [])
    assert isinstance(playbook_steps, list)


def test_workflow_engine_llm_planner_can_override_workflow() -> None:
    engine = WorkflowEngine(settings=Settings(ORCHESTRATION_LLM_PLANNER_ENABLED="true"))

    async def fake_planner(self, **kwargs):
        return "triage-only", "mock-planner", "non-critical blast radius"

    with patch.object(WorkflowEngine, "_plan_workflow_name", fake_planner):
        selection = __import__("asyncio").run(
            engine.select_with_planner(severity=AlertSeverity.CRITICAL, stream_count=50)
        )

    assert selection.definition.name == "triage-only"
    assert selection.planner_used is True
    assert selection.planner_model == "mock-planner"
    assert selection.planner_reason == "non-critical blast radius"


def test_workflow_engine_llm_planner_falls_back_safely() -> None:
    engine = WorkflowEngine(settings=Settings(ORCHESTRATION_LLM_PLANNER_ENABLED="true"))

    async def fake_planner(self, **kwargs):
        return None, "mock-planner", "planner returned unsupported workflow"

    with patch.object(WorkflowEngine, "_plan_workflow_name", fake_planner):
        selection = __import__("asyncio").run(
            engine.select_with_planner(severity=AlertSeverity.CRITICAL, stream_count=50)
        )

    assert selection.definition.name == "critical-auto-remediation"
    assert selection.planner_used is False
    assert selection.planner_model == "mock-planner"
    assert "unsupported" in selection.planner_reason


def test_orchestrator_runtime_path_produces_workflow_decision() -> None:
    decision = __import__("asyncio").run(OrchestratorAgent().decide_workflow_async_with_runtime(make_alert(), make_incident()))

    assert decision.workflow
    assert decision.next_action
    assert decision.message_bus_provider in {"kafka", "rabbitmq", "azure-service-bus", "servicebus", "azure"}


def test_context_agent_runtime_path_collects_context() -> None:
    alert = make_alert()
    incident = make_incident()

    context = __import__("asyncio").run(ContextIntelligenceAgent().collect_with_runtime(alert, incident))

    assert context.alert.service == "orders-db"
    assert context.incident_id
