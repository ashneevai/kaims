from context_agent import ContextIntelligenceAgent


def test_production_context_defaults_exclude_static_demo_connectors() -> None:
    agent = ContextIntelligenceAgent()
    connector_names = {connector.name for connector in agent.connectors}

    assert "servicenow" not in connector_names
    assert "prometheus" not in connector_names
    assert "kubernetes" not in connector_names
    assert "jenkins" not in connector_names
    assert "github" not in connector_names
    assert "cmdb" not in connector_names

    assert "discovery-mcp" in connector_names
    assert "local-evidence" in connector_names
    assert "vectordb" in connector_names
