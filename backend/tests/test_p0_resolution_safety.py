from types import SimpleNamespace
from unittest.mock import patch

import pytest

from common.capability_registry import CapabilityRegistry, LEGACY_ACTION_CAPABILITIES
from common.event_publishers import _resolve_required_scope


def test_all_legacy_execution_actions_map_to_registered_capabilities() -> None:
    registry = CapabilityRegistry()

    for capability_id in LEGACY_ACTION_CAPABILITIES.values():
        assert registry.is_registered(capability_id)


def test_unknown_capability_is_rejected() -> None:
    registry = CapabilityRegistry()

    with pytest.raises(ValueError, match="UNSUPPORTED_CAPABILITY"):
        registry.require("unknown.operation")


def test_production_scope_refuses_missing_tenant_and_environment() -> None:
    alert = SimpleNamespace(metadata={}, labels={}, environment="")
    incident = SimpleNamespace(metadata={}, environment="")

    with patch("common.event_publishers.get_settings", return_value=SimpleNamespace(environment="production")):
        with pytest.raises(ValueError, match="tenant scope is required"):
            _resolve_required_scope(alert, incident)


def test_local_scope_uses_explicit_local_identity_for_development_only() -> None:
    alert = SimpleNamespace(metadata={}, labels={}, environment="")
    incident = SimpleNamespace(metadata={}, environment="")

    with patch("common.event_publishers.get_settings", return_value=SimpleNamespace(environment="local")):
        tenant_id, environment = _resolve_required_scope(alert, incident)

    assert tenant_id == "local"
    assert environment == "local"
