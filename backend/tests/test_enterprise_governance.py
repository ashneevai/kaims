from __future__ import annotations

from common.enterprise_governance import (
    build_tamper_evident_audit_record,
    enforce_tenant_scope,
    validate_secret_governance,
    verify_tamper_evident_audit_record,
)


def test_production_requires_tenant_scope() -> None:
    decision = enforce_tenant_scope(expected_tenant_id="", payload_tenant_id="", production=True)
    assert decision.allowed is False
    assert decision.reason == "TENANT_SCOPE_MISSING"


def test_cross_tenant_execution_is_blocked() -> None:
    decision = enforce_tenant_scope(expected_tenant_id="tenant-a", payload_tenant_id="tenant-b", production=True)
    assert decision.allowed is False
    assert decision.reason == "TENANT_SCOPE_MISMATCH"


def test_matching_tenant_is_allowed() -> None:
    assert enforce_tenant_scope(expected_tenant_id="tenant-a", payload_tenant_id="tenant-a", production=True).allowed


def test_inline_secret_material_is_forbidden() -> None:
    decision = validate_secret_governance(
        secret_ref="vault://kaims/prod/orders",
        payload={"connection": {"password": "do-not-store-this"}},
        production=True,
    )
    assert decision.allowed is False
    assert decision.reason == "INLINE_SECRET_MATERIAL_FORBIDDEN"
    assert "connection.password" in decision.inline_secret_paths


def test_production_requires_supported_external_secret_reference() -> None:
    assert validate_secret_governance(secret_ref="", payload={}, production=True).allowed is False
    assert validate_secret_governance(secret_ref="env://TOKEN", payload={}, production=True).allowed is False
    assert validate_secret_governance(secret_ref="azure-keyvault://kaims/orders", payload={}, production=True).allowed


def test_audit_record_detects_tampering_and_chains_previous_hash() -> None:
    first = build_tamper_evident_audit_record(
        event={"action": "restart", "target": "orders"},
        previous_hash=None,
        tenant_id="tenant-a",
        actor_id="automation-agent",
        actor_type="service",
    )
    assert verify_tamper_evident_audit_record(first)
    second = build_tamper_evident_audit_record(
        event={"action": "validate", "target": "orders"},
        previous_hash=first["record_hash"],
        tenant_id="tenant-a",
        actor_id="closure-service",
        actor_type="service",
    )
    assert second["previous_hash"] == first["record_hash"]
    assert verify_tamper_evident_audit_record(second)
    second["event"]["target"] = "payments"
    assert verify_tamper_evident_audit_record(second) is False
