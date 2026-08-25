from __future__ import annotations

from common.audit_ledger import PrivilegedActor, verify_chain
from common.enterprise_governance import build_tamper_evident_audit_record


def _record(*, tenant: str, previous_hash: str | None, sequence: int, action: str) -> dict:
    row = build_tamper_evident_audit_record(
        event={"action": action},
        previous_hash=previous_hash,
        tenant_id=tenant,
        actor_id="automation-agent",
        actor_type="service",
    )
    row["sequence"] = sequence
    row["ledger_row_id"] = f"row-{sequence}"
    return row


def test_chain_verification_accepts_valid_per_tenant_sequence() -> None:
    first = _record(tenant="tenant-a", previous_hash=None, sequence=1, action="restart")
    second = _record(
        tenant="tenant-a",
        previous_hash=first["record_hash"],
        sequence=2,
        action="validate",
    )
    result = verify_chain([first, second], tenant_id="tenant-a")
    assert result["valid"] is True
    assert result["record_count"] == 2
    assert result["chain_head"] == second["record_hash"]


def test_chain_verification_detects_hash_break() -> None:
    first = _record(tenant="tenant-a", previous_hash=None, sequence=1, action="restart")
    second = _record(tenant="tenant-a", previous_hash="wrong", sequence=2, action="validate")
    result = verify_chain([first, second], tenant_id="tenant-a")
    assert result["valid"] is False
    assert any("HASH_CHAIN_BREAK" in failure for failure in result["failures"])


def test_chain_verification_detects_tampering() -> None:
    first = _record(tenant="tenant-a", previous_hash=None, sequence=1, action="restart")
    first["event"]["action"] = "delete"
    result = verify_chain([first], tenant_id="tenant-a")
    assert result["valid"] is False
    assert any("RECORD_TAMPERED" in failure for failure in result["failures"])


def test_chain_verification_detects_sequence_break_and_cross_tenant_record() -> None:
    first = _record(tenant="tenant-b", previous_hash=None, sequence=3, action="restart")
    result = verify_chain([first], tenant_id="tenant-a")
    assert result["valid"] is False
    assert any("TENANT_MISMATCH" in failure for failure in result["failures"])
    assert any("SEQUENCE_BREAK" in failure for failure in result["failures"])


def test_privileged_actor_requires_authentication_in_production() -> None:
    actor = PrivilegedActor(actor_id="approver@example.com", actor_type="human")
    try:
        actor.validate(production=True)
    except ValueError as exc:
        assert str(exc) == "PRIVILEGED_ACTOR_AUTHENTICATION_MISSING"
    else:
        raise AssertionError("production privileged identity must require authentication method")
