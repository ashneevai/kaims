from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any


_SECRET_REF = re.compile(r"^(vault|aws-secretsmanager|azure-keyvault|gcp-secretmanager)://[^\s]+$", re.IGNORECASE)
_FORBIDDEN_SECRET_KEYS = {"password", "passwd", "token", "api_key", "apikey", "secret", "client_secret", "private_key"}


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str, ensure_ascii=False)


def _contains_inline_secret(value: Any, path: str = "") -> list[str]:
    findings: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            key_text = str(key).strip().lower()
            child = f"{path}.{key}" if path else str(key)
            if key_text in _FORBIDDEN_SECRET_KEYS and str(item or "").strip():
                findings.append(child)
            findings.extend(_contains_inline_secret(item, child))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            findings.extend(_contains_inline_secret(item, f"{path}[{index}]"))
    return findings


@dataclass(frozen=True)
class TenantScopeDecision:
    allowed: bool
    reason: str
    tenant_id: str | None


@dataclass(frozen=True)
class SecretGovernanceDecision:
    allowed: bool
    reason: str
    secret_ref: str | None
    inline_secret_paths: tuple[str, ...] = ()


def enforce_tenant_scope(*, expected_tenant_id: Any, payload_tenant_id: Any, production: bool) -> TenantScopeDecision:
    expected = str(expected_tenant_id or "").strip()
    actual = str(payload_tenant_id or "").strip()
    if production and (not expected or not actual):
        return TenantScopeDecision(False, "TENANT_SCOPE_MISSING", actual or expected or None)
    if expected and actual and expected != actual:
        return TenantScopeDecision(False, "TENANT_SCOPE_MISMATCH", actual)
    return TenantScopeDecision(True, "tenant scope verified", actual or expected or None)


def validate_secret_governance(
    *,
    secret_ref: Any,
    payload: Any = None,
    production: bool,
) -> SecretGovernanceDecision:
    ref = str(secret_ref or "").strip()
    inline = tuple(sorted(set(_contains_inline_secret(payload))))
    if inline:
        return SecretGovernanceDecision(False, "INLINE_SECRET_MATERIAL_FORBIDDEN", ref or None, inline)
    if production and not ref:
        return SecretGovernanceDecision(False, "SECRET_REF_REQUIRED", None)
    if ref and not _SECRET_REF.fullmatch(ref):
        return SecretGovernanceDecision(False, "UNSUPPORTED_SECRET_REFERENCE", ref)
    return SecretGovernanceDecision(True, "external secret reference verified", ref or None)


def build_tamper_evident_audit_record(
    *,
    event: dict[str, Any],
    previous_hash: str | None,
    tenant_id: str,
    actor_id: str,
    actor_type: str,
    occurred_at: datetime | None = None,
) -> dict[str, Any]:
    timestamp = (occurred_at or datetime.now(UTC)).isoformat()
    body = {
        "tenant_id": str(tenant_id).strip(),
        "actor_id": str(actor_id).strip(),
        "actor_type": str(actor_type).strip(),
        "occurred_at": timestamp,
        "event": event,
        "previous_hash": str(previous_hash or ""),
        "audit_contract_version": "1.0",
    }
    body["record_hash"] = hashlib.sha256(_canonical(body).encode("utf-8")).hexdigest()
    return body


def verify_tamper_evident_audit_record(record: dict[str, Any]) -> bool:
    if not isinstance(record, dict):
        return False
    expected = str(record.get("record_hash") or "")
    if not expected:
        return False
    unsigned = {key: value for key, value in record.items() if key != "record_hash"}
    actual = hashlib.sha256(_canonical(unsigned).encode("utf-8")).hexdigest()
    return actual == expected
