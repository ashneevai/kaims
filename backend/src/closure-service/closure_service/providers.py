from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

import httpx

from common.models import RemediationAction
from common.resolution_models import EvidenceMode, ValidationPlan


def _compare(value: float, operator: str, expected: Any) -> bool:
    op = operator.strip().lower()
    if op in {"truthy", "true"}:
        return bool(value)
    if op in {"falsy", "false"}:
        return not bool(value)
    expected_number = float(expected)
    if op in {"<", "lt"}:
        return value < expected_number
    if op in {"<=", "le"}:
        return value <= expected_number
    if op in {">", "gt"}:
        return value > expected_number
    if op in {">=", "ge"}:
        return value >= expected_number
    if op in {"==", "=", "eq"}:
        return value == expected_number
    if op in {"!=", "ne"}:
        return value != expected_number
    raise ValueError(f"Unsupported validation operator: {operator}")


def _content_hash(payload: Any) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


@dataclass(slots=True)
class PrometheusValidationEvidenceProvider:
    """Collect independent live recovery evidence from Prometheus instant queries.

    A ValidationCheck using provider='prometheus' treats `signal` as PromQL and
    evaluates the returned scalar/vector value against the check operator and
    expected value. Unsupported providers are intentionally left absent so the
    engine cannot claim recovery when a mandatory source was not queried.
    """

    base_url: str
    timeout_seconds: float = 10.0

    async def collect(
        self,
        action: RemediationAction,
        plan: ValidationPlan,
        window_index: int,
    ) -> dict[str, Any]:
        observations: list[dict[str, Any]] = []
        evidence: list[dict[str, Any]] = []
        provider_failures: list[str] = []
        endpoint = f"{self.base_url.rstrip('/')}/api/v1/query"

        async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
            for check in plan.checks:
                if check.provider.strip().lower() != "prometheus":
                    continue
                try:
                    response = await client.get(endpoint, params={"query": check.signal})
                    response.raise_for_status()
                    payload = response.json()
                    value = self._extract_numeric_value(payload)
                    passed = _compare(value, check.operator, check.expected_value)
                    digest = _content_hash(payload)
                    evidence_id = f"prometheus:{digest[:24]}"
                    evidence_record = {
                        "evidence_id": evidence_id,
                        "provider": "prometheus",
                        "source_uri": str(response.url),
                        "query": check.signal,
                        "content_hash": digest,
                        "window_index": window_index,
                    }
                    evidence.append(evidence_record)
                    observations.append(
                        {
                            "check_id": check.check_id,
                            "provider": "prometheus",
                            "source_uri": str(response.url),
                            "resource_id": check.resource_id,
                            "mode": EvidenceMode.LIVE.value,
                            "value": value,
                            "passed": passed,
                            "regression": False,
                            "evidence_id": evidence_id,
                            "content_hash": digest,
                            "metadata": {"query": check.signal, "operator": check.operator},
                        }
                    )
                except (httpx.HTTPError, ValueError, TypeError, KeyError) as exc:
                    provider_failures.append(f"{check.check_id}: {exc}")

        if not observations:
            return {
                "status": "VALIDATION_DATA_UNAVAILABLE",
                "mode": EvidenceMode.UNAVAILABLE.value,
                "provider": "prometheus",
                "evidence": [],
                "observations": [],
                "reason": "; ".join(provider_failures) or "No Prometheus validation checks were available",
            }
        return {
            "status": "OBSERVED",
            "mode": EvidenceMode.LIVE.value,
            "provider": "prometheus",
            "evidence": evidence,
            "observations": observations,
            "reason": "; ".join(provider_failures),
        }

    @staticmethod
    def _extract_numeric_value(payload: dict[str, Any]) -> float:
        if payload.get("status") != "success":
            raise ValueError("Prometheus query did not return success")
        data = payload.get("data") if isinstance(payload.get("data"), dict) else {}
        result_type = str(data.get("resultType") or "")
        result = data.get("result")
        if result_type == "scalar" and isinstance(result, list) and len(result) >= 2:
            return float(result[1])
        if result_type == "vector" and isinstance(result, list):
            if not result:
                return 0.0
            values = []
            for item in result:
                value_pair = item.get("value") if isinstance(item, dict) else None
                if isinstance(value_pair, list) and len(value_pair) >= 2:
                    values.append(float(value_pair[1]))
            if values:
                return max(values)
        raise ValueError(f"Unsupported or empty Prometheus result type: {result_type}")
