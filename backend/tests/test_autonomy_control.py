from __future__ import annotations

from common.autonomy_control import AutonomyMode, PLATFORM_SLOS, action_allowed_for_mode, evaluate_autonomy_mode


def _healthy_metrics() -> dict[str, float]:
    result = {}
    for slo in PLATFORM_SLOS:
        result[slo.name] = slo.target if slo.direction == "gte" else max(0.0, slo.target * 0.5)
    return result


def test_healthy_platform_allows_autonomous_mode() -> None:
    result = evaluate_autonomy_mode(metrics=_healthy_metrics())
    assert result["mode"] == AutonomyMode.AUTONOMOUS.value
    assert result["score"] == 100


def test_noncritical_slo_breach_degrades_to_guided() -> None:
    metrics = _healthy_metrics()
    metrics["alert_to_triage_p95_seconds"] = 90
    result = evaluate_autonomy_mode(metrics=metrics)
    assert result["mode"] == AutonomyMode.GUIDED.value


def test_critical_slo_breach_degrades_to_hitl_only() -> None:
    metrics = _healthy_metrics()
    metrics["duplicate_production_effect_rate"] = 0.01
    result = evaluate_autonomy_mode(metrics=metrics)
    assert result["mode"] == AutonomyMode.HITL_ONLY.value
    assert result["critical_failures"]


def test_missing_critical_signal_fails_closed() -> None:
    metrics = _healthy_metrics()
    del metrics["audit_chain_valid_rate"]
    result = evaluate_autonomy_mode(metrics=metrics)
    assert result["mode"] == AutonomyMode.HITL_ONLY.value


def test_manual_kill_switch_overrides_health() -> None:
    result = evaluate_autonomy_mode(metrics=_healthy_metrics(), manual_kill_switch=True)
    assert result["mode"] == AutonomyMode.KILL_SWITCH.value
    assert result["score"] == 0


def test_audit_chain_break_forces_hitl() -> None:
    result = evaluate_autonomy_mode(metrics=_healthy_metrics(), audit_chain_broken=True)
    assert result["mode"] == AutonomyMode.HITL_ONLY.value


def test_guided_and_hitl_require_approval_for_mutations() -> None:
    assert action_allowed_for_mode(mode="GUIDED", requires_approval=False) is False
    assert action_allowed_for_mode(mode="GUIDED", requires_approval=True) is True
    assert action_allowed_for_mode(mode="HITL_ONLY", requires_approval=False) is False
    assert action_allowed_for_mode(mode="HITL_ONLY", requires_approval=True) is True
    assert action_allowed_for_mode(mode="HITL_ONLY", requires_approval=False, is_read_only=True) is True


def test_kill_switch_blocks_mutations_and_reads() -> None:
    assert action_allowed_for_mode(mode="KILL_SWITCH", requires_approval=True) is False
    assert action_allowed_for_mode(mode="KILL_SWITCH", requires_approval=False, is_read_only=True) is False
