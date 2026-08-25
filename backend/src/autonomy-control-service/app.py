from __future__ import annotations

from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from common.autonomy_runtime import AutonomyRuntimeStore
from common.config import get_settings
from common.service import create_app

settings = get_settings()
settings.service_name = "autonomy-control-service"
store = AutonomyRuntimeStore(settings.redis_url, environment=settings.environment)


class EvaluationRequest(BaseModel):
    tenant_id: str = "default"
    metrics: dict[str, float | int | None] = Field(default_factory=dict)
    critical_dependency_unavailable: bool = False
    audit_chain_broken: bool = False


class KillSwitchRequest(BaseModel):
    tenant_id: str = "default"
    enabled: bool
    actor_id: str
    reason: str


async def shutdown(_: FastAPI) -> None:
    await store.close()


app = create_app(title="KaiMS Autonomy Control Plane", settings=settings, shutdown=shutdown)


@app.get("/autonomy/status")
async def autonomy_status(tenant_id: str = "default") -> dict[str, Any]:
    return await store.get(tenant_id)


@app.post("/autonomy/evaluate")
async def evaluate(request: EvaluationRequest) -> dict[str, Any]:
    current = await store.get(request.tenant_id)
    return await store.evaluate_and_set(
        tenant_id=request.tenant_id,
        metrics=request.metrics,
        manual_kill_switch=bool(current.get("manual_kill_switch", False)),
        critical_dependency_unavailable=request.critical_dependency_unavailable,
        audit_chain_broken=request.audit_chain_broken,
    )


@app.post("/autonomy/kill-switch")
async def kill_switch(request: KillSwitchRequest) -> dict[str, Any]:
    try:
        return await store.set_kill_switch(
            tenant_id=request.tenant_id,
            enabled=request.enabled,
            actor_id=request.actor_id,
            reason=request.reason,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
