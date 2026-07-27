from __future__ import annotations

import asyncio
import json
import logging
import re
from enum import StrEnum
from typing import Any, TypedDict

import httpx

from ai_workbench_common.agent_runtime import AgentRuntime, ContextFailure, ValidationError
from ai_workbench_common.agentic import AgentContext, BaseAgent
from ai_workbench_common.memory_store import InMemoryStore, MemoryStore
from ai_workbench_common.model_evaluation import AzureAIEvaluationClient, EvaluationResult, build_quality_evaluation
from ai_workbench_common.model_gateway import GenerationRequest, HttpModelGateway, ModelGateway, RouterModelGateway
from ai_workbench_common.models import Context, Evidence
from common.config import get_settings
from common.models import AlertSeverity, Recommendation
from ai_workbench_common.prompts import (
    PROMPT_ASSESS_IMPACT,
    PROMPT_IDENTIFY_ROOT_CAUSE,
    PROMPT_RECOMMEND_REMEDIATION,
)
from langgraph.graph import END, StateGraph

logger = logging.getLogger("kaiops.resolution_agent")


class ModelTask(StrEnum):
    """Mirrors model_router.ModelTask's wire values without importing that service's package."""

    RCA = "rca"
    IMPACT = "impact"
    FIX = "fix"
    SUMMARIZATION = "summarization"
    GENERAL = "general"


class ResolutionState(TypedDict, total=False):
    context: Context
    gathered_context: dict[str, Any]
    root_cause: str
    impact: str
    recommended_action: str
    remediation_target: str
    confidence: float
    rationale: str
    commands: list[str]
    model_usage: list[dict[str, Any]]
    model_calls: list[dict[str, Any]]
    rca_analysis: dict[str, Any]
    impact_analysis: dict[str, Any]
    remediation_analysis: dict[str, Any]


class ResolutionIntelligenceAgent(BaseAgent):
    name = "resolution-agent"

    def __init__(
        self,
        model_router: Any | None = None,
        model_gateway: ModelGateway | None = None,
        runtime: AgentRuntime | None = None,
        memory_store: MemoryStore | None = None,
        evaluation_client: AzureAIEvaluationClient | None = None,
    ) -> None:
        settings = get_settings()
        self.model_router = model_router
        if model_gateway is not None:
            self.model_gateway = model_gateway
        elif model_router is not None:
            # Allows tests/tools to inject an in-process ModelRouter-like object directly.
            self.model_gateway = RouterModelGateway(model_router)
        else:
            self.model_gateway = HttpModelGateway(
                settings.model_router_url,
                timeout_seconds=settings.llm_request_timeout_seconds,
            )
        self.runtime = runtime or AgentRuntime(max_attempts=2)
        self.memory_store = memory_store or InMemoryStore()
        self.evaluation_client = evaluation_client or AzureAIEvaluationClient(settings)
        self.evaluation_service_url = settings.evaluation_service_url
        # Bound each model call so a single blocked provider cannot stall event consumption.
        # Mirrors settings.llm_request_timeout_seconds so operators can raise/lower both the
        # gateway's own timeout and this step-level guard from one place.
        self.model_step_timeout_seconds = settings.llm_request_timeout_seconds
        # Keeps strong references to fire-and-forget evaluation-publish tasks so they
        # aren't garbage-collected mid-flight; discarded automatically once done.
        self._background_tasks: set[asyncio.Task[None]] = set()
        self.graph = self._build_graph()

    @staticmethod
    def _norm(value: Any) -> str:
        return str(value or "").strip().lower()

    @staticmethod
    def _extract_runbook_commands(runbook: str, *, max_items: int = 4) -> list[str]:
        if not str(runbook or "").strip():
            return []
        commands: list[str] = []
        seen: set[str] = set()
        # context-agent's write_rag_document emits one fenced ```bash block per remediation
        # step under a single "## Remediation Script" heading (see context-agent/app.py,
        # _execution_script_lines/write_rag_document). Scope to that section, then pull every
        # fence inside it -- a single non-greedy regex spanning to the first ``` would only
        # ever see the first step and silently drop the rest of a multi-command runbook.
        section_match = re.search(
            r"##\s*Remediation Script\s*([\s\S]*?)(?=\n##\s|\Z)",
            str(runbook),
            flags=re.IGNORECASE,
        )
        if section_match:
            fences = re.findall(
                r"```(?:bash|sh|shell)?\s*([\s\S]*?)```",
                section_match.group(1),
                flags=re.IGNORECASE,
            )
            for fence in fences:
                script = "; ".join(
                    line.strip()
                    for line in fence.splitlines()
                    if line.strip() and not line.strip().startswith("#")
                ).strip()
                if script and script.lower() not in seen:
                    commands.append(script)
                    seen.add(script.lower())
                if len(commands) >= max_items:
                    return commands
            if commands:
                return commands
        for line in str(runbook).splitlines():
            token = line.strip().lstrip("- ").strip().strip("`")
            if not token:
                continue
            token = re.sub(r"^\s*(cmd|command|script|query)\s*:\s*", "", token, flags=re.IGNORECASE).strip()
            if token.startswith("#"):
                continue
            # Capture command-like steps while avoiding prose-heavy runbook lines.
            if (
                token.startswith(("bash ", "sh ", "pwsh ", "powershell ", "python ", "curl "))
                or token.startswith(("kubectl ", "helm ", "terraform ", "ansible-playbook ", "redis-cli ", "mysql "))
                or token.startswith("scripts/")
                or token.startswith("./")
                or token.startswith("Invoke-")
                or token.startswith("Get-")
            ):
                if token.lower() in seen:
                    continue
                commands.append(token)
                seen.add(token.lower())
            if len(commands) >= max_items:
                break
        return commands

    @staticmethod
    def _sanitize_commands(commands: list[str], *, max_items: int = 4) -> list[str]:
        sanitized: list[str] = []
        seen: set[str] = set()
        for raw in commands:
            token = str(raw or "").strip().strip("`")
            if not token:
                continue
            token = re.sub(r"^\s*(cmd|command|script|query)\s*:\s*", "", token, flags=re.IGNORECASE).strip()
            if not token or token.startswith("#"):
                continue
            if token.lower().startswith("preview only"):
                continue
            if token.lower().startswith("recommended_action"):
                continue
            key = token.lower()
            if key in seen:
                continue
            seen.add(key)
            sanitized.append(token)
            if len(sanitized) >= max_items:
                break
        return sanitized

    @staticmethod
    def _model_call_is_fallback(usage: dict[str, Any] | None) -> bool:
        if not isinstance(usage, dict):
            return False
        provider = ResolutionIntelligenceAgent._norm(usage.get("provider"))
        model = ResolutionIntelligenceAgent._norm(usage.get("model"))
        return (
            bool(usage.get("fallback"))
            or "fallback" in provider
            or "fallback" in model
            or "error" in usage
        )

    @staticmethod
    def _extract_model_object(content: Any) -> dict[str, Any] | None:
        text = str(content or "").strip()
        if not text:
            return None
        fenced = re.search(r"```(?:json)?\s*([\s\S]*?)```", text, flags=re.IGNORECASE)
        candidates = [fenced.group(1).strip()] if fenced else []
        candidates.append(text)
        first_brace = text.find("{")
        last_brace = text.rfind("}")
        if first_brace >= 0 and last_brace > first_brace:
            candidates.append(text[first_brace:last_brace + 1])
        for candidate in candidates:
            try:
                parsed = json.loads(candidate)
            except (TypeError, ValueError):
                continue
            if isinstance(parsed, dict):
                return parsed
        return None

    @staticmethod
    def _extract_model_text(content: Any, *, keys: tuple[str, ...], fallback_text: str) -> str:
        text = str(content or "").strip()
        if not text:
            return fallback_text
        parsed = ResolutionIntelligenceAgent._extract_model_object(text)
        if parsed is None:
            return text
        metadata = parsed.get("metadata") if isinstance(parsed.get("metadata"), dict) else {}
        if metadata.get("fallback"):
            return fallback_text
        for key in keys:
            value = parsed.get(key)
            if str(value or "").strip():
                return str(value).strip()
        return fallback_text

    @staticmethod
    def _validated_evidence_ids(values: Any, valid_ids: set[str]) -> list[str]:
        if not isinstance(values, list):
            return []
        accepted: list[str] = []
        for value in values:
            raw = str(value or "").strip()
            if raw.lower().startswith("external-knowledge://"):
                if raw not in accepted:
                    accepted.append(raw)
                continue
            match = raw if raw in valid_ids else next(
                (
                    evidence_id
                    for evidence_id in valid_ids
                    if raw.startswith(evidence_id)
                    and raw[len(evidence_id):len(evidence_id) + 1] in {"", ":", " ", "-", "—"}
                ),
                "",
            )
            if match and match not in accepted:
                accepted.append(match)
        return accepted

    def _infer_root_cause(self, context: Context, model_root_cause: str) -> str:
        raw_description = str(context.alert.description or "").strip()
        normalized_description = self._norm(raw_description)
        if (
            ("error 1227" in normalized_description or "access denied" in normalized_description)
            and "replication client" in normalized_description
            and ("slave_status" in normalized_description or "replica" in normalized_description)
        ):
            return (
                "The MySQL account used by mysql-exporter lacks the REPLICATION CLIENT privilege required by "
                "the slave_status collector, so MySQL rejects that scrape with error 1227."
            )
        deployment = str(context.deployment or "").strip()
        if deployment and any(
            keyword in normalized_description for keyword in ["deploy", "release", "rollout", "version"]
        ):
            return deployment

        for change in context.recent_changes[:5]:
            message = self._norm(change.get("message") or change.get("title"))
            if any(keyword in message for keyword in ["deploy", "release", "rollback", "config", "schema"]):
                return str(change.get("message") or change.get("title") or model_root_cause).strip()

        return str(model_root_cause or f"Likely degradation in {context.alert.service}").strip()

    def _infer_action_and_commands(self, context: Context, root_cause: str, model_action: str) -> tuple[str, list[str], str]:
        description = self._norm(context.alert.description)
        root = self._norm(root_cause)
        if "replication client privilege" in root and "mysql-exporter" in root:
            return (
                "Verify the exporter account and grant only REPLICATION CLIENT through the approved database-access process, then validate slave_status metrics.",
                [
                    "mysql -e \"SELECT CURRENT_USER(); SHOW GRANTS FOR CURRENT_USER();\"",
                    "mysql -e \"SHOW REPLICA STATUS\\G\"",
                ],
                str(context.alert.service or "mysql-exporter").strip(),
            )
        runbook = str(context.runbook or "")
        runbook_commands = self._sanitize_commands(self._extract_runbook_commands(runbook), max_items=4)
        if runbook_commands:
            target = str(context.alert.service or "service").strip()
            return (
                "Execute approved runbook remediation script and validation checks",
                runbook_commands,
                target,
            )

        if any(keyword in root for keyword in ["deploy", "release", "rollout", "version"]):
            target = str(context.kubernetes.get("deployment") or context.alert.service or "service").strip()
            return (
                "Rollback deployment",
                runbook_commands or [f"kubectl rollout undo deployment/{target} -n prod"],
                target,
            )

        if "pod" in description or "oom" in description or "crashloop" in description:
            target = str(context.kubernetes.get("deployment") or context.alert.service or "service").strip()
            return (
                "Restart pod",
                runbook_commands or [f"kubectl rollout restart deployment/{target} -n prod"],
                target,
            )

        if "latency" in description or "timeout" in description:
            target = str(context.alert.service or "service").strip()
            return (
                "Scale deployment and validate latency reduction",
                runbook_commands or [f"kubectl scale deployment/{target} --replicas=3 -n prod"],
                target,
            )

        if "database" in description or "replica" in description:
            target = str(context.alert.service or "database").strip()
            return (
                "Fail over database and validate replication health",
                runbook_commands or ["mysql -e \"SHOW REPLICA STATUS;\""],
                target,
            )

        target = str(context.alert.service or "service").strip()
        action = str(model_action or "Investigate service and apply runbook remediation").strip()
        if runbook_commands:
            return action, runbook_commands, target
        fallback_commands = [
            f"kubectl rollout status deployment/{target} -n prod --timeout=180s",
            f"kubectl get pods -n prod | findstr {target}",
        ]
        return action, self._sanitize_commands(fallback_commands, max_items=4), target

    async def _generate_with_fallback(
        self,
        *,
        context: Context,
        task: ModelTask,
        prompt: str,
        payload: dict[str, Any],
        fallback_content: str,
    ) -> dict[str, Any]:
        try:
            response = await asyncio.wait_for(
                self.model_gateway.generate(
                    GenerationRequest(
                        severity=context.alert.severity,
                        task=task.value,
                        prompt=prompt,
                        payload=payload,
                    )
                ),
                timeout=self.model_step_timeout_seconds,
            )
            if not isinstance(response, dict):
                raise ValueError("model gateway returned a non-dict response")
            usage = response.get("usage") if isinstance(response.get("usage"), dict) else {}
            usage.setdefault("provider", str(response.get("model") or "unknown"))
            usage.setdefault("model", str(usage.get("provider") or "unknown"))
            usage.setdefault("task", task.value)
            usage.setdefault("input_tokens", 0)
            usage.setdefault("output_tokens", 0)
            usage.setdefault("total_tokens", 0)
            usage.setdefault("total_cost_usd", 0.0)
            usage.setdefault("estimated", True)
            response_model = str(response.get("model") or "unknown")
            if "fallback" in response_model.lower() or self._model_call_is_fallback(usage):
                usage["fallback"] = True
            return {
                "model": response_model,
                "content": str(response.get("content") or fallback_content),
                "usage": usage,
            }
        except Exception as exc:
            return {
                "model": "fallback",
                "content": fallback_content,
                "usage": {
                    "provider": "fallback",
                    "model": "fallback",
                    "task": task.value,
                    "input_tokens": 0,
                    "output_tokens": 0,
                    "total_tokens": 0,
                    "total_cost_usd": 0.0,
                    "estimated": True,
                    "error": str(exc),
                },
            }

    async def _judge_groundedness(self, *, prediction: str, context_text: str) -> EvaluationResult | None:
        """Best-effort LLM-judge groundedness score. Never raises, never blocks resolve()."""
        if not self.evaluation_client.enabled or not context_text.strip():
            return None
        try:
            return await asyncio.wait_for(
                asyncio.to_thread(
                    self.evaluation_client.evaluate,
                    prediction,
                    metric="groundedness",
                    context=context_text,
                ),
                timeout=self.model_step_timeout_seconds,
            )
        except Exception:
            return None

    async def _post_evaluation(self, payload: dict[str, Any]) -> None:
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.post(f"{self.evaluation_service_url.rstrip('/')}/evaluations", json=payload)
            response.raise_for_status()
        except Exception as exc:
            logger.warning("evaluation_service_publish_failed", extra={"error": str(exc)})

    def _publish_evaluation(self, *, recommendation: Recommendation, report: dict[str, Any]) -> None:
        """Fire-and-forget: never awaited, never allowed to affect resolve()'s result."""
        model_calls = recommendation.metadata.get("model_calls")
        last_call = model_calls[-1] if isinstance(model_calls, list) and model_calls else {}
        payload = {
            "report": report,
            "agent": self.name,
            "incident_id": str(recommendation.incident_id),
            "recommendation_id": str(recommendation.id),
            "model_provider": str(last_call.get("provider") or "") or None,
            "model_name": str(last_call.get("model") or "") or None,
        }
        task = asyncio.create_task(self._post_evaluation(payload))
        self._background_tasks.add(task)
        task.add_done_callback(self._background_tasks.discard)

    async def can_execute(self, context: AgentContext) -> bool:
        return "context-agent" in context.previous_agent_results or "context" in context.previous_agent_results

    def _build_graph(self):
        workflow = StateGraph(ResolutionState)
        workflow.add_node("collect_context", self.collect_context)
        workflow.add_node("generate_rca", self.generate_rca)
        workflow.add_node("impact_analysis", self.impact_analysis)
        workflow.add_node("generate_fix", self.generate_fix)
        workflow.add_node("confidence_scoring", self.confidence_scoring)
        workflow.set_entry_point("collect_context")
        workflow.add_edge("collect_context", "generate_rca")
        workflow.add_edge("generate_rca", "impact_analysis")
        workflow.add_edge("impact_analysis", "generate_fix")
        workflow.add_edge("generate_fix", "confidence_scoring")
        workflow.add_edge("confidence_scoring", END)
        return workflow.compile()

    async def collect_context(self, state: ResolutionState) -> ResolutionState:
        context = state["context"]

        runbook_preview = (context.runbook or "")[:800]
        related_incident_preview = [
            {
                "title": str(item.get("title", ""))[:120],
                "service": item.get("service"),
                "severity": item.get("severity"),
            }
            for item in context.related_incidents[:3]
        ]
        recent_change_preview = [
            {
                "id": item.get("id"),
                "message": str(item.get("message") or item.get("title") or "")[:160],
            }
            for item in context.recent_changes[:5]
        ]
        discovery_report = (
            context.metadata.get("discovery_report")
            if isinstance(context.metadata.get("discovery_report"), dict)
            else {}
        )
        raw_evidence = list(discovery_report.get("evidence")) if isinstance(discovery_report.get("evidence"), list) else []
        source_event_id = str(context.alert.labels.get("source_event_id") or context.alert.id)
        raw_evidence.insert(
            0,
            {
                "evidence_id": f"alert:{source_event_id}",
                "source": str(context.alert.source or "alert"),
                "uri": str(
                    context.alert.labels.get("log_source_path")
                    or context.alert.annotations.get("generatorURL")
                    or f"alert://{context.alert.id}"
                ),
                "service": context.alert.service,
                "snippet": context.alert.description,
                "diagnostic_signals": ["alert_payload"],
            },
        )
        context_evidence = (
            context.metadata.get("context_evidence")
            if isinstance(context.metadata.get("context_evidence"), dict)
            else {}
        )
        for source_name in ("logs", "code", "tickets", "telemetry", "database", "rag"):
            rows = context_evidence.get(source_name)
            if isinstance(rows, list):
                raw_evidence.extend(row for row in rows if isinstance(row, dict))
        unique_evidence: dict[str, dict[str, Any]] = {}
        for index, item in enumerate(raw_evidence):
            if isinstance(item, dict):
                key = str(item.get("evidence_id") or item.get("uri") or item.get("path") or index)
                unique_evidence[key] = item
        raw_evidence = list(unique_evidence.values())
        service_terms = {
            token
            for value in (context.alert.service, context.alert.name, *context.alert.labels.values())
            for token in re.split(r"[^a-z0-9]+", self._norm(value))
            if len(token) >= 3
        }
        relevant_evidence: list[dict[str, Any]] = []
        for item in raw_evidence:
            if not isinstance(item, dict):
                continue
            evidence_text = self._norm(
                " ".join(
                    str(item.get(key) or "")
                    for key in ("evidence_id", "source", "uri", "path", "snippet", "service")
                )
            )
            if service_terms and not any(term in evidence_text for term in service_terms):
                continue
            relevant_evidence.append(
                {
                    "evidence_id": item.get("evidence_id"),
                    "source": item.get("source"),
                    "uri": item.get("uri") or item.get("path"),
                    "snippet": str(item.get("snippet") or "")[:500],
                    "diagnostic_signals": item.get("diagnostic_signals", []),
                    "signal_counts": item.get("signal_counts", {}),
                    "supporting_evidence": item.get("supporting_evidence", []),
                }
            )
            if len(relevant_evidence) >= 24:
                break

        log_evidence = [
            row for row in relevant_evidence if str(row.get("source") or "").lower() in {"log", "opensearch"}
        ]
        code_evidence = [row for row in relevant_evidence if str(row.get("source") or "").lower() == "code"]
        discovery_analysis = (
            discovery_report.get("report")
            if isinstance(discovery_report.get("report"), dict)
            else {}
        )
        detected_errors = (
            discovery_analysis.get("detected_errors")
            if isinstance(discovery_analysis.get("detected_errors"), list)
            else discovery_report.get("detected_errors")
            if isinstance(discovery_report.get("detected_errors"), list)
            else []
        )

        state["gathered_context"] = {
            "alert": {
                "name": context.alert.name,
                "service": context.alert.service,
                "severity": context.alert.severity.value,
                "description": context.alert.description,
                "labels": context.alert.labels,
            },
            "observability": context.observability,
            "discovery_evidence": relevant_evidence,
            "log_intelligence": log_evidence[:8],
            "code_evidence": code_evidence[:8],
            "detected_errors": detected_errors[:12],
            "deployment": context.deployment,
            "related_incidents": related_incident_preview,
            "runbook": runbook_preview,
            "dependency_services": context.dependency_services[:8],
            "recent_changes": recent_change_preview,
        }
        return state

    async def generate_rca(self, state: ResolutionState) -> ResolutionState:
        context = state["context"]
        discovery_report = (
            context.metadata.get("discovery_report")
            if isinstance(context.metadata.get("discovery_report"), dict)
            else {}
        )
        discovery_analysis = (
            discovery_report.get("report")
            if isinstance(discovery_report.get("report"), dict)
            else {}
        )
        external_knowledge_used = bool(discovery_analysis.get("external_knowledge_used"))
        external_hypotheses = (
            discovery_analysis.get("hypotheses")
            if isinstance(discovery_analysis.get("hypotheses"), list)
            else []
        )
        external_citations = [
            str(value).strip()
            for value in (discovery_analysis.get("citations") if isinstance(discovery_analysis.get("citations"), list) else [])
            if str(value or "").strip().lower().startswith("external-knowledge://")
        ]
        prompt = PROMPT_IDENTIFY_ROOT_CAUSE
        payload = {"summary": context.alert.description, **state["gathered_context"]}
        response = await self._generate_with_fallback(
            context=context,
            task=ModelTask.RCA,
            prompt=prompt,
            payload=payload,
            fallback_content=f"Likely service degradation in {context.alert.service}",
        )
        parsed = self._extract_model_object(response["content"]) or {}
        content = self._extract_model_text(
            response["content"],
            keys=("root_cause", "cause", "summary"),
            fallback_text=f"Evidence is insufficient to determine the root cause of {context.alert.service} degradation.",
        )
        state["root_cause"] = self._infer_root_cause(context, content)
        valid_ids = {
            str(row.get("evidence_id"))
            for row in state["gathered_context"].get("discovery_evidence", [])
            if isinstance(row, dict) and row.get("evidence_id")
        }
        cited = self._validated_evidence_ids(parsed.get("evidence_used"), valid_ids)
        try:
            model_confidence = max(0.0, min(1.0, float(parsed.get("confidence_score", 0.0))))
        except (TypeError, ValueError):
            model_confidence = 0.0
        explicit_alert_diagnosis = (
            "lacks the replication client privilege" in self._norm(state["root_cause"])
            and "error 1227" in self._norm(context.alert.description)
        )
        external_grounding_used = False
        if explicit_alert_diagnosis:
            source_event_id = str(context.alert.labels.get("source_event_id") or context.alert.id)
            alert_evidence_id = f"alert:{source_event_id}"
            if alert_evidence_id in valid_ids and alert_evidence_id not in cited:
                cited.insert(0, alert_evidence_id)
            model_confidence = max(model_confidence, 0.95)
        if not cited and external_knowledge_used:
            best_external_hypothesis = next(
                (
                    str(item.get("cause") or "").strip()
                    for item in external_hypotheses
                    if isinstance(item, dict) and str(item.get("cause") or "").strip()
                ),
                "",
            )
            if best_external_hypothesis:
                state["root_cause"] = best_external_hypothesis
            if external_citations:
                cited.extend(value for value in external_citations if value not in cited)
            else:
                cited.append("external-knowledge://discovery")
            best_external_confidence = 0.0
            for item in external_hypotheses:
                if not isinstance(item, dict):
                    continue
                try:
                    best_external_confidence = float(item.get("confidence") or 0.0)
                    break
                except (TypeError, ValueError):
                    continue
            model_confidence = max(model_confidence, min(max(best_external_confidence, 0.5), 0.6))
            external_grounding_used = True
        if not cited:
            model_confidence = min(model_confidence, 0.49)
        state["rca_analysis"] = {
            "root_cause": state["root_cause"],
            "evidence_used": cited,
            "missing_evidence": parsed.get("missing_evidence", []),
            "alternative_causes": parsed.get("alternative_causes", []),
            "grounding_notes": parsed.get("grounding_notes", ""),
            "confidence_score": model_confidence,
            "evidence_validation": {
                "requested": parsed.get("evidence_used", []),
                "accepted": cited,
                "available_count": len(valid_ids),
            },
            "external_knowledge_used": external_grounding_used,
        }
        state["rationale"] = (
            f"Model {response['model']} proposed the RCA with {len(cited)} validated evidence citation(s); "
            f"confidence={model_confidence:.2f}."
        )
        state.setdefault("model_usage", []).append(response["usage"])
        state.setdefault("model_calls", []).append(
            {
                "task": ModelTask.RCA.value,
                "provider": response["model"],
                "model": response["usage"].get("model"),
                "prompt": prompt,
                "payload": payload,
                "response": {
                    "text": response["content"],
                    "parameters": {
                        "provider": response["model"],
                        "model": response["usage"].get("model"),
                        "task": ModelTask.RCA.value,
                    },
                },
                "usage": response["usage"],
            }
        )
        return state

    async def impact_analysis(self, state: ResolutionState) -> ResolutionState:
        context = state["context"]
        prompt = PROMPT_ASSESS_IMPACT
        payload = {
            "alert": state["gathered_context"].get("alert", {}),
            "metrics": context.observability,
            "dependencies": context.dependency_services[:8],
            "discovery_evidence": state["gathered_context"].get("discovery_evidence", []),
            "log_intelligence": state["gathered_context"].get("log_intelligence", []),
            "detected_errors": state["gathered_context"].get("detected_errors", []),
        }
        response = await self._generate_with_fallback(
            context=context,
            task=ModelTask.IMPACT,
            prompt=prompt,
            payload=payload,
            fallback_content=f"{context.alert.service.title()} service impact requires immediate triage",
        )
        parsed = self._extract_model_object(response["content"]) or {}
        normalized_description = self._norm(context.alert.description)
        normalized_root_cause = self._norm(state.get("root_cause"))
        if "replication client privilege" in normalized_root_cause and "mysql-exporter" in normalized_root_cause:
            state["impact"] = (
                "Observed impact: mysql-exporter cannot collect slave_status/replication metrics. "
                "Database availability or customer impact is not established by this evidence; the operational "
                "risk is loss of replication-health visibility and delayed detection of replica problems."
            )
        elif "latency" in normalized_description:
            state["impact"] = f"{context.alert.service.title()} latency"
        else:
            state["impact"] = self._extract_model_text(
                response["content"],
                keys=("impact_summary", "customer_impact", "service_impact", "severity_rationale", "summary"),
                fallback_text=f"{context.alert.service.title()} service impact requires immediate triage",
            )
        valid_ids = {
            str(row.get("evidence_id"))
            for row in state["gathered_context"].get("discovery_evidence", [])
            if isinstance(row, dict) and row.get("evidence_id")
        }
        impact_citations = self._validated_evidence_ids(parsed.get("evidence_used"), valid_ids)
        try:
            impact_confidence = max(0.0, min(1.0, float(parsed.get("confidence_score", 0.0))))
        except (TypeError, ValueError):
            impact_confidence = 0.0
        if not impact_citations:
            impact_confidence = min(impact_confidence, 0.49)
        state["impact_analysis"] = {
            **parsed,
            "evidence_used": impact_citations,
            "confidence_score": impact_confidence,
            "observed_vs_risk": "Observed claims require accepted evidence citations; remaining claims are risk or assumptions.",
        }
        state.setdefault("model_usage", []).append(response["usage"])
        state.setdefault("model_calls", []).append(
            {
                "task": ModelTask.IMPACT.value,
                "provider": response["model"],
                "model": response["usage"].get("model"),
                "prompt": prompt,
                "payload": payload,
                "response": {
                    "text": response["content"],
                    "parameters": {
                        "provider": response["model"],
                        "model": response["usage"].get("model"),
                        "task": ModelTask.IMPACT.value,
                    },
                },
                "usage": response["usage"],
            }
        )
        return state

    async def generate_fix(self, state: ResolutionState) -> ResolutionState:
        context = state["context"]
        prompt = PROMPT_RECOMMEND_REMEDIATION
        payload = {"service": context.alert.service, "runbook": context.runbook, "root_cause": state.get("root_cause", "")}
        response = await self._generate_with_fallback(
            context=context,
            task=ModelTask.FIX,
            prompt=prompt,
            payload=payload,
            fallback_content=f"Investigate {context.alert.service} health and apply documented runbook remediation",
        )
        parsed = self._extract_model_object(response["content"]) or {}
        model_action = self._extract_model_text(
            response["content"],
            keys=("recommended_action", "action", "summary"),
            fallback_text=f"Investigate {context.alert.service} health and apply documented runbook remediation",
        )
        action, commands, remediation_target = self._infer_action_and_commands(
            context,
            str(state.get("root_cause") or ""),
            model_action,
        )
        state["remediation_target"] = remediation_target
        state.setdefault("model_usage", []).append(response["usage"])
        state.setdefault("model_calls", []).append(
            {
                "task": ModelTask.FIX.value,
                "provider": response["model"],
                "model": response["usage"].get("model"),
                "prompt": prompt,
                "payload": payload,
                "response": {
                    "text": response["content"],
                    "parameters": {
                        "provider": response["model"],
                        "model": response["usage"].get("model"),
                        "task": ModelTask.FIX.value,
                    },
                },
                "usage": response["usage"],
            }
        )
        state["recommended_action"] = action
        state["commands"] = commands
        state["remediation_analysis"] = {
            **parsed,
            "recommended_action": action,
            "commands": commands,
            "remediation_target": remediation_target,
        }
        return state

    async def confidence_scoring(self, state: ResolutionState) -> ResolutionState:
        context = state["context"]
        rca_confidence = float(state.get("rca_analysis", {}).get("confidence_score") or 0.0)
        impact_confidence = float(state.get("impact_analysis", {}).get("confidence_score") or 0.0)
        score = (rca_confidence * 0.7) + (impact_confidence * 0.3)
        if context.deployment:
            score += 0.04
        if context.related_incidents:
            score += 0.03
        if context.runbook:
            score += 0.03
        if context.alert.severity in {AlertSeverity.HIGH, AlertSeverity.CRITICAL}:
            score += 0.02
        if state.get("commands"):
            score += 0.02
        if state.get("gathered_context", {}).get("discovery_evidence"):
            score += 0.03
        if not state.get("rca_analysis", {}).get("evidence_used"):
            score = min(score, 0.49)

        fallback_hits = 0
        for usage in state.get("model_usage", []):
            if self._model_call_is_fallback(usage):
                fallback_hits += 1
        if fallback_hits:
            score -= min(0.2, 0.08 * fallback_hits)
            score = min(score, 0.64)
        if fallback_hits >= max(1, len(state.get("model_usage", []))):
            score = min(score, 0.49)

        state["confidence"] = round(max(0.05, min(score, 0.99)), 4)
        return state

    async def resolve(self, context: Context) -> Recommendation:
        state = await self.graph.ainvoke({"context": context})
        runbook_present = bool((context.runbook or "").strip())
        discovery_evidence = state.get("gathered_context", {}).get("discovery_evidence") or []
        evidence = [
            Evidence(
                id=f"ctx:{context.incident_id}",
                type="context",
                source="context-agent",
                confidence=0.9,
                metadata={"service": context.alert.service},
                content={"related_incidents": len(context.related_incidents)},
            ),
            Evidence(
                id=f"runbook:{context.incident_id}",
                type="runbook",
                source="knowledge-router",
                confidence=0.85 if runbook_present else 0.25,
                metadata={"present": runbook_present},
                content={"preview": (context.runbook or "")[:180]},
            ),
        ]
        if discovery_evidence:
            # collect_context already filtered discovery-mcp evidence down to items relevant
            # to this alert's service/labels; surface that grounding on the recommendation
            # instead of letting it disappear once the RCA/impact/fix prompts consume it.
            evidence.append(
                Evidence(
                    id=f"discovery:{context.incident_id}",
                    type="discovery",
                    source="discovery-mcp",
                    confidence=0.8,
                    metadata={"item_count": len(discovery_evidence)},
                    content={
                        "sources": [str(item.get("source") or "") for item in discovery_evidence[:6] if item.get("source")],
                    },
                )
            )
        recommendation = Recommendation(
            incident_id=context.incident_id,
            root_cause=state["root_cause"],
            confidence=state["confidence"],
            impact=state["impact"],
            recommended_action=state["recommended_action"],
            severity=context.alert.severity,
            rationale=state["rationale"],
            commands=state.get("commands", []),
            risk="high" if context.alert.severity == AlertSeverity.CRITICAL else "medium",
        )
        recommendation.metadata["model_usage"] = state.get("model_usage", [])
        recommendation.metadata["model_calls"] = state.get("model_calls", [])
        recommendation.metadata["evidence"] = [item.model_dump(mode="json") for item in evidence]
        accepted_evidence_ids = [
            str(value)
            for value in state.get("rca_analysis", {}).get("evidence_used", [])
            if str(value or "").strip()
        ]
        recommendation.metadata["evidence_ids"] = list(
            dict.fromkeys([*accepted_evidence_ids, *(item.id for item in evidence)])
        )
        recommendation.metadata["reasoning"] = state.get("rationale", "")
        recommendation.metadata["rca_analysis"] = state.get("rca_analysis", {})
        recommendation.metadata["impact_analysis"] = state.get("impact_analysis", {})
        recommendation.metadata["remediation_analysis"] = state.get("remediation_analysis", {})
        recommendation.metadata["detected_errors"] = state.get("gathered_context", {}).get("detected_errors", [])
        recommendation.metadata["detected_error_count"] = len(recommendation.metadata["detected_errors"])
        recommendation.metadata["service"] = str(context.alert.service or "")
        recommendation.metadata["environment"] = str(context.alert.environment or "prod")
        recommendation.metadata["remediation_target"] = str(state.get("remediation_target") or context.alert.service or "")
        recommendation.metadata["recommended_commands"] = state.get("commands", [])
        discovery_report = (
            context.metadata.get("discovery_report")
            if isinstance(context.metadata.get("discovery_report"), dict)
            else {}
        )
        discovery_analysis = (
            discovery_report.get("report")
            if isinstance(discovery_report.get("report"), dict)
            else {}
        )
        recommendation.metadata["external_knowledge_eligible"] = bool(
            discovery_analysis.get("external_knowledge_eligible")
        )
        recommendation.metadata["external_knowledge_used"] = bool(
            discovery_analysis.get("external_knowledge_used")
        )
        recommendation.metadata["external_tools_used"] = list(
            discovery_analysis.get("external_tools_used", [])
            if isinstance(discovery_analysis.get("external_tools_used"), list)
            else []
        )
        recommendation.metadata["external_knowledge_error"] = (
            str(discovery_analysis.get("external_knowledge_error") or "")[:300] or None
        )
        fallback_usages = [usage for usage in state.get("model_usage", []) if self._model_call_is_fallback(usage)]
        recommendation.metadata["fallback_used"] = bool(fallback_usages)
        recommendation.metadata["fallback_reason"] = "; ".join(
            str(usage.get("error") or usage.get("fallback_reason") or "model-router fallback")
            for usage in fallback_usages
        )[:800] or None
        recommendation.metadata["quality_gate"] = {
            "trusted_for_auto_execution": not fallback_usages and recommendation.confidence >= 0.9,
            "requires_human_review": bool(fallback_usages) or recommendation.confidence < 0.75,
            "reason": "model fallback used" if fallback_usages else "confidence policy",
        }
        citations = [f"incident://{context.incident_id}"]
        if runbook_present:
            citations.append(f"runbook://{context.alert.service}")
        if discovery_evidence:
            citations.append(f"discovery://{context.incident_id}")
            evidence_by_id = {
                str(item.get("evidence_id")): str(item.get("uri") or "")
                for item in discovery_evidence
                if isinstance(item, dict) and str(item.get("evidence_id") or "").strip()
            }
            citations.extend(
                evidence_by_id[evidence_id]
                for evidence_id in accepted_evidence_ids
                if evidence_by_id.get(evidence_id)
            )
        recommendation.metadata["citations"] = list(dict.fromkeys(citations))
        external_judge = await self._judge_groundedness(
            prediction=f"{recommendation.root_cause} {recommendation.recommended_action} {recommendation.rationale}",
            context_text=context.runbook or "",
        )
        recommendation.metadata["evaluation"] = build_quality_evaluation(
            prediction={
                "root_cause": recommendation.root_cause,
                "impact": recommendation.impact,
                "recommended_action": recommendation.recommended_action,
                "rationale": recommendation.rationale,
                "commands": recommendation.commands,
            },
            context={
                "alert": context.alert.model_dump(mode="json"),
                "runbook": context.runbook,
                "related_incidents": context.related_incidents,
                "metadata": context.metadata,
            },
            confidence=recommendation.confidence,
            citations=recommendation.metadata["citations"],
            rag_matches=context.metadata.get("rag_matches", []) if isinstance(context.metadata, dict) else [],
            runbook_found=runbook_present,
            fallback_used=any(
                str((usage or {}).get("provider") or "").lower() == "fallback"
                or str((usage or {}).get("model") or "").lower() == "fallback"
                or "error" in (usage or {})
                for usage in state.get("model_usage", [])
            ),
            external=external_judge,
        )
        self._publish_evaluation(recommendation=recommendation, report=recommendation.metadata["evaluation"])
        return recommendation

    async def resolve_with_runtime(self, context: Context) -> Recommendation:
        runtime_context = AgentContext.from_context(context)
        runtime_result = await self.runtime.run(self, runtime_context)
        recommendation = runtime_result.result
        if not isinstance(recommendation, Recommendation):
            raise ValidationError("resolution runtime produced non-recommendation output")
        recommendation.metadata["runtime"] = {
            "status": runtime_result.state.execution_status,
            "retry_count": runtime_result.state.retries,
            "reflection": runtime_result.reflection,
        }
        await self.memory_store.append(
            "incident-memory",
            {
                "incident_id": str(context.incident_id),
                "service": context.alert.service,
                "recommended_action": recommendation.recommended_action,
                "confidence": recommendation.confidence,
                "reflection": runtime_result.reflection,
            },
        )
        return recommendation

    async def initialize(self, context: AgentContext, state: Any) -> None:
        state.execution_status = "analyzing"

    async def plan(self, context: AgentContext, state: Any) -> dict[str, Any]:
        payload = context.previous_agent_results.get("context-agent") or context.previous_agent_results.get("context")
        model_task_count = 3
        if not isinstance(payload, dict):
            raise ContextFailure("resolution agent requires serialized context payload")
        return {
            "phase": "resolution",
            "steps": ["collect_context", "generate_rca", "impact_analysis", "generate_fix", "confidence_scoring"],
            "model_task_count": model_task_count,
        }

    async def execute(self, context: AgentContext) -> Recommendation:
        context_payload = context.previous_agent_results.get("context-agent") or context.previous_agent_results.get("context")
        if not isinstance(context_payload, dict):
            raise ContextFailure("AgentContext.previous_agent_results must include serialized context")
        recommendation = await self.resolve(Context.model_validate(context_payload))
        context.set_result(self.name, recommendation.model_dump(mode="json"))
        return recommendation

    async def validate(self, result: Any) -> bool:
        if not isinstance(result, Recommendation):
            return False
        if result.confidence <= 0:
            raise ValidationError("confidence must be greater than zero")
        evidence_ids = result.metadata.get("evidence_ids", [])
        if not isinstance(evidence_ids, list) or not evidence_ids:
            raise ValidationError("recommendation must include evidence_ids")
        return True

    async def reflect(
        self,
        context: AgentContext,
        state: Any,
        *,
        result: Any | None,
        error: Exception | None,
    ) -> dict[str, Any]:
        confidence = float(result.confidence) if isinstance(result, Recommendation) else 0.0
        quality = "high" if confidence >= 0.85 else "medium" if confidence >= 0.65 else "low"
        return {
            "agent": self.name,
            "quality": quality,
            "lessons_learned": [
                "Preserve runbook and incident evidence links in every recommendation.",
                "Escalate to approval path when confidence is below policy threshold.",
            ],
            "failed_tool_calls": [],
            "missing_evidence": [] if confidence >= 0.5 else ["runbook", "related_incidents"],
            "confidence_adjustment": 0.0,
            "error": str(error) if error else None,
        }
