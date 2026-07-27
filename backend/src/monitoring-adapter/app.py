from __future__ import annotations
import asyncio
from collections import deque
import hashlib
import heapq
import json
import os
import re
import sys
import uuid
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from pathlib import Path
from time import perf_counter
from typing import Any, Literal
from urllib.parse import urlparse
from uuid import UUID

from common.config import get_settings
from common.ai_layer_client import AiLayerClient
from common.database import create_engine, create_schema, create_session_factory
from common.event_publishers import build_agent_event_contract, build_event_envelope
from common.logging import get_logger
from ai_workbench_common.model_evaluation import build_quality_evaluation
from common.models import (
    Alert,
    AlertSeverity,
    EvidenceReference,
    RawAlert,
    Incident,
    IncidentStatus,
    Approval,
    ApprovalDecision,
    Recommendation,
    RemediationAction,
    RemediationStatus,
    ResolutionReport,
)
from common.repository import IncidentRepository
from common.service import create_app
from common.telemetry import EVENT_CONTRACTS_EMITTED, EVENT_PUBLISH_LATENCY
from common.topics import (
    ALERT_CONTEXT_REQUESTED,
    ALERT_NORMALIZED,
    ALERT_RCA_REQUESTED,
    ALERT_RECEIVED,
    APPROVAL_REQUESTED,
    AUTOMATION_EXECUTED,
    JIRA_INVESTIGATIONS,
    RAW_ALERTS,
    RESOLUTION_GENERATED,
)
from ai_workbench_common.prompts import PROMPT_SUMMARIZE_RCA
import httpx
from fastapi import BackgroundTasks, Body, Header, HTTPException, Query
from pydantic import BaseModel, Field, model_validator
from monitoring_adapter.state import (
    ALERT_SEVERITY_OVERRIDES_FILE,
    FLOW_CATALOG_FILE,
    ONBOARDING_CONNECTIVITY_FILE,
    SCENARIOS,
    SCENARIOS_TEXT_FILE,
    alert_severity_overrides_path,
    default_flow_catalog_entries,
    ensure_flow_catalog_exists,
    flow_catalog_path,
    load_alert_severity_overrides,
    list_scenarios,
    load_onboarding_connectivity,
    load_scenarios_from_text_file,
    merged_scenarios,
    onboarding_connectivity_path,
    rag_root_path,
    remove_alert_severity_override,
    resolve_flow_id,
    save_alert_severity_overrides,
    save_onboarding_connectivity,
    scenario_source_rows,
    scenarios_text_path,
    severity_from_string,
    slugify,
    upsert_alert_severity_override,
)
from monitoring_adapter.onboarding_pipelines import (
    ExistingRulePipelineRequest,
    NewRuleOnboardingRequest,
    build_prometheus_rules_yaml,
    capabilities_catalog,
    find_pipeline_rows,
    run_existing_rule_pipeline,
    run_new_rule_pipeline,
)
from monitoring_adapter.existing_monitoring import (
    apply_field_mapping,
    build_webhook_path,
    default_field_mappings,
    get_provider_adapter,
    hash_secrets,
    mask_secrets,
    normalize_provider_name,
    verify_hmac_signature,
)
from monitoring_adapter.landing_pad_normalizer import normalize_landing_pad_alert
from monitoring_adapter.landing_pad_sources import SUPPORTED_SUFFIXES, load_landing_pad_file
from monitoring_adapter.email_ingestion import ImapConfig, email_to_alert_payload, fetch_unseen_emails
from monitoring_adapter.dedup import compute_fingerprint
from monitoring_adapter.jira_client import JiraClient, JiraClientError
from monitoring_adapter.jira_admission import JiraAdmissionState
from monitoring_adapter.log_ingestion import (
    LogWatchState,
    OpenSearchLogState,
    fetch_new_log_lines,
    fetch_opensearch_error_logs,
    log_line_to_alert_payload,
)

ALERT_BODY = Body(...)

settings = get_settings()
settings.service_name = "monitoring-adapter"
logger = get_logger(__name__)
RECENT_ALERTS: deque[dict[str, Any]] = deque(maxlen=200)
RECENT_INGESTION_EVENTS: deque[dict[str, Any]] = deque(maxlen=500)
RECENT_INGESTION_EVENTS_BY_SOURCE: dict[str, deque[dict[str, Any]]] = {}
# Fallback only for deployments without database-backed workflow state.
PENDING_WORKFLOWS: dict[str, dict[str, Any]] = {}
CLOSED_INCIDENTS: deque[dict[str, Any]] = deque(maxlen=500)
LANDING_PAD_INPUT_DIR = Path(os.getenv("LANDING_PAD_INPUT_DIR", "/app/ingested_alerts/input"))
LANDING_PAD_PROCESSED_DIR = LANDING_PAD_INPUT_DIR.parent / "processed"
LANDING_PAD_FAILED_DIR = LANDING_PAD_INPUT_DIR.parent / "failed"
LANDING_PAD_ARCHIVE_DIR = LANDING_PAD_INPUT_DIR.parent / "archive"
LANDING_PAD_INPUT_REPLAYED_DIR = LANDING_PAD_INPUT_DIR.parent / "input_replayed"
LANDING_PAD_INPUT_FAILED_DIR = LANDING_PAD_INPUT_DIR.parent / "input_failed"

# Archival strategy for processed/failed landing-pad records — opt-in, since
# most deployments are fine keeping everything in processed/failed. When
# enabled, a background sweep moves files older than the configured age out
# of processed/<source>/<date>/ and failed/<source>/<date>/ into the mirrored
# path under archive/, preserving the source/date layout.
LANDING_PAD_ARCHIVE_ENABLED = str(os.getenv("LANDING_PAD_ARCHIVE_ENABLED", "false")).strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}
LANDING_PAD_ARCHIVE_AFTER_DAYS = max(
    1.0,
    float(os.getenv("LANDING_PAD_ARCHIVE_AFTER_DAYS", "30") or 30),
)
LANDING_PAD_ARCHIVE_INTERVAL_SECONDS = max(
    60.0,
    float(os.getenv("LANDING_PAD_ARCHIVE_INTERVAL_SECONDS", "3600") or 3600),
)
_DEFAULT_LANDING_PAD_REPLAY_DIR = LANDING_PAD_INPUT_DIR.parent / "Alerts"
LANDING_PAD_ADDITIONAL_INPUT_DIRS = [
    Path(item.strip())
    for item in os.getenv("LANDING_PAD_ADDITIONAL_INPUT_DIRS", str(_DEFAULT_LANDING_PAD_REPLAY_DIR)).split(os.pathsep)
    if item.strip()
]
# Archive folders (processed/failed/input_replayed/input_failed) are partitioned
# by UTC date (YYYY/MM/DD) so no single directory accumulates an unbounded
# number of entries as tickets, emails and fault-lab alerts stream in. The
# live `input/` inbox stays flat since the watcher/Alertmanager need a cheap,
# non-recursive scan of it and files are archived out of it quickly.
LANDING_PAD_LISTING_LOOKBACK_DAYS = max(1, int(os.getenv("LANDING_PAD_LISTING_LOOKBACK_DAYS", "14") or 14))
LANDING_PAD_DEDUP_LOOKBACK_DAYS = max(1, int(os.getenv("LANDING_PAD_DEDUP_LOOKBACK_DAYS", "30") or 30))

# Bounds for burst ingestion (a 10,000-alert burst across CSV/email/webhook
# sources): how many publish+persist operations may run concurrently
# process-wide, and how long a claimed-but-never-finished input file waits
# before being recovered for retry.
LANDING_PAD_INGEST_CONCURRENCY = max(1, int(os.getenv("LANDING_PAD_INGEST_CONCURRENCY", "8") or 8))
LANDING_PAD_CLAIM_STALE_MINUTES = max(1.0, float(os.getenv("LANDING_PAD_CLAIM_STALE_MINUTES", "15") or 15))
ALERTMANAGER_DEDUP_TTL_SECONDS = max(
    30.0,
    float(os.getenv("ALERTMANAGER_DEDUP_TTL_SECONDS", "900") or 900),
)
ALERTMANAGER_DEDUP_MAX_ENTRIES = max(
    100,
    int(os.getenv("ALERTMANAGER_DEDUP_MAX_ENTRIES", "10000") or 10000),
)
_ALERTMANAGER_RECENT_DELIVERIES: dict[str, float] = {}
_LOG_DISCOVERY_ADMISSIONS: deque[float] = deque()

LANDING_PAD_FILE_WATCHER_ENABLED = str(os.getenv("LANDING_PAD_FILE_WATCHER_ENABLED", "true")).strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}
LANDING_PAD_FILE_WATCHER_INTERVAL_SECONDS = max(
    2.0,
    float(os.getenv("LANDING_PAD_FILE_WATCHER_INTERVAL_SECONDS", "5") or 5),
)

_PROMPT_FRAGMENT_PATTERNS = (
    "identify the most likely root cause using only",
    "assess customer, service, dependency, and business impact",
    "generate an operator-safe remediation",
)


def _is_prompt_fragment(value: str) -> bool:
    text = str(value or "").strip().lower()
    return any(fragment in text for fragment in _PROMPT_FRAGMENT_PATTERNS)


def _clean_recommendation_text(value: Any, *, keys: tuple[str, ...], fallback: str) -> str:
    """Return operator-readable recommendation text from model/scenario payloads."""
    if value is None:
        return fallback
    text = str(value).strip()
    if not text:
        return fallback
    if text.startswith("{") and text.endswith("}"):
        try:
            payload = json.loads(text)
        except Exception:
            return fallback if _is_prompt_fragment(text) else text
        if isinstance(payload, dict):
            for key in keys:
                candidate = payload.get(key)
                if isinstance(candidate, (str, int, float)):
                    candidate_text = str(candidate).strip()
                    if candidate_text and not _is_prompt_fragment(candidate_text):
                        return candidate_text
            metadata = payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {}
            if metadata.get("fallback"):
                return fallback
            for key in ("summary", "content", "title"):
                candidate = payload.get(key)
                if isinstance(candidate, (str, int, float)):
                    candidate_text = str(candidate).strip()
                    if candidate_text and not _is_prompt_fragment(candidate_text):
                        return candidate_text
        return fallback
    return fallback if _is_prompt_fragment(text) else text


def _clean_resolution_fields(scenario: dict[str, Any], service: str, description: str) -> dict[str, str]:
    service_name = str(service or scenario.get("service") or "the affected service").strip()
    description_text = str(description or scenario.get("description") or "").strip()
    root_fallback = (
        f"{service_name} is unhealthy or unreachable according to the selected alert signal."
    )
    if description_text:
        root_fallback = f"{description_text}"
    impact_fallback = (
        f"{service_name} may have degraded availability, latency, or dependent workflow impact until recovery is validated."
    )
    action_fallback = "Execute the approved runbook remediation script and validation checks."
    root_cause = _clean_recommendation_text(
        scenario.get("root_cause"),
        keys=("root_cause", "cause", "summary", "content", "title"),
        fallback=root_fallback,
    )
    impact = _clean_recommendation_text(
        scenario.get("impact"),
        keys=("impact", "customer_impact", "dependency_impact", "summary", "content", "title"),
        fallback=impact_fallback,
    )
    recommended_action = _clean_recommendation_text(
        scenario.get("recommended_action"),
        keys=("recommended_action", "action", "summary", "content", "title"),
        fallback=action_fallback,
    )
    return {
        "root_cause": root_cause,
        "impact": impact,
        "recommended_action": recommended_action,
    }
LANDING_PAD_FILE_WATCHER_BATCH_SIZE = max(
    1,
    min(int(os.getenv("LANDING_PAD_FILE_WATCHER_BATCH_SIZE", "25") or 25), 200),
)
LANDING_PAD_FILE_WATCHER_STALE_HOURS = max(
    0.0,
    float(os.getenv("LANDING_PAD_FILE_WATCHER_STALE_HOURS", "24") or 24),
)
LANDING_PAD_SCAN_MAX_FILES = max(
    100,
    int(os.getenv("LANDING_PAD_SCAN_MAX_FILES", "4000") or 4000),
)
LANDING_PAD_SCAN_MAX_PARSE_BYTES = max(
    16_384,
    int(os.getenv("LANDING_PAD_SCAN_MAX_PARSE_BYTES", "1048576") or 1_048_576),
)
# Jira ticket ingestion — shared-secret webhook auth (checked via
# ?token=... query param or X-Webhook-Token header). Empty secret means the
# endpoint is disabled (fails closed, unlike the HMAC webhook verifier
# elsewhere in this file which fails open when unconfigured).
JIRA_WEBHOOK_SECRET = str(os.getenv("JIRA_WEBHOOK_SECRET", "") or "").strip()

# Outbound Jira API — distinct from JIRA_WEBHOOK_SECRET above (inbound
# auth). When CENTRALIZED_JIRA_ROUTING_ENABLED is true, Prometheus/log/
# email ingestion route through the centralized dedup step and create or
# update Jira tickets instead of publishing straight to the landing pad —
# Jira's own webhook (unchanged, JIRA_WEBHOOK_SECRET above) becomes the
# only door back into the landing pad. Off by default so this can be
# rolled out only once real Jira credentials are configured.
JIRA_API_BASE_URL = str(os.getenv("JIRA_API_BASE_URL", "") or "").strip()
JIRA_API_EMAIL = str(os.getenv("JIRA_API_EMAIL", "") or "").strip()
JIRA_API_TOKEN = str(os.getenv("JIRA_API_TOKEN", "") or "").strip()
JIRA_PROJECT_KEY = str(os.getenv("JIRA_PROJECT_KEY", "") or "").strip()
CENTRALIZED_JIRA_ROUTING_ENABLED = str(os.getenv("CENTRALIZED_JIRA_ROUTING_ENABLED", "false")).strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}

# Log ingestion — watches log files, extracts failure lines as alerts, and
# routes them through the same centralized Jira dedup step as Prometheus
# and email. Disabled unless explicit paths are configured.
LOG_INGESTION_ENABLED = str(os.getenv("LOG_INGESTION_ENABLED", "false")).strip().lower() in {"1", "true", "yes", "on"}
LOG_WATCH_PATHS = [Path(item.strip()) for item in os.getenv("LOG_WATCH_PATHS", "").split(os.pathsep) if item.strip()]
LOG_POLL_INTERVAL_SECONDS = max(5.0, float(os.getenv("LOG_POLL_INTERVAL_SECONDS", "30") or 30))
LOG_DEFAULT_SERVICE = str(os.getenv("LOG_DEFAULT_SERVICE", "log-ingestion") or "log-ingestion").strip()
LOG_INGESTION_STATE_FILE = LANDING_PAD_INPUT_DIR.parent / "log_ingestion_state.json"
OPENSEARCH_LOG_INGESTION_ENABLED = str(
    os.getenv("OPENSEARCH_LOG_INGESTION_ENABLED", "false")
).strip().lower() in {"1", "true", "yes", "on"}
OPENSEARCH_LOG_URL = str(os.getenv("OPENSEARCH_LOG_URL", "http://host.docker.internal:9200") or "").strip()
OPENSEARCH_LOG_INDEX = str(os.getenv("OPENSEARCH_LOG_INDEX", "otel-*") or "otel-*").strip()
OPENSEARCH_LOG_DOCKER_API_URL = str(
    os.getenv("OPENSEARCH_LOG_DOCKER_API_URL", "http://docker-socket-proxy:2375") or ""
).strip()
OPENSEARCH_LOG_POLL_INTERVAL_SECONDS = max(
    10.0, float(os.getenv("OPENSEARCH_LOG_POLL_INTERVAL_SECONDS", "30") or 30)
)
OPENSEARCH_LOG_LOOKBACK_SECONDS = max(30, int(os.getenv("OPENSEARCH_LOG_LOOKBACK_SECONDS", "300") or 300))
OPENSEARCH_LOG_BATCH_SIZE = max(1, min(int(os.getenv("OPENSEARCH_LOG_BATCH_SIZE", "100") or 100), 500))
OPENSEARCH_LOG_STATE_FILE = LANDING_PAD_INPUT_DIR.parent / "opensearch_log_ingestion_state.json"
OPENSEARCH_LOG_TRIGGER_TROUBLESHOOTING = str(
    os.getenv("OPENSEARCH_LOG_TRIGGER_TROUBLESHOOTING", "true")
).strip().lower() in {"1", "true", "yes", "on"}
OPENSEARCH_LOG_JIRA_ROUTING_ENABLED = str(
    os.getenv("OPENSEARCH_LOG_JIRA_ROUTING_ENABLED", "false")
).strip().lower() in {"1", "true", "yes", "on"}
PROMETHEUS_JIRA_ROUTING_ENABLED = str(
    os.getenv("PROMETHEUS_JIRA_ROUTING_ENABLED", "false")
).strip().lower() in {"1", "true", "yes", "on"}
EMAIL_JIRA_ROUTING_ENABLED = str(
    os.getenv("EMAIL_JIRA_ROUTING_ENABLED", "false")
).strip().lower() in {"1", "true", "yes", "on"}
JIRA_TRIGGER_TROUBLESHOOTING = str(
    os.getenv("JIRA_TRIGGER_TROUBLESHOOTING", "true")
).strip().lower() in {"1", "true", "yes", "on"}
JIRA_TRIGGER_ON_COMMENT = str(
    os.getenv("JIRA_TRIGGER_ON_COMMENT", "false")
).strip().lower() in {"1", "true", "yes", "on"}
JIRA_ADMISSION_STATE_FILE = LANDING_PAD_INPUT_DIR.parent / "jira_admission_state.json"
JIRA_RECURRENCE_WINDOW_SECONDS = max(
    30, int(os.getenv("JIRA_RECURRENCE_WINDOW_SECONDS", "300") or 300)
)
JIRA_COMMENT_COOLDOWN_SECONDS = max(
    0, int(os.getenv("JIRA_COMMENT_COOLDOWN_SECONDS", "900") or 900)
)
JIRA_MAX_NEW_ISSUES_PER_HOUR = max(
    1, int(os.getenv("JIRA_MAX_NEW_ISSUES_PER_HOUR", "5") or 5)
)
JIRA_LOG_MIN_OCCURRENCES = max(1, int(os.getenv("JIRA_LOG_MIN_OCCURRENCES", "3") or 3))
LOG_DISCOVERY_MAX_PER_MINUTE = max(
    1, int(os.getenv("LOG_DISCOVERY_MAX_PER_MINUTE", "4") or 4)
)
JIRA_PROMETHEUS_MIN_OCCURRENCES = max(
    1, int(os.getenv("JIRA_PROMETHEUS_MIN_OCCURRENCES", "1") or 1)
)
JIRA_EMAIL_MIN_OCCURRENCES = max(1, int(os.getenv("JIRA_EMAIL_MIN_OCCURRENCES", "1") or 1))
JIRA_ALLOWED_SEVERITIES = {
    item.strip().lower()
    for item in os.getenv("JIRA_ALLOWED_SEVERITIES", "warning,high,critical").split(",")
    if item.strip()
}
JIRA_POLLING_ENABLED = str(os.getenv("JIRA_POLLING_ENABLED", "true")).strip().lower() in {
    "1", "true", "yes", "on"
}
JIRA_POLL_INTERVAL_SECONDS = max(30.0, float(os.getenv("JIRA_POLL_INTERVAL_SECONDS", "60") or 60))
JIRA_POLL_BATCH_SIZE = max(1, min(int(os.getenv("JIRA_POLL_BATCH_SIZE", "25") or 25), 100))
_JIRA_SESSION_VERSIONS: set[str] = set()
NONACTIONABLE_ALERT_PUBLISH_ENABLED = str(
    os.getenv("NONACTIONABLE_ALERT_PUBLISH_ENABLED", "false")
).strip().lower() in {"1", "true", "yes", "on"}
JIRA_ADMISSION = JiraAdmissionState(
    JIRA_ADMISSION_STATE_FILE,
    recurrence_window_seconds=JIRA_RECURRENCE_WINDOW_SECONDS,
    comment_cooldown_seconds=JIRA_COMMENT_COOLDOWN_SECONDS,
    max_new_issues_per_hour=JIRA_MAX_NEW_ISSUES_PER_HOUR,
    min_occurrences={
        "logs": JIRA_LOG_MIN_OCCURRENCES,
        "prometheus": JIRA_PROMETHEUS_MIN_OCCURRENCES,
        "email": JIRA_EMAIL_MIN_OCCURRENCES,
    },
)
_PIPELINE_AUDIT_RECENT: dict[str, float] = {}


def _should_audit_pipeline(fingerprint: str, outcome: str, *, ttl_seconds: float = 300.0) -> bool:
    now = perf_counter()
    key = f"{fingerprint}:{outcome}"
    previous = _PIPELINE_AUDIT_RECENT.get(key)
    if previous is not None and now - previous < ttl_seconds:
        return False
    _PIPELINE_AUDIT_RECENT[key] = now
    if len(_PIPELINE_AUDIT_RECENT) > 10_000:
        cutoff = now - ttl_seconds
        for audit_key, seen_at in list(_PIPELINE_AUDIT_RECENT.items()):
            if seen_at < cutoff:
                _PIPELINE_AUDIT_RECENT.pop(audit_key, None)
    return True

# Email ingestion via IMAP polling — disabled unless explicitly enabled and
# fully configured, since it requires real mailbox credentials.
EMAIL_INGESTION_ENABLED = str(os.getenv("EMAIL_INGESTION_ENABLED", "false")).strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}
EMAIL_IMAP_HOST = str(os.getenv("EMAIL_IMAP_HOST", "") or "").strip()
EMAIL_IMAP_PORT = int(os.getenv("EMAIL_IMAP_PORT", "993") or 993)
EMAIL_IMAP_USER = str(os.getenv("EMAIL_IMAP_USER", "") or "").strip()
EMAIL_IMAP_PASSWORD = str(os.getenv("EMAIL_IMAP_PASSWORD", "") or "").strip()
EMAIL_IMAP_MAILBOX = str(os.getenv("EMAIL_IMAP_MAILBOX", "INBOX") or "INBOX").strip()
EMAIL_IMAP_USE_SSL = str(os.getenv("EMAIL_IMAP_USE_SSL", "true")).strip().lower() in {"1", "true", "yes", "on"}
EMAIL_IMAP_SEARCH_CRITERIA = str(os.getenv("EMAIL_IMAP_SEARCH_CRITERIA", "UNSEEN") or "UNSEEN").strip().upper()
EMAIL_IMAP_MARK_SEEN = str(os.getenv("EMAIL_IMAP_MARK_SEEN", "true")).strip().lower() in {"1", "true", "yes", "on"}
EMAIL_POLL_INTERVAL_SECONDS = max(15.0, float(os.getenv("EMAIL_POLL_INTERVAL_SECONDS", "60") or 60))
EMAIL_POLL_BATCH_SIZE = max(1, min(int(os.getenv("EMAIL_POLL_BATCH_SIZE", "25") or 25), 100))
EMAIL_DEFAULT_SERVICE = str(os.getenv("EMAIL_DEFAULT_SERVICE", "email-inbox") or "email-inbox").strip()
EMAIL_ALERT_SUBJECT_REGEX = str(
    os.getenv(
        "EMAIL_ALERT_SUBJECT_REGEX",
        r"(?i)\b(alert|incident|critical|warning|error|failure|failed|down|sev[1-5]|p[1-5])\b",
    )
)
_EMAIL_SESSION_MESSAGE_IDS: set[str] = set()

WORKER_FAILURE_COUNTS: dict[str, int] = {
    "incident_projection_worker": 0,
    "landing_pad_file_watcher": 0,
    "email_poll_worker": 0,
    "jira_poll_worker": 0,
    "landing_pad_archive_worker": 0,
    "log_poll_worker": 0,
    "opensearch_log_poll_worker": 0,
}
WORKER_FAILURE_THRESHOLD = max(1, int(os.getenv("WORKER_FAILURE_THRESHOLD", "5") or 5))
_ALLOWED_PROJECT_ENVIRONMENTS = {"dev", "staging", "prod"}
_ALLOWED_ONBOARDING_PROVIDERS = {"prometheus", "new_relic", "datadog"}
_ALLOWED_ACTIVE_PROVIDERS = {"prometheus", "new_relic", "datadog", "azure_service_bus"}
_ALLOWED_DEPLOYMENT_MODES = {"on_prem", "azure_cloud"}
ONBOARDING_RULE_EVENTS = "onboarding-rule-events"


def _date_partition_dir(base: Path, moment: datetime) -> Path:
    """Return the YYYY/MM/DD partition of `base` for the given UTC moment."""
    return base / f"{moment:%Y}" / f"{moment:%m}" / f"{moment:%d}"


def _recent_date_partition_dirs(base: Path, *, days: int) -> list[Path]:
    """Existing date partitions under `base` for the last `days` days, newest first.

    Bounds directory scans (dedup checks, recent-file listings) to a fixed
    number of small partitions instead of walking a growing multi-year archive.
    """
    now = datetime.now(timezone.utc)
    directories: list[Path] = []
    seen: set[Path] = set()
    for offset in range(days):
        candidate = _date_partition_dir(base, now - timedelta(days=offset))
        if candidate in seen:
            continue
        seen.add(candidate)
        if candidate.is_dir():
            directories.append(candidate)
    return directories


def _collect_partitioned_json_files(base: Path, *, lookback_days: int, max_files: int | None = None) -> list[Path]:
    files: list[Path] = []
    for directory in _recent_date_partition_dirs(base, days=lookback_days):
        candidates = (path for path in directory.glob("*.json"))
        if max_files is None:
            ordered = sorted(candidates, key=lambda item: item.name, reverse=True)
        else:
            # Archive filenames start with a fixed-width UTC timestamp. Select
            # by name without stat()ing every historical file, then perform
            # metadata reads only for the small bounded result set.
            ordered = heapq.nlargest(max_files, candidates, key=lambda item: item.name)
        files.extend(ordered)
        if max_files is not None and len(files) >= max_files:
            return heapq.nlargest(max_files, files, key=lambda item: item.name)
    if max_files is not None:
        return heapq.nlargest(max_files, files, key=lambda item: item.name)
    return files


def _persist_alert_to_landing_pad(
    mapped_payload: dict[str, Any],
    raw_alert: dict[str, Any],
    *,
    status: Literal["processed", "failed"],
    error: str | None = None,
) -> str | None:
    try:
        base_dir = LANDING_PAD_PROCESSED_DIR if status == "processed" else LANDING_PAD_FAILED_DIR
        now = datetime.now(timezone.utc)
        # Must match the YYYY/MM/DD scheme every reader scans
        # (_collect_partitioned_json_files / _recent_date_partition_dirs /
        # the dedup check / GET /landing-pad/recent) — a prior source-named
        # subfolder scheme here silently orphaned every write from all of
        # those readers.
        target_dir = _date_partition_dir(base_dir, now)
        target_dir.mkdir(parents=True, exist_ok=True)
        alert_name = slugify(str(mapped_payload.get("name") or "prometheus-alert"))
        labels = mapped_payload.get("labels", {}) if isinstance(mapped_payload.get("labels"), dict) else {}
        fingerprint = str(labels.get("alert_fingerprint") or "no-fingerprint").strip() or "no-fingerprint"
        safe_fingerprint = re.sub(r"[^a-zA-Z0-9_-]", "-", fingerprint)[:24]
        file_name = f"{now.strftime('%Y%m%dT%H%M%S%fZ')}_{alert_name}_{safe_fingerprint}.json"
        out_path = target_dir / file_name
        payload = {
            "received_at": now.isoformat(),
            "source": str(mapped_payload.get("source") or "prometheus-alertmanager"),
            "status": status,
            "error": error,
            "alert": mapped_payload,
            "raw": raw_alert,
        }
        out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        recent_event = {
            "file": file_name,
            "path": str(out_path),
            "modified_at": now.isoformat(),
            "received_at": now.isoformat(),
            "status": status,
            "error": error,
            "source": mapped_payload.get("source"),
            "name": mapped_payload.get("name"),
            "service": mapped_payload.get("service"),
            "environment": mapped_payload.get("environment"),
            "severity": mapped_payload.get("severity"),
            "description": mapped_payload.get("description"),
            "application": mapped_payload.get("application") or labels.get("application"),
            "project": mapped_payload.get("project") or labels.get("project"),
            "project_name": mapped_payload.get("project_name") or labels.get("project_name"),
            "labels": labels,
            "annotations": mapped_payload.get("annotations") or {},
            "origin_system": mapped_payload.get("origin_system") or labels.get("origin_system"),
            "ingestion_channel": mapped_payload.get("ingestion_channel") or labels.get("ingestion_channel"),
            "alert_status": labels.get("alert_status"),
            "alertname": labels.get("alertname"),
        }
        RECENT_INGESTION_EVENTS.appendleft(recent_event)
        source_key = str(recent_event.get("source") or recent_event.get("origin_system") or "unknown").strip().lower()
        RECENT_INGESTION_EVENTS_BY_SOURCE.setdefault(source_key or "unknown", deque(maxlen=50)).appendleft(recent_event)
        return str(out_path)
    except Exception:
        logger.exception("failed to persist alert to landing pad %s", status)
        return None


def _write_alert_to_landing_pad_input(mapped_payload: dict[str, Any], raw_alert: dict[str, Any]) -> Path:
    LANDING_PAD_INPUT_DIR.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc)
    alert_name = slugify(str(mapped_payload.get("name") or "prometheus-alert"))
    labels = mapped_payload.get("labels", {}) if isinstance(mapped_payload.get("labels"), dict) else {}
    fingerprint = str(labels.get("alert_fingerprint") or uuid.uuid4().hex).strip() or uuid.uuid4().hex
    safe_fingerprint = re.sub(r"[^a-zA-Z0-9_-]", "-", fingerprint)[:24]
    file_name = f"{now.strftime('%Y%m%dT%H%M%S%fZ')}_{alert_name}_{safe_fingerprint}_{uuid.uuid4().hex[:8]}.json"
    out_path = LANDING_PAD_INPUT_DIR / file_name
    tmp_path = out_path.with_suffix(".tmp")
    payload = {
        "received_at": now.isoformat(),
        "source": "prometheus-alertmanager",
        "status": "received",
        "alert": mapped_payload,
        "raw": raw_alert,
    }
    tmp_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    tmp_path.replace(out_path)
    return out_path


def _landing_pad_file_rows(source_dir: Path, limit: int, *, partitioned: bool = False) -> list[dict[str, Any]]:
    source_dir.mkdir(parents=True, exist_ok=True)
    # rglob (not glob) so this still finds files once processed/failed are
    # nested into <source>/<date>/ subfolders; harmless no-op for the flat
    # input/replayed/failed-input dirs this is also used for.
    if partitioned:
        candidates = _collect_partitioned_json_files(source_dir, lookback_days=LANDING_PAD_LISTING_LOOKBACK_DAYS)
    else:
        # Keep inbox scans cheap even when legacy folders contain very deep trees.
        candidates = [
            path
            for path in source_dir.rglob("*")
            if path.is_file() and path.suffix.lower() in SUPPORTED_SUFFIXES
        ]
    files = heapq.nlargest(limit, candidates, key=lambda path: path.stat().st_mtime)
    rows: list[dict[str, Any]] = []
    for path in files:
        entry: dict[str, Any] = {
            "file": path.name,
            "path": str(path),
            "modified_at": datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc).isoformat(),
            "size_bytes": int(path.stat().st_size),
        }
        try:
            if path.suffix.lower() == ".json" and path.stat().st_size <= LANDING_PAD_SCAN_MAX_PARSE_BYTES:
                payload = json.loads(path.read_text(encoding="utf-8"))
                alert = payload.get("alert") if isinstance(payload, dict) and isinstance(payload.get("alert"), dict) else payload
            elif path.suffix.lower() == ".json":
                payload = {"source": "json", "received_at": entry["modified_at"]}
                alert = {}
                entry["parse_error"] = (
                    f"skipped parse for file larger than LANDING_PAD_SCAN_MAX_PARSE_BYTES={LANDING_PAD_SCAN_MAX_PARSE_BYTES}"
                )
            else:
                loaded = load_landing_pad_file(path)
                alert = loaded[0][0] if loaded else {}
                payload = {"source": alert.get("source"), "received_at": entry["modified_at"]}
            labels = alert.get("labels", {}) if isinstance(alert, dict) and isinstance(alert.get("labels"), dict) else {}
            annotations = alert.get("annotations", {}) if isinstance(alert, dict) and isinstance(alert.get("annotations"), dict) else {}
            entry.update(
                {
                    "received_at": payload.get("received_at") if isinstance(payload, dict) else None,
                    "source": payload.get("source") if isinstance(payload, dict) else None,
                    "name": alert.get("name") if isinstance(alert, dict) else None,
                    "service": alert.get("service") if isinstance(alert, dict) else None,
                    "severity": alert.get("severity") if isinstance(alert, dict) else None,
                    "alert_status": labels.get("alert_status") or labels.get("status"),
                    "alertname": labels.get("alertname"),
                    "summary": annotations.get("summary"),
                }
            )
        except Exception as exc:
            entry["parse_error"] = str(exc)
        rows.append(entry)
    return rows


def _landing_pad_input_files(limit: int) -> list[Path]:
    LANDING_PAD_INPUT_DIR.mkdir(parents=True, exist_ok=True)
    for directory in LANDING_PAD_ADDITIONAL_INPUT_DIRS:
        directory.mkdir(parents=True, exist_ok=True)
    candidate_dirs = [LANDING_PAD_INPUT_DIR, *LANDING_PAD_ADDITIONAL_INPUT_DIRS]
    candidates: list[Path] = []
    scanned = 0
    for directory in candidate_dirs:
        for path in directory.glob("*"):
            if scanned >= LANDING_PAD_SCAN_MAX_FILES:
                break
            scanned += 1
            if path.is_file() and path.suffix.lower() in SUPPORTED_SUFFIXES:
                candidates.append(path)
        if scanned >= LANDING_PAD_SCAN_MAX_FILES:
            break
    return heapq.nsmallest(limit, candidates, key=lambda path: path.stat().st_mtime)


def _mapped_alerts_from_landing_pad_payload(payload: dict[str, Any]) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    if isinstance(payload.get("alert"), dict):
        raw_alert = payload.get("raw") if isinstance(payload.get("raw"), dict) else payload["alert"]
        return [(normalize_landing_pad_alert(payload["alert"], raw_alert), raw_alert)]

    alerts_payload = payload.get("alerts") if isinstance(payload.get("alerts"), list) else None
    if alerts_payload is None:
        return [(normalize_landing_pad_alert(payload, payload), payload)]

    common_labels = payload.get("commonLabels", {}) if isinstance(payload.get("commonLabels"), dict) else {}
    common_annotations = payload.get("commonAnnotations", {}) if isinstance(payload.get("commonAnnotations"), dict) else {}
    mapped: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for item in alerts_payload:
        if not isinstance(item, dict):
            continue
        status = str(item.get("status") or payload.get("status") or "firing").strip().lower()
        if status != "firing":
            continue
        labels = item.get("labels", {}) if isinstance(item.get("labels"), dict) else {}
        annotations = item.get("annotations", {}) if isinstance(item.get("annotations"), dict) else {}
        merged_labels = {**common_labels, **labels}
        merged_annotations = {**common_annotations, **annotations}
        mapped_payload = {
            "source": "prometheus-alertmanager",
            "name": str(merged_labels.get("alertname") or "prometheus-alert"),
            "service": str(
                merged_labels.get("service")
                or merged_labels.get("job")
                or merged_labels.get("instance")
                or "kaiops-platform"
            ),
            "environment": str(merged_labels.get("environment") or merged_labels.get("env") or "prod"),
            "severity": str(merged_labels.get("severity") or "warning").lower(),
            "description": str(
                merged_annotations.get("description")
                or merged_annotations.get("summary")
                or merged_labels.get("alertname")
                or "Prometheus alert"
            ),
            "labels": {
                **merged_labels,
                "alert_status": status,
                "alert_fingerprint": str(item.get("fingerprint") or ""),
            },
            "annotations": {
                **merged_annotations,
                "startsAt": str(item.get("startsAt") or ""),
                "endsAt": str(item.get("endsAt") or ""),
                "generatorURL": str(item.get("generatorURL") or ""),
            },
        }
        mapped.append((normalize_landing_pad_alert(mapped_payload, item), item))
    return mapped


def _archive_landing_pad_input_file(path: Path, target_dir: Path) -> str:
    partition_dir = _date_partition_dir(target_dir, datetime.now(timezone.utc))
    partition_dir.mkdir(parents=True, exist_ok=True)
    original_name = path.name.split("_", 1)[1] if path.parent.name == ".claiming" and "_" in path.name else path.name
    target_path = partition_dir / original_name
    if target_path.exists():
        original_path = Path(original_name)
        target_path = partition_dir / f"{original_path.stem}_{uuid.uuid4().hex[:8]}{original_path.suffix}"
    try:
        path.replace(target_path)
    except FileNotFoundError:
        # Another worker may have already claimed or archived the file.
        # Treat that as an idempotent archive outcome so the replay path
        # can complete without surfacing a hard failure to the gateway.
        return str(target_path)
    return str(target_path)


def _landing_pad_input_is_stale(path: Path, *, original_parent: Path) -> bool:
    if LANDING_PAD_FILE_WATCHER_STALE_HOURS <= 0:
        return False
    if original_parent.resolve() != LANDING_PAD_INPUT_DIR.resolve():
        return False
    modified_at = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
    age_seconds = (datetime.now(timezone.utc) - modified_at).total_seconds()
    return age_seconds > LANDING_PAD_FILE_WATCHER_STALE_HOURS * 3600


def _processed_landing_pad_match_exists(mapped_payload: dict[str, Any]) -> bool:
    labels = mapped_payload.get("labels", {}) if isinstance(mapped_payload.get("labels"), dict) else {}
    alert_name = slugify(str(mapped_payload.get("name") or "prometheus-alert"))
    fingerprint = str(labels.get("alert_fingerprint") or "no-fingerprint").strip() or "no-fingerprint"
    safe_fingerprint = re.sub(r"[^a-zA-Z0-9_-]", "-", fingerprint)[:24]
    pattern = f"*_{alert_name}_{safe_fingerprint}.json"
    # Dedup only needs to look back a bounded window of date partitions rather
    # than the entire historical archive, which otherwise grows without limit.
    return any(
        path.is_file()
        for directory in _recent_date_partition_dirs(LANDING_PAD_PROCESSED_DIR, days=LANDING_PAD_DEDUP_LOOKBACK_DAYS)
        for path in directory.glob(pattern)
    )


async def _claim_landing_pad_input_file(path: Path) -> tuple[Path, Path] | None:
    """Atomically move `path` into a sibling `.claiming/` dir so different
    files never contend and the same file is never processed twice.

    `Path.rename` is atomic at the syscall level for the source path on both
    POSIX and Windows NTFS: once one caller's rename succeeds, a concurrent
    renamer of the same source path fails immediately with FileNotFoundError.
    This fully replaces the need for a global lock across files. Claiming
    happens in a directory sibling to the file's own parent (not one shared
    global dir) since LANDING_PAD_ADDITIONAL_INPUT_DIRS may live on a
    different volume, and rename requires same-volume source/destination.
    """
    original_parent = path.parent
    claim_dir = original_parent / ".claiming"
    claim_dir.mkdir(parents=True, exist_ok=True)
    claimed_path = claim_dir / f"{uuid.uuid4().hex[:8]}_{path.name}"
    for attempt in range(3):
        try:
            path.rename(claimed_path)
            return claimed_path, original_parent
        except FileNotFoundError:
            return None
        except PermissionError:
            # Transient on Windows (Defender/indexer briefly holding a lock on
            # a just-written file); essentially never happens in Linux
            # containers. Give it a couple of short retries, then defer to
            # the next watcher tick rather than blocking this one.
            if attempt >= 2:
                return None
            await asyncio.sleep(0.05)
        except OSError:
            return None
    return None


def _recover_stale_claims() -> int:
    """Move `.claiming/` entries older than LANDING_PAD_CLAIM_STALE_MINUTES
    back into their parent input dir for retry.

    If a worker crashes after claiming a file but before archiving it, the
    claimed file is invisible to the watcher forever (it only lists the
    parent dir, never `.claiming/`). This sweep recovers those orphans.
    """
    recovered = 0
    now = datetime.now(timezone.utc)
    for directory in [LANDING_PAD_INPUT_DIR, *LANDING_PAD_ADDITIONAL_INPUT_DIRS]:
        claim_dir = directory / ".claiming"
        if not claim_dir.is_dir():
            continue
        for claimed_path in claim_dir.iterdir():
            if not claimed_path.is_file():
                continue
            try:
                modified_at = datetime.fromtimestamp(claimed_path.stat().st_mtime, tz=timezone.utc)
                age_seconds = (now - modified_at).total_seconds()
                if age_seconds <= LANDING_PAD_CLAIM_STALE_MINUTES * 60:
                    continue
                original_name = claimed_path.name.split("_", 1)[1] if "_" in claimed_path.name else claimed_path.name
                target_path = directory / original_name
                if target_path.exists():
                    target_path = directory / f"{uuid.uuid4().hex[:8]}_{original_name}"
                claimed_path.replace(target_path)
                recovered += 1
            except Exception:
                logger.exception("failed to recover stale landing-pad claim %s", claimed_path)
    return recovered


# Shared across every publish+persist operation (CSV/webhook rows, individual
# files, whole watcher-tick batches) so total in-flight ingestion work stays
# globally bounded regardless of how many files or rows are involved at once.
_LANDING_PAD_INGEST_SEMAPHORE = asyncio.Semaphore(LANDING_PAD_INGEST_CONCURRENCY)


async def _ingest_one_landing_pad_row(mapped_payload: dict[str, Any], raw_alert: dict[str, Any]) -> dict[str, Any]:
    """Publish+persist a single alert row, bounded by the shared ingest
    semaphore. Raises on failure after recording a `failed` audit entry for
    this row; callers gather with return_exceptions=True so one bad row never
    blocks its siblings."""
    async with _LANDING_PAD_INGEST_SEMAPHORE:
        try:
            alert = _build_alert_from_payload(mapped_payload)
            await _publish_ingested_alert(alert)
            landing_pad_file = _persist_alert_to_landing_pad(mapped_payload, raw_alert, status="processed")
            return {
                "alert_id": str(alert.id),
                "name": alert.name,
                "service": alert.service,
                "severity": alert.severity.value,
                "landing_pad_file": landing_pad_file,
            }
        except Exception as exc:
            _persist_alert_to_landing_pad(mapped_payload, raw_alert, status="failed", error=str(exc))
            raise


async def _process_landing_pad_input_file_unlocked(
    path: Path,
    *,
    original_parent: Path,
    skip_existing_processed: bool = True,
) -> dict[str, Any]:
    try:
        if _landing_pad_input_is_stale(path, original_parent=original_parent):
            archived_path = _archive_landing_pad_input_file(path, LANDING_PAD_INPUT_REPLAYED_DIR)
            return {
                "file": path.name,
                "status": "archived_stale",
                "archived_path": archived_path,
                "reason": f"input file older than {LANDING_PAD_FILE_WATCHER_STALE_HOURS:g} hours",
            }

        if path.suffix.lower() == ".json":
            payload = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(payload, dict):
                raise ValueError("landing pad input must be a JSON object")
            source_rows = load_landing_pad_file(path)
            mapped_alerts = (
                source_rows
                if source_rows and source_rows[0][0].get("source") == "email"
                else _mapped_alerts_from_landing_pad_payload(payload)
            )
        else:
            mapped_alerts = load_landing_pad_file(path)
        if not mapped_alerts:
            raise ValueError("landing pad input did not contain a firing alert")

        if skip_existing_processed and all(_processed_landing_pad_match_exists(mapped_payload) for mapped_payload, _ in mapped_alerts):
            archived_path = _archive_landing_pad_input_file(path, LANDING_PAD_INPUT_REPLAYED_DIR)
            return {
                "file": path.name,
                "status": "skipped_duplicate",
                "archived_path": archived_path,
                "reason": "matching processed landing-pad audit already exists",
            }

        results = await asyncio.gather(
            *(_ingest_one_landing_pad_row(mapped_payload, raw_alert) for mapped_payload, raw_alert in mapped_alerts),
            return_exceptions=True,
        )
        ingested_rows = [row for row in results if not isinstance(row, Exception)]
        row_failures = [
            {"index": index, "error": str(row)} for index, row in enumerate(results) if isinstance(row, Exception)
        ]

        if not row_failures:
            status = "processed"
            archive_dir = LANDING_PAD_INPUT_REPLAYED_DIR
        elif ingested_rows:
            status = "processed_partial"
            archive_dir = LANDING_PAD_INPUT_REPLAYED_DIR
        else:
            status = "failed_all_rows"
            archive_dir = LANDING_PAD_INPUT_FAILED_DIR

        archived_path = _archive_landing_pad_input_file(path, archive_dir)
        return {
            "file": path.name,
            "status": status,
            "archived_path": archived_path,
            "alerts": ingested_rows,
            "row_count": len(mapped_alerts),
            "row_failures": row_failures,
        }
    except Exception as exc:
        logger.exception("failed to replay landing pad input file %s", path)
        try:
            archived_path = _archive_landing_pad_input_file(path, LANDING_PAD_INPUT_FAILED_DIR)
        except Exception:
            archived_path = str(path)
        return {"file": path.name, "status": "failed", "error": str(exc), "archived_path": archived_path}


async def _process_landing_pad_input_file(
    path: Path,
    *,
    skip_existing_processed: bool = True,
) -> dict[str, Any]:
    # Alertmanager requests can process a newly written file directly while
    # the optional watcher independently scans the same directory. Claiming
    # the file (an atomic rename into a sibling .claiming/ dir) before doing
    # any work means the two can never race on the same file, and different
    # files are never serialized against each other.
    claimed = await _claim_landing_pad_input_file(path)
    if claimed is None:
        return {
            "file": path.name,
            "status": "already_processed",
            "archived_path": str(path),
            "reason": "landing-pad input was claimed by another processor",
        }
    claimed_path, original_parent = claimed
    return await _process_landing_pad_input_file_unlocked(
        claimed_path,
        original_parent=original_parent,
        skip_existing_processed=skip_existing_processed,
    )


class OnboardingProviderStatus(BaseModel):
    ok: bool = False
    message: str = ""


class OnboardingProject(BaseModel):
    name: str
    owner_team: str
    environment: str
    region: str

    @model_validator(mode="after")
    def _validate_project(self) -> "OnboardingProject":
        self.name = str(self.name or "").strip()
        self.owner_team = str(self.owner_team or "").strip()
        self.environment = str(self.environment or "").strip().lower()
        self.region = str(self.region or "").strip()
        if not self.name:
            raise ValueError("project.name is required")
        if not self.owner_team:
            raise ValueError("project.owner_team is required")
        if self.environment not in _ALLOWED_PROJECT_ENVIRONMENTS:
            raise ValueError("project.environment must be one of dev, staging, prod")
        if not self.region:
            raise ValueError("project.region is required")
        return self


class OnboardingConnectivityPayload(BaseModel):
    project: OnboardingProject
    deployment_mode: str = "on_prem"
    prometheus_url: str = ""
    new_relic_url: str = ""
    datadog_url: str = ""
    azure_subscription_id: str = ""
    azure_resource_group: str = ""
    azure_service_bus_namespace: str = ""
    azure_service_bus_topic: str = ""
    azure_service_bus_subscription: str = ""
    azure_content_safety_enabled: bool = False
    azure_content_safety_endpoint: str = ""
    user_assignments: dict[str, list[str]] = Field(default_factory=dict)
    provider_statuses: dict[str, OnboardingProviderStatus] = Field(default_factory=dict)
    active_provider: str | None = None
    test_status: bool | None = None
    test_message: str | None = None
    tested_at: str | None = None
    updated_at: str | None = None

    @model_validator(mode="before")
    @classmethod
    def _normalize_raw_payload(cls, raw: Any) -> Any:
        if not isinstance(raw, dict):
            raise ValueError("Invalid onboarding payload")

        normalized = dict(raw)

        statuses_raw = normalized.get("provider_statuses", {})
        if statuses_raw is None:
            statuses_raw = {}
        if not isinstance(statuses_raw, dict):
            raise ValueError("provider_statuses must be an object")
        provider_statuses: dict[str, Any] = {}
        for provider_name, status in statuses_raw.items():
            provider = str(provider_name or "").strip().lower().replace(" ", "_")
            if provider not in _ALLOWED_ONBOARDING_PROVIDERS:
                continue
            if not isinstance(status, dict):
                raise ValueError(f"provider_statuses.{provider} must be an object")
            provider_statuses[provider] = {
                "ok": bool(status.get("ok", False)),
                "message": str(status.get("message", "")).strip(),
            }
        normalized["provider_statuses"] = provider_statuses

        assignments_raw = normalized.get("user_assignments", {})
        if assignments_raw is None:
            assignments_raw = {}
        if not isinstance(assignments_raw, dict):
            raise ValueError("user_assignments must be an object")
        user_assignments: dict[str, list[str]] = {}
        for username, projects in assignments_raw.items():
            normalized_user = str(username or "").strip()
            if not normalized_user:
                continue
            if not isinstance(projects, list):
                raise ValueError(f"user_assignments.{normalized_user} must be a list")
            normalized_projects = [str(item or "").strip() for item in projects if str(item or "").strip()]
            user_assignments[normalized_user] = list(dict.fromkeys(normalized_projects))
        normalized["user_assignments"] = user_assignments

        deployment_mode = str(normalized.get("deployment_mode", "on_prem")).strip().lower().replace("-", "_")
        normalized["deployment_mode"] = deployment_mode or "on_prem"

        normalized["azure_subscription_id"] = str(normalized.get("azure_subscription_id", "")).strip()
        normalized["azure_resource_group"] = str(normalized.get("azure_resource_group", "")).strip()
        normalized["azure_service_bus_namespace"] = str(normalized.get("azure_service_bus_namespace", "")).strip()
        normalized["azure_service_bus_topic"] = str(normalized.get("azure_service_bus_topic", "")).strip()
        normalized["azure_service_bus_subscription"] = str(normalized.get("azure_service_bus_subscription", "")).strip()
        normalized["azure_content_safety_enabled"] = bool(normalized.get("azure_content_safety_enabled", False))
        normalized["azure_content_safety_endpoint"] = str(normalized.get("azure_content_safety_endpoint", "")).strip()

        active_provider = str(normalized.get("active_provider", "")).strip().lower().replace(" ", "_")
        normalized["active_provider"] = active_provider or None
        return normalized

    @staticmethod
    def _normalize_endpoint(value: str, field_name: str) -> str:
        endpoint = str(value or "").strip()
        if not endpoint:
            return ""
        parsed = urlparse(endpoint)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError(f"{field_name} must be a valid http(s) URL")
        return endpoint

    @model_validator(mode="after")
    def _validate_payload(self) -> "OnboardingConnectivityPayload":
        self.deployment_mode = str(self.deployment_mode or "on_prem").strip().lower().replace("-", "_")
        if self.deployment_mode not in _ALLOWED_DEPLOYMENT_MODES:
            raise ValueError("deployment_mode must be one of on_prem, azure_cloud")

        self.prometheus_url = self._normalize_endpoint(self.prometheus_url, "prometheus_url")
        self.new_relic_url = self._normalize_endpoint(self.new_relic_url, "new_relic_url")
        self.datadog_url = self._normalize_endpoint(self.datadog_url, "datadog_url")
        self.azure_subscription_id = str(self.azure_subscription_id or "").strip()
        self.azure_resource_group = str(self.azure_resource_group or "").strip()
        self.azure_service_bus_namespace = str(self.azure_service_bus_namespace or "").strip()
        self.azure_service_bus_topic = str(self.azure_service_bus_topic or "").strip()
        self.azure_service_bus_subscription = str(self.azure_service_bus_subscription or "").strip()
        self.azure_content_safety_endpoint = str(self.azure_content_safety_endpoint or "").strip()

        if self.deployment_mode == "azure_cloud":
            if not self.azure_subscription_id:
                raise ValueError("azure_subscription_id is required for azure_cloud mode")
            if not self.azure_service_bus_namespace:
                raise ValueError("azure_service_bus_namespace is required for azure_cloud mode")
            if not self.azure_service_bus_topic:
                raise ValueError("azure_service_bus_topic is required for azure_cloud mode")
            if not self.azure_service_bus_subscription:
                raise ValueError("azure_service_bus_subscription is required for azure_cloud mode")

        if self.active_provider and self.active_provider not in _ALLOWED_ACTIVE_PROVIDERS:
            raise ValueError("active_provider must be one of prometheus, new_relic, datadog, azure_service_bus")
        self.test_message = str(self.test_message or "").strip() or None
        self.tested_at = str(self.tested_at or "").strip() or None
        self.updated_at = str(self.updated_at or "").strip() or None
        return self


class OnboardingConnectivitySnapshot(BaseModel):
    project: dict[str, Any] = Field(default_factory=dict)
    deployment_mode: str = "on_prem"
    prometheus_url: str = ""
    new_relic_url: str = ""
    datadog_url: str = ""
    azure_subscription_id: str = ""
    azure_resource_group: str = ""
    azure_service_bus_namespace: str = ""
    azure_service_bus_topic: str = ""
    azure_service_bus_subscription: str = ""
    azure_content_safety_enabled: bool = False
    azure_content_safety_endpoint: str = ""
    user_assignments: dict[str, list[str]] = Field(default_factory=dict)
    updated_at: str | None = None


class OnboardingConnectivityResponse(BaseModel):
    connectivity: OnboardingConnectivitySnapshot


class OnboardingStateResponse(BaseModel):
    rows: list[dict[str, Any]] = Field(default_factory=list)


class OnboardingCompletePayload(BaseModel):
    connectivity: OnboardingConnectivityPayload
    project_mode: Literal["new", "existing"] = "existing"
    onboarding_path: Literal["existing_monitoring", "setup_monitoring"] = "existing_monitoring"
    start_rules_onboarding: bool = False
    plain_language_requirements: list[str] = Field(default_factory=list)
    source_documents: list[dict[str, Any]] = Field(default_factory=list)
    selected_monitoring_tool: str | None = None
    generate_documents: bool = True
    include_smoke_test_alert: bool = False

    @model_validator(mode="before")
    @classmethod
    def _normalize_raw_payload(cls, raw: Any) -> Any:
        if not isinstance(raw, dict):
            raise ValueError("Invalid onboarding completion payload")
        normalized = dict(raw)
        requirements_raw = normalized.get("plain_language_requirements", [])
        if isinstance(requirements_raw, str):
            requirements = [line.strip() for line in requirements_raw.splitlines() if line.strip()]
        elif isinstance(requirements_raw, list):
            requirements = [str(item or "").strip() for item in requirements_raw if str(item or "").strip()]
        else:
            raise ValueError("plain_language_requirements must be a list or newline-delimited string")
        normalized["plain_language_requirements"] = requirements
        source_documents_raw = normalized.get("source_documents", [])
        if isinstance(source_documents_raw, list):
            normalized["source_documents"] = [item for item in source_documents_raw if isinstance(item, dict)]
        else:
            raise ValueError("source_documents must be a list of document metadata objects")
        selected_tool = str(normalized.get("selected_monitoring_tool") or "").strip().lower().replace(" ", "_")
        normalized["selected_monitoring_tool"] = selected_tool or None
        onboarding_path = str(normalized.get("onboarding_path") or "existing_monitoring").strip().lower()
        normalized["onboarding_path"] = onboarding_path or "existing_monitoring"
        normalized["generate_documents"] = bool(normalized.get("generate_documents", True))
        normalized["include_smoke_test_alert"] = bool(normalized.get("include_smoke_test_alert", False))
        return normalized

    @model_validator(mode="after")
    def _validate_payload(self) -> "OnboardingCompletePayload":
        if self.selected_monitoring_tool and self.selected_monitoring_tool not in _ALLOWED_ONBOARDING_PROVIDERS:
            raise ValueError("selected_monitoring_tool must be one of prometheus, new_relic, datadog")
        if self.onboarding_path == "setup_monitoring" and not self.plain_language_requirements:
            raise ValueError("plain_language_requirements are required when start_rules_onboarding is true")
        return self


OnboardingProject.model_rebuild()
OnboardingConnectivityPayload.model_rebuild()
OnboardingConnectivitySnapshot.model_rebuild()
OnboardingConnectivityResponse.model_rebuild()
OnboardingStateResponse.model_rebuild()
OnboardingCompletePayload.model_rebuild()


def _json_safe(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_safe(item) for item in value]
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, datetime):
        return value.isoformat()
    return value


def _record_worker_failure(worker_name: str, exc: Exception) -> None:
    current = int(WORKER_FAILURE_COUNTS.get(worker_name, 0) or 0)
    WORKER_FAILURE_COUNTS[worker_name] = current + 1
    logger.exception(
        "background_worker_failed",
        extra={"worker": worker_name, "failure_count": WORKER_FAILURE_COUNTS[worker_name], "error": str(exc)},
    )


def _record_worker_success(worker_name: str) -> None:
    WORKER_FAILURE_COUNTS[worker_name] = 0


async def _load_pending_workflow_from_db(incident_id: str) -> dict[str, Any] | None:
    session_factory = getattr(app.state, "session_factory", None)
    if not settings.database_enabled or session_factory is None:
        return PENDING_WORKFLOWS.get(str(incident_id))
    async with session_factory() as session:
        repo = IncidentRepository(session)
        return await repo.get_pending_workflow(incident_id)


async def _save_pending_workflow_to_db(
    *, incident_id: str, recommendation_id: str, flow_id: str, trace_id: str | None, payload: dict[str, Any]
) -> None:
    session_factory = getattr(app.state, "session_factory", None)
    if not settings.database_enabled or session_factory is None:
        PENDING_WORKFLOWS[str(incident_id)] = _json_safe(payload)
        return
    async with session_factory() as session:
        repo = IncidentRepository(session)
        await repo.save_pending_workflow(
            incident_id=incident_id,
            recommendation_id=recommendation_id,
            flow_id=flow_id,
            trace_id=trace_id,
            payload=_json_safe(payload),
        )
        await session.commit()


async def _mark_pending_workflow_completed_in_db(incident_id: str, final_payload: dict[str, Any]) -> None:
    session_factory = getattr(app.state, "session_factory", None)
    if not settings.database_enabled or session_factory is None:
        PENDING_WORKFLOWS.pop(str(incident_id), None)
        return
    async with session_factory() as session:
        repo = IncidentRepository(session)
        await repo.mark_pending_workflow_completed(incident_id, _json_safe(final_payload))
        await session.commit()


def _build_local_metadata_envelope(
    *,
    event_type: str,
    incident: dict[str, Any],
    alert: dict[str, Any],
    decision: dict[str, Any],
    status: str,
    payload: dict[str, Any],
    confidence: float | None = None,
    model_provider: str | None = None,
    model_name: str | None = None,
    fallback_reason: str | None = None,
    transport_provider: str | None = None,
) -> dict[str, Any]:
    incident_id = str(incident.get("id") or "").strip()
    alert_id = str(alert.get("id") or "").strip()
    trace_id = str(incident.get("trace_id") or alert.get("trace_id") or "").strip()
    service = str(incident.get("service") or alert.get("service") or "unknown").strip() or "unknown"
    environment = str(incident.get("environment") or alert.get("environment") or "prod").strip() or "prod"
    severity = str(incident.get("severity") or alert.get("severity") or "warning").strip().lower()
    correlation_id = str(alert.get("correlation_id") or "").strip() or None
    provider = str(transport_provider or decision.get("message_bus_provider") or "rabbitmq").strip().lower() or "rabbitmq"

    return build_event_envelope(
        event_type=event_type,
        identity={
            "incident_id": incident_id,
            "alert_id": alert_id or None,
            "trace_id": trace_id,
            "correlation_id": correlation_id,
            "causation_id": None,
            "parent_event_id": None,
        },
        scope={
            "tenant_id": "default",
            "service": service,
            "environment": environment,
            "region": None,
            "team": None,
        },
        state={
            "severity": severity,
            "status": str(status or "unknown").strip().lower() or "unknown",
            "owner": None,
        },
        policy={
            "risk_tier": str(decision.get("risk_tier") or "unknown").strip().lower(),
            "execution_mode": str(decision.get("execution_mode") or "unknown").strip().lower(),
            "requires_approval": bool(decision.get("requires_approval", False)),
            "policy_version": str(decision.get("policy_version") or "policy-v1"),
            "policy_reason": str(decision.get("policy_reason") or ""),
        },
        ai={
            "confidence": confidence,
            "model_provider": model_provider,
            "model_name": model_name,
            "fallback_reason": fallback_reason,
        },
        transport={
            "provider": provider,
            "channel": "local-workflow",
            "partition": None,
            "offset": None,
            "delivery_tag": None,
        },
        idempotency={
            "idempotency_key": f"{event_type}:{incident_id}",
            "fingerprint": correlation_id,
        },
        payload=payload,
    )

INCIDENT_PROJECTION_WORKER_ENABLED = str(
    os.getenv("INCIDENT_PROJECTION_WORKER_ENABLED", "true")
).strip().lower() in {"1", "true", "yes", "on"}
INCIDENT_PROJECTION_INTERVAL_SECONDS = max(
    15.0,
    float(os.getenv("INCIDENT_PROJECTION_INTERVAL_SECONDS", "60") or 60),
)
INCIDENT_PROJECTION_BATCH_SIZE = max(
    10,
    min(int(os.getenv("INCIDENT_PROJECTION_BATCH_SIZE", "100") or 100), 500),
)
async def _incident_projection_worker() -> None:
    stop_event = app.state.monitoring_adapter_stop_event
    while not stop_event.is_set():
        # This is a reconciliation/repair loop, not the primary event path.
        # Delay it so startup and interactive reads receive capacity first.
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=float(INCIDENT_PROJECTION_INTERVAL_SECONDS))
            continue
        except asyncio.TimeoutError:
            pass

        try:
            if settings.database_enabled and getattr(app.state, "session_factory", None) is not None:
                async with app.state.session_factory() as session:
                    repo = IncidentRepository(session)
                    await repo.project_recent_incident_events(limit=INCIDENT_PROJECTION_BATCH_SIZE)
                    await session.commit()
            _record_worker_success("incident_projection_worker")
        except Exception as exc:
            _record_worker_failure("incident_projection_worker", exc)


async def _landing_pad_file_watcher() -> None:
    stop_event = app.state.monitoring_adapter_stop_event
    while not stop_event.is_set():
        try:
            _recover_stale_claims()
            paths = _landing_pad_input_files(LANDING_PAD_FILE_WATCHER_BATCH_SIZE)
            await asyncio.gather(*(_process_landing_pad_input_file(path) for path in paths), return_exceptions=True)
            _record_worker_success("landing_pad_file_watcher")
        except Exception as exc:
            _record_worker_failure("landing_pad_file_watcher", exc)

        try:
            await asyncio.wait_for(stop_event.wait(), timeout=float(LANDING_PAD_FILE_WATCHER_INTERVAL_SECONDS))
        except asyncio.TimeoutError:
            continue


def _sweep_landing_pad_archive_once() -> dict[str, int]:
    """Move processed/failed landing-pad files older than
    LANDING_PAD_ARCHIVE_AFTER_DAYS into the mirrored path under
    archive/<source>/<date>/, preserving the source/date layout. Returns a
    counter dict so callers (worker loop or the manual trigger endpoint) can
    report how much was moved.
    """
    cutoff = datetime.now(timezone.utc).timestamp() - (LANDING_PAD_ARCHIVE_AFTER_DAYS * 86400)
    moved = 0
    errors = 0
    for base_dir in (LANDING_PAD_PROCESSED_DIR, LANDING_PAD_FAILED_DIR):
        if not base_dir.exists():
            continue
        for path in base_dir.rglob("*.json"):
            if not path.is_file():
                continue
            try:
                if path.stat().st_mtime >= cutoff:
                    continue
                relative = path.relative_to(base_dir)
                target_path = LANDING_PAD_ARCHIVE_DIR / base_dir.name / relative
                target_path.parent.mkdir(parents=True, exist_ok=True)
                if target_path.exists():
                    target_path = target_path.with_name(f"{target_path.stem}_{uuid.uuid4().hex[:8]}{target_path.suffix}")
                path.replace(target_path)
                moved += 1
            except Exception:
                logger.exception("failed to archive landing pad file %s", path)
                errors += 1
    return {"moved": moved, "errors": errors}


async def _landing_pad_archive_worker() -> None:
    stop_event = app.state.monitoring_adapter_stop_event
    while not stop_event.is_set():
        try:
            result = _sweep_landing_pad_archive_once()
            if result["moved"]:
                logger.info("landing pad archive sweep moved %s file(s)", result["moved"])
            _record_worker_success("landing_pad_archive_worker")
        except Exception as exc:
            _record_worker_failure("landing_pad_archive_worker", exc)

        try:
            await asyncio.wait_for(stop_event.wait(), timeout=float(LANDING_PAD_ARCHIVE_INTERVAL_SECONDS))
        except asyncio.TimeoutError:
            continue


async def _process_polled_email(message: dict[str, Any]) -> None:
    mapped_payload = email_to_alert_payload(message, default_service=EMAIL_DEFAULT_SERVICE)

    if CENTRALIZED_JIRA_ROUTING_ENABLED or EMAIL_JIRA_ROUTING_ENABLED:
        try:
            alert = _build_alert_from_payload(mapped_payload)
            await _publish_ingested_alert(alert)
            mapped_payload["labels"] = dict(alert.labels)
            _persist_alert_to_landing_pad(mapped_payload, message, status="processed")
        except Exception as exc:
            logger.exception("failed to expose polled email %s in live stream", message.get("message_id"))
            _persist_alert_to_landing_pad(mapped_payload, message, status="failed", error=str(exc))
            return
        # raw-alerts is the single automatic path into Discovery and Jira.
        # Publishing again through the legacy direct-routing helper would
        # create two incident candidates for the same message.
        return
        # Same reasoning as the Alertmanager path: email no longer
        # shortcuts into the landing pad — routes through centralized
        # dedup and Jira create-or-update instead.
        try:
            await _route_and_trigger_investigation(mapped_payload, message, source="email")
        except Exception:
            logger.exception("failed to route polled email %s through jira", message.get("message_id"))
        return

    try:
        alert = _build_alert_from_payload(mapped_payload)
        await _publish_ingested_alert(alert)
    except Exception as exc:
        logger.exception("failed to ingest polled email %s", message.get("message_id"))
        _persist_alert_to_landing_pad(mapped_payload, message, status="failed", error=str(exc))
        return
    mapped_payload["labels"] = dict(alert.labels)
    _persist_alert_to_landing_pad(mapped_payload, message, status="processed")


async def _email_poll_worker() -> None:
    stop_event = app.state.monitoring_adapter_stop_event
    imap_config = ImapConfig(
        host=EMAIL_IMAP_HOST,
        port=EMAIL_IMAP_PORT,
        username=EMAIL_IMAP_USER,
        password=EMAIL_IMAP_PASSWORD,
        mailbox=EMAIL_IMAP_MAILBOX,
        use_ssl=EMAIL_IMAP_USE_SSL,
        mark_seen=EMAIL_IMAP_MARK_SEEN,
        search_criterion=EMAIL_IMAP_SEARCH_CRITERIA,
        subject_pattern=EMAIL_ALERT_SUBJECT_REGEX,
    )
    while not stop_event.is_set():
        try:
            # imaplib is blocking/sync — run it off the event loop thread.
            messages = await asyncio.to_thread(fetch_unseen_emails, imap_config, limit=EMAIL_POLL_BATCH_SIZE)
            for message in messages:
                message_id = str(message.get("message_id") or "").strip()
                if message_id and message_id in _EMAIL_SESSION_MESSAGE_IDS:
                    continue
                await _process_polled_email(message)
                if message_id:
                    _EMAIL_SESSION_MESSAGE_IDS.add(message_id)
            logger.info("email_poll_complete mailbox=%s fetched=%s", EMAIL_IMAP_MAILBOX, len(messages))
            _record_worker_success("email_poll_worker")
        except Exception as exc:
            _record_worker_failure("email_poll_worker", exc)

        try:
            await asyncio.wait_for(stop_event.wait(), timeout=float(EMAIL_POLL_INTERVAL_SECONDS))
        except asyncio.TimeoutError:
            continue


async def _process_log_line(record: dict[str, Any]) -> None:
    mapped_payload = log_line_to_alert_payload(record, default_service=LOG_DEFAULT_SERVICE)
    if mapped_payload is None:
        return  # not a failure line — no alert, no Jira ticket
    # Live stream persistence and Jira qualification are independent. Every
    # normalized error remains auditable even when it is not Jira-actionable.
    _persist_alert_to_landing_pad(mapped_payload, record, status="processed")
    jira_routing_enabled = CENTRALIZED_JIRA_ROUTING_ENABLED or (
        OPENSEARCH_LOG_JIRA_ROUTING_ENABLED and str(record.get("source_path") or "").startswith("opensearch://")
    )
    if jira_routing_enabled:
        try:
            await _route_and_trigger_investigation(
                mapped_payload,
                record,
                source="logs",
                trigger_enabled=OPENSEARCH_LOG_TRIGGER_TROUBLESHOOTING,
                persist_evidence=False,
            )
        except Exception:
            logger.exception("failed to route log alert through jira: %s", record.get("source_path"))
        return
    if not NONACTIONABLE_ALERT_PUBLISH_ENABLED:
        logger.info(
            "jira_pipeline stage=classification outcome=live_stream_only source=logs log_source=%s "
            "reason=jira routing disabled",
            record.get("source_path"),
        )
        return
    try:
        alert = _build_alert_from_payload(mapped_payload)
        await _publish_ingested_alert(alert)
    except Exception as exc:
        logger.exception("failed to ingest log alert from %s", record.get("source_path"))
        _persist_alert_to_landing_pad(mapped_payload, record, status="failed", error=str(exc))
        return
    mapped_payload["labels"] = dict(alert.labels)


async def _log_poll_worker() -> None:
    stop_event = app.state.monitoring_adapter_stop_event
    state = LogWatchState(LOG_INGESTION_STATE_FILE)
    while not stop_event.is_set():
        try:
            # File I/O is blocking — run it off the event loop thread.
            records = await asyncio.to_thread(fetch_new_log_lines, LOG_WATCH_PATHS, state)
            for record in records:
                await _process_log_line(record)
            _record_worker_success("log_poll_worker")
        except Exception as exc:
            _record_worker_failure("log_poll_worker", exc)

        try:
            await asyncio.wait_for(stop_event.wait(), timeout=float(LOG_POLL_INTERVAL_SECONDS))
        except asyncio.TimeoutError:
            continue


async def _opensearch_log_poll_worker() -> None:
    stop_event = app.state.monitoring_adapter_stop_event
    state = OpenSearchLogState(OPENSEARCH_LOG_STATE_FILE)
    while not stop_event.is_set():
        try:
            records = await fetch_opensearch_error_logs(
                endpoint=OPENSEARCH_LOG_URL,
                index_pattern=OPENSEARCH_LOG_INDEX,
                state=state,
                lookback_seconds=OPENSEARCH_LOG_LOOKBACK_SECONDS,
                batch_size=OPENSEARCH_LOG_BATCH_SIZE,
                docker_api_endpoint=OPENSEARCH_LOG_DOCKER_API_URL,
            )
            for record in records:
                await _process_log_line(record)
            _record_worker_success("opensearch_log_poll_worker")
        except Exception as exc:
            _record_worker_failure("opensearch_log_poll_worker", exc)

        try:
            await asyncio.wait_for(stop_event.wait(), timeout=float(OPENSEARCH_LOG_POLL_INTERVAL_SECONDS))
        except asyncio.TimeoutError:
            continue


async def _jira_poll_worker() -> None:
    """Project recent Jira tickets without requiring a publicly reachable webhook."""
    stop_event = app.state.monitoring_adapter_stop_event
    client = _jira_api_client()
    if client is None:
        logger.warning("jira_poll_disabled reason=api credentials are incomplete")
        return
    while not stop_event.is_set():
        try:
            issues = await client.list_recent_issues(limit=JIRA_POLL_BATCH_SIZE)
            ingested = 0
            for issue in reversed(issues):
                fields = issue.get("fields") if isinstance(issue.get("fields"), dict) else {}
                version = f"{issue.get('key')}:{fields.get('updated') or fields.get('created') or ''}"
                if version in _JIRA_SESSION_VERSIONS:
                    continue
                payload = {"webhookEvent": "jira:poll", "issue": issue, "event_origin": "jira"}
                mapped_payload, _ = _jira_payload_to_alert_payload(payload)
                alert = _build_alert_from_payload(mapped_payload)
                labels = fields.get("labels") if isinstance(fields.get("labels"), list) else []
                managed = "managed_by_kaiops" in labels or "kaiops-auto-created" in labels or any(
                    str(label).startswith(("kaiops_incident_", "kaiops-candidate-")) for label in labels
                )
                if managed and settings.database_enabled and getattr(app.state, "session_factory", None) is not None:
                    async with app.state.session_factory() as session:
                        await IncidentRepository(session).save_alert(alert)
                        await session.commit()
                    RECENT_ALERTS.appendleft(alert.model_dump(mode="json"))
                else:
                    await _publish_ingested_alert(alert)
                mapped_payload["labels"] = dict(alert.labels)
                _persist_alert_to_landing_pad(mapped_payload, payload, status="processed")
                _JIRA_SESSION_VERSIONS.add(version)
                ingested += 1
            logger.info("jira_poll_complete project=%s fetched=%s ingested=%s", JIRA_PROJECT_KEY, len(issues), ingested)
            _record_worker_success("jira_poll_worker")
        except Exception as exc:
            _record_worker_failure("jira_poll_worker", exc)
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=float(JIRA_POLL_INTERVAL_SECONDS))
        except asyncio.TimeoutError:
            continue


async def _on_startup(_: Any) -> None:
    app.state.monitoring_adapter_stop_event = asyncio.Event()
    if INCIDENT_PROJECTION_WORKER_ENABLED:
        app.state.incident_projection_task = asyncio.create_task(_incident_projection_worker())
    if LANDING_PAD_FILE_WATCHER_ENABLED:
        app.state.landing_pad_file_watcher_task = asyncio.create_task(_landing_pad_file_watcher())
    if LANDING_PAD_ARCHIVE_ENABLED:
        app.state.landing_pad_archive_task = asyncio.create_task(_landing_pad_archive_worker())
    if EMAIL_INGESTION_ENABLED:
        if EMAIL_IMAP_HOST and EMAIL_IMAP_USER and EMAIL_IMAP_PASSWORD:
            app.state.email_poll_task = asyncio.create_task(_email_poll_worker())
        else:
            logger.warning(
                "EMAIL_INGESTION_ENABLED is true but EMAIL_IMAP_HOST/EMAIL_IMAP_USER/EMAIL_IMAP_PASSWORD "
                "are not fully configured — email polling will not start."
            )
    if JIRA_POLLING_ENABLED:
        if JIRA_API_BASE_URL and JIRA_API_EMAIL and JIRA_API_TOKEN and JIRA_PROJECT_KEY:
            app.state.jira_poll_task = asyncio.create_task(_jira_poll_worker())
        else:
            logger.warning("JIRA_POLLING_ENABLED is true but Jira API credentials are incomplete")
    if LOG_INGESTION_ENABLED:
        if LOG_WATCH_PATHS:
            app.state.log_poll_task = asyncio.create_task(_log_poll_worker())
        else:
            logger.warning("LOG_INGESTION_ENABLED is true but LOG_WATCH_PATHS is empty — log polling will not start.")
    if OPENSEARCH_LOG_INGESTION_ENABLED:
        if OPENSEARCH_LOG_URL:
            app.state.opensearch_log_poll_task = asyncio.create_task(_opensearch_log_poll_worker())
        else:
            logger.warning(
                "OPENSEARCH_LOG_INGESTION_ENABLED is true but OPENSEARCH_LOG_URL is empty; polling will not start."
            )


async def _on_shutdown(_: Any) -> None:
    stop_event = getattr(app.state, "monitoring_adapter_stop_event", None)
    if stop_event is not None:
        stop_event.set()
    projection_task = getattr(app.state, "incident_projection_task", None)
    if projection_task is not None:
        projection_task.cancel()
        try:
            await projection_task
        except asyncio.CancelledError:
            pass
    watcher_task = getattr(app.state, "landing_pad_file_watcher_task", None)
    if watcher_task is not None:
        watcher_task.cancel()
        try:
            await watcher_task
        except asyncio.CancelledError:
            pass
    archive_task = getattr(app.state, "landing_pad_archive_task", None)
    if archive_task is not None:
        archive_task.cancel()
        try:
            await archive_task
        except asyncio.CancelledError:
            pass
    email_task = getattr(app.state, "email_poll_task", None)
    if email_task is not None:
        email_task.cancel()
        try:
            await email_task
        except asyncio.CancelledError:
            pass
    log_task = getattr(app.state, "log_poll_task", None)
    if log_task is not None:
        log_task.cancel()
        try:
            await log_task
        except asyncio.CancelledError:
            pass
    opensearch_log_task = getattr(app.state, "opensearch_log_poll_task", None)
    if opensearch_log_task is not None:
        opensearch_log_task.cancel()
        try:
            await opensearch_log_task
        except asyncio.CancelledError:
            pass
    jira_task = getattr(app.state, "jira_poll_task", None)
    if jira_task is not None:
        jira_task.cancel()
        try:
            await jira_task
        except asyncio.CancelledError:
            pass


app = create_app(
    title="KaiMS Monitoring Adapter",
    settings=settings,
    startup=_on_startup,
    shutdown=_on_shutdown,
)

def _ensure_workflow_import_paths() -> None:
    services_root = Path(__file__).resolve().parents[1]
    for relative_path in (
        "common",
        "alert-intelligence",
        "context-agent",
        "model-router",
        "orchestrator",
        "resolution-agent",
        "remediation-engine",
        "closure-service",
        "approval-service",
    ):
        candidate = str(services_root / relative_path)
        if candidate not in sys.path:
            sys.path.insert(0, candidate)


def build_sample_alert(flow_id: str = "payment-latency", trace_id: str | None = None) -> Alert:
    scenarios = merged_scenarios()
    scenario = scenarios.get(flow_id, scenarios["payment-latency"])
    return Alert(
        source=scenario["source"],
        name=str(scenario.get("alert_name") or scenario["name"]),
        service=scenario["service"],
        severity=AlertSeverity(severity_from_string(str(scenario["severity"]))),
        description=scenario["description"],
        labels=scenario["labels"],
        annotations=scenario["annotations"],
        trace_id=trace_id,
    )


def build_payment_latency_alert(trace_id: str | None = None) -> Alert:
    return build_sample_alert("payment-latency", trace_id)


def _normalize_project_name(project: dict[str, Any]) -> str:
    project_name = str(project.get("name", "")).strip()
    return project_name or "untitled-project"


def _normalize_provider_name(provider_name: str) -> str:
    return provider_name.strip().lower().replace(" ", "_")


def _select_monitoring_tool(connectivity: OnboardingConnectivityPayload, preferred: str | None = None) -> str:
    preferred_tool = _normalize_provider_name(preferred or "") if preferred else ""
    if preferred_tool in _ALLOWED_ONBOARDING_PROVIDERS:
        return preferred_tool
    active_provider = _normalize_provider_name(str(connectivity.active_provider or ""))
    if active_provider in _ALLOWED_ONBOARDING_PROVIDERS:
        return active_provider
    if connectivity.prometheus_url:
        return "prometheus"
    if connectivity.new_relic_url:
        return "new_relic"
    if connectivity.datadog_url:
        return "datadog"
    return "prometheus"


def _selected_tool_url(connectivity: OnboardingConnectivityPayload, selected_tool: str) -> str:
    if selected_tool == "new_relic":
        return str(connectivity.new_relic_url or "").strip()
    if selected_tool == "datadog":
        return str(connectivity.datadog_url or "").strip()
    return str(connectivity.prometheus_url or "").strip()


def _build_onboarding_rule_seed(connectivity: OnboardingConnectivityPayload, selected_tool: str) -> dict[str, Any]:
    project = connectivity.project
    return {
        "project_name": str(project.name or "").strip(),
        "description": "Monitoring onboarding workflow",
        "business_unit": "",
        "environment": str(project.environment or "prod").strip().lower(),
        "criticality": "high",
        "sla": "",
        "support_team": str(project.owner_team or "").strip(),
        "business_owner": str(project.owner_team or "").strip(),
        "technical_owner": str(project.owner_team or "").strip(),
        "technology_stack": [],
        "cloud_provider": "azure" if connectivity.deployment_mode == "azure_cloud" else "on_prem",
        "region": str(project.region or "").strip(),
        "monitoring_platforms": [selected_tool],
        "notification_platforms": ["slack", "teams", "pagerduty"],
    }


def _build_landing_pad_summary(connectivity: OnboardingConnectivityPayload, selected_tool: str) -> dict[str, Any]:
    project_name = str(connectivity.project.name or "").strip()
    configured_endpoint = _selected_tool_url(connectivity, selected_tool)
    return {
        "ready": True,
        "project_name": project_name,
        "selected_monitoring_tool": selected_tool,
        "configured_monitoring_endpoint": configured_endpoint,
        "landing_pad_endpoint": "/alerts/alertmanager",
        "message": (
            "Send alerts from your monitoring platform to /alerts/alertmanager. "
            "Landing pad ingestion will trigger the downstream KaiMS workflow."
        ),
    }


def _build_onboarding_rag_documents(
    *,
    connectivity: OnboardingConnectivityPayload,
    selected_tool: str,
    workflow_result: dict[str, Any],
    requirements: list[str],
    source_documents: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    project_name = str(connectivity.project.name or "").strip()
    owner_team = str(connectivity.project.owner_team or "").strip() or "platform-ops"
    environment = str(connectivity.project.environment or "prod").strip()
    workflow_id = str(workflow_result.get("workflow_id") or "").strip()
    onboarding_id = str(workflow_result.get("onboarding_id") or "").strip()
    trace_id = str(workflow_result.get("trace_id") or "").strip()
    generated_rules = workflow_result.get("generated_rules", []) if isinstance(workflow_result.get("generated_rules"), list) else []
    rules_summary = "\n".join(
        f"- {item.get('name', 'unnamed-rule')} ({item.get('platform', selected_tool)}): {item.get('expression', '')}" for item in generated_rules[:15]
    ) or "- Rules generated by onboarding pipeline"
    requirements_summary = "\n".join(f"- {line}" for line in requirements) or "- Plain-language requirement provided"
    source_ref = f"workflow:{workflow_id}" if workflow_id else "workflow:new-rule-onboarding"
    normalized_sources = [item for item in (source_documents or []) if isinstance(item, dict)]
    source_doc_types: list[str] = []
    source_doc_lines: list[str] = []
    source_text_lines: list[str] = []
    for item in normalized_sources:
        kind = str(item.get("kind") or "reference").strip().lower() or "reference"
        name = str(item.get("name") or "uploaded-document").strip() or "uploaded-document"
        excerpt = str(item.get("excerpt") or "").strip()
        content = str(item.get("content") or item.get("text") or "").strip()
        source_preview = (content or excerpt)[:2000]
        if kind not in source_doc_types:
            source_doc_types.append(kind)
        source_doc_lines.append(f"- {kind}: {name}{f' | {excerpt}' if excerpt else ''}")
        if source_preview:
            source_text_lines.append(f"### {kind}: {name}\n{source_preview}")
    source_doc_summary = "\n".join(source_doc_lines) or "- No explicit source documents supplied"
    source_text_summary = "\n\n".join(source_text_lines) or "No source document content supplied."
    required_doc_summary = [
        "past tickets or incidents that show repeated failure patterns",
        "troubleshooting or diagnostic notes that capture investigation steps",
        "RCA / postmortem docs with root cause and corrective actions",
        "resolution notes, runbooks, and validation logs",
    ]
    metadata_updates = [
        "Add document provenance and evidence source labels to each generated rule",
        "Capture RCA steps, diagnostic commands, and resolution actions in onboarding metadata",
        "Link ticket, log, and postmortem references to the generated runbook entries",
    ]

    shared_metadata = {
        "project_name": project_name,
        "selected_monitoring_tool": selected_tool,
        "workflow_id": workflow_id,
        "onboarding_id": onboarding_id,
        "trace_id": trace_id,
        "owner_team": owner_team,
        "source_document_types": source_doc_types,
    }

    def metadata_payload(values: dict[str, Any]) -> dict[str, str]:
        normalized: dict[str, str] = {}
        for key, value in values.items():
            if value is None:
                normalized[str(key)] = ""
            elif isinstance(value, (list, tuple, set)):
                normalized[str(key)] = ", ".join(str(item) for item in value if str(item).strip())
            elif isinstance(value, dict):
                normalized[str(key)] = json.dumps(value, sort_keys=True)
            else:
                normalized[str(key)] = str(value)
        return normalized

    incident_doc = {
        "kind": "incident",
        "alert_id": f"{project_name}-rule-onboarding",
        "alert_type": "monitoring-rule-onboarding",
        "severity": "high",
        "title": f"{project_name} Monitoring Rule Onboarding",
        "summary": f"Plain-language monitoring requirements were converted to {selected_tool} rules.",
        "content": (
            f"Project {project_name} onboarding completed in {environment}.\n"
            f"Selected tool: {selected_tool}.\n"
            f"Requirements:\n{requirements_summary}\n\nGenerated rules:\n{rules_summary}\n\nSource documents:\n{source_doc_summary}"
            f"\n\nSource document previews:\n{source_text_summary}"
        ),
        "services": [project_name],
        "deployment": environment,
        "recommended_action": "Review generated rules and approve production deployment.",
        "source_system": "monitoring-adapter",
        "source_ref": source_ref,
        "metadata": metadata_payload({
            **shared_metadata,
            "document_class": "onboarding-incident",
            "required_documents": required_doc_summary,
            "source_document_count": len(normalized_sources),
        }),
    }

    runbook_doc = {
        "kind": "runbook",
        "alert_id": f"{project_name}-rule-runbook",
        "alert_type": "rule-operations",
        "severity": "high",
        "title": f"{project_name} Rule Monitoring & Resolution Runbook",
        "summary": "Operational runbook for monitoring generated rules, triage, RCA, and resolution.",
        "content": (
            "1. Verify rule expression output for false positives.\n"
            "2. Validate alert routing and escalation channels.\n"
            "3. Run RCA checklist for noisy or missed alerts.\n"
            "4. Apply threshold or duration tuning and redeploy through workflow editor.\n"
            "5. Confirm health restoration and close incident with audit notes."
        ),
        "services": [project_name],
        "deployment": environment,
        "root_cause": "Threshold drift, metric quality, or dependency changes can cause noisy or delayed alerts.",
        "impact": "Delayed detection and unnecessary incidents for production services.",
        "execution_plan": "Tune rule thresholds, re-run simulation, then promote approved rules.",
        "recommended_action": "Use workflow simulation and governance checks before production push.",
        "source_system": "monitoring-adapter",
        "source_ref": source_ref,
        "metadata": metadata_payload({
            **shared_metadata,
            "required_documents": required_doc_summary,
            "metadata_updates": metadata_updates,
        }),
    }

    dependency_doc = {
        "kind": "dependency",
        "alert_id": f"{project_name}-rule-dependencies",
        "alert_type": "dependency-map",
        "severity": "warning",
        "title": f"{project_name} Rule Dependency & RCA Metadata",
        "summary": "Dependency and metadata baseline for rule monitoring, RCA, and resolution workflows.",
        "content": (
            f"Monitoring tool endpoint: {_selected_tool_url(connectivity, selected_tool) or 'not-provided'}.\n"
            f"Deployment mode: {connectivity.deployment_mode}.\n"
            "Track dependencies for data pipeline, scrape/export health, and notification delivery."
        ),
        "services": [project_name],
        "deployment": environment,
        "dependencies": [selected_tool, "notification-platform", "incident-orchestrator"],
        "source_system": "monitoring-adapter",
        "source_ref": source_ref,
        "metadata": metadata_payload({
            **shared_metadata,
            "document_class": "dependency-metadata",
            "source_document_types": source_doc_types,
        }),
    }

    change_doc = {
        "kind": "change",
        "alert_id": f"{project_name}-rule-change",
        "alert_type": "rules-change-plan",
        "severity": "warning",
        "title": f"{project_name} Rules Change Record",
        "summary": "Change record for generated monitoring rules and rollout governance.",
        "content": (
            "This change introduces LLM-generated monitoring rules from plain-language requirements.\n"
            "Rollout phases: staging validation, simulation review, governance approval, production deployment."
        ),
        "services": [project_name],
        "deployment": environment,
        "change_id": onboarding_id or workflow_id or f"{project_name}-rule-change",
        "execution_plan": "Deploy by environment with rollback guardrails and post-deploy SLO checks.",
        "source_system": "monitoring-adapter",
        "source_ref": source_ref,
        "metadata": metadata_payload({
            **shared_metadata,
            "document_class": "change-record",
        }),
    }

    docs = [incident_doc, runbook_doc, dependency_doc, change_doc]
    for doc in docs:
        doc["metadata"] = metadata_payload({
            **(doc.get("metadata") if isinstance(doc.get("metadata"), dict) else {}),
            "evaluation": build_quality_evaluation(
                prediction={
                    "title": doc.get("title"),
                    "summary": doc.get("summary"),
                    "content": doc.get("content"),
                    "recommended_action": doc.get("recommended_action"),
                },
                context={
                    "requirements": requirements_summary,
                    "generated_rules": rules_summary,
                    "source_documents": source_doc_summary,
                    "source_previews": source_text_summary,
                },
                confidence=0.82 if normalized_sources else 0.68,
                citations=[source_ref] if source_ref else [],
                rag_matches=[],
                runbook_found=bool(normalized_sources),
                fallback_used=not bool(normalized_sources),
            ),
        })

    return docs


def _prometheus_rules_output_path(project_name: str, workflow_id: str) -> Path:
    safe_project = re.sub(r"[^a-zA-Z0-9_-]", "-", str(project_name or "project").strip()) or "project"
    safe_workflow = re.sub(r"[^a-zA-Z0-9_-]", "-", str(workflow_id or "workflow").strip()) or str(uuid.uuid4())
    primary_output_dir = rag_root_path() / "changes" / "prometheus_rules"

    def _ensure_writable_directory(path: Path) -> None:
        # Handle races and stale filesystem entries (including broken symlinks)
        # so onboarding can always write generated rules.
        for _ in range(3):
            try:
                path.mkdir(parents=True, exist_ok=True)
                return
            except FileExistsError:
                if path.exists() and path.is_dir():
                    return

                if os.path.lexists(path):
                    try:
                        path.unlink()
                    except IsADirectoryError:
                        # Another request may have completed directory creation.
                        if path.exists() and path.is_dir():
                            return
                        raise

                parent = path.parent
                try:
                    parent.mkdir(parents=True, exist_ok=True)
                except FileExistsError:
                    if parent.exists() and parent.is_dir():
                        continue
                    if os.path.lexists(parent):
                        try:
                            parent.unlink()
                        except IsADirectoryError:
                            if parent.exists() and parent.is_dir():
                                continue
                            raise

        # Final attempt after cleanup/retry loop.
        path.mkdir(parents=True, exist_ok=True)

    output_dir = primary_output_dir
    try:
        _ensure_writable_directory(primary_output_dir)
    except Exception:
        logger.exception(
            "prometheus_rules_output_dir_unavailable",
            extra={"primary_output_dir": str(primary_output_dir)},
        )
        fallback_output_dir = Path("/tmp/kaiops/prometheus_rules")
        _ensure_writable_directory(fallback_output_dir)
        output_dir = fallback_output_dir

    return output_dir / f"{safe_project}-{safe_workflow}.yml"


async def _generate_upload_and_test_prometheus_rules(
    *,
    endpoint_url: str,
    project_name: str,
    workflow_id: str,
    generated_rules: list[dict[str, Any]],
    include_smoke_test_alert: bool,
) -> dict[str, Any]:
    yaml_content = build_prometheus_rules_yaml(
        project_name,
        generated_rules,
        include_smoke_test_alert=include_smoke_test_alert,
    )
    output_path = _prometheus_rules_output_path(project_name, workflow_id)
    output_path.write_text(yaml_content, encoding="utf-8")
    expected_group_name = f"{re.sub(r'[^a-zA-Z0-9]+', '-', str(project_name or '').strip().lower()).strip('-') or 'project'}-generated-rules"

    details: dict[str, Any] = {
        "yaml_generated": True,
        "yaml_path": str(output_path),
        "yaml": yaml_content,
        "upload": {
            "attempted": False,
            "ok": False,
            "message": "Prometheus push API is not available; rules are written to local changes directory.",
            "reload_requested": False,
            "reload_ok": False,
        },
        "test": {
            "attempted": False,
            "ok": False,
            "message": "Prometheus endpoint not provided.",
            "loaded_rule_groups": 0,
            "loaded_rules": 0,
            "active_alerts": 0,
        },
        "smoke_test_alert_enabled": include_smoke_test_alert,
    }

    normalized_endpoint = str(endpoint_url or "").strip().rstrip("/")
    if not normalized_endpoint:
        return details

    async with httpx.AsyncClient(timeout=12.0) as client:
        reload_url = f"{normalized_endpoint}/-/reload"
        rules_url = f"{normalized_endpoint}/api/v1/rules"
        alerts_url = f"{normalized_endpoint}/api/v1/alerts"
        details["upload"]["attempted"] = True
        details["upload"]["reload_requested"] = True
        try:
            reload_response = await client.post(reload_url)
            details["upload"]["reload_ok"] = reload_response.status_code < 400
            details["upload"]["message"] = f"Reload endpoint returned HTTP {reload_response.status_code}."
        except Exception as exc:
            details["upload"]["message"] = f"Reload request failed: {exc}"

        details["test"]["attempted"] = True
        try:
            rules_response = await client.get(rules_url)
            body = rules_response.json() if "application/json" in str(rules_response.headers.get("content-type", "")).lower() else {}
            api_status = str(body.get("status") or "").strip().lower() if isinstance(body, dict) else ""
            loaded_group_count = 0
            loaded_rule_count = 0
            if isinstance(body, dict):
                data = body.get("data", {}) if isinstance(body.get("data"), dict) else {}
                groups = data.get("groups", []) if isinstance(data.get("groups"), list) else []
                matching_groups = [
                    group for group in groups
                    if str(group.get("name") or "").strip() == expected_group_name
                ]
                loaded_group_count = len(matching_groups)
                loaded_rule_count = sum(len(group.get("rules", []) or []) for group in matching_groups)

            active_alert_count = 0
            try:
                alerts_response = await client.get(alerts_url)
                alerts_body = alerts_response.json() if "application/json" in str(alerts_response.headers.get("content-type", "")).lower() else {}
                if isinstance(alerts_body, dict):
                    alerts_data = alerts_body.get("data", {}) if isinstance(alerts_body.get("data"), dict) else {}
                    alerts = alerts_data.get("alerts", []) if isinstance(alerts_data.get("alerts"), list) else []
                    active_alert_count = len(
                        [
                            alert
                            for alert in alerts
                            if str((alert.get("labels") or {}).get("project") or "").strip() == expected_group_name.removesuffix("-generated-rules")
                        ]
                    )
            except Exception:
                logger.exception("failed to count active alerts for rule group %s", expected_group_name)
                active_alert_count = 0

            details["test"]["loaded_rule_groups"] = loaded_group_count
            details["test"]["loaded_rules"] = loaded_rule_count
            details["test"]["active_alerts"] = active_alert_count

            rules_api_ok = rules_response.status_code < 400 and api_status in {"", "success"}
            loaded_ok = loaded_rule_count > 0
            details["test"]["ok"] = bool(rules_api_ok and loaded_ok)
            details["upload"]["ok"] = bool(details["upload"].get("reload_ok") and loaded_ok)
            details["test"]["message"] = (
                f"Rules API HTTP {rules_response.status_code}; loaded_groups={loaded_group_count}; "
                f"loaded_rules={loaded_rule_count}; active_alerts={active_alert_count}."
            )
        except Exception as exc:
            details["test"]["message"] = f"Prometheus test request failed: {exc}"
            details["upload"]["ok"] = bool(details["upload"].get("reload_ok", False))

    return details


def _build_onboarding_steps_response(
    *,
    onboarding_path: str,
    project_mode: str,
    start_rules_onboarding: bool,
    requirements: list[str],
    rules_result: dict[str, Any] | None,
    prometheus_result: dict[str, Any] | None,
    rag_documents: list[dict[str, Any]],
    landing_pad_summary: dict[str, Any],
) -> list[dict[str, Any]]:
    uses_setup_flow = str(onboarding_path or "").strip().lower() == "setup_monitoring"
    step_one = {
        "step": 1,
        "title": "Create/Update Project",
        "status": "completed",
        "details": {"project_mode": project_mode},
    }
    step_two = {
        "step": 2,
        "title": "Select Onboarding Path",
        "status": "completed",
        "details": {
            "path": "setup_monitoring" if uses_setup_flow else "existing_monitoring",
            "summary": (
                "Create monitoring rules and configure Prometheus"
                if uses_setup_flow
                else "Use existing monitoring and ingest alerts into landing pad"
            ),
        },
    }
    step_three = {
        "step": 3,
        "title": "Capture Rules In Plain English" if uses_setup_flow else "Configure Landing Pad Ingestion",
        "status": (
            "completed" if (uses_setup_flow and start_rules_onboarding and requirements) else
            ("completed" if not uses_setup_flow else "skipped")
        ),
        "details": {
            "requirements_count": len(requirements) if uses_setup_flow else 0,
            "requirements": requirements if uses_setup_flow else [],
            "landing_pad": landing_pad_summary if not uses_setup_flow else {},
        },
    }
    step_four_status = "skipped"
    step_four_title = "Convert To YAML, Upload In Prometheus, Test" if uses_setup_flow else "Ingest Alerts and Trigger Workflow"
    step_four_details: dict[str, Any] = {
        "message": (
            "Rule conversion and Prometheus upload were skipped."
            if uses_setup_flow
            else "Alert ingestion via landing pad is ready; incoming alerts will trigger downstream workflow."
        ),
        "landing_pad": landing_pad_summary if not uses_setup_flow else {},
    }
    if uses_setup_flow and start_rules_onboarding and rules_result:
        step_four_status = "completed"
        step_four_details = {
            "workflow_id": rules_result.get("workflow_id"),
            "rule_conversion": "completed",
            "prometheus": prometheus_result or {"message": "Prometheus deployment not attempted."},
        }
    if not uses_setup_flow:
        step_four_status = "completed"

    step_five = {
        "step": 5,
        "title": "Generate Monitoring/Troubleshooting/Resolution Docs",
        "status": "completed" if rag_documents else "skipped",
        "details": {
            "generated_document_count": len(rag_documents),
            "documents": rag_documents,
        },
    }
    return [step_one, step_two, step_three, {"step": 4, "title": step_four_title, "status": step_four_status, "details": step_four_details}, step_five]


async def persist_onboarding_connectivity(payload: dict[str, Any]) -> None:
    session_factory = getattr(app.state, "session_factory", None)
    if not settings.database_enabled or session_factory is None:
        return

    project = payload.get("project", {}) if isinstance(payload.get("project"), dict) else {}
    if not isinstance(project, dict):
        project = {}

    project_name = _normalize_project_name(project)
    provider_statuses = payload.get("provider_statuses", {}) if isinstance(payload.get("provider_statuses"), dict) else {}
    connectivity_payload = {
        "deployment_mode": str(payload.get("deployment_mode", "on_prem")).strip().lower().replace("-", "_"),
        "prometheus_url": str(payload.get("prometheus_url", "")).strip(),
        "new_relic_url": str(payload.get("new_relic_url", "")).strip(),
        "datadog_url": str(payload.get("datadog_url", "")).strip(),
        "azure_subscription_id": str(payload.get("azure_subscription_id", "")).strip(),
        "azure_resource_group": str(payload.get("azure_resource_group", "")).strip(),
        "azure_service_bus_namespace": str(payload.get("azure_service_bus_namespace", "")).strip(),
        "azure_service_bus_topic": str(payload.get("azure_service_bus_topic", "")).strip(),
        "azure_service_bus_subscription": str(payload.get("azure_service_bus_subscription", "")).strip(),
        "azure_content_safety_enabled": bool(payload.get("azure_content_safety_enabled", False)),
        "azure_content_safety_endpoint": str(payload.get("azure_content_safety_endpoint", "")).strip(),
        "user_assignments": payload.get("user_assignments", {}) if isinstance(payload.get("user_assignments"), dict) else {},
        "updated_at": payload.get("updated_at"),
        "active_provider": _normalize_provider_name(str(payload.get("active_provider", ""))) if payload.get("active_provider") else None,
    }
    selected_provider = _normalize_provider_name(str(payload.get("active_provider", "project")))
    now = datetime.now(timezone.utc)

    async with session_factory() as session:
        repo = IncidentRepository(session)
        await repo.save_onboarding_state(
            project_name=project_name,
            provider_name="project",
            owner_team=str(project.get("owner_team", "")).strip() or None,
            environment=str(project.get("environment", "")).strip() or None,
            region=str(project.get("region", "")).strip() or None,
            endpoint_url=None,
            test_status="saved",
            test_message="Project configuration saved",
            project_payload=project,
            connectivity_payload=connectivity_payload,
            last_tested_at=None,
        )

        for provider_name, endpoint_key in (("prometheus", "prometheus_url"), ("new_relic", "new_relic_url"), ("datadog", "datadog_url")):
            provider_state = provider_statuses.get(provider_name, {}) if isinstance(provider_statuses, dict) else {}
            has_test_result = isinstance(provider_state, dict) and ("ok" in provider_state or "message" in provider_state)
            ok = bool(provider_state.get("ok", False)) if has_test_result else False
            message = None
            if has_test_result:
                message = str(provider_state.get("message", "")).strip() or None
            await repo.save_onboarding_state(
                project_name=project_name,
                provider_name=provider_name,
                owner_team=str(project.get("owner_team", "")).strip() or None,
                environment=str(project.get("environment", "")).strip() or None,
                region=str(project.get("region", "")).strip() or None,
                endpoint_url=str(payload.get(endpoint_key, "")).strip() or None,
                test_status="connected" if ok else ("failed" if has_test_result else None),
                test_message=message,
                project_payload=project,
                connectivity_payload={
                    "provider": provider_name,
                    "endpoint_url": str(payload.get(endpoint_key, "")).strip(),
                    "state": provider_state,
                    "selected_provider": selected_provider,
                    "updated_at": payload.get("updated_at"),
                },
                last_tested_at=now if has_test_result else None,
            )

        await session.commit()


async def persist_onboarding_pipeline_result(result: dict[str, Any]) -> None:
    session_factory = getattr(app.state, "session_factory", None)
    if not settings.database_enabled or session_factory is None:
        return

    project = result.get("project", {}) if isinstance(result.get("project"), dict) else {}
    project_name = _normalize_project_name({"name": project.get("project_name")})
    provider_name = str(result.get("pipeline") or "onboarding_pipeline").strip().lower()

    payload = {
        "workflow_id": result.get("workflow_id"),
        "onboarding_id": result.get("onboarding_id"),
        "project_id": result.get("project_id"),
        "trace_id": result.get("trace_id"),
        "status": result.get("status"),
        "pipeline": result.get("pipeline"),
        "summary": result.get("summary") or result.get("approval_package") or {},
        "event_contract": result.get("event_contract") or {},
        "result": result,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }

    async with session_factory() as session:
        repo = IncidentRepository(session)
        await repo.save_onboarding_state(
            project_name=project_name,
            provider_name=provider_name,
            owner_team=str(project.get("support_team", "")).strip() or None,
            environment=str(project.get("environment", "")).strip() or None,
            region=str(project.get("region", "")).strip() or None,
            endpoint_url=None,
            test_status=str(result.get("status", "completed")),
            test_message=f"{provider_name} workflow persisted",
            project_payload=project,
            connectivity_payload=payload,
            last_tested_at=datetime.now(timezone.utc),
        )
        await session.commit()


async def publish_onboarding_pipeline_event(result: dict[str, Any]) -> None:
    contract = result.get("event_contract", {}) if isinstance(result.get("event_contract"), dict) else {}
    if not contract:
        return
    try:
        started = perf_counter()
        await app.state.producer.publish(
            ONBOARDING_RULE_EVENTS,
            contract,
            key=str(contract.get("project_id") or "onboarding"),
        )
        EVENT_PUBLISH_LATENCY.labels(settings.service_name, ONBOARDING_RULE_EVENTS, "monitoring-adapter").observe(
            max(0.0, perf_counter() - started)
        )
    except Exception:
        logger.exception("failed to publish onboarding pipeline event")


async def run_local_payment_workflow(
    trace_id: str | None = None,
    flow_id: str = "payment-latency",
    model_router: Any | None = None,
    run_comparison: bool = True,
    auto_approve: bool = True,
) -> dict[str, Any]:
    """Run the agent workflow in-process for local demos with Kafka disabled."""
    _ensure_workflow_import_paths()
    from alert_intelligence import AlertIntelligenceAgent
    from closure_service import ClosureValidationAgent
    from orchestrator import OrchestratorAgent
    from remediation_engine import RemediationEngine

    agent_order = [
        "Alert Intelligence Agent",
        "Orchestrator Agent",
        "Context Intelligence Agent",
        "Resolution Intelligence Agent",
        "Human Approval Layer",
        "Remediation Automation Engine",
        "Closure & Validation",
    ]

    async def persist_step(*operations: Any) -> None:
        session_factory = getattr(app.state, "session_factory", None)
        engine = None
        if not settings.database_enabled:
            return
        if session_factory is None:
            engine = create_engine(settings)
            session_factory = create_session_factory(engine)
            await create_schema(engine)
        try:
            async with session_factory() as session:
                repo = IncidentRepository(session)
                for operation in operations:
                    await operation(repo)
                await session.commit()
        finally:
            if engine is not None:
                await engine.dispose()

    def track_agent_work_operation(
        *,
        incident_id: Any,
        agent_name: str,
        work_item: str,
        status: str,
        sequence: int,
        trace_id: str | None,
        ticket_id: str | None,
        details: dict[str, Any] | None = None,
        started_at: datetime | None = None,
        completed_at: datetime | None = None,
    ):
        async def _operation(repo: IncidentRepository) -> None:
            await repo.save_agent_work_item(
                incident_id=incident_id,
                agent_name=agent_name,
                work_item=work_item,
                status=status,
                sequence=sequence,
                trace_id=trace_id,
                ticket_id=ticket_id,
                details=_json_safe(details or {}),
                started_at=started_at,
                completed_at=completed_at,
            )

        return _operation

    def track_metadata_event_operation(envelope: dict[str, Any]):
        async def _operation(repo: IncidentRepository) -> None:
            await repo.save_incident_event(_json_safe(envelope))

        return _operation

    scenarios = merged_scenarios()
    resolved_flow_id = resolve_flow_id(flow_id, scenarios)
    scenario = scenarios[resolved_flow_id]
    ai_client = AiLayerClient(settings)
    alert = build_sample_alert(resolved_flow_id, trace_id=trace_id)
    enriched_alert, incident = await AlertIntelligenceAgent().process(alert)
    incident.trace_id = trace_id
    await persist_step(lambda repo: repo.save_alert(enriched_alert), lambda repo: repo.save_incident(incident))
    now = datetime.now(timezone.utc)
    await persist_step(
        *[
            track_agent_work_operation(
                incident_id=incident.id,
                agent_name=agent_name,
                work_item="Assigned to incident workflow",
                status="pending",
                sequence=index,
                trace_id=trace_id,
                ticket_id=incident.ticket_id,
                details={"assigned_by": "orchestrator", "flow_id": flow_id},
                started_at=now,
                completed_at=None,
            )
            for index, agent_name in enumerate(agent_order, start=1)
        ]
    )
    alert_event = {
        "sequence": 1,
        "agent": "Alert Intelligence Agent",
        "action": "Deduplicated, correlated, classified, and enriched alert",
        "input": {
            "flow_id": flow_id,
            "source": alert.source,
            "name": alert.name,
            "service": alert.service,
            "severity": alert.severity.value,
            "description": alert.description,
            "labels": alert.labels,
            "annotations": alert.annotations,
            "trace_id": trace_id,
        },
        "decision": f"Severity classified as {enriched_alert.severity}; correlation ID {enriched_alert.correlation_id}",
        "output": "Created incident and enriched alert event",
        "communicates_to": "Orchestrator Agent via enriched-alerts",
        "metrics": {
            "deduplicated_count": enriched_alert.deduplicated_count,
            "metadata_fields": len(enriched_alert.metadata),
        },
    }
    await persist_step(
        track_agent_work_operation(
            incident_id=incident.id,
            agent_name="Alert Intelligence Agent",
            work_item="Deduplicate, correlate, classify, and enrich alert",
            status="completed",
            sequence=1,
            trace_id=trace_id,
            ticket_id=incident.ticket_id,
            details={
                "action": alert_event["action"],
                "input": alert_event["input"],
                "decision": alert_event["decision"],
                "output": alert_event["output"],
                "communicates_to": alert_event["communicates_to"],
                "metrics": alert_event["metrics"],
            },
            started_at=now,
            completed_at=datetime.now(timezone.utc),
        )
    )
    context_task = asyncio.create_task(ai_client.collect_context(alert=enriched_alert, incident=incident))
    decision_task = asyncio.create_task(OrchestratorAgent().decide_workflow_async(enriched_alert, incident))
    context, decision = await asyncio.gather(context_task, decision_task)
    context.trace_id = trace_id
    orchestrator_event = {
        "sequence": 2,
        "agent": "Orchestrator Agent",
        "action": "Selected incident workflow and downstream agents",
        "input": {
            "incident_id": incident.id,
            "service": incident.service,
            "severity": incident.severity.value,
            "title": incident.title,
            "workflow": decision.workflow,
            "trace_id": trace_id,
        },
        "decision": decision.__dict__,
        "workflow": decision.workflow,
        "output": (
            f"Workflow {decision.workflow}; next action: {decision.next_action}; "
            f"approval required: {decision.requires_approval}; message bus: {decision.message_bus_provider}"
        ),
        "communicates_to": ", ".join(decision.downstream_agents),
        "metrics": {
            "downstream_agents": len(decision.downstream_agents),
            "requires_approval": decision.requires_approval,
            "message_bus_provider": decision.message_bus_provider,
            "stream_count": decision.stream_count,
            "stream_threshold": decision.stream_threshold,
        },
    }
    await persist_step(
        track_agent_work_operation(
            incident_id=incident.id,
            agent_name="Orchestrator Agent",
            work_item="Select workflow and downstream agents",
            status="completed",
            sequence=2,
            trace_id=trace_id,
            ticket_id=incident.ticket_id,
            details={
                "action": orchestrator_event["action"],
                "input": orchestrator_event["input"],
                "decision": orchestrator_event["decision"],
                "output": orchestrator_event["output"],
                "communicates_to": orchestrator_event["communicates_to"],
                "metrics": orchestrator_event["metrics"],
            },
            started_at=now,
            completed_at=datetime.now(timezone.utc),
        )
    )
    orchestration_envelope = _build_local_metadata_envelope(
        event_type="incident.workflow.selected",
        incident=incident.model_dump(mode="json"),
        alert=enriched_alert.model_dump(mode="json"),
        decision=decision.__dict__,
        status="investigating",
        payload={
            "workflow": decision.workflow,
            "next_action": decision.next_action,
            "downstream_agents": decision.downstream_agents,
        },
        transport_provider=decision.message_bus_provider,
    )
    await persist_step(track_metadata_event_operation(orchestration_envelope))
    context_event = {
        "sequence": 3,
        "agent": "Context Intelligence Agent",
        "action": "Collected operational context and RAG evidence",
        "input": {
            "incident_id": incident.id,
            "alert_service": enriched_alert.service,
            "alert_severity": enriched_alert.severity.value,
            "deployment_label": enriched_alert.labels.get("deployment"),
            "workflow": decision.workflow,
            "trace_id": trace_id,
        },
        "decision": f"Most relevant deployment: {context.deployment}",
        "output": "Context object with runbook, related incidents, dependencies, metrics, and changes",
        "communicates_to": "Resolution Intelligence Agent via context-events",
        "metrics": {
            "related_incidents": len(context.related_incidents),
            "dependency_services": len(context.dependency_services),
            "recent_changes": len(context.recent_changes),
            "rag_documents": context.metadata.get("rag_documents", 0) if isinstance(context.metadata, dict) else 0,
            "rag_matches": context.metadata.get("rag_matches", []) if isinstance(context.metadata, dict) else [],
            "rag_top_similarity": context.metadata.get("rag_top_similarity", 0.0) if isinstance(context.metadata, dict) else 0.0,
            "rag_service_tagged_match": context.metadata.get("rag_service_tagged_match", False)
            if isinstance(context.metadata, dict)
            else False,
            "rag_index": context.metadata.get("rag_index", {}) if isinstance(context.metadata, dict) else {},
            "runbook_found": bool(context.runbook),
        },
    }
    await persist_step(
        track_agent_work_operation(
            incident_id=incident.id,
            agent_name="Context Intelligence Agent",
            work_item="Collect context and RAG evidence",
            status="completed",
            sequence=3,
            trace_id=trace_id,
            ticket_id=incident.ticket_id,
            details={
                "action": context_event["action"],
                "input": context_event["input"],
                "decision": context_event["decision"],
                "output": context_event["output"],
                "communicates_to": context_event["communicates_to"],
                "metrics": context_event["metrics"],
            },
            started_at=now,
            completed_at=datetime.now(timezone.utc),
        )
    )
    model_errors: list[dict[str, str]] = []
    cleaned_resolution = _clean_resolution_fields(
        scenario,
        service=enriched_alert.service,
        description=enriched_alert.description,
    )
    try:
        recommendation = await ai_client.resolve(context=context)
    except Exception as exc:
        recommendation = Recommendation(
            incident_id=incident.id,
            root_cause=cleaned_resolution["root_cause"],
            confidence=0.72,
            impact=cleaned_resolution["impact"],
            recommended_action=cleaned_resolution["recommended_action"],
            severity=enriched_alert.severity,
            rationale=(
                "RCA model route failed; recommendation is based on retrieved RAG context "
                "and scenario evidence. See FinOps errors for provider details."
            ),
            commands=[],
            risk="high" if enriched_alert.severity == AlertSeverity.CRITICAL else "medium",
        )
        model_errors.append(
            {
                "provider": "router",
                "task": "resolution",
                "prompt": "Resolution Intelligence Agent LangGraph workflow",
                "payload": str({"alert": enriched_alert.description, "context": context.metadata}),
                "error": str(exc),
            }
        )
    recommendation.root_cause = _clean_recommendation_text(
        getattr(recommendation, "root_cause", None),
        keys=("root_cause", "cause", "summary", "content", "title"),
        fallback=cleaned_resolution["root_cause"],
    )
    recommendation.impact = _clean_recommendation_text(
        getattr(recommendation, "impact", None),
        keys=("impact", "customer_impact", "dependency_impact", "summary", "content", "title"),
        fallback=cleaned_resolution["impact"],
    )
    recommendation.recommended_action = _clean_recommendation_text(
        getattr(recommendation, "recommended_action", None),
        keys=("recommended_action", "action", "summary", "content", "title"),
        fallback=cleaned_resolution["recommended_action"],
    )
    recommendation.rationale = (
        f"Evidence links {recommendation.root_cause} to {recommendation.impact}; "
        f"recommended action is {recommendation.recommended_action}."
    )
    recommendation.trace_id = trace_id
    recommendation.metadata["display_fields_sanitized"] = True
    recommendation.metadata["rag_documents"] = context.metadata.get("rag_documents", 0)
    recommendation.metadata["rag_matches"] = context.metadata.get("rag_matches", [])
    recommendation.metadata["rag_top_similarity"] = context.metadata.get("rag_top_similarity", 0.0)
    recommendation.metadata["rag_service_tagged_match"] = context.metadata.get("rag_service_tagged_match", False)
    recommendation.metadata["runbook_found"] = bool(context.runbook)
    recommendation.metadata["policy_version"] = decision.policy_version
    recommendation.metadata["policy_reason"] = decision.policy_reason
    recommendation.metadata["orchestration_decision"] = {
        "workflow": decision.workflow,
        "requires_approval": decision.requires_approval,
        "risk_tier": decision.risk_tier,
        "execution_mode": decision.execution_mode,
        "policy_version": decision.policy_version,
        "policy_reason": decision.policy_reason,
        "message_bus_provider": decision.message_bus_provider,
        "stream_count": decision.stream_count,
        "stream_threshold": decision.stream_threshold,
    }
    recommendation.metadata["evaluation"] = build_quality_evaluation(
        prediction={
            "root_cause": recommendation.root_cause,
            "impact": recommendation.impact,
            "recommended_action": recommendation.recommended_action,
            "rationale": recommendation.rationale,
            "commands": recommendation.commands,
        },
        context={
            "scenario": scenario,
            "alert": enriched_alert.model_dump(mode="json"),
            "incident": incident.model_dump(mode="json"),
            "context_metadata": context.metadata,
            "runbook": context.runbook,
        },
        confidence=float(recommendation.confidence),
        citations=list(recommendation.metadata.get("citations", [])),
        rag_matches=context.metadata.get("rag_matches", []) if isinstance(context.metadata, dict) else [],
        runbook_found=bool(context.runbook),
        fallback_used=bool(model_errors),
    )
    await persist_step(lambda repo: repo.save_recommendation_as_audit(recommendation))
    model_usage = list(recommendation.metadata.get("model_usage", []))
    model_calls = list(recommendation.metadata.get("model_calls", []))
    if run_comparison:
        comparison_payload = {
            "service": enriched_alert.service,
            "incident": incident.title,
            "root_cause": recommendation.root_cause,
            "recommended_action": recommendation.recommended_action,
        }
        comparison_prompt = PROMPT_SUMMARIZE_RCA
        try:
            result = await ai_client.route_model(
                severity=enriched_alert.severity,
                task="summarization",
                prompt=comparison_prompt,
                payload=comparison_payload,
            )
            usage = result.get("usage")
            content = result.get("content")
            if not isinstance(usage, dict):
                raise TypeError("Comparison result missing usage payload")

            provider_name = str(usage.get("provider") or result.get("model") or "model-router")
            model_usage.append(usage)
            model_calls.append(
                {
                    "task": "summarization",
                    "provider": provider_name,
                    "model": usage.get("model"),
                    "prompt": comparison_prompt,
                    "payload": comparison_payload,
                    "response": {
                        "text": content,
                        "parameters": {
                            "provider": provider_name,
                            "model": usage.get("model"),
                            "task": "summarization",
                        },
                    },
                    "usage": usage,
                }
            )
        except Exception as exc:
            model_errors.append(
                {
                    "provider": "model-router-endpoint",
                    "task": "summarization",
                    "prompt": comparison_prompt,
                    "payload": str(comparison_payload),
                    "error": str(exc),
                }
            )
    resolution_event = {
        "sequence": 4,
        "agent": "Resolution Intelligence Agent",
        "action": "Ran LangGraph RCA workflow",
        "input": {
            "incident_id": incident.id,
            "severity": enriched_alert.severity.value,
            "deployment": context.deployment,
            "related_incidents": len(context.related_incidents),
            "workflow": decision.workflow,
            "trace_id": trace_id,
        },
        "decision": f"Root cause: {recommendation.root_cause}; action: {recommendation.recommended_action}",
        "output": "Recommendation with impact, rationale, commands, confidence, and risk",
        "communicates_to": "Human Approval Layer via resolution-events",
        "metrics": {
            "confidence": recommendation.confidence,
            "commands": len(recommendation.commands),
            "risk": recommendation.risk,
        },
        "llm_calls": model_calls,
        "llm_errors": model_errors,
    }
    await persist_step(
        track_agent_work_operation(
            incident_id=incident.id,
            agent_name="Resolution Intelligence Agent",
            work_item="Run RCA and produce recommendation",
            status="completed",
            sequence=4,
            trace_id=trace_id,
            ticket_id=incident.ticket_id,
            details={
                "action": resolution_event["action"],
                "input": resolution_event["input"],
                "decision": resolution_event["decision"],
                "output": resolution_event["output"],
                "communicates_to": resolution_event["communicates_to"],
                "metrics": resolution_event["metrics"],
                "llm_calls": resolution_event.get("llm_calls", []),
                "llm_errors": resolution_event.get("llm_errors", []),
            },
            started_at=now,
            completed_at=datetime.now(timezone.utc),
        )
    )
    requires_human_approval = enriched_alert.severity in {AlertSeverity.HIGH, AlertSeverity.CRITICAL}
    recommendation_envelope = _build_local_metadata_envelope(
        event_type="incident.recommendation.generated",
        incident=incident.model_dump(mode="json"),
        alert=enriched_alert.model_dump(mode="json"),
        decision=decision.__dict__,
        status="awaiting_approval" if (requires_human_approval and not auto_approve) else "remediating",
        payload={
            "recommendation_id": str(recommendation.id),
            "flow_id": str(getattr(decision, "flow_id", "") or ""),
            "trace_id": str(trace_id or ""),
            "recommended_action": recommendation.recommended_action,
            "root_cause": recommendation.root_cause,
            "impact": recommendation.impact,
            "risk": recommendation.risk,
        },
        confidence=float(recommendation.confidence),
        model_provider=(model_usage[0].get("provider") if model_usage else None),
        model_name=(model_usage[0].get("model") if model_usage else None),
        fallback_reason=(model_errors[0].get("error") if model_errors else None),
        transport_provider=decision.message_bus_provider,
    )
    await persist_step(track_metadata_event_operation(recommendation_envelope))
    finops = build_finops_summary(model_usage, model_errors)

    if requires_human_approval and not auto_approve:
        pending_approval = Approval(
            incident_id=incident.id,
            recommendation_id=recommendation.id,
            decision=ApprovalDecision.PENDING,
            approver=None,
            channel="web",
            comment=scenario["remediation_comment"],
            trace_id=trace_id,
            metadata={
                "policy_version": decision.policy_version,
                "policy_reason": decision.policy_reason,
                "orchestration_decision": recommendation.metadata.get("orchestration_decision", {}),
            },
        )
        approval_event = {
            "sequence": 5,
            "agent": "Human Approval Layer",
            "action": "Paused workflow for user approval",
            "input": {
                "incident_id": incident.id,
                "recommendation_id": recommendation.id,
                "recommended_action": recommendation.recommended_action,
                "channel": pending_approval.channel,
                "workflow": decision.workflow,
                "trace_id": trace_id,
            },
            "decision": pending_approval.decision.value,
            "output": "Awaiting explicit user decision in Approval Workbench",
            "communicates_to": "Approval Workbench",
            "metrics": {"approval_required": True, "channel": pending_approval.channel},
        }
        await persist_step(
            lambda repo: repo.save_approval(pending_approval),
            track_agent_work_operation(
                incident_id=incident.id,
                agent_name="Human Approval Layer",
                work_item="Await user approval decision",
                status="pending",
                sequence=5,
                trace_id=trace_id,
                ticket_id=incident.ticket_id,
                details={
                    "action": approval_event["action"],
                    "input": approval_event["input"],
                    "decision": approval_event["decision"],
                    "output": approval_event["output"],
                    "communicates_to": approval_event["communicates_to"],
                    "metrics": approval_event["metrics"],
                },
                started_at=now,
                completed_at=None,
            ),
        )

        metrics = {
            "alerts_processed": 1,
            "deduplicated_count": enriched_alert.deduplicated_count,
            "severity": enriched_alert.severity.value,
            "related_incidents": len(context.related_incidents),
            "dependency_services": len(context.dependency_services),
            "recent_changes": len(context.recent_changes),
            "recommendation_confidence": recommendation.confidence,
            "agent_handoffs": 4,
            "approval_required": True,
            "remediation_status": "pending_approval",
            "health_restored": False,
            "alerts_cleared": False,
        }

        base_events = [alert_event, orchestrator_event, context_event, resolution_event]
        pending_payload = {
            "flow_id": flow_id,
            "trace_id": trace_id,
            "scenario": {
                "id": flow_id,
                "title": scenario["title"],
                "recommended_action": recommendation.recommended_action,
            },
            "alert": enriched_alert.model_dump(mode="json"),
            "incident": incident.model_dump(mode="json"),
            "decision": decision.__dict__,
            "context": context.model_dump(mode="json"),
            "recommendation": recommendation.model_dump(mode="json"),
            "events_base": base_events,
            "metrics_base": {
                "alerts_processed": 1,
                "deduplicated_count": enriched_alert.deduplicated_count,
                "severity": enriched_alert.severity.value,
                "related_incidents": len(context.related_incidents),
                "dependency_services": len(context.dependency_services),
                "recent_changes": len(context.recent_changes),
                "recommendation_confidence": recommendation.confidence,
                "approval_required": True,
            },
            "finops": finops,
            "ticket_id": incident.ticket_id,
            "service": incident.service,
        }
        incident_id_str = str(incident.id)
        recommendation_id_str = str(recommendation.id)
        safe_pending_payload = _json_safe(pending_payload)
        await _save_pending_workflow_to_db(
            incident_id=incident_id_str,
            recommendation_id=recommendation_id_str,
            flow_id=flow_id,
            trace_id=trace_id,
            payload=safe_pending_payload,
        )

        return {
            "mode": "local-no-kafka",
            "scenario": {
                "id": flow_id,
                "title": scenario["title"],
                "recommended_action": recommendation.recommended_action,
            },
            "alert": enriched_alert.model_dump(mode="json"),
            "incident": incident.model_dump(mode="json"),
            "decision": decision.__dict__,
            "context": context.model_dump(mode="json"),
            "recommendation": recommendation.model_dump(mode="json"),
            "approval": pending_approval.model_dump(mode="json"),
            "remediation_action": {},
            "closure_report": {},
            "metrics": metrics,
            "finops": finops,
            "events": base_events + [approval_event],
            "next_step": "Awaiting user approval for high-risk action. Approve in Approval tab to continue workflow.",
        }

    approval = Approval(
        incident_id=incident.id,
        recommendation_id=recommendation.id,
        decision=ApprovalDecision.APPROVED,
        approver="kaiops-demo",
        channel="web",
        comment=scenario["remediation_comment"],
        trace_id=trace_id,
        metadata={
            "policy_version": decision.policy_version,
            "policy_reason": decision.policy_reason,
            "orchestration_decision": recommendation.metadata.get("orchestration_decision", {}),
            "service": context.alert.service,
            "incident_service": context.alert.service,
            "environment": context.alert.environment,
            "remediation_target": recommendation.metadata.get("remediation_target") or context.alert.service,
            "target": recommendation.metadata.get("remediation_target") or context.alert.service,
            "recommended_action": recommendation.recommended_action,
            "recommended_commands": recommendation.commands,
        },
    )
    await persist_step(lambda repo: repo.save_approval(approval))
    approval_event = {
        "sequence": 5,
        "agent": "Human Approval Layer",
        "action": "Auto-approved low-risk recommendation",
        "input": {
            "incident_id": incident.id,
            "recommendation_id": recommendation.id,
            "recommended_action": recommendation.recommended_action,
            "channel": approval.channel,
            "workflow": decision.workflow,
            "trace_id": trace_id,
        },
        "decision": approval.decision.value,
        "output": f"Approved by {approval.approver} on {approval.channel}",
        "communicates_to": "Remediation Automation Engine via approval-events",
        "metrics": {"approval_required": False, "channel": approval.channel},
    }
    await persist_step(
        track_agent_work_operation(
            incident_id=incident.id,
            agent_name="Human Approval Layer",
            work_item="Review and approve recommendation",
            status="completed",
            sequence=5,
            trace_id=trace_id,
            ticket_id=incident.ticket_id,
            details={
                "action": approval_event["action"],
                "input": approval_event["input"],
                "decision": approval_event["decision"],
                "output": approval_event["output"],
                "communicates_to": approval_event["communicates_to"],
                "metrics": approval_event["metrics"],
            },
            started_at=now,
            completed_at=datetime.now(timezone.utc),
        )
    )
    engine = RemediationEngine()
    action = engine.build_action(approval)
    action.parameters.update({"root_cause": recommendation.root_cause, "impact": recommendation.impact})
    action = await engine.execute(action)
    action.trace_id = trace_id
    await persist_step(
        lambda repo: repo.save_action(action),
        lambda repo: repo.save_action_audit(action),
    )
    remediation_event = {
        "sequence": 6,
        "agent": "Remediation Automation Engine",
        "action": "Executed remediation strategy plugin",
        "input": {
            "approval_id": approval.id,
            "comment": approval.comment,
            "action_type": action.action_type,
            "target": action.target,
            "trace_id": trace_id,
        },
        "decision": f"Selected plugin action {action.action_type}",
        "output": action.output,
        "communicates_to": "Closure & Validation via remediation-events",
        "metrics": {"status": action.status.value, "target": action.target},
    }
    await persist_step(
        track_agent_work_operation(
            incident_id=incident.id,
            agent_name="Remediation Automation Engine",
            work_item="Execute remediation strategy",
            status="completed" if action.status.value == "succeeded" else action.status.value,
            sequence=6,
            trace_id=trace_id,
            ticket_id=incident.ticket_id,
            details={
                "action": remediation_event["action"],
                "input": remediation_event["input"],
                "decision": remediation_event["decision"],
                "output": remediation_event["output"],
                "communicates_to": remediation_event["communicates_to"],
                "metrics": remediation_event["metrics"],
            },
            started_at=now,
            completed_at=datetime.now(timezone.utc),
        )
    )
    closure_report = await ClosureValidationAgent().validate(action)
    closure_report.trace_id = trace_id
    await persist_step(
        lambda repo: repo.save_report(closure_report),
        lambda repo: repo.save_knowledge_base(closure_report, service=incident.service),
    )
    closure_event = {
        "sequence": 7,
        "agent": "Closure & Validation",
        "action": "Validated health and generated closure report",
        "input": {
            "remediation_action_id": action.id,
            "status": action.status.value,
            "output": action.output,
            "trace_id": trace_id,
        },
        "decision": "Health restored" if closure_report.health_restored else "Health not restored",
        "output": closure_report.knowledge_base_entry,
        "communicates_to": "Knowledge Base and audit log",
        "metrics": {
            "alerts_cleared": closure_report.alerts_cleared,
            "health_restored": closure_report.health_restored,
        },
    }
    await persist_step(
        track_agent_work_operation(
            incident_id=incident.id,
            agent_name="Closure & Validation",
            work_item="Validate recovery and close incident",
            status="completed" if closure_report.health_restored else "failed",
            sequence=7,
            trace_id=trace_id,
            ticket_id=incident.ticket_id,
            details={
                "action": closure_event["action"],
                "input": closure_event["input"],
                "decision": closure_event["decision"],
                "output": closure_event["output"],
                "communicates_to": closure_event["communicates_to"],
                "metrics": closure_event["metrics"],
            },
            started_at=now,
            completed_at=datetime.now(timezone.utc),
        )
    )
    metrics = {
        "alerts_processed": 1,
        "deduplicated_count": enriched_alert.deduplicated_count,
        "severity": enriched_alert.severity.value,
        "related_incidents": len(context.related_incidents),
        "dependency_services": len(context.dependency_services),
        "recent_changes": len(context.recent_changes),
        "recommendation_confidence": recommendation.confidence,
        "agent_handoffs": 6,
        "approval_required": False,
        "remediation_status": action.status.value,
        "health_restored": closure_report.health_restored,
        "alerts_cleared": closure_report.alerts_cleared,
    }

    final_payload = {
        "mode": "local-no-kafka",
        "scenario": {
            "id": flow_id,
            "title": scenario["title"],
            "recommended_action": recommendation.recommended_action,
        },
        "alert": enriched_alert.model_dump(mode="json"),
        "incident": incident.model_dump(mode="json"),
        "decision": decision.__dict__,
        "context": context.model_dump(mode="json"),
        "recommendation": recommendation.model_dump(mode="json"),
        "approval": approval.model_dump(mode="json"),
        "remediation_action": action.model_dump(mode="json"),
        "closure_report": closure_report.model_dump(mode="json"),
        "metrics": metrics,
        "finops": finops,
        "events": [
            alert_event,
            orchestrator_event,
            context_event,
            resolution_event,
            approval_event,
            remediation_event,
            closure_event,
        ],
        "next_step": "Incident closed in local demo. Review closure report and lessons learned.",
    }
    _record_closed_incident(
        scenario=final_payload.get("scenario", {}),
        incident=final_payload.get("incident", {}),
        recommendation=final_payload.get("recommendation", {}),
        remediation_action=final_payload.get("remediation_action", {}),
        closure_report=final_payload.get("closure_report", {}),
        metrics=final_payload.get("metrics", {}),
        trace_id=trace_id,
    )
    closure_envelope = _build_local_metadata_envelope(
        event_type="incident.closed",
        incident=final_payload.get("incident", {}),
        alert=final_payload.get("alert", {}),
        decision=final_payload.get("decision", {}),
        status="closed" if bool(closure_report.health_restored) else "failed",
        payload={
            "action_type": action.action_type,
            "action_status": action.status.value,
            "health_restored": bool(closure_report.health_restored),
            "alerts_cleared": bool(closure_report.alerts_cleared),
        },
        confidence=float(recommendation.confidence),
        model_provider=(model_usage[0].get("provider") if model_usage else None),
        model_name=(model_usage[0].get("model") if model_usage else None),
        transport_provider=decision.message_bus_provider,
    )
    await persist_step(track_metadata_event_operation(closure_envelope))
    return final_payload


async def continue_pending_workflow(
    *,
    flow_id: str,
    incident_id: str,
    recommendation_id: str,
    decision_token: str,
    approver: str | None,
    channel: str | None,
    comment: str | None,
    modified_action: str | None,
    trace_id: str | None,
) -> dict[str, Any]:
    from closure_service import ClosureValidationAgent
    from remediation_engine import RemediationEngine

    incident_key = str(incident_id)
    persisted = await _load_pending_workflow_from_db(incident_key)
    pending: dict[str, Any] | None = None
    if persisted and str(persisted.get("status") or "").strip().lower() == "completed":
        completed_payload = persisted.get("completed_payload") if isinstance(persisted.get("completed_payload"), dict) else None
        if completed_payload:
            return completed_payload
    if persisted and isinstance(persisted.get("payload"), dict):
        pending = persisted.get("payload", {})

    if not pending:
        raise HTTPException(status_code=404, detail="No pending workflow found for incident")

    if str(pending.get("flow_id")) != str(flow_id):
        raise HTTPException(status_code=400, detail="Flow ID does not match pending workflow")

    recommendation_data = pending.get("recommendation", {})
    if str(recommendation_data.get("id", "")) != str(recommendation_id):
        raise HTTPException(status_code=400, detail="Recommendation ID does not match pending workflow")

    token = str(decision_token or "").strip().lower()
    decision_map = {
        "approve": ApprovalDecision.APPROVED,
        "approved": ApprovalDecision.APPROVED,
        "reject": ApprovalDecision.REJECTED,
        "rejected": ApprovalDecision.REJECTED,
        "modify": ApprovalDecision.MODIFIED,
        "modified": ApprovalDecision.MODIFIED,
    }
    approval_decision = decision_map.get(token)
    if approval_decision is None:
        raise HTTPException(status_code=400, detail="Invalid approval decision")

    approval_trace_id = trace_id or str(pending.get("trace_id") or "") or None
    incident_uuid = UUID(str(incident_id))
    recommendation_uuid = UUID(str(recommendation_id))

    async def persist_step(*operations: Any) -> None:
        session_factory = getattr(app.state, "session_factory", None)
        engine = None
        if not settings.database_enabled:
            return
        if session_factory is None:
            engine = create_engine(settings)
            session_factory = create_session_factory(engine)
            await create_schema(engine)
        try:
            async with session_factory() as session:
                repo = IncidentRepository(session)
                for operation in operations:
                    await operation(repo)
                await session.commit()
        finally:
            if engine is not None:
                await engine.dispose()

    def track_agent_work_operation(
        *,
        incident_id_value: Any,
        agent_name: str,
        work_item: str,
        status: str,
        sequence: int,
        trace_id_value: str | None,
        ticket_id: str | None,
        details: dict[str, Any] | None = None,
        started_at: datetime | None = None,
        completed_at: datetime | None = None,
    ):
        async def _operation(repo: IncidentRepository) -> None:
            await repo.save_agent_work_item(
                incident_id=incident_id_value,
                agent_name=agent_name,
                work_item=work_item,
                status=status,
                sequence=sequence,
                trace_id=trace_id_value,
                ticket_id=ticket_id,
                details=details or {},
                started_at=started_at,
                completed_at=completed_at,
            )

        return _operation

    incident_data = pending.get("incident", {}) if isinstance(pending.get("incident"), dict) else {}
    recommendation_metadata = recommendation_data.get("metadata", {}) if isinstance(recommendation_data.get("metadata"), dict) else {}
    recommended_commands = recommendation_data.get("commands") if isinstance(recommendation_data.get("commands"), list) else []
    approval = Approval(
        incident_id=incident_uuid,
        recommendation_id=recommendation_uuid,
        decision=approval_decision,
        approver=(approver or "sre@example.com").strip() or "sre@example.com",
        channel=(channel or "web").strip() or "web",
        comment=(comment or "").strip() or None,
        modified_action=(modified_action or "").strip() or None,
        trace_id=approval_trace_id,
        metadata={
            "service": str(
                incident_data.get("service")
                or pending.get("service")
                or recommendation_metadata.get("service")
                or ""
            ).strip(),
            "incident_service": str(
                incident_data.get("service")
                or pending.get("service")
                or recommendation_metadata.get("service")
                or ""
            ).strip(),
            "environment": str(
                incident_data.get("environment")
                or recommendation_metadata.get("environment")
                or "prod"
            ).strip(),
            "remediation_target": str(
                recommendation_metadata.get("remediation_target")
                or incident_data.get("deployment")
                or incident_data.get("service")
                or pending.get("service")
                or ""
            ).strip(),
            "target": str(
                recommendation_metadata.get("remediation_target")
                or incident_data.get("deployment")
                or incident_data.get("service")
                or pending.get("service")
                or ""
            ).strip(),
            "recommended_action": str(
                recommendation_data.get("recommended_action")
                or recommendation_data.get("action")
                or ""
            ).strip(),
            "recommended_commands": [
                str(item).strip() for item in recommended_commands if str(item).strip()
            ],
        },
    )

    now = datetime.now(timezone.utc)
    await persist_step(
        lambda repo: repo.save_approval(approval),
        track_agent_work_operation(
            incident_id_value=incident_uuid,
            agent_name="Human Approval Layer",
            work_item="Review and approve recommendation",
            status="completed",
            sequence=5,
            trace_id_value=approval_trace_id,
            ticket_id=str(pending.get("ticket_id") or "") or None,
            details={"decision": approval.decision.value, "channel": approval.channel},
            started_at=now,
            completed_at=datetime.now(timezone.utc),
        ),
    )

    service_name = str(incident_data.get("service") or pending.get("service") or "unknown")

    if approval.decision == ApprovalDecision.REJECTED:
        action = RemediationAction(
            incident_id=incident_uuid,
            approval_id=approval.id,
            action_type="manual-review",
            target=service_name,
            status=RemediationStatus.SKIPPED,
            output="Remediation skipped because approval was rejected.",
            trace_id=approval_trace_id,
        )
        closure_report = ResolutionReport(
            incident_id=incident_uuid,
            recommendation_id=recommendation_uuid,
            remediation_action_id=action.id,
            root_cause=str(recommendation_data.get("root_cause", "N/A")),
            impact=str(recommendation_data.get("impact", "N/A")),
            action_taken="Approval rejected",
            validation={"approval_rejected": True},
            alerts_cleared=False,
            health_restored=False,
            knowledge_base_entry="Workflow halted: recommendation rejected during approval.",
            lessons_learned=["High-risk action requires explicit approval before remediation."],
            trace_id=approval_trace_id,
        )
    else:
        engine = RemediationEngine()
        action = engine.build_action(approval)
        action.parameters.update(
            {
                "root_cause": str(recommendation_data.get("root_cause", "N/A")),
                "impact": str(recommendation_data.get("impact", "N/A")),
            }
        )
        if approval.decision == ApprovalDecision.MODIFIED and approval.modified_action:
            action.action_type = approval.modified_action
        action = await engine.execute(action)
        action.trace_id = approval_trace_id

        closure_report = await ClosureValidationAgent().validate(action)
        closure_report.trace_id = approval_trace_id

    await persist_step(
        lambda repo: repo.save_action(action),
        lambda repo: repo.save_report(closure_report),
        lambda repo: repo.save_knowledge_base(closure_report, service=service_name),
    )

    remediation_status = "completed" if action.status.value == "succeeded" else action.status.value
    await persist_step(
        track_agent_work_operation(
            incident_id_value=incident_uuid,
            agent_name="Remediation Automation Engine",
            work_item="Execute remediation strategy",
            status=remediation_status,
            sequence=6,
            trace_id_value=approval_trace_id,
            ticket_id=str(pending.get("ticket_id") or "") or None,
            details={"status": action.status.value, "target": action.target},
            started_at=now,
            completed_at=datetime.now(timezone.utc),
        ),
        track_agent_work_operation(
            incident_id_value=incident_uuid,
            agent_name="Closure & Validation",
            work_item="Validate recovery and close incident",
            status="completed" if closure_report.health_restored else "failed",
            sequence=7,
            trace_id_value=approval_trace_id,
            ticket_id=str(pending.get("ticket_id") or "") or None,
            details={
                "health_restored": closure_report.health_restored,
                "alerts_cleared": closure_report.alerts_cleared,
            },
            started_at=now,
            completed_at=datetime.now(timezone.utc),
        ),
    )

    approval_event = {
        "sequence": 5,
        "agent": "Human Approval Layer",
        "action": "User decision submitted from Approval Workbench",
        "input": {
            "incident_id": incident_id,
            "recommendation_id": recommendation_id,
            "channel": approval.channel,
            "comment": approval.comment,
            "trace_id": approval_trace_id,
        },
        "decision": approval.decision.value,
        "output": f"Decision by {approval.approver}",
        "communicates_to": "Remediation Automation Engine",
        "metrics": {"approval_required": True, "channel": approval.channel},
    }
    remediation_event = {
        "sequence": 6,
        "agent": "Remediation Automation Engine",
        "action": "Executed remediation strategy plugin",
        "input": {
            "approval_id": str(approval.id),
            "action_type": action.action_type,
            "target": action.target,
            "trace_id": approval_trace_id,
        },
        "decision": f"Selected plugin action {action.action_type}",
        "output": action.output,
        "communicates_to": "Closure & Validation via remediation-events",
        "metrics": {"status": action.status.value, "target": action.target},
    }
    closure_event = {
        "sequence": 7,
        "agent": "Closure & Validation",
        "action": "Validated health and generated closure report",
        "input": {
            "remediation_action_id": str(action.id),
            "status": action.status.value,
            "output": action.output,
            "trace_id": approval_trace_id,
        },
        "decision": "Health restored" if closure_report.health_restored else "Health not restored",
        "output": closure_report.knowledge_base_entry,
        "communicates_to": "Knowledge Base and audit log",
        "metrics": {
            "alerts_cleared": closure_report.alerts_cleared,
            "health_restored": closure_report.health_restored,
        },
    }

    metrics_base = pending.get("metrics_base", {}) if isinstance(pending.get("metrics_base"), dict) else {}
    final_incident_status = IncidentStatus.CLOSED if closure_report.health_restored else IncidentStatus.FAILED
    final_incident_payload = {
        **incident_data,
        "status": final_incident_status.value,
        "closed_at": datetime.now(timezone.utc).isoformat() if closure_report.health_restored else incident_data.get("closed_at"),
    }
    final_incident = Incident.model_validate(final_incident_payload)
    metrics = {
        **metrics_base,
        "agent_handoffs": 6,
        "approval_required": True,
        "remediation_status": action.status.value,
        "health_restored": closure_report.health_restored,
        "alerts_cleared": closure_report.alerts_cleared,
    }

    events_base = pending.get("events_base", []) if isinstance(pending.get("events_base"), list) else []
    final_payload = {
        "mode": "local-no-kafka",
        "scenario": pending.get("scenario", {}),
        "alert": pending.get("alert", {}),
        "incident": final_incident.model_dump(mode="json"),
        "decision": pending.get("decision", {}),
        "context": pending.get("context", {}),
        "recommendation": recommendation_data,
        "approval": approval.model_dump(mode="json"),
        "remediation_action": action.model_dump(mode="json"),
        "closure_report": closure_report.model_dump(mode="json"),
        "metrics": metrics,
        "finops": pending.get("finops", {}),
        "events": events_base + [approval_event, remediation_event, closure_event],
        "next_step": "Incident closed after user approval.",
    }
    _record_closed_incident(
        scenario=final_payload.get("scenario", {}),
        incident=final_payload.get("incident", {}),
        recommendation=final_payload.get("recommendation", {}),
        remediation_action=final_payload.get("remediation_action", {}),
        closure_report=final_payload.get("closure_report", {}),
        metrics=final_payload.get("metrics", {}),
        trace_id=approval_trace_id,
    )
    await persist_step(
        lambda repo: repo.save_incident(final_incident),
        lambda repo: repo.save_incident_event(
            _json_safe(
                _build_local_metadata_envelope(
                    event_type="incident.closed",
                    incident=final_payload.get("incident", {}),
                    alert=final_payload.get("alert", {}),
                    decision=final_payload.get("decision", {}),
                    status="closed" if bool(closure_report.health_restored) else "failed",
                    payload={
                        "approval_decision": approval.decision.value,
                        "action_type": action.action_type,
                        "action_status": action.status.value,
                        "health_restored": bool(closure_report.health_restored),
                        "alerts_cleared": bool(closure_report.alerts_cleared),
                    },
                    confidence=float(recommendation_data.get("confidence", 0.0) or 0.0),
                    transport_provider=str(final_payload.get("decision", {}).get("message_bus_provider") or "rabbitmq"),
                )
            )
        )
    )
    await _mark_pending_workflow_completed_in_db(incident_key, final_payload)
    return final_payload


def build_finops_summary(model_usage: list[dict[str, Any]], model_errors: list[dict[str, str]]) -> dict[str, Any]:
    totals = {
        "input_tokens": sum(int(item.get("input_tokens", 0)) for item in model_usage),
        "output_tokens": sum(int(item.get("output_tokens", 0)) for item in model_usage),
        "total_tokens": sum(int(item.get("total_tokens", 0)) for item in model_usage),
        "total_cost_usd": round(sum(float(item.get("total_cost_usd", 0.0)) for item in model_usage), 8),
        "calls": len(model_usage),
        "failed_calls": len(model_errors),
    }
    by_provider: dict[str, dict[str, Any]] = {}
    for item in model_usage:
        provider = str(item.get("provider", "unknown"))
        row = by_provider.setdefault(
            provider,
            {"provider": provider, "calls": 0, "total_tokens": 0, "total_cost_usd": 0.0},
        )
        row["calls"] += 1
        row["total_tokens"] += int(item.get("total_tokens", 0))
        row["total_cost_usd"] = round(float(row["total_cost_usd"]) + float(item.get("total_cost_usd", 0.0)), 8)
    return {
        "totals": totals,
        "by_provider": list(by_provider.values()),
        "calls": model_usage,
        "errors": model_errors,
        "currency": "USD",
    }


def _record_closed_incident(
    *,
    scenario: dict[str, Any],
    incident: dict[str, Any],
    recommendation: dict[str, Any],
    remediation_action: dict[str, Any],
    closure_report: dict[str, Any],
    metrics: dict[str, Any],
    trace_id: str | None,
) -> None:
    recommendation_metadata = recommendation.get("metadata", {}) if isinstance(recommendation.get("metadata"), dict) else {}
    orchestration_decision = (
        recommendation_metadata.get("orchestration_decision", {})
        if isinstance(recommendation_metadata.get("orchestration_decision"), dict)
        else {}
    )
    CLOSED_INCIDENTS.appendleft(
        {
            "incident_id": str(closure_report.get("incident_id") or incident.get("id") or ""),
            "flow_id": str(scenario.get("id") or ""),
            "title": str(scenario.get("title") or incident.get("title") or "Incident"),
            "service": str(incident.get("service") or "unknown"),
            "severity": str(metrics.get("severity") or incident.get("severity") or "unknown").upper(),
            "risk": str(recommendation.get("risk") or "unknown").upper(),
            "risk_tier": str(orchestration_decision.get("risk_tier") or "unknown").upper(),
            "execution_mode": str(orchestration_decision.get("execution_mode") or "unknown").lower(),
            "transport_provider": str(orchestration_decision.get("message_bus_provider") or "unknown").lower(),
            "status": "closed" if bool(closure_report.get("health_restored")) else "failed",
            "decision": str(recommendation.get("recommended_action") or "N/A"),
            "action_type": str(remediation_action.get("action_type") or "N/A"),
            "action_status": str(remediation_action.get("status") or "N/A"),
            "health_restored": bool(closure_report.get("health_restored")),
            "alerts_cleared": bool(closure_report.get("alerts_cleared")),
            "root_cause": str(closure_report.get("root_cause") or "N/A"),
            "impact": str(closure_report.get("impact") or "N/A"),
            "trace_id": str(trace_id or closure_report.get("trace_id") or ""),
            "closed_at": datetime.now(timezone.utc).isoformat(),
        }
    )


def _severity_to_support_tier(severity: str) -> str:
    """Maps severity to a first-line (L1) vs specialist-escalation (L2/L3)
    support tier, for display/filtering only — no notification or assignment
    routing yet. "L1" corresponds to the existing SystemRole.L1_OPERATOR
    role; "L2/L3" corresponds to L2_ENGINEER + L3_ENGINEER combined (this
    project doesn't currently split severity between L2 and L3 individually).
    Critical/high alerts skip straight to L2/L3 since they need a specialist
    right away; warning/info are routine enough for L1 to triage first.
    """
    normalized = str(severity or "").strip().lower()
    if normalized in {"critical", "high"}:
        return "L2/L3"
    return "L1"


def _build_alert_from_payload(payload: dict[str, Any], trace_id: str | None = None) -> Alert:
    trace_id = trace_id or uuid.uuid4().hex
    labels = dict(payload.get("labels", {}) if isinstance(payload.get("labels"), dict) else {})
    annotations = payload.get("annotations", {}) if isinstance(payload.get("annotations"), dict) else {}
    severity_value = severity_from_string(str(payload.get("severity", labels.get("severity", "warning"))))

    alert_name = str(payload.get("name", payload.get("alertname", labels.get("alertname", "unknown-alert")))).strip().lower()
    service_name = str(payload.get("service", labels.get("service", labels.get("job", "")))).strip().lower()
    environment_name = str(payload.get("environment", labels.get("env", labels.get("environment", "")))).strip().lower()
    for rule in load_alert_severity_overrides():
        if not isinstance(rule, dict):
            continue
        rule_name = str(rule.get("name") or "").strip().lower()
        rule_service = str(rule.get("service") or "").strip().lower()
        rule_environment = str(rule.get("environment") or "").strip().lower()
        if not rule_name or rule_name != alert_name:
            continue
        if rule_service and rule_service != service_name:
            continue
        if rule_environment and rule_environment != environment_name:
            continue
        severity_value = severity_from_string(str(rule.get("severity") or severity_value))
        break

    labels.setdefault("support_tier", _severity_to_support_tier(severity_value))

    return Alert(
        source=payload.get("source", payload.get("generatorURL", "unknown")),
        name=payload.get("name", payload.get("alertname", labels.get("alertname", "unknown-alert"))),
        service=payload.get("service", labels.get("service", labels.get("job", "unknown"))),
        environment=payload.get("environment", labels.get("env", labels.get("environment", "prod"))),
        severity=AlertSeverity(severity_value),
        description=payload.get("description", annotations.get("summary", "")),
        labels=labels,
        annotations=annotations,
        correlation_id=str(payload.get("correlation_id") or labels.get("incident_correlation_id") or "") or None,
        trace_id=trace_id,
    )


async def _publish_ingested_alert(alert: Alert, *, topic: str = RAW_ALERTS) -> None:
    payload = _build_raw_alert_event_payload(alert)
    started = perf_counter()
    await app.state.producer.publish(topic, payload, key=alert.service)
    EVENT_PUBLISH_LATENCY.labels(settings.service_name, topic, "monitoring-adapter").observe(
        max(0.0, perf_counter() - started)
    )
    EVENT_CONTRACTS_EMITTED.labels(settings.service_name, topic, "monitoring-adapter", "v1").inc()
    RECENT_ALERTS.appendleft(
        {
            "id": str(alert.id),
            "trace_id": alert.trace_id,
            "source": alert.source,
            "name": alert.name,
            "service": alert.service,
            "environment": alert.environment,
            "severity": alert.severity.value,
            "description": alert.description,
            "labels": alert.labels,
            "annotations": alert.annotations,
            "created_at": alert.created_at.isoformat(),
        }
    )


def _build_raw_alert_event_payload(alert: Alert) -> dict[str, Any]:
    incident_hint = str(alert.id)
    source_event_id = str(
        alert.labels.get("source_event_id")
        or alert.labels.get("opensearch_document_id")
        or alert.labels.get("email_message_id")
        or alert.labels.get("jira_issue_id")
        or alert.id
    )
    fingerprint = str(
        alert.fingerprint
        or compute_fingerprint(
            {
                "name": alert.name,
                "service": alert.service,
                "environment": alert.environment,
                "labels": alert.labels,
            }
        )
    )
    raw_payload_ref = str(
        alert.labels.get("landing_pad_ref")
        or alert.labels.get("log_source_path")
        or alert.annotations.get("generatorURL")
        or f"landing-pad://{source_event_id}"
    )
    idempotency_key = hashlib.sha256(
        f"raw-alert|{alert.source}|{source_event_id}|{fingerprint}".encode()
    ).hexdigest()
    raw_alert = RawAlert(
        event_id=incident_hint,
        source_event_id=source_event_id,
        idempotency_key=idempotency_key,
        source=alert.source,
        source_type=str(alert.labels.get("source_type") or alert.source),
        application=str(alert.labels.get("application") or alert.labels.get("project_name") or alert.service),
        service=alert.service,
        environment=alert.environment,
        observed_severity=alert.severity,
        title=alert.name,
        description=alert.description,
        observed_at=alert.starts_at,
        raw_payload_ref=raw_payload_ref,
        fingerprint=fingerprint,
        labels={str(key): str(value) for key, value in alert.labels.items()},
        annotations={str(key): str(value) for key, value in alert.annotations.items()},
        evidence=[
            EvidenceReference(
                evidence_id=f"source:{source_event_id}",
                source=alert.source,
                uri=raw_payload_ref,
                summary=alert.description[:1000],
                observed_at=alert.starts_at,
            )
        ],
        trace_id=alert.trace_id,
    )
    event_contract = build_agent_event_contract(
        flow_id=incident_hint,
        incident_id=incident_hint,
        trace_id=str(alert.trace_id or ""),
        correlation_id=str(alert.correlation_id or "") or None,
        agent="monitoring-adapter",
        payload={
            "source": alert.source,
            "name": alert.name,
            "service": alert.service,
            "severity": alert.severity.value,
            "topic": RAW_ALERTS,
        },
        metadata={
            "environment": alert.environment,
        },
        confidence=1.0,
        reasoning="raw alert accepted by monitoring adapter ingestion endpoint",
        citations=[f"alert://{alert.id}"],
        evidence_ids=[f"alert:{alert.id}"],
    )
    return {
        "alert": alert,
        "raw_alert": raw_alert,
        "event_id": raw_alert.event_id,
        "source_event_id": source_event_id,
        "trace_id": alert.trace_id,
        "idempotency_key": idempotency_key,
        "event_contract": event_contract,
    }


def _normalize_slug(token: str) -> str:
    return re.sub(r"[^a-z0-9_-]", "-", str(token or "").strip().lower())


def _db_required() -> Any:
    session_factory = getattr(app.state, "session_factory", None)
    if not settings.database_enabled or session_factory is None:
        raise HTTPException(status_code=503, detail="Database is required for monitoring integrations")
    return session_factory


def _merge_raw_and_labels(payload: dict[str, Any]) -> dict[str, Any]:
    raw = payload.get("rawPayload") if isinstance(payload.get("rawPayload"), dict) else {}
    labels = payload.get("labels") if isinstance(payload.get("labels"), dict) else {}
    return {**raw, **labels}


async def _publish_lifecycle_events(normalized: dict[str, Any], trace_id: str | None = None) -> None:
    event_payload = {
        "trace_id": str(trace_id or normalized.get("trace_id") or ""),
        "provider": normalized.get("provider"),
        "application": normalized.get("application"),
        "environment": normalized.get("environment"),
        "severity": normalized.get("severity"),
        "alert_name": normalized.get("alertName"),
        "resource": normalized.get("resource"),
        "labels": normalized.get("labels", {}),
        "annotations": normalized.get("annotations", {}),
        "normalized": normalized,
        "ts": datetime.now(timezone.utc).isoformat(),
    }
    for topic in (
        ALERT_RECEIVED,
        ALERT_NORMALIZED,
        ALERT_CONTEXT_REQUESTED,
        ALERT_RCA_REQUESTED,
        RESOLUTION_GENERATED,
        APPROVAL_REQUESTED,
        AUTOMATION_EXECUTED,
    ):
        started = perf_counter()
        await app.state.producer.publish(topic, event_payload, key=str(normalized.get("application") or "unknown"))
        EVENT_PUBLISH_LATENCY.labels(settings.service_name, topic, "monitoring-adapter").observe(
            max(0.0, perf_counter() - started)
        )
        EVENT_CONTRACTS_EMITTED.labels(settings.service_name, topic, "monitoring-adapter", "v1").inc()


async def _persist_monitoring_audit(
    *,
    tenant_id: str,
    actor: str,
    action: str,
    provider: str | None,
    outcome: str,
    message: str,
    payload: dict[str, Any],
    integration_id: str | None = None,
) -> None:
    session_factory = getattr(app.state, "session_factory", None)
    if not settings.database_enabled or session_factory is None:
        return
    async with session_factory() as session:
        repo = IncidentRepository(session)
        await repo.save_monitoring_connection_audit(
            audit_id=str(uuid.uuid4()),
            integration_id=integration_id,
            tenant_id=tenant_id,
            actor=actor,
            action=action,
            provider=provider,
            outcome=outcome,
            message=message,
            payload=payload,
        )
        await session.commit()


async def _persist_received_and_normalized(
    *,
    tenant_id: str,
    provider: str,
    integration_id: str | None,
    payload: dict[str, Any],
    normalized: dict[str, Any],
    signature_valid: bool,
    auth_valid: bool,
) -> tuple[str, str]:
    session_factory = _db_required()
    received_id = str(uuid.uuid4())
    normalized_id = str(uuid.uuid4())
    provider_alert_id = str(payload.get("id") or payload.get("alert_id") or payload.get("fingerprint") or "").strip() or None
    dedupe_seed = f"{provider}:{provider_alert_id or normalized.get('alertName') or ''}:{normalized.get('resource') or ''}"
    dedupe_key = uuid.uuid5(uuid.NAMESPACE_OID, dedupe_seed).hex
    async with session_factory() as session:
        repo = IncidentRepository(session)
        await repo.save_monitoring_received_alert(
            received_alert_id=received_id,
            integration_id=integration_id,
            tenant_id=tenant_id,
            provider=provider,
            provider_alert_id=provider_alert_id,
            dedupe_key=dedupe_key,
            signature_valid=signature_valid,
            auth_valid=auth_valid,
            status="received",
            raw_payload=payload,
        )
        await repo.save_monitoring_normalized_alert(
            normalized_alert_id=normalized_id,
            received_alert_id=received_id,
            integration_id=integration_id,
            tenant_id=tenant_id,
            provider=provider,
            application=str(normalized.get("application") or "unknown-app"),
            environment=str(normalized.get("environment") or "prod"),
            severity=str(normalized.get("severity") or "warning"),
            alert_name=str(normalized.get("alertName") or "provider-alert"),
            resource=str(normalized.get("resource") or "unknown"),
            labels=normalized.get("labels", {}),
            annotations=normalized.get("annotations", {}),
            normalized_payload=normalized,
        )
        await session.commit()
    return received_id, normalized_id


def _integration_health_snapshot(
    *,
    provider: str,
    validation: dict[str, Any],
    test_ok: bool = True,
    detail: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload = {
        "provider": provider,
        "validation": validation,
        "detail": detail or {},
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    return {
        "status": "healthy" if test_ok and bool(validation.get("valid", False)) else "degraded",
        "connectivity_ok": bool(validation.get("connectivity", False)),
        "authentication_ok": bool(validation.get("authentication", False)),
        "webhook_ok": bool(validation.get("alertmanager", False) or validation.get("api", False)),
        "payload": payload,
    }


@app.get("/monitoring/providers")
async def list_monitoring_providers() -> dict[str, Any]:
    rows = [
        {
            "id": provider,
            "name": provider.replace("_", " ").title(),
            "category": "existing_monitoring",
            "capabilities": ["connect", "validate", "discover", "webhook", "normalize"],
        }
        for provider in (
            "prometheus",
            "grafana",
            "datadog",
            "new_relic",
            "dynatrace",
            "azure_monitor",
            "splunk",
            "nagios",
            "zabbix",
            "elastic",
        )
    ]
    return {"rows": rows, "count": len(rows)}


@app.get("/monitoring/integrations")
async def list_monitoring_integrations(tenant_id: str = "default") -> dict[str, Any]:
    session_factory = _db_required()
    async with session_factory() as session:
        repo = IncidentRepository(session)
        rows = await repo.list_monitoring_integrations(tenant_id=tenant_id)
    return {"rows": rows, "count": len(rows)}


@app.post("/monitoring/integrations")
async def create_monitoring_integration(payload: dict[str, Any] = ALERT_BODY) -> dict[str, Any]:
    session_factory = _db_required()
    provider = normalize_provider_name(str(payload.get("provider") or ""))
    integration_id = str(payload.get("id") or uuid.uuid4())
    tenant_id = str(payload.get("tenant_id") or "default")
    project_name = str(payload.get("project_name") or "untitled-project").strip() or "untitled-project"
    auth_type = str(payload.get("auth_type") or "api_key").strip() or "api_key"
    endpoint_url = str(payload.get("endpoint_url") or payload.get("server_url") or "").strip() or None
    deployment_mode = str(payload.get("deployment_mode") or "existing_monitoring").strip() or "existing_monitoring"
    config_payload = payload.get("config", {}) if isinstance(payload.get("config"), dict) else {}
    credentials = payload.get("credentials", {}) if isinstance(payload.get("credentials"), dict) else {}
    adapter = get_provider_adapter(provider)
    validation = adapter.validate(config_payload, credentials)
    webhook_path = str(payload.get("webhook_path") or build_webhook_path(provider)).strip()
    async with session_factory() as session:
        repo = IncidentRepository(session)
        await repo.save_monitoring_integration(
            integration_id=integration_id,
            tenant_id=tenant_id,
            project_name=project_name,
            provider=provider,
            status="validated" if validation.get("valid") else "draft",
            active=bool(payload.get("active", False)),
            auth_type=auth_type,
            endpoint_url=endpoint_url,
            webhook_path=webhook_path,
            deployment_mode=deployment_mode,
            config_payload=config_payload,
            validation_payload=validation,
        )
        await repo.save_monitoring_credential(
            credential_id=str(uuid.uuid4()),
            integration_id=integration_id,
            credential_type=auth_type,
            secret_ref=str(payload.get("secret_ref") or f"secret://monitoring/{integration_id}"),
            encrypted_payload=hash_secrets(credentials),
            redacted_payload=mask_secrets(credentials),
        )
        await repo.save_monitoring_webhook_endpoint(
            endpoint_id=str(uuid.uuid4()),
            integration_id=integration_id,
            provider=provider,
            webhook_path=webhook_path,
            token_hash=(hash_secrets({"token": str(payload.get("webhook_token") or "")}).get("token") or None),
            hmac_enabled=bool(payload.get("hmac_enabled", False)),
            m_tls_enabled=bool(payload.get("m_tls_enabled", False)),
            active=True,
            metadata_payload={"created_via": "monitoring-api"},
        )
        mappings_payload = payload.get("mappings") if isinstance(payload.get("mappings"), list) else default_field_mappings()
        mappings_saved = await repo.replace_monitoring_alert_mappings(
            integration_id=integration_id,
            provider=provider,
            mappings=mappings_payload,
        )
        health = _integration_health_snapshot(provider=provider, validation=validation)
        await repo.save_monitoring_connection_health(
            health_id=str(uuid.uuid4()),
            integration_id=integration_id,
            provider=provider,
            status=health["status"],
            connectivity_ok=health["connectivity_ok"],
            authentication_ok=health["authentication_ok"],
            webhook_ok=health["webhook_ok"],
            last_received_alert_at=None,
            last_successful_test_at=datetime.now(timezone.utc),
            rate_limit_remaining=None,
            payload=health["payload"],
        )
        await session.commit()

    await _persist_monitoring_audit(
        tenant_id=tenant_id,
        actor="api",
        action="integration.create",
        provider=provider,
        outcome="success",
        message="Monitoring integration created",
        payload={"integration_id": integration_id, "mappings_saved": mappings_saved},
        integration_id=integration_id,
    )

    return {
        "id": integration_id,
        "tenant_id": tenant_id,
        "provider": provider,
        "project_name": project_name,
        "webhook_path": webhook_path,
        "status": "validated" if validation.get("valid") else "draft",
        "validation": validation,
    }


@app.get("/monitoring/integrations/{integration_id}")
async def get_monitoring_integration(integration_id: str) -> dict[str, Any]:
    session_factory = _db_required()
    async with session_factory() as session:
        repo = IncidentRepository(session)
        row = await repo.get_monitoring_integration(integration_id)
        if row is None:
            raise HTTPException(status_code=404, detail="Monitoring integration not found")
        mappings = await repo.list_monitoring_alert_mappings(integration_id)
    row["mappings"] = mappings
    return row


@app.put("/monitoring/integrations/{integration_id}")
async def update_monitoring_integration(integration_id: str, payload: dict[str, Any] = ALERT_BODY) -> dict[str, Any]:
    session_factory = _db_required()
    async with session_factory() as session:
        repo = IncidentRepository(session)
        existing = await repo.get_monitoring_integration(integration_id)
        if existing is None:
            raise HTTPException(status_code=404, detail="Monitoring integration not found")
        provider = normalize_provider_name(str(payload.get("provider") or existing.get("provider") or ""))
        adapter = get_provider_adapter(provider)
        config_payload = payload.get("config_payload", existing.get("config_payload", {}))
        if not isinstance(config_payload, dict):
            config_payload = {}
        credentials = payload.get("credentials", {}) if isinstance(payload.get("credentials"), dict) else {}
        validation = adapter.validate(config_payload, credentials)
        await repo.save_monitoring_integration(
            integration_id=integration_id,
            tenant_id=str(payload.get("tenant_id") or existing.get("tenant_id") or "default"),
            project_name=str(payload.get("project_name") or existing.get("project_name") or "untitled-project"),
            provider=provider,
            status=str(payload.get("status") or existing.get("status") or "validated"),
            active=bool(payload.get("active", existing.get("active", True))),
            auth_type=str(payload.get("auth_type") or existing.get("auth_type") or "api_key"),
            endpoint_url=str(payload.get("endpoint_url") or existing.get("endpoint_url") or "").strip() or None,
            webhook_path=str(payload.get("webhook_path") or existing.get("webhook_path") or build_webhook_path(provider)).strip(),
            deployment_mode=str(payload.get("deployment_mode") or existing.get("deployment_mode") or "existing_monitoring"),
            config_payload=config_payload,
            validation_payload=validation,
        )
        if isinstance(payload.get("mappings"), list):
            await repo.replace_monitoring_alert_mappings(
                integration_id=integration_id,
                provider=provider,
                mappings=payload.get("mappings", []),
            )
        await session.commit()

    await _persist_monitoring_audit(
        tenant_id=str(payload.get("tenant_id") or existing.get("tenant_id") or "default"),
        actor="api",
        action="integration.update",
        provider=provider,
        outcome="success",
        message="Monitoring integration updated",
        payload={"integration_id": integration_id},
        integration_id=integration_id,
    )
    return {"id": integration_id, "provider": provider, "validation": validation, "status": "updated"}


@app.delete("/monitoring/integrations/{integration_id}")
async def delete_monitoring_integration(integration_id: str) -> dict[str, Any]:
    session_factory = _db_required()
    async with session_factory() as session:
        repo = IncidentRepository(session)
        deleted = await repo.delete_monitoring_integration(integration_id)
        await session.commit()
    return {"id": integration_id, "deleted": deleted > 0}


@app.post("/monitoring/integrations/{integration_id}/validate")
async def validate_monitoring_integration(integration_id: str, payload: dict[str, Any] = ALERT_BODY) -> dict[str, Any]:
    session_factory = _db_required()
    async with session_factory() as session:
        repo = IncidentRepository(session)
        row = await repo.get_monitoring_integration(integration_id)
        if row is None:
            raise HTTPException(status_code=404, detail="Monitoring integration not found")
        provider = normalize_provider_name(str(row.get("provider") or ""))
        adapter = get_provider_adapter(provider)
        config_payload = payload.get("config") if isinstance(payload.get("config"), dict) else row.get("config_payload", {})
        credentials = payload.get("credentials") if isinstance(payload.get("credentials"), dict) else {}
        validation = adapter.validate(config_payload, credentials)
        health = _integration_health_snapshot(provider=provider, validation=validation)
        await repo.save_monitoring_connection_health(
            health_id=str(uuid.uuid4()),
            integration_id=integration_id,
            provider=provider,
            status=health["status"],
            connectivity_ok=health["connectivity_ok"],
            authentication_ok=health["authentication_ok"],
            webhook_ok=health["webhook_ok"],
            last_received_alert_at=None,
            last_successful_test_at=datetime.now(timezone.utc),
            rate_limit_remaining=None,
            payload=health["payload"],
        )
        await session.commit()
    return {"id": integration_id, "provider": provider, "validation": validation, "health": health}


@app.post("/monitoring/integrations/{integration_id}/discover")
async def discover_monitoring_objects(integration_id: str, payload: dict[str, Any] = ALERT_BODY) -> dict[str, Any]:
    session_factory = _db_required()
    async with session_factory() as session:
        repo = IncidentRepository(session)
        row = await repo.get_monitoring_integration(integration_id)
        if row is None:
            raise HTTPException(status_code=404, detail="Monitoring integration not found")
    provider = normalize_provider_name(str(row.get("provider") or ""))
    adapter = get_provider_adapter(provider)
    config_payload = payload.get("config") if isinstance(payload.get("config"), dict) else row.get("config_payload", {})
    credentials = payload.get("credentials") if isinstance(payload.get("credentials"), dict) else {}
    discovered = adapter.discover_alerts(config_payload, credentials)
    return {"id": integration_id, "provider": provider, "discovered": discovered}


@app.post("/monitoring/integrations/{integration_id}/register-webhook")
async def register_monitoring_webhook(integration_id: str, payload: dict[str, Any] = Body(default_factory=dict)) -> dict[str, Any]:
    session_factory = _db_required()
    default_gateway_base = str(getattr(settings, "gateway_public_base_url", "") or "http://localhost:8080")
    public_base_url = str(payload.get("public_base_url") or default_gateway_base).rstrip("/")
    async with session_factory() as session:
        repo = IncidentRepository(session)
        row = await repo.get_monitoring_integration(integration_id)
        if row is None:
            raise HTTPException(status_code=404, detail="Monitoring integration not found")
        provider = normalize_provider_name(str(row.get("provider") or ""))
        adapter = get_provider_adapter(provider)
        webhook_path = str(row.get("webhook_path") or build_webhook_path(provider))
        webhook_url = f"{public_base_url}{webhook_path}"
        registration = adapter.register_webhook(row.get("config_payload", {}), webhook_url)
        await repo.save_monitoring_webhook_endpoint(
            endpoint_id=str(uuid.uuid4()),
            integration_id=integration_id,
            provider=provider,
            webhook_path=webhook_path,
            token_hash=None,
            hmac_enabled=bool(payload.get("hmac_enabled", False)),
            m_tls_enabled=bool(payload.get("m_tls_enabled", False)),
            active=True,
            metadata_payload={"registration": registration},
        )
        await session.commit()
    return {"id": integration_id, "provider": provider, "webhook_url": webhook_url, "registration": registration}


@app.get("/monitoring/integrations/{integration_id}/mapping")
async def get_monitoring_mapping(integration_id: str) -> dict[str, Any]:
    session_factory = _db_required()
    async with session_factory() as session:
        repo = IncidentRepository(session)
        integration = await repo.get_monitoring_integration(integration_id)
        if integration is None:
            raise HTTPException(status_code=404, detail="Monitoring integration not found")
        rows = await repo.list_monitoring_alert_mappings(integration_id)
    return {"id": integration_id, "provider": integration.get("provider"), "rows": rows, "count": len(rows)}


@app.put("/monitoring/integrations/{integration_id}/mapping")
async def put_monitoring_mapping(integration_id: str, payload: dict[str, Any] = ALERT_BODY) -> dict[str, Any]:
    session_factory = _db_required()
    mappings = payload.get("mappings") if isinstance(payload.get("mappings"), list) else []
    async with session_factory() as session:
        repo = IncidentRepository(session)
        integration = await repo.get_monitoring_integration(integration_id)
        if integration is None:
            raise HTTPException(status_code=404, detail="Monitoring integration not found")
        count = await repo.replace_monitoring_alert_mappings(
            integration_id=integration_id,
            provider=str(integration.get("provider") or ""),
            mappings=mappings,
        )
        await session.commit()
    return {"id": integration_id, "saved": count}


@app.post("/monitoring/integrations/{integration_id}/test-alert")
async def test_monitoring_alert(integration_id: str, payload: dict[str, Any] = ALERT_BODY) -> dict[str, Any]:
    session_factory = _db_required()
    async with session_factory() as session:
        repo = IncidentRepository(session)
        integration = await repo.get_monitoring_integration(integration_id)
        if integration is None:
            raise HTTPException(status_code=404, detail="Monitoring integration not found")
        mappings = await repo.list_monitoring_alert_mappings(integration_id)
    provider = normalize_provider_name(str(integration.get("provider") or ""))
    adapter = get_provider_adapter(provider)
    sample_payload = payload.get("alert") if isinstance(payload.get("alert"), dict) else payload
    normalized = adapter.normalize_alert(sample_payload if isinstance(sample_payload, dict) else {}, None)
    normalized = apply_field_mapping(normalized, mappings)
    raw_for_alert = _merge_raw_and_labels(normalized)
    mapped_payload = {
        "source": provider,
        "name": str(normalized.get("alertName") or "provider-alert"),
        "service": str(normalized.get("application") or "unknown-app"),
        "environment": str(normalized.get("environment") or "prod"),
        "severity": str(normalized.get("severity") or "warning"),
        "description": str((normalized.get("annotations") or {}).get("summary") or normalized.get("alertName") or "provider-alert"),
        "labels": normalized.get("labels", {}),
        "annotations": normalized.get("annotations", {}),
        "alertname": str(normalized.get("alertName") or "provider-alert"),
        "raw": raw_for_alert,
    }
    alert = _build_alert_from_payload(mapped_payload)
    await _publish_ingested_alert(alert)
    await _publish_lifecycle_events(normalized)
    await _persist_monitoring_audit(
        tenant_id=str(integration.get("tenant_id") or "default"),
        actor="api",
        action="integration.test_alert",
        provider=provider,
        outcome="success",
        message="Test alert processed",
        payload={"integration_id": integration_id, "alert_id": str(alert.id)},
        integration_id=integration_id,
    )
    return {"id": integration_id, "provider": provider, "alert_id": str(alert.id), "normalized": normalized}


@app.post("/monitoring/integrations/{integration_id}/activate")
async def activate_monitoring_integration(integration_id: str) -> dict[str, Any]:
    session_factory = _db_required()
    async with session_factory() as session:
        repo = IncidentRepository(session)
        row = await repo.get_monitoring_integration(integration_id)
        if row is None:
            raise HTTPException(status_code=404, detail="Monitoring integration not found")
        await repo.save_monitoring_integration(
            integration_id=integration_id,
            tenant_id=str(row.get("tenant_id") or "default"),
            project_name=str(row.get("project_name") or "untitled-project"),
            provider=str(row.get("provider") or "prometheus"),
            status="active",
            active=True,
            auth_type=str(row.get("auth_type") or "api_key"),
            endpoint_url=row.get("endpoint_url"),
            webhook_path=str(row.get("webhook_path") or build_webhook_path(str(row.get("provider") or "prometheus"))),
            deployment_mode=str(row.get("deployment_mode") or "existing_monitoring"),
            config_payload=row.get("config_payload") or {},
            validation_payload=row.get("validation_payload") or {},
        )
        await session.commit()
    return {"id": integration_id, "active": True, "status": "active"}


@app.post("/monitoring/integrations/{integration_id}/deactivate")
async def deactivate_monitoring_integration(integration_id: str) -> dict[str, Any]:
    session_factory = _db_required()
    async with session_factory() as session:
        repo = IncidentRepository(session)
        row = await repo.get_monitoring_integration(integration_id)
        if row is None:
            raise HTTPException(status_code=404, detail="Monitoring integration not found")
        await repo.save_monitoring_integration(
            integration_id=integration_id,
            tenant_id=str(row.get("tenant_id") or "default"),
            project_name=str(row.get("project_name") or "untitled-project"),
            provider=str(row.get("provider") or "prometheus"),
            status="inactive",
            active=False,
            auth_type=str(row.get("auth_type") or "api_key"),
            endpoint_url=row.get("endpoint_url"),
            webhook_path=str(row.get("webhook_path") or build_webhook_path(str(row.get("provider") or "prometheus"))),
            deployment_mode=str(row.get("deployment_mode") or "existing_monitoring"),
            config_payload=row.get("config_payload") or {},
            validation_payload=row.get("validation_payload") or {},
        )
        await session.commit()
    return {"id": integration_id, "active": False, "status": "inactive"}


@app.get("/monitoring/health")
async def get_monitoring_health(tenant_id: str = "default") -> dict[str, Any]:
    session_factory = _db_required()
    async with session_factory() as session:
        repo = IncidentRepository(session)
        rows = await repo.list_monitoring_connection_health(tenant_id=tenant_id)
    return {"rows": rows, "count": len(rows)}


@app.get("/monitoring/audit")
async def get_monitoring_audit(tenant_id: str = "default", limit: int = 100) -> dict[str, Any]:
    session_factory = _db_required()
    async with session_factory() as session:
        repo = IncidentRepository(session)
        rows = await repo.list_monitoring_connection_audit(tenant_id=tenant_id, limit=limit)
    return {"rows": rows, "count": len(rows)}


async def _ingest_provider_alert(
    *,
    provider_hint: str,
    payload: dict[str, Any],
    x_trace_id: str | None,
    x_signature: str | None,
    x_webhook_token: str | None,
) -> dict[str, Any]:
    provider = normalize_provider_name(provider_hint)
    tenant_id = str(payload.get("tenant_id") or "default")
    integration_id = str(payload.get("integration_id") or "").strip() or None

    session_factory = _db_required()
    mappings: list[dict[str, Any]] = []
    expected_token = ""
    hmac_secret = ""
    integration: dict[str, Any] | None = None
    if integration_id:
        async with session_factory() as session:
            repo = IncidentRepository(session)
            integration = await repo.get_monitoring_integration(integration_id)
            if integration is not None:
                mappings = await repo.list_monitoring_alert_mappings(integration_id)
                config_payload = integration.get("config_payload") if isinstance(integration.get("config_payload"), dict) else {}
                expected_token = str(config_payload.get("webhook_token") or "")
                hmac_secret = str(config_payload.get("hmac_secret") or "")

    auth_valid = True if not expected_token else (str(x_webhook_token or "") == expected_token)
    body_as_string = json.dumps(payload, sort_keys=True)
    signature_valid = verify_hmac_signature(hmac_secret, body_as_string, x_signature)

    adapter = get_provider_adapter(provider)
    normalized = adapter.normalize_alert(payload, None)
    normalized = apply_field_mapping(normalized, mappings)

    mapped_payload = {
        "source": provider,
        "name": str(normalized.get("alertName") or f"{provider}-alert"),
        "service": str(normalized.get("application") or "unknown-app"),
        "environment": str(normalized.get("environment") or "prod"),
        "severity": str(normalized.get("severity") or "warning"),
        "description": str((normalized.get("annotations") or {}).get("summary") or normalized.get("alertName") or f"{provider}-alert"),
        "labels": normalized.get("labels", {}),
        "annotations": normalized.get("annotations", {}),
    }
    alert = _build_alert_from_payload(mapped_payload, trace_id=x_trace_id)
    await _publish_ingested_alert(alert)
    received_id, normalized_id = await _persist_received_and_normalized(
        tenant_id=tenant_id,
        provider=provider,
        integration_id=integration_id,
        payload=payload,
        normalized=normalized,
        signature_valid=signature_valid,
        auth_valid=auth_valid,
    )
    await _publish_lifecycle_events(normalized, trace_id=x_trace_id)
    await _persist_monitoring_audit(
        tenant_id=tenant_id,
        actor="landing-pad",
        action="webhook.ingest",
        provider=provider,
        outcome="success" if signature_valid and auth_valid else "degraded",
        message="Provider webhook ingested",
        payload={
            "received_alert_id": received_id,
            "normalized_alert_id": normalized_id,
            "alert_id": str(alert.id),
            "signature_valid": signature_valid,
            "auth_valid": auth_valid,
        },
        integration_id=integration_id,
    )
    return {
        "provider": provider,
        "integration_id": integration_id,
        "alert_id": str(alert.id),
        "received_alert_id": received_id,
        "normalized_alert_id": normalized_id,
        "signature_valid": signature_valid,
        "auth_valid": auth_valid,
        "status": "accepted",
    }


@app.post("/api/v1/alerts/prometheus")
async def ingest_prometheus_alert(payload: dict[str, Any] = ALERT_BODY, x_trace_id: str | None = Header(default=None), x_signature: str | None = Header(default=None), x_webhook_token: str | None = Header(default=None)) -> dict[str, Any]:
    return await _ingest_provider_alert(
        provider_hint="prometheus",
        payload=payload,
        x_trace_id=x_trace_id,
        x_signature=x_signature,
        x_webhook_token=x_webhook_token,
    )


@app.post("/api/v1/alerts/datadog")
async def ingest_datadog_alert(payload: dict[str, Any] = ALERT_BODY, x_trace_id: str | None = Header(default=None), x_signature: str | None = Header(default=None), x_webhook_token: str | None = Header(default=None)) -> dict[str, Any]:
    return await _ingest_provider_alert(
        provider_hint="datadog",
        payload=payload,
        x_trace_id=x_trace_id,
        x_signature=x_signature,
        x_webhook_token=x_webhook_token,
    )


@app.post("/api/v1/alerts/newrelic")
async def ingest_newrelic_alert(payload: dict[str, Any] = ALERT_BODY, x_trace_id: str | None = Header(default=None), x_signature: str | None = Header(default=None), x_webhook_token: str | None = Header(default=None)) -> dict[str, Any]:
    return await _ingest_provider_alert(
        provider_hint="new_relic",
        payload=payload,
        x_trace_id=x_trace_id,
        x_signature=x_signature,
        x_webhook_token=x_webhook_token,
    )


@app.post("/api/v1/alerts/dynatrace")
async def ingest_dynatrace_alert(payload: dict[str, Any] = ALERT_BODY, x_trace_id: str | None = Header(default=None), x_signature: str | None = Header(default=None), x_webhook_token: str | None = Header(default=None)) -> dict[str, Any]:
    return await _ingest_provider_alert(
        provider_hint="dynatrace",
        payload=payload,
        x_trace_id=x_trace_id,
        x_signature=x_signature,
        x_webhook_token=x_webhook_token,
    )


@app.post("/api/v1/alerts/azure-monitor")
async def ingest_azure_monitor_alert(payload: dict[str, Any] = ALERT_BODY, x_trace_id: str | None = Header(default=None), x_signature: str | None = Header(default=None), x_webhook_token: str | None = Header(default=None)) -> dict[str, Any]:
    return await _ingest_provider_alert(
        provider_hint="azure_monitor",
        payload=payload,
        x_trace_id=x_trace_id,
        x_signature=x_signature,
        x_webhook_token=x_webhook_token,
    )


@app.post("/api/v1/alerts/splunk")
async def ingest_splunk_alert(payload: dict[str, Any] = ALERT_BODY, x_trace_id: str | None = Header(default=None), x_signature: str | None = Header(default=None), x_webhook_token: str | None = Header(default=None)) -> dict[str, Any]:
    return await _ingest_provider_alert(
        provider_hint="splunk",
        payload=payload,
        x_trace_id=x_trace_id,
        x_signature=x_signature,
        x_webhook_token=x_webhook_token,
    )


@app.post("/api/v1/alerts/generic")
async def ingest_generic_provider_alert(provider: str = "prometheus", payload: dict[str, Any] = ALERT_BODY, x_trace_id: str | None = Header(default=None), x_signature: str | None = Header(default=None), x_webhook_token: str | None = Header(default=None)) -> dict[str, Any]:
    return await _ingest_provider_alert(
        provider_hint=provider,
        payload=payload,
        x_trace_id=x_trace_id,
        x_signature=x_signature,
        x_webhook_token=x_webhook_token,
    )


@app.post("/alerts", response_model=Alert)
async def ingest_alert(payload: dict = ALERT_BODY, x_trace_id: str | None = Header(default=None)) -> Alert:
    alert = _build_alert_from_payload(payload, trace_id=x_trace_id)
    await _publish_ingested_alert(alert)
    return alert


async def _ingest_one_alertmanager_alert(mapped_payload: dict[str, Any], item: dict[str, Any], status: str) -> dict[str, Any]:
    """Write+process one Alertmanager alert. Concurrency is bounded inside
    _process_landing_pad_input_file's per-row worker (the shared ingest
    semaphore), so this function needs no bound of its own."""
    labels = mapped_payload.get("labels", {}) if isinstance(mapped_payload.get("labels"), dict) else {}
    alertname = str(labels.get("alertname") or "unknown-alert")
    service = str(mapped_payload.get("service") or "unknown")
    try:
        landing_pad_input_file = _write_alert_to_landing_pad_input(mapped_payload, item)
        process_result = await _process_landing_pad_input_file(
            landing_pad_input_file,
            skip_existing_processed=False,
        )
    except Exception as exc:
        logger.exception("failed to land alertmanager alert")
        _persist_alert_to_landing_pad(mapped_payload, item, status="failed", error=str(exc))
        return {
            "kind": "skipped",
            "status": status,
            "alertname": alertname,
            "service": service,
            "reason": f"landing pad ingestion failed: {exc}",
        }

    processed_alerts = process_result.get("alerts") if isinstance(process_result.get("alerts"), list) else []
    if processed_alerts:
        return {
            "kind": "ingested",
            "rows": [
                {
                    **alert_row,
                    "status": status,
                    "landing_pad_input_file": str(landing_pad_input_file),
                    "landing_pad_archived_path": process_result.get("archived_path"),
                }
                for alert_row in processed_alerts
            ],
        }

    return {
        "kind": "skipped",
        "status": status,
        "alertname": alertname,
        "service": service,
        "reason": str(process_result.get("reason") or process_result.get("error") or process_result.get("status")),
        "landing_pad_input_file": str(landing_pad_input_file),
        "landing_pad_archived_path": process_result.get("archived_path"),
    }


def _alertmanager_delivery_key(item: dict[str, Any], labels: dict[str, Any], status: str) -> str:
    fingerprint = str(item.get("fingerprint") or "").strip()
    if fingerprint:
        return f"{status}:{fingerprint}"
    stable_payload = json.dumps(
        {
            "status": status,
            "labels": labels,
            "startsAt": item.get("startsAt"),
        },
        sort_keys=True,
        default=str,
    )
    return hashlib.sha256(stable_payload.encode("utf-8")).hexdigest()


def _claim_alertmanager_delivery(delivery_key: str) -> bool:
    """Return False for repeated Alertmanager notifications within the TTL.

    Alertmanager intentionally repeats unresolved alerts. Without this guard,
    every repeat creates another landing-pad file and can form a monitoring
    feedback loop when the alert itself concerns KaiOps latency.
    """
    now = perf_counter()
    cutoff = now - ALERTMANAGER_DEDUP_TTL_SECONDS
    if len(_ALERTMANAGER_RECENT_DELIVERIES) >= ALERTMANAGER_DEDUP_MAX_ENTRIES:
        expired = [key for key, seen_at in _ALERTMANAGER_RECENT_DELIVERIES.items() if seen_at < cutoff]
        for key in expired:
            _ALERTMANAGER_RECENT_DELIVERIES.pop(key, None)
        if len(_ALERTMANAGER_RECENT_DELIVERIES) >= ALERTMANAGER_DEDUP_MAX_ENTRIES:
            oldest = min(_ALERTMANAGER_RECENT_DELIVERIES, key=_ALERTMANAGER_RECENT_DELIVERIES.get)
            _ALERTMANAGER_RECENT_DELIVERIES.pop(oldest, None)

    last_seen = _ALERTMANAGER_RECENT_DELIVERIES.get(delivery_key)
    if last_seen is not None and last_seen >= cutoff:
        return False
    _ALERTMANAGER_RECENT_DELIVERIES[delivery_key] = now
    return True


@app.post("/alerts/alertmanager")
async def ingest_alertmanager_webhook(payload: dict = ALERT_BODY, x_trace_id: str | None = Header(default=None)) -> dict[str, Any]:
    alerts_payload = payload.get("alerts", []) if isinstance(payload, dict) else []
    if not isinstance(alerts_payload, list):
        raise HTTPException(status_code=400, detail="alertmanager payload must contain an alerts array")

    common_labels = payload.get("commonLabels", {}) if isinstance(payload.get("commonLabels"), dict) else {}
    common_annotations = payload.get("commonAnnotations", {}) if isinstance(payload.get("commonAnnotations"), dict) else {}

    received = len(alerts_payload)
    queued_rows: list[dict[str, Any]] = []
    skipped_rows: list[dict[str, Any]] = []

    for item in alerts_payload:
        if not isinstance(item, dict):
            skipped_rows.append({"reason": "non-object alert item"})
            continue

        status = str(item.get("status") or payload.get("status") or "firing").strip().lower()
        labels = item.get("labels", {}) if isinstance(item.get("labels"), dict) else {}
        annotations = item.get("annotations", {}) if isinstance(item.get("annotations"), dict) else {}
        merged_labels = {**common_labels, **labels}
        merged_annotations = {**common_annotations, **annotations}
        origin_system = str(
            merged_labels.get("source_system")
            or merged_labels.get("origin_system")
            or merged_labels.get("source")
            or "prometheus"
        ).strip().lower() or "prometheus"
        delivery_key = _alertmanager_delivery_key(item, merged_labels, status)

        if status != "firing":
            skipped_rows.append(
                {
                    "status": status,
                    "alertname": str(merged_labels.get("alertname") or "unknown-alert"),
                    "service": str(merged_labels.get("service") or merged_labels.get("job") or "unknown"),
                    "reason": "Only firing alerts are sent to landing pad",
                }
            )
            continue
        if not _claim_alertmanager_delivery(delivery_key):
            skipped_rows.append(
                {
                    "status": status,
                    "alertname": str(merged_labels.get("alertname") or "unknown-alert"),
                    "service": str(merged_labels.get("service") or merged_labels.get("job") or "unknown"),
                    "reason": "Duplicate Alertmanager delivery suppressed within deduplication window",
                }
            )
            continue

        mapped_payload = {
            "source": origin_system,
            "name": str(merged_labels.get("alertname") or "prometheus-alert"),
            "service": str(merged_labels.get("service") or merged_labels.get("job") or merged_labels.get("instance") or "kaiops-platform"),
            "environment": str(merged_labels.get("environment") or merged_labels.get("env") or "prod"),
            "severity": str(merged_labels.get("severity") or "warning").lower(),
            "description": str(merged_annotations.get("description") or merged_annotations.get("summary") or merged_labels.get("alertname") or "Prometheus alert"),
            "labels": {
                **merged_labels,
                "origin_system": origin_system,
                "ingestion_channel": "monitoring",
                "transport": "alertmanager",
                "alert_status": status,
                "alert_fingerprint": str(item.get("fingerprint") or ""),
            },
            "annotations": {
                **merged_annotations,
                "startsAt": str(item.get("startsAt") or ""),
                "endsAt": str(item.get("endsAt") or ""),
                "generatorURL": str(item.get("generatorURL") or ""),
            },
        }
        if CENTRALIZED_JIRA_ROUTING_ENABLED or PROMETHEUS_JIRA_ROUTING_ENABLED:
            # Prometheus no longer shortcuts into the landing pad — it
            # routes through centralized dedup and Jira create-or-update.
            # Jira's own webhook (unchanged) is what eventually reaches the
            # landing pad, once a human/Jira acts on the resulting ticket.
            try:
                result = await _route_and_trigger_investigation(mapped_payload, item, source="prometheus")
                if result.get("routed"):
                    queued_rows.append(
                        {
                            "status": status,
                            "alertname": mapped_payload["name"],
                            "service": mapped_payload["service"],
                            "jira_issue_key": result.get("jira_issue_key"),
                            "jira_action": result.get("action"),
                        }
                    )
                else:
                    _ALERTMANAGER_RECENT_DELIVERIES.pop(delivery_key, None)
                    skipped_rows.append(
                        {
                            "status": status,
                            "alertname": mapped_payload["name"],
                            "service": mapped_payload["service"],
                            "reason": str(result.get("reason") or "jira routing failed"),
                        }
                    )
            except Exception as exc:
                _ALERTMANAGER_RECENT_DELIVERIES.pop(delivery_key, None)
                logger.exception("failed to route alertmanager alert through jira")
                skipped_rows.append(
                    {
                        "status": status,
                        "alertname": mapped_payload["name"],
                        "service": mapped_payload["service"],
                        "reason": f"jira routing failed: {exc}",
                    }
                )
            continue

        try:
            landing_pad_input_file = _write_alert_to_landing_pad_input(mapped_payload, item)
            queued_rows.append(
                {
                    "status": status,
                    "alertname": mapped_payload["name"],
                    "service": mapped_payload["service"],
                    "landing_pad_input_file": str(landing_pad_input_file),
                }
            )
        except Exception as exc:
            _ALERTMANAGER_RECENT_DELIVERIES.pop(delivery_key, None)
            logger.exception("failed to enqueue alertmanager alert")
            _persist_alert_to_landing_pad(mapped_payload, item, status="failed", error=str(exc))
            skipped_rows.append(
                {
                    "status": status,
                    "alertname": mapped_payload["name"],
                    "service": mapped_payload["service"],
                    "reason": f"landing pad enqueue failed: {exc}",
                }
            )

    return {
        "received": received,
        "queued": len(queued_rows),
        "skipped": len(skipped_rows),
        "rows": queued_rows,
        "skipped_rows": skipped_rows,
    }


def _jira_api_client() -> JiraClient | None:
    if not (JIRA_API_BASE_URL and JIRA_API_EMAIL and JIRA_API_TOKEN and JIRA_PROJECT_KEY):
        return None
    return JiraClient(
        base_url=JIRA_API_BASE_URL,
        email=JIRA_API_EMAIL,
        api_token=JIRA_API_TOKEN,
        project_key=JIRA_PROJECT_KEY,
    )


def _jira_issue_description(
    normalized: dict[str, Any],
    raw_item: dict[str, Any],
    *,
    source: str,
    recurring: bool = False,
) -> str:
    labels = normalized.get("labels") if isinstance(normalized.get("labels"), dict) else {}
    service = str(normalized.get("service") or labels.get("service") or "unknown-service")
    severity = str(normalized.get("severity") or "warning").upper()
    timestamp = str(raw_item.get("timestamp") or labels.get("startsAt") or "Not provided")
    source_path = str(raw_item.get("source_path") or labels.get("log_source_path") or source)
    trace_id = str(raw_item.get("trace_id") or labels.get("trace_id") or "").strip()
    document_id = str(raw_item.get("document_id") or labels.get("opensearch_document_id") or "").strip()
    error_signature = str(labels.get("error_signature") or "").strip()
    details = str(normalized.get("description") or normalized.get("name") or "No error message provided").strip()

    lines = [
        "h2. Incident summary",
        f"KaiOps {'detected another occurrence of' if recurring else 'detected'} an error affecting *{service}*.",
        "",
        "h2. Classification",
        f"* Service: {service}",
        f"* Severity: {severity}",
        f"* Source: {source}",
        f"* Detected at: {timestamp}",
        f"* Environment: {normalized.get('environment') or 'unknown'}",
        "",
        "h2. Error details",
        "{code}",
        details[:5000],
        "{code}",
        "",
        "h2. Evidence",
        f"* Log source: {source_path}",
    ]
    if trace_id:
        lines.append(f"* Trace ID: {trace_id}")
    if document_id:
        lines.append(f"* OpenSearch document ID: {document_id}")
    if error_signature:
        lines.append(f"* Deduplication signature: {error_signature}")
    lines.extend(
        [
            "",
            "h2. Automated troubleshooting",
            "* Context collection requested",
            "* Discovery checks requested",
            "* Subsequent matching occurrences will be added as comments",
        ]
    )
    return "\n".join(lines)


def _claim_log_discovery_capacity() -> bool:
    now = perf_counter()
    cutoff = now - 60.0
    while _LOG_DISCOVERY_ADMISSIONS and _LOG_DISCOVERY_ADMISSIONS[0] < cutoff:
        _LOG_DISCOVERY_ADMISSIONS.popleft()
    if len(_LOG_DISCOVERY_ADMISSIONS) >= LOG_DISCOVERY_MAX_PER_MINUTE:
        return False
    _LOG_DISCOVERY_ADMISSIONS.append(now)
    return True


async def _route_and_trigger_investigation(
    mapped_payload: dict[str, Any],
    raw_item: dict[str, Any],
    *,
    source: str,
    trigger_enabled: bool = True,
    persist_evidence: bool = True,
) -> dict[str, Any]:
    """Persist raw evidence, apply a cheap recurrence gate, then run Discovery.

    Jira is deliberately absent from this stage. Alert Intelligence owns the
    post-Discovery actionability decision and Jira create-or-update operation.
    """
    normalized = normalize_landing_pad_alert(mapped_payload, raw_item)
    fingerprint = compute_fingerprint(normalized)
    severity = str(normalized.get("severity") or "warning").lower()
    if severity not in JIRA_ALLOWED_SEVERITIES:
        decision = None
        result = {
            "routed": False,
            "action": "suppressed",
            "reason": "severity not admitted for Discovery",
            "fingerprint": fingerprint,
            "occurrence_count": 1,
        }
    else:
        decision = JIRA_ADMISSION.evaluate_for_discovery(
            fingerprint=fingerprint,
            source=source,
            severity=severity,
        )
        result = {
            "routed": decision.allowed,
            "action": decision.action,
            "reason": decision.reason,
            "fingerprint": fingerprint,
            "occurrence_count": decision.occurrence_count,
        }
    labels = dict(mapped_payload.get("labels") or {})
    project_name = str(
        labels.get("project_name")
        or labels.get("application")
        or mapped_payload.get("project_name")
        or mapped_payload.get("application")
        or ("KaiOps" if source in {"prometheus", "email"} else source)
    )
    labels.update(
        {
            "pipeline_outcome": str(result.get("action") or "failed"),
            "pipeline_reason": str(result.get("reason") or ""),
            "project_name": project_name,
            "application": project_name,
            "origin_system": source,
            "source_event_id": str(
                raw_item.get("document_id")
                or raw_item.get("message_id")
                or labels.get("alert_fingerprint")
                or fingerprint
            ),
            "discovery_fingerprint": fingerprint,
            "occurrence_count": str(result.get("occurrence_count") or 1),
            "pipeline_stage": "pre_discovery_admission",
        }
    )
    mapped_payload["labels"] = labels
    if persist_evidence:
        _persist_alert_to_landing_pad(mapped_payload, raw_item, status="processed")
    should_trigger = result.get("routed") and trigger_enabled and JIRA_TRIGGER_TROUBLESHOOTING
    if should_trigger and source == "logs" and not _claim_log_discovery_capacity():
        result.update(
            {
                "routed": False,
                "action": "rate_limited",
                "reason": f"log Discovery budget limited to {LOG_DISCOVERY_MAX_PER_MINUTE} per minute",
            }
        )
        labels.update(
            {
                "pipeline_outcome": "rate_limited",
                "pipeline_reason": str(result["reason"]),
            }
        )
        mapped_payload["labels"] = labels
        should_trigger = False
    if not should_trigger:
        logger.info(
            "incident_pipeline stage=pre_discovery outcome=%s source=%s fingerprint=%s reason=%s",
            result.get("action"),
            source,
            fingerprint,
            result.get("reason") or "discovery disabled",
        )
        return result

    labels.update(
        {
            "troubleshooting_requested": "true",
            "pipeline_stage": "discovery_requested",
        }
    )
    mapped_payload["labels"] = labels
    alert = _build_alert_from_payload(mapped_payload)
    await _publish_ingested_alert(alert, topic=RAW_ALERTS)
    logger.info(
        "incident_pipeline stage=discovery outcome=published source=%s fingerprint=%s alert_id=%s",
        source,
        fingerprint,
        alert.id,
    )
    result["discovery_published"] = True
    result["alert_id"] = str(alert.id)
    return result


async def _route_alert_through_jira(mapped_payload: dict[str, Any], raw_item: dict[str, Any], *, source: str) -> dict[str, Any]:
    """The centralized dedup -> Jira decision point every ingestion path
    (Prometheus, logs, email) routes through when
    CENTRALIZED_JIRA_ROUTING_ENABLED is on, instead of publishing straight
    to the landing pad. Looks up whether an open Jira ticket already exists
    for this alert's fingerprint; creates a new issue if not, comments on
    the existing one if so. Does NOT touch the landing pad, raw-alerts
    queue, or _build_alert_from_payload — those only run later, when Jira's
    own webhook (unchanged) calls back into /api/v1/alerts/jira.
    """
    client = _jira_api_client()
    if client is None:
        logger.warning("centralized jira routing enabled but JIRA_API_* is not fully configured; alert dropped")
        return {"routed": False, "reason": "jira api not configured"}

    session_factory = getattr(app.state, "session_factory", None)
    if not settings.database_enabled or session_factory is None:
        logger.warning("centralized jira routing requires a database; alert dropped")
        return {"routed": False, "reason": "database not available"}

    normalized = normalize_landing_pad_alert(mapped_payload, raw_item)
    fingerprint = compute_fingerprint(normalized)
    summary = str(normalized.get("name") or "alert")
    description = _jira_issue_description(normalized, raw_item, source=source)
    severity = str(normalized.get("severity") or "warning")
    if severity.lower() not in JIRA_ALLOWED_SEVERITIES:
        audited = _should_audit_pipeline(fingerprint, "severity_suppressed")
        if audited:
            logger.info(
                "jira_pipeline stage=admission outcome=suppressed source=%s fingerprint=%s reason=severity severity=%s",
                source,
                fingerprint,
                severity,
            )
        return {
            "routed": False,
            "action": "suppressed",
            "reason": "severity not admitted",
            "fingerprint": fingerprint,
            "audited": audited,
        }

    async with session_factory() as session:
        repo = IncidentRepository(session)
        existing = await repo.get_open_jira_ticket_link(fingerprint)
        if existing is None:
            try:
                recovered_issue_key = await client.find_open_issue_by_label(f"kaiops-fingerprint-{fingerprint}")
                if recovered_issue_key:
                    await repo.save_jira_ticket_link(
                        fingerprint=fingerprint,
                        jira_issue_key=recovered_issue_key,
                        source=source,
                    )
                    await session.commit()
                    existing = await repo.get_open_jira_ticket_link(fingerprint)
            except JiraClientError:
                logger.exception("failed to search Jira for fingerprint %s", fingerprint)
        if existing is not None:
            issue_key = str(existing["jira_issue_key"])
            try:
                # A ticket can be closed by a human directly in Jira between
                # occurrences — check before commenting on a closed issue.
                status_name = await client.get_issue_status(issue_key)
                if status_name.strip().lower() in {"done", "closed", "resolved"}:
                    await repo.close_jira_ticket_link(issue_key)
                    existing = None
            except JiraClientError:
                logger.exception("failed to check jira issue status for %s", issue_key)

        decision = JIRA_ADMISSION.evaluate(
            fingerprint=fingerprint,
            source=source,
            severity=severity,
            has_open_ticket=existing is not None,
        )
        audited = decision.allowed or _should_audit_pipeline(fingerprint, decision.action)
        if audited:
            logger.info(
                "jira_pipeline stage=admission outcome=%s source=%s fingerprint=%s occurrences=%s reason=%s",
                decision.action,
                source,
                fingerprint,
                decision.occurrence_count,
                decision.reason,
            )
        if not decision.allowed:
            return {
                "routed": False,
                "action": decision.action,
                "reason": decision.reason,
                "fingerprint": fingerprint,
                "occurrence_count": decision.occurrence_count,
                "audited": audited,
            }

        if existing is not None:
            issue_key = str(existing["jira_issue_key"])
            try:
                await client.add_comment(
                    issue_key,
                    _jira_issue_description(normalized, raw_item, source=source, recurring=True),
                )
                await repo.bump_jira_ticket_occurrence(fingerprint)
                await session.commit()
                logger.info(
                    "jira_pipeline stage=jira outcome=commented source=%s fingerprint=%s issue=%s",
                    source,
                    fingerprint,
                    issue_key,
                )
                return {
                    "routed": True,
                    "action": "commented",
                    "jira_issue_key": issue_key,
                    "fingerprint": fingerprint,
                    "audited": True,
                }
            except JiraClientError:
                logger.exception("failed to comment on jira issue %s", issue_key)
                return {"routed": False, "reason": "jira comment failed", "jira_issue_key": issue_key}

        try:
            issue_key = await client.create_issue(
                summary=summary,
                description=description,
                severity=severity,
                labels={"fingerprint": fingerprint, "managed": "by-kaiops"},
            )
            await repo.save_jira_ticket_link(fingerprint=fingerprint, jira_issue_key=issue_key, source=source)
            await session.commit()
            logger.info(
                "jira_pipeline stage=jira outcome=created source=%s fingerprint=%s issue=%s",
                source,
                fingerprint,
                issue_key,
            )
            return {
                "routed": True,
                "action": "created",
                "jira_issue_key": issue_key,
                "fingerprint": fingerprint,
                "audited": True,
            }
        except JiraClientError:
            logger.exception("failed to create jira issue for fingerprint %s", fingerprint)
            return {"routed": False, "reason": "jira create failed"}


def _jira_priority_to_severity(priority_name: str) -> str:
    normalized = str(priority_name or "").strip().lower()
    if normalized in {"highest", "blocker", "critical"}:
        return "critical"
    if normalized in {"high"}:
        return "high"
    if normalized in {"low", "lowest", "trivial"}:
        return "info"
    return "warning"


def _jira_adf_to_text(value: Any) -> str:
    """Flatten Jira Cloud Atlassian Document Format into readable plain text.

    Jira REST v3 returns rich-text fields as nested ADF objects.  Raw ``str()``
    output is neither useful evidence nor a safe LLM input, so normalize it at
    the adapter boundary while preserving paragraph/list separation.
    """
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, list):
        return "\n".join(filter(None, (_jira_adf_to_text(item) for item in value))).strip()
    if not isinstance(value, dict):
        return str(value).strip()

    node_type = str(value.get("type") or "")
    if node_type == "text":
        return str(value.get("text") or "")
    if node_type == "hardBreak":
        return "\n"

    children = value.get("content")
    if not isinstance(children, list):
        return ""
    rendered = [_jira_adf_to_text(child) for child in children]
    rendered = [text for text in rendered if text]

    if node_type == "listItem":
        return "\n".join(f"- {line}" for text in rendered for line in text.splitlines() if line.strip())
    separator = "\n" if node_type in {
        "doc",
        "heading",
        "paragraph",
        "bulletList",
        "orderedList",
        "blockquote",
        "codeBlock",
        "table",
        "tableRow",
        "tableCell",
        "tableHeader",
    } else ""
    return separator.join(rendered).strip()


def _jira_payload_to_alert_payload(payload: dict[str, Any]) -> tuple[dict[str, Any], str]:
    issue = payload.get("issue", {}) if isinstance(payload, dict) else {}
    if not isinstance(issue, dict):
        raise ValueError("jira webhook payload must contain an issue object")
    fields = issue.get("fields", {}) if isinstance(issue.get("fields"), dict) else {}
    issue_key = str(issue.get("key") or "unknown-issue")
    issue_id = str(issue.get("id") or "")
    summary = str(fields.get("summary") or issue_key)
    priority = fields.get("priority", {}) if isinstance(fields.get("priority"), dict) else {}
    status_field = fields.get("status", {}) if isinstance(fields.get("status"), dict) else {}
    project = fields.get("project", {}) if isinstance(fields.get("project"), dict) else {}
    reporter = fields.get("reporter", {}) if isinstance(fields.get("reporter"), dict) else {}
    assignee = fields.get("assignee", {}) if isinstance(fields.get("assignee"), dict) else {}
    webhook_event = str(payload.get("webhookEvent") or "").strip()
    jira_labels = fields.get("labels") if isinstance(fields.get("labels"), list) else []
    managed = "managed_by_kaiops" in jira_labels
    kaiops_incident_label = next(
        (str(label) for label in jira_labels if str(label).startswith("kaiops_incident_")),
        "",
    )
    description = _jira_adf_to_text(fields.get("description")) or summary

    mapped_payload = {
        "source": "jira",
        "name": summary,
        "service": str(project.get("key") or "jira-tickets"),
        "environment": "prod",
        "severity": _jira_priority_to_severity(str(priority.get("name") or "")),
        "description": description,
        "labels": {
            "alert_status": "firing",
            "ticket_id": issue_key,
            "jira_issue_id": issue_id,
            "jira_status": str(status_field.get("name") or ""),
            "jira_priority": str(priority.get("name") or ""),
            "jira_reporter": str(reporter.get("displayName") or ""),
            "jira_assignee": str(assignee.get("displayName") or ""),
            "jira_webhook_event": webhook_event,
            "managed_by_kaiops": str(managed).lower(),
            "kaiops_incident_id": kaiops_incident_label.removeprefix("kaiops_incident_").replace("_", "-"),
            "event_origin": "kaiops" if managed else "jira",
        },
        "annotations": {
            "summary": summary,
            "description": description,
        },
    }
    return mapped_payload, issue_key


def _is_kaiops_managed_jira_update(payload: dict[str, Any]) -> bool:
    issue = payload.get("issue", {}) if isinstance(payload, dict) else {}
    fields = issue.get("fields", {}) if isinstance(issue, dict) and isinstance(issue.get("fields"), dict) else {}
    labels = fields.get("labels") if isinstance(fields.get("labels"), list) else []
    comment = payload.get("comment", {}) if isinstance(payload.get("comment"), dict) else {}
    comment_body = str(comment.get("body") or "")
    return "managed_by_kaiops" in labels and (
        "[kaiops-managed-update]" in comment_body
        or str(payload.get("event_origin") or "").lower() == "kaiops"
    )


async def _process_jira_webhook(payload: dict[str, Any], trace_id: str | None) -> None:
    """Runs after the HTTP response has already been sent (via BackgroundTasks)
    so the webhook receiver can ack Jira with 200 immediately instead of
    making Jira wait on alert-build + publish + landing-pad persistence.
    """
    if _is_kaiops_managed_jira_update(payload):
        issue = payload.get("issue", {}) if isinstance(payload, dict) else {}
        logger.info("ignored KaiOps-originated Jira webhook issue=%s", issue.get("key"))
        return
    try:
        mapped_payload, issue_key = _jira_payload_to_alert_payload(payload)
    except ValueError:
        logger.exception("received malformed jira webhook payload")
        return
    try:
        alert = _build_alert_from_payload(mapped_payload, trace_id=trace_id)
        await _publish_ingested_alert(alert)
    except Exception as exc:
        logger.exception("failed to ingest jira webhook for issue %s", issue_key)
        _persist_alert_to_landing_pad(mapped_payload, payload, status="failed", error=str(exc))
        return
    mapped_payload["labels"] = dict(alert.labels)
    _persist_alert_to_landing_pad(mapped_payload, payload, status="processed")


@app.post("/api/v1/tickets/jira")
@app.post("/api/v1/alerts/jira")
async def ingest_jira_webhook(
    payload: dict = ALERT_BODY,
    background_tasks: BackgroundTasks = None,
    token: str | None = None,
    x_webhook_token: str | None = Header(default=None),
    x_trace_id: str | None = Header(default=None),
) -> dict[str, Any]:
    """Ingest a Jira issue-created/updated webhook into the same landing pad
    pipeline Prometheus alerts use. Auth is a shared secret, checked via
    either ?token=... or the X-Webhook-Token header — configured via
    JIRA_WEBHOOK_SECRET. Fails closed: if the secret isn't configured, this
    endpoint refuses all requests rather than accepting unverified webhooks.

    Registered under both /api/v1/tickets/jira (original path) and
    /api/v1/alerts/jira (the provider-webhook convention build_webhook_path()
    uses for every other monitoring provider), so register-webhook's
    auto-generated URL for the "jira" provider resolves to a real receiver.

    Responds 200 immediately after basic validation; the actual alert build +
    publish + landing-pad persistence happens in a background task so slow
    downstream steps can't cause Jira to time out and retry the webhook.
    """
    if not JIRA_WEBHOOK_SECRET:
        raise HTTPException(status_code=503, detail="Jira ingestion is not configured (JIRA_WEBHOOK_SECRET unset)")
    provided_token = str(token or x_webhook_token or "").strip()
    if not provided_token or provided_token != JIRA_WEBHOOK_SECRET:
        raise HTTPException(status_code=401, detail="invalid or missing Jira webhook token")

    issue = payload.get("issue", {}) if isinstance(payload, dict) else {}
    if not isinstance(issue, dict):
        raise HTTPException(status_code=400, detail="jira webhook payload must contain an issue object")
    issue_key = str(issue.get("key") or "unknown-issue")
    webhook_event = str(payload.get("webhookEvent") or "").strip()

    background_tasks.add_task(_process_jira_webhook, payload, x_trace_id)
    logger.info("received jira webhook event=%s issue=%s", webhook_event, issue_key)
    return {"received": True, "webhookEvent": webhook_event, "ticket_id": issue_key}


@app.get("/alerts")
async def alerts_help() -> dict[str, Any]:
    return {
        "message": "Use POST /alerts to submit alerts. GET /alerts is informational.",
        "example": {
            "method": "POST",
            "path": "/alerts",
            "payload": {
                "source": "monitoring-adapter",
                "name": "DatabaseReplicaLag",
                "service": "orders-db",
                "severity": "critical",
                "description": "Database replica lag exceeded threshold",
            },
        },
    }


@app.get("/alerts/severity-overrides")
async def get_alert_severity_overrides() -> dict[str, Any]:
    rows = load_alert_severity_overrides()
    return {
        "rows": rows,
        "count": len(rows),
        "storage_file": str(alert_severity_overrides_path()),
        "storage_key": ALERT_SEVERITY_OVERRIDES_FILE,
    }


@app.put("/alerts/severity-overrides")
async def put_alert_severity_override(payload: dict[str, Any] = ALERT_BODY) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="payload must be an object")
    rows = upsert_alert_severity_override(payload)
    return {"ok": True, "rows": rows, "count": len(rows)}


@app.delete("/alerts/severity-overrides")
async def delete_alert_severity_override(
    name: str = Query(default=""),
    service: str = Query(default=""),
    environment: str = Query(default=""),
) -> dict[str, Any]:
    rows = remove_alert_severity_override(name=name, service=service, environment=environment)
    return {"ok": True, "rows": rows, "count": len(rows)}


@app.get("/alerts/recent")
async def get_recent_alerts(limit: int = 50) -> dict[str, Any]:
    safe_limit = max(1, min(int(limit), 200))
    session_factory = getattr(app.state, "session_factory", None)
    if settings.database_enabled and session_factory is not None:
        async with session_factory() as session:
            repo = IncidentRepository(session)
            rows = await repo.list_alerts(limit=safe_limit, include_incident_context=False)
        return {"rows": rows, "count": len(rows)}

    rows = list(RECENT_ALERTS)[:safe_limit]
    return {"rows": rows, "count": len(rows)}


@app.get("/alerts/all")
async def get_all_alerts(limit: int = 500) -> dict[str, Any]:
    safe_limit = max(1, min(int(limit), 5000))
    session_factory = getattr(app.state, "session_factory", None)
    if settings.database_enabled and session_factory is not None:
        async with session_factory() as session:
            repo = IncidentRepository(session)
            rows = await repo.list_alerts(limit=safe_limit, include_incident_context=False)
        return {"rows": rows, "count": len(rows)}

    rows = list(RECENT_ALERTS)[:safe_limit]
    return {"rows": rows, "count": len(rows)}


def _alert_application_candidates(row: dict[str, Any]) -> list[str]:
    labels = row.get("labels", {}) if isinstance(row.get("labels"), dict) else {}
    candidates = [
        row.get("application"),
        row.get("project"),
        row.get("project_name"),
        row.get("service"),
        labels.get("application"),
        labels.get("project"),
        labels.get("project_name"),
        labels.get("deployment"),
        labels.get("namespace"),
        labels.get("job"),
    ]
    return [str(value or "").strip() for value in candidates if str(value or "").strip()]


def _is_displayable_alert_application(value: str) -> bool:
    normalized = str(value or "").strip()
    if not normalized:
        return False
    if "/" in normalized or ":" in normalized:
        return False
    if re.match(r"^(unknown|default|prod|dev|staging|warning|critical|high|info)$", normalized, re.IGNORECASE):
        return False
    if re.match(
        r"^(prometheus|alertmanager|blackbox|node-exporter|mysql|redis|rabbitmq|kafka|zookeeper)$",
        normalized,
        re.IGNORECASE,
    ):
        return False
    return True


@app.get("/alerts/applications")
async def get_alert_applications(limit: int = 5000) -> dict[str, Any]:
    safe_limit = max(1, min(int(limit), 10000))
    session_factory = getattr(app.state, "session_factory", None)
    if settings.database_enabled and session_factory is not None:
        async with session_factory() as session:
            repo = IncidentRepository(session)
            rows = await repo.list_alerts(limit=safe_limit)
    else:
        rows = list(RECENT_ALERTS)[:safe_limit]

    seen: set[str] = set()
    applications: list[str] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        for candidate in _alert_application_candidates(row):
            if not _is_displayable_alert_application(candidate):
                continue
            if candidate in seen:
                continue
            seen.add(candidate)
            applications.append(candidate)

    return {
        "rows": [{"name": name} for name in applications],
        "count": len(applications),
        "scanned_alerts": len(rows),
    }


@app.get("/alerts/{alert_id}/processed-result")
async def get_processed_result(alert_id: str) -> dict[str, Any]:
    session_factory = getattr(app.state, "session_factory", None)
    if not settings.database_enabled or session_factory is None:
        raise HTTPException(status_code=503, detail="Database is not enabled for processed results")

    async with session_factory() as session:
        repo = IncidentRepository(session)
        result = await repo.get_processed_result_by_alert_id(alert_id)

    if not result:
        raise HTTPException(status_code=404, detail="No processed result found for alert")
    return result


@app.post("/sample/payment-latency", response_model=Alert)
async def sample_payment_latency(x_trace_id: str | None = Header(default=None)) -> Alert:
    alert = build_payment_latency_alert(trace_id=x_trace_id)
    payload = _build_raw_alert_event_payload(alert)
    started = perf_counter()
    await app.state.producer.publish(RAW_ALERTS, payload, key=alert.service)
    EVENT_PUBLISH_LATENCY.labels(settings.service_name, RAW_ALERTS, "monitoring-adapter").observe(
        max(0.0, perf_counter() - started)
    )
    EVENT_CONTRACTS_EMITTED.labels(settings.service_name, RAW_ALERTS, "monitoring-adapter", "v1").inc()
    return alert


@app.get("/sample/flows")
async def sample_flows() -> dict[str, Any]:
    return {"flows": list_scenarios()}


@app.get("/sample/scenarios/source")
async def sample_scenarios_source() -> dict[str, Any]:
    rows = scenario_source_rows()
    return {
        "rows": rows,
        "count": len(rows),
        "sources": {
            "hardcoded": "SCENARIOS",
            "text_file": str(scenarios_text_path()),
            "flow_catalog": f"{flow_catalog_path()} (informational only; not merged)",
        },
    }


@app.get("/onboarding/connectivity", response_model=OnboardingConnectivityResponse)
async def get_onboarding_connectivity() -> OnboardingConnectivityResponse:
    connectivity = load_onboarding_connectivity()
    snapshot = OnboardingConnectivitySnapshot.model_validate(connectivity if isinstance(connectivity, dict) else {})
    return OnboardingConnectivityResponse(connectivity=snapshot)


@app.get("/onboarding/state", response_model=OnboardingStateResponse)
async def get_onboarding_state() -> OnboardingStateResponse:
    session_factory = getattr(app.state, "session_factory", None)
    if not settings.database_enabled or session_factory is None:
        return OnboardingStateResponse(rows=[])

    async with session_factory() as session:
        repo = IncidentRepository(session)
        rows = await repo.list_onboarding_state()
    return OnboardingStateResponse(rows=rows)


@app.delete("/onboarding/state/{project_name}")
async def delete_onboarding_state(project_name: str, provider_name: str | None = None) -> dict[str, Any]:
    session_factory = getattr(app.state, "session_factory", None)
    if not settings.database_enabled or session_factory is None:
        raise HTTPException(status_code=503, detail="Database is not enabled for onboarding state deletion")

    normalized_project = str(project_name or "").strip()
    if not normalized_project:
        raise HTTPException(status_code=400, detail="project_name is required")

    normalized_provider = str(provider_name or "").strip().lower() or None
    async with session_factory() as session:
        repo = IncidentRepository(session)
        deleted = await repo.delete_onboarding_state(normalized_project, normalized_provider)
        await session.commit()

    # Keep delete idempotent for admin UX: deleting an already-absent row should not be treated as an API error.
    return {
        "deleted": deleted,
        "project_name": normalized_project,
        "provider_name": normalized_provider,
        "message": "Onboarding state deleted" if deleted > 0 else "Onboarding state row not found (already deleted)",
    }


def _source_balanced_recent_rows(rows: list[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
    """Return a newest-first window without allowing one source to hide all others.

    The ingestion buffer is intentionally shared across sources. During a
    Prometheus burst, a plain ``rows[:limit]`` made recently polled Jira and
    email events invisible even though they were successfully ingested.
    Reserve a small slice for every source present in the buffer, then fill
    remaining capacity with the newest events across all sources.
    """
    if limit <= 0 or not rows:
        return []
    if len(rows) <= limit:
        return rows

    sources: dict[str, list[tuple[int, dict[str, Any]]]] = {}
    for index, row in enumerate(rows):
        source = str(row.get("source") or row.get("origin_system") or "unknown").strip().lower() or "unknown"
        sources.setdefault(source, []).append((index, row))

    # At most one eighth of the window is reserved per source. This exposes
    # minority sources while leaving most capacity for true recency.
    reserve = max(1, min(25, limit // max(len(sources), 1)))
    selected: dict[int, dict[str, Any]] = {}
    for source_rows in sources.values():
        for index, row in source_rows[:reserve]:
            selected[index] = row

    for index, row in enumerate(rows):
        if len(selected) >= limit:
            break
        selected.setdefault(index, row)

    return [selected[index] for index in sorted(selected)[:limit]]


@app.get("/landing-pad/recent")
def get_landing_pad_recent(limit: int = 20, include_archive: bool = False) -> dict[str, Any]:
    """Read landing-pad audit files on FastAPI's bounded worker threadpool.

    The archive can contain thousands of files during an alert burst. Keeping
    this handler synchronous is intentional: Starlette executes it outside the
    asyncio event loop, so filesystem metadata and JSON parsing cannot freeze
    unrelated health, alert, and rule API requests.
    """
    safe_limit = max(1, min(int(limit), 200))
    buffered_rows = list(RECENT_INGESTION_EVENTS)
    seen_files = {str(row.get("file") or row.get("path") or "") for row in buffered_rows}
    for source_rows in RECENT_INGESTION_EVENTS_BY_SOURCE.values():
        for row in source_rows:
            identity = str(row.get("file") or row.get("path") or "")
            if identity and identity in seen_files:
                continue
            buffered_rows.append(row)
            if identity:
                seen_files.add(identity)
    buffered_rows.sort(key=lambda row: str(row.get("received_at") or row.get("modified_at") or ""), reverse=True)
    live_rows = _source_balanced_recent_rows(buffered_rows, safe_limit)
    if live_rows:
        return {
            "processed_dir": str(LANDING_PAD_PROCESSED_DIR),
            "failed_dir": str(LANDING_PAD_FAILED_DIR),
            "partition_scheme": "YYYY/MM/DD",
            "listing_lookback_days": 0,
            "source": "live-memory-buffer",
            "rows": live_rows,
            "count": len(live_rows),
        }
    if not include_archive:
        return {
            "processed_dir": str(LANDING_PAD_PROCESSED_DIR),
            "failed_dir": str(LANDING_PAD_FAILED_DIR),
            "partition_scheme": "YYYY/MM/DD",
            "listing_lookback_days": 0,
            "source": "live-memory-buffer",
            "rows": [],
            "count": 0,
        }
    LANDING_PAD_PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    LANDING_PAD_FAILED_DIR.mkdir(parents=True, exist_ok=True)

    recent_lookback_days = min(LANDING_PAD_LISTING_LOOKBACK_DAYS, 3)
    scan_cap = max(safe_limit * 3, 80)

    files = heapq.nlargest(
        safe_limit,
        [
            *_collect_partitioned_json_files(
                LANDING_PAD_PROCESSED_DIR,
                lookback_days=recent_lookback_days,
                max_files=scan_cap,
            ),
            *_collect_partitioned_json_files(
                LANDING_PAD_FAILED_DIR,
                lookback_days=recent_lookback_days,
                max_files=scan_cap,
            ),
        ],
        key=lambda path: path.name,
    )

    rows: list[dict[str, Any]] = []
    for path in files:
        try:
            filename_timestamp = datetime.strptime(path.name[:22], "%Y%m%dT%H%M%S%fZ").replace(tzinfo=timezone.utc)
            modified_at = filename_timestamp.isoformat()
        except ValueError:
            modified_at = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc).isoformat()
        entry: dict[str, Any] = {
            "file": path.name,
            "path": str(path),
            "modified_at": modified_at,
        }
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            alert = payload.get("alert", {}) if isinstance(payload, dict) else {}
            labels = alert.get("labels", {}) if isinstance(alert.get("labels"), dict) else {}
            annotations = alert.get("annotations", {}) if isinstance(alert.get("annotations"), dict) else {}
            entry.update(
                {
                    "received_at": payload.get("received_at") if isinstance(payload, dict) else None,
                    "status": payload.get("status") if isinstance(payload, dict) else None,
                    "error": payload.get("error") if isinstance(payload, dict) else None,
                    "source": (
                        alert.get("source") or payload.get("source")
                        if isinstance(alert, dict)
                        else payload.get("source")
                    ),
                    "name": alert.get("name") if isinstance(alert, dict) else None,
                    "service": alert.get("service") if isinstance(alert, dict) else None,
                    "environment": alert.get("environment") if isinstance(alert, dict) else None,
                    "severity": alert.get("severity") if isinstance(alert, dict) else None,
                    "description": alert.get("description") if isinstance(alert, dict) else None,
                    "application": alert.get("application") or labels.get("application"),
                    "project": alert.get("project") or labels.get("project"),
                    "project_name": alert.get("project_name") or labels.get("project_name"),
                    "labels": labels,
                    "annotations": annotations,
                    "origin_system": (
                        alert.get("origin_system")
                        or labels.get("origin_system")
                        or labels.get("source_system")
                    ),
                    "ingestion_channel": alert.get("ingestion_channel") or labels.get("ingestion_channel"),
                    "alert_status": labels.get("alert_status") if isinstance(labels, dict) else None,
                    "alertname": labels.get("alertname") if isinstance(labels, dict) else None,
                    "summary": annotations.get("summary") if isinstance(annotations, dict) else None,
                }
            )
        except Exception:
            entry["parse_error"] = "invalid_json"
        rows.append(entry)

    return {
        "processed_dir": str(LANDING_PAD_PROCESSED_DIR),
        "failed_dir": str(LANDING_PAD_FAILED_DIR),
        "partition_scheme": "YYYY/MM/DD",
        "listing_lookback_days": recent_lookback_days,
        "rows": rows,
        "count": len(rows),
    }


@app.get("/landing-pad/input")
async def get_landing_pad_input(limit: int = 50) -> dict[str, Any]:
    safe_limit = max(1, min(int(limit), 200))
    pending_rows = _landing_pad_file_rows(LANDING_PAD_INPUT_DIR, safe_limit)
    additional_pending: list[dict[str, Any]] = []
    for directory in LANDING_PAD_ADDITIONAL_INPUT_DIRS:
        additional_pending.extend(_landing_pad_file_rows(directory, safe_limit))
    additional_pending = sorted(
        additional_pending,
        key=lambda row: str(row.get("modified_at") or ""),
        reverse=True,
    )[:safe_limit]
    replayed_rows = _landing_pad_file_rows(LANDING_PAD_INPUT_REPLAYED_DIR, safe_limit, partitioned=True)
    failed_rows = _landing_pad_file_rows(LANDING_PAD_INPUT_FAILED_DIR, safe_limit, partitioned=True)
    pending_count = len(_landing_pad_input_files(10_000))
    return {
        "input_dir": str(LANDING_PAD_INPUT_DIR),
        "additional_input_dirs": [str(path) for path in LANDING_PAD_ADDITIONAL_INPUT_DIRS],
        "replayed_dir": str(LANDING_PAD_INPUT_REPLAYED_DIR),
        "failed_dir": str(LANDING_PAD_INPUT_FAILED_DIR),
        "partition_scheme": "YYYY/MM/DD",
        "listing_lookback_days": LANDING_PAD_LISTING_LOOKBACK_DAYS,
        "watcher_enabled": LANDING_PAD_FILE_WATCHER_ENABLED,
        "watcher_interval_seconds": LANDING_PAD_FILE_WATCHER_INTERVAL_SECONDS,
        "watcher_batch_size": LANDING_PAD_FILE_WATCHER_BATCH_SIZE,
        "watcher_stale_hours": LANDING_PAD_FILE_WATCHER_STALE_HOURS,
        "pending_count": pending_count,
        "pending_rows": pending_rows,
        "additional_pending_rows": additional_pending,
        "replayed_rows": replayed_rows,
        "failed_rows": failed_rows,
    }


@app.post("/landing-pad/input/process")
async def process_landing_pad_input(payload: dict[str, Any] = Body(default={})) -> dict[str, Any]:
    requested_limit = payload.get("limit", LANDING_PAD_FILE_WATCHER_BATCH_SIZE) if isinstance(payload, dict) else LANDING_PAD_FILE_WATCHER_BATCH_SIZE
    safe_limit = max(1, min(int(requested_limit or LANDING_PAD_FILE_WATCHER_BATCH_SIZE), 200))
    gathered = await asyncio.gather(
        *(_process_landing_pad_input_file(path) for path in _landing_pad_input_files(safe_limit)),
        return_exceptions=True,
    )
    results = [
        row if isinstance(row, dict) else {"status": "failed", "error": str(row)}
        for row in gathered
    ]
    processed = len([row for row in results if row.get("status") in {"processed", "processed_partial"}])
    failed = len([row for row in results if row.get("status") in {"failed", "failed_all_rows"}])
    return {
        "requested": safe_limit,
        "processed": processed,
        "failed": failed,
        "remaining": len(_landing_pad_input_files(10_000)),
        "rows": results,
    }


@app.get("/landing-pad/archive")
async def get_landing_pad_archive(limit: int = 50) -> dict[str, Any]:
    safe_limit = max(1, min(int(limit), 200))
    rows = _landing_pad_file_rows(LANDING_PAD_ARCHIVE_DIR, safe_limit)
    return {
        "archive_dir": str(LANDING_PAD_ARCHIVE_DIR),
        "archive_enabled": LANDING_PAD_ARCHIVE_ENABLED,
        "archive_after_days": LANDING_PAD_ARCHIVE_AFTER_DAYS,
        "archive_interval_seconds": LANDING_PAD_ARCHIVE_INTERVAL_SECONDS,
        "rows": rows,
        "count": len(rows),
    }


@app.post("/landing-pad/archive/run")
async def run_landing_pad_archive() -> dict[str, Any]:
    """Manually trigger one archive sweep immediately, independent of the
    background worker's interval — useful for testing and for on-demand
    cleanup without waiting for LANDING_PAD_ARCHIVE_INTERVAL_SECONDS.
    """
    result = _sweep_landing_pad_archive_once()
    return {
        "archive_after_days": LANDING_PAD_ARCHIVE_AFTER_DAYS,
        **result,
    }


@app.get("/agent-work/items")
async def get_agent_work_items(limit: int = 100) -> dict[str, Any]:
    session_factory = getattr(app.state, "session_factory", None)
    if not settings.database_enabled or session_factory is None:
        return {"rows": []}

    async with session_factory() as session:
        repo = IncidentRepository(session)
        rows = await repo.list_agent_work_items(limit=limit)
    return {"rows": rows}


@app.get("/incidents/closed")
async def get_closed_incidents(limit: int = 100) -> dict[str, Any]:
    safe_limit = max(1, min(int(limit), 500))
    session_factory = getattr(app.state, "session_factory", None)
    if settings.database_enabled and session_factory is not None:
        async with session_factory() as session:
            repo = IncidentRepository(session)
            rows = await repo.list_closed_incidents(limit=safe_limit)
        return {"rows": rows, "count": len(rows)}

    rows = list(CLOSED_INCIDENTS)[:safe_limit]
    return {"rows": rows, "count": len(rows)}


@app.get("/incidents/metadata")
async def get_incident_metadata(
    limit: int = 100,
    risk_tier: str | None = None,
    execution_mode: str | None = None,
    transport_provider: str | None = None,
    status: str | None = None,
    service: str | None = None,
) -> dict[str, Any]:
    safe_limit = max(1, min(int(limit), 1000))
    session_factory = getattr(app.state, "session_factory", None)
    if settings.database_enabled and session_factory is not None:
        async with session_factory() as session:
            repo = IncidentRepository(session)
            rows = await repo.list_incident_projections(
                limit=safe_limit,
                risk_tier=risk_tier,
                execution_mode=execution_mode,
                transport_provider=transport_provider,
                status=status,
                service=service,
            )
        return {"rows": rows, "count": len(rows)}

    rows = list(CLOSED_INCIDENTS)
    if risk_tier:
        rows = [row for row in rows if str(row.get("risk") or "").strip().lower() == str(risk_tier).strip().lower()]
    if execution_mode:
        rows = [
            row
            for row in rows
            if str(row.get("execution_mode") or "").strip().lower() == str(execution_mode).strip().lower()
        ]
    if transport_provider:
        rows = [
            row
            for row in rows
            if str(row.get("transport_provider") or "").strip().lower() == str(transport_provider).strip().lower()
        ]
    if status:
        rows = [row for row in rows if str(row.get("status") or "").strip().lower() == str(status).strip().lower()]
    if service:
        rows = [row for row in rows if str(row.get("service") or "").strip() == str(service).strip()]
    rows = rows[:safe_limit]
    return {"rows": rows, "count": len(rows)}


@app.get("/incidents/{incident_id}/stage-completeness")
async def get_incident_stage_completeness(incident_id: str) -> dict[str, Any]:
    session_factory = getattr(app.state, "session_factory", None)
    if not settings.database_enabled or session_factory is None:
        raise HTTPException(status_code=503, detail="Database is not enabled for incident stage completeness")

    async with session_factory() as session:
        repo = IncidentRepository(session)
        result = await repo.get_incident_stage_completeness(incident_id)

    if not result:
        raise HTTPException(status_code=404, detail="No incident stage completeness found for incident")
    return result


@app.post("/onboarding/connectivity", response_model=OnboardingConnectivityResponse)
async def post_onboarding_connectivity(
    payload: OnboardingConnectivityPayload = Body(...),
) -> OnboardingConnectivityResponse:
    if isinstance(payload, dict):
        payload = OnboardingConnectivityPayload.model_validate(payload)
    validated_payload = payload.model_dump(mode="json")
    sanitized = save_onboarding_connectivity(validated_payload)
    await persist_onboarding_connectivity(validated_payload)
    snapshot = OnboardingConnectivitySnapshot.model_validate(sanitized if isinstance(sanitized, dict) else {})
    return OnboardingConnectivityResponse(connectivity=snapshot)


@app.post("/onboarding/complete")
async def post_onboarding_complete(payload: OnboardingCompletePayload = Body(...)) -> dict[str, Any]:
    if isinstance(payload, dict):
        payload = OnboardingCompletePayload.model_validate(payload)

    connectivity = payload.connectivity
    connectivity_payload = connectivity.model_dump(mode="json")
    selected_tool = _select_monitoring_tool(connectivity, payload.selected_monitoring_tool)
    landing_pad_summary = _build_landing_pad_summary(connectivity, selected_tool)
    should_start_rules_onboarding = bool(payload.onboarding_path == "setup_monitoring" and payload.start_rules_onboarding)

    sanitized_connectivity = save_onboarding_connectivity(connectivity_payload)
    await persist_onboarding_connectivity(connectivity_payload)
    connectivity_snapshot = OnboardingConnectivitySnapshot.model_validate(
        sanitized_connectivity if isinstance(sanitized_connectivity, dict) else {}
    )

    response: dict[str, Any] = {
        "project_mode": payload.project_mode,
        "onboarding_path": payload.onboarding_path,
        "connectivity": connectivity_snapshot.model_dump(mode="json"),
        "landing_pad_ingestion": landing_pad_summary,
        "rules_onboarding": {
            "started": False,
            "status": "not-required" if payload.onboarding_path == "existing_monitoring" else "not-requested",
        },
        "rag_documents": [],
        "workflow_steps": _build_onboarding_steps_response(
            onboarding_path=payload.onboarding_path,
            project_mode=payload.project_mode,
            start_rules_onboarding=should_start_rules_onboarding,
            requirements=[],
            rules_result=None,
            prometheus_result=None,
            rag_documents=[],
            landing_pad_summary=landing_pad_summary,
        ),
    }

    requirements = [item for item in payload.plain_language_requirements if str(item or "").strip()]

    if not should_start_rules_onboarding:
        if payload.generate_documents and payload.source_documents:
            response["rag_documents"] = _build_onboarding_rag_documents(
                connectivity=connectivity,
                selected_tool=selected_tool,
                workflow_result={
                    "workflow_id": f"{connectivity.project.name}-service-knowledge",
                    "onboarding_id": f"{connectivity.project.name}-onboarding",
                    "trace_id": "",
                    "generated_rules": [],
                },
                requirements=requirements,
                source_documents=payload.source_documents,
            )
            response["workflow_steps"] = _build_onboarding_steps_response(
                onboarding_path=payload.onboarding_path,
                project_mode=payload.project_mode,
                start_rules_onboarding=False,
                requirements=requirements,
                rules_result=None,
                prometheus_result=None,
                rag_documents=response.get("rag_documents", []),
                landing_pad_summary=landing_pad_summary,
            )
        return response

    endpoint_url = _selected_tool_url(connectivity, selected_tool)

    project_seed = _build_onboarding_rule_seed(connectivity, selected_tool)
    new_rule_payload = NewRuleOnboardingRequest.model_validate(
        {
            "project": project_seed,
            "monitoring_requirements": requirements,
            "target_platforms": [selected_tool],
            "discovery_inputs": {
                "endpoint_url": endpoint_url,
                "deployment_mode": str(connectivity.deployment_mode or "on_prem").strip(),
                "environment": str(connectivity.project.environment or "prod").strip(),
                "region": str(connectivity.project.region or "").strip(),
                "selected_monitoring_tool": selected_tool,
                "generated_from_plain_language": True,
            },
        }
    )

    workflow_result = run_new_rule_pipeline(new_rule_payload)
    await persist_onboarding_pipeline_result(workflow_result)
    await publish_onboarding_pipeline_event(workflow_result)

    prometheus_upload_result: dict[str, Any] | None = None
    if selected_tool == "prometheus":
        prometheus_upload_result = await _generate_upload_and_test_prometheus_rules(
            endpoint_url=endpoint_url,
            project_name=str(connectivity.project.name or "").strip(),
            workflow_id=str(workflow_result.get("workflow_id") or "").strip(),
            generated_rules=workflow_result.get("generated_rules", []) if isinstance(workflow_result.get("generated_rules"), list) else [],
            include_smoke_test_alert=payload.include_smoke_test_alert,
        )

    response["rules_onboarding"] = {
        "started": True,
        "status": str(workflow_result.get("status") or "completed"),
        "workflow_id": str(workflow_result.get("workflow_id") or "").strip(),
        "result": workflow_result,
    }
    if payload.generate_documents:
        response["rag_documents"] = _build_onboarding_rag_documents(
            connectivity=connectivity,
            selected_tool=selected_tool,
            workflow_result=workflow_result,
            requirements=requirements,
            source_documents=payload.source_documents,
        )
    response["workflow_steps"] = _build_onboarding_steps_response(
        onboarding_path=payload.onboarding_path,
        project_mode=payload.project_mode,
        start_rules_onboarding=should_start_rules_onboarding,
        requirements=requirements,
        rules_result=workflow_result,
        prometheus_result=prometheus_upload_result,
        rag_documents=response.get("rag_documents", []),
        landing_pad_summary=landing_pad_summary,
    )
    return response


@app.get("/onboarding/rules/capabilities")
async def get_onboarding_rule_capabilities() -> dict[str, Any]:
    rows = capabilities_catalog()
    return {"rows": rows, "count": len(rows)}


@app.post("/onboarding/rules/pipeline/existing")
async def onboarding_rules_pipeline_existing(payload: ExistingRulePipelineRequest = Body(...)) -> dict[str, Any]:
    result = run_existing_rule_pipeline(payload)
    await persist_onboarding_pipeline_result(result)
    await publish_onboarding_pipeline_event(result)
    return result


@app.post("/onboarding/rules/pipeline/new")
async def onboarding_rules_pipeline_new(payload: NewRuleOnboardingRequest = Body(...)) -> dict[str, Any]:
    result = run_new_rule_pipeline(payload)
    await persist_onboarding_pipeline_result(result)
    await publish_onboarding_pipeline_event(result)
    return result


@app.post("/onboarding/rules/pipeline/create")
async def onboarding_rules_pipeline_new_alias(payload: NewRuleOnboardingRequest = Body(...)) -> dict[str, Any]:
    # Backward-compatible alias for older callers.
    result = run_new_rule_pipeline(payload)
    await persist_onboarding_pipeline_result(result)
    await publish_onboarding_pipeline_event(result)
    return result


@app.get("/onboarding/rules/pipeline/{workflow_id}")
async def get_onboarding_rules_pipeline(workflow_id: str) -> dict[str, Any]:
    session_factory = getattr(app.state, "session_factory", None)
    if not settings.database_enabled or session_factory is None:
        raise HTTPException(status_code=503, detail="Database is not enabled for onboarding workflow lookup")

    async with session_factory() as session:
        repo = IncidentRepository(session)
        rows = await repo.list_onboarding_state()

    matched = find_pipeline_rows(rows, workflow_id)
    if not matched:
        raise HTTPException(status_code=404, detail="Onboarding rule workflow not found")

    latest = matched[-1]
    payload = latest.get("connectivity_payload", {}) if isinstance(latest.get("connectivity_payload"), dict) else {}
    return {
        "workflow_id": workflow_id,
        "status": payload.get("status"),
        "pipeline": payload.get("pipeline"),
        "project_name": latest.get("project_name"),
        "updated_at": latest.get("updated_at"),
        "result": payload.get("result") if isinstance(payload.get("result"), dict) else {},
    }


@app.put("/onboarding/rules/pipeline/{workflow_id}")
async def update_onboarding_rules_pipeline(workflow_id: str, payload: dict[str, Any] = ALERT_BODY) -> dict[str, Any]:
    session_factory = getattr(app.state, "session_factory", None)
    if not settings.database_enabled or session_factory is None:
        raise HTTPException(status_code=503, detail="Database is not enabled for onboarding workflow update")

    async with session_factory() as session:
        repo = IncidentRepository(session)
        rows = await repo.list_onboarding_state()
        matched = find_pipeline_rows(rows, workflow_id)
        if not matched:
            raise HTTPException(status_code=404, detail="Onboarding rule workflow not found")

        latest = matched[-1]
        connectivity_payload = (
            dict(latest.get("connectivity_payload", {}))
            if isinstance(latest.get("connectivity_payload"), dict)
            else {}
        )
        previous_result = connectivity_payload.get("result", {}) if isinstance(connectivity_payload.get("result"), dict) else {}
        incoming_result = payload.get("result", {}) if isinstance(payload.get("result"), dict) else {}
        merged_result = {**previous_result, **incoming_result}

        target_project_name = str(payload.get("project_name") or latest.get("project_name") or "").strip()
        if not target_project_name:
            raise HTTPException(status_code=400, detail="project_name is required")

        project_payload = latest.get("project_payload", {}) if isinstance(latest.get("project_payload"), dict) else {}
        if isinstance(payload.get("project"), dict):
            project_payload = {**project_payload, **payload.get("project", {})}

        connectivity_payload.update(
            {
                "workflow_id": workflow_id,
                "status": str(payload.get("status") or connectivity_payload.get("status") or merged_result.get("status") or "updated"),
                "pipeline": str(connectivity_payload.get("pipeline") or latest.get("provider_name") or "onboarding_pipeline"),
                "summary": payload.get("summary") if isinstance(payload.get("summary"), dict) else connectivity_payload.get("summary", {}),
                "result": merged_result,
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }
        )

        await repo.save_onboarding_state(
            project_name=target_project_name,
            provider_name=str(latest.get("provider_name") or "onboarding_pipeline").strip().lower(),
            owner_team=str(payload.get("owner_team") or latest.get("owner_team") or "").strip() or None,
            environment=str(payload.get("environment") or latest.get("environment") or "").strip() or None,
            region=str(payload.get("region") or latest.get("region") or "").strip() or None,
            endpoint_url=str(payload.get("endpoint_url") or latest.get("endpoint_url") or "").strip() or None,
            test_status=str(connectivity_payload.get("status") or latest.get("test_status") or "updated"),
            test_message=str(payload.get("test_message") or latest.get("test_message") or "Workflow updated by admin"),
            project_payload=project_payload,
            connectivity_payload=connectivity_payload,
            last_tested_at=datetime.now(timezone.utc),
        )
        await session.commit()

    return {
        "workflow_id": workflow_id,
        "status": connectivity_payload.get("status"),
        "pipeline": connectivity_payload.get("pipeline"),
        "project_name": target_project_name,
        "updated_at": connectivity_payload.get("updated_at"),
        "result": connectivity_payload.get("result", {}),
    }


@app.delete("/onboarding/rules/pipeline/{workflow_id}")
async def delete_onboarding_rules_pipeline(workflow_id: str) -> dict[str, Any]:
    session_factory = getattr(app.state, "session_factory", None)
    if not settings.database_enabled or session_factory is None:
        raise HTTPException(status_code=503, detail="Database is not enabled for onboarding workflow delete")

    async with session_factory() as session:
        repo = IncidentRepository(session)
        rows = await repo.list_onboarding_state()
        matched = find_pipeline_rows(rows, workflow_id)
        if not matched:
            raise HTTPException(status_code=404, detail="Onboarding rule workflow not found")

        deleted_total = 0
        for row in matched:
            deleted_total += await repo.delete_onboarding_state(
                str(row.get("project_name") or "").strip(),
                str(row.get("provider_name") or "").strip().lower() or None,
            )
        await session.commit()

    return {"workflow_id": workflow_id, "deleted": deleted_total}


@app.post("/sample/payment-latency/workflow")
async def sample_payment_latency_workflow(
    fast_mode: bool = False,
    x_trace_id: str | None = Header(default=None),
) -> dict[str, Any]:
    return await run_local_payment_workflow(trace_id=x_trace_id, run_comparison=not fast_mode, auto_approve=False)


@app.post("/sample/{flow_id}/workflow")
async def sample_flow_workflow(
    flow_id: str,
    fast_mode: bool = False,
    x_trace_id: str | None = Header(default=None),
) -> dict[str, Any]:
    return await run_local_payment_workflow(
        trace_id=x_trace_id,
        flow_id=flow_id,
        run_comparison=not fast_mode,
        auto_approve=False,
    )


@app.post("/sample/{flow_id}/workflow/continue")
async def continue_flow_workflow(
    flow_id: str,
    payload: dict[str, Any] = ALERT_BODY,
    x_trace_id: str | None = Header(default=None),
) -> dict[str, Any]:
    return await continue_pending_workflow(
        flow_id=flow_id,
        incident_id=str(payload.get("incident_id") or ""),
        recommendation_id=str(payload.get("recommendation_id") or ""),
        decision_token=str(payload.get("decision") or ""),
        approver=str(payload.get("approver") or "").strip() or None,
        channel=str(payload.get("channel") or "").strip() or None,
        comment=str(payload.get("comment") or "").strip() or None,
        modified_action=str(payload.get("modified_action") or "").strip() or None,
        trace_id=x_trace_id,
    )
