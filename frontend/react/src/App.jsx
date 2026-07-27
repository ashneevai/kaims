import { useEffect, useMemo, useRef, useState } from "react";
import {
  ALERT_DOC_KIND_OPTIONS,
  APPROVAL_NAV_PRIMARY_ROLES,
  DOCUMENT_PROVIDER_ROLES,
  MONITORING_TOOL_OPTIONS,
  ONBOARDING_SOURCE_DOC_BUCKETS,
  ONBOARDING_SOURCE_DOC_EXTENSIONS,
  ONBOARDING_SOURCE_DOC_SAMPLE_FILES,
  ROLE_ALLOWED_TABS,
} from "./onboardingConfig";
import {
  classifyOnboardingDocumentType,
  deriveMonitoringRequirementsFromDocument,
  extractMonitoringToolAndUrl,
  extractOnboardingProjectName,
  looksLikeUuid,
  normalizeMatchToken,
  normalizeRoleName,
  severityOverrideKey,
  simplifyMonitoringUrl,
  summarizeUploadedDocument,
} from "./onboardingUtils";

const DEFAULT_ALERT = {
  source: "monitoring-adapter",
  name: "PaymentLatencySpike",
  service: "payments",
  severity: "high",
  description: "Payment latency crossed 2.5s threshold for 5m",
};

const REAL_USE_CASE_SCOPE = "real-usecases";
const TEST_USE_CASE_SCOPE = "test-usecases";
const CORE_MONITOR_PROJECTS = ["KaiOps", "Telemetry"];
const FIXED_MONITOR_SCOPES = [...CORE_MONITOR_PROJECTS, REAL_USE_CASE_SCOPE, TEST_USE_CASE_SCOPE];

const SERVICE_TOPIC_FLOW = [
  { service: "monitoring-adapter", consumes: "-", publishes: "raw-alerts", agent: "alert" },
  { service: "alert-intelligence", consumes: "raw-alerts", publishes: "enriched-alerts", agent: "Alert Intelligence Agent" },
  { service: "orchestrator", consumes: "enriched-alerts", publishes: "orchestration-events", agent: "Orchestrator Agent" },
  { service: "context-agent", consumes: "orchestration-events", publishes: "context-events", agent: "Context Intelligence Agent" },
  { service: "resolution-agent", consumes: "context-events", publishes: "resolution-events", agent: "Resolution Intelligence Agent" },
  { service: "approval-service", consumes: "resolution-events", publishes: "approval-events", agent: "Human Approval Layer" },
  { service: "remediation-engine", consumes: "approval-events", publishes: "remediation-events", agent: "Remediation Automation Engine" },
  { service: "closure-service", consumes: "remediation-events", publishes: "closure-events", agent: "Closure & Validation" },
];

const RECOMMENDED_WORKER_PROFILE = {
  "monitoring-adapter": { containers: 1, workers: 2, role: "landing-pad intake" },
  "alert-intelligence": { containers: 1, workers: 2, role: "dedupe and correlation workers" },
  orchestrator: { containers: 1, workers: 2, role: "master routing workers" },
  "context-agent": { containers: 1, workers: 3, role: "RAG and evidence workers" },
  "resolution-agent": { containers: 1, workers: 3, role: "RCA and recommendation workers" },
  "approval-service": { containers: 1, workers: 1, role: "decision gate" },
  "remediation-engine": { containers: 1, workers: 2, role: "execution policy workers" },
  "closure-service": { containers: 1, workers: 2, role: "post-check workers" },
};

const SCALE_CAPACITY_GUIDE = [
  {
    rate: "100/hr",
    perSecond: "0.03/sec",
    masters: "1 master",
    workers: "1 worker per service",
    vm: "1 VM: 2 vCPU / 8 GB RAM",
    config: "MESSAGE_BUS_WORKER_COUNT=1",
    state: "Local Compose state is acceptable for dev/smoke.",
  },
  {
    rate: "500/hr",
    perSecond: "0.14/sec",
    masters: "1 master",
    workers: "1 alert-intel, 2 context, 2 resolution, 1 remediation",
    vm: "1 VM: 4 vCPU / 16 GB RAM",
    config: "Use docker-compose.scale.yml; CONTEXT_AGENT_WORKERS=2, RESOLUTION_AGENT_WORKERS=2",
    state: "Move Redis/MySQL to managed or dedicated VM if dashboards and approvals are active.",
  },
  {
    rate: "1,000/hr",
    perSecond: "0.28/sec",
    masters: "2 orchestrators",
    workers: "2 alert-intel, 3 context, 3 resolution, 2 closure, 1-2 remediation",
    vm: "2 VMs: 4 vCPU / 16 GB each, or 1 VM: 8 vCPU / 32 GB",
    config: "Enable Kafka/RabbitMQ; ORCHESTRATOR_WORKERS=2, ALERT_INTELLIGENCE_WORKERS=2",
    state: "Use shared DB, shared cache, shared message bus, shared vector index.",
  },
  {
    rate: "10,000/hr",
    perSecond: "2.78/sec",
    masters: "3+ orchestrators",
    workers: "4+ alert-intel, 6-10 context, 6-10 resolution, 3+ remediation",
    vm: "3-6 VMs: 8 vCPU / 32 GB each, or AKS/VMSS node pool",
    config: "Externalize DB/Redis/bus/vector store; tune RAG_EMBEDDING_BATCH_SIZE and provider limits",
    state: "Production HA required: load balancer, managed DB, Kafka/Event Hubs, vector DB, object storage.",
  },
];

const AGENT_DISPLAY_ALIASES = {
  "orchestrator agent": "Master Agent",
  orchestrator: "Master Agent",
  "closure & validation": "Validator Agent",
  "closure-service": "Validator Agent",
};

const AGENT_ROUTE_ALIASES = {
  "master agent": "orchestrator agent",
  "master agent (orchestrator agent)": "orchestrator agent",
  "validator agent": "closure & validation",
  "validator agent (closure & validation)": "closure & validation",
};

const PREFERENCE_STORAGE_KEY = "kaiops.ui.preferences.v1";
const UI_THEME_VALUES = new Set(["auto", "light", "dark"]);
const TAB_SHORTCUT_MAP = {
  Digit1: "home",
  Digit2: "approval",
  Digit3: "executive",
  Digit4: "admin",
  Digit5: "trace",
  Digit6: "safety",
  Digit7: "rag",
  Digit9: "closed",
  Digit0: "summary",
};
const VALID_TABS = new Set(Object.values(TAB_SHORTCUT_MAP));
function extractObservedRoutingMetrics(workflow) {
  if (!workflow || typeof workflow !== "object") {
    return {};
  }
  const rawEvents = [workflow.events, workflow.workflow_events, workflow.agent_events]
    .find((items) => Array.isArray(items)) || [];
  const events = rawEvents.filter((item) => item && typeof item === "object");
  const traceRows = [workflow.event_trace, workflow.trace_events, workflow?.trace?.events]
    .find((items) => Array.isArray(items)) || [];
  const latestEvent = [...events].reverse().find((item) => item && typeof item === "object") || null;
  const orchestratorEvent = [...events].reverse().find((item) => {
    const agent = String(item?.agent || "").trim().toLowerCase();
    return agent.includes("orchestrator") || agent.includes("master");
  }) || latestEvent;
  const latestTrace = [...traceRows]
    .filter((row) => row && typeof row === "object")
    .sort((a, b) => {
      const aTime = parseUtcTimestamp(a.timestamp)?.getTime() || 0;
      const bTime = parseUtcTimestamp(b.timestamp)?.getTime() || 0;
      return bTime - aTime;
    })[0] || null;

  const recommendationMetadata =
    typeof workflow?.recommendation?.metadata === "object" ? workflow.recommendation.metadata : {};
  const metrics = typeof orchestratorEvent?.metrics === "object"
    ? { ...orchestratorEvent.metrics }
    : (typeof latestEvent?.metrics === "object" ? { ...latestEvent.metrics } : {});
  const decision =
    (typeof workflow?.decision === "object" && workflow.decision)
    || (typeof workflow?.orchestration_decision === "object" && workflow.orchestration_decision)
    || (typeof recommendationMetadata?.orchestration_decision === "object" && recommendationMetadata.orchestration_decision)
    || (typeof orchestratorEvent?.decision === "object" && orchestratorEvent.decision)
    || {};

  const provider =
    metrics.message_bus_provider
    || decision.message_bus_provider
    || latestTrace?.transport_provider
    || latestEvent?.input?.transport_provider
    || latestEvent?.transport_provider
    || workflow?.transport_provider
    || "";

  return {
    ...metrics,
    workflow: metrics.workflow || decision.workflow || workflow?.scenario?.id || "",
    next_action:
      metrics.next_action
      || decision.next_action
      || workflow?.next_step
      || workflow?.recommendation?.recommended_action
      || "",
    requires_approval:
      metrics.requires_approval
      ?? decision.requires_approval
      ?? workflow?.approval?.required
      ?? workflow?.recommendation?.requires_approval,
    risk_tier: metrics.risk_tier || decision.risk_tier || latestTrace?.risk_tier || "",
    execution_mode: metrics.execution_mode || decision.execution_mode || latestTrace?.execution_mode || "",
    policy_version: metrics.policy_version || decision.policy_version || workflow?.recommendation?.policy_version || "",
    message_bus_provider: provider,
  };
}

function normalizeMatchTokens(value) {
  return String(value || "")
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .map((item) => item.trim())
    .filter((item) => item.length >= 3);
}

function hasTokenOverlap(left, right) {
  const leftTokens = normalizeMatchTokens(left);
  const rightTokens = normalizeMatchTokens(right);
  if (!leftTokens.length || !rightTokens.length) {
    return false;
  }
  const rightSet = new Set(rightTokens);
  return leftTokens.some((token) => rightSet.has(token));
}

const KAIOPS_CORE_SERVICE_SET = new Set([
  "api-gateway",
  "monitoring-adapter",
  "alert-intelligence",
  "orchestrator",
  "context-agent",
  "resolution-agent",
  "approval-service",
  "remediation-engine",
  "closure-service",
  "model-router",
]);

function normalizeMonitorToken(value) {
  return String(value || "")
    .trim()
    .toLowerCase()
    .replace(/[\s_]+/g, "-")
    .replace(/-+/g, "-");
}

function isKaiopsCoreSelection(value) {
  const token = normalizeMonitorToken(value);
  return token === "kaiops-core" || token === "kaiops-core1" || token === "kaiops" || token === "core";
}

function isKaiopsCoreAlert(row) {
  const labels = typeof row?.labels === "object" && row?.labels ? row.labels : {};
  const metadata = typeof row?.metadata === "object" && row?.metadata ? row.metadata : {};
  const service = String(row?.service || labels?.service || "").trim().toLowerCase();
  const alertName = String(row?.name || labels?.alertname || "").trim().toLowerCase();
  const ownerTeam = String(metadata?.owner_team || labels?.team || "").trim().toLowerCase();
  const project = String(row?.project || row?.project_name || row?.application || labels?.project || labels?.project_name || "")
    .trim()
    .toLowerCase();

  if (project.includes("telemetry") || project.includes("astronomy")) {
    return false;
  }
  if (KAIOPS_CORE_SERVICE_SET.has(service)) {
    return true;
  }
  if (alertName.includes("kaiops")) {
    return true;
  }
  if (ownerTeam === "platform-ops" || ownerTeam === "kaiops") {
    return true;
  }
  return project.includes("kaiops");
}

const PROMPT_FRAGMENT_PATTERNS = [
  "identify the most likely root cause using only",
  "assess customer, service, dependency, and business impact",
  "generate an operator-safe remediation",
];

function isPromptFragment(value) {
  const text = String(value || "").trim().toLowerCase();
  return PROMPT_FRAGMENT_PATTERNS.some((fragment) => text.includes(fragment));
}

function cleanRecommendationText(value, fallback = "-") {
  if (value == null) {
    return fallback;
  }
  if (typeof value === "object") {
    // Jira Cloud rich-text (ADF) is source evidence, never an RCA result.
    if (value?.type === "doc" && Array.isArray(value?.content)) {
      return fallback;
    }
  }
  const text = String(value).trim();
  if (!text) {
    return fallback;
  }
  const normalized = text.toLowerCase();
  if (
    normalized === "[object object]"
    || (
      (normalized.startsWith("{'type': 'doc'") || normalized.startsWith('{"type":"doc"'))
      && (normalized.includes("'content'") || normalized.includes('"content"'))
    )
  ) {
    return fallback;
  }
  const payload = parseStructuredIntelligence(text);
  if (payload) {
    const keys = [
      "root_cause",
      "cause",
      "impact_summary",
      "service_impact",
      "impact",
      "customer_impact",
      "dependency_impact",
      "severity_rationale",
      "recommended_action",
      "action",
      "summary",
      "content",
      "title",
    ];
    for (const key of keys) {
      const candidate = String(payload[key] || "").trim();
      if (candidate && !isPromptFragment(candidate)) {
        return candidate;
      }
    }
    if (payload.metadata?.fallback) {
      return fallback;
    }
    return fallback;
  }
  return isPromptFragment(text) ? fallback : text;
}

function filterAlertsForMonitor(rows, applicationToMonitor) {
  const target = String(applicationToMonitor || "").trim().toLowerCase();
  const alertRows = Array.isArray(rows) ? rows : [];
  if (!target) {
    return alertRows;
  }
  if (target === REAL_USE_CASE_SCOPE) {
    return alertRows.filter((row) => !isGeneratedOrTestAlert(row));
  }
  if (target === TEST_USE_CASE_SCOPE) {
    return alertRows.filter((row) => isGeneratedOrTestAlert(row));
  }
  return alertRows.filter((row) => {
    const labels = typeof row?.labels === "object" && row?.labels ? row.labels : {};
    const explicitProject = String(
      row?.project_name
      || labels?.project_name
      || row?.project
      || labels?.project
      || row?.application
      || labels?.application
      || ""
    ).trim().toLowerCase();
    if (target === "telemetry") {
      return explicitProject === "telemetry" || explicitProject === "astronomy-shop";
    }
    if (isKaiopsCoreSelection(target) && (explicitProject === "telemetry" || explicitProject === "astronomy-shop")) {
      return false;
    }
    if (isKaiopsCoreSelection(target)) {
      return isKaiopsCoreAlert(row);
    }
    const metadata = typeof row?.metadata === "object" && row?.metadata ? row.metadata : {};
    const candidates = [
      row?.application,
      row?.project,
      row?.project_name,
      row?.service,
      row?.source,
      row?.name,
      metadata?.owner_team,
      labels?.application,
      labels?.project,
      labels?.project_name,
      labels?.deployment,
      labels?.namespace,
      labels?.service,
      labels?.job,
      labels?.instance,
      labels?.team,
      labels?.alertname,
    ]
      .map((value) => String(value || "").trim().toLowerCase())
      .filter(Boolean);
    return candidates.some(
      (value) =>
        value === target ||
        value.includes(target) ||
        target.includes(value) ||
        hasTokenOverlap(value, target)
    );
  });
}

function filterRowsForMonitor(rows, applicationToMonitor) {
  const target = String(applicationToMonitor || "").trim().toLowerCase();
  const items = Array.isArray(rows) ? rows : [];
  if (!target) {
    return items;
  }
  if (target === REAL_USE_CASE_SCOPE) {
    return items.filter((row) => !isGeneratedOrTestAlert(row));
  }
  if (target === TEST_USE_CASE_SCOPE) {
    return items.filter((row) => isGeneratedOrTestAlert(row));
  }
  return items.filter((row) => {
    if (isKaiopsCoreSelection(target)) {
      const service = String(row?.service || "").trim().toLowerCase();
      const owner = String(row?.owner || row?.owner_team || "").trim().toLowerCase();
      return KAIOPS_CORE_SERVICE_SET.has(service) || owner === "platform-ops" || owner === "kaiops";
    }
    const labels = typeof row?.labels === "object" && row?.labels ? row.labels : {};
    const candidates = [
      row?.application,
      row?.project,
      row?.project_name,
      row?.service,
      row?.source,
      row?.provider_name,
      row?.owner,
      row?.owner_team,
      labels?.application,
      labels?.project,
      labels?.project_name,
      labels?.deployment,
      labels?.namespace,
      labels?.service,
      labels?.job,
      labels?.instance,
    ]
      .map((value) => String(value || "").trim().toLowerCase())
      .filter(Boolean);
    return candidates.some(
      (value) =>
        value === target ||
        value.includes(target) ||
        target.includes(value) ||
        hasTokenOverlap(value, target)
    );
  });
}

function isGeneratedOrTestAlert(row) {
  const tokens = [
    row?.name,
    row?.alert_name,
    row?.rule_name,
    row?.rule,
    row?.alert_rule,
    row?.labels?.alertname,
    row?.service,
    row?.application,
    row?.project_name,
    row?.project,
  ].map((value) => String(value || "").toLowerCase()).join(" ");
  return /(^|[-_\s])(e2e|ui-e2e|admin-e2e|setup-doc-e2e|stress|smoke|onboarding-smoke-test)([-_\s]|$)/i.test(tokens)
    || tokens.includes("stresspipelinealert")
    || tokens.includes("onboarding-smoke-test");
}

function isEphemeralProjectName(value) {
  const token = String(value || "").trim().toLowerCase();
  if (!token) {
    return false;
  }
  return /(^|[-_\s])(e2e|ui-e2e|admin-e2e|setup-doc-e2e|stress|smoke|onboarding-smoke-test)([-_\s]|$)/i.test(token);
}

function normalizeAlertChannel(row) {
  const labels = typeof row?.labels === "object" && row?.labels ? row.labels : {};
  const metadata = typeof row?.metadata === "object" && row?.metadata ? row.metadata : {};
  const projectName = String(
    row?.project_name
    || row?.application
    || labels?.project_name
    || labels?.application
    || ""
  ).trim().toLowerCase();
  const explicitOrigin = String(
    labels?.origin_system
    || labels?.source_system
    || metadata?.origin_system
    || row?.origin_system
    || ""
  ).trim().toLowerCase();
  const explicitChannel = String(
    labels?.ingestion_channel
    || labels?.source_channel
    || metadata?.ingestion_channel
    || row?.ingestion_channel
    || ""
  ).trim().toLowerCase();
  // OpenSearch is the transport for logs from both KaiOps and the
  // OpenTelemetry demo. Preserve the owning project before classifying the
  // transport as a generic log channel.
  if (projectName === "telemetry" || projectName === "astronomy-shop") return "telemetry";
  if (explicitOrigin.includes("telemetry") || explicitOrigin.includes("opentelemetry")) return "telemetry";
  if (explicitOrigin.includes("email") || explicitChannel.includes("email")) return "email";
  if (explicitOrigin.includes("jira") || explicitOrigin.includes("ticket") || explicitChannel.includes("ticket")) return "ticket";
  if (explicitOrigin.includes("log") || explicitOrigin.includes("opensearch") || explicitChannel.includes("log")) return "log";
  const source = [
    row?.source,
    row?.provider,
    row?.provider_name,
    row?.source_type,
    row?.origin,
    row?.channel_type,
    row?.channel,
    row?.ticket_provider,
    row?.notification_channel,
    row?.integration,
    metadata?.source,
    metadata?.channel,
    labels?.source,
    labels?.channel,
    labels?.job,
    labels?.alertname,
  ]
    .map((value) => String(value || "").trim().toLowerCase())
    .filter(Boolean)
    .join(" ");
  if (
    source.includes("telemetry")
    || source.includes("opentelemetry")
    || source.includes("astronomy")
  ) {
    return "telemetry";
  }
  if (
    source.includes("prometheus")
    || source.includes("alertmanager")
    || source.includes("monitoring-adapter")
  ) {
    return "prometheus";
  }
  if (source.includes("email") || source.includes("smtp") || source.includes("mail") || source.includes("outlook")) {
    return "email";
  }
  if (
    source.includes("opensearch")
    || source.includes("log-alert")
    || source.includes("log monitoring")
  ) {
    return "log";
  }
  if (
    source.includes("jira")
    || source.includes("ticket")
    || source.includes("itsm")
    || source.includes("servicenow")
    || source.includes("snow")
    || source.includes("incident")
    || source.includes("closed-incidents")
  ) {
    return "ticket";
  }
  if (
    String(labels?.alertname || "").trim()
    || String(row?.expr || row?.expression || row?.query || "").trim()
  ) {
    return "prometheus";
  }
  return "prometheus";
}

function sourceChannelLabel(value) {
  const key = String(value || "").trim().toLowerCase();
  if (key === "prometheus") return "Prometheus";
  if (key === "email") return "Email";
  if (key === "ticket") return "Ticket";
  if (key === "telemetry") return "Telemetry / Prometheus";
  if (key === "log") return "Logs / OpenSearch";
  if (key === "other") return "Other";
  return key || "Unknown";
}

function summarizeAlertSources(rows) {
  const summary = { prometheus: 0, telemetry: 0, email: 0, ticket: 0, log: 0 };
  (Array.isArray(rows) ? rows : []).forEach((row) => {
    const channels = Array.isArray(row?.source_channels) && row.source_channels.length
      ? row.source_channels
      : [normalizeAlertChannel(row)];
    channels.forEach((channel) => {
      const key = String(channel || "").trim().toLowerCase();
      if (summary[key] !== undefined) {
        summary[key] += 1;
      }
    });
  });
  return summary;
}

function monitorScopeLabel(scope) {
  const key = String(scope || "").trim().toLowerCase();
  if (key === REAL_USE_CASE_SCOPE) {
    return "All Applications (Real Signals)";
  }
  if (key === TEST_USE_CASE_SCOPE) {
    return "Test Use Cases";
  }
  if (key === "telemetry") {
    return "Telemetry (Application Only)";
  }
  if (key === "kaiops") {
    return "KaiOps (Application Only)";
  }
  return scope || "Real Use Cases";
}

function alertTimeMs(row) {
  return (
    parseUtcTimestamp(row?.created_at || row?.starts_at || row?.closed_at || row?.updated_at)?.getTime()
    || 0
  );
}

function alertIdentityKeys(row) {
  // Different sources populate different identity fields for the *same* real-world alert:
  // a landing-pad file listing carries no fingerprint/incident_id at all (see
  // _landing_pad_file_rows on the backend, which never surfaces labels), while the
  // primary /alerts/all API row for that same alert does. Returning every candidate key
  // (instead of picking just the single highest-priority one) lets the caller union two
  // rows together if ANY key overlaps, rather than requiring both sides to agree on which
  // identity field happened to be available.
  const labels = typeof row?.labels === "object" && row?.labels ? row.labels : {};
  const keys = [];

  const fingerprint = String(
    row?.fingerprint
    || row?.alert_fingerprint
    || labels?.alert_fingerprint
    || labels?.fingerprint
    || ""
  ).trim();
  if (fingerprint) {
    keys.push(`fingerprint:${fingerprint.toLowerCase()}`);
  }

  const incidentId = String(row?.incident_id || "").trim();
  if (incidentId) {
    keys.push(`incident:${incidentId.toLowerCase()}`);
  }

  const correlation = String(row?.correlation_id || row?.trace_id || "").trim();
  if (correlation) {
    keys.push(`correlation:${correlation.toLowerCase()}`);
  }

  const name = String(row?.name || row?.alert_name || labels?.alertname || "").trim().toLowerCase();
  const service = String(row?.service || labels?.service || labels?.job || "").trim().toLowerCase();
  if (name && service) {
    const severity = String(row?.severity || labels?.severity || "").trim().toLowerCase();
    const timestampMs = alertTimeMs(row);
    const bucket = timestampMs > 0 ? Math.floor(timestampMs / (5 * 60 * 1000)) : 0;
    keys.push(`composite:${name}|${service}|${severity}|${bucket}`);
  }

  return keys;
}

function alertApplicationCandidate(row) {
  const application = String(row?.application || "").trim();
  const service = String(row?.service || "").trim();
  // An application value that's just a copy of the service name is almost always a bad
  // fallback (some mappers default "application" to "service" when the real project/app
  // name is unknown), not a genuine project label -- don't let it win over a real one.
  return application && application.toLowerCase() !== service.toLowerCase() ? application : "";
}

function alertRowScore(row) {
  const status = String(row?.status || row?.state || "").trim().toLowerCase();
  const openScore = isApprovalResolvedStatus(status) || row?._closed_incident ? 0 : 10;
  const dataScore = [row?.trace_id, row?.correlation_id, row?.description, row?.annotations?.description]
    .filter((item) => String(item || "").trim()).length;
  return openScore + dataScore;
}

function resolveCanonicalAlertRow(row, candidates) {
  if (!row || typeof row !== "object") {
    return row;
  }
  const rowKeys = new Set(alertIdentityKeys(row));
  if (!rowKeys.size) {
    return row;
  }
  const matches = (Array.isArray(candidates) ? candidates : []).filter((candidate) => {
    if (!candidate || typeof candidate !== "object") {
      return false;
    }
    return alertIdentityKeys(candidate).some((key) => rowKeys.has(key));
  });
  if (!matches.length) {
    return row;
  }
  return matches
    .slice()
    .sort((left, right) => {
      const leftCanonical = ALERT_UUID_PATTERN.test(String(left?.alert_id || left?.id || "")) ? 1 : 0;
      const rightCanonical = ALERT_UUID_PATTERN.test(String(right?.alert_id || right?.id || "")) ? 1 : 0;
      if (leftCanonical !== rightCanonical) {
        return rightCanonical - leftCanonical;
      }
      const leftLanding = left?._stream_kind === "landing_pad" ? 1 : 0;
      const rightLanding = right?._stream_kind === "landing_pad" ? 1 : 0;
      if (leftLanding !== rightLanding) {
        return leftLanding - rightLanding;
      }
      return alertRowScore(right) - alertRowScore(left);
    })[0];
}

function dedupeAndConsolidateAlertRows(rows, options = {}) {
  const allowedChannels = new Set(
    Array.isArray(options.channels)
      ? options.channels
      : ["prometheus", "telemetry", "email", "ticket", "log"]
  );
  const keyToGroup = new Map();
  const groups = [];

  (Array.isArray(rows) ? rows : []).forEach((row) => {
    if (!row || typeof row !== "object") {
      return;
    }
    const channel = normalizeAlertChannel(row);
    if (!allowedChannels.has(channel)) {
      return;
    }

    const candidateKeys = alertIdentityKeys(row);
    // A row with zero candidate keys (no name/service and no id at all) can't be matched
    // to anything -- give it a unique key so it still shows up as its own row instead of
    // silently colliding with every other keyless row under a single shared bucket.
    const lookupKeys = candidateKeys.length ? candidateKeys : [`row:${groups.length}:${Math.random()}`];
    let group = null;
    for (const key of lookupKeys) {
      if (keyToGroup.has(key)) {
        group = keyToGroup.get(key);
        break;
      }
    }

    if (!group) {
      group = { row: { ...row, source_channel: channel, source_channels: [channel] }, channels: new Set([channel]) };
      groups.push(group);
    } else {
      group.channels.add(channel);
      const incomingScore = alertRowScore(row);
      const existingScore = alertRowScore(group.row);
      const incomingTime = alertTimeMs(row);
      const existingTime = alertTimeMs(group.row);
      const incomingIsLandingPad = row?._stream_kind === "landing_pad";
      const existingIsLandingPad = group.row?._stream_kind === "landing_pad";
      const shouldReplace = existingIsLandingPad && !incomingIsLandingPad
        ? true
        : !existingIsLandingPad && incomingIsLandingPad
          ? false
          : incomingScore > existingScore || (incomingScore === existingScore && incomingTime > existingTime);
      const priorApplication = alertApplicationCandidate(group.row);
      const incomingApplication = alertApplicationCandidate(row);
      if (shouldReplace) {
        group.row = { ...row, source_channel: channel };
        if (!alertApplicationCandidate(group.row) && priorApplication) {
          group.row.application = priorApplication;
        }
      } else if (!priorApplication && incomingApplication) {
        group.row.application = incomingApplication;
      }
    }

    // Register every candidate key from this row against the resolved group so a later
    // row matching via a *different* one of these keys still merges into the same group.
    lookupKeys.forEach((key) => keyToGroup.set(key, group));
  });

  return groups
    .map((entry) => ({
      ...entry.row,
      source_channels: Array.from(entry.channels).sort(),
    }))
    .sort((a, b) => alertTimeMs(b) - alertTimeMs(a));
}

function mapClosedIncidentToAlertStreamRow(row) {
  const payload = row?.projection_payload && typeof row.projection_payload === "object" ? row.projection_payload : {};
  const eventPayload = payload?.event_payload && typeof payload.event_payload === "object" ? payload.event_payload : {};
  const service = String(row?.service || eventPayload.service || "-").trim();
  const incidentId = String(row?.incident_id || row?.flow_id || "").trim();
  const alertId = String(row?.alert_id || incidentId || "").trim();
  const status = String(row?.status || "closed").trim();
  const closedAt = String(row?.closed_at || row?.updated_at || "").trim();
  const alertName = String(
    row?.alert_name
    || row?.name
    || eventPayload.alert_name
    || eventPayload.alert_type
    || (service && service !== "-" ? `${service} closed incident` : "Closed incident")
  ).trim();
  return {
    ...row,
    alert_id: alertId,
    id: alertId || incidentId,
    incident_id: incidentId,
    name: alertName,
    alert_name: alertName,
    rule_name: row?.rule_name || row?.alert_type || eventPayload.alert_type || alertName,
    application: row?.application || row?.project_name || row?.project || service,
    service,
    severity: row?.severity || "info",
    status,
    state: status,
    created_at: closedAt || row?.created_at || row?.updated_at,
    starts_at: row?.starts_at || closedAt,
    closed_at: closedAt,
    source: row?.source || "closed-incidents",
    _stream_kind: "recent_closed",
    _closed_incident: true,
    annotations: {
      ...(row?.annotations || {}),
      description: eventPayload.action_taken || row?.summary || "Recently closed incident.",
    },
  };
}

function projectHintFromAlertRow(row) {
  const labels = typeof row?.labels === "object" && row?.labels ? row.labels : {};
  const candidates = [
    row?.application,
    row?.project_name,
    row?.project,
    labels?.application,
    labels?.project_name,
    labels?.project,
  ]
    .map((value) => String(value || "").trim())
    .filter(Boolean);
  return candidates[0] || "";
}

const ALERT_UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function mapLandingPadRowToAlertStreamRow(row, index = 0) {
  const payload = row && typeof row === "object" ? row : {};
  const labels = typeof payload.labels === "object" && payload.labels ? payload.labels : {};
  const incidentId = String(payload.incident_id || payload.id || payload.alert_id || payload.file || `landing-${index + 1}`).trim();
  const alertName = String(payload.name || payload.alert_name || payload.alertname || labels.alertname || "Landing Pad Alert").trim();
  const channel = normalizeAlertChannel(payload);
  return {
    ...payload,
    id: incidentId,
    alert_id: String(payload.alert_id || incidentId).trim(),
    incident_id: String(payload.incident_id || incidentId).trim(),
    name: alertName,
    alert_name: alertName,
    application: String(payload.application || payload.project_name || payload.project || labels.application || labels.project || labels.project_name || "").trim(),
    service: String(payload.service || labels.service || labels.job || "-").trim(),
    severity: String(payload.severity || labels.severity || "warning").trim().toLowerCase(),
    status: String(payload.status || payload.alert_status || "open").trim().toLowerCase(),
    state: String(payload.state || payload.alert_status || payload.status || "open").trim().toLowerCase(),
    created_at: payload.received_at || payload.created_at || payload.starts_at || payload.modified_at || payload.updated_at || "",
    starts_at: payload.starts_at || payload.received_at || payload.created_at || "",
    source: String(payload.source || payload.provider || payload.channel || "landing-pad").trim(),
    source_channel: channel,
    _stream_kind: "landing_pad",
  };
}

function mergeAlertStreamRows(openRows, recentClosedRows) {
  const merged = [];
  const seen = new Set();
  const add = (row) => {
    if (!row || typeof row !== "object") {
      return;
    }
    const key = String(row.alert_id || row.id || row.incident_id || "").trim();
    if (key && seen.has(key)) {
      return;
    }
    if (key) {
      seen.add(key);
    }
    merged.push(row);
  };
  (Array.isArray(openRows) ? openRows : []).forEach(add);
  (Array.isArray(recentClosedRows) ? recentClosedRows : []).map(mapClosedIncidentToAlertStreamRow).forEach(add);
  return dedupeAndConsolidateAlertRows(
    merged,
    { channels: ["prometheus", "telemetry", "email", "ticket", "log"] }
  );
}

function onboardingSourceDocCategoryLabel(category) {
  const key = String(category || "other").trim();
  if (key === "knowledge_pack") {
    return "Service Knowledge";
  }
  return ONBOARDING_SOURCE_DOC_BUCKETS.find((bucket) => bucket.key === key)?.label || "Other Evidence";
}

function fallbackFetchTargets(path) {
  const normalized = String(path || "").trim();
  if (!normalized) {
    return [];
  }
  const targets = [normalized];
  const processedResultPrefix = "/monitoring-adapter/alerts/";
  const processedResultSuffix = "/processed-result";
  if (normalized.startsWith(processedResultPrefix) && normalized.endsWith(processedResultSuffix)) {
    const alertId = normalized.slice(processedResultPrefix.length, normalized.length - processedResultSuffix.length);
    if (alertId) {
      targets.push(`/api-gateway/alerts/${alertId}/processed-result`);
    }
  }
  return Array.from(new Set(targets));
}

async function fetchJson(path, options = {}) {
  const maxAttemptsRaw = Number(options?.maxAttempts);
  const maxAttempts = Number.isFinite(maxAttemptsRaw) && maxAttemptsRaw >= 1
    ? Math.min(Math.max(Math.floor(maxAttemptsRaw), 1), 4)
    : 3;
  let lastError = null;
  const { authenticated, onUnauthorized, maxAttempts: _maxAttempts, ...fetchOptions } = options || {};
  const targets = fallbackFetchTargets(path);
  const requestTarget = targets[0] || path;
  const timeoutMsRaw = Number(fetchOptions.timeoutMs);
  const timeoutMs = Number.isFinite(timeoutMsRaw) && timeoutMsRaw > 0 ? timeoutMsRaw : 15000;

  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    for (const target of targets) {
      const controller = new AbortController();
      const timeoutHandle = setTimeout(() => controller.abort(new Error(`Request timeout after ${timeoutMs}ms`)), timeoutMs);
      try {
        const response = await fetch(target, {
          ...fetchOptions,
          signal: controller.signal,
          headers: {
            "Content-Type": "application/json",
            ...(fetchOptions.headers || {}),
          },
        });
        clearTimeout(timeoutHandle);

        if (!response.ok) {
          const text = await response.text();
          if (response.status === 401 && authenticated && typeof onUnauthorized === "function") {
            onUnauthorized(text, requestTarget);
            throw new Error("Session expired. Please sign in again.");
          }
          const shouldRetry = response.status >= 500 && attempt < maxAttempts;
          if (shouldRetry) {
            await new Promise((resolve) => setTimeout(resolve, attempt * 500));
            break;
          }
          throw new Error(`HTTP ${response.status}: ${text || "request failed"}`);
        }

        return response.json();
      } catch (error) {
        clearTimeout(timeoutHandle);
        const message = String(error?.message || "");
        if (message === "Session expired. Please sign in again.") {
          throw error;
        }
        lastError = message === "Failed to fetch"
          ? new Error(`Failed to reach ${requestTarget}. Open the UI through http://localhost:8501 with Docker/nginx running, or use the Vite proxy with api-gateway on http://localhost:8010.`)
          : error;
        if (target !== targets[targets.length - 1]) {
          continue;
        }
        if (attempt < maxAttempts) {
          await new Promise((resolve) => setTimeout(resolve, attempt * 500));
        }
      }
    }
  }

  throw lastError || new Error("request failed");
}

function HealthBadge({ ok, label }) {
  return (
    <span className={`health ${ok ? "ok" : "error"}`}>
      <span className="health-dot" />
      {label}
    </span>
  );
}

function htmlEscape(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function asDisplayValue(value) {
  if (value === null || value === undefined || value === "") {
    return "-";
  }
  if (typeof value === "object") {
    try {
      return JSON.stringify(value);
    } catch (_error) {
      return "[object]";
    }
  }
  return String(value);
}

function parseUtcTimestamp(value) {
  const raw = String(value || "").trim();
  if (!raw) {
    return null;
  }
  const normalized = /Z$|[+-]\d\d:\d\d$/.test(raw) ? raw : `${raw}Z`;
  const parsed = new Date(normalized);
  if (Number.isNaN(parsed.getTime())) {
    return null;
  }
  return parsed;
}

function formatIstTimestamp(value) {
  const parsed = parseUtcTimestamp(value);
  if (!parsed) {
    return "-";
  }
  return `${new Intl.DateTimeFormat("en-IN", {
    timeZone: "Asia/Kolkata",
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).format(parsed)} IST`;
}

function formatUtcTimestamp(value) {
  return formatIstTimestamp(value);
}

function clampQualityScore(value, fallback = 0) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) {
    return fallback;
  }
  return Math.min(Math.max(numeric, 0), 1);
}

function formatQualityPercent(value) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) {
    return "-";
  }
  return `${Math.round(clampQualityScore(numeric) * 100)}%`;
}

function qualityToneFromScore(value, inverse = false) {
  const score = clampQualityScore(value, inverse ? 1 : 0);
  const effective = inverse ? 1 - score : score;
  if (effective >= 0.82) {
    return "success";
  }
  if (effective >= 0.62) {
    return "warning";
  }
  return "error";
}

function normalizeEvaluationEnvelope(source = {}, fallback = {}) {
  const raw = source && typeof source === "object" ? source : {};
  const fallbackConfidence = clampQualityScore(fallback.confidence, 0);
  const ragMatchScore = clampQualityScore(raw.rag_match_score ?? fallback.ragMatchScore, 0);
  const citationCoverage = clampQualityScore(raw.citation_coverage ?? fallback.citationCoverage, 0);
  const evidenceCoverage = clampQualityScore(raw.evidence_coverage ?? fallback.evidenceCoverage, 0);
  const groundingScore = clampQualityScore(raw.grounding_score ?? ((ragMatchScore * 0.45) + (citationCoverage * 0.25) + (evidenceCoverage * 0.3)), 0);
  const confidenceScore = clampQualityScore(raw.confidence_score ?? fallbackConfidence, fallbackConfidence);
  const hallucinationRisk = clampQualityScore(raw.hallucination_risk ?? (1 - ((groundingScore * 0.55) + (confidenceScore * 0.25) + (citationCoverage * 0.2))), 0);
  const hallucinationScore = clampQualityScore(raw.hallucination_score ?? (1 - hallucinationRisk), 0);
  const overallScore = clampQualityScore(
    raw.overall_score ?? ((confidenceScore * 0.3) + (groundingScore * 0.3) + (hallucinationScore * 0.2) + (citationCoverage * 0.1) + (evidenceCoverage * 0.1)),
    0,
  );
  return {
    contractVersion: raw.contract_version || "kaiops.evaluation.v1",
    provider: raw.provider || "ui-derived-quality-gate",
    confidenceScore,
    groundingScore,
    hallucinationRisk,
    hallucinationScore,
    citationCoverage,
    evidenceCoverage,
    ragMatchScore,
    overallScore,
    qualityLabel: raw.quality_label || (overallScore >= 0.82 ? "high" : overallScore >= 0.62 ? "medium" : "low"),
    requiresReview: Boolean(raw.requires_review ?? (hallucinationRisk >= 0.45 || groundingScore < 0.55 || confidenceScore < 0.65)),
    externalJudge: raw.external_judge && typeof raw.external_judge === "object" ? raw.external_judge : {},
    signals: raw.signals && typeof raw.signals === "object" ? raw.signals : {},
  };
}

function elapsedSeconds(start, end) {
  const startDate = parseUtcTimestamp(start);
  const endDate = parseUtcTimestamp(end);
  if (!startDate || !endDate) {
    return "-";
  }
  const delta = Math.max(0, endDate.getTime() - startDate.getTime());
  return (delta / 1000).toFixed(3);
}

function normalizeTraceServiceName(event) {
  const eventType = String(event?.event_type || "").trim().toLowerCase();
  if (eventType.includes("closure")) {
    return "closure-service";
  }
  if (eventType.includes("recommendation") || eventType.includes("resolution")) {
    return "resolution-agent";
  }
  if (eventType.includes("approval")) {
    return "approval-service";
  }
  if (eventType.includes("context")) {
    return "context-agent";
  }
  if (eventType.includes("workflow") || eventType.includes("orchestration")) {
    return "orchestrator";
  }
  if (eventType.includes("remediation")) {
    return "remediation-engine";
  }

  const rawService = String(event?.service || "").trim();
  if (!rawService) {
    return "-";
  }
  if (!looksLikeUuid(rawService)) {
    return rawService;
  }
  return "monitoring-adapter";
}

function routeForAgent(agentName) {
  const rawNeedle = String(agentName || "").trim().toLowerCase();
  const needle = AGENT_ROUTE_ALIASES[rawNeedle] || rawNeedle;
  if (!needle) {
    return null;
  }
  return (
    SERVICE_TOPIC_FLOW.find((row) => String(row?.agent || "").trim().toLowerCase() === needle) || null
  );
}

function displayAgentName(agentName) {
  const token = String(agentName || "").trim();
  if (!token) {
    return "-";
  }
  const alias = AGENT_DISPLAY_ALIASES[token.toLowerCase()];
  return alias ? `${alias} (${token})` : token;
}

function compactText(value, maxLength = 180) {
  const text = String(value || "").trim();
  if (!text) {
    return "";
  }
  return text.length > maxLength ? `${text.slice(0, Math.max(24, maxLength - 1))}...` : text;
}

function hasMeaningfulValue(value) {
  if (value === null || value === undefined) {
    return false;
  }
  if (typeof value === "string") {
    const normalized = value.trim();
    return Boolean(normalized && normalized !== "-");
  }
  if (Array.isArray(value)) {
    return value.length > 0;
  }
  if (typeof value === "object") {
    return Object.keys(value).length > 0;
  }
  return true;
}

function stringifyTimelineValue(value) {
  if (!hasMeaningfulValue(value)) {
    return "";
  }
  if (typeof value === "string") {
    return value;
  }
  try {
    return JSON.stringify(value, null, 2);
  } catch (_error) {
    return String(value);
  }
}

function isFailureStatus(value) {
  const token = String(value || "").trim().toLowerCase();
  if (!token) {
    return false;
  }
  return ["fail", "failed", "failure", "error", "exception", "rejected", "timeout", "denied"].some((flag) => token.includes(flag));
}

function normalizeApprovalStatus(value) {
  return String(value || "").trim().toLowerCase();
}

function canonicalIncidentStatus(...values) {
  const statuses = values
    .flat()
    .map((value) => String(value || "").trim().toLowerCase())
    .filter(Boolean);
  if (!statuses.length) {
    return "unknown";
  }

  const terminalPriority = ["closed", "resolved", "failed", "cancelled", "canceled"];
  const terminal = terminalPriority.find((candidate) => statuses.includes(candidate));
  return terminal || statuses[0];
}

function isApprovalResolvedStatus(value) {
  const token = normalizeApprovalStatus(value);
  if (!token) {
    return false;
  }
  return ["approved", "rejected", "closed", "resolved", "failed", "cancelled", "canceled"].includes(token);
}

function isApprovalPendingStatus(value) {
  const token = normalizeApprovalStatus(value);
  if (!token) {
    return false;
  }
  return ["awaiting_approval", "pending", "queued", "awaiting user approval", "standby"].includes(token);
}

function statusPillClass(value) {
  const token = normalizeApprovalStatus(value);
  if (!token) {
    return "status-open";
  }
  if (token.includes("approved")) {
    return "status-approved";
  }
  if (token.includes("rejected")) {
    return "status-rejected";
  }
  if (token.includes("closed") || token.includes("resolved")) {
    return "status-closed";
  }
  if (token.includes("failed") || token.includes("error") || token.includes("blocked") || token.includes("denied")) {
    return "status-failed";
  }
  const normalized = token.replace(/[^a-z0-9]+/g, "_");
  return normalized ? `status-${normalized}` : "status-open";
}

function extractEventError(event) {
  if (!event || typeof event !== "object") {
    return "";
  }
  const status = String(event.status || "").trim();
  const candidates = [
    event.error,
    event.errors,
    event.exception,
    event.failure,
    event.failure_reason,
    event.error_message,
    event.detail,
    event.message,
  ];
  const hit = candidates.find((item) => hasMeaningfulValue(item));
  if (hit !== undefined) {
    return stringifyTimelineValue(hit);
  }
  if (isFailureStatus(status)) {
    const reason = hasMeaningfulValue(event.policy_reason) ? stringifyTimelineValue(event.policy_reason) : "";
    return reason || `Status: ${status}`;
  }
  return "";
}

function extractEventInput(event) {
  if (!event || typeof event !== "object") {
    return null;
  }
  const payload = typeof event.payload === "object" && event.payload ? event.payload : null;
  const candidates = [
    event.input_value,
    event.input,
    event.input_payload,
    event.request,
    event.context,
    event.source_payload,
    payload?.input,
    payload?.request,
    payload?.context,
  ];
  const hit = candidates.find((item) => hasMeaningfulValue(item));
  return hit === undefined ? null : hit;
}

function extractEventOutput(event) {
  if (!event || typeof event !== "object") {
    return null;
  }
  const payload = typeof event.payload === "object" && event.payload ? event.payload : null;
  const candidates = [
    event.output_value,
    event.output,
    event.result,
    payload,
    event.response,
    event.recommendation,
    event.decision,
  ];
  const hit = candidates.find((item) => hasMeaningfulValue(item));
  if (!hasMeaningfulValue(hit)) {
    return null;
  }
  const eventType = String(event.event_type || "").trim();
  if (typeof hit === "string" && eventType && hit.trim() === eventType && hasMeaningfulValue(payload)) {
    return payload;
  }
  return hit;
}

function buildPreviewExecutionPlan(workflow) {
  const safeWorkflow = workflow && typeof workflow === "object" ? workflow : {};
  const recommendation = typeof safeWorkflow.recommendation === "object" && safeWorkflow.recommendation ? safeWorkflow.recommendation : {};
  const incident = typeof safeWorkflow.incident === "object" && safeWorkflow.incident ? safeWorkflow.incident : {};
  const alert = typeof safeWorkflow.alert === "object" && safeWorkflow.alert ? safeWorkflow.alert : {};

  const target = String(
    recommendation?.metadata?.remediation_target
    || recommendation?.target
    || incident?.service
    || alert?.service
    || "unknown-target"
  ).trim();
  const environment = String(incident?.environment || alert?.environment || "prod").trim() || "prod";
  const recommendationText = String(recommendation?.recommended_action || "rollback deployment").trim() || "rollback deployment";
  const lowered = recommendationText.toLowerCase();

  const actionType = lowered.includes("restart pod")
    ? "restart_pod"
    : lowered.includes("scale")
      ? "scale_deployment"
      : lowered.includes("restart service")
        ? "restart_service"
        : lowered.includes("cache")
          ? "clear_cache"
          : lowered.includes("failover") || lowered.includes("database")
            ? "failover_database"
            : lowered.includes("terraform")
              ? "terraform_rollback"
              : "rollback_deployment";

  const preview = {
    commands: [],
    scripts: [],
    queries: [],
  };

  if (actionType === "restart_pod") {
    preview.commands = [
      `kubectl rollout restart deployment/${target} -n ${environment}`,
      `kubectl rollout status deployment/${target} -n ${environment} --timeout=180s`,
    ];
    preview.scripts = [`scripts/remediation/restart_pod.ps1 -Service ${target} -Namespace ${environment}`];
    preview.queries = [`sum(rate(http_requests_total{service='${target}',status=~'5..'}[5m]))`];
  } else if (actionType === "scale_deployment") {
    preview.commands = [
      `kubectl scale deployment/${target} --replicas=3 -n ${environment}`,
      `kubectl rollout status deployment/${target} -n ${environment} --timeout=180s`,
    ];
    preview.scripts = [`scripts/remediation/scale_deployment.ps1 -Service ${target} -Namespace ${environment} -Replicas 3`];
    preview.queries = [`avg_over_time(container_cpu_usage_seconds_total{pod=~'${target}.*'}[10m])`];
  } else if (actionType === "restart_service") {
    preview.commands = [`ansible-playbook playbooks/restart-service.yml -e service=${target} -e env=${environment}`];
    preview.scripts = [`scripts/remediation/restart_service.ps1 -Service ${target} -Environment ${environment}`];
    preview.queries = [`max_over_time(up{job='${target}'}[5m])`];
  } else if (actionType === "clear_cache") {
    preview.commands = [`redis-cli -h ${target}-redis -n 0 FLUSHDB`];
    preview.scripts = [`scripts/remediation/clear_cache.ps1 -Service ${target}`];
    preview.queries = [`sum(rate(cache_miss_total{service='${target}'}[5m]))`];
  } else if (actionType === "failover_database") {
    preview.commands = ["mysql -e \"CALL mysql.rds_failover();\""];
    preview.scripts = ["scripts/remediation/failover_database.ps1"];
    preview.queries = ["SHOW REPLICA STATUS;"];
  } else if (actionType === "terraform_rollback") {
    preview.commands = [
      "terraform init",
      `terraform apply -auto-approve -var service=${target} -var rollback=true`,
    ];
    preview.scripts = [`scripts/remediation/terraform_rollback.ps1 -Service ${target} -Environment ${environment}`];
    preview.queries = [`sum(rate(terraform_apply_failures_total{service='${target}'}[15m]))`];
  } else {
    preview.commands = [
      `kubectl rollout undo deployment/${target} -n ${environment}`,
      `kubectl rollout status deployment/${target} -n ${environment} --timeout=180s`,
    ];
    preview.scripts = [`scripts/remediation/rollback_deployment.ps1 -Service ${target} -Namespace ${environment}`];
    preview.queries = [`sum(rate(http_requests_total{service='${target}',status=~'5..'}[5m]))`];
  }

  return {
    actionType,
    recommendationText,
    plan: preview,
  };
}

function deriveExecutionCommands(workflow, traceRows) {
  const safeWorkflow = workflow && typeof workflow === "object" ? workflow : {};
  const safeTraceRows = Array.isArray(traceRows) ? traceRows : [];
  const recommendation = typeof safeWorkflow.recommendation === "object" && safeWorkflow.recommendation ? safeWorkflow.recommendation : {};
  const recommendationMetadata = typeof recommendation.metadata === "object" && recommendation.metadata ? recommendation.metadata : {};
  const remediationAction = typeof safeWorkflow.remediation_action === "object" && safeWorkflow.remediation_action ? safeWorkflow.remediation_action : {};
  const decision =
    (typeof safeWorkflow.decision === "object" && safeWorkflow.decision)
    || (typeof safeWorkflow.orchestration_decision === "object" && safeWorkflow.orchestration_decision)
    || (typeof recommendationMetadata.orchestration_decision === "object" && recommendationMetadata.orchestration_decision)
    || {};

  const explicit =
    (Array.isArray(recommendation.commands) && recommendation.commands)
    || (Array.isArray(remediationAction.commands) && remediationAction.commands)
    || (Array.isArray(decision.commands) && decision.commands)
    || [];
  const derived = [];
  const seen = new Set();
  const pushUnique = (value, prefix = "") => {
    const token = String(value || "").trim();
    if (!token) {
      return;
    }
    const line = `${prefix}${token}`;
    const key = line.toLowerCase();
    if (seen.has(key)) {
      return;
    }
    seen.add(key);
    derived.push(line);
  };

  const pushPlan = (plan) => {
    if (!plan || typeof plan !== "object") {
      return;
    }
    (Array.isArray(plan.commands) ? plan.commands : []).forEach((item) => pushUnique(item, "cmd: "));
    (Array.isArray(plan.scripts) ? plan.scripts : []).forEach((item) => pushUnique(item, "script: "));
    (Array.isArray(plan.queries) ? plan.queries : []).forEach((item) => pushUnique(item, "query: "));
  };

  explicit.forEach((item) => pushUnique(item, "cmd: "));

  const remediationParams = typeof remediationAction.parameters === "object" && remediationAction.parameters
    ? remediationAction.parameters
    : {};
  pushPlan(remediationParams.execution_plan);
  (Array.isArray(remediationParams.commands) ? remediationParams.commands : []).forEach((item) => pushUnique(item, "cmd: "));

  safeTraceRows.forEach((row) => {
    const payload = typeof row?.payload === "object" && row.payload ? row.payload : {};
    pushPlan(payload?.execution_plan);

    const payloadAction = typeof payload?.remediation_action === "object" && payload.remediation_action ? payload.remediation_action : {};
    const payloadParams = typeof payloadAction.parameters === "object" && payloadAction.parameters ? payloadAction.parameters : {};
    pushPlan(payloadParams.execution_plan);
    (Array.isArray(payloadParams.commands) ? payloadParams.commands : []).forEach((item) => pushUnique(item, "cmd: "));

    const commands = Array.isArray(payload?.commands) ? payload.commands : [];
    commands.forEach((item) => pushUnique(item, "cmd: "));
  });

  if (!derived.length) {
    const preview = buildPreviewExecutionPlan(safeWorkflow);
    pushUnique("Pending live executor - no command has been executed yet", "cmd: ");
    pushUnique(`# recommended_action: ${preview.recommendationText}`, "cmd: ");
    (preview.plan.commands || []).forEach((item) => pushUnique(item, "cmd: "));
    (preview.plan.scripts || []).forEach((item) => pushUnique(item, "script: "));
    (preview.plan.queries || []).forEach((item) => pushUnique(item, "query: "));
  }

  return derived;
}

function remediationOutcomeFromAction(action) {
  const safeAction = action && typeof action === "object" ? action : {};
  const status = String(safeAction.status || "").trim().toLowerCase();
  const error = String(safeAction.error || "").trim();
  const output = String(safeAction.output || "").trim();
  const parameters = safeAction.parameters && typeof safeAction.parameters === "object" ? safeAction.parameters : {};
  const executionResult = parameters.execution_result && typeof parameters.execution_result === "object"
    ? parameters.execution_result
    : {};
  const executorError = String(executionResult.stderr || executionResult.error || "").trim();
  const executorOutput = String(executionResult.stdout || "").trim();
  const reason = error || executorError || output || executorOutput || "";

  if (!status && !reason) {
    return null;
  }

  let title = "Remediation status";
  if (status === "succeeded") {
    title = "Remediation executed successfully";
  } else if (status === "skipped") {
    title = "Remediation was approved but not executed";
  } else if (status === "failed") {
    title = "Remediation execution failed";
  }

  let detail = reason || `Remediation engine returned status ${status || "unknown"}.`;
  if (/no real .*executor is configured/i.test(detail) || /configure a connector executor/i.test(detail)) {
    detail = `${detail} Add a real remediation connector with executor settings and secret_ref, or edit the plan to use the approved local triage script.`;
  }

  return {
    status: status || "unknown",
    title,
    detail,
    actionType: safeAction.action_type || "-",
    target: safeAction.target || "-",
  };
}

function shellArg(value) {
  const token = String(value || "").trim();
  if (!token) {
    return "''";
  }
  if (/^[a-zA-Z0-9_./:@=-]+$/.test(token)) {
    return token;
  }
  return `'${token.replace(/'/g, "'\\''")}'`;
}

function buildKaiOpsRemediationScript({
  service,
  environment,
  apiGatewayUrl,
  prometheusUrl,
  mysqlHost,
  mysqlDatabase,
  mysqlUser,
} = {}) {
  return [
    "bash scripts/remediation/kaiops_alert_health_triage.sh",
    "--service", shellArg(service || "kaiops-service"),
    "--environment", shellArg(environment || "prod"),
    "--api-gateway-url", shellArg(apiGatewayUrl || "http://api-gateway:8000"),
    "--prometheus-url", shellArg(prometheusUrl || "http://prometheus:9090"),
    "--mysql-host", shellArg(mysqlHost || "mysql"),
    "--mysql-database", shellArg(mysqlDatabase || "kaiops"),
    "--mysql-user", shellArg(mysqlUser || "kaiops"),
    "--dry-run", "true",
  ].join(" ");
}

function firstTraceTimestamp(rows, predicate) {
  const safeRows = Array.isArray(rows) ? rows : [];
  const hit = safeRows.find((row) => {
    if (!row || typeof row !== "object") {
      return false;
    }
    return predicate(row);
  });
  return String(hit?.timestamp || "").trim();
}

function firstEventTimestamp(rows, predicate) {
  const safeRows = Array.isArray(rows) ? rows : [];
  const hit = safeRows.find((row) => {
    if (!row || typeof row !== "object") {
      return false;
    }
    return predicate(row);
  });
  return String(hit?.timestamp || "").trim();
}

function buildSyntheticFlowRows({ workflow, events, traceRows, ingestAt, incidentCreatedAt }) {
  const safeWorkflow = workflow && typeof workflow === "object" ? workflow : {};
  const safeEvents = Array.isArray(events) ? events : [];
  const safeTraceRows = Array.isArray(traceRows) ? traceRows : [];

  const alert = typeof safeWorkflow.alert === "object" && safeWorkflow.alert ? safeWorkflow.alert : {};
  const incident = typeof safeWorkflow.incident === "object" && safeWorkflow.incident ? safeWorkflow.incident : {};
  const context = typeof safeWorkflow.context === "object" && safeWorkflow.context ? safeWorkflow.context : {};
  const contextMetadata = typeof context.metadata === "object" && context.metadata ? context.metadata : {};
  const recommendation = typeof safeWorkflow.recommendation === "object" && safeWorkflow.recommendation ? safeWorkflow.recommendation : {};
  const recommendationMetadata = typeof recommendation.metadata === "object" && recommendation.metadata ? recommendation.metadata : {};
  const remediationAction =
    typeof safeWorkflow.remediation_action === "object" && safeWorkflow.remediation_action
      ? safeWorkflow.remediation_action
      : {};
  const decision =
    (typeof safeWorkflow.decision === "object" && safeWorkflow.decision)
    || (typeof safeWorkflow.orchestration_decision === "object" && safeWorkflow.orchestration_decision)
    || (typeof recommendationMetadata.orchestration_decision === "object" && recommendationMetadata.orchestration_decision)
    || {};

  const contextTraceRow = safeTraceRows
    .slice()
    .reverse()
    .find((row) => String(row?.event_type || "").toLowerCase().includes("context"));
  const contextEventPayload = (contextTraceRow && typeof contextTraceRow.payload === "object" && contextTraceRow.payload)
    ? contextTraceRow.payload
    : {};
  const contextEventMetadata = typeof contextEventPayload?.metadata === "object" && contextEventPayload.metadata
    ? contextEventPayload.metadata
    : {};
  const contextAgentEvent = safeEvents
    .slice()
    .reverse()
    .find((event) => String(event?.agent || "").toLowerCase().includes("context intelligence"));
  const contextAgentDetails = typeof contextAgentEvent?.details === "object" && contextAgentEvent.details
    ? contextAgentEvent.details
    : {};
  const contextAgentMetrics = typeof contextAgentDetails?.metrics === "object" && contextAgentDetails.metrics
    ? contextAgentDetails.metrics
    : {};

  const ragMatches =
    (Array.isArray(contextMetadata.rag_matches) && contextMetadata.rag_matches)
    || (Array.isArray(recommendationMetadata.rag_matches) && recommendationMetadata.rag_matches)
    || (Array.isArray(contextEventMetadata.rag_matches) && contextEventMetadata.rag_matches)
    || (Array.isArray(contextAgentMetrics.rag_matches) && contextAgentMetrics.rag_matches)
    || [];

  const ragDocumentsRaw =
    contextMetadata.rag_documents
    ?? recommendationMetadata.rag_documents
    ?? contextEventMetadata.rag_documents
    ?? contextAgentMetrics.rag_documents
    ?? contextEventPayload.rag_document_count
    ?? null;
  const ragTopSimilarityRaw =
    contextMetadata.rag_top_similarity
    ?? recommendationMetadata.rag_top_similarity
    ?? contextEventMetadata.rag_top_similarity
    ?? null;
  const ragDocuments = ragDocumentsRaw === null || ragDocumentsRaw === undefined || ragDocumentsRaw === ""
    ? null
    : Number(ragDocumentsRaw);
  const ragTopSimilarity = ragTopSimilarityRaw === null || ragTopSimilarityRaw === undefined || ragTopSimilarityRaw === ""
    ? null
    : Number(ragTopSimilarityRaw);
  const runbookFound =
    Boolean(context.runbook)
    || Boolean(recommendationMetadata.runbook_found)
    || Boolean(contextEventPayload.document_available)
    || Boolean(contextEventMetadata.document_available)
    || Boolean(contextAgentMetrics.runbook_found);
  const ragDocumentDisplay = Number.isFinite(ragDocuments) ? ragDocuments : ragMatches.length;
  const executionCommands = deriveExecutionCommands(safeWorkflow, safeTraceRows);
  const traceEventTypes = safeTraceRows
    .map((row) => String(row?.event_type || "").trim())
    .filter(Boolean);

  const findTraceEvents = (needles) => {
    const tokens = Array.isArray(needles) ? needles : [];
    const matches = traceEventTypes.filter((eventType) => {
      const normalized = eventType.toLowerCase();
      return tokens.some((needle) => normalized.includes(String(needle || "").toLowerCase()));
    });
    return Array.from(new Set(matches));
  };
  const findTraceRows = (needles) => {
    const tokens = Array.isArray(needles) ? needles : [];
    return safeTraceRows.filter((row) => {
      const haystack = [
        row?.event_type,
        row?.event_stage,
        row?.source_channel,
        row?.transport_channel,
        row?.service_name,
      ].map((item) => String(item || "").toLowerCase()).join(" ");
      return tokens.some((needle) => haystack.includes(String(needle || "").toLowerCase()));
    });
  };

  const landingTimestamp =
    String(ingestAt || "").trim()
    || firstTraceTimestamp(safeTraceRows, (row) => {
      const eventType = String(row?.event_type || "").toLowerCase();
      const source = String(row?.source_channel || "").toLowerCase();
      return eventType.includes("alert") || source.includes("raw-alert");
    })
    || String(incidentCreatedAt || "").trim();

  const dedupeTimestamp =
    firstEventTimestamp(safeEvents, (event) => String(event?.agent || "").toLowerCase().includes("alert intelligence"))
    || firstTraceTimestamp(safeTraceRows, (row) => String(row?.event_type || "").toLowerCase().includes("workflow"))
    || landingTimestamp;

  const configTimestamp =
    firstTraceTimestamp(safeTraceRows, (row) => {
      const eventType = String(row?.event_type || "").toLowerCase();
      const stage = String(row?.event_stage || "").toLowerCase();
      return eventType.includes("config") || eventType.includes("connection") || stage.includes("config");
    })
    || dedupeTimestamp;

  const contextTimestamp =
    firstEventTimestamp(safeEvents, (event) => String(event?.agent || "").toLowerCase().includes("context intelligence"))
    || firstTraceTimestamp(safeTraceRows, (row) => String(row?.event_type || "").toLowerCase().includes("context"))
    || dedupeTimestamp;

  const routingTimestamp =
    firstTraceTimestamp(safeTraceRows, (row) => {
      const eventType = String(row?.event_type || "").toLowerCase();
      return eventType.includes("workflow.selected") || eventType.includes("recommendation.generated");
    })
    || firstEventTimestamp(safeEvents, (event) => String(event?.agent || "").toLowerCase().includes("orchestrator"))
    || contextTimestamp;

  const recommendationTimestamp =
    firstTraceTimestamp(safeTraceRows, (row) => {
      const eventType = String(row?.event_type || "").toLowerCase();
      return eventType.includes("recommendation") || eventType.includes("resolution");
    })
    || firstEventTimestamp(safeEvents, (event) => String(event?.agent || "").toLowerCase().includes("resolution"))
    || routingTimestamp;

  const approvalTimestamp =
    firstTraceTimestamp(safeTraceRows, (row) => String(row?.event_type || "").toLowerCase().includes("approval"))
    || firstEventTimestamp(safeEvents, (event) => String(event?.agent || "").toLowerCase().includes("approval"))
    || recommendationTimestamp;

  const remediationTimestamp =
    String(remediationAction.completed_at || remediationAction.started_at || "").trim()
    || firstEventTimestamp(safeEvents, (event) => String(event?.agent || "").toLowerCase().includes("remediation"))
    || firstTraceTimestamp(safeTraceRows, (row) => String(row?.event_type || "").toLowerCase().includes("remediation"))
    || approvalTimestamp;

  const closureTimestamp =
    firstTraceTimestamp(safeTraceRows, (row) => {
      const eventType = String(row?.event_type || "").toLowerCase();
      return eventType.includes("closure") || eventType.includes("validation");
    })
    || String(safeWorkflow?.closure_report?.completed_at || safeWorkflow?.closure_report?.created_at || "").trim()
    || "";

  const rows = [];
  const traceId = alert.trace_id || incident.trace_id || context.trace_id || recommendation.trace_id || remediationAction.trace_id || "";
  const pushBusRow = ({ flowOrder, stage, consumes, publishes, timestamp, detail, payload = {}, backendEvents = [] }) => {
    const observedBusRow = safeTraceRows
      .slice()
      .reverse()
      .find((row) => {
        const channel = String(row?.transport_channel || row?.source_channel || "").trim().toLowerCase();
        return channel === String(publishes || "").trim().toLowerCase();
      });
    const observedProvider = String(observedBusRow?.transport_provider || "").trim();
    const provider = observedProvider && observedProvider.toLowerCase() !== "unknown"
      ? observedProvider
      : (decision.message_bus_provider || "rabbitmq");
    rows.push({
      flowOrder,
      stage,
      agent: "Message Bus",
      service: provider,
      consumes,
      publishes,
      timestamp,
      elapsed: elapsedSeconds(ingestAt || incidentCreatedAt, timestamp),
      detail,
      tables: "message_topics, incident_events",
      inputValueText: stringifyTimelineValue({
        provider,
        trace_id: traceId,
        ...payload,
      }),
      outputValueText: stringifyTimelineValue({
        delivered_to: publishes,
        trace_id: traceId,
      }),
      errorValueText: "",
      backendEvents,
    });
  };

  if (landingTimestamp || hasMeaningfulValue(alert)) {
    rows.push({
      flowOrder: 10,
      stage: "Alert Landed In Landing Pad",
      agent: "Monitoring Adapter",
      service: "monitoring-adapter",
      consumes: "provider webhook",
      publishes: "raw-alerts",
      timestamp: landingTimestamp,
      elapsed: elapsedSeconds(ingestAt || incidentCreatedAt, landingTimestamp),
      detail: "Alert ingested from monitoring provider and staged for downstream workflow processing.",
      tables: "incident_events",
      inputValueText: stringifyTimelineValue({
        source: alert.source,
        name: alert.name,
        service: alert.service,
        severity: alert.severity,
      }),
      outputValueText: stringifyTimelineValue({
        correlation_id: alert.correlation_id,
        trace_id: traceId,
      }),
      errorValueText: "",
      backendEvents: findTraceEvents(["alert", "incident.opened", "incident.created"]),
    });
    pushBusRow({
      flowOrder: 20,
      stage: "Raw Alert Topic Handoff",
      consumes: "provider webhook",
      publishes: "raw-alerts",
      timestamp: landingTimestamp,
      detail: "Landing pad publishes the normalized alert envelope onto the raw-alerts topic for alert intelligence workers.",
      payload: {
        source_service: "monitoring-adapter",
        target_service: "alert-intelligence",
        topic: "raw-alerts",
      },
      backendEvents: findTraceEvents(["alert", "raw-alerts"]),
    });
  }

  if (hasMeaningfulValue(alert.deduplicated_count) || dedupeTimestamp) {
    rows.push({
      flowOrder: 30,
      stage: "Deduplication And Incident Correlation",
      agent: "Alert Intelligence Agent",
      service: "alert-intelligence",
      consumes: "raw-alerts",
      publishes: "enriched-alerts",
      timestamp: dedupeTimestamp,
      elapsed: elapsedSeconds(ingestAt || incidentCreatedAt, dedupeTimestamp),
      detail: "Deduplication, severity classification, and incident correlation completed.",
      tables: "alerts, incidents, incident_events",
      inputValueText: stringifyTimelineValue({
        deduplicated_count: alert.deduplicated_count,
        correlation_id: alert.correlation_id,
        incident_id: incident.id,
      }),
      outputValueText: stringifyTimelineValue({
        incident_title: incident.title,
        severity: incident.severity,
        status: incident.status,
        trace_id: traceId,
      }),
      errorValueText: "",
      backendEvents: findTraceEvents(["workflow.selected", "context.collected"]),
    });
    pushBusRow({
      flowOrder: 40,
      stage: "Enriched Alert Topic Handoff",
      consumes: "raw-alerts",
      publishes: "enriched-alerts",
      timestamp: dedupeTimestamp,
      detail: "Alert intelligence publishes the correlated incident signal for orchestration routing.",
      payload: {
        source_service: "alert-intelligence",
        target_service: "orchestrator",
        incident_id: incident.id,
        topic: "enriched-alerts",
      },
      backendEvents: findTraceEvents(["workflow.selected", "enriched-alerts"]),
    });
  }

  if (hasMeaningfulValue(decision) || routingTimestamp) {
    rows.push({
      flowOrder: 50,
      stage: "Orchestrator Workflow Selection",
      agent: "Orchestrator Agent",
      service: "orchestrator",
      consumes: "enriched-alerts",
      publishes: "workflow request",
      timestamp: routingTimestamp,
      elapsed: elapsedSeconds(ingestAt || incidentCreatedAt, routingTimestamp),
      detail: "Orchestrator selects the incident workflow, worker route, approval requirement, and execution policy.",
      tables: "incident_events, incident_projections, pending_workflows",
      inputValueText: stringifyTimelineValue({
        alert: alert.name,
        service: alert.service || incident.service,
        severity: alert.severity || incident.severity,
        incident_id: incident.id,
      }),
      outputValueText: stringifyTimelineValue({
        workflow: decision.workflow,
        next_action: decision.next_action,
        requires_approval: decision.requires_approval,
        risk_tier: decision.risk_tier,
        trace_id: traceId,
      }),
      errorValueText: "",
      backendEvents: findTraceEvents(["workflow.selected"]),
    });
  }

  rows.push({
    flowOrder: 60,
    stage: "Configuration And Connector Lookup",
    agent: "Config Service",
    service: "config",
    consumes: "workflow request",
    publishes: "connector profile",
    timestamp: configTimestamp,
    elapsed: elapsedSeconds(ingestAt || incidentCreatedAt, configTimestamp),
    detail: "Service, environment, monitoring, message bus, RAG, and remediation connector settings resolved before agent execution.",
    tables: "kaiops-connections.json, service_profiles, connector registry",
    inputValueText: stringifyTimelineValue({
      service: alert.service || incident.service,
      environment: alert.environment || incident.environment,
      requested_profiles: ["monitoring", "message_bus", "rag", "remediation"],
    }),
    outputValueText: stringifyTimelineValue({
      monitoring_provider: decision.monitoring_provider || decision.provider || "prometheus",
      message_bus_provider: decision.message_bus_provider || "rabbitmq",
      workflow: decision.workflow || "guided-remediation",
      execution_mode: decision.execution_mode || "-",
      trace_id: traceId,
    }),
    errorValueText: "",
    backendEvents: findTraceEvents(["config", "connection", "workflow.selected"]),
  });
  pushBusRow({
    flowOrder: 70,
    stage: "Orchestration Event Topic Handoff",
    consumes: "workflow request + connector profile",
    publishes: "orchestration-events",
    timestamp: routingTimestamp,
    detail: "Orchestrator publishes the runnable work item for context-agent workers with config, policy, and trace metadata attached.",
    payload: {
      source_service: "orchestrator",
      target_service: "context-agent",
      topic: "orchestration-events",
      workflow: decision.workflow || "guided-remediation",
    },
    backendEvents: findTraceEvents(["workflow.selected", "orchestration-events"]),
  });

  if (ragDocuments > 0 || ragMatches.length || contextTimestamp) {
    rows.push({
      flowOrder: 80,
      stage: "RAG Context Retrieval",
      agent: "Context Intelligence Agent",
      service: "context-agent",
      consumes: "orchestration-events",
      publishes: "context-events",
      timestamp: contextTimestamp,
      elapsed: elapsedSeconds(ingestAt || incidentCreatedAt, contextTimestamp),
      detail: "Context built from RAG corpus, dependencies, recent changes, and observability connectors.",
      tables: "incident_events, agent_work_items",
      inputValueText: stringifyTimelineValue({
        service: alert.service,
        deployment: context.deployment,
        related_incidents: Array.isArray(context.related_incidents) ? context.related_incidents.length : 0,
      }),
      outputValueText: stringifyTimelineValue({
        rag_documents: ragDocumentDisplay,
        rag_matches: ragMatches,
        runbook_found: runbookFound,
        trace_id: traceId,
      }),
      errorValueText: "",
      backendEvents: findTraceEvents(["context.collected"]),
    });
  }

  if (contextTimestamp || runbookFound || ragMatches.length) {
    rows.push({
      flowOrder: 90,
      stage: "Context Merge And Evidence Assembly",
      agent: "Context Intelligence Agent",
      service: "context-agent",
      consumes: "ranked rag matches + connector evidence",
      publishes: "context-events",
      timestamp: contextTimestamp,
      elapsed: elapsedSeconds(ingestAt || incidentCreatedAt, contextTimestamp),
      detail: "RAG matches, dependency evidence, recent incidents, deployment metadata, and observability signals merged into one context payload.",
      tables: "incident_events, dependencies, changes, runbooks, agent_work_items",
      inputValueText: stringifyTimelineValue({
        documents_ranked: ragDocumentDisplay,
        dependency_count: Array.isArray(context.dependencies) ? context.dependencies.length : "-",
        related_incidents: Array.isArray(context.related_incidents) ? context.related_incidents.length : 0,
        connector_events: findTraceRows(["connector", "context"]).length,
      }),
      outputValueText: stringifyTimelineValue({
        runbook_found: runbookFound,
        document_available: Boolean(contextEventPayload.document_available || runbookFound),
        context_summary: context.summary || contextEventPayload.summary || "-",
        trace_id: traceId,
      }),
      errorValueText: "",
      backendEvents: findTraceEvents(["context.collected", "connector", "dependency"]),
    });
    pushBusRow({
      flowOrder: 100,
      stage: "Context Event Topic Handoff",
      consumes: "orchestration-events",
      publishes: "context-events",
      timestamp: contextTimestamp,
      detail: "Context-agent publishes the assembled incident context for resolution-agent workers.",
      payload: {
        source_service: "context-agent",
        target_service: "resolution-agent",
        topic: "context-events",
        documents_ranked: ragDocumentDisplay,
      },
      backendEvents: findTraceEvents(["context.collected", "context-events"]),
    });
  }

  if (ragMatches.length || (typeof ragTopSimilarity === "number" && ragTopSimilarity > 0)) {
    rows.push({
      flowOrder: 85,
      stage: "Embedding And Semantic Search",
      agent: "VectorDB Connector",
      service: "context-agent",
      consumes: "context query",
      publishes: "ranked rag matches",
      timestamp: contextTimestamp,
      elapsed: elapsedSeconds(ingestAt || incidentCreatedAt, contextTimestamp),
      detail: "Vector similarity and metadata ranking used to retrieve the most relevant runbook, incident, and deployment documents.",
      tables: "rag corpus",
      inputValueText: stringifyTimelineValue({
        query: `${alert.service || ""} ${alert.name || ""} ${alert.description || ""}`.trim(),
        rag_document_count: ragDocuments,
      }),
      outputValueText: stringifyTimelineValue({
        rag_top_similarity: ragTopSimilarity ?? "-",
        top_matches: ragMatches.slice(0, 5),
        trace_id: traceId,
      }),
      errorValueText: "",
      backendEvents: findTraceEvents(["context.collected", "recommendation.generated"]),
    });
  }

  if (hasMeaningfulValue(recommendation) || recommendationTimestamp) {
    rows.push({
      flowOrder: 110,
      stage: "Resolution Recommendation Generated",
      agent: "Resolution Intelligence Agent",
      service: "resolution-agent",
      consumes: "context-events",
      publishes: "resolution-events",
      timestamp: recommendationTimestamp,
      elapsed: elapsedSeconds(ingestAt || incidentCreatedAt, recommendationTimestamp),
      detail: "RCA, impact, recommended action, confidence, and operator-safe execution plan generated from the assembled context.",
      tables: "incident_events, recommendations, evaluation_records",
      inputValueText: stringifyTimelineValue({
        incident_id: incident.id || recommendation.incident_id,
        service: incident.service || alert.service,
        context_trace_id: context.trace_id || traceId,
      }),
      outputValueText: stringifyTimelineValue({
        recommendation_id: recommendation.id,
        root_cause: recommendation.root_cause,
        confidence: recommendation.confidence,
        grounding_score: recommendationMetadata.grounding_score,
        hallucination_score: recommendationMetadata.hallucination_score,
        trace_id: traceId,
      }),
      errorValueText: "",
      backendEvents: findTraceEvents(["recommendation.generated", "resolution"]),
    });
    pushBusRow({
      flowOrder: 120,
      stage: "Resolution Event Topic Handoff",
      consumes: "context-events",
      publishes: "resolution-events",
      timestamp: recommendationTimestamp,
      detail: "Resolution-agent publishes RCA, impact, confidence, and the editable remediation plan for approval routing.",
      payload: {
        source_service: "resolution-agent",
        target_service: "approval-service",
        topic: "resolution-events",
        recommendation_id: recommendation.id,
      },
      backendEvents: findTraceEvents(["recommendation.generated", "resolution-events"]),
    });
  }

  if (approvalTimestamp || hasMeaningfulValue(recommendation.id)) {
    rows.push({
      flowOrder: 130,
      stage: "Human Approval Gate",
      agent: "Approval Service",
      service: "approval-service",
      consumes: "resolution-events",
      publishes: "approval-events",
      timestamp: approvalTimestamp,
      elapsed: elapsedSeconds(ingestAt || incidentCreatedAt, approvalTimestamp),
      detail: "Recommendation and editable remediation plan presented for human approval before execution.",
      tables: "approvals, pending_workflows, incident_events",
      inputValueText: stringifyTimelineValue({
        recommendation_id: recommendation.id,
        risk_tier: decision.risk_tier,
        requires_approval: decision.requires_approval ?? true,
        approver_role: decision.approver_role || "L2/L3/Admin",
      }),
      outputValueText: stringifyTimelineValue({
        approval_status: remediationAction.approval_id ? "approved" : "pending",
        approval_id: remediationAction.approval_id,
        editable_plan: true,
        trace_id: traceId,
      }),
      errorValueText: "",
      backendEvents: findTraceEvents(["approval.requested", "approval.recorded"]),
    });
    pushBusRow({
      flowOrder: 140,
      stage: "Approval Event Topic Handoff",
      consumes: "resolution-events",
      publishes: "approval-events",
      timestamp: approvalTimestamp,
      detail: "Approval-service publishes the human decision and edited execution plan for remediation-engine workers.",
      payload: {
        source_service: "approval-service",
        target_service: "remediation-engine",
        topic: "approval-events",
        approval_id: remediationAction.approval_id,
      },
      backendEvents: findTraceEvents(["approval.recorded", "approval-events"]),
    });
  }

  if (executionCommands.length || hasMeaningfulValue(remediationAction.output) || remediationTimestamp) {
    const remediationParameters =
      typeof remediationAction.parameters === "object" && remediationAction.parameters
        ? remediationAction.parameters
        : {};
    const executionPlan =
      typeof remediationParameters.execution_plan === "object" && remediationParameters.execution_plan
        ? remediationParameters.execution_plan
        : {};
    const executionResult =
      typeof remediationParameters.execution_result === "object" && remediationParameters.execution_result
        ? remediationParameters.execution_result
        : {};
    const remediationExecuted = hasMeaningfulValue(remediationAction.status) || hasMeaningfulValue(remediationAction.output);
    const executedLive = executionResult.executed === true || String(remediationAction.status || "").toLowerCase() === "succeeded";
    const skippedExecution = String(remediationAction.status || "").toLowerCase() === "skipped" || executionResult.executed === false;
    rows.push({
      flowOrder: 150,
      stage: "Remediation Command Execution",
      agent: "Remediation Automation Engine",
      service: "remediation-engine",
      consumes: "approval-events",
      publishes: "remediation-events",
      timestamp: remediationTimestamp,
      elapsed: elapsedSeconds(ingestAt || incidentCreatedAt, remediationTimestamp),
      detail: executedLive
        ? "Approved remediation was executed by the configured backend executor and the execution result was captured."
        : skippedExecution
          ? "Approved remediation was not executed because no live executor/connector is configured; the approved command plan is preserved for operator action."
          : "Remediation command/script/query plan is waiting for approval or executor dispatch.",
      tables: "actions, audit_logs, incident_events",
      inputValueText: stringifyTimelineValue({
        mode: executedLive ? "live_executed" : skippedExecution ? "not_executed" : "pending_dispatch",
        action_type: remediationAction.action_type,
        target: remediationAction.target,
        executor: executionResult.executor,
        commands: Array.isArray(executionPlan.commands) ? executionPlan.commands : executionCommands,
        scripts: Array.isArray(executionPlan.scripts) ? executionPlan.scripts : [],
        queries: Array.isArray(executionPlan.queries) ? executionPlan.queries : [],
      }),
      outputValueText: stringifyTimelineValue({
        status: remediationAction.status || (remediationExecuted ? "-" : "pending"),
        executed: executionResult.executed,
        reason: executionResult.reason,
        output: remediationAction.output,
        error: remediationAction.error,
        trace_id: traceId,
      }),
      errorValueText: stringifyTimelineValue(remediationAction.error),
      backendEvents: findTraceEvents(["remediation.executed", "closure.completed"]),
    });
    pushBusRow({
      flowOrder: 160,
      stage: "Remediation Event Topic Handoff",
      consumes: "approval-events",
      publishes: "remediation-events",
      timestamp: remediationTimestamp,
      detail: "Remediation-engine publishes execution status, output, and connector result for closure validation.",
      payload: {
        source_service: "remediation-engine",
        target_service: "closure-service",
        topic: "remediation-events",
        action_id: remediationAction.id,
        status: remediationAction.status,
      },
      backendEvents: findTraceEvents(["remediation.executed", "remediation-events"]),
    });
  }

  if (closureTimestamp) {
    rows.push({
      flowOrder: 170,
      stage: "Closure Validation And Incident Update",
      agent: "Closure & Validation",
      service: "closure-service",
      consumes: "remediation-events",
      publishes: "closure-events",
      timestamp: closureTimestamp,
      elapsed: elapsedSeconds(ingestAt || incidentCreatedAt, closureTimestamp),
      detail: "Post-remediation validation updates incident status, evidence, audit trail, and cockpit projection.",
      tables: "incident_events, incident_projections, actions, audit_logs",
      inputValueText: stringifyTimelineValue({
        remediation_status: remediationAction.status,
        action_id: remediationAction.id,
      }),
      outputValueText: stringifyTimelineValue({
        health_restored: safeWorkflow?.closure_report?.health_restored,
        incident_status: incident.status,
        trace_id: traceId,
      }),
      errorValueText: "",
      backendEvents: findTraceEvents(["closure.completed", "validation"]),
    });
  }

  return rows;
}

function summarizeEventType(value) {
  const token = String(value || "").trim();
  if (!token) {
    return "Workflow Event";
  }
  return token
    .split(".")
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" -> ");
}

function timelinePhaseOrder(row) {
  const explicitOrder = Number(row?.flowOrder);
  if (Number.isFinite(explicitOrder) && explicitOrder > 0) {
    return explicitOrder;
  }
  const stage = String(row?.stage || "").toLowerCase();
  const eventHints = Array.isArray(row?.backendEvents)
    ? row.backendEvents.map((item) => String(item || "").toLowerCase())
    : [];
  const haystack = `${stage} ${eventHints.join(" ")}`;

  if (haystack.includes("landing pad") || haystack.includes("alert received") || haystack.includes("alert landed") || haystack.includes("incident.alert")) {
    return 10;
  }
  if (haystack.includes("raw alert topic")) {
    return 20;
  }
  if (haystack.includes("dedup") || haystack.includes("correlation") || haystack.includes("enrich")) {
    return 30;
  }
  if (haystack.includes("enriched alert topic")) {
    return 40;
  }
  if (haystack.includes("routing") || haystack.includes("orchestrator") || haystack.includes("workflow.selected")) {
    return 50;
  }
  if (haystack.includes("config") || haystack.includes("connector lookup") || haystack.includes("connection")) {
    return 60;
  }
  if (haystack.includes("orchestration event topic")) {
    return 70;
  }
  if (haystack.includes("rag context") || haystack.includes("context retrieval") || haystack.includes("context intelligence") || haystack.includes("incident.context.collected")) {
    return 80;
  }
  if (haystack.includes("embedding") || haystack.includes("semantic") || haystack.includes("vector")) {
    return 85;
  }
  if (haystack.includes("context merge") || haystack.includes("evidence assembly")) {
    return 90;
  }
  if (haystack.includes("context event topic")) {
    return 100;
  }
  if (haystack.includes("recommendation") || haystack.includes("resolution")) {
    return 110;
  }
  if (haystack.includes("policy")) {
    return 115;
  }
  if (haystack.includes("resolution event topic")) {
    return 120;
  }
  if (haystack.includes("approval")) {
    return 130;
  }
  if (haystack.includes("approval event topic")) {
    return 140;
  }
  if (haystack.includes("remediation") || haystack.includes("command") || haystack.includes("execute")) {
    return 150;
  }
  if (haystack.includes("remediation event topic")) {
    return 160;
  }
  if (haystack.includes("closure") || haystack.includes("validation")) {
    return 170;
  }
  return 99;
}

function buildAlertDocumentDrafts(alertRow, workflowPayload) {
  const alertName = String(alertRow?.name || alertRow?.alert_name || "Alert").trim();
  const service = String(alertRow?.service || "unknown-service").trim();
  const severity = String(alertRow?.severity || "high").trim().toLowerCase();
  const alertId = String(alertRow?.alert_id || alertRow?.id || "").trim();
  const workflow = workflowPayload?.workflow || workflowPayload || {};
  const recommendation = typeof workflow?.recommendation === "object" && workflow.recommendation ? workflow.recommendation : {};
  const incident = typeof workflow?.incident === "object" && workflow.incident ? workflow.incident : {};
  const rootCause = cleanRecommendationText(recommendation?.root_cause, "");
  const impact = cleanRecommendationText(recommendation?.impact, "");
  const suggestedAction = cleanRecommendationText(recommendation?.recommended_action, "");
  const commonHeader = `Alert ${alertName} observed on ${service} with severity ${severity.toUpperCase()}.`;
  const fallbackRootCause = "Investigate recent deploys, dependency health, and resource saturation.";
  const commonRoot = rootCause || fallbackRootCause;
  const remediationPreview = buildPreviewExecutionPlan(workflow);
  const remediationCommands = Array.isArray(remediationPreview?.plan?.commands) ? remediationPreview.plan.commands : [];
  const remediationScripts = Array.isArray(remediationPreview?.plan?.scripts) ? remediationPreview.plan.scripts : [];
  const remediationQueries = Array.isArray(remediationPreview?.plan?.queries) ? remediationPreview.plan.queries : [];
  const remediationPlanText = [
    remediationCommands.length ? `Commands:\n${remediationCommands.map((item) => `- ${item}`).join("\n")}` : "",
    remediationScripts.length ? `Scripts:\n${remediationScripts.map((item) => `- ${item}`).join("\n")}` : "",
    remediationQueries.length ? `Queries:\n${remediationQueries.map((item) => `- ${item}`).join("\n")}` : "",
  ].filter(Boolean).join("\n\n");

  return {
    incident: {
      kind: "incident",
      title: `${alertName} Incident Summary`.slice(0, 160),
      summary: [
        `${alertName} detected for ${service}.`,
        impact ? `Impact: ${impact}.` : "",
      ].filter(Boolean).join(" "),
      content: [
        commonHeader,
        `Probable root cause: ${commonRoot}`,
        incident?.id ? `Incident reference: ${String(incident.id)}.` : "",
        "Escalation path: L1 -> L2 -> L3 with timeline checkpoints at 5m, 15m, and 30m.",
      ].filter(Boolean).join("\n\n"),
      services: service,
      severity,
      alert_type: alertName,
      alert_id: alertId,
      root_cause: rootCause,
      impact,
      recommended_action: suggestedAction,
    },
    runbook: {
      kind: "runbook",
      title: `${alertName} Runbook`.slice(0, 160),
      summary: [
        `${alertName} detected for ${service}.`,
        suggestedAction ? `Recommended action: ${suggestedAction}.` : "",
      ].filter(Boolean).join(" "),
      content: [
        commonHeader,
        `Probable root cause: ${commonRoot}`,
        suggestedAction ? `Immediate action: ${suggestedAction}.` : "Immediate action: inspect logs, metrics, and dependency health.",
        "Verification: confirm error rate and latency return to baseline before closure.",
      ].filter(Boolean).join("\n\n"),
      services: service,
      severity,
      alert_type: alertName,
      alert_id: alertId,
      root_cause: rootCause,
      impact,
      recommended_action: suggestedAction,
    },
    deployment: {
      kind: "deployment",
      title: `${alertName} Deployment Guidance`.slice(0, 160),
      summary: `Deployment guardrails and rollback checks for ${service}.`,
      content: [
        commonHeader,
        "Pre-deploy checks: SLO burn rate, dependency readiness, and database migration safety.",
        "Post-deploy checks: p95 latency, error budget consumption, and alert noise monitoring for 30m.",
        "Rollback criteria: sustained critical alerts for 10m or failed synthetic checks.",
      ].join("\n\n"),
      services: service,
      severity,
      alert_type: alertName,
      alert_id: alertId,
      root_cause: rootCause,
      impact,
      recommended_action: suggestedAction,
    },
    change: {
      kind: "change",
      title: `${alertName} Change Record`.slice(0, 160),
      summary: `Change notes and approvals for ${service} remediation actions.`,
      content: [
        commonHeader,
        "Change scope: configuration, deployment, and policy updates tied to this alert pattern.",
        "Approval checklist: peer review, CAB approval (if required), and blast-radius assessment.",
        "Backout plan: revert config, redeploy previous version, and validate health endpoints.",
      ].join("\n\n"),
      services: service,
      severity,
      alert_type: alertName,
      alert_id: alertId,
      root_cause: rootCause,
      impact,
      recommended_action: suggestedAction,
    },
    dependency: {
      kind: "dependency",
      title: `${alertName} Dependency Map`.slice(0, 160),
      summary: `Dependency and upstream/downstream checks for ${service}.`,
      content: [
        commonHeader,
        "Dependencies to inspect: datastore latency, queue backlog, external API error rates, and network saturation.",
        "Signals to capture: timeout spikes, retry storms, and circuit breaker open rate.",
        "Mitigation path: isolate degraded dependency, apply traffic shaping, and monitor stabilization.",
      ].join("\n\n"),
      services: service,
      severity,
      alert_type: alertName,
      alert_id: alertId,
      root_cause: rootCause,
      impact,
      recommended_action: suggestedAction,
    },
    remediation: {
      kind: "remediation",
      title: `${alertName} Remediation Command Plan`.slice(0, 160),
      summary: `Auto-generated remediation commands/scripts/queries for ${service}.`,
      content: [
        commonHeader,
        `Recommended remediation action: ${remediationPreview.recommendationText || suggestedAction || "Rollback deployment"}.`,
        `Probable root cause: ${commonRoot}`,
        remediationPlanText || "No remediation command plan was generated.",
      ].filter(Boolean).join("\n\n"),
      services: service,
      severity,
      alert_type: alertName,
      alert_id: alertId,
      root_cause: rootCause,
      impact,
      recommended_action: remediationPreview.recommendationText || suggestedAction,
      execution_plan: remediationPlanText,
      commands: remediationCommands,
      scripts: remediationScripts,
      queries: remediationQueries,
    },
  };
}

function toFiniteNumber(value) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : 0;
}

function percentile(values, fraction) {
  const nums = (Array.isArray(values) ? values : [])
    .map((value) => Number(value))
    .filter((value) => Number.isFinite(value))
    .sort((a, b) => a - b);
  if (!nums.length) {
    return 0;
  }
  const index = Math.min(nums.length - 1, Math.max(0, Math.ceil(fraction * nums.length) - 1));
  return nums[index];
}

function normalizeUsageRow(row) {
  const entry = row && typeof row === "object" ? row : {};
  const usage = entry?.usage && typeof entry.usage === "object" ? entry.usage : {};
  const responseParams = entry?.response?.parameters && typeof entry.response.parameters === "object"
    ? entry.response.parameters
    : {};
  const inputTokens = toFiniteNumber(entry.input_tokens ?? usage.input_tokens ?? entry.prompt_tokens ?? usage.prompt_tokens);
  const outputTokens = toFiniteNumber(entry.output_tokens ?? usage.output_tokens ?? entry.completion_tokens ?? usage.completion_tokens);
  const totalTokens = toFiniteNumber(entry.total_tokens ?? usage.total_tokens ?? (inputTokens + outputTokens));
  const totalCostUsd = toFiniteNumber(
    entry.total_cost_usd
      ?? usage.total_cost_usd
      ?? entry.cost_usd
      ?? usage.cost_usd
      ?? entry.total_cost
      ?? usage.total_cost
  );
  const note = [entry.error, usage.error, entry.reason, usage.reason]
    .map((item) => String(item || "").trim())
    .find((item) => item && item !== "-") || "";
  const estimated = Boolean(entry.estimated ?? usage.estimated);
  const fallback = Boolean(entry.fallback ?? usage.fallback)
    || ["fallback", "heuristic-fallback", "provider-error"].includes(String(entry.provider || usage.provider || entry.model || usage.model || "").trim().toLowerCase());
  return {
    task: entry.task || entry.agent || entry.service || entry.action || entry.event_type || "-",
    provider: entry.provider || entry.vendor || entry.model_provider || usage.provider || responseParams.provider || "-",
    model: entry.model || entry.model_name || entry.deployment || usage.model || responseParams.model || "-",
    input_tokens: inputTokens,
    output_tokens: outputTokens,
    total_tokens: totalTokens,
    total_cost_usd: totalCostUsd,
    note,
    estimated,
    fallback,
  };
}

function isPlaceholderUsageValue(value) {
  const token = String(value || "").trim().toLowerCase();
  return !token || token === "-" || token === "unknown" || token === "n/a" || token === "na" || token === "none" || token === "null";
}

function isMeaningfulUsageRow(row) {
  const hasUsage = toFiniteNumber(row?.input_tokens) > 0 || toFiniteNumber(row?.output_tokens) > 0 || toFiniteNumber(row?.total_tokens) > 0 || toFiniteNumber(row?.total_cost_usd) > 0;
  const hasProvider = !isPlaceholderUsageValue(row?.provider);
  const hasModel = !isPlaceholderUsageValue(row?.model);
  const hasErrorNote = Boolean(String(row?.note || "").trim());
  return hasUsage || hasProvider || hasModel || hasErrorNote;
}

function usageRowIdentity(row) {
  return [
    String(row?.task || "").trim().toLowerCase(),
    String(row?.provider || "").trim().toLowerCase(),
    String(row?.model || "").trim().toLowerCase(),
    String(row?.note || "").trim().toLowerCase(),
    Number(row?.input_tokens || 0),
    Number(row?.output_tokens || 0),
    Number(row?.total_tokens || 0),
  ].join("|");
}

function dedupeUsageRows(rows) {
  const seen = new Set();
  const out = [];
  rows.forEach((row) => {
    const key = usageRowIdentity(row);
    if (seen.has(key)) {
      return;
    }
    seen.add(key);
    out.push(row);
  });
  return out;
}

function HorizontalBarChart({ title, subtitle, items }) {
  const safeItems = Array.isArray(items) ? items : [];
  const maxValue = safeItems.reduce((best, item) => Math.max(best, toFiniteNumber(item?.value)), 0);
  return (
    <article className="panel executive-chart-card">
      <div className="panel-head">
        <h3>{title}</h3>
      </div>
      {subtitle ? <p className="subtitle">{subtitle}</p> : null}
      <div className="executive-bars">
        {safeItems.map((item, index) => {
          const value = toFiniteNumber(item?.value);
          const widthPct = maxValue > 0 ? (value / maxValue) * 100 : 0;
          const normalizedWidth = maxValue > 0 && value > 0 ? Math.max(4, widthPct) : 0;
          const tone = String(item?.tone || "ops");
          return (
            <div className="executive-bar-row" key={`bar-${index}`}>
              <span>{item?.label || "-"}</span>
              <strong>{item?.displayValue ?? String(value)}</strong>
              <div className="executive-bar-track">
                <div className={`executive-bar-fill tone-${tone}`} style={{ width: `${normalizedWidth}%` }} />
              </div>
            </div>
          );
        })}
        {!safeItems.length ? <p className="subtitle">No chart data available.</p> : null}
      </div>
    </article>
  );
}

function SuccessFailureDonut({ success, failure }) {
  const safeSuccess = Math.max(0, toFiniteNumber(success));
  const safeFailure = Math.max(0, toFiniteNumber(failure));
  const total = safeSuccess + safeFailure;
  const successPct = total > 0 ? (safeSuccess / total) * 100 : 0;
  return (
    <article className="panel executive-chart-card">
      <div className="panel-head">
        <h3>Success vs Failure</h3>
      </div>
      <div className="executive-donut-wrap">
        <div
          className="executive-donut"
          style={{
            background: `conic-gradient(var(--ok) 0 ${successPct}%, var(--danger) ${successPct}% 100%)`,
          }}
        >
          <div className="executive-donut-core">
            <strong>{total}</strong>
            <span>Requests</span>
          </div>
        </div>
        <div className="executive-donut-legend">
          <div><span className="legend-dot legend-ok" />Success: {safeSuccess}</div>
          <div><span className="legend-dot legend-danger" />Failure: {safeFailure}</div>
        </div>
      </div>
    </article>
  );
}

const ONBOARDING_STEP_BACKGROUND = {
  setup_monitoring: {
    1: "Saved to the OnboardingStateRecord table (keyed by project_name) via POST /onboarding/complete on monitoring-adapter.",
    2: "No backend call - determines which branch of the same request monitoring-adapter executes next (rule onboarding vs landing pad ingestion).",
    3: "Your plain-English lines are sent to the new-rule-onboarding pipeline, which asks the model-router (LLM) to translate them into concrete Prometheus rule specs (metric, threshold, duration).",
    4: "Generated rules are rendered into Prometheus rule YAML under backend/rag/changes/prometheus_rules, and Prometheus is asked to reload; a simulation check validates the rule behaves as expected.",
    5: "The discovery layer searches incident-only RAG records for similar historical tickets, extracts their resolution context, then creates and saves a new runbook via POST /rag/documents. Existing runbooks are not used as the primary source.",
  },
  existing_monitoring: {
    1: "Saved to the OnboardingStateRecord table (keyed by project_name) via POST /onboarding/complete on monitoring-adapter.",
    2: "No backend call - determines which branch of the same request monitoring-adapter executes next (rule onboarding vs landing pad ingestion).",
    3: "Saves the ingestion endpoint/connection profile you provide. This is the URL your monitoring tool's webhook (e.g. Alertmanager) should POST alerts to.",
    4: "Incoming alerts hit monitoring-adapter's /alerts/alertmanager endpoint, are written to the landing pad, published to the raw-alerts topic, and consumed by alert-intelligence -> orchestrator -> the rest of the incident pipeline.",
    5: "Optional. If rule onboarding was also enabled, documents are generated the same way as the Setup Monitoring path and appear under the Alert Knowledge tab.",
  },
};

function explainOnboardingStepBackground(stepNumber, isSetupMonitoring) {
  const table = ONBOARDING_STEP_BACKGROUND[isSetupMonitoring ? "setup_monitoring" : "existing_monitoring"];
  return table[stepNumber] || "No background detail available for this step.";
}

function findHistoricalTicketDiscoveryDocument(documents, applicationId, applicationName) {
  const normalizedId = String(applicationId || "").trim();
  const normalizedName = String(applicationName || "").trim().toLowerCase();
  return (Array.isArray(documents) ? documents : []).find((doc) => {
    const metadata = doc?.metadata && typeof doc.metadata === "object" ? doc.metadata : {};
    const services = Array.isArray(doc?.services) ? doc.services : [doc?.service];
    return String(doc?.kind || "").trim().toLowerCase() === "runbook"
      && String(metadata?.context_strategy || "").trim() === "similar-historical-tickets-first"
      && (
        (normalizedId && String(metadata?.application_id || "").trim() === normalizedId)
        || (normalizedName && services.some((service) => String(service || "").trim().toLowerCase() === normalizedName))
      );
  }) || null;
}

function HistoricalTicketDiscoveryPanel({ applicationId, applicationName, documents, loading = false }) {
  const discoveryDoc = findHistoricalTicketDiscoveryDocument(documents, applicationId, applicationName);
  const metadata = discoveryDoc?.metadata && typeof discoveryDoc.metadata === "object" ? discoveryDoc.metadata : {};
  const ticketPaths = Array.isArray(metadata.historical_ticket_paths)
    ? metadata.historical_ticket_paths.filter(Boolean)
    : [];
  const ticketCount = Number(metadata.historical_ticket_count ?? ticketPaths.length ?? 0);
  const discoveryComplete = Boolean(discoveryDoc);
  return (
    <section className="ticket-discovery-layer">
      <div className="panel-head">
        <div>
          <h3>Discovery Layer: Historical Ticket Context</h3>
          <p className="subtitle">Runbooks are grounded in similar resolved incidents before new guidance is generated.</p>
        </div>
        <span className={`workflow-pill ${discoveryComplete ? "workflow-pill-active" : "workflow-pill-idle"}`}>
          {loading ? "discovering" : discoveryComplete ? "complete" : "waiting"}
        </span>
      </div>
      <div className="ticket-discovery-flow" aria-label="Historical ticket discovery workflow">
        <div className="ticket-discovery-step"><strong>1. Alert Rules</strong><span>Service and generated rule patterns form the search query.</span></div>
        <span className="ticket-discovery-arrow" aria-hidden="true">→</span>
        <div className="ticket-discovery-step"><strong>2. Similar Tickets</strong><span>{discoveryComplete ? `${ticketCount} incident match${ticketCount === 1 ? "" : "es"} found` : "Incident-only search pending"}</span></div>
        <span className="ticket-discovery-arrow" aria-hidden="true">→</span>
        <div className="ticket-discovery-step"><strong>3. Context Extraction</strong><span>Root cause and resolution evidence are extracted from matched tickets.</span></div>
        <span className="ticket-discovery-arrow" aria-hidden="true">→</span>
        <div className="ticket-discovery-step"><strong>4. Runbook</strong><span>{discoveryDoc?.title || "Generated after discovery completes"}</span></div>
      </div>
      {discoveryComplete ? (
        <div className="ticket-discovery-evidence">
          <strong>Evidence sources</strong>
          {ticketPaths.length ? (
            <ul>{ticketPaths.map((path, index) => <li key={`historical-ticket-${index}`} title={String(path)}>{String(path)}</li>)}</ul>
          ) : (
            <p>Fallback guidance used because no sufficiently similar historical ticket was found.</p>
          )}
        </div>
      ) : (
        <p className="subtitle">This panel updates dynamically when the rule-generation agent publishes the application runbook.</p>
      )}
    </section>
  );
}

function FlowTimelineGraph({ rows }) {
  const timelineRows = Array.isArray(rows) ? rows : [];
  if (!timelineRows.length) {
    return <p className="subtitle">No timeline data found for selected alert.</p>;
  }

  const parseMaybeJson = (value) => {
    const text = String(value || "").trim();
    if (!text) {
      return null;
    }
    try {
      const parsed = JSON.parse(text);
      return parsed && typeof parsed === "object" ? parsed : null;
    } catch (_error) {
      return null;
    }
  };

  const classifyStage = (row) => {
    const stage = String(row?.stage || "").toLowerCase();
    if (stage.includes("landing pad") || stage.includes("alert received") || stage.includes("alert landed")) {
      return { kind: "ingestion", short: "ING", label: "Landing Pad" };
    }
    if (stage.includes("topic handoff") || stage.includes("message bus")) {
      return { kind: "bus", short: "BUS", label: "Message Bus" };
    }
    if (stage.includes("dedup") || stage.includes("correlation") || stage.includes("enrich")) {
      return { kind: "dedupe", short: "DED", label: "Dedup" };
    }
    if (stage.includes("config") || stage.includes("connector lookup")) {
      return { kind: "config", short: "CFG", label: "Config" };
    }
    if (stage.includes("routing") || stage.includes("orchestrator") || stage.includes("workflow")) {
      return { kind: "orchestration", short: "ORC", label: "Orchestrator" };
    }
    if (stage.includes("discovery agent") || stage.includes("code and log context")) {
      return { kind: "discovery", short: "DSC", label: "Discovery" };
    }
    if (stage.includes("rag context") || stage.includes("context retrieval") || stage.includes("context intelligence")) {
      return { kind: "rag", short: "RAG", label: "RAG" };
    }
    if (stage.includes("embedding") || stage.includes("semantic") || stage.includes("vector")) {
      return { kind: "semantic", short: "SEM", label: "Semantic" };
    }
    if (stage.includes("context merge") || stage.includes("evidence assembly")) {
      return { kind: "context", short: "CTX", label: "Context" };
    }
    if (stage.includes("resolution") || stage.includes("recommendation")) {
      return { kind: "resolution", short: "RCA", label: "Resolution" };
    }
    if (stage.includes("approval")) {
      return { kind: "approval", short: "APR", label: "Approval" };
    }
    if (stage.includes("policy")) {
      return { kind: "policy", short: "POL", label: "Policy" };
    }
    if (stage.includes("remediation") || stage.includes("command") || stage.includes("execute")) {
      return { kind: "execution", short: "CMD", label: "Execution" };
    }
    if (stage.includes("closure") || stage.includes("validation")) {
      return { kind: "closure", short: "CLS", label: "Closure" };
    }
    return { kind: "generic", short: "EVT", label: "Event" };
  };

  const getRowBackendEvents = (row) => {
    const input = parseMaybeJson(row?.inputValueText);
    const output = parseMaybeJson(row?.outputValueText);
    const rawEvents = Array.from(
      new Set(
        [
          ...(Array.isArray(row?.backendEvents) ? row.backendEvents : []),
          String(input?.event_type || "").trim(),
          String(output?.event_type || "").trim(),
        ].filter(Boolean)
      )
    );

    const orderHints = [
      "incident.alert",
      "incident.workflow.selected",
      "incident.context.collected",
      "incident.recommendation.generated",
      "incident.approval.requested",
      "incident.approval.recorded",
      "incident.remediation.executed",
      "incident.closure.completed",
    ];

    const eventWeight = (eventName) => {
      const normalized = String(eventName || "").toLowerCase();
      const index = orderHints.findIndex((hint) => normalized.includes(hint));
      return index === -1 ? orderHints.length : index;
    };

    return rawEvents
      .slice()
      .sort((left, right) => {
        const leftWeight = eventWeight(left);
        const rightWeight = eventWeight(right);
        if (leftWeight !== rightWeight) {
          return leftWeight - rightWeight;
        }
        return String(left).localeCompare(String(right));
      });
  };

  const explainBackground = (row, stageMeta) => {
    const input = parseMaybeJson(row?.inputValueText);
    const output = parseMaybeJson(row?.outputValueText);
    const topicIn = String(row?.consumes || "-");
    const topicOut = String(row?.publishes || "-");
    const dbTables = String(row?.tables || "-");
    const mergedBackendEvents = getRowBackendEvents(row);
    const eventStage = String(output?.event_stage || input?.event_stage || row?.detail || "-").trim() || "-";
    const eventStatus = String(output?.status || input?.status || "-").trim() || "-";
    const traceId = String(output?.trace_id || input?.trace_id || "-").trim() || "-";

    return [
      `stage_kind: ${stageMeta.kind}`,
      `backend_events: ${mergedBackendEvents.length ? mergedBackendEvents.join(" | ") : "none"}`,
      `source_topic: ${topicIn}`,
      `target_topic: ${topicOut}`,
      `tables_touched: ${dbTables}`,
      `event_stage: ${eventStage}`,
      `event_status: ${eventStatus}`,
      `trace_id: ${traceId}`,
    ].join("\n");
  };

  const copyPlanStep = async (value) => {
    const text = String(value || "").trim();
    if (!text || typeof navigator === "undefined" || !navigator.clipboard?.writeText) {
      return;
    }
    try {
      await navigator.clipboard.writeText(text);
    } catch (_error) {
      // Best-effort copy for operator convenience.
    }
  };

  const extractExecutionPlan = (row) => {
    const input = parseMaybeJson(row?.inputValueText);
    const output = parseMaybeJson(row?.outputValueText);
    const commands = [];
    const scripts = [];
    const queries = [];
    const seenObjects = new WeakSet();

    const pushUnique = (target, value) => {
      const token = String(value || "").trim();
      if (!token) {
        return;
      }
      if (!target.some((item) => item.toLowerCase() === token.toLowerCase())) {
        target.push(token);
      }
    };

    const classifyLine = (raw) => {
      const token = String(raw || "").trim();
      if (!token) {
        return;
      }
      const lowered = token.toLowerCase();
      if (lowered.startsWith("cmd:")) {
        pushUnique(commands, token.slice(4).trim());
        return;
      }
      if (lowered.startsWith("script:")) {
        pushUnique(scripts, token.slice(7).trim());
        return;
      }
      if (lowered.startsWith("query:")) {
        pushUnique(queries, token.slice(6).trim());
        return;
      }
      pushUnique(commands, token);
    };

    const collectFromPlanText = (value) => {
      const text = String(value || "").trim();
      if (!text) {
        return;
      }
      let currentSection = "command";
      text.split(/\r?\n/).forEach((line) => {
        const token = String(line || "").trim();
        if (!token) {
          return;
        }
        if (/^commands?\s*:/i.test(token)) {
          currentSection = "command";
          const inline = token.replace(/^commands?\s*:/i, "").trim();
          if (inline) {
            classifyLine(`cmd: ${inline}`);
          }
          return;
        }
        if (/^scripts?\s*:/i.test(token)) {
          currentSection = "script";
          const inline = token.replace(/^scripts?\s*:/i, "").trim();
          if (inline) {
            classifyLine(`script: ${inline}`);
          }
          return;
        }
        if (/^(queries?|sql)\s*:/i.test(token)) {
          currentSection = "query";
          const inline = token.replace(/^(queries?|sql)\s*:/i, "").trim();
          if (inline) {
            classifyLine(`query: ${inline}`);
          }
          return;
        }

        const normalized = token.replace(/^[-*]\s*/, "").trim();
        if (!normalized) {
          return;
        }
        if (/^(cmd|command|script|query)\s*:/i.test(normalized)) {
          classifyLine(normalized);
          return;
        }
        if (currentSection === "script") {
          pushUnique(scripts, normalized);
          return;
        }
        if (currentSection === "query") {
          pushUnique(queries, normalized);
          return;
        }
        pushUnique(commands, normalized);
      });
    };

    const collectFromValue = (value) => {
      if (!hasMeaningfulValue(value)) {
        return;
      }
      if (Array.isArray(value)) {
        value.forEach(collectFromValue);
        return;
      }
      if (typeof value === "string") {
        collectFromPlanText(value);
        return;
      }
      if (typeof value !== "object" || value === null) {
        return;
      }
      if (seenObjects.has(value)) {
        return;
      }
      seenObjects.add(value);

      (Array.isArray(value.commands) ? value.commands : []).forEach(classifyLine);
      (Array.isArray(value.scripts) ? value.scripts : []).forEach((item) => pushUnique(scripts, item));
      (Array.isArray(value.queries) ? value.queries : []).forEach((item) => pushUnique(queries, item));

      if (hasMeaningfulValue(value.execution_plan)) {
        collectFromValue(value.execution_plan);
      }

      [
        value.parameters,
        value.remediation_action,
        value.source_payload,
        value.recommendation,
        value.decision,
        value.payload,
        value.input,
        value.output,
        value.result,
      ].forEach((item) => {
        if (item && typeof item === "object") {
          collectFromValue(item);
        }
      });
    };

    collectFromValue(input);
    collectFromValue(output);

    return {
      commands: commands.filter(Boolean),
      scripts: scripts.filter(Boolean),
      queries: queries.filter(Boolean),
    };
  };

  const observedPhases = Array.from(new Map(timelineRows.map((row) => {
    const meta = classifyStage(row);
    return [meta.kind, meta];
  })).values());
  const errorCount = timelineRows.filter((row) => timelineRowHasError(row)).length;
  const compactRows = timelineRows.map((row, index) => {
    const stageMeta = classifyStage(row);
    return {
      key: `compact-${index}`,
      phase: stageMeta.label,
      stage: row.stage || "-",
      agent: row.agent || "-",
      elapsed: row.elapsed !== "-" ? `${row.elapsed}s` : "-",
      status: timelineRowStatus(row) === "failed" ? "error" : timelineRowStatus(row) === "fallback" ? "fallback" : "ok",
      detail: compactText(row.detail, 120) || "-",
    };
  });
  const totalElapsedSeconds = timelineRows.reduce((sum, row) => {
    const value = Number(row?.elapsed);
    return Number.isFinite(value) ? sum + Math.max(0, value) : sum;
  }, 0);
  const totalElapsedDisplay = timelineRows.length ? `${totalElapsedSeconds.toFixed(3)}s` : "-";

  return (
    <div className="timeline-graph">
      <div className="timeline-summary-strip">
        <div className="timeline-summary-metric">
          <strong>{timelineRows.length}</strong>
          <span>Total Stages</span>
        </div>
        <div className="timeline-summary-metric">
          <strong>{observedPhases.length}</strong>
          <span>Observed Phases</span>
        </div>
        <div className="timeline-summary-metric">
          <strong>{Math.max(0, timelineRows.length - errorCount)}</strong>
          <span>Successful Stages</span>
        </div>
        <div className="timeline-phase-strip">
          {observedPhases.map((phase) => {
            return (
              <span
                key={`phase-${phase.kind}`}
                className={`timeline-phase-pill phase-${phase.kind} is-active`}
                title={`${phase.label} observed from runtime events`}
              >
                {phase.label}
              </span>
            );
          })}
        </div>
      </div>
      {timelineRows.map((row, index) => (
        (() => {
          const stageMeta = classifyStage(row);
          const backendEvents = getRowBackendEvents(row);
          const executionPlan = extractExecutionPlan(row);
          const nextRow = timelineRows[index + 1] || null;
          const fallbackStatus = timelineRowStatus(row, nextRow);
          const nextStep = inferTimelineNextStep(row, nextRow);
          const hasExecutionPlan = stageMeta.kind === "execution"
            && (executionPlan.commands.length || executionPlan.scripts.length || executionPlan.queries.length);
          return (
        <article
          className={`timeline-node stage-${stageMeta.kind} ${(fallbackStatus === "failed" || hasMeaningfulValue(row?.errorValueText)) ? "timeline-has-error" : ""}`}
          key={`timeline-node-${index}`}
          style={{ animationDelay: `${Math.min(index * 70, 560)}ms` }}
        >
          <div className="timeline-rail">
            <span className="timeline-dot" />
            {index < timelineRows.length - 1 ? <span className="timeline-line" /> : null}
          </div>
          <div className="timeline-body">
            <div className="timeline-headline">
              <strong>
                <span className={`timeline-stage-badge stage-${stageMeta.kind}`}>{stageMeta.short}</span>
                {" "}
                {row.stage || "-"}
              </strong>
              <span>{formatUtcTimestamp(row.timestamp)}</span>
            </div>
            <div className="timeline-meta">
              <span>{row.agent || "-"}</span>
              <span>{row.service || "-"}</span>
              <span>{row.elapsed !== "-" ? `${row.elapsed}s` : "-"}</span>
              {fallbackStatus === "fallback" ? <span>fallback path</span> : null}
            </div>
            <p>{row.detail || "-"}</p>
            {nextStep && nextStep !== "-" ? (
              <div className="timeline-tags">
                <span className="timeline-tag">next: {nextStep}</span>
              </div>
            ) : null}
            {row.inputValueText ? (
              <details>
                <summary>Input Value</summary>
                <pre className="result">{row.inputValueText}</pre>
              </details>
            ) : null}
            {row.outputValueText ? (
              <details>
                <summary>Output Value</summary>
                <pre className="result">{row.outputValueText}</pre>
              </details>
            ) : null}
            {hasExecutionPlan ? (
              <details open>
                <summary>Resolution Plan (Commands, Scripts, Queries)</summary>
                <div className="timeline-plan-grid">
                  <div className="timeline-plan-section">
                    <h4>Commands</h4>
                    {executionPlan.commands.length ? executionPlan.commands.map((step, stepIndex) => (
                      <div className="timeline-plan-row" key={`cmd-${index}-${stepIndex}`}>
                        <pre className="result">{step}</pre>
                        <button type="button" className="timeline-copy-btn" onClick={() => copyPlanStep(step)}>Copy</button>
                      </div>
                    )) : <p className="subtitle">No command steps.</p>}
                  </div>
                  <div className="timeline-plan-section">
                    <h4>Scripts</h4>
                    {executionPlan.scripts.length ? executionPlan.scripts.map((step, stepIndex) => (
                      <div className="timeline-plan-row" key={`script-${index}-${stepIndex}`}>
                        <pre className="result">{step}</pre>
                        <button type="button" className="timeline-copy-btn" onClick={() => copyPlanStep(step)}>Copy</button>
                      </div>
                    )) : <p className="subtitle">No script steps.</p>}
                  </div>
                  <div className="timeline-plan-section">
                    <h4>Queries</h4>
                    {executionPlan.queries.length ? executionPlan.queries.map((step, stepIndex) => (
                      <div className="timeline-plan-row" key={`query-${index}-${stepIndex}`}>
                        <pre className="result">{step}</pre>
                        <button type="button" className="timeline-copy-btn" onClick={() => copyPlanStep(step)}>Copy</button>
                      </div>
                    )) : <p className="subtitle">No validation queries.</p>}
                  </div>
                </div>
              </details>
            ) : null}
            {row.errorValueText ? (
              <details open>
                <summary>Error</summary>
                <pre className="result">{row.errorValueText}</pre>
              </details>
            ) : null}
            <details>
              <summary>How This Worked In Background</summary>
              <pre className="result">{explainBackground(row, stageMeta)}</pre>
            </details>
            <div className="timeline-tags">
              <span className="timeline-tag">in: {row.consumes || "-"}</span>
              <span className="timeline-tag">out: {row.publishes || "-"}</span>
              <span className="timeline-tag">db: {row.tables || "-"}</span>
            </div>
            <div className="timeline-backend-events">
              <span className="timeline-backend-label">backend:</span>
              {backendEvents.length ? backendEvents.map((eventName, eventIndex) => (
                <span className="timeline-backend-chip" key={`backend-${index}-${eventIndex}`}>
                  {eventName}
                </span>
              )) : <span className="timeline-backend-chip is-empty">none</span>}
            </div>
          </div>
        </article>
          );
        })()
      ))}
      <article className="panel" style={{ marginTop: 10 }}>
        <div className="panel-head">
          <h3>Stage Summary Table</h3>
          <p>Compact timeline view with phase, ownership, and status.</p>
        </div>
        <div className="table-wrap table-wrap-scroll-x">
          <table>
            <thead>
              <tr>
                <th>Phase</th>
                <th>Stage</th>
                <th>Agent</th>
                <th>Elapsed</th>
                <th>Status</th>
                <th>Detail</th>
              </tr>
            </thead>
            <tbody>
              {compactRows.map((row) => (
                <tr key={row.key}>
                  <td>{row.phase}</td>
                  <td>{row.stage}</td>
                  <td>{row.agent}</td>
                  <td>{row.elapsed}</td>
                  <td><span className={`pill ${row.status === "error" ? "status-failed" : "status-approved"}`}>{row.status}</span></td>
                  <td>{row.detail}</td>
                </tr>
              ))}
              <tr>
                <td colSpan={3}><strong>Total Alert Time</strong></td>
                <td><strong>{totalElapsedDisplay}</strong></td>
                <td>-</td>
                <td>Cumulative elapsed time across all listed stages.</td>
              </tr>
            </tbody>
          </table>
        </div>
      </article>
    </div>
  );
}

function UnifiedIncidentTimeline({ workflow, rows, documents = [] }) {
  const [expandedPhaseId, setExpandedPhaseId] = useState("");
  const safeWorkflow = workflow && typeof workflow === "object" ? workflow : {};
  const safeRows = Array.isArray(rows) ? rows : [];
  const lanes = [
    { id: "detect", icon: "↗", label: "Detect", hint: "Signal received", match: ["landing", "ingest", "alert", "monitor"] },
    { id: "discover", icon: "⌕", label: "Discover", hint: "Evidence collected", match: ["discover", "ticket", "log", "trace", "code", "context"] },
    { id: "diagnose", icon: "◇", label: "Diagnose", hint: "Cause assessed", match: ["resolution", "root cause", "rca", "impact", "model"] },
    { id: "decide", icon: "✓", label: "Decide", hint: "Risk reviewed", match: ["approval", "decision", "policy", "risk"] },
    { id: "act", icon: "⚡", label: "Act", hint: "Fix executed", match: ["remedi", "execute", "command", "action"] },
    { id: "validate", icon: "◎", label: "Validate", hint: "Recovery confirmed", match: ["validat", "closure", "closed", "health restored"] },
  ];
  const assigned = new Set();
  // Lane text is built from curated, human-readable fields only -- NOT the raw
  // inputValueText/outputValueText JSON blobs, which almost always carry a trace_id
  // (matches "discover"'s "trace" token) or similar incidental substrings and would
  // otherwise pull unrelated events (e.g. ingestion/topic-handoff rows) into the wrong lane.
  const laneText = (row) => [row?.status, row?.stage, row?.detail, row?.agent, row?.service, row?.consumes, row?.publishes]
    .map((item) => String(item || "").toLowerCase())
    .join(" ");
  const laneRows = lanes.map((lane) => {
    // A row is claimed by at most one lane: the first (in detect -> validate order) whose
    // keywords match. Previously every lane re-tested every row independently, so a single
    // event could match more than one lane's keywords and appear duplicated across phases.
    const matched = safeRows.filter((row, index) => {
      if (assigned.has(index)) {
        return false;
      }
      const text = laneText(row);
      const hit = lane.match.some((token) => text.includes(token));
      if (hit) assigned.add(index);
      return hit;
    });
    return { ...lane, rows: matched };
  });
  safeRows.forEach((row, index) => {
    if (!assigned.has(index)) {
      const target = laneRows[Math.min(laneRows.length - 1, Math.floor((index / Math.max(1, safeRows.length)) * laneRows.length))];
      target.rows.push(row);
    }
  });
  const recommendation = safeWorkflow?.recommendation || {};
  const contextMetadata = recommendation?.metadata || safeWorkflow?.context?.metadata || {};
  const retrievedSources = Array.from(new Set([
    ...(Array.isArray(contextMetadata?.sources) ? contextMetadata.sources : []),
    ...(Array.isArray(documents) ? documents.map((doc) => doc?.source || doc?.kind || doc?.path) : []),
    ...safeRows.flatMap((row) => {
      const text = timelineRowText(row).toLowerCase();
      return [
        text.includes("ticket") || text.includes("jira") ? "Jira / tickets" : "",
        text.includes("log") || text.includes("opensearch") ? "Logs" : "",
        text.includes("trace") || text.includes("jaeger") ? "Traces" : "",
        text.includes("code") || text.includes("repository") ? "Source code" : "",
        text.includes("prometheus") || text.includes("metric") ? "Metrics" : "",
      ].filter(Boolean);
    }),
  ].map((value) => String(value || "").trim()).filter(Boolean)));
  const expandedLane = laneRows.find((lane) => lane.id === expandedPhaseId && lane.rows.length) || null;

  return (
    <section className="unified-incident-timeline" aria-label="Unified incident timeline">
      <header className="unified-timeline-header">
        <div>
          <span className="discovery-eyebrow">Live incident journey</span>
          <h3>Signal to Recovery</h3>
          <p>One ordered view joining ingestion, discovery, context retrieval, reasoning, approval, remediation, and validation.</p>
        </div>
        <div className="unified-timeline-stats">
          <span><strong>{safeRows.length}</strong> events</span>
          <span><strong>{retrievedSources.length}</strong> sources</span>
          <span><strong>{laneRows.filter((lane) => lane.rows.length).length}</strong>/6 phases observed</span>
        </div>
      </header>
      <div className="unified-source-strip">
        <strong>Evidence</strong>
        {retrievedSources.length
          ? retrievedSources.map((source) => <span key={source}>{compactText(source, 42)}</span>)
          : <span>Waiting for source evidence</span>}
      </div>
      <div className="timeline-phase-map">
        {laneRows.map((lane, laneIndex) => {
          const failed = lane.rows.some((row) => timelineRowHasError(row));
          const fallback = lane.rows.some((row) => timelineRowStatus(row) === "fallback");
          const status = failed ? "failed" : fallback ? "fallback" : lane.rows.length ? "complete" : "waiting";
          const latest = lane.rows[lane.rows.length - 1] || {};
          return (
            <article className={`timeline-phase-card is-${status}`} key={lane.id}>
              <div className="timeline-phase-top">
                <span className="timeline-phase-icon" aria-hidden="true">{lane.icon}</span>
                <span className="timeline-phase-number">{String(laneIndex + 1).padStart(2, "0")}</span>
                <i className="timeline-phase-status">{status}</i>
              </div>
              <h4>{lane.label}</h4>
              <p>{lane.hint}</p>
              <div className="timeline-phase-summary">
                <strong>{lane.rows.length}</strong>
                <span>{lane.rows.length === 1 ? "event" : "events"}</span>
              </div>
              {lane.rows.length ? (
                <div className="timeline-phase-latest">
                  <strong>{compactText(latest.stage || latest.agent || latest.service || `${lane.label} event`, 60)}</strong>
                  <p>{compactText(latest.detail || latest.outputValueText || latest.inputValueText, 140) || "No additional detail was recorded for this event."}</p>
                  <small>
                    {latest.agent || latest.service || "KaiOps"} · {formatIstTimestamp(latest.timestamp || latest.created_at)}
                    {latest.status || timelineRowStatus(latest) ? ` · ${latest.status || timelineRowStatus(latest)}` : ""}
                  </small>
                </div>
              ) : (
                <small className="timeline-phase-latest timeline-phase-latest-empty">Not reached yet</small>
              )}
              {lane.rows.length ? (
                <button
                  type="button"
                  className={`timeline-phase-toggle ${expandedPhaseId === lane.id ? "is-active" : ""}`}
                  aria-expanded={expandedPhaseId === lane.id}
                  aria-controls="timeline-event-panel"
                  onClick={() => setExpandedPhaseId((current) => current === lane.id ? "" : lane.id)}
                >
                  {expandedPhaseId === lane.id ? "Hide events" : "View events"}
                </button>
              ) : null}
            </article>
          );
        })}
      </div>
      {expandedLane ? (
        <section className="timeline-event-panel" id="timeline-event-panel" aria-live="polite">
          <header>
            <div>
              <span className="timeline-phase-icon" aria-hidden="true">{expandedLane.icon}</span>
              <div>
                <strong>{expandedLane.label} events</strong>
                <small>{expandedLane.rows.length} recorded workflow event(s)</small>
              </div>
            </div>
            <button type="button" className="button-secondary" onClick={() => setExpandedPhaseId("")}>Close</button>
          </header>
          <div className="timeline-event-list">
            {expandedLane.rows.slice(0, 20).map((row, rowIndex) => (
              <article key={`${expandedLane.id}-expanded-${rowIndex}`}>
                <span className="timeline-event-index">{String(rowIndex + 1).padStart(2, "0")}</span>
                <div>
                  <header>
                    <strong>{row.stage || row.agent || row.service || `Event ${rowIndex + 1}`}</strong>
                    <span>{row.status || timelineRowStatus(row)}</span>
                  </header>
                  <p>{compactText(row.detail || row.outputValueText || row.inputValueText, 360) || "Stage completed."}</p>
                  <small>
                    {row.agent || row.service || "KaiOps"} · {formatIstTimestamp(row.timestamp || row.created_at)}
                    {row.executionTimeMs || row.execution_time_ms ? ` · ${row.executionTimeMs || row.execution_time_ms} ms` : ""}
                  </small>
                </div>
              </article>
            ))}
          </div>
        </section>
      ) : null}
    </section>
  );
}

function DiscoveryFlowView({ workflow, timelineRows = [], selectedAlert = null, compact = false }) {
  const safeWorkflow = workflow && typeof workflow === "object" ? workflow : {};
  const recommendation = safeWorkflow?.recommendation && typeof safeWorkflow.recommendation === "object"
    ? safeWorkflow.recommendation
    : {};
  const recommendationMetadata = recommendation?.metadata && typeof recommendation.metadata === "object"
    ? recommendation.metadata
    : {};
  const metadataCandidates = [
    safeWorkflow?.context?.metadata,
    safeWorkflow?.recommendation?.metadata,
  ].filter((row) => row && typeof row === "object");
  const tracePayloads = (Array.isArray(safeWorkflow.event_trace) ? safeWorkflow.event_trace : [])
    .map((row) => row?.payload)
    .filter((row) => row && typeof row === "object");
  const eventContracts = [
    ...(Array.isArray(safeWorkflow.events) ? safeWorkflow.events : []),
    ...tracePayloads,
  ]
    .map((row) => row?.event_contract?.payload?.discovery || row?.payload?.discovery || row?.discovery)
    .filter((row) => row && typeof row === "object");
  const mcp = metadataCandidates.map((row) => row.discovery_report).find((row) => row && typeof row === "object") || {};
  const contractDiscovery = eventContracts[0] || {};
  const report =
    (mcp.report && typeof mcp.report === "object" && mcp.report)
    || contractDiscovery
    || {};
  const evidence =
    (Array.isArray(mcp.evidence) && mcp.evidence)
    || (Array.isArray(contractDiscovery.evidence) && contractDiscovery.evidence)
    || [];
  let stages =
    (Array.isArray(mcp.retrieval_stages) && mcp.retrieval_stages)
    || (Array.isArray(contractDiscovery.retrieval_stages) && contractDiscovery.retrieval_stages)
    || [];
  if (!stages.length) {
    stages = (Array.isArray(timelineRows) ? timelineRows : [])
      .filter((row) => String(row?.stage || "").toLowerCase().includes("discovery"))
      .map((row) => ({
        stage: row.stage,
        status: row.errorValueText ? "failed" : "completed",
        error: row.errorValueText || "",
      }));
  }
  if (!stages.length && evidence.length) {
    const sources = [...new Set(evidence.map((row) => row?.source).filter(Boolean))];
    stages = [
      { stage: "query_planned", status: "completed" },
      ...sources.map((source) => ({ stage: `${source}_search`, status: "completed", result_count: evidence.filter((row) => row?.source === source).length })),
      { stage: "evidence_correlated", status: "completed", result_count: evidence.length },
    ];
  }
  const hypotheses = Array.isArray(report.hypotheses) ? report.hypotheses : [];
  const modelInteraction =
    (mcp.model_interaction && typeof mcp.model_interaction === "object" && mcp.model_interaction)
    || (contractDiscovery.model_interaction && typeof contractDiscovery.model_interaction === "object" && contractDiscovery.model_interaction)
    || {};
  const sourceCounts = evidence.reduce((counts, row) => {
    const source = String(row?.source || "other").toLowerCase();
    counts[source] = (counts[source] || 0) + 1;
    return counts;
  }, {});
  const rootCause = cleanRecommendationText(
    recommendation?.root_cause,
    report.summary || safeWorkflow?.alert?.description || selectedAlert?.description || "-"
  );
  const impact = cleanRecommendationText(
    recommendation?.impact,
    `${selectedAlert?.service || safeWorkflow?.alert?.service || "Selected service"} may have degraded availability, latency, or downstream workflow impact until mitigation is validated.`
  );
  const recommendedAction = cleanRecommendationText(recommendation?.recommended_action, "-");
  const supportingReasonCandidates = [
    ...(Array.isArray(recommendationMetadata?.reasoning_steps) ? recommendationMetadata.reasoning_steps : []),
    ...(Array.isArray(recommendationMetadata?.reason_codes) ? recommendationMetadata.reason_codes : []),
    ...(Array.isArray(recommendationMetadata?.causal_factors) ? recommendationMetadata.causal_factors : []),
    ...hypotheses.flatMap((row) => Array.isArray(row?.supporting_evidence) ? row.supporting_evidence : []),
    ...(Array.isArray(timelineRows) ? timelineRows : [])
      .filter((row) => row?.errorValueText)
      .map((row) => `${row.stage || "stage"}: ${row.errorValueText}`),
  ]
    .map((row) => compactText(row, 220))
    .map((row) => String(row || "").trim())
    .filter(Boolean);
  const detailedReasons = Array.from(new Set(supportingReasonCandidates)).slice(0, 12);
  const protocol = mcp.protocol || "mcp-jsonrpc-2.0";
  const hasDiscovery = stages.length > 0 || evidence.length > 0 || Boolean(report.summary);
  const sourceOrder = ["log", "ticket", "code", "mysql", "metric", "trace", "opensearch"];
  const visibleSources = Array.from(new Set([...sourceOrder, ...Object.keys(sourceCounts)]))
    .filter((source) => sourceCounts[source]);
  const stageDetail = (stage) => {
    const name = String(stage?.stage || "").toLowerCase();
    if (name.includes("query_planned")) return "Build service, alert, environment, trace, scenario, application, and ticket search terms.";
    if (name.includes("log_search") || name.includes("logs_search")) return "Search runtime and landing-pad logs and preserve matching lines with source URIs.";
    if (name.includes("ticket_search") || name.includes("tickets_search")) return "Search Jira CSV, email, historical incidents, and landing-pad ticket content.";
    if (name.includes("code_search")) return "Search the affected service source first, then the full project repository.";
    if (name.includes("mysql_search")) return "Search KaiOps incident projections and related operational records.";
    if (name.includes("telemetry_search")) return "Correlate Prometheus metrics, Jaeger traces, and OpenSearch logs by service and trace ID.";
    if (name.includes("onboarding_context_merge")) return "Merge application ownership, environment, namespace, monitoring, and onboarding metadata into context.";
    if (name.includes("evidence_correlated")) return "Deduplicate and rank facts while retaining evidence IDs and provenance.";
    if (name.includes("llm_analysis")) return "Send only retrieved evidence to the model and require cited JSON RCA.";
    if (name.includes("discovery_completed")) return "Publish grounded discovery context to downstream RCA and impact analysis.";
    return "Execute the recorded discovery stage and preserve its input, status, and output.";
  };

  return (
    <section className={`discovery-workspace ${compact ? "is-compact" : ""}`}>
      {compact ? (
        <header className="discovery-compact-head">
          <h4>Discovery Agent Trace</h4>
          <div className="discovery-kpis">
            <span><strong>{stages.length}</strong> stages</span>
            <span><strong>{evidence.length}</strong> evidence</span>
            <span><strong>{hypotheses.length}</strong> hypotheses</span>
            <span><strong>{protocol.includes("mcp") ? "MCP" : protocol}</strong> protocol</span>
          </div>
        </header>
      ) : (
        <header className="discovery-hero">
          <div>
            <span className="discovery-eyebrow">Evidence-grounded investigation</span>
            <h3>Discovery Agent</h3>
            <p>Dynamic retrieval from logs, tickets, and code followed by cited RCA reasoning.</p>
          </div>
          <div className="discovery-kpis">
            <span><strong>{stages.length}</strong> stages</span>
            <span><strong>{evidence.length}</strong> evidence</span>
            <span><strong>{hypotheses.length}</strong> hypotheses</span>
            <span><strong>{protocol.includes("mcp") ? "MCP" : protocol}</strong> protocol</span>
          </div>
        </header>
      )}

      {hasDiscovery ? (
        <>
          <div className="discovery-flow" aria-label="Dynamic discovery agent flow">
            {stages.map((stage, index) => {
              const state = String(stage.status || "completed").toLowerCase();
              return (
                <div className="discovery-flow-segment" key={`discovery-stage-${index}-${stage.stage || ""}`}>
                  <article className={`discovery-stage is-${state}`}>
                    <span className="discovery-stage-index">{index + 1}</span>
                    <div>
                      <strong>{String(stage.stage || `stage ${index + 1}`).replaceAll("_", " ")}</strong>
                      <small>{state}{Number.isFinite(Number(stage.result_count)) ? ` · ${stage.result_count} result(s)` : ""}</small>
                      <p className="discovery-stage-detail">{stageDetail(stage)}</p>
                      {Number(stage.result_count) === 0 ? <small className="discovery-no-match">No matching evidence was returned by this source.</small> : null}
                      {Array.isArray(stage.terms) && stage.terms.length ? <small>Query: {stage.terms.join(", ")}</small> : null}
                      {stage.model ? <small>Model: {stage.model}</small> : null}
                      {stage.error ? <p>{stage.error}</p> : null}
                    </div>
                  </article>
                  {index < stages.length - 1 ? <span className="discovery-connector" aria-hidden="true">↓</span> : null}
                </div>
              );
            })}
          </div>

          <div className="discovery-grid">
            <article className="discovery-panel">
              <div className="panel-head">
                <h4>RCA synthesis</h4>
                <p>{report.model ? `Model: ${report.model}` : "Model details not reported"}</p>
              </div>
              <p className="discovery-summary">{report.summary || "Retrieval completed; no synthesis summary was returned."}</p>
              {hypotheses.length ? hypotheses.map((row, index) => (
                <div className="discovery-hypothesis" key={`discovery-hypothesis-${index}`}>
                  <strong>{row.cause || `Hypothesis ${index + 1}`}</strong>
                  <span>{Math.round(Number(row.confidence || 0) * 100)}% confidence</span>
                  <small>Evidence: {(row.supporting_evidence || []).join(", ") || "not cited"}</small>
                </div>
              )) : (
                <p className="subtitle">{report.insufficient_evidence ? "Insufficient evidence for a defensible root-cause hypothesis." : "No hypothesis was returned."}</p>
              )}
            </article>

            <article className="discovery-panel">
              <div className="panel-head">
                <h4>What Was Retrieved From Each Source</h4>
                <p>Every fact retains its source, search match, URI, location, and content hash.</p>
              </div>
              <div className="discovery-source-grid">
                {visibleSources.map((source) => (
                  <div key={`source-${source}`}>
                    <strong>{sourceCounts[source] || 0}</strong>
                    <span>{source}</span>
                  </div>
                ))}
              </div>
              <div className="discovery-evidence-list">
                {evidence.map((row, index) => (
                  <details key={`evidence-${row.evidence_id || index}`}>
                    <summary><strong>{row.evidence_id || `EVIDENCE-${index + 1}`}</strong> · {row.source || "source"}</summary>
                    <small>{row.uri || row.path || "No source URI"}</small>
                    <pre className="result">{row.snippet || "No evidence snippet returned."}</pre>
                    {Array.isArray(row.matched_terms) && row.matched_terms.length ? <small>Matched: {row.matched_terms.join(", ")}</small> : null}
                    {row.sha256 ? <small>Content hash: {row.sha256}</small> : null}
                  </details>
                ))}
                {!evidence.length ? <p className="subtitle">No cited evidence was returned for this run.</p> : null}
              </div>
            </article>

            <article className="discovery-panel discovery-model-panel">
              <div className="panel-head">
                <h4>Prompt And Response Received</h4>
                <p>{modelInteraction.model ? `${modelInteraction.provider || "provider"} · ${modelInteraction.model}` : "Available for newly processed alerts"}</p>
              </div>
              {modelInteraction.prompt ? (
                <>
                  <div className="discovery-message-label">Prompt</div>
                  <pre className="result discovery-message">{modelInteraction.prompt}</pre>
                  <details>
                    <summary>Request payload sent with the prompt</summary>
                    <pre className="result discovery-message">{JSON.stringify(modelInteraction.request_payload || {}, null, 2)}</pre>
                  </details>
                  <div className="discovery-message-label">Response received</div>
                  <pre className="result discovery-message">{typeof modelInteraction.response_received === "string"
                    ? modelInteraction.response_received
                    : JSON.stringify(modelInteraction.response_received ?? modelInteraction.parsed_response ?? {}, null, 2)}</pre>
                  {modelInteraction.usage && Object.keys(modelInteraction.usage).length ? (
                    <small>Usage: {JSON.stringify(modelInteraction.usage)}</small>
                  ) : null}
                </>
              ) : (
                <p className="subtitle">This alert predates prompt auditing. Reprocess it to capture the exact prompt, evidence payload, model, and response.</p>
              )}
            </article>

            <article className="discovery-panel discovery-outcome-panel">
              <div className="panel-head">
                <h4>Detailed RCA and Impact</h4>
                <p>Root cause, impact scope, and explicit reasoning signals merged from discovery and context metadata.</p>
              </div>
              <div className="table-wrap table-wrap-scroll-x">
                <table>
                  <tbody>
                    <tr><th>Root Cause</th><td>{rootCause}</td></tr>
                    <tr><th>Impact</th><td>{impact}</td></tr>
                    <tr><th>Recommended Action</th><td>{recommendedAction}</td></tr>
                  </tbody>
                </table>
              </div>
              {detailedReasons.length ? (
                <div>
                  <h5 style={{ margin: "8px 0 6px" }}>Reason Breakdown</h5>
                  <ul style={{ margin: 0, paddingLeft: 18 }}>
                    {detailedReasons.map((reason, index) => (
                      <li key={`discovery-reason-${index}`}>{reason}</li>
                    ))}
                  </ul>
                </div>
              ) : (
                <p className="subtitle">No explicit reason trace was returned by this run.</p>
              )}
            </article>
          </div>
        </>
      ) : (
        <div className="discovery-empty">
          <strong>No Discovery Agent trace exists for this alert.</strong>
          <p>Process a fresh alert after the MCP deployment. This view will construct itself from the stages and evidence returned by that run.</p>
        </div>
      )}
    </section>
  );
}

function parseStructuredIntelligence(value) {
  if (value && typeof value === "object" && !Array.isArray(value)) {
    return value;
  }
  const text = String(value || "").trim();
  if (!text) {
    return null;
  }
  const fenced = text.match(/```(?:json)?\s*([\s\S]*?)```/i);
  const candidates = [fenced?.[1], text];
  const firstBrace = text.indexOf("{");
  const lastBrace = text.lastIndexOf("}");
  if (firstBrace >= 0 && lastBrace > firstBrace) {
    candidates.push(text.slice(firstBrace, lastBrace + 1));
  }
  for (const candidate of candidates.filter(Boolean)) {
    try {
      const parsed = JSON.parse(candidate);
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
        return parsed;
      }
    } catch (_error) {
      // Continue through compatible legacy model-response shapes.
    }
  }
  return null;
}

function intelligenceListText(value) {
  if (Array.isArray(value)) {
    return value
      .map((item) => {
        if (item && typeof item === "object") {
          return item.snippet || item.summary || item.evidence_id || item.id || Object.values(item).filter(Boolean).join(": ");
        }
        return String(item || "").trim();
      })
      .filter(Boolean)
      .join("; ");
  }
  if (value && typeof value === "object") {
    return Object.entries(value)
      .map(([key, item]) => `${key.replaceAll("_", " ")}: ${intelligenceListText(item)}`)
      .join("; ");
  }
  return String(value || "").trim();
}

function groundedIntelligenceDisplay(label, value) {
  const parsed = parseStructuredIntelligence(value);
  if (!parsed) {
    return { headline: cleanRecommendationText(value, `No ${label.toLowerCase()} was produced.`), details: [] };
  }
  const isRca = label === "RCA";
  const isImpact = label === "Impact";
  const headlineValue = (
    isRca
      ? parsed.root_cause || parsed.cause || parsed.summary
      : isImpact
        ? parsed.impact_summary || parsed.service_impact || parsed.customer_impact || parsed.severity_rationale || parsed.summary
        : parsed.recommended_action || parsed.action || parsed.summary
  );
  const headline = cleanRecommendationText(
    headlineValue,
    `No grounded ${label.toLowerCase()} was produced.`,
  );
  const detailCandidates = isRca
    ? [
        ["Evidence used", parsed.evidence_used],
        ["Alternative causes", parsed.alternative_causes],
        ["Missing evidence", parsed.missing_evidence],
        ["Grounding notes", parsed.grounding_notes],
      ]
    : isImpact
      ? [
          ["Impacted services", parsed.impacted_services],
          ["Customer impact", parsed.customer_impact],
          ["Dependency impact", parsed.dependency_impact],
          ["Blast radius", parsed.blast_radius],
          ["Evidence used", parsed.evidence_used],
          ["Missing evidence", parsed.missing_evidence],
          ["Assumptions", parsed.assumptions],
        ]
      : [
          ["Why", parsed.why_this_action],
          ["Validation", parsed.validation_queries],
          ["Rollback", parsed.rollback_plan],
          ["Missing evidence", parsed.missing_evidence],
        ];
  const details = detailCandidates
    .map(([detailLabel, detailValue]) => ({ label: detailLabel, value: intelligenceListText(detailValue) }))
    .filter((item) => item.value);
  const confidence = Number(parsed.confidence_score);
  if (
    Number.isFinite(confidence)
    && confidence >= 0
    && !headline.toLowerCase().startsWith("no grounded")
  ) {
    details.push({ label: "Confidence", value: `${Math.round(confidence * 100)}%` });
  }
  return { headline, details };
}

function canonicalIncidentAnalysis(workflow, alertRow = null) {
  const safeWorkflow = workflow && typeof workflow === "object" ? workflow : {};
  const recommendation = safeWorkflow.recommendation && typeof safeWorkflow.recommendation === "object"
    ? safeWorkflow.recommendation
    : {};
  const metadata = recommendation.metadata && typeof recommendation.metadata === "object"
    ? recommendation.metadata
    : {};
  const contextMetadata = safeWorkflow?.context?.metadata && typeof safeWorkflow.context.metadata === "object"
    ? safeWorkflow.context.metadata
    : {};
  const discovery = contextMetadata.discovery_report && typeof contextMetadata.discovery_report === "object"
    ? contextMetadata.discovery_report
    : {};
  const report = discovery.report && typeof discovery.report === "object" ? discovery.report : {};
  const hypotheses = Array.isArray(report.hypotheses) ? report.hypotheses : [];
  const rca = metadata.rca_analysis && typeof metadata.rca_analysis === "object" ? metadata.rca_analysis : {};
  const impact = metadata.impact_analysis && typeof metadata.impact_analysis === "object" ? metadata.impact_analysis : {};
  const remediation = metadata.remediation_analysis && typeof metadata.remediation_analysis === "object"
    ? metadata.remediation_analysis
    : {};
  const confirmedRootCause = cleanRecommendationText(rca.root_cause || recommendation.root_cause, "");
  const hypothesis = hypotheses.find((item) => item && item.cause);
  const rootCause = confirmedRootCause
    || (hypothesis ? `Hypothesis (not confirmed): ${cleanRecommendationText(hypothesis.cause, "")}` : "")
    || "RCA pending: available evidence is insufficient for a grounded conclusion.";
  const explicitImpact = cleanRecommendationText(
    impact.impact_summary
      || impact.customer_impact
      || impact.service_impact
      || recommendation.impact,
    "",
  );
  const action = cleanRecommendationText(remediation.recommended_action || recommendation.recommended_action, "");
  const externalKnowledgeUsed = Boolean(
    rca.external_knowledge_used
      || report.external_knowledge_used
      || metadata.external_knowledge_used
  );
  const externalKnowledgeEligible = Boolean(
    report.external_knowledge_eligible
      || metadata.external_knowledge_eligible
  );
  const externalKnowledgeError = cleanRecommendationText(
    report.external_knowledge_error || metadata.external_knowledge_error,
    "",
  );
  return {
    rootCause,
    impact: explicitImpact || "Impact not established from current evidence.",
    action: action || "Recommended action pending grounded RCA.",
    rca,
    impactAnalysis: impact,
    remediation,
    status: confirmedRootCause ? "resolved-analysis" : hypothesis ? "hypothesis" : "insufficient-evidence",
    confidence: Number(recommendation.confidence ?? rca.confidence_score ?? hypothesis?.confidence ?? 0),
    externalKnowledgeUsed,
    externalKnowledgeEligible,
    externalKnowledgeError,
    externalKnowledgeStatus: externalKnowledgeUsed
      ? "used"
      : externalKnowledgeError
        ? `failed: ${externalKnowledgeError}`
        : externalKnowledgeEligible
          ? "eligible; no configured external evidence returned"
          : "not required",
    externalToolsUsed: Array.isArray(metadata.external_tools_used)
      ? metadata.external_tools_used
      : Array.isArray(report.external_tools_used)
        ? report.external_tools_used
        : [],
    service: alertRow?.service || safeWorkflow?.alert?.service || recommendation?.metadata?.service || "unknown",
  };
}

function downloadInvestigationArtifact(filename, payload) {
  const safeName = String(filename || "kaiops-investigation.json")
    .replace(/[^a-z0-9._-]+/gi, "-")
    .replace(/-+/g, "-")
    .toLowerCase();
  const content = typeof payload === "string" ? payload : JSON.stringify(payload, null, 2);
  const blob = new Blob([content], {
    type: typeof payload === "string" ? "text/plain;charset=utf-8" : "application/json;charset=utf-8",
  });
  const objectUrl = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = objectUrl;
  anchor.download = safeName;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(objectUrl);
}

function IntelligenceConnectionView({ workflow, documents = [], onDownloadDocument }) {
  const safeWorkflow = workflow && typeof workflow === "object" ? workflow : {};
  const context = safeWorkflow.context && typeof safeWorkflow.context === "object" ? safeWorkflow.context : {};
  const metadata = context.metadata && typeof context.metadata === "object" ? context.metadata : {};
  const recommendation = safeWorkflow.recommendation && typeof safeWorkflow.recommendation === "object"
    ? safeWorkflow.recommendation
    : {};
  const recommendationMetadata = recommendation.metadata && typeof recommendation.metadata === "object"
    ? recommendation.metadata
    : {};
  const metadataCandidates = [
    metadata,
    recommendationMetadata,
  ].filter((row) => row && typeof row === "object");
  const tracePayloads = (Array.isArray(safeWorkflow.event_trace) ? safeWorkflow.event_trace : [])
    .map((row) => row?.payload)
    .filter((row) => row && typeof row === "object");
  const eventContracts = [
    ...(Array.isArray(safeWorkflow.events) ? safeWorkflow.events : []),
    ...tracePayloads,
  ]
    .map((row) => row?.event_contract?.payload?.discovery || row?.payload?.discovery || row?.discovery)
    .filter((row) => row && typeof row === "object");
  const discovery = metadataCandidates
    .map((row) => row.discovery_report)
    .find((row) => row && typeof row === "object")
    || {};
  const contractDiscovery = eventContracts[0] || {};
  const report =
    (discovery.report && typeof discovery.report === "object" && discovery.report)
    || (contractDiscovery.report && typeof contractDiscovery.report === "object" && contractDiscovery.report)
    || contractDiscovery
    || {};
  const evidence =
    (Array.isArray(discovery.evidence) && discovery.evidence)
    || (Array.isArray(contractDiscovery.evidence) && contractDiscovery.evidence)
    || [];
  const canonicalAnalysis = canonicalIncidentAnalysis(safeWorkflow);
  const ragMatches = metadataCandidates
    .map((row) => (Array.isArray(row.rag_matches) ? row.rag_matches : null))
    .find((row) => Array.isArray(row))
    || [];
  const sourceCounts = evidence.reduce((result, item) => {
    const source = String(item?.source || "other").toLowerCase();
    result[source] = (result[source] || 0) + 1;
    return result;
  }, {});
  const dependencyRows = Array.isArray(context.dependency_services)
    ? context.dependency_services
    : Array.isArray(context.dependencies)
      ? context.dependencies
      : [];
  const dependencies = dependencyRows
    .map((item) => (typeof item === "string" ? item : item?.service || item?.name || item?.id || ""))
    .filter(Boolean);
  const relatedIncidents = Array.isArray(context.related_incidents)
    ? context.related_incidents
    : Array.isArray(context.incidents)
      ? context.incidents
      : [];
  const recentChanges = Array.isArray(context.recent_changes)
    ? context.recent_changes
    : Array.isArray(context.changes)
      ? context.changes
      : [];
  const contextItems = [
    context.deployment ? { label: "Deployment", value: context.deployment, source: "Jenkins / alert / RAG deployment" } : null,
    dependencies.length
      ? { label: "Dependencies", value: dependencies.join(", "), source: "CMDB + dependency documents" }
      : null,
    relatedIncidents.length
      ? { label: "Related incidents", value: `${relatedIncidents.length} historical incident(s)`, source: "RAG incident search" }
      : null,
    recentChanges.length
      ? { label: "Recent changes", value: `${recentChanges.length} change record(s)`, source: "ServiceNow + GitHub + RAG changes" }
      : null,
    context.runbook ? { label: "Runbook", value: compactText(context.runbook, 180), source: "RAG runbook retrieval" } : null,
    ragMatches.length ? { label: "Ranked documents", value: `${ragMatches.length} semantic/metadata match(es)`, source: "Vector and metadata search" } : null,
    evidence.length ? { label: "Discovery evidence", value: `${evidence.length} grounded fact(s)`, source: "Discovery MCP" } : null,
  ].filter(Boolean);
  const hypotheses = Array.isArray(report.hypotheses) ? report.hypotheses : [];
  const rcaAnalysis = recommendationMetadata.rca_analysis && typeof recommendationMetadata.rca_analysis === "object"
    ? recommendationMetadata.rca_analysis
    : {};
  const impactAnalysis = recommendationMetadata.impact_analysis && typeof recommendationMetadata.impact_analysis === "object"
    ? recommendationMetadata.impact_analysis
    : {};
  const remediationAnalysis = recommendationMetadata.remediation_analysis && typeof recommendationMetadata.remediation_analysis === "object"
    ? recommendationMetadata.remediation_analysis
    : {};
  const detectedErrors = Array.isArray(report.detected_errors)
    ? report.detected_errors
    : Array.isArray(discovery.detected_errors)
      ? discovery.detected_errors
      : Array.isArray(recommendationMetadata.detected_errors)
        ? recommendationMetadata.detected_errors
        : [];
  const supportingIds = Array.from(new Set([
    ...(Array.isArray(report.citations) ? report.citations : []),
    ...hypotheses.flatMap((item) => Array.isArray(item?.supporting_evidence) ? item.supporting_evidence : []),
    ...(Array.isArray(rcaAnalysis.evidence_used) ? rcaAnalysis.evidence_used : []),
    ...(Array.isArray(impactAnalysis.evidence_used) ? impactAnalysis.evidence_used : []),
    ...detectedErrors.map((item) => item?.evidence_id),
  ].filter(Boolean)));
  const queryTerms = Array.isArray(discovery.query_terms)
    ? discovery.query_terms
    : Array.isArray(contractDiscovery.query_terms)
      ? contractDiscovery.query_terms
      : Array.isArray(report.query_terms)
        ? report.query_terms
        : Array.isArray(metadata.query_terms)
          ? metadata.query_terms
          : Array.isArray(recommendationMetadata.query_terms)
            ? recommendationMetadata.query_terms
            : [];
  const reasoningConfidence = Number(
    recommendation.confidence
    ?? rcaAnalysis.confidence_score
    ?? report.confidence_score
    ?? 0
  );
  const storyStages = [
    {
      id: "signal",
      number: "01",
      eyebrow: "Question formed",
      title: "Alert becomes a search plan",
      summary: "Service, alert name, environment, symptoms, and scenario are converted into focused retrieval terms.",
      metric: queryTerms.length || "Auto",
      metricLabel: queryTerms.length === 1 ? "query term" : "query terms",
      tags: queryTerms.slice(0, 5),
      tone: "blue",
    },
    {
      id: "discover",
      number: "02",
      eyebrow: "Read-only discovery",
      title: "Tools return source facts",
      summary: "Logs, tickets, traces, metrics, and code are searched. Every useful fact keeps its source and immutable evidence ID.",
      metric: evidence.length,
      metricLabel: evidence.length === 1 ? "grounded fact" : "grounded facts",
      tags: Object.entries(sourceCounts).map(([source, count]) => `${source} ${count}`).slice(0, 5),
      tone: "violet",
    },
    {
      id: "context",
      number: "03",
      eyebrow: "Context retrieval",
      title: "Facts are connected to operations",
      summary: "Semantic and metadata search rank documents, then merge dependencies, recent changes, related incidents, and runbook guidance.",
      metric: ragMatches.length || documents.length,
      metricLabel: "ranked documents",
      tags: [
        dependencies.length ? `${dependencies.length} dependencies` : "",
        recentChanges.length ? `${recentChanges.length} changes` : "",
        relatedIncidents.length ? `${relatedIncidents.length} incidents` : "",
        context.runbook ? "runbook found" : "",
      ].filter(Boolean),
      tone: "green",
    },
    {
      id: "reason",
      number: "04",
      eyebrow: "Grounded reasoning",
      title: "RCA and impact are derived",
      summary: "The reasoning agent compares hypotheses against collected context, retains alternatives and missing evidence, and cites supporting facts.",
      metric: Number.isFinite(reasoningConfidence) && reasoningConfidence > 0 ? `${Math.round(reasoningConfidence * 100)}%` : supportingIds.length,
      metricLabel: Number.isFinite(reasoningConfidence) && reasoningConfidence > 0 ? "confidence" : "citations",
      tags: supportingIds.slice(0, 4),
      tone: "orange",
    },
    {
      id: "act",
      number: "05",
      eyebrow: "Decision ready",
      title: "Evidence becomes an action",
      summary: "RCA, impact, and safety constraints produce an operator-readable recommendation for approval, execution, and validation.",
      metric: recommendation.recommended_action ? "Ready" : "Pending",
      metricLabel: "recommended action",
      tags: ["approval gate", "guarded execution", "recovery validation"],
      tone: "red",
    },
  ];
  const fallbackWithoutGrounding = Boolean(
    (metadata.fallback_used || recommendationMetadata.fallback_used)
    && (!Array.isArray(rcaAnalysis.evidence_used) || !rcaAnalysis.evidence_used.length)
  );
  const outputs = [
    {
      label: "RCA",
      value: fallbackWithoutGrounding
        ? null
        : Object.keys(rcaAnalysis).length
        ? rcaAnalysis
        : recommendation.root_cause || (hypotheses[0] && {
            root_cause: hypotheses[0].cause,
            evidence_used: hypotheses[0].supporting_evidence,
            alternative_causes: hypotheses.slice(1).map((item) => item.cause),
            confidence_score: hypotheses[0].confidence,
            grounding_notes: report.summary,
          }) || canonicalAnalysis.rootCause,
    },
    {
      label: "Impact",
      value: fallbackWithoutGrounding
        ? null
        : Object.keys(impactAnalysis).length
        ? impactAnalysis
        : recommendation.impact || report.impact || canonicalAnalysis.impact,
    },
    {
      label: "Recommended action",
      value: Object.keys(remediationAnalysis).length
        ? remediationAnalysis
        : recommendation.recommended_action || (Array.isArray(report.recommended_next_checks)
          ? {
              recommended_action: report.recommended_next_checks[0],
              validation_queries: report.recommended_next_checks.slice(1),
              missing_evidence: report.insufficient_evidence ? ["Resolution Agent output is not available yet."] : [],
            }
          : canonicalAnalysis.action),
    },
  ].map((item) => ({ ...item, display: groundedIntelligenceDisplay(item.label, item.value) }));
  const investigationPackage = {
    generated_at: new Date().toISOString(),
    alert: safeWorkflow.alert || {},
    incident: safeWorkflow.incident || {},
    query_plan: { query_terms: queryTerms, retrieval_stages: discovery.retrieval_stages || [] },
    discovery_evidence: evidence,
    assembled_context: context,
    ranked_documents: ragMatches,
    linked_documents: documents,
    hypotheses,
    detected_errors: detectedErrors,
    citations: supportingIds,
    recommendation,
  };
  const stageArtifact = (stageId) => {
    if (stageId === "signal") return investigationPackage.query_plan;
    if (stageId === "discover") return { source_counts: sourceCounts, evidence };
    if (stageId === "context") return { context, ranked_documents: ragMatches, linked_documents: documents };
    if (stageId === "reason") {
      return {
        report,
        hypotheses,
        citations: supportingIds,
        rca_analysis: rcaAnalysis,
        impact_analysis: impactAnalysis,
        root_cause: recommendation.root_cause,
        impact: recommendation.impact,
      };
    }
    return {
      recommended_action: recommendation.recommended_action,
      remediation_analysis: remediationAnalysis,
      preventive_action: recommendation.preventive_action,
      validation: recommendation.validation || report.recommended_next_checks || [],
      approval: safeWorkflow.approval || {},
    };
  };

  return (
    <section className="intelligence-connection">
      <header>
        <div>
          <span className="discovery-eyebrow">Connected data lineage</span>
          <h3>Discovery Evidence → Context Assembly → RCA & Impact</h3>
          <p>This is the handoff between the two agents. Only retrieved evidence and assembled context should support downstream conclusions.</p>
        </div>
        <div className="intelligence-header-actions">
          <span className={`workflow-pill ${evidence.length || contextItems.length ? "workflow-pill-active" : "workflow-pill-idle"}`}>
            {evidence.length || contextItems.length ? "connected" : "no context"}
          </span>
          <button type="button" className="button-primary" onClick={() => downloadInvestigationArtifact("kaiops-complete-investigation.json", investigationPackage)}>
            Download complete investigation
          </button>
        </div>
      </header>
      <div className="investigation-story">
        <div className="investigation-story-intro">
          <span>How KaiOps reached this conclusion</span>
          <strong>Every conclusion moves through an observable, evidence-backed handoff.</strong>
        </div>
        <div className="investigation-story-track">
          {storyStages.map((stage, index) => (
            <div className="investigation-story-segment" key={stage.id}>
              <article className={`investigation-story-card tone-${stage.tone}`}>
                <header>
                  <span className="investigation-story-number">{stage.number}</span>
                  <div>
                    <small>{stage.eyebrow}</small>
                    <h4>{stage.title}</h4>
                  </div>
                </header>
                <p>{stage.summary}</p>
                <div className="investigation-story-metric">
                  <strong>{stage.metric}</strong>
                  <span>{stage.metricLabel}</span>
                </div>
                <div className="investigation-story-tags">
                  {stage.tags.length
                    ? stage.tags.map((tag) => <span key={`${stage.id}-${tag}`}>{compactText(tag, 30)}</span>)
                    : <span>Awaiting persisted data</span>}
                </div>
                <button
                  type="button"
                  className="investigation-download-button"
                  onClick={() => downloadInvestigationArtifact(`kaiops-${stage.number}-${stage.id}.json`, stageArtifact(stage.id))}
                >
                  Download {stage.id === "discover" ? "evidence & logs" : stage.id === "context" ? "context & documents" : stage.id === "reason" ? "RCA & impact" : stage.id === "act" ? "action plan" : "search plan"}
                </button>
              </article>
              {index < storyStages.length - 1 ? (
                <div className="investigation-story-handoff" aria-hidden="true">
                  <i>→</i>
                  <small>{index === 0 ? "query" : index === 1 ? "evidence" : index === 2 ? "context" : "decision"}</small>
                </div>
              ) : null}
            </div>
          ))}
        </div>
      </div>
      <div className="intelligence-lineage-heading">
        <span className="discovery-eyebrow">Live lineage from this alert</span>
        <h4>Inspect exactly what entered each stage</h4>
        <p>Source facts are shown on the left, assembled operational context in the middle, and the derived conclusions on the right.</p>
      </div>
      <div className="intelligence-connection-flow">
        <article className="intelligence-column intelligence-discovery-column">
          <span className="intelligence-column-step">1</span>
          <h4>Issues and facts discovered</h4>
          <p className="subtitle">Raw facts with immutable evidence IDs and source provenance.</p>
          <div className="intelligence-source-list">
            {Object.entries(sourceCounts).map(([source, count]) => (
              <div key={`lineage-source-${source}`}><strong>{count}</strong><span>{source}</span></div>
            ))}
            {!Object.keys(sourceCounts).length ? <small>No MCP evidence stored for this alert.</small> : null}
          </div>
          {evidence.slice(0, 6).map((item, index) => (
            <div className="intelligence-fact" key={`lineage-evidence-${item.evidence_id || index}`}>
              <strong>{item.evidence_id || `FACT-${index + 1}`}</strong>
              <span>{item.source || "source"} · {compactText(item.snippet, 150)}</span>
              <button
                type="button"
                className="intelligence-inline-download"
                onClick={() => downloadInvestigationArtifact(`kaiops-${item.source || "evidence"}-${item.evidence_id || index + 1}.json`, item)}
              >
                Download {String(item.source || "evidence").toLowerCase()}
              </button>
            </div>
          ))}
        </article>
        <span className="intelligence-handoff" aria-hidden="true">→</span>
        <article className="intelligence-column intelligence-context-column">
          <span className="intelligence-column-step">2</span>
          <h4>Context Intelligence assembled</h4>
          <p className="subtitle">Operational context merged with Discovery evidence before reasoning.</p>
          {contextItems.map((item) => (
            <div className="intelligence-context-item" key={`context-item-${item.label}`}>
              <strong>{item.label}</strong>
              <span>{item.value}</span>
              <small>Retrieved from: {item.source}</small>
            </div>
          ))}
          {!contextItems.length ? <p className="subtitle">No structured context payload is attached to this alert.</p> : null}
        </article>
        <span className="intelligence-handoff" aria-hidden="true">→</span>
        <article className="intelligence-column intelligence-output-column">
          <span className="intelligence-column-step">3</span>
          <h4>Grounded intelligence produced</h4>
          <p className="subtitle">RCA, impact, and action generated from the context shown to the left.</p>
          {detectedErrors.length ? (
            <div className="intelligence-output-item">
              <strong>Detected application errors ({detectedErrors.length})</strong>
              {detectedErrors.map((error, index) => (
                <div className="intelligence-fact" key={`detected-error-${error?.evidence_id || index}`}>
                  <strong>{error?.service || error?.container || `Application error ${index + 1}`}</strong>
                  <span>{compactText(error?.message, 320)}</span>
                  <small>
                    {[error?.timestamp, ...(Array.isArray(error?.signals) ? error.signals : []), error?.evidence_id]
                      .filter(Boolean)
                      .join(" · ")}
                  </small>
                </div>
              ))}
              <button
                type="button"
                className="intelligence-inline-download"
                onClick={() => downloadInvestigationArtifact("kaiops-detected-application-errors.json", detectedErrors)}
              >
                Download detected errors
              </button>
            </div>
          ) : null}
          {outputs.map((item) => (
            <div className="intelligence-output-item" key={`output-${item.label}`}>
              <strong>{item.label}</strong>
              <span>{item.display.headline}</span>
              {item.label === "RCA" && canonicalAnalysis.externalKnowledgeUsed ? (
                <span className="workflow-pill workflow-pill-active" style={{ alignSelf: "flex-start" }}>
                  grounded via external knowledge fallback
                </span>
              ) : null}
              {item.display.details.length ? (
                <dl className="intelligence-output-details">
                  {item.display.details.map((detail) => (
                    <div key={`${item.label}-${detail.label}`}>
                      <dt>{detail.label}</dt>
                      <dd>{detail.value}</dd>
                    </div>
                  ))}
                </dl>
              ) : null}
              <button
                type="button"
                className="intelligence-inline-download"
                onClick={() => downloadInvestigationArtifact(`kaiops-${item.label}.json`, {
                  type: item.label,
                  value: item.value,
                  display: item.display,
                  citations: supportingIds,
                })}
              >
                Download {item.label}
              </button>
            </div>
          ))}
          <div className="intelligence-citations">
            <strong>Supporting evidence IDs</strong>
            <span>{supportingIds.join(", ") || "No explicit citations returned"}</span>
          </div>
          <div className="intelligence-document-downloads">
            <strong>{documents.length} linked document(s)</strong>
            {documents.length ? (
              <button
                type="button"
                className="button-primary"
                onClick={() => downloadInvestigationArtifact("kaiops-linked-document-package.json", {
                  documents,
                  ranked_matches: ragMatches,
                  assembled_context: context,
                })}
              >
                Download all documents + context
              </button>
            ) : null}
            {documents.slice(0, 6).map((doc, index) => (
              <button
                type="button"
                className="button-secondary"
                key={`intelligence-download-${doc?.path || doc?.document_id || doc?.title || index}`}
                disabled={!doc?.path && !doc?.content && !doc?.summary && !doc?.recommended_action}
                onClick={() => onDownloadDocument && onDownloadDocument(doc)}
              >
                Download {compactText(doc?.title || doc?.path || `Document ${index + 1}`, 34)}
              </button>
            ))}
            {!documents.length ? <small>No alert-linked document is available yet.</small> : null}
          </div>
        </article>
      </div>
    </section>
  );
}

function ContextRetrievalGraph({ workflow, timelineRows, documents, evaluation, documentContract, onLoadDocumentContent, onDownloadDocument, compact = false }) {
  const [documentPreviewState, setDocumentPreviewState] = useState({ key: "", loading: false, content: null, error: "" });
  const safeWorkflow = workflow && typeof workflow === "object" ? workflow : {};
  const safeTimelineRows = Array.isArray(timelineRows) ? timelineRows : [];
  const safeDocuments = Array.isArray(documents) ? documents : [];
  const recommendation = safeWorkflow.recommendation && typeof safeWorkflow.recommendation === "object" ? safeWorkflow.recommendation : {};
  const recommendationMetadata = recommendation.metadata && typeof recommendation.metadata === "object" ? recommendation.metadata : {};
  const context = safeWorkflow.context && typeof safeWorkflow.context === "object" ? safeWorkflow.context : {};
  const contextMetadata = context.metadata && typeof context.metadata === "object" ? context.metadata : {};
  const contextTraceRow = safeTimelineRows
    .slice()
    .reverse()
    .find((row) => {
      const text = `${row?.stage || ""} ${row?.service || ""} ${row?.agent || ""} ${row?.outputValueText || ""}`.toLowerCase();
      return text.includes("context") || text.includes("rag") || text.includes("semantic") || text.includes("vector");
    });
  const parseMaybeJson = (value) => {
    const text = String(value || "").trim();
    if (!text) {
      return null;
    }
    try {
      const parsed = JSON.parse(text);
      return parsed && typeof parsed === "object" ? parsed : null;
    } catch (_error) {
      return null;
    }
  };
  const contextTraceOutput = parseMaybeJson(contextTraceRow?.outputValueText) || {};
  const traceMetadata = contextTraceOutput.metadata && typeof contextTraceOutput.metadata === "object" ? contextTraceOutput.metadata : {};
  const discoveryEvidence =
    (contextMetadata.discovery_evidence && typeof contextMetadata.discovery_evidence === "object" && contextMetadata.discovery_evidence)
    || (recommendationMetadata.discovery_evidence && typeof recommendationMetadata.discovery_evidence === "object" && recommendationMetadata.discovery_evidence)
    || (traceMetadata.discovery_evidence && typeof traceMetadata.discovery_evidence === "object" && traceMetadata.discovery_evidence)
    || {};
  const discoveryMcp =
    (contextMetadata.discovery_report && typeof contextMetadata.discovery_report === "object" && contextMetadata.discovery_report)
    || (recommendationMetadata.discovery_report && typeof recommendationMetadata.discovery_report === "object" && recommendationMetadata.discovery_report)
    || (traceMetadata.discovery_report && typeof traceMetadata.discovery_report === "object" && traceMetadata.discovery_report)
    || {};
  const discoveryReport = discoveryMcp.report && typeof discoveryMcp.report === "object" ? discoveryMcp.report : {};
  const mcpEvidence = Array.isArray(discoveryMcp.evidence) ? discoveryMcp.evidence : [];
  const retrievalStages = Array.isArray(discoveryMcp.retrieval_stages) ? discoveryMcp.retrieval_stages : [];
  const hypotheses = Array.isArray(discoveryReport.hypotheses) ? discoveryReport.hypotheses : [];
  const codeMatches = Array.isArray(discoveryEvidence.code_matches) ? discoveryEvidence.code_matches : [];
  const logMatches = Array.isArray(discoveryEvidence.log_matches) ? discoveryEvidence.log_matches : [];
  const ragMatches =
    (Array.isArray(contextMetadata.rag_matches) && contextMetadata.rag_matches)
    || (Array.isArray(recommendationMetadata.rag_matches) && recommendationMetadata.rag_matches)
    || (Array.isArray(traceMetadata.rag_matches) && traceMetadata.rag_matches)
    || [];
  const ragIndex =
    (contextMetadata.rag_index && typeof contextMetadata.rag_index === "object" && contextMetadata.rag_index)
    || (recommendationMetadata.rag_index && typeof recommendationMetadata.rag_index === "object" && recommendationMetadata.rag_index)
    || (traceMetadata.rag_index && typeof traceMetadata.rag_index === "object" && traceMetadata.rag_index)
    || {};
  const firstDoc = safeDocuments[0] || {};
  const embeddingModel =
    (ragIndex.embedding_model && typeof ragIndex.embedding_model === "object" && ragIndex.embedding_model)
    || (firstDoc.embedding_model && typeof firstDoc.embedding_model === "object" && firstDoc.embedding_model)
    || {};
  const vectorStore =
    (ragIndex.vector_store && typeof ragIndex.vector_store === "object" && ragIndex.vector_store)
    || (firstDoc.vector_store && typeof firstDoc.vector_store === "object" && firstDoc.vector_store)
    || {};
  const alert = safeWorkflow.alert && typeof safeWorkflow.alert === "object" ? safeWorkflow.alert : {};
  const queryText = compactText(
    [
      alert.service || safeWorkflow.service,
      alert.name || safeWorkflow.alert_name,
      alert.description || safeWorkflow.description,
      recommendation.title,
    ].filter(Boolean).join(" "),
    180
  ) || "Selected alert service, name, severity, and description";
  const topSimilarity = Number(
    contextMetadata.rag_top_match_confidence
    ?? recommendationMetadata.rag_top_match_confidence
    ?? traceMetadata.rag_top_match_confidence
    ?? contextMetadata.rag_top_similarity
    ?? recommendationMetadata.rag_top_similarity
    ?? traceMetadata.rag_top_similarity
    ?? 0
  );
  const topSemanticScore = Number(
    contextMetadata.rag_top_semantic_score
    ?? recommendationMetadata.rag_top_semantic_score
    ?? traceMetadata.rag_top_semantic_score
    ?? 0
  );
  const topMetadataScore = Number(
    contextMetadata.rag_top_metadata_match_score
    ?? recommendationMetadata.rag_top_metadata_match_score
    ?? traceMetadata.rag_top_metadata_match_score
    ?? 0
  );
  const linkedSummary = documentContract?.document_link_summary && typeof documentContract.document_link_summary === "object"
    ? documentContract.document_link_summary
    : {};
  const reportedDocCount = Number(ragIndex.document_count ?? ragIndex.total_documents ?? linkedSummary.count ?? safeDocuments.length ?? ragMatches.length ?? 0);
  const docCount = Number.isFinite(reportedDocCount) && reportedDocCount > 0 ? reportedDocCount : 0;
  const reportedIndexedCount = Number(ragIndex.embedded_document_count ?? ragIndex.metadata_embedding_count ?? 0);
  const indexedCount = Number.isFinite(reportedIndexedCount) && reportedIndexedCount > 0 ? reportedIndexedCount : 0;
  const touchedDocuments = (safeDocuments.length ? safeDocuments : ragMatches).slice(0, 8);
  const bestMatch = touchedDocuments[0] || {};
  const hasIndexInfo = hasMeaningfulValue(ragIndex) || hasMeaningfulValue(embeddingModel) || hasMeaningfulValue(vectorStore);
  const embeddingProvider = embeddingModel.provider || (hasIndexInfo ? "configured by backend" : "not reported");
  const embeddingName = embeddingModel.model || (hasIndexInfo ? "not reported" : "not reported");
  const vectorProvider = vectorStore.provider || (hasIndexInfo ? "configured by backend" : "not reported");
  const contextQuality = evaluation && typeof evaluation === "object" ? evaluation : {};
  const flowSteps = [
    {
      id: "receive",
      label: "Query Received",
      meta: "Context agent consumes orchestration-events",
      detail: queryText,
      status: safeWorkflow.incident || alert.name ? "observed" : "inferred",
    },
    {
      id: "normalize",
      label: "Signal Normalized",
      meta: "service + severity + labels + incident id",
      detail: compactText(`${alert.service || "-"} | ${alert.severity || recommendation.severity || "-"} | ${safeWorkflow?.incident?.id || safeWorkflow.incident_id || "-"}`, 160),
      status: alert.service || safeWorkflow.incident_id ? "observed" : "inferred",
    },
    {
      id: "index",
      label: "Index Checked",
      meta: `${docCount || touchedDocuments.length || 0} document(s), ${indexedCount || "metadata"} indexed`,
      detail: `Embedding: ${embeddingName} | Store: ${vectorProvider}`,
      status: docCount || touchedDocuments.length || hasIndexInfo ? "observed" : "warning",
    },
    {
      id: "search",
      label: "Search Ranked",
      meta: `${ragMatches.length || touchedDocuments.length || 0} match(es)`,
      detail: `Confidence ${Number.isFinite(topSimilarity) && topSimilarity > 0 ? `${Math.round(topSimilarity * 100)}%` : "not reported"} | semantic ${Number.isFinite(topSemanticScore) && topSemanticScore > 0 ? `${Math.round(topSemanticScore * 100)}%` : "-"} | metadata ${Number.isFinite(topMetadataScore) && topMetadataScore > 0 ? `${Math.round(topMetadataScore * 100)}%` : "-"}`,
      status: ragMatches.length || touchedDocuments.length ? "observed" : "warning",
    },
    {
      id: "touch",
      label: "Documents Touched",
      meta: bestMatch.title || bestMatch.path || "no linked document title",
      detail: compactText(bestMatch.match_reason || bestMatch.summary || bestMatch.content || bestMatch.path || "Linked alert documents are used as context evidence.", 180),
      status: touchedDocuments.length ? "observed" : "warning",
    },
    {
      id: "assemble",
      label: "Context Prepared",
      meta: "context-events published",
      detail: `Grounding ${Math.round((contextQuality.groundingScore || 0) * 100)}% | Confidence ${Math.round((contextQuality.confidenceScore || recommendation.confidence || 0) * 100)}%`,
      status: contextTraceRow || safeWorkflow.context || recommendation ? "observed" : "inferred",
    },
  ];
  const documentKey = (doc, index = 0) => String(doc?.path || doc?.document_id || doc?.title || `doc-${index}`).trim();
  const documentMetadata = (doc) => ({
    document_id: doc?.document_id || doc?.id || "-",
    title: doc?.title || "-",
    kind: doc?.kind || doc?.document_kind || "-",
    path: doc?.path || "-",
    services: doc?.services || doc?.service || "-",
    owner: doc?.owner || "-",
    version: doc?.version || "-",
    freshness_score: doc?.freshness_score ?? "-",
    embedding_status: doc?.embedding_status || "-",
    vector_store: doc?._vector_store || doc?.vector_store?.provider || "-",
    match_reason: doc?.match_reason || "-",
    match_confidence: doc?.match_confidence ?? doc?._similarity ?? doc?.score ?? "-",
    semantic_score: doc?.semantic_score ?? doc?._semantic_score ?? "-",
    metadata_match_score: doc?.metadata_match_score ?? doc?._metadata_match_score ?? "-",
    source_ref: doc?.source_ref || "-",
  });
  const documentContextExcerpt = (doc) => compactText(
    doc?.context_excerpt
    || doc?.matched_text
    || doc?.snippet
    || doc?.match_reason
    || doc?.summary
    || doc?.recommended_action
    || doc?.content
    || doc?.path,
    320
  ) || "No context excerpt was reported for this document.";
  const viewDocument = async (doc, index) => {
    const key = documentKey(doc, index);
    if (!key) {
      return;
    }
    if (documentPreviewState.key === key && documentPreviewState.content && !documentPreviewState.error) {
      setDocumentPreviewState({ key: "", loading: false, content: null, error: "" });
      return;
    }
    setDocumentPreviewState({ key, loading: true, content: null, error: "" });
    try {
      const loaded = typeof onLoadDocumentContent === "function"
        ? await onLoadDocumentContent(doc)
        : doc;
      setDocumentPreviewState({
        key,
        loading: false,
        content: loaded && typeof loaded === "object" ? loaded : doc,
        error: "",
      });
    } catch (error) {
      setDocumentPreviewState({
        key,
        loading: false,
        content: doc,
        error: String(error?.message || "Unable to load document content."),
      });
    }
  };
  const renderDocumentPreview = (doc, index) => {
    const key = documentKey(doc, index);
    if (documentPreviewState.key !== key) {
      return null;
    }
    const full = documentPreviewState.content && typeof documentPreviewState.content === "object"
      ? documentPreviewState.content
      : doc;
    const metadata = documentMetadata({ ...doc, ...full });
    const body = String(
      full?.content
      || full?.text
      || full?.summary
      || full?.recommended_action
      || doc?.content
      || doc?.summary
      || ""
    ).trim();
    return (
      <div className="context-doc-preview">
        {documentPreviewState.loading ? <p className="subtitle">Loading document content...</p> : null}
        {documentPreviewState.error ? <p className="error">{documentPreviewState.error}</p> : null}
        <details open>
          <summary>Document Metadata</summary>
          <pre className="result">{JSON.stringify(metadata, null, 2)}</pre>
        </details>
        <details open>
          <summary>Document View</summary>
          <pre className="result">{body || "No document body was returned. Metadata is shown above."}</pre>
        </details>
      </div>
    );
  };
  const indexRows = [
    ["Embedding Provider", embeddingProvider],
    ["Embedding Model", embeddingName],
    ["Fallback Model", embeddingModel.fallback_model || "-"],
    ["Fallback Active", embeddingModel.fallback_active ? "yes" : "no"],
    ["Vector Store", vectorProvider],
    ["Enterprise Index", ragIndex.enterprise_index_enabled ? "enabled" : "not enabled"],
    ["Vector Index", (vectorStore.index || vectorStore.index_name || vectorStore.configured) ? String(vectorStore.index || vectorStore.index_name || "configured") : "-"],
    ["Documents Seen", String(docCount || touchedDocuments.length || "-")],
  ];

  return (
    <div className={`context-flow-panel ${compact ? "is-compact" : ""}`}>
      <div className="context-flow-header">
        <div>
          <h3>Context Retrieval Flow</h3>
          <p>Query intake, document indexing, semantic search, document touchpoints, and context assembly for the selected alert.</p>
        </div>
        <div className="context-flow-scoreboard">
          <span><strong>{ragMatches.length || safeDocuments.length}</strong> matches</span>
          <span><strong>{Number.isFinite(topSimilarity) && topSimilarity > 0 ? `${Math.round(topSimilarity * 100)}%` : "-"}</strong> confidence</span>
          <span><strong>{Math.round((contextQuality.groundingScore || 0) * 100) || "-"}</strong> grounding</span>
        </div>
      </div>
      <div className="context-flow-track">
        {flowSteps.map((step, index) => (
          <div className="context-flow-segment" key={step.id}>
            <article className={`context-flow-node status-${step.status}`}>
              <span className="context-flow-step">{index + 1}</span>
              <strong>{step.label}</strong>
              <small>{step.meta}</small>
              <p>{step.detail}</p>
            </article>
            {index < flowSteps.length - 1 ? <span className="context-flow-arrow" aria-hidden="true">-&gt;</span> : null}
          </div>
        ))}
      </div>
      <div className="context-flow-grid">
        <article className="context-flow-detail">
          <div className="panel-head">
            <h4>MCP Discovery And LLM Analysis</h4>
            <p>Read-only log, ticket, and code tools followed by evidence-grounded model reasoning.</p>
          </div>
          <div className="context-flow-scoreboard">
            <span><strong>{mcpEvidence.length}</strong> cited evidence</span>
            <span><strong>{retrievalStages.length}</strong> stages</span>
            <span><strong>{hypotheses.length}</strong> hypotheses</span>
          </div>
          {retrievalStages.length ? (
            <div className="context-doc-list">
              {retrievalStages.map((stage, index) => (
                <div className="context-doc-row" key={`mcp-stage-${index}-${stage.stage || ""}`}>
                  <strong>{String(stage.stage || "stage").replaceAll("_", " ")}</strong>
                  <span>{stage.status || "unknown"}{Number.isFinite(Number(stage.result_count)) ? ` · ${stage.result_count} result(s)` : ""}</span>
                  {stage.error ? <small>{stage.error}</small> : null}
                </div>
              ))}
            </div>
          ) : <p className="subtitle">No MCP retrieval trace was returned for this alert.</p>}
          {discoveryReport.summary ? <p>{discoveryReport.summary}</p> : null}
          {hypotheses.map((hypothesis, index) => (
            <div className="context-doc-row" key={`mcp-hypothesis-${index}`}>
              <strong>{hypothesis.cause || `Hypothesis ${index + 1}`}</strong>
              <span>Confidence {Math.round(Number(hypothesis.confidence || 0) * 100)}%</span>
              <small>Citations: {(hypothesis.supporting_evidence || []).join(", ") || "none"}</small>
            </div>
          ))}
          {mcpEvidence.length ? (
            <details>
              <summary>Retrieved Evidence And Provenance</summary>
              <pre className="result">{JSON.stringify(mcpEvidence, null, 2)}</pre>
            </details>
          ) : null}
        </article>
        <article className="context-flow-detail">
          <div className="panel-head">
            <h4>Discovery Agent: Code And Log Evidence</h4>
            <p>Read-only evidence retrieved using service, alert, scenario, ticket, and component terms.</p>
          </div>
          <div className="context-flow-scoreboard">
            <span><strong>{codeMatches.length}</strong> code matches</span>
            <span><strong>{logMatches.length}</strong> log matches</span>
            <span><strong>{Array.isArray(discoveryEvidence.query_terms) ? discoveryEvidence.query_terms.length : 0}</strong> query terms</span>
          </div>
          {codeMatches.length || logMatches.length ? (
            <div className="context-doc-list">
              {[...logMatches, ...codeMatches].slice(0, 20).map((match, index) => (
                <div className="context-doc-row" key={`discovery-evidence-${index}-${match.path || ""}-${match.line || ""}`}>
                  <strong>{String(match.kind || "evidence").toUpperCase()} · {match.path || "unknown path"}{match.line ? `:${match.line}` : ""}</strong>
                  <span>Matched: {Array.isArray(match.matched_terms) ? match.matched_terms.join(", ") : "-"}</span>
                  <pre className="result">{match.snippet || "No snippet returned."}</pre>
                </div>
              ))}
            </div>
          ) : (
            <p className="subtitle">
              No code/log evidence was returned for this run. Configure CODE_DISCOVERY_ROOTS and LOG_DISCOVERY_ROOTS,
              rebuild the context-agent, and process a new alert to populate this panel.
            </p>
          )}
          <details>
            <summary>Discovery Query And Roots</summary>
            <pre className="result">{JSON.stringify({
              query_terms: discoveryEvidence.query_terms || [],
              code_roots: discoveryEvidence.code_roots || [],
              log_roots: discoveryEvidence.log_roots || [],
            }, null, 2)}</pre>
          </details>
        </article>
        <article className="context-flow-detail">
          <div className="panel-head">
            <h4>Documents And Metadata Touched</h4>
            <p>{safeDocuments.length ? "Backend linked documents for this alert." : ragMatches.length ? "RAG match metadata is shown because no backend linked-document rows were returned." : "No document match metadata was returned for this alert."}</p>
          </div>
          {touchedDocuments.length ? (
            <div className="context-doc-list">
              {touchedDocuments.map((doc, index) => (
                <div className="context-doc-row" key={`${doc.document_id || doc.path || doc.title || index}`}>
                  <strong>{doc.title || doc.path || `Document ${index + 1}`}</strong>
                  <span>{doc.kind || doc.document_kind || "document"} | confidence {Math.round(Number(doc.match_confidence || doc._similarity || doc.score || 0) * 100) || "-"}%</span>
                  <small>semantic {Math.round(Number(doc.semantic_score || doc._semantic_score || 0) * 100) || "-"}% | metadata {Math.round(Number(doc.metadata_match_score || doc._metadata_match_score || 0) * 100) || "-"}%</small>
                  <div className="context-doc-highlight">
                    <strong>Context collected from this document</strong>
                    <p>{documentContextExcerpt(doc)}</p>
                  </div>
                  <details>
                    <summary>Metadata</summary>
                    <pre className="result">{JSON.stringify(documentMetadata(doc), null, 2)}</pre>
                  </details>
                  <div className="context-doc-actions">
                    <button type="button" className="button-secondary" onClick={() => viewDocument(doc, index)}>
                      {documentPreviewState.key === documentKey(doc, index) ? "Hide" : "View"} Document
                    </button>
                    <button
                      type="button"
                      className="button-secondary"
                      disabled={!doc.path && !doc.content && !doc.summary && !doc.recommended_action}
                      title="Download this document and its collected context"
                      onClick={() => onDownloadDocument && onDownloadDocument(doc)}
                    >
                      Download
                    </button>
                  </div>
                  {renderDocumentPreview(doc, index)}
                </div>
              ))}
            </div>
          ) : (
            <p className="subtitle">No linked documents are reported for this alert yet.</p>
          )}
        </article>
        <article className="context-flow-detail">
          <h4>Index And Embedding</h4>
          <div className="table-wrap table-wrap-scroll-x">
            <table>
              <tbody>
                {indexRows.map(([label, value]) => (
                  <tr key={`context-index-${label}`}><th>{label}</th><td>{value}</td></tr>
                ))}
              </tbody>
            </table>
          </div>
          {!hasIndexInfo ? (
            <p className="subtitle">The selected payload did not include full RAG index metadata. The context agent may still have used fallback matching or historical metadata.</p>
          ) : null}
        </article>
      </div>
    </div>
  );
}

function AgentEventsGraph({ rows }) {
  const eventRows = Array.isArray(rows) ? rows : [];
  if (!eventRows.length) {
    return <p className="subtitle">No events found for selected alert.</p>;
  }

  const flowNodes = [
    { id: "alert-intelligence", label: "Alert Intelligence Agent", short: "A1" },
    { id: "orchestrator", label: "Master Agent", short: "M" },
    { id: "discovery-agent", label: "Discovery Agent", short: "D" },
    { id: "context-agent", label: "Context Intelligence Agent", short: "C" },
    { id: "resolution-agent", label: "Resolution Intelligence Agent", short: "R" },
    { id: "approval-service", label: "Human Approval Layer", short: "H" },
    { id: "remediation-engine", label: "Remediation Automation Engine", short: "X" },
    { id: "closure-service", label: "Validator Agent", short: "V" },
  ];

  const detectAgentId = (row) => {
    const haystack = [
      row?.agent,
      row?.action,
      row?.eventType,
      row?.detail,
      row?.backgroundDetailText,
      row?.inputValueText,
      row?.outputValueText,
    ]
      .map((item) => String(item || "").toLowerCase())
      .join(" | ");
    if (
      haystack.includes("alert intelligence")
      || haystack.includes("alert-intelligence")
      || haystack.includes("incident.alert")
      || haystack.includes("raw-alert")
      || haystack.includes("enriched-alert")
    ) {
      return "alert-intelligence";
    }
    if (haystack.includes("master agent") || haystack.includes("orchestrator")) {
      return "orchestrator";
    }
    if (haystack.includes("discovery agent") || haystack.includes("local-evidence") || haystack.includes("code_matches") || haystack.includes("log_matches")) {
      return "discovery-agent";
    }
    if (haystack.includes("context intelligence") || haystack.includes("context-agent")) {
      return "context-agent";
    }
    if (haystack.includes("resolution intelligence") || haystack.includes("resolution-agent") || haystack.includes("recommendation")) {
      return "resolution-agent";
    }
    if (haystack.includes("approval") || haystack.includes("human approval")) {
      return "approval-service";
    }
    if (haystack.includes("remediation")) {
      return "remediation-engine";
    }
    if (haystack.includes("validator") || haystack.includes("closure")) {
      return "closure-service";
    }
    return "";
  };

  const groupedRows = new Map(flowNodes.map((node) => [node.id, []]));
  eventRows.forEach((row) => {
    const id = detectAgentId(row);
    if (!id || !groupedRows.has(id)) {
      return;
    }
    groupedRows.get(id).push(row);
  });

  // Some runs persist sparse early-stage metadata; synthesize one Alert Intelligence row for visibility.
  if (!(groupedRows.get("alert-intelligence") || []).length && eventRows.length) {
    const seed = eventRows
      .slice()
      .sort((a, b) => toFiniteNumber(a?.sequence) - toFiniteNumber(b?.sequence))[0];
    groupedRows.set("alert-intelligence", [
      {
        ...seed,
        action: "Alert landed, deduped, and enriched for orchestration.",
        decision: seed?.decision || "severity + correlation applied",
        output: seed?.output || "enriched-alert emitted",
        communicates_to: seed?.communicates_to || "orchestration-events",
      },
    ]);
  }

  const visibleFlowNodes = flowNodes.filter((node) => (groupedRows.get(node.id) || []).length > 0);
  if (!visibleFlowNodes.length) {
    return <p className="subtitle">No mapped agent events found for this alert yet.</p>;
  }

  return (
    <div className="agent-dag-flow">
      <div className="agent-dag-track">
        {visibleFlowNodes.map((node, index) => {
          const rowsForNode = (groupedRows.get(node.id) || [])
            .slice()
            .sort((a, b) => toFiniteNumber(a?.sequence) - toFiniteNumber(b?.sequence));
          const latest = rowsForNode[rowsForNode.length - 1] || null;
          const hasError = hasMeaningfulValue(latest?.errorValueText);
          const statusLabel = hasError ? "error" : "observed";

          return (
            <div key={`agent-dag-${node.id}`} className="agent-dag-segment">
              <article className={`agent-dag-node status-${statusLabel}`}>
                <div className="agent-dag-head">
                  <span className="agent-dag-badge">{node.short}</span>
                  <strong>{node.label}</strong>
                  <span className={`agent-dag-status status-${statusLabel}`}>{statusLabel}</span>
                </div>
                <p>{latest?.action || "No agent event captured yet."}</p>
                <div className="agent-event-kv">
                  <span>Decision: {compactText(latest?.decision, 140) || "-"}</span>
                  <span>Output: {compactText(latest?.output, 140) || "-"}</span>
                  <span>Next: {latest?.communicates_to || "-"}</span>
                  <span>Events: {rowsForNode.length}</span>
                </div>
                {latest?.backgroundDetailText ? (
                  <details>
                    <summary>Background Details</summary>
                    <pre className="result">{latest.backgroundDetailText}</pre>
                  </details>
                ) : null}
                {rowsForNode.length ? (
                  <details>
                    <summary>Agent Event Timeline ({rowsForNode.length})</summary>
                    <div className="agent-event-rows">
                      {rowsForNode.map((row, rowIndex) => (
                        <div key={`agent-node-${node.id}-row-${rowIndex}`} className="agent-event-row timeline">
                          <strong>{row.sequence || rowIndex + 1}.</strong>
                          <span>{compactText(row.action, 120) || "-"}</span>
                          <span>{compactText(row.decision, 120) || "-"}</span>
                          <span>{formatUtcTimestamp(row.timestamp)}</span>
                          <span>{row.eventType || "-"}</span>
                        </div>
                      ))}
                    </div>
                  </details>
                ) : null}
              </article>
              {index < flowNodes.length - 1 ? <div className="agent-dag-arrow" aria-hidden="true">→</div> : null}
            </div>
          );
        })}
      </div>
    </div>
  );
}

function TopicFlowGraph({ routing, timelineRows }) {
  const safeRouting = routing && typeof routing === "object" ? routing : {};
  const safeRows = Array.isArray(timelineRows) ? timelineRows : [];
  const published = Array.from(new Set(
    safeRows
      .map((row) => String(row?.publishes || "").trim())
      .filter((item) => item && item !== "-" && item.toLowerCase() !== "unknown")
  ));
  const consumed = Array.from(new Set(
    safeRows
      .map((row) => String(row?.consumes || "").trim())
      .filter((item) => item && item !== "-" && item.toLowerCase() !== "unknown")
  ));
  const provider = String(safeRouting?.message_bus_provider || "rabbitmq").trim().toUpperCase();
  const actualRows = SERVICE_TOPIC_FLOW.map((row) => {
    const hasTopicActivity = published.includes(row.publishes) || consumed.includes(row.consumes);
    return {
      service: row.service,
      consumed: hasTopicActivity ? row.consumes : "-",
      published: hasTopicActivity ? row.publishes : "-",
      provider,
      status: hasTopicActivity ? "Observed" : "Configured",
    };
  });
  const configuredRows = SERVICE_TOPIC_FLOW.map((row) => ({
    service: row.service,
    consumes: row.consumes === "-" ? "-" : `${row.consumes} (enabled transports)`,
    publishes: row.publishes,
  }));

  return (
    <MessageBusTopology
      actual={{ rows: actualRows, published, consumed }}
      configuredRows={configuredRows}
      routing={safeRouting}
      primaryTopic={published[0] || "raw-alerts"}
      compact
    />
  );
}

function classifySelectedAlertPath(workflow, timelineRows, selectedAlert) {
  const safeWorkflow = workflow && typeof workflow === "object" ? workflow : {};
  const safeRows = Array.isArray(timelineRows) ? timelineRows : [];
  const safeAlert = selectedAlert && typeof selectedAlert === "object" ? selectedAlert : {};
  const recommendation = safeWorkflow?.recommendation && typeof safeWorkflow.recommendation === "object" ? safeWorkflow.recommendation : {};
  const recommendationMetadata = recommendation?.metadata && typeof recommendation.metadata === "object" ? recommendation.metadata : {};
  const decision =
    (safeWorkflow?.decision && typeof safeWorkflow.decision === "object" && safeWorkflow.decision)
    || (safeWorkflow?.orchestration_decision && typeof safeWorkflow.orchestration_decision === "object" && safeWorkflow.orchestration_decision)
    || (recommendationMetadata?.orchestration_decision && typeof recommendationMetadata.orchestration_decision === "object" && recommendationMetadata.orchestration_decision)
    || {};
  const approval = safeWorkflow?.approval && typeof safeWorkflow.approval === "object" ? safeWorkflow.approval : {};
  const remediation = safeWorkflow?.remediation_action && typeof safeWorkflow.remediation_action === "object" ? safeWorkflow.remediation_action : {};
  const closure = safeWorkflow?.closure_report && typeof safeWorkflow.closure_report === "object" ? safeWorkflow.closure_report : {};
  const rowText = safeRows
    .map((row) => `${row?.stage || ""} ${row?.agent || ""} ${row?.service || ""} ${row?.consumes || ""} ${row?.publishes || ""} ${row?.detail || ""} ${row?.inputValueText || ""} ${row?.outputValueText || ""}`)
    .join(" ")
    .toLowerCase();
  const incidentStatus = String(safeWorkflow?.incident?.status || safeAlert.status || safeAlert.state || "").trim().toLowerCase();
  const explicitApproval = safeWorkflow?.approval?.required ?? decision?.requires_approval ?? recommendation?.requires_approval;
  const approvalRequired = explicitApproval === true || ["awaiting_approval", "pending_approval"].some((token) => incidentStatus.includes(token));
  const hasApproval = approvalRequired || hasMeaningfulValue(approval.status || approval.id || approval.approval_id) || rowText.includes("approval");
  const hasRemediation = hasMeaningfulValue(remediation.status || remediation.id || remediation.action_type) || rowText.includes("remediation");
  const hasClosure = Boolean(closure.health_restored || closure.closed_at) || ["closed", "resolved", "complete", "completed", "validated"].some((token) => incidentStatus.includes(token)) || rowText.includes("closure-events") || rowText.includes("closure service");
  const hasResolution = hasMeaningfulValue(recommendation.id || recommendation.root_cause || recommendation.recommended_action) || rowText.includes("resolution") || rowText.includes("model router");
  const hasContext = hasMeaningfulValue(safeWorkflow?.context) || rowText.includes("context") || rowText.includes("rag");
  const hasOrchestration = hasContext || hasResolution || hasApproval || hasRemediation || hasClosure || rowText.includes("orchestrator") || rowText.includes("orchestration");
  const hasAlertIntelligence = hasOrchestration || rowText.includes("alert intelligence") || rowText.includes("enriched-alerts");
  const label = hasClosure
    ? "Closed path"
    : hasRemediation
      ? "Remediation path"
      : hasApproval
        ? "Approval path"
        : hasResolution
          ? "Resolution path"
          : hasContext
            ? "Context path"
            : hasAlertIntelligence
              ? "Intelligence path"
              : "Intake path";
  return {
    label,
    approvalRequired,
    hasAlertIntelligence,
    hasOrchestration,
    hasContext,
    hasResolution,
    hasApproval,
    hasRemediation,
    hasClosure,
  };
}

function parseTimelineJson(value) {
  const text = String(value || "").trim();
  if (!text) {
    return null;
  }
  try {
    const parsed = JSON.parse(text);
    return parsed && typeof parsed === "object" ? parsed : null;
  } catch (_error) {
    return null;
  }
}

function classifyFlowStageFromRow(row) {
  const stage = String(row?.stage || "").toLowerCase();
  if (stage.includes("landing pad") || stage.includes("alert received") || stage.includes("alert landed")) {
    return { kind: "ingestion", short: "ING", label: "Landing Pad" };
  }
  if (stage.includes("topic handoff") || stage.includes("message bus")) {
    return { kind: "bus", short: "BUS", label: "Message Bus" };
  }
  if (stage.includes("dedup") || stage.includes("correlation") || stage.includes("enrich")) {
    return { kind: "dedupe", short: "DED", label: "Dedup" };
  }
  if (stage.includes("config") || stage.includes("connector lookup")) {
    return { kind: "config", short: "CFG", label: "Config" };
  }
  if (stage.includes("routing") || stage.includes("orchestrator") || stage.includes("workflow")) {
    return { kind: "orchestration", short: "ORC", label: "Orchestrator" };
  }
  if (stage.includes("discovery agent") || stage.includes("code and log context")) {
    return { kind: "discovery", short: "DSC", label: "Discovery" };
  }
  if (stage.includes("rag context") || stage.includes("context retrieval") || stage.includes("context intelligence")) {
    return { kind: "rag", short: "RAG", label: "RAG" };
  }
  if (stage.includes("embedding") || stage.includes("semantic") || stage.includes("vector")) {
    return { kind: "semantic", short: "SEM", label: "Semantic" };
  }
  if (stage.includes("context merge") || stage.includes("evidence assembly")) {
    return { kind: "context", short: "CTX", label: "Context" };
  }
  if (stage.includes("resolution") || stage.includes("recommendation")) {
    return { kind: "resolution", short: "RCA", label: "Resolution" };
  }
  if (stage.includes("approval")) {
    return { kind: "approval", short: "APR", label: "Approval" };
  }
  if (stage.includes("policy")) {
    return { kind: "policy", short: "POL", label: "Policy" };
  }
  if (stage.includes("remediation") || stage.includes("command") || stage.includes("execute")) {
    return { kind: "execution", short: "CMD", label: "Execution" };
  }
  if (stage.includes("closure") || stage.includes("validation")) {
    return { kind: "closure", short: "CLS", label: "Closure" };
  }
  return { kind: "generic", short: "EVT", label: "Event" };
}

function timelineRowText(row) {
  return [
    row?.status,
    row?.stage,
    row?.detail,
    row?.agent,
    row?.service,
    row?.consumes,
    row?.publishes,
    row?.errorValueText,
    row?.inputValueText,
    row?.outputValueText,
  ].map((item) => String(item || "").toLowerCase()).join(" ");
}

function timelineRowIndicatesFallback(text) {
  return [
    "fallback",
    "heuristic-fallback",
    "skipped",
    "not executed",
    "no live executor",
    "no real",
    "policy-blocked",
    "safety gate",
    "live mutation blocked",
    "requires_human_review",
  ].some((token) => text.includes(token));
}

function timelineRowIndicatesSuccess(text) {
  return [
    "succeeded",
    "success",
    "completed",
    "closed",
    "observed",
    "validated",
    "recommendation_id",
    "approval_id",
  ].some((token) => text.includes(token));
}

function timelineRowHasError(row) {
  if (!hasMeaningfulValue(row?.errorValueText)) {
    return false;
  }
  const text = timelineRowText(row);
  if (timelineRowIndicatesFallback(text) || timelineRowIndicatesSuccess(text)) {
    return false;
  }
  return text.includes("error") || text.includes("failed") || text.includes("exception") || text.includes("timeout");
}

function timelineRowStatus(row, nextRow = null) {
  const text = timelineRowText(row);
  if (timelineRowIndicatesFallback(text)) {
    return "fallback";
  }
  if (timelineRowHasError(row)) {
    return "failed";
  }
  if (timelineRowIndicatesSuccess(text) || hasMeaningfulValue(row)) {
    return "observed";
  }
  if (nextRow) {
    return "continued";
  }
  return "waiting";
}

function inferTimelineNextStep(row, nextRow = null) {
  const outputText = String(row?.outputValueText || "").trim();
  const inputText = String(row?.inputValueText || "").trim();
  const detailText = String(row?.detail || "").trim();
  const transport = String(row?.publishes || "").trim();
  const parsedOutput = parseTimelineJson(outputText) || {};
  const parsedInput = parseTimelineJson(inputText) || {};
  const explicit = [
    parsedOutput?.next_action,
    parsedOutput?.fallback_path,
    parsedInput?.next_action,
    parsedInput?.fallback_path,
    row?.communicates_to,
  ].find((value) => hasMeaningfulValue(value));
  if (explicit) {
    return String(explicit).trim();
  }
  if (nextRow?.stage) {
    return `${transport || "next"} -> ${nextRow.stage}`;
  }
  if (transport && transport !== "-") {
    return transport;
  }
  if (timelineRowIndicatesFallback(`${outputText} ${detailText}`.toLowerCase())) {
    return "Guarded path preserved for operator review";
  }
  return "-";
}

function buildDynamicFlowSections(rows) {
  const safeRows = Array.isArray(rows) ? rows.filter(Boolean) : [];
  const sections = [];
  safeRows.forEach((row, index) => {
    const meta = classifyFlowStageFromRow(row);
    const current = sections[sections.length - 1];
    if (!current || current.kind !== meta.kind) {
      sections.push({
        key: `${meta.kind}-${sections.length}`,
        kind: meta.kind,
        label: meta.label,
        short: meta.short,
        rows: [row],
        startIndex: index,
      });
      return;
    }
    current.rows.push(row);
  });
  return sections.map((section) => {
    const lastRow = section.rows[section.rows.length - 1] || null;
    const nextRow = safeRows[section.startIndex + section.rows.length] || null;
    const status = section.rows.some((row) => timelineRowHasError(row))
      ? "failed"
      : section.rows.some((row) => timelineRowStatus(row) === "fallback")
        ? "fallback"
        : "observed";
    return {
      ...section,
      lastRow,
      nextRow,
      status,
      nextStep: inferTimelineNextStep(lastRow, nextRow),
    };
  });
}

function ApplicationSankeyFlow({ workflow, timelineRows, routing, alertRows, selectedAlert, selectedAlertId, onDrillTimeline }) {
  const safeWorkflow = workflow && typeof workflow === "object" ? workflow : {};
  const safeRows = Array.isArray(timelineRows) ? timelineRows : [];
  const safeRouting = routing && typeof routing === "object" ? routing : {};
  const safeAlert = selectedAlert && typeof selectedAlert === "object" ? selectedAlert : {};
  const safeAlerts = Array.isArray(alertRows) ? alertRows : [];
  const publishedTopics = new Set(
    safeRows
      .map((row) => String(row?.publishes || "").trim())
      .filter((topic) => topic && topic !== "-" && topic.toLowerCase() !== "unknown")
  );
  const consumedTopics = new Set(
    safeRows
      .map((row) => String(row?.consumes || "").trim())
      .filter((topic) => topic && topic !== "-" && topic.toLowerCase() !== "unknown")
  );
  const observedTopics = new Set([...publishedTopics, ...consumedTopics]);
  const path = classifySelectedAlertPath(safeWorkflow, safeRows, safeAlert);
  const dynamicSections = buildDynamicFlowSections(safeRows);
  const topicRows = SERVICE_TOPIC_FLOW.map((row, index) => {
    const topic = String(row.publishes || "").trim();
    const consumed = String(row.consumes || "").trim();
    const observed = observedTopics.has(topic) || observedTopics.has(consumed);
    return {
      ...row,
      index: index + 1,
      observed,
      status: observed ? "observed" : "configured",
    };
  }).filter((row) => row.observed || row.service === "monitoring-adapter" || row.service === "alert-intelligence" || (path.hasOrchestration && row.service === "orchestrator"));
  const workerRows = SERVICE_TOPIC_FLOW.slice(1).map((row) => {
    const text = safeRows
      .map((item) => `${item?.agent || ""} ${item?.service || ""} ${item?.stage || ""} ${item?.detail || ""}`)
      .join(" ")
      .toLowerCase();
    const service = String(row.service || "").toLowerCase();
    const agent = String(row.agent || "").toLowerCase();
    const observed = text.includes(service) || text.includes(agent) || observedTopics.has(row.consumes) || observedTopics.has(row.publishes);
    const profile = RECOMMENDED_WORKER_PROFILE[row.service] || { containers: 1, workers: 1, role: "worker" };
    return { ...row, observed, profile, slots: Number(profile.containers || 1) * Number(profile.workers || 1) };
  }).filter((row) => {
    if (row.observed) return true;
    if (row.service === "alert-intelligence") return true;
    if (row.service === "orchestrator") return path.hasOrchestration;
    if (row.service === "context-agent") return path.hasContext;
    if (row.service === "resolution-agent") return path.hasResolution;
    if (row.service === "approval-service") return path.hasApproval;
    if (row.service === "remediation-engine") return path.hasRemediation;
    if (row.service === "closure-service") return path.hasClosure;
    return false;
  });
  const landedAlertCount = Math.max(
    safeAlerts.length,
    safeWorkflow?.alert ? 1 : 0,
    safeRows.some((row) => String(row?.stage || "").toLowerCase().includes("landing")) ? 1 : 0,
  );
  const provider = String(safeRouting.message_bus_provider || "rabbitmq").trim();
  const workflowName = String(safeRouting.workflow || safeWorkflow?.decision?.workflow || "guided-remediation").trim();
  const executionMode = String(safeRouting.execution_mode || safeWorkflow?.decision?.execution_mode || "parallel-workers").trim();
  const incidentId = String(safeWorkflow?.incident?.id || safeWorkflow?.incident_id || "-").trim();
  const approvalRequired = Boolean(
    safeWorkflow?.approval?.required
    ?? safeWorkflow?.decision?.requires_approval
    ?? safeWorkflow?.recommendation?.requires_approval
  );
  const remediationStatus = String(safeWorkflow?.remediation_action?.status || "pending").trim();
  const alertName = String(
    safeAlert.name
    || safeAlert.alert_name
    || safeWorkflow?.alert?.name
    || safeWorkflow?.alert?.alertname
    || selectedAlertId
    || "selected alert"
  ).trim();
  const landedFile = String(
    safeAlert.file_name
    || safeAlert.filename
    || safeAlert.source_file
    || safeAlert.file_path
    || safeAlert.path
    || safeWorkflow?.alert?.source_file
    || safeWorkflow?.alert?.file_name
    || ""
  ).trim();
  const landingSource = String(safeAlert.source || safeAlert.provider || safeWorkflow?.alert?.source || "landing pad").trim();
  const landingTime = formatIstTimestamp(
    safeAlert.created_at
    || safeAlert.starts_at
    || safeAlert.received_at
    || safeWorkflow?.alert?.starts_at
    || safeRows[0]?.timestamp
    || ""
  );
  const alertService = String(safeAlert.service || safeWorkflow?.alert?.service || "-").trim();
  const alertSeverity = String(safeAlert.severity || safeWorkflow?.alert?.severity || "-").trim();
  const activeWorkerCount = workerRows.filter((row) => row.observed).length;
  const observedTopicCount = topicRows.filter((row) => row.observed).length;
  const masterProfile = RECOMMENDED_WORKER_PROFILE.orchestrator;
  const masterSlots = Number(masterProfile.containers || 1) * Number(masterProfile.workers || 1);
  const workerSlots = workerRows.reduce((sum, row) => sum + Number(row.slots || 0), 0);
  const sankeyStats = [
    ["Alerts Landed", landedAlertCount || "-"],
    ["Topics Observed", `${observedTopicCount}/${topicRows.length}`],
    ["Master Nodes", `${masterProfile.containers} x orchestrator`],
    ["Worker Slots", workerSlots],
    ["Path", path.label],
  ];
  const staticStageRows = [
    { id: "landed", title: landedFile ? "File Landed" : "Alert Landed", detail: landedFile || alertName, meta: `${landingSource} | ${landingTime || "time not reported"}`, tone: "blue", status: landedAlertCount ? "observed" : "ready" },
    { id: "normalized", title: "Landing Pad Normalized", detail: `${alertService} | ${alertSeverity}`, meta: "labels + severity + trace id", tone: "blue", status: safeRows.length ? "observed" : "ready" },
    { id: "topics", title: "Topics Created", detail: `${observedTopicCount}/${topicRows.length} observed`, meta: provider, tone: "purple", status: observedTopicCount ? "observed" : "configured" },
    ...(path.hasOrchestration ? [{ id: "master", title: "Master Nodes Route Work", detail: `${masterProfile.containers} orchestrator container(s), ${masterSlots} consumer slot(s)`, meta: `${workflowName} | ${executionMode}`, tone: "green", status: observedTopics.has("orchestration-events") ? "observed" : "ready" }] : []),
    ...(workerRows.length ? [{ id: "workers", title: "Parallel Workers Process", detail: `${activeWorkerCount}/${workerRows.length} worker services observed`, meta: `${workerSlots} recommended worker slots`, tone: "teal", status: activeWorkerCount ? "observed" : "ready" }] : []),
    { id: "outputs", title: "Cockpit Updated", detail: incidentId, meta: path.hasRemediation ? `remediation ${remediationStatus}` : path.hasApproval ? `approval ${approvalRequired ? "required" : "observed"}` : path.label, tone: "orange", status: incidentId !== "-" ? "observed" : "ready" },
  ];
  const staticStageColumns = [
    {
      id: "source",
      title: landedFile ? "Landed File" : "Landed Alert",
      subtitle: landingSource,
      nodes: [
        { title: alertName, meta: landedFile || selectedAlertId || "selected row", status: landedAlertCount ? "observed" : "ready" },
        { title: "Service / Severity", meta: `${alertService} / ${alertSeverity}`, status: "ready" },
      ],
    },
    {
      id: "landing",
      title: "Landing Pad",
      subtitle: "/alerts/alertmanager",
      nodes: [
        { title: "Normalize Alert", meta: "labels + severity + trace", status: safeRows.length ? "observed" : "ready" },
        { title: "Persist Intake", meta: "alerts, incidents, incident_events", status: safeRows.length ? "observed" : "ready" },
      ],
    },
    {
      id: "topics",
      title: "Topic Creation",
      subtitle: provider,
      nodes: topicRows.map((row) => ({
        title: row.publishes,
        meta: row.consumes === "-" ? "seed topic" : `after ${row.consumes}`,
        status: row.status,
      })),
    },
    ...(path.hasOrchestration ? [{
      id: "master",
      title: "Master Node",
      subtitle: executionMode,
      nodes: [
        { title: "orchestrator masters", meta: `${masterProfile.containers} container(s) x ${masterProfile.workers} worker(s) = ${masterSlots} route slot(s)`, status: observedTopics.has("orchestration-events") ? "observed" : "ready" },
        { title: "workflow policy", meta: `${workflowName}; ${approvalRequired ? "approval required" : "approval optional"}`, status: approvalRequired ? "observed" : "ready" },
      ],
    }] : []),
    ...(workerRows.length ? [{
      id: "workers",
      title: "Parallel Workers",
      subtitle: "independent consumers",
      nodes: workerRows.map((row) => ({
        title: row.service,
        meta: `${row.profile.containers} container(s) x ${row.profile.workers} worker(s) = ${row.slots} slot(s); ${row.consumes} -> ${row.publishes}`,
        status: row.observed ? "observed" : "ready",
      })),
    }] : []),
    {
      id: "outputs",
      title: "Cockpit Outputs",
      subtitle: "operator workspace",
      nodes: [
        { title: "Incident", meta: incidentId, status: incidentId !== "-" ? "observed" : "ready" },
        ...(path.hasContext ? [{ title: "Documents + RAG", meta: "context, matches, citations", status: safeRows.some((row) => String(row?.stage || "").toLowerCase().includes("rag")) ? "observed" : "ready" }] : []),
        ...(path.hasApproval ? [{ title: "Approval", meta: approvalRequired ? "decision gate" : "observed decision", status: approvalRequired ? "observed" : "ready" }] : []),
        ...(path.hasRemediation ? [{ title: "Remediation", meta: remediationStatus || "pending", status: remediationStatus !== "pending" ? "observed" : "ready" }] : []),
        ...(path.hasClosure ? [{ title: "Closure", meta: safeWorkflow?.incident?.status || "validated", status: "observed" }] : []),
      ],
    },
  ];

  const stageRows = dynamicSections.length
    ? dynamicSections.map((section) => ({
        id: section.key,
        title: section.label,
        detail: section.lastRow?.stage || section.label,
        meta: `${section.lastRow?.agent || "-"} | ${section.lastRow?.consumes || "-"} -> ${section.lastRow?.publishes || "-"}`,
        tone: section.status === "failed" ? "orange" : section.status === "fallback" ? "purple" : "blue",
        status: section.status === "failed" ? "ready" : "observed",
        nextStep: section.nextStep,
      }))
    : staticStageRows;
  const stageColumns = dynamicSections.length
    ? dynamicSections.map((section) => ({
        id: section.key,
        title: section.label,
        subtitle: section.nextStep && section.nextStep !== "-"
          ? `next: ${section.nextStep}`
          : (section.lastRow?.publishes || section.lastRow?.service || "observed"),
        nodes: section.rows.map((row, index) => ({
          title: row.stage || `${section.label} ${index + 1}`,
          meta: `${row.agent || "-"} | ${row.consumes || "-"} -> ${row.publishes || "-"}`,
          status: timelineRowStatus(row, safeRows[safeRows.indexOf(row) + 1]) === "failed" ? "ready" : "observed",
        })),
      }))
    : staticStageColumns;

  return (
    <div className="application-sankey">
      <div className="context-flow-header">
        <div>
          <h3>Application Alert Flow</h3>
          <p>Actual landed alert/file first, then the downstream processing path. Use drilldown to inspect each stage in Flow Timeline.</p>
          <p>Best single-VM profile: one service container per stage with broker-backed worker consumers; add more VMs behind a load balancer for horizontal replicas.</p>
        </div>
        <div className="context-flow-scoreboard">
          {sankeyStats.map(([label, value]) => (
            <span key={`sankey-stat-${label}`}>
              {label}
              <strong>{value}</strong>
            </span>
          ))}
        </div>
      </div>

      <div className="app-flow-landed-card">
        <div>
          <span>{landedFile ? "Actual File Landed" : "Actual Alert Landed"}</span>
          <strong>{landedFile || alertName}</strong>
          <small>{alertName} | {alertService} | {alertSeverity}</small>
        </div>
        <button type="button" className="button-secondary" onClick={onDrillTimeline}>
          View Flow Timeline Detail
        </button>
      </div>

      <div className="app-sankey-stage-flow" aria-label="Actual alert processing flow">
        {stageRows.map((stage, index) => (
          <div className="app-sankey-stage-wrap" key={stage.id}>
            <article className={`app-sankey-stage tone-${stage.tone} status-${stage.status}`} style={{ animationDelay: `${index * 70}ms` }}>
              <span>{index + 1}</span>
              <div>
                <strong>{stage.title}</strong>
                <p>{stage.detail}</p>
                <small>{stage.meta}</small>
                {stage.nextStep && stage.nextStep !== "-" ? <small>next: {stage.nextStep}</small> : null}
              </div>
              <button type="button" className="timeline-copy-btn" onClick={onDrillTimeline}>Timeline</button>
            </article>
            {index < stageRows.length - 1 ? <i className={`app-sankey-stage-link tone-${stage.tone}`} aria-hidden="true" /> : null}
          </div>
        ))}
      </div>

      <div className="app-sankey-columns">
        {stageColumns.map((column) => (
          <section className={`app-sankey-column column-${column.id}`} key={column.id}>
            <div className="app-sankey-column-head">
              <strong>{column.title}</strong>
              <span>{column.subtitle}</span>
            </div>
            <div className="app-sankey-node-list">
              {column.nodes.map((node, index) => (
                <article className={`app-sankey-node status-${node.status}`} key={`${column.id}-${node.title}-${index}`}>
                  <strong>{node.title}</strong>
                  <span>{node.meta}</span>
                </article>
              ))}
            </div>
          </section>
        ))}
      </div>
    </div>
  );
}

function ProcessingFlowMap({ workflow, timelineRows, routing, selectedAlert, selectedAlertId, onDrillTimeline }) {
  const safeWorkflow = workflow && typeof workflow === "object" ? workflow : {};
  const safeRows = Array.isArray(timelineRows) ? timelineRows : [];
  const safeRouting = routing && typeof routing === "object" ? routing : {};
  const safeAlert = selectedAlert && typeof selectedAlert === "object" ? selectedAlert : {};
  const path = classifySelectedAlertPath(safeWorkflow, safeRows, safeAlert);
  const dynamicSections = buildDynamicFlowSections(safeRows);
  const rowByOrder = (order) => safeRows.find((row) => Number(row?.flowOrder) === order) || {};
  const firstRowMatching = (tokens) => {
    const needles = Array.isArray(tokens) ? tokens : [];
    return safeRows.find((row) => {
      const haystack = `${row?.stage || ""} ${row?.service || ""} ${row?.agent || ""} ${row?.consumes || ""} ${row?.publishes || ""}`.toLowerCase();
      return needles.some((token) => haystack.includes(String(token || "").toLowerCase()));
    }) || {};
  };
  const alertName = String(
    safeAlert.name
    || safeAlert.alert_name
    || safeWorkflow?.alert?.name
    || safeWorkflow?.alert?.alertname
    || selectedAlertId
    || "selected alert"
  ).trim();
  const service = String(safeAlert.service || safeWorkflow?.alert?.service || safeWorkflow?.incident?.service || "-").trim();
  const severity = String(safeAlert.severity || safeWorkflow?.alert?.severity || safeWorkflow?.incident?.severity || "-").trim();
  const incidentId = String(safeWorkflow?.incident?.id || safeWorkflow?.incident_id || "-").trim();
  const workflowName = String(safeRouting.workflow || safeWorkflow?.decision?.workflow || "guided-remediation").trim();
  const busProvider = String(safeRouting.message_bus_provider || safeWorkflow?.decision?.message_bus_provider || "rabbitmq").trim();
  const executionMode = String(safeRouting.execution_mode || safeWorkflow?.decision?.execution_mode || "parallel-workers").trim();
  const traceId = String(
    safeWorkflow?.alert?.trace_id
    || safeWorkflow?.incident?.trace_id
    || safeWorkflow?.context?.trace_id
    || safeWorkflow?.recommendation?.trace_id
    || ""
  ).trim();
  const recommendation = safeWorkflow?.recommendation && typeof safeWorkflow.recommendation === "object" ? safeWorkflow.recommendation : {};
  const contextPayload = safeWorkflow?.context && typeof safeWorkflow.context === "object" ? safeWorkflow.context : {};
  const contextMetadata = contextPayload?.metadata && typeof contextPayload.metadata === "object" ? contextPayload.metadata : {};
  const recommendationMetadata = recommendation?.metadata && typeof recommendation.metadata === "object" ? recommendation.metadata : {};
  const remediation = safeWorkflow?.remediation_action && typeof safeWorkflow.remediation_action === "object" ? safeWorkflow.remediation_action : {};
  const documentsRow = firstRowMatching(["rag context", "semantic", "context merge"]);
  const remediationPlan = remediation?.parameters?.execution_plan && typeof remediation.parameters.execution_plan === "object"
    ? remediation.parameters.execution_plan
    : {};
  const parseFlowJson = (value) => {
    const text = String(value || "").trim();
    if (!text) {
      return {};
    }
    try {
      const parsed = JSON.parse(text);
      return parsed && typeof parsed === "object" ? parsed : {};
    } catch (_error) {
      return {};
    }
  };
  const contextRetrievalRow = rowByOrder(80);
  const semanticSearchRow = rowByOrder(85);
  const contextMergeRow = rowByOrder(90);
  const resolutionRow = rowByOrder(110);
  const contextRetrievalOutput = parseFlowJson(contextRetrievalRow.outputValueText);
  const semanticSearchOutput = parseFlowJson(semanticSearchRow.outputValueText);
  const contextMergeOutput = parseFlowJson(contextMergeRow.outputValueText);
  const resolutionOutput = parseFlowJson(resolutionRow.outputValueText);
  const contextRetrievalInput = parseFlowJson(contextRetrievalRow.inputValueText);
  const resolutionInput = parseFlowJson(resolutionRow.inputValueText);
  const ragMatches = Array.isArray(contextRetrievalOutput.rag_matches)
    ? contextRetrievalOutput.rag_matches
    : Array.isArray(semanticSearchOutput.top_matches)
      ? semanticSearchOutput.top_matches
      : [];
  const topRagMatches = ragMatches.slice(0, 5);
  const ragIndex =
    (contextMetadata.rag_index && typeof contextMetadata.rag_index === "object" && contextMetadata.rag_index)
    || (recommendationMetadata.rag_index && typeof recommendationMetadata.rag_index === "object" && recommendationMetadata.rag_index)
    || {};
  const embeddingModel =
    (ragIndex.embedding_model && typeof ragIndex.embedding_model === "object" && ragIndex.embedding_model)
    || {};
  const vectorStore =
    (ragIndex.vector_store && typeof ragIndex.vector_store === "object" && ragIndex.vector_store)
    || {};
  const embeddingProvider = String(embeddingModel.provider || contextMetadata.embedding_provider || "not reported").trim();
  const embeddingName = String(embeddingModel.model || contextMetadata.embedding_model || "not reported").trim();
  const embeddingFallback = String(embeddingModel.fallback_active ? embeddingModel.fallback_model || "active" : embeddingModel.fallback_model || "-").trim();
  const vectorProvider = String(vectorStore.provider || contextMetadata.vector_store || "not reported").trim();
  const vectorIndexName = String(vectorStore.index || vectorStore.index_name || ragIndex.index_name || ragIndex.name || "-").trim();
  const indexedDocuments = ragIndex.document_count ?? ragIndex.total_documents ?? ragIndex.embedded_document_count ?? contextRetrievalOutput.rag_documents ?? "-";
  const modelUsage = Array.isArray(recommendationMetadata.model_usage)
    ? recommendationMetadata.model_usage
    : Array.isArray(recommendation.model_usage)
      ? recommendation.model_usage
      : [];
  const primaryModelCall = modelUsage[0] || {};
  const modelRouterProvider = String(primaryModelCall.provider || primaryModelCall.model_provider || recommendationMetadata.model_provider || "model-router").trim();
  const modelRouterModel = String(primaryModelCall.model || primaryModelCall.model_name || recommendationMetadata.model_name || "not reported").trim();
  const modelRouterTask = String(primaryModelCall.task || primaryModelCall.model_task || recommendationMetadata.model_task || "rca").trim();
  const modelRouterCalls = modelUsage.length;
  const modelRouterTokens = modelUsage.reduce((sum, row) => sum + Number(row.total_tokens || row.input_tokens || 0), 0);
  const modelRouterFailed = modelUsage.some((row) => {
    const safeRow = row && typeof row === "object" ? row : {};
    return hasMeaningfulValue(safeRow.error) || String(safeRow.status || "").trim().toLowerCase() === "failed";
  });
  const modelRouterFallback = modelUsage.some((row) => {
    const safeRow = row && typeof row === "object" ? row : {};
    const provider = String(safeRow.provider || safeRow.model_provider || "").trim().toLowerCase();
    const model = String(safeRow.model || safeRow.model_name || "").trim().toLowerCase();
    return provider.includes("fallback") || model.includes("fallback");
  });
  const modelRouterStatus = modelRouterFailed
    ? "failed"
    : modelRouterFallback
      ? "fallback"
      : modelRouterCalls > 0
        ? "observed"
        : "waiting";
  const contextDetailRows = [
    ["Query", contextRetrievalInput.service || contextRetrievalInput.query || service],
    ["Deployment", contextRetrievalInput.deployment || "-"],
    ["Related Incidents", contextRetrievalInput.related_incidents ?? "-"],
    ["RAG Documents", contextRetrievalOutput.rag_documents ?? "-"],
    ["Index Name", vectorIndexName],
    ["Vector Store", vectorProvider],
    ["Embedding Model", `${embeddingProvider} / ${embeddingName}`],
    ["Embedding Fallback", embeddingFallback || "-"],
    ["Runbook Found", String(contextRetrievalOutput.runbook_found ?? contextMergeOutput.runbook_found ?? "-")],
    ["Top Match Confidence", semanticSearchOutput.rag_top_match_confidence ?? semanticSearchOutput.rag_top_similarity ?? "-"],
    ["Top Semantic Score", semanticSearchOutput.rag_top_semantic_score ?? "-"],
    ["Top Metadata Score", semanticSearchOutput.rag_top_metadata_match_score ?? "-"],
    ["Context Summary", contextMergeOutput.context_summary || "-"],
  ];
  const resolutionDetailRows = [
    ["Incident", resolutionInput.incident_id || incidentId],
    ["Recommendation ID", resolutionOutput.recommendation_id || recommendation.id || "-"],
    ["Root Cause", cleanRecommendationText(resolutionOutput.root_cause || recommendation.root_cause, "-")],
    ["Impact", cleanRecommendationText(recommendation.impact, "-")],
    ["Recommended Action", cleanRecommendationText(recommendation.recommended_action, "-")],
    ["Model Router", `${modelRouterProvider} / ${modelRouterModel}`],
    ["Model Task", modelRouterTask],
    ["LLM Calls", modelRouterCalls || "-"],
    ["Tokens", modelRouterTokens || "-"],
    ["Confidence", resolutionOutput.confidence ?? recommendation.confidence ?? "-"],
    ["Grounding Score", resolutionOutput.grounding_score ?? recommendation?.metadata?.grounding_score ?? "-"],
    ["Hallucination Score", resolutionOutput.hallucination_score ?? recommendation?.metadata?.hallucination_score ?? "-"],
  ];
  const incidentStatusText = String(safeWorkflow?.incident?.status || safeAlert.status || safeAlert.state || "").trim().toLowerCase();
  const isClosed = ["closed", "resolved", "validated", "complete", "completed"].some((token) => incidentStatusText.includes(token));
  const allTimelineText = safeRows
    .map((row) => `${row?.stage || ""} ${row?.detail || ""} ${row?.errorValueText || ""} ${row?.inputValueText || ""} ${row?.outputValueText || ""}`)
    .join(" ")
    .toLowerCase();
  const fallbackDetected = ["fallback", "skipped", "not executed", "no live executor", "no real", "blocked", "policy"].some((token) => allTimelineText.includes(token));
  const rowIndicatesFallback = (text) => [
    "fallback",
    "heuristic-fallback",
    "skipped",
    "not executed",
    "no live executor",
    "no real",
    "policy-blocked",
    "safety gate",
    "live mutation blocked",
  ].some((token) => text.includes(token));
  const rowIndicatesSuccess = (text) => [
    "succeeded",
    "success",
    "completed",
    "closed",
    "observed",
    "validated",
    "confidence",
    "recommendation_id",
  ].some((token) => text.includes(token));
  const rowHasFailure = (row) => {
    const text = `${row?.status || ""} ${row?.detail || ""} ${row?.errorValueText || ""} ${row?.inputValueText || ""} ${row?.outputValueText || ""}`.toLowerCase();
    if (!hasMeaningfulValue(row?.errorValueText)) {
      return false;
    }
    if (rowIndicatesFallback(text) || rowIndicatesSuccess(text)) {
      return false;
    }
    return text.includes("error") || text.includes("failed") || text.includes("exception");
  };
  const failedCount = safeRows.filter(rowHasFailure).length;

  const nodeStatus = (row, order, fallbackHint = "") => {
    // Only trust the dedicated error/fallback signal for this stage, not the
    // stringified input/output JSON blobs — those often contain unrelated
    // fields (e.g. the incident's overall lifecycle status) whose text can
    // coincidentally include words like "failed", which previously caused
    // unrelated stages to be mislabeled as failed.
    const errorText = String(row?.errorValueText || "").toLowerCase();
    const hintText = String(fallbackHint || "").toLowerCase();
    const statusText = `${errorText} ${hintText}`;
    if (statusText.includes("error") || statusText.includes("failed") || statusText.includes("exception")) {
      return "failed";
    }
    if (
      statusText.includes("fallback")
      || statusText.includes("skipped")
      || statusText.includes("not executed")
      || statusText.includes("no live executor")
      || statusText.includes("no real")
      || statusText.includes("policy-blocked")
      || statusText.includes("safety gate")
      || statusText.includes("live mutation blocked")
    ) {
      return "fallback";
    }
    if (rowIndicatesSuccess(statusText)) {
      return "observed";
    }
    if (statusText.includes("error") || statusText.includes("failed") || statusText.includes("exception")) {
      return "failed";
    }
    if (isClosed && Number(order || 0) >= 170) {
      return "closed";
    }
    if (hasMeaningfulValue(row) || safeRows.some((item) => Number(item?.flowOrder) === order)) {
      return "observed";
    }
    return "waiting";
  };

  const makeNode = ({ key, title, meta, detail, type = "service", row = {}, order, fallbackHint = "", statusOverride = "", nextStep = "" }) => {
    const observed = hasMeaningfulValue(row) || safeRows.some((item) => Number(item?.flowOrder) === order);
    const status = statusOverride || nodeStatus(row, order, fallbackHint);
    return { key, title, meta, detail, type, row, order, observed, status, nextStep };
  };

  const mainNodes = [
    makeNode({ key: "source", title: "Alerts ingested by third party", meta: "Prometheus / Grafana / external tools", detail: alertName, order: 5, type: "source", row: safeAlert }),
    makeNode({ key: "landing", title: "Alerts landed in Landing Pad", meta: "/input or /alerts/alertmanager", detail: `${service} | ${severity}`, order: 10, row: rowByOrder(10) }),
    makeNode({ key: "normalize", title: "Alert normalized to canonical format", meta: "labels + annotations + trace id", detail: traceId || "trace generated by intake", order: 10, row: rowByOrder(10) }),
    makeNode({ key: "raw-bus", title: "Raw alert message published", meta: `${busProvider}: raw-alerts`, detail: "Monitoring Adapter -> Alert Intelligence", order: 20, type: "bus", row: rowByOrder(20) }),
    makeNode({
      key: "alert-ai",
      title: "Alert intelligence: classify, dedupe, correlate",
      meta: "policy + labels + fingerprint + service",
      detail: `severity=${severity}; incident=${incidentId}`,
      order: 30,
      row: {
        ...rowByOrder(30),
        inputValueText: stringifyTimelineValue({
          alert: alertName,
          service,
          environment: safeAlert.environment || safeWorkflow?.alert?.environment || "-",
          fingerprint: safeAlert.fingerprint || safeAlert.labels?.alert_fingerprint || "-",
        }),
        outputValueText: stringifyTimelineValue({
          severity_classification: severity,
          deduplicated_count: safeAlert.deduplicated_count ?? safeWorkflow?.alert?.deduplicated_count ?? "-",
          correlation_id: safeAlert.correlation_id || safeWorkflow?.alert?.correlation_id || "-",
          incident_id: incidentId,
        }),
      },
    }),
  ];

  const orchestrationNodes = path.hasOrchestration ? [
    makeNode({ key: "enriched-bus", title: "Enriched alert message published", meta: `${busProvider}: enriched-alerts`, detail: "Alert Intelligence -> Orchestrator", order: 40, type: "bus", row: rowByOrder(40) }),
    makeNode({ key: "orchestrator", title: "Orchestrator workflow selected", meta: workflowName, detail: `execution=${executionMode}`, order: 50, row: rowByOrder(50) }),
    makeNode({ key: "config", title: "Config and connector lookup", meta: "connections + playbooks + action catalog", detail: "workflow, bus provider, risk, executor profile", order: 60, type: "config", row: rowByOrder(60) }),
    makeNode({ key: "orch-bus", title: "Execution work item published", meta: `${busProvider}: orchestration-events`, detail: "Orchestrator -> Context Agent", order: 70, type: "bus", row: rowByOrder(70) }),
  ] : [];

  const workerLanes = [
    ...(path.hasContext ? [{
      key: "context",
      title: "Context",
      nodes: [
        makeNode({ key: "ctx-agent", title: "Context Agent consumes orchestration-events", meta: "query + signal + service", detail: service, order: 80, row: rowByOrder(80) }),
        makeNode({ key: "index", title: "Checks index and documents", meta: `${vectorProvider} / ${vectorIndexName}`, detail: `${indexedDocuments} document(s), embedding ${embeddingProvider}/${embeddingName}`, order: 85, type: "store", row: documentsRow }),
        makeNode({ key: "ranked", title: "Search ranked", meta: "semantic + metadata ranking", detail: `top similarity ${semanticSearchOutput.rag_top_similarity ?? "not reported"}`, order: 85, type: "store", row: rowByOrder(85) }),
        makeNode({ key: "context-merge", title: "Context merged and evidence assembled", meta: "docs + deps + connector evidence", detail: "context-events payload prepared", order: 90, row: rowByOrder(90) }),
        makeNode({ key: "context-bus", title: "Context message published", meta: `${busProvider}: context-events`, detail: "Context Agent -> Resolution Agent", order: 100, type: "bus", row: rowByOrder(100) }),
      ],
    }] : []),
    ...(path.hasResolution ? [{
      key: "resolution",
      title: "Resolution",
      nodes: [
        makeNode({
          key: "model-router",
          title: "Model Router LLM call",
          meta: `${modelRouterProvider} / ${modelRouterModel}`,
          detail: `${modelRouterTask} | ${modelRouterCalls || 0} call(s) | ${modelRouterTokens || 0} token(s)`,
          order: 109,
          type: "config",
          row: modelUsage.length
            ? {
                inputValueText: stringifyTimelineValue({ task: modelRouterTask, provider: modelRouterProvider, model: modelRouterModel }),
                outputValueText: stringifyTimelineValue({
                  calls: modelRouterCalls,
                  tokens: modelRouterTokens,
                  status: modelRouterStatus,
                  errors: modelUsage.map((row) => row?.error).filter(Boolean),
                }),
                errorValueText: modelRouterFailed ? stringifyTimelineValue(modelUsage.map((row) => row?.error).filter(Boolean)) : "",
              }
            : {},
          fallbackHint: modelRouterFallback ? "fallback" : "",
          statusOverride: modelRouterStatus,
        }),
        makeNode({ key: "resolution-agent", title: "Resolution Agent consumes context-events", meta: "RCA + impact + action", detail: cleanRecommendationText(recommendation.root_cause, "root cause analysis"), order: 110, row: rowByOrder(110) }),
        makeNode({ key: "impact", title: "Impact analysis", meta: "customer + dependency impact", detail: cleanRecommendationText(recommendation.impact, "-"), order: 110, row: rowByOrder(110) }),
        makeNode({ key: "action", title: "Recommendation action", meta: "safe next step", detail: cleanRecommendationText(recommendation.recommended_action, "-"), order: 110, row: rowByOrder(110) }),
        makeNode({ key: "confidence", title: "Confidence and grounding", meta: "quality guardrails", detail: `confidence ${recommendation.confidence ?? "-"}`, order: 110, row: rowByOrder(110) }),
        ...(path.hasApproval || path.hasRemediation ? [makeNode({ key: "resolution-bus", title: "Resolution message published", meta: `${busProvider}: resolution-events`, detail: "Resolution Agent -> Approval Service", order: 120, type: "bus", row: rowByOrder(120) })] : []),
      ],
    }] : []),
    ...(path.hasApproval || path.hasRemediation ? [{
      key: "remediation",
      title: "Approval + Remediation",
      nodes: [
        ...(path.hasApproval ? [
          makeNode({ key: "approval", title: "Human approval gate", meta: "L2/L3/Admin can edit plan", detail: remediation.approval_id || "pending decision", order: 130, row: rowByOrder(130) }),
          makeNode({ key: "approval-bus", title: "Approval message published", meta: `${busProvider}: approval-events`, detail: "Approval Service -> Remediation Engine", order: 140, type: "bus", row: rowByOrder(140) }),
        ] : []),
        ...(path.hasRemediation ? [makeNode({ key: "execute", title: "Remediation Engine validates and executes", meta: "policy + executor + secret_ref", detail: remediation.status || "pending", order: 150, row: rowByOrder(150), fallbackHint: remediation?.error || remediation?.output || "" })] : []),
        ...(fallbackDetected ? [
          makeNode({
            key: "fallback",
            title: "Fallback or safety gate applied",
            meta: "plan preserved, live mutation blocked",
            detail: remediation.error || remediation.output || "No live executor/connector was available, so the approved plan remains available for operator action.",
            order: 151,
            type: "config",
            row: rowByOrder(150),
            fallbackHint: "fallback",
          }),
        ] : []),
        ...(path.hasRemediation ? [
          makeNode({ key: "script", title: "Execution plan script", meta: "editable before approval", detail: Array.isArray(remediationPlan.scripts) && remediationPlan.scripts.length ? remediationPlan.scripts[0] : "no script reported", order: 150, type: "config", row: rowByOrder(150) }),
          makeNode({ key: "rem-bus", title: "Remediation message published", meta: `${busProvider}: remediation-events`, detail: "Remediation Engine -> Closure Service", order: 160, type: "bus", row: rowByOrder(160) }),
        ] : []),
      ],
    }] : []),
    ...(path.hasClosure ? [{
      key: "closure",
      title: "Closure",
      nodes: [
        makeNode({ key: "closure-service", title: "Closure Service validates outcome", meta: "post-checks + incident projection", detail: safeWorkflow?.incident?.status || "-", order: 170, row: rowByOrder(170) }),
        makeNode({ key: "closure-bus", title: "Closure message published", meta: `${busProvider}: closure-events`, detail: "Dashboard, reports, notifications", order: 180, type: "bus", row: firstRowMatching(["closure-events"]) }),
      ],
    }] : []),
  ];

  const statusLabel = (status) => {
    if (status === "failed") return "Failed";
    if (status === "fallback") return "Review required";
    if (status === "closed") return "Closed";
    if (status === "observed") return "Observed";
    return "Waiting";
  };
  const renderNode = (node) => (
    <article className={`processing-flow-node node-${node.type} status-${node.status}`} key={node.key}>
      <div className="processing-node-head">
        <strong>{node.title}</strong>
        <em>{statusLabel(node.status)}</em>
      </div>
      <span>{node.meta}</span>
      <p>{compactText(node.detail, 150) || "-"}</p>
      <small>
        {node.status === "fallback"
          ? "fallback, blocked execution, or safety gate path used"
          : node.status === "failed"
            ? "error detected in selected alert flow"
            : node.status === "closed"
              ? "incident closure path completed"
              : node.status === "observed"
                ? "observed from selected alert flow"
                : "configured path, not observed yet"}
      </small>
        {node.nextStep && node.nextStep !== "-" ? <small>next step: {node.nextStep}</small> : null}
      {node.row?.inputValueText || node.row?.outputValueText ? (
        <details>
          <summary>Details</summary>
          {node.row?.inputValueText ? <pre className="result">{node.row.inputValueText}</pre> : null}
          {node.row?.outputValueText ? <pre className="result">{node.row.outputValueText}</pre> : null}
        </details>
      ) : null}
    </article>
  );

  return (
    <div className="processing-flow-map">
      <div className="context-flow-header">
        <div>
          <h3>Complete Processing Flow</h3>
          <p>Architecture-style view for the selected alert. Use Flow Timeline for full event payload details.</p>
        </div>
        <button type="button" className="button-secondary" onClick={onDrillTimeline}>Open Detailed Timeline</button>
      </div>
      <div className="processing-flow-status-strip">
        <span><strong>{safeRows.length}</strong> timeline rows</span>
        <span><strong>{failedCount}</strong> failures</span>
        <span><strong>{fallbackDetected ? "yes" : "no"}</strong> fallback</span>
        <span><strong>{isClosed ? "closed" : incidentStatusText || "open"}</strong> incident</span>
        <span><strong>{path.label}</strong> selected path</span>
      </div>
      {fallbackDetected || failedCount ? (
        <div className={`processing-flow-banner ${failedCount ? "is-failed" : "is-fallback"}`}>
          <strong>{failedCount ? "Flow needs attention" : "Fallback path detected"}</strong>
          <span>
            {failedCount
              ? "One or more stages reported errors. Open the detailed timeline to inspect exact payloads."
              : "A safety gate, fallback, or skipped execution was detected. The plan is preserved and closure should reflect the guarded outcome."}
          </span>
        </div>
      ) : null}
      {dynamicSections.length ? (
      <div className="processing-flow-lanes">
        {dynamicSections.map((section) => {
          const nodes = section.rows.map((row, index) => {
            const rowIndex = safeRows.indexOf(row);
            const nextRow = rowIndex >= 0 ? safeRows[rowIndex + 1] : null;
            return makeNode({
              key: `${section.key}-${index}`,
              title: row.stage || section.label,
              meta: `${row.agent || "-"} | ${row.consumes || "-"} -> ${row.publishes || "-"}`,
              detail: row.detail || "Observed stage from incident timeline.",
              type: row.publishes && row.publishes !== "-" ? "bus" : "service",
              row,
              order: row.flowOrder || row.sequence || index + 1,
              fallbackHint: inferTimelineNextStep(row, nextRow),
              statusOverride: timelineRowStatus(row, nextRow),
              nextStep: inferTimelineNextStep(row, nextRow),
            });
          });
          return (
            <section className="processing-flow-lane" key={section.key}>
              <h4>{section.label}</h4>
              {section.nextStep && section.nextStep !== "-" ? <p className="subtitle">next: {section.nextStep}</p> : null}
              {nodes.map((node, index) => (
                <div className="processing-flow-step" key={node.key}>
                  {renderNode(node)}
                  {index < nodes.length - 1 ? <span className="processing-flow-arrow" aria-hidden="true">v</span> : null}
                </div>
              ))}
            </section>
          );
        })}
      </div>
      ) : (
      <>
      <div className="processing-flow-spine">
        {mainNodes.map((node, index) => (
          <div className="processing-flow-step" key={node.key}>
            {renderNode(node)}
            {index < mainNodes.length - 1 ? <span className="processing-flow-arrow" aria-hidden="true">v</span> : null}
          </div>
        ))}
      </div>
      {orchestrationNodes.length ? (
        <div className="processing-flow-spine">
          {orchestrationNodes.map((node, index) => (
            <div className="processing-flow-step" key={node.key}>
              {renderNode(node)}
              {index < orchestrationNodes.length - 1 ? <span className="processing-flow-arrow" aria-hidden="true">v</span> : null}
            </div>
          ))}
        </div>
      ) : null}
      {workerLanes.length ? (
      <div className="processing-flow-lanes">
        {workerLanes.map((lane) => (
          <section className="processing-flow-lane" key={lane.key}>
            <h4>{lane.title}</h4>
            {lane.nodes.map((node, index) => (
              <div className="processing-flow-step" key={node.key}>
                {renderNode(node)}
                {index < lane.nodes.length - 1 ? <span className="processing-flow-arrow" aria-hidden="true">v</span> : null}
              </div>
            ))}
          </section>
        ))}
      </div>
      ) : (
        <div className="processing-flow-banner">
          <strong>No downstream worker cycle required</strong>
          <span>This selected alert currently only shows intake/intelligence stages. Context, resolution, approval, remediation, and closure will appear only if the workflow reaches those stages.</span>
        </div>
      )}
      </>
      )}
      <div className="processing-flow-detail-grid">
        <article className="processing-flow-detail-card">
          <div className="panel-head">
            <h4>Context Details</h4>
            <p>Same evidence path as Context Flow, shown inline for this processing map.</p>
          </div>
          <div className="table-wrap table-wrap-scroll-x">
            <table>
              <tbody>
                {contextDetailRows.map(([label, value]) => (
                  <tr key={`processing-context-${label}`}><th>{label}</th><td>{String(value ?? "-")}</td></tr>
                ))}
              </tbody>
            </table>
          </div>
          <h4>Documents / Matches Touched</h4>
          {topRagMatches.length ? (
            <div className="processing-flow-match-list">
              {topRagMatches.map((match, index) => (
                <div className="processing-flow-match" key={`processing-match-${index}`}>
                  <strong>{match.title || match.document_id || match.path || `Match ${index + 1}`}</strong>
                  <span>{match.kind || match.document_kind || "document"} | confidence {Math.round(Number(match.match_confidence || match._similarity || match.score || 0) * 100) || "-"}%</span>
                  <small>{compactText(match.match_reason || match.summary || match.path || JSON.stringify(match), 180)}</small>
                </div>
              ))}
            </div>
          ) : (
            <p className="subtitle">No RAG match list was reported for this selected alert.</p>
          )}
        </article>
        <article className="processing-flow-detail-card">
          <div className="panel-head">
          <h4>Resolution Details</h4>
          <p>RCA, impact, recommendation, and quality scores from the Resolution Agent.</p>
          </div>
          <div className="table-wrap table-wrap-scroll-x">
            <table>
              <tbody>
                {resolutionDetailRows.map(([label, value]) => (
                  <tr key={`processing-resolution-${label}`}><th>{label}</th><td>{String(value ?? "-")}</td></tr>
                ))}
              </tbody>
            </table>
          </div>
          <h4>LLM Calls Through Model Router</h4>
          {modelUsage.length ? (
            <div className="processing-flow-match-list">
              {modelUsage.slice(0, 6).map((usage, index) => (
                <div className="processing-flow-match" key={`processing-llm-${index}`}>
                  <strong>{usage.provider || usage.model_provider || "model-router"}</strong>
                  <span>{usage.model || usage.model_name || "-"} | task {usage.task || usage.model_task || "-"}</span>
                  <small>
                    input {usage.input_tokens ?? "-"} | output {usage.output_tokens ?? "-"} | total {usage.total_tokens ?? "-"} | cost {usage.total_cost_usd ?? "-"}
                  </small>
                </div>
              ))}
            </div>
          ) : (
            <p className="subtitle">No persisted model-router usage rows were reported for this selected alert.</p>
          )}
          <h4>Execution Plan Preview</h4>
          <div className="processing-flow-match-list">
            <div className="processing-flow-match">
              <strong>Commands</strong>
              <span>{Array.isArray(remediationPlan.commands) ? remediationPlan.commands.length : 0} item(s)</span>
              <small>{Array.isArray(remediationPlan.commands) && remediationPlan.commands.length ? remediationPlan.commands.join(" | ") : "No command list reported."}</small>
            </div>
            <div className="processing-flow-match">
              <strong>Scripts</strong>
              <span>{Array.isArray(remediationPlan.scripts) ? remediationPlan.scripts.length : 0} item(s)</span>
              <small>{Array.isArray(remediationPlan.scripts) && remediationPlan.scripts.length ? remediationPlan.scripts.join(" | ") : "No script reported."}</small>
            </div>
            <div className="processing-flow-match">
              <strong>Queries</strong>
              <span>{Array.isArray(remediationPlan.queries) ? remediationPlan.queries.length : 0} item(s)</span>
              <small>{Array.isArray(remediationPlan.queries) && remediationPlan.queries.length ? remediationPlan.queries.join(" | ") : "No validation query reported."}</small>
            </div>
          </div>
        </article>
      </div>
    </div>
  );
}

function MessageBusTopology({ actual, configuredRows, routing, primaryTopic, compact = false }) {
  const safeActual = actual && typeof actual === "object" ? actual : {};
  const safeRouting = routing && typeof routing === "object" ? routing : {};
  const published = Array.isArray(safeActual.published) ? safeActual.published : [];
  const consumed = Array.isArray(safeActual.consumed) ? safeActual.consumed : [];
  const observedTopics = new Set([...published, ...consumed].map((topic) => String(topic || "").trim()).filter(Boolean));
  const rows = Array.isArray(configuredRows) ? configuredRows : [];
  const provider = String(safeRouting?.message_bus_provider || safeActual?.rows?.[0]?.provider || "Azure Service Bus").trim();
  const workflow = String(safeRouting?.workflow || "alert-workflow").trim();
  const executionMode = String(safeRouting?.execution_mode || "parallel-workers").trim();
  const sourceTopic = String(primaryTopic || rows.find((row) => row?.publishes)?.publishes || "kaiops-orchestration-events").trim();
  const workerNodes = [
    { title: "Alert Intelligence", service: "alert-intelligence", topic: "enriched-alerts", lane: "worker" },
    { title: "Context Worker", service: "context-agent", topic: "context-events", lane: "worker" },
    { title: "Resolution Worker", service: "resolution-agent", topic: "resolution-events", lane: "worker" },
    { title: "Approval Worker", service: "approval-service", topic: "approval-events", lane: "gate" },
    { title: "Remediation Worker", service: "remediation-engine", topic: "remediation-events", lane: "worker" },
    { title: "Closure Worker", service: "closure-service", topic: "closure-events", lane: "worker" },
  ];

  const isObserved = (topic) => observedTopics.has(String(topic || "").replace(" (enabled transports)", ""));

  return (
    <div className={`message-bus-topology ${compact ? "compact" : ""}`} aria-label="Message bus topology">
      <div className="bus-summary-strip">
        <div>
          <span>Provider</span>
          <strong>{provider}</strong>
        </div>
        <div>
          <span>Workflow</span>
          <strong>{workflow}</strong>
        </div>
        <div>
          <span>Execution</span>
          <strong>{executionMode}</strong>
        </div>
        <div>
          <span>Primary Topic</span>
          <strong>{sourceTopic}</strong>
        </div>
      </div>

      <div className="bus-path-stage-grid">
        <section className="bus-stage bus-stage-ingest">
          <div className="bus-stage-head">
            <span className="bus-node-icon">LP</span>
            <div>
              <strong>Landing Pad</strong>
              <span>Alert intake and normalization</span>
            </div>
          </div>
          <div className="bus-endpoint-box">
            <span>HTTP ingestion</span>
            <code>/alerts/alertmanager</code>
          </div>
          <div className="bus-topic-pill active">raw-alerts</div>
        </section>

        <section className="bus-stage bus-stage-topic">
          <div className="bus-stage-head">
            <span className="bus-node-icon">TC</span>
            <div>
              <strong>Topic Creation</strong>
              <span>Provisioned routing channels</span>
            </div>
          </div>
          <div className="bus-topic-sequence" aria-label="Sequential topic creation flow">
            {rows.map((row, index) => {
              const topic = String(row?.publishes || "").trim();
              const consumes = String(row?.consumes || "").replace(" (enabled transports)", "").trim();
              const state = isObserved(topic) ? "created" : "configured";
              return (
                <div className="bus-topic-sequence-step" key={`${topic || "topic"}-${index}`}>
                  <div className={`bus-topic-create-row ${state}`}>
                    <span>{index + 1}</span>
                    <div>
                      <strong>{topic || "-"}</strong>
                      <small>{consumes && consumes !== "-" ? `after ${consumes}` : "landing pad seed topic"}</small>
                    </div>
                    <em>{state}</em>
                  </div>
                  {index < rows.length - 1 ? (
                    <div className="bus-topic-sequence-arrow" aria-hidden="true">
                      <i />
                      <span>next</span>
                    </div>
                  ) : null}
                </div>
              );
            })}
          </div>
        </section>

        <section className="bus-stage bus-stage-master">
          <div className="bus-stage-head">
            <span className="bus-node-icon">MN</span>
            <div>
              <strong>Master Node</strong>
              <span>Orchestrator coordinates workers</span>
            </div>
          </div>
          <div className="bus-master-node">
            <strong>orchestrator</strong>
            <span>Consumes enriched-alerts</span>
            <span>Publishes orchestration-events</span>
          </div>
        </section>
      </div>

      <div className="bus-flow-arrow-row" aria-hidden="true">
        <span>Landing Pad</span>
        <i />
        <span>Topics</span>
        <i />
        <span>Master Node</span>
        <i />
        <span>Parallel Workers</span>
      </div>

      <section className="bus-parallel-section">
        <div className="bus-stage-head">
          <span className="bus-node-icon">PW</span>
          <div>
            <strong>Parallel Processing Workers</strong>
            <span>Independent consumers process topic events concurrently</span>
          </div>
        </div>
        <div className="bus-worker-grid">
          {workerNodes.map((worker) => (
            <div className={`bus-worker-node ${worker.lane}`} key={worker.service}>
              <span>{worker.service}</span>
              <strong>{worker.title}</strong>
              <em className={isObserved(worker.topic) ? "observed" : "pending"}>
                {isObserved(worker.topic) ? "observed" : "ready"}
              </em>
              <code>{worker.topic}</code>
            </div>
          ))}
        </div>
      </section>

      <div className="bus-observed-rail">
        <strong>Observed Topics</strong>
        <div>
          {[...observedTopics].map((topic) => (
            <span key={`observed-topic-${topic}`}>{topic}</span>
          ))}
          {!observedTopics.size ? <span>No live topic activity yet</span> : null}
        </div>
      </div>
    </div>
  );
}

function ExecutionPlanGraph({ plan }) {
  const safePlan = plan && typeof plan === "object" ? plan : {};
  const commands = Array.isArray(safePlan.commands) ? safePlan.commands : [];
  const grouped = { commands: [], scripts: [], queries: [] };
  commands.forEach((item) => {
    const token = String(item || "").trim();
    if (!token) {
      return;
    }
    if (/^script\s*:/i.test(token)) {
      grouped.scripts.push(token.replace(/^script\s*:/i, "").trim());
      return;
    }
    if (/^query\s*:/i.test(token)) {
      grouped.queries.push(token.replace(/^query\s*:/i, "").trim());
      return;
    }
    grouped.commands.push(token.replace(/^cmd\s*:/i, "").trim());
  });

  return (
    <div className="execution-graph">
      <article className="execution-card">
        <h4>Plan Core</h4>
        <div className="execution-grid">
          <span>Workflow</span><strong>{safePlan.workflow || "-"}</strong>
          <span>Action</span><strong>{safePlan.action || "-"}</strong>
          <span>Rationale</span><strong>{safePlan.rationale || "-"}</strong>
          <span>Mode</span><strong>{safePlan.executionMode || "-"}</strong>
          <span>Risk</span><strong>{safePlan.riskTier || "-"}</strong>
          <span>Provider</span><strong>{String(safePlan.provider || "-").toUpperCase()}</strong>
          <span>Approval</span><strong>{String(safePlan.requiresApproval)}</strong>
          <span>Incident Status</span><strong>{safePlan.incidentStatus || "-"}</strong>
          <span>Approval Status</span><strong>{safePlan.approvalStatus || "-"}</strong>
        </div>
      </article>
      <article className="execution-card">
        <h4>Remediation Plan</h4>
        <div className="execution-command-list">
          {grouped.commands.length ? grouped.commands.map((command, index) => (
            <div className="execution-command" key={`cmd-${index}`} style={{ animationDelay: `${Math.min(index * 80, 640)}ms` }}>
              <span>{index + 1}</span>
              <code>{String(command || "-")}</code>
            </div>
          )) : <p className="subtitle">No command sequence found.</p>}
          {grouped.scripts.length ? (
            <>
              <h4>Scripts</h4>
              {grouped.scripts.map((script, index) => (
                <div className="execution-command" key={`script-${index}`}>
                  <span>S{index + 1}</span>
                  <code>{script}</code>
                </div>
              ))}
            </>
          ) : null}
          {grouped.queries.length ? (
            <>
              <h4>Validation Queries</h4>
              {grouped.queries.map((query, index) => (
                <div className="execution-command" key={`query-${index}`}>
                  <span>Q{index + 1}</span>
                  <code>{query}</code>
                </div>
              ))}
            </>
          ) : null}
        </div>
      </article>
    </div>
  );
}

function renderHtmlTable(headers, rows) {
  const safeHeaders = Array.isArray(headers) ? headers : [];
  const safeRows = Array.isArray(rows) ? rows : [];
  const head = safeHeaders.map((header) => `<th>${htmlEscape(header)}</th>`).join("");
  const body = safeRows.length
    ? safeRows
        .map((row) => {
          const cells = Array.isArray(row) ? row : [];
          return `<tr>${cells.map((cell) => `<td>${htmlEscape(asDisplayValue(cell))}</td>`).join("")}</tr>`;
        })
        .join("")
    : `<tr><td colspan="${Math.max(1, safeHeaders.length)}">No rows available.</td></tr>`;
  return `<table><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table>`;
}

function normalizeGeneratedRuleRows(source) {
  const payload = source && typeof source === "object" ? source : {};
  const candidates = [
    payload.generated_rules,
    payload.rules,
    payload.rule_candidates,
    payload.rule_set,
    payload.output?.rules,
    payload.result?.rules,
    payload.data?.rules,
  ];
  const first = candidates.find((item) => Array.isArray(item) && item.length) || [];
  return first.map((item, index) => {
    const row = item && typeof item === "object" ? item : {};
    return {
      id: String(row.id || row.rule_id || row.name || `rule-${index + 1}`),
      name: String(row.name || row.rule_name || row.alertname || `rule-${index + 1}`),
      platform: String(row.platform || row.target_platform || row.provider || "prometheus"),
      contractMode: String(row.contract_mode || row.adapter_mode || "-"),
      contractStatus: String(row.contract_status || row.adapter_status || "-"),
      severity: String(row.severity || row.level || "-").toLowerCase(),
      expression: String(row.expression || row.expr || row.query || row.condition || "-").trim(),
      status: String(row.status || row.state || "generated"),
    };
  });
}

function cleanRuleIntentLine(line) {
  return String(line || "")
    .replace(/^[^\n:]{1,180}\.(?:md|markdown|txt|log|json|ya?ml|csv)\s*:\s*/i, "")
    .trim();
}

function slugForPrometheus(value) {
  return String(value || "kaiops")
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9_:-]+/g, "-")
    .replace(/^-+|-+$/g, "") || "kaiops";
}

function yamlQuote(value) {
  return JSON.stringify(String(value ?? ""));
}

function inferPrometheusExpression(requirement, serviceName) {
  const text = String(requirement || "").toLowerCase();
  const service = String(serviceName || "service").trim() || "service";
  const numberMatch = text.match(/(?:above|over|greater than|exceeds?|>=?)\s+([0-9]+(?:\.[0-9]+)?)/i);
  const threshold = numberMatch ? Number(numberMatch[1]) : null;
  if (text.includes("unavailable") || text.includes("down") || text.includes("not reachable") || text.includes("not available")) {
    return `up{service="${service}"} == 0`;
  }
  if (text.includes("latency") || text.includes("p95") || text.includes("p99")) {
    const metric = text.includes("p99") ? "request_latency_ms_p99" : "request_latency_ms_p95";
    return `quantile_over_time(0.95, ${metric}{service="${service}"}[5m]) > ${threshold || 500}`;
  }
  if (text.includes("error rate") || text.includes("5xx") || text.includes("errors")) {
    return `avg_over_time(error_rate_percent{service="${service}"}[5m]) > ${threshold || 5}`;
  }
  if (text.includes("row") || text.includes("table")) {
    return `sum_over_time(mysql_table_rows{service="${service}"}[5m]) > ${threshold || 20}`;
  }
  if (text.includes("cpu")) {
    return `avg_over_time(cpu_usage_percent{service="${service}"}[5m]) > ${threshold || 85}`;
  }
  if (text.includes("memory")) {
    return `avg_over_time(memory_usage_percent{service="${service}"}[5m]) > ${threshold || 85}`;
  }
  return `vector(1)`;
}

function inferRuleDuration(requirement) {
  const match = String(requirement || "").match(/for\s+([0-9]+)\s*(minutes?|mins?|m|hours?|hrs?|h)\b/i);
  if (!match) {
    return "5m";
  }
  const value = match[1];
  const unit = String(match[2] || "m").toLowerCase();
  return unit.startsWith("h") ? `${value}h` : `${value}m`;
}

function inferRuleSeverity(requirement) {
  const text = String(requirement || "").toLowerCase();
  if (text.includes("critical")) return "critical";
  if (text.includes("high")) return "high";
  if (text.includes("low")) return "low";
  if (text.includes("info")) return "info";
  return "warning";
}

function buildPrometheusRulePreview({ projectName, serviceName, environment, requirements }) {
  const project = slugForPrometheus(projectName || serviceName || "kaiops-project");
  const service = String(serviceName || project).trim() || project;
  const env = String(environment || "prod").trim() || "prod";
  const lines = (Array.isArray(requirements) ? requirements : [])
    .map((item) => String(item || "").trim())
    .filter(Boolean);
  const ruleLines = lines.length ? lines : [`Alert when ${service} is unavailable for 5 minutes.`];
  const rendered = ruleLines.map((line, index) => {
    const severity = inferRuleSeverity(line);
    const name = `${project}-${slugForPrometheus(line).slice(0, 52) || `rule-${index + 1}`}-${severity}`;
    const expr = inferPrometheusExpression(line, service);
    const duration = inferRuleDuration(line);
    return [
      `    - alert: ${name}`,
      `      expr: ${expr}`,
      `      for: ${duration}`,
      "      labels:",
      `        severity: ${severity}`,
      `        project: ${project}`,
      `        service: ${service}`,
      `        environment: ${env}`,
      "      annotations:",
      `        summary: ${yamlQuote(line)}`,
      `        description: ${yamlQuote(`Generated from KaiOps guided setup for ${project}.`)}`,
    ].join("\n");
  });
  return [
    "groups:",
    `  - name: ${project}-generated-rules`,
    "    rules:",
    ...rendered,
  ].join("\n");
}

function summarizeAlertRuleContext(row, workflow = {}) {
  const alertRow = row && typeof row === "object" ? row : {};
  const alertLabels = typeof alertRow.labels === "object" && alertRow.labels ? alertRow.labels : {};
  const alertAnnotations = typeof alertRow.annotations === "object" && alertRow.annotations ? alertRow.annotations : {};
  const workflowPayload = workflow && typeof workflow === "object" ? workflow : {};
  const recommendation = typeof workflowPayload.recommendation === "object" && workflowPayload.recommendation ? workflowPayload.recommendation : {};
  const recommendationMetadata = typeof recommendation.metadata === "object" && recommendation.metadata ? recommendation.metadata : {};
  const candidates = [
    alertRow.rule_name,
    alertRow.rule,
    alertRow.alert_rule,
    alertRow.rule_expression,
    alertRow.rule_query,
    alertLabels.rule_name,
    alertLabels.alertname,
    alertLabels.alert,
    alertLabels.rule,
    recommendationMetadata.rule_name,
    recommendationMetadata.rule,
  ]
    .map((value) => String(value || "").trim())
    .filter(Boolean);
  const expressionCandidates = [
    alertRow.expression,
    alertRow.expr,
    alertRow.query,
    alertRow.rule_expression,
    alertRow.rule_query,
    recommendationMetadata.rule_expression,
    recommendationMetadata.rule_query,
    alertAnnotations.expression,
    alertAnnotations.query,
  ]
    .map((value) => String(value || "").trim())
    .filter(Boolean);

  const ruleName = candidates[0] || String(alertRow.name || alertRow.alert_name || alertLabels.alertname || "Alert Rule").trim();
  const expression = expressionCandidates[0] || "No explicit rule expression was surfaced in the incident payload.";
  const service = String(alertRow.service || alertLabels.service || recommendationMetadata.service || "").trim();
  const environment = String(alertRow.environment || alertLabels.environment || recommendationMetadata.environment || "").trim();
  const note = [service ? `service=${service}` : "", environment ? `environment=${environment}` : ""].filter(Boolean).join(" | ");
  const expandRuleValues = (value) => {
    if (Array.isArray(value)) return value;
    if (value && typeof value === "object") return Object.values(value);
    const text = String(value || "").trim();
    if (!text) return [];
    try {
      const parsed = JSON.parse(text);
      if (Array.isArray(parsed)) return parsed;
    } catch (_error) {
      // Plain rule names can be comma or newline separated.
    }
    return text.split(/\r?\n|,\s*(?=[A-Za-z])/);
  };
  const rules = [
    ...candidates,
    ...expandRuleValues(alertRow.rules),
    ...expandRuleValues(alertRow.matched_rules),
    ...expandRuleValues(alertRow.correlated_rules),
    ...expandRuleValues(alertLabels.rules),
    ...expandRuleValues(alertLabels.matched_rules),
    ...expandRuleValues(alertLabels.correlated_rules),
    ...expandRuleValues(recommendationMetadata.rules),
    ...expandRuleValues(recommendationMetadata.matched_rules),
  ]
    .map((value, index) => {
      const item = value && typeof value === "object" ? value : {};
      const name = String(item.name || item.rule_name || item.alert || value || "").trim();
      const ruleExpression = String(item.expression || item.expr || item.query || (index === 0 ? expressionCandidates[0] : "") || "").trim();
      return name ? { name, expression: ruleExpression } : null;
    })
    .filter(Boolean)
    .filter((item, index, all) => all.findIndex((candidate) => candidate.name.toLowerCase() === item.name.toLowerCase()) === index);
  if (!rules.length) {
    rules.push({ name: ruleName, expression: expressionCandidates[0] || "" });
  }

  return {
    ruleName: rules[0]?.name || ruleName,
    expression,
    rules,
    summary: compactText(alertAnnotations.summary || alertRow.summary || alertRow.description, 220) || "No concise incident summary was supplied.",
    note: note || "Derived from alert labels and workflow metadata.",
    source: String(alertRow.source || alertRow.provider || alertLabels.job || "payload metadata").trim(),
    severity: String(alertRow.severity || alertLabels.severity || recommendation?.severity || "warning").trim().toLowerCase(),
  };
}

function buildWorkflowFlowStages(workflow, timelineRows = []) {
  const safeWorkflow = workflow && typeof workflow === "object" ? workflow : {};
  const safeRows = Array.isArray(timelineRows) ? timelineRows : [];
  const findStage = (needle) => safeRows.find((row) => String(row?.stage || row?.agent || row?.detail || "").toLowerCase().includes(needle));
  const hasParallelProcessing = safeRows.some((row) => {
    const token = String(row?.agent || row?.service || row?.detail || "").toLowerCase();
    return token.includes("alert intelligence") || token.includes("orchestrator") || token.includes("context") || token.includes("resolution");
  });
  return [
    {
      id: "landing-pad",
      label: "Landing Pad",
      detail: "Raw alerts are accepted, normalized, and added to the incident stream.",
      status: findStage("landing") ? "done" : "active",
    },
    {
      id: "parallel-processing",
      label: "Parallel Processing",
      detail: hasParallelProcessing
        ? "Alert intelligence, orchestration, context, and resolution work the stream in parallel workers."
        : "Backend workers fan out the alert stream through independent services for concurrent processing.",
      status: hasParallelProcessing ? "done" : "active",
    },
    {
      id: "approval",
      label: "Approval Gate",
      detail: String(safeWorkflow?.approval?.status || safeWorkflow?.decision?.status || "pending").trim(),
      status: safeWorkflow?.approval?.status ? "done" : "active",
    },
    {
      id: "remediation",
      label: "Remediation Execution",
      detail: `${Array.isArray(safeWorkflow?.remediation_action?.parameters?.execution_plan?.commands) ? safeWorkflow.remediation_action.parameters.execution_plan.commands.length : 0} commands captured for execution or review.`,
      status: safeWorkflow?.remediation_action?.status ? "done" : "active",
    },
    {
      id: "closure",
      label: "Closure & Validation",
      detail: String(safeWorkflow?.closure_report?.health_restored ? "Service restored and closure completed." : "Validation continues after remediation.").trim(),
      status: safeWorkflow?.closure_report?.health_restored ? "done" : "active",
    },
  ];
}

export default function App() {
  const defaultMonitorApplications = FIXED_MONITOR_SCOPES;
  const [applicationToMonitor, setApplicationToMonitor] = useState("KaiOps");
  const [monitorApplications, setMonitorApplications] = useState(defaultMonitorApplications);
  const [activeTab, setActiveTab] = useState("home");
  const [uiDensity, setUiDensity] = useState("comfortable");
  const [uiTheme, setUiTheme] = useState("auto");
  const [health, setHealth] = useState({ loading: false, ok: false, message: "Not checked" });
  const [alerts, setAlerts] = useState({ loading: false, rows: [], error: "" });
  const [alertsLimit, setAlertsLimit] = useState(25);
  const [alertSeverityOverrides, setAlertSeverityOverrides] = useState({ loading: false, rows: [], error: "", savingKey: "" });
  const [alertSeverityDrafts, setAlertSeverityDrafts] = useState({});
  const [dashboardAlertQuery, setDashboardAlertQuery] = useState("");
  const [dashboardAlertFocus, setDashboardAlertFocus] = useState("all");
  const [incidentMetadata, setIncidentMetadata] = useState({ loading: false, rows: [], error: "" });
  const [closedIncidents, setClosedIncidents] = useState({ loading: false, rows: [], error: "" });
  const [flows, setFlows] = useState({ loading: false, rows: [], error: "" });
  const [gatewaySummary, setGatewaySummary] = useState({ loading: false, data: {}, error: "" });
  const [gatewayRecent, setGatewayRecent] = useState({ loading: false, rows: [], error: "" });
  const [modelProviderStatus, setModelProviderStatus] = useState({ loading: false, data: null, error: "" });
  const [landingPadRecent, setLandingPadRecent] = useState({ loading: false, rows: [], error: "" });
  const [ingestionStreamChannel, setIngestionStreamChannel] = useState("all");
  const [ingestionStreamQuery, setIngestionStreamQuery] = useState("");
  const [ragDocs, setRagDocs] = useState({ loading: false, rows: [], error: "" });
  const [guidanceQuery, setGuidanceQuery] = useState("");
  const [guidanceState, setGuidanceState] = useState({ loading: false, rows: [], error: "" });
  const [submitState, setSubmitState] = useState({ loading: false, result: null, error: "" });
  const [workflowState, setWorkflowState] = useState({ loading: false, result: null, error: "" });
  const [approvalState, setApprovalState] = useState({ loading: false, result: null, error: "" });
  const [inlineRejectState, setInlineRejectState] = useState({ incidentId: "", comment: "" });
  const [showAdvancedApprovalForm, setShowAdvancedApprovalForm] = useState(false);
  const [approvalFilter, setApprovalFilter] = useState("all");
  const [approvalIncidentContext, setApprovalIncidentContext] = useState({
    loading: false,
    incident_id: "",
    payload: null,
    error: "",
  });
  const [selectedAlertId, setSelectedAlertId] = useState("");
  const alertStreamRefreshInFlight = useRef(false);
  const [selectedApprovalIncidentId, setSelectedApprovalIncidentId] = useState("");
  const [selectedAlertData, setSelectedAlertData] = useState({ loading: false, payload: null, error: "", alertId: "" });
  const [selectedAlertDocumentLinks, setSelectedAlertDocumentLinks] = useState({
    loading: false,
    alertId: "",
    rows: [],
    canonicalAlert: null,
    contract: null,
    error: "",
  });
  const [selectedStageCompleteness, setSelectedStageCompleteness] = useState({
    loading: false,
    data: null,
    error: "",
    incidentId: "",
  });
  const [homeDetailTab, setHomeDetailTab] = useState("timeline");
  const [diagnosticsDetailTab, setDiagnosticsDetailTab] = useState("pipeline");
  const [approvalForm, setApprovalForm] = useState({
    action: "approve",
    incident_id: "",
    recommendation_id: "",
    approver: "admin",
    channel: "web",
    comment: "",
    modified_action: "",
  });
  const [remediationPlanEditor, setRemediationPlanEditor] = useState({
    commands: "",
    scripts: "",
    queries: "",
    connection_url: "",
    connection_type: "application",
    namespace: "",
    notes: "",
  });
  const [remediationExecutionState, setRemediationExecutionState] = useState({ loading: false, result: null, error: "" });
  const [selectedFlow, setSelectedFlow] = useState("payment-latency");
  const [metadataFilters, setMetadataFilters] = useState({
    risk_tier: "all",
    execution_mode: "all",
    transport_provider: "all",
    status: "all",
    service: "",
  });
  const [closedFilters, setClosedFilters] = useState({ risk: "all", mode: "all" });
  const [form, setForm] = useState(DEFAULT_ALERT);
  const [adminWorkspace, setAdminWorkspace] = useState("users");
  const [adminAuthForm, setAdminAuthForm] = useState({ username: "admin", password: "", device: "react-ui" });
  const [adminSession, setAdminSession] = useState({ loading: false, accessToken: "", refreshToken: "", user: null, error: "" });
  const [adminRoles, setAdminRoles] = useState([]);
  const [adminUsers, setAdminUsers] = useState({ loading: false, rows: [], error: "" });
  const [adminCreateUser, setAdminCreateUser] = useState({
    username: "",
    email: "",
    password: "",
    first_name: "",
    last_name: "",
    role_id: 1,
    status: "active",
    is_active: true,
  });
  const [adminEditUser, setAdminEditUser] = useState({
    id: null,
    username: "",
    email: "",
    first_name: "",
    last_name: "",
    role_id: 1,
    status: "active",
    is_active: true,
  });
  const [adminEditPanelOpen, setAdminEditPanelOpen] = useState(false);
  const [adminResetPasswordForm, setAdminResetPasswordForm] = useState({ user_id: null, new_password: "" });
  const [onboardingForm, setOnboardingForm] = useState({
    name: "kaiops-project",
    owner_team: "platform-ops",
    environment: "prod",
    region: "us-east-1",
    deployment_mode: "on_prem",
    monitoring_tool: "prometheus",
    monitoring_url: "http://prometheus:9090",
    prometheus_url: "http://prometheus:9090",
    new_relic_url: "",
    datadog_url: "",
    azure_subscription_id: "",
    azure_resource_group: "",
    azure_service_bus_namespace: "",
    azure_service_bus_topic: "kaiops-orchestration-events",
    azure_service_bus_subscription: "kaiops-orchestration-sub",
    azure_content_safety_enabled: false,
    azure_content_safety_endpoint: "",
    assignment_username: "",
    assignment_project: "",
    onboarding_path: "setup_monitoring",
    start_rule_onboarding: true,
    service_knowledge_prompt: "",
    rule_onboarding_plain_language: "",
  });
  const [onboardingState, setOnboardingState] = useState({ loading: false, connectivity: {}, rows: [], error: "", success: "" });
  const [onboardingRuleCapabilities, setOnboardingRuleCapabilities] = useState({ loading: false, rows: [], error: "" });
  const [onboardingRuleWizardStep, setOnboardingRuleWizardStep] = useState(1);
  const [onboardingRuleWizardMode, setOnboardingRuleWizardMode] = useState("existing");
  const [existingRulePipelineForm, setExistingRulePipelineForm] = useState({
    platform: "prometheus",
    mode: "bidirectional",
    connection_url: "",
    rules_json: JSON.stringify([
      {
        name: "project_cpu_high",
        metric: "cpu_usage_percent",
        threshold: 85,
        duration: "5m",
        aggregation: "avg",
        severity: "high",
        labels: { project: "kaiops-project" },
      },
    ], null, 2),
  });
  const [newRulePipelineForm, setNewRulePipelineForm] = useState({
    requirements_text: [
      "Alert if CPU stays above 80% for more than 5 minutes with high severity",
      "Alert when latency is over 2000 for 10 minutes critical",
    ].join("\n"),
    selected_tool: "prometheus",
  });
  const [onboardingProjectMode, setOnboardingProjectMode] = useState("existing");
  const [onboardingRuleRunState, setOnboardingRuleRunState] = useState({ loading: false, result: null, error: "" });
  const [onboardingWorkflowSteps, setOnboardingWorkflowSteps] = useState([]);
  const [onboardingLandingPadSummary, setOnboardingLandingPadSummary] = useState({});
  const [onboardingGeneratedDocs, setOnboardingGeneratedDocs] = useState([]);
  const [onboardingSourceDocs, setOnboardingSourceDocs] = useState({ loading: false, rows: [], error: "" });
  const [knowledgePackState, setKnowledgePackState] = useState({
    loading: false,
    draft: null,
    error: "",
    success: "",
    approved: false,
  });
  const [knowledgePackCorrections, setKnowledgePackCorrections] = useState({});
  // Backend re-validation results for manually corrected fields, keyed by fact key.
  // Populated by revalidateKnowledgeCorrections(); until a field has been re-validated
  // here, its correction is treated as unverified rather than auto-"accepted".
  const [knowledgePackRevalidation, setKnowledgePackRevalidation] = useState({ loading: false, error: "", facts: {}, validatedCorrections: {} });
  const [onboardingReviewAck, setOnboardingReviewAck] = useState({ rules: false, docs: false, metadata: false });
  const [onboardingDocApprovalState, setOnboardingDocApprovalState] = useState({
    loading: false,
    error: "",
    success: "",
    approved: false,
  });
  const [onboardingRuleLookup, setOnboardingRuleLookup] = useState({ workflow_id: "", loading: false, result: null, error: "" });
  const [selectedOnboardingProject, setSelectedOnboardingProject] = useState("");
  const [monitoringAppForm, setMonitoringAppForm] = useState({
    tenant_id: "default",
    name: "",
    owner_team: "platform-ops",
    owner_email: "",
    environment: "prod",
    namespace: "default",
    region: "us-east-1",
    technology: "python-fastapi",
    metrics_endpoint: "http://api-gateway:8000/metrics",
    labels_text: "security=internal,compliance=sox,workload_kind=Deployment",
  });
  const [monitoringApps, setMonitoringApps] = useState({ loading: false, rows: [], error: "" });
  const [monitoringAppSubmit, setMonitoringAppSubmit] = useState({ loading: false, error: "", success: "" });
  const [selectedMonitoringAppId, setSelectedMonitoringAppId] = useState("");
  const [monitoringAppDetails, setMonitoringAppDetails] = useState({ loading: false, history: [], validations: [], dashboards: [], error: "" });
  const [onboardingRuleEditor, setOnboardingRuleEditor] = useState({
    workflow_id: "",
    project_name: "",
    payload_json: "",
  });
  const [onboardingRuleEditorState, setOnboardingRuleEditorState] = useState({ loading: false, error: "", success: "" });
  const [alertOnboarding, setAlertOnboarding] = useState({
    kind: "incident",
    title: "New Alert Onboarding",
    summary: "",
    content: "Provide troubleshooting and escalation steps for this alert scenario.",
    services: "payments",
    severity: "high",
    alert_type: "availability",
    alert_id: "",
    execution_plan: "",
    remediation_commands_text: "",
    remediation_scripts_text: "",
    remediation_queries_text: "",
  });
  const [alertKnowledgePrompt, setAlertKnowledgePrompt] = useState("");
  const [alertKnowledgeSourceDoc, setAlertKnowledgeSourceDoc] = useState({
    loading: false,
    name: "",
    size: 0,
    text: "",
    excerpt: "",
    error: "",
  });
  const [alertKnowledgeView, setAlertKnowledgeView] = useState("onboarding");
  const [projectSetupStep, setProjectSetupStep] = useState("docs_rules");
  const [projectSetupShowAll, setProjectSetupShowAll] = useState(false);
  const [alertOnboardingState, setAlertOnboardingState] = useState({ loading: false, result: null, error: "" });
  const [docPromptAlert, setDocPromptAlert] = useState(null);
  const [docPromptKind, setDocPromptKind] = useState("runbook");
  const [docPromptMode, setDocPromptMode] = useState("create");
  const [docPromptExistingDoc, setDocPromptExistingDoc] = useState(null);
  const [docPromptDocsByKind, setDocPromptDocsByKind] = useState({});
  const [alertRuleDraft, setAlertRuleDraft] = useState({ platform: "prometheus", requirement: "" });
  const [alertRuleState, setAlertRuleState] = useState({ loading: false, result: null, error: "" });
  const alertDetailsRef = useRef(null);
  const docPromptRef = useRef(null);
  const approvalQueueRef = useRef(null);
  const monitoringInspectRef = useRef(null);
  const alertKnowledgeRef = useRef(null);
  const approvalIncidentRequestRef = useRef({ incidentId: "", inFlight: false, lastFetchedAt: 0 });
  const healthRequestRef = useRef(0);
  const recentAlertsRequestRef = useRef({ inFlight: false, requestId: "", startedAt: 0 });
  const incidentMetadataRequestRef = useRef(false);
  const closedIncidentsRequestRef = useRef(false);

  const formValid = useMemo(() => {
    return [form.source, form.name, form.service, form.severity, form.description].every((v) => String(v || "").trim());
  }, [form]);

  async function checkHealth() {
    const requestId = Date.now() + Math.floor(Math.random() * 1000);
    healthRequestRef.current = requestId;
    setHealth({ loading: true, ok: false, message: "Checking API Gateway..." });
    try {
      const data = await fetchJson("/api-gateway/healthz", { timeoutMs: 10000 });
      if (healthRequestRef.current !== requestId) {
        return;
      }
      setHealth({ loading: false, ok: data?.status === "ok", message: `${data?.service || "api-gateway"} is ${data?.status || "unknown"}` });
      loadMonitorApplications().catch(() => {});
    } catch (error) {
      if (healthRequestRef.current !== requestId) {
        return;
      }
      setHealth({ loading: false, ok: false, message: error.message });
    }
  }

  function unwrap(payload) {
    return payload?.data || payload || {};
  }

  async function loadRecentAlerts(options = {}) {
    const background = Boolean(options && options.background);
    if (recentAlertsRequestRef.current.inFlight) {
      const startedAt = Number(recentAlertsRequestRef.current.startedAt || 0);
      if (startedAt && Date.now() - startedAt > 15000) {
        recentAlertsRequestRef.current = { inFlight: false, requestId: "", startedAt: 0 };
      } else {
        return;
      }
    }
    if (recentAlertsRequestRef.current.inFlight) {
      return;
    }
    const requestId = `${Date.now()}-${Math.floor(Math.random() * 1000)}`;
    recentAlertsRequestRef.current = { inFlight: true, requestId, startedAt: Date.now() };
    setAlerts((prev) => ({ ...prev, loading: !background, error: "" }));
    try {
      const [payload, landingPayload] = await Promise.all([
        fetchJson(`/api-gateway/alerts/all?limit=${alertsLimit}`, {
          timeoutMs: background ? 6000 : 7000,
          maxAttempts: 1,
        }),
        fetchJson(`/api-gateway/landing-pad/recent?limit=${Math.min(Math.max(alertsLimit, 50), 200)}`, {
          timeoutMs: background ? 6000 : 7000,
          maxAttempts: 1,
        }).catch(() => null),
      ]);
      const data = unwrap(payload);
      const rows = data?.rows || [];
      const landingRowsRaw = unwrap(landingPayload)?.rows;
      const landingRows = (Array.isArray(landingRowsRaw) ? landingRowsRaw : [])
        .filter((row) => String(row?.status || "").trim().toLowerCase() !== "failed")
        .map((row, index) => mapLandingPadRowToAlertStreamRow(row, index));
      const mergedRows = dedupeAndConsolidateAlertRows([
        ...(Array.isArray(rows) ? rows : []),
        ...landingRows,
      ]);
      if (recentAlertsRequestRef.current.requestId !== requestId) {
        return;
      }
      setAlerts({ loading: false, rows: mergedRows, error: "" });
    } catch (error) {
      if (background) {
        if (recentAlertsRequestRef.current.requestId !== requestId) {
          return;
        }
        setAlerts((prev) => ({
          loading: false,
          rows: Array.isArray(prev.rows) ? prev.rows : [],
          error: Array.isArray(prev.rows) && prev.rows.length ? "" : String(error?.message || "Unable to refresh alerts"),
        }));
        return;
      }
      try {
        const fallbackPayload = await fetchJson(`/api-gateway/landing-pad/recent?limit=${alertsLimit}`, {
          timeoutMs: 7000,
          maxAttempts: 1,
        });
        const fallbackRowsRaw = unwrap(fallbackPayload)?.rows;
        const fallbackRows = (Array.isArray(fallbackRowsRaw) ? fallbackRowsRaw : []).map((row, index) => mapLandingPadRowToAlertStreamRow(row, index));
        if (recentAlertsRequestRef.current.requestId !== requestId) {
          return;
        }
        setAlerts({
          loading: false,
          rows: fallbackRows,
          error: fallbackRows.length ? "Primary alert endpoint is slow. Showing latest landing-pad ingestion." : String(error?.message || "Unable to load alerts"),
        });
        return;
      } catch (_fallbackError) {
        // Fall through to existing error path if fallback also fails.
      }
      if (recentAlertsRequestRef.current.requestId !== requestId) {
        return;
      }
      setAlerts((prev) => ({
        loading: false,
        rows: Array.isArray(prev.rows) ? prev.rows : [],
        error: background && Array.isArray(prev.rows) && prev.rows.length ? "" : error.message,
      }));
    } finally {
      if (recentAlertsRequestRef.current.requestId === requestId) {
        recentAlertsRequestRef.current = { inFlight: false, requestId: "", startedAt: 0 };
      }
    }
  }

  async function loadAlertSeverityOverrides() {
    setAlertSeverityOverrides((prev) => ({ ...prev, loading: true, error: "" }));
    try {
      const payload = await fetchJson("/api-gateway/alerts/severity-overrides");
      const data = unwrap(payload);
      const rows = Array.isArray(data?.rows) ? data.rows : [];
      setAlertSeverityOverrides((prev) => ({ ...prev, loading: false, rows, error: "" }));
    } catch (error) {
      setAlertSeverityOverrides((prev) => ({ ...prev, loading: false, rows: [], error: error.message }));
    }
  }

  async function applyAlertSeverityOverrideRule(row) {
    const alertName = String(row?.name || row?.alert_name || "").trim();
    const service = String(row?.service || "").trim();
    const environment = String(row?.environment || "").trim();
    const key = severityOverrideKey(alertName, service, environment);
    const draftSeverity = String(alertSeverityDrafts[key] || row?.severity || "warning").trim().toLowerCase();
    if (!alertName) {
      setAlertSeverityOverrides((prev) => ({ ...prev, error: "Alert name is required for severity override." }));
      return;
    }
    setAlertSeverityOverrides((prev) => ({ ...prev, savingKey: key, error: "" }));
    try {
      await fetchJson("/api-gateway/alerts/severity-overrides", {
        method: "PUT",
        body: JSON.stringify({
          name: alertName,
          service,
          environment,
          severity: draftSeverity,
          requested_by: String(adminSession?.user?.username || "ui-user").trim(),
          requested_role: String(currentRole || "").trim(),
          updated_at: new Date().toISOString(),
        }),
      });
      await loadAlertSeverityOverrides();
      setAlertSeverityOverrides((prev) => ({ ...prev, savingKey: "", error: "" }));
    } catch (error) {
      setAlertSeverityOverrides((prev) => ({ ...prev, savingKey: "", error: error.message }));
    }
  }

  async function clearAlertSeverityOverrideRule(row) {
    const alertName = String(row?.name || row?.alert_name || "").trim();
    const service = String(row?.service || "").trim();
    const environment = String(row?.environment || "").trim();
    const key = severityOverrideKey(alertName, service, environment);
    if (!alertName) {
      return;
    }
    setAlertSeverityOverrides((prev) => ({ ...prev, savingKey: key, error: "" }));
    try {
      const params = new URLSearchParams({ name: alertName, service, environment });
      await fetchJson(`/api-gateway/alerts/severity-overrides?${params.toString()}`, { method: "DELETE" });
      await loadAlertSeverityOverrides();
      setAlertSeverityOverrides((prev) => ({ ...prev, savingKey: "", error: "" }));
    } catch (error) {
      setAlertSeverityOverrides((prev) => ({ ...prev, savingKey: "", error: error.message }));
    }
  }

  async function loadMonitoringApplications() {
    setMonitoringApps((prev) => ({ ...prev, loading: true, error: "" }));
    try {
      const payload = await fetchJson("/api-gateway/applications", authenticatedOptions());
      const data = unwrap(payload);
      const rows = Array.isArray(data?.rows) ? data.rows : [];
      setMonitoringApps({ loading: false, rows, error: "" });
      setSelectedMonitoringAppId((current) => {
        const normalizedCurrent = String(current || "").trim();
        if (normalizedCurrent && rows.some((row) => String(row?.id || "").trim() === normalizedCurrent)) {
          return normalizedCurrent;
        }
        return String(rows[0]?.id || "").trim();
      });
    } catch (error) {
      setMonitoringApps({ loading: false, rows: [], error: error.message });
    }
  }

  async function loadMonitoringApplicationDetails(applicationId) {
    const normalized = String(applicationId || "").trim();
    if (!normalized) {
      setMonitoringAppDetails({ loading: false, history: [], validations: [], dashboards: [], error: "" });
      return;
    }
    setMonitoringAppDetails((prev) => ({ ...prev, loading: true, error: "" }));
    try {
      const [historyPayload, validationsPayload, dashboardsPayload] = await Promise.all([
        fetchJson(`/api-gateway/applications/${normalized}/history`, authenticatedOptions()),
        fetchJson(`/api-gateway/applications/${normalized}/validations`, authenticatedOptions()),
        fetchJson(`/api-gateway/applications/${normalized}/dashboards`, authenticatedOptions()),
      ]);
      const historyRows = Array.isArray(unwrap(historyPayload)?.rows) ? unwrap(historyPayload).rows : [];
      const validationRows = Array.isArray(unwrap(validationsPayload)?.rows) ? unwrap(validationsPayload).rows : [];
      const dashboardRows = Array.isArray(unwrap(dashboardsPayload)?.rows) ? unwrap(dashboardsPayload).rows : [];
      setMonitoringAppDetails({ loading: false, history: historyRows, validations: validationRows, dashboards: dashboardRows, error: "" });
    } catch (error) {
      setMonitoringAppDetails({ loading: false, history: [], validations: [], dashboards: [], error: error.message });
    }
  }

  async function submitMonitoringApplication(event) {
    event.preventDefault();
    setMonitoringAppSubmit({ loading: true, error: "", success: "" });
    try {
      const metricsEndpoint = String(monitoringAppForm.metrics_endpoint || "").trim() || "http://api-gateway:8000/metrics";
      if (!/^https?:\/\//i.test(metricsEndpoint)) {
        setMonitoringAppSubmit({
          loading: false,
          error: "Metrics Endpoint must start with http:// or https:// (for example, http://api-gateway:8000/metrics).",
          success: "",
        });
        return;
      }
      const labels = Object.fromEntries(
        String(monitoringAppForm.labels_text || "")
          .split(",")
          .map((entry) => entry.trim())
          .filter(Boolean)
          .map((entry) => {
            const [key, ...rest] = entry.split("=");
            return [String(key || "").trim(), rest.join("=").trim()];
          })
          .filter(([key]) => key)
      );
      const payload = {
        tenant_id: monitoringAppForm.tenant_id,
        name: monitoringAppForm.name,
        owner_team: monitoringAppForm.owner_team,
        owner_email: monitoringAppForm.owner_email || null,
        environment: monitoringAppForm.environment,
        namespace: monitoringAppForm.namespace,
        region: monitoringAppForm.region,
        technology: monitoringAppForm.technology,
        metrics_endpoint: metricsEndpoint,
        monitoring_platform: "prometheus",
        labels,
      };
      await fetchJson("/api-gateway/applications", authenticatedOptions({
        method: "POST",
        body: JSON.stringify(payload),
      }));
      setMonitoringAppSubmit({ loading: false, error: "", success: `Queued onboarding for ${monitoringAppForm.name}` });
      setMonitoringAppForm((curr) => ({ ...curr, name: "", owner_email: "", metrics_endpoint: "http://api-gateway:8000/metrics" }));
      await loadMonitoringApplications();
      await loadMonitorApplications();
      await refreshViewsAfterSubmit();
    } catch (error) {
      setMonitoringAppSubmit({ loading: false, error: error.message, success: "" });
    }
  }

  async function loadAlertDetails(alertId, fallbackRow = null) {
    const normalized = String(alertId || "").trim();
    if (!normalized) {
      return;
    }
    if (!ALERT_UUID_PATTERN.test(normalized)) {
      const landingAlert = fallbackRow && typeof fallbackRow === "object" ? fallbackRow : {};
      setSelectedAlertData({
        loading: false,
        payload: {
          data: {
            alert: landingAlert,
            incident: null,
            context: {
              metadata: {
                source: landingAlert.source || "landing-pad",
                origin_system: landingAlert.origin_system || landingAlert.labels?.origin_system || "",
                ingestion_channel: landingAlert.ingestion_channel || landingAlert.labels?.ingestion_channel || "",
                processing_state: "landing_pad_only",
              },
            },
            timeline: [],
          },
        },
        error: "",
        alertId: normalized,
      });
      return;
    }
    setSelectedAlertData((prev) => ({
      loading: true,
      payload: String(prev.alertId || "") === normalized ? prev.payload : null,
      error: "",
      alertId: normalized,
    }));
    try {
      const payload = await fetchJson(`/monitoring-adapter/alerts/${normalized}/processed-result`, { timeoutMs: 25000 });
      setSelectedAlertData((prev) => {
        if (String(prev.alertId || "") !== normalized) {
          return prev;
        }
        return { loading: false, payload, error: "", alertId: normalized };
      });
    } catch (error) {
      setSelectedAlertData((prev) => {
        if (String(prev.alertId || "") !== normalized) {
          return prev;
        }
        return {
          loading: false,
          payload: prev.payload,
          error: String(error?.message || "Unable to load processed alert details"),
          alertId: normalized,
        };
      });
    }
  }

  async function loadSelectedAlertDocumentLinks(alertId, fallbackRow = null) {
    const normalized = String(alertId || "").trim();
    if (!normalized) {
      setSelectedAlertDocumentLinks({ loading: false, alertId: "", rows: [], canonicalAlert: null, contract: null, error: "" });
      return;
    }
    if (!ALERT_UUID_PATTERN.test(normalized)) {
      setSelectedAlertDocumentLinks({
        loading: false,
        alertId: normalized,
        rows: [],
        canonicalAlert: fallbackRow && typeof fallbackRow === "object" ? fallbackRow : null,
        contract: {
          document_link_summary: {
            count: 0,
            source: "landing-pad-local-fallback",
            processing_state: "landing_pad_only",
          },
        },
        error: "",
      });
      return;
    }
    setSelectedAlertDocumentLinks((current) => ({
      ...current,
      loading: true,
      alertId: normalized,
      error: "",
    }));
    try {
      const payload = await fetchJson(`/api-gateway/alerts/${encodeURIComponent(normalized)}/linked-documents?limit=${alertsLimit}`);
      const data = unwrap(payload);
      const rows = Array.isArray(data?.linked_documents) ? data.linked_documents : [];
      setSelectedAlertDocumentLinks((current) => {
        if (String(current.alertId || "") !== normalized) {
          return current;
        }
        return {
          loading: false,
          alertId: normalized,
          rows,
          canonicalAlert: data?.canonical_alert || null,
          contract: data || null,
          error: "",
        };
      });
    } catch (error) {
      setSelectedAlertDocumentLinks((current) => {
        if (String(current.alertId || "") !== normalized) {
          return current;
        }
        return {
          ...current,
          loading: false,
          rows: [],
          canonicalAlert: null,
          contract: null,
          error: String(error?.message || "Unable to load linked documents"),
        };
      });
    }
  }

  async function loadIncidentStageCompleteness(incidentId) {
    const normalized = String(incidentId || "").trim();
    if (!normalized) {
      setSelectedStageCompleteness({ loading: false, data: null, error: "", incidentId: "" });
      return;
    }
    setSelectedStageCompleteness({ loading: true, data: null, error: "", incidentId: normalized });
    try {
      const payload = await fetchJson(`/api-gateway/incidents/${normalized}/stage-completeness`);
      const stageData = payload?.data || payload;
      setSelectedStageCompleteness((prev) => {
        if (String(prev.incidentId || "") !== normalized) {
          return prev;
        }
        return { loading: false, data: stageData, error: "", incidentId: normalized };
      });
    } catch (error) {
      setSelectedStageCompleteness((prev) => {
        if (String(prev.incidentId || "") !== normalized) {
          return prev;
        }
        return { loading: false, data: null, error: error.message, incidentId: normalized };
      });
    }
  }

  function openAlertDetails(row) {
    const canonicalRow = resolveCanonicalAlertRow(row, alerts.rows);
    const alertId = canonicalRow?.alert_id || canonicalRow?.id || canonicalRow?.incident_id;
    if (!alertId) {
      return;
    }
    setSelectedAlertId(String(alertId));
    setActiveTab("home");
    setHomeDetailTab("timeline");
    loadAlertDetails(alertId, canonicalRow);
    loadSelectedAlertDocumentLinks(alertId, canonicalRow);
  }

  function openAlertDetailsFromIncident(row) {
    const incidentId = String(row?.incident_id || row?.id || "").trim();
    if (!incidentId) {
      return;
    }
    setApprovalState({ loading: false, result: null, error: "" });
    const scopedAlerts = visibleAlerts;
    const matchedAlert = scopedAlerts.find((alertRow) => {
      const alertId = String(alertRow?.alert_id || alertRow?.id || alertRow?.incident_id || "").trim();
      const sourceIncident = String(alertRow?.incident_id || "").trim();
      return alertId === incidentId || sourceIncident === incidentId;
    });
    openAlertDetails(matchedAlert || row);
  }

  useEffect(() => {
    if (activeTab !== "home" || !selectedAlertId) {
      return;
    }
    if (typeof window === "undefined") {
      return;
    }
    window.requestAnimationFrame(() => {
      alertDetailsRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
    });
  }, [activeTab, selectedAlertId]);

  useEffect(() => {
    if (activeTab !== "home") {
      return;
    }
    const payload = selectedAlertData?.payload?.data || selectedAlertData?.payload || {};
    const workflow = payload?.workflow || payload || {};
    const currentIncidentId = String(workflow?.incident?.id || workflow?.incident_id || "").trim();

    if (!currentIncidentId) {
      setSelectedStageCompleteness({ loading: false, data: null, error: "", incidentId: "" });
      return;
    }
    if (
      String(selectedStageCompleteness.incidentId || "") === String(currentIncidentId)
      && (selectedStageCompleteness.data || selectedStageCompleteness.loading || selectedStageCompleteness.error)
    ) {
      return;
    }
    loadIncidentStageCompleteness(currentIncidentId);
  }, [activeTab, selectedAlertData.payload, selectedStageCompleteness.incidentId, selectedStageCompleteness.data, selectedStageCompleteness.loading, selectedStageCompleteness.error]);

  useEffect(() => {
    const scopedRows = mergeAlertStreamRows(
      filterAlertsForMonitor(alerts.rows, applicationToMonitor),
      filterRowsForMonitor(closedIncidents.rows, applicationToMonitor),
    );
    if (activeTab !== "home") {
      return;
    }
    if (!scopedRows.length) {
      if (selectedAlertId) {
        setSelectedAlertId("");
      }
      if (selectedAlertData.payload || selectedAlertData.error) {
        setSelectedAlertData({ loading: false, payload: null, error: "", alertId: "" });
      }
      return;
    }
    const selectedExists = scopedRows.some(
      (row) => String(row?.alert_id || row?.id || row?.incident_id || "") === selectedAlertId
    );
    if (selectedExists) {
      if (String(selectedAlertData.alertId || "") !== String(selectedAlertId || "")) {
        loadAlertDetails(selectedAlertId);
      }
      if (String(selectedAlertDocumentLinks.alertId || "") !== String(selectedAlertId || "")) {
        loadSelectedAlertDocumentLinks(selectedAlertId);
      }
      return;
    }
    openAlertDetails(scopedRows[0]);
  }, [activeTab, alerts.rows, closedIncidents.rows, applicationToMonitor, selectedAlertId, selectedAlertData.payload, selectedAlertData.error, selectedAlertData.alertId, selectedAlertDocumentLinks.alertId]);

  async function loadIncidentMetadata() {
    if (incidentMetadataRequestRef.current) {
      return;
    }
    incidentMetadataRequestRef.current = true;
    setIncidentMetadata((prev) => ({ ...prev, loading: true, error: "" }));
    try {
      const params = new URLSearchParams({ limit: "120" });
      if (metadataFilters.risk_tier !== "all") {
        params.set("risk_tier", metadataFilters.risk_tier);
      }
      if (metadataFilters.execution_mode !== "all") {
        params.set("execution_mode", metadataFilters.execution_mode);
      }
      if (metadataFilters.transport_provider !== "all") {
        params.set("transport_provider", metadataFilters.transport_provider);
      }
      if (metadataFilters.status !== "all") {
        params.set("status", metadataFilters.status);
      }
      if (String(metadataFilters.service || "").trim()) {
        params.set("service", String(metadataFilters.service).trim());
      }
      const payload = await fetchJson(`/api-gateway/incidents/metadata?${params.toString()}`);
      const data = unwrap(payload);
      const rows = data?.rows || [];
      setIncidentMetadata({ loading: false, rows: Array.isArray(rows) ? rows : [], error: "" });
    } catch (error) {
      setIncidentMetadata({ loading: false, rows: [], error: error.message });
    } finally {
      incidentMetadataRequestRef.current = false;
    }
  }

  async function loadClosedIncidents() {
    if (closedIncidentsRequestRef.current) {
      return;
    }
    closedIncidentsRequestRef.current = true;
    setClosedIncidents((prev) => ({ ...prev, loading: true, error: "" }));
    try {
      const payload = await fetchJson("/api-gateway/incidents/closed?limit=120", { timeoutMs: 12000 });
      const data = unwrap(payload);
      const rows = Array.isArray(data?.rows) ? data.rows : [];
      if (rows.length) {
        setClosedIncidents({ loading: false, rows, error: "" });
        return;
      }

      const [closedPayload, resolvedPayload, failedPayload] = await Promise.all([
        fetchJson("/api-gateway/incidents/metadata?limit=120&status=closed", { timeoutMs: 10000, maxAttempts: 2 }),
        fetchJson("/api-gateway/incidents/metadata?limit=120&status=resolved", { timeoutMs: 10000, maxAttempts: 2 }),
        fetchJson("/api-gateway/incidents/metadata?limit=120&status=failed", { timeoutMs: 10000, maxAttempts: 2 }),
      ]);
      const closedRows = Array.isArray(unwrap(closedPayload)?.rows) ? unwrap(closedPayload).rows : [];
      const resolvedRows = Array.isArray(unwrap(resolvedPayload)?.rows) ? unwrap(resolvedPayload).rows : [];
      const failedRows = Array.isArray(unwrap(failedPayload)?.rows) ? unwrap(failedPayload).rows : [];
      const merged = [...closedRows, ...resolvedRows, ...failedRows];
      const deduped = [];
      const seen = new Set();
      merged.forEach((row) => {
        const key = String(row?.incident_id || row?.id || "").trim();
        if (!key || seen.has(key)) {
          return;
        }
        seen.add(key);
        deduped.push(row);
      });
      setClosedIncidents({ loading: false, rows: deduped, error: "" });
    } catch (error) {
      setClosedIncidents({ loading: false, rows: [], error: error.message });
    } finally {
      closedIncidentsRequestRef.current = false;
    }
  }

  async function refreshApprovalDrivenViews(incidentId = "") {
    const normalizedIncidentId = String(incidentId || "").trim();
    const tasks = [
      loadRecentAlerts(),
      loadIncidentMetadata(),
      loadGatewayRecent(),
      loadGatewaySummary(),
      loadClosedIncidents(),
    ];

    if (selectedAlertId) {
      tasks.push(loadAlertDetails(selectedAlertId));
      tasks.push(loadSelectedAlertDocumentLinks(selectedAlertId));
    }

    if (selectedApprovalIncidentId && (!normalizedIncidentId || selectedApprovalIncidentId === normalizedIncidentId)) {
      tasks.push(loadApprovalIncidentContext(selectedApprovalIncidentId));
    }

    await Promise.all(tasks);
  }

  function refreshApprovalDrivenViewsSoon(incidentId = "") {
    window.setTimeout(() => {
      refreshApprovalDrivenViews(incidentId);
    }, 1200);
  }

  async function loadFlows() {
    setFlows((prev) => ({ ...prev, loading: true, error: "" }));
    try {
      const payload = await fetchJson("/api-gateway/sample/flows");
      const data = unwrap(payload);
      const rows = data?.flows || [];
      const normalizedRows = Array.isArray(rows) ? rows : [];
      const firstFlowId = normalizedRows[0]?.id || normalizedRows[0]?.flow_id;
      if (firstFlowId && !selectedFlow) {
        setSelectedFlow(firstFlowId);
      }
      setFlows({ loading: false, rows: normalizedRows, error: "" });
    } catch (error) {
      setFlows({ loading: false, rows: [], error: error.message });
    }
  }

  async function loadGatewaySummary() {
    setGatewaySummary((prev) => ({ ...prev, loading: true, error: "" }));
    try {
      const payload = await fetchJson("/api-gateway/observability/summary");
      setGatewaySummary({ loading: false, data: payload || {}, error: "" });
    } catch (error) {
      setGatewaySummary({ loading: false, data: {}, error: error.message });
    }
  }

  async function loadGatewayRecent() {
    setGatewayRecent((prev) => ({ ...prev, loading: true, error: "" }));
    try {
      const payload = await fetchJson("/api-gateway/observability/recent");
      const rows = payload?.events || [];
      setGatewayRecent({ loading: false, rows: Array.isArray(rows) ? rows : [], error: "" });
    } catch (error) {
      setGatewayRecent({ loading: false, rows: [], error: error.message });
    }
  }

  async function loadLandingPadRecent() {
    setLandingPadRecent((prev) => ({ ...prev, loading: true, error: "" }));
    try {
      const payload = await fetchJson("/api-gateway/landing-pad/recent?limit=200");
      const data = unwrap(payload);
      const rows = data?.rows || [];
      setLandingPadRecent({ loading: false, rows: Array.isArray(rows) ? rows : [], error: "" });
    } catch (error) {
      setLandingPadRecent({ loading: false, rows: [], error: error.message });
    }
  }

  async function loadRagDocs() {
    setRagDocs((prev) => ({ ...prev, loading: true, error: "" }));
    try {
      const payload = await fetchJson("/api-gateway/rag/documents");
      const rows = payload?.documents || payload?.data?.documents || [];
      setRagDocs({ loading: false, rows: Array.isArray(rows) ? rows : [], error: "" });
    } catch (error) {
      setRagDocs({ loading: false, rows: [], error: error.message });
    }
  }

  async function loadMonitorApplications() {
    try {
      const payload = await fetchJson("/api-gateway/applications", authenticatedOptions());
      const data = unwrap(payload);
      const applicationRows = Array.isArray(data?.rows) ? data.rows : [];
      setMonitoringApps({ loading: false, rows: applicationRows, error: "" });
      const registered = applicationRows
        .map((row) => String(row?.name || "").trim())
        .filter(Boolean);
      const ordered = Array.from(new Set([
        ...CORE_MONITOR_PROJECTS.filter((name) => registered.some((item) => item.toLowerCase() === name.toLowerCase())),
        ...registered,
        REAL_USE_CASE_SCOPE,
        TEST_USE_CASE_SCOPE,
      ]));
      const options = ordered.length ? ordered : defaultMonitorApplications;
      setMonitorApplications(options);
      setApplicationToMonitor((current) => (
        options.some((item) => item.toLowerCase() === String(current || "").toLowerCase())
          ? current
          : options[0] || "KaiOps"
      ));
    } catch (_error) {
      setMonitorApplications(defaultMonitorApplications);
      setApplicationToMonitor((current) => (
        defaultMonitorApplications.includes(current) ? current : "KaiOps"
      ));
    }
  }

  async function searchGuidanceDocs() {
    const query = String(guidanceQuery || "").trim();
    if (!query) {
      setGuidanceState({ loading: false, rows: [], error: "Enter search text to find guidance." });
      return;
    }
    setGuidanceState({ loading: true, rows: [], error: "" });
    try {
      const params = new URLSearchParams({ query, limit: "8" });
      const payload = await fetchJson(`/api-gateway/rag/search?${params.toString()}`);
      const rows = payload?.matches || payload?.data?.matches || [];
      setGuidanceState({ loading: false, rows: Array.isArray(rows) ? rows : [], error: "" });
    } catch (error) {
      setGuidanceState({ loading: false, rows: [], error: error.message });
    }
  }

  async function reloadRagDocs() {
    try {
      await fetchJson("/api-gateway/rag/reload", authenticatedOptions({ method: "POST", body: JSON.stringify({}) }));
      await loadRagDocs();
    } catch (error) {
      setRagDocs((prev) => ({ ...prev, error: error.message }));
    }
  }

  async function submitAlert(event) {
    event.preventDefault();
    setSubmitState({ loading: true, result: null, error: "" });
    try {
      const payload = await fetchJson("/api-gateway/alerts", {
        method: "POST",
        body: JSON.stringify(form),
      });
      setSubmitState({ loading: false, result: payload, error: "" });
      await loadRecentAlerts();
    } catch (error) {
      setSubmitState({ loading: false, result: null, error: error.message });
    }
  }

  async function runWorkflow(flowId) {
    const normalized = String(flowId || "").trim();
    if (!normalized) {
      return;
    }
    setWorkflowState({ loading: true, result: null, error: "" });
    try {
      const payload = await fetchJson(`/api-gateway/sample/${normalized}/workflow`, {
        method: "POST",
        body: JSON.stringify({}),
      });
      setWorkflowState({ loading: false, result: payload, error: "" });
      await Promise.all([loadRecentAlerts(), loadGatewaySummary(), loadGatewayRecent(), loadIncidentMetadata(), loadClosedIncidents()]);
    } catch (error) {
      setWorkflowState({ loading: false, result: null, error: error.message });
    }
  }

  function adminHeaders() {
    const token = String(adminSession.accessToken || "").trim();
    return token ? { Authorization: `Bearer ${token}` } : {};
  }

  function authenticatedOptions(options = {}) {
    const headers = adminHeaders();
    return {
      ...options,
      authenticated: true,
      onUnauthorized: () => {
        setAdminSession({
          loading: false,
          accessToken: "",
          refreshToken: "",
          user: null,
          error: "Session expired. Please sign in again.",
        });
        setAdminUsers({ loading: false, rows: [], error: "" });
        setActiveTab("home");
      },
      headers: {
        ...headers,
        ...(options.headers || {}),
      },
    };
  }

  async function adminLogin(event) {
    event.preventDefault();
    setAdminSession((current) => ({ ...current, loading: true, error: "" }));
    try {
      const response = await fetchJson("/api-gateway/auth/login", {
        method: "POST",
        body: JSON.stringify({
          username: String(adminAuthForm.username || "").trim(),
          password: String(adminAuthForm.password || ""),
          device: String(adminAuthForm.device || "react-ui").trim(),
        }),
      });
      setAdminSession({
        loading: false,
        accessToken: response?.access_token || "",
        refreshToken: response?.refresh_token || "",
        user: response?.user || null,
        error: "",
      });
    } catch (error) {
      setAdminSession((current) => ({ ...current, loading: false, error: error.message }));
    }
  }

  async function adminLogout() {
    const headers = adminHeaders();
    try {
      if (headers.Authorization) {
        await fetchJson("/api-gateway/auth/logout", { method: "POST", headers, body: JSON.stringify({}) });
      }
    } catch (_error) {
      // Ignore logout errors and clear local session regardless.
    }
    setAdminSession({ loading: false, accessToken: "", refreshToken: "", user: null, error: "" });
    setAdminUsers({ loading: false, rows: [], error: "" });
    setAdminEditUser({ id: null, username: "", email: "", first_name: "", last_name: "", role_id: 1, status: "active", is_active: true });
    setAdminEditPanelOpen(false);
    setAdminResetPasswordForm({ user_id: null, new_password: "" });
    setActiveTab("home");
  }

  async function loadAdminUsersAndRoles() {
    const headers = adminHeaders();
    if (!headers.Authorization) {
      return;
    }
    setAdminUsers((current) => ({ ...current, loading: true, error: "" }));
    try {
      const [usersPayload, rolesPayload] = await Promise.all([
        fetchJson("/api-gateway/users?page=1&page_size=50", authenticatedOptions()),
        fetchJson("/api-gateway/roles", authenticatedOptions()),
      ]);
      const usersRows = usersPayload?.rows || usersPayload?.data?.rows || [];
      const rolesRows = rolesPayload?.data || rolesPayload || [];
      setAdminUsers({ loading: false, rows: Array.isArray(usersRows) ? usersRows : [], error: "" });
      setAdminRoles(Array.isArray(rolesRows) ? rolesRows : []);
    } catch (error) {
      setAdminUsers({ loading: false, rows: [], error: error.message });
    }
  }

  async function createAdminUser(event) {
    event.preventDefault();
    const headers = adminHeaders();
    if (!headers.Authorization) {
      setAdminUsers((current) => ({ ...current, error: "Admin login required." }));
      return;
    }
    setAdminUsers((current) => ({ ...current, loading: true, error: "" }));
    try {
      await fetchJson("/api-gateway/users", authenticatedOptions({
        method: "POST",
        body: JSON.stringify({
          ...adminCreateUser,
          role_id: Number(adminCreateUser.role_id || 1),
        }),
      }));
      setAdminCreateUser({
        username: "",
        email: "",
        password: "",
        first_name: "",
        last_name: "",
        role_id: 1,
        status: "active",
        is_active: true,
      });
      await loadAdminUsersAndRoles();
    } catch (error) {
      setAdminUsers((current) => ({ ...current, loading: false, error: error.message }));
    }
  }

  function selectAdminUserForEdit(row) {
    const selectedId = Number(row?.id || 0);
    if (!selectedId) {
      return;
    }
    setAdminEditUser({
      id: selectedId,
      username: String(row?.username || "").trim(),
      email: String(row?.email || "").trim(),
      first_name: String(row?.first_name || "").trim(),
      last_name: String(row?.last_name || "").trim(),
      role_id: Number(row?.role_id || 1),
      status: String(row?.status || "active").trim(),
      is_active: Boolean(row?.is_active),
    });
    setAdminEditPanelOpen(true);
    setAdminResetPasswordForm((current) => ({ ...current, user_id: selectedId, new_password: "" }));
  }

  async function updateAdminUser(event) {
    event.preventDefault();
    const headers = adminHeaders();
    if (!headers.Authorization || !adminEditUser.id) {
      setAdminUsers((current) => ({ ...current, error: "Admin login and selected user are required." }));
      return;
    }
    setAdminUsers((current) => ({ ...current, loading: true, error: "" }));
    try {
      await fetchJson(`/api-gateway/users/${adminEditUser.id}`, authenticatedOptions({
        method: "PUT",
        body: JSON.stringify({
          email: String(adminEditUser.email || "").trim(),
          first_name: String(adminEditUser.first_name || "").trim(),
          last_name: String(adminEditUser.last_name || "").trim(),
          role_id: Number(adminEditUser.role_id || 1),
          status: String(adminEditUser.status || "active").trim(),
          is_active: Boolean(adminEditUser.is_active),
        }),
      }));
      await loadAdminUsersAndRoles();
      setAdminEditPanelOpen(false);
    } catch (error) {
      setAdminUsers((current) => ({ ...current, loading: false, error: error.message }));
    }
  }

  async function resetAdminUserPassword(event) {
    event.preventDefault();
    const headers = adminHeaders();
    const selectedUserId = Number(adminResetPasswordForm.user_id || 0);
    if (!headers.Authorization || !selectedUserId) {
      setAdminUsers((current) => ({ ...current, error: "Select a user to reset password." }));
      return;
    }
    setAdminUsers((current) => ({ ...current, loading: true, error: "" }));
    try {
      await fetchJson(`/api-gateway/users/${selectedUserId}/reset-password`, authenticatedOptions({
        method: "PATCH",
        body: JSON.stringify({ new_password: String(adminResetPasswordForm.new_password || "") }),
      }));
      setAdminResetPasswordForm((current) => ({ ...current, new_password: "" }));
      await loadAdminUsersAndRoles();
    } catch (error) {
      setAdminUsers((current) => ({ ...current, loading: false, error: error.message }));
    }
  }

  function applyProjectOnboardingRow(row) {
    if (!row || typeof row !== "object") {
      return;
    }
    const projectPayload = row.project_payload && typeof row.project_payload === "object" ? row.project_payload : {};
    const connectivityPayload = row.connectivity_payload && typeof row.connectivity_payload === "object" ? row.connectivity_payload : {};
    const monitoring = extractMonitoringToolAndUrl(connectivityPayload);
    setSelectedOnboardingProject(String(row.project_name || projectPayload.name || "").trim());
    setOnboardingForm((curr) => ({
      ...curr,
      name: String(row.project_name || projectPayload.name || curr.name || "").trim(),
      owner_team: String(row.owner_team || projectPayload.owner_team || curr.owner_team || "").trim(),
      environment: String(row.environment || projectPayload.environment || curr.environment || "prod").trim(),
      region: String(row.region || projectPayload.region || curr.region || "").trim(),
      deployment_mode: String(connectivityPayload.deployment_mode || curr.deployment_mode || "on_prem").trim(),
      monitoring_tool: monitoring.tool,
      monitoring_url: monitoring.url,
      prometheus_url: monitoring.tool === "prometheus" ? monitoring.url : "",
      new_relic_url: monitoring.tool === "new_relic" ? monitoring.url : "",
      datadog_url: monitoring.tool === "datadog" ? monitoring.url : "",
      azure_subscription_id: String(connectivityPayload.azure_subscription_id || curr.azure_subscription_id || "").trim(),
      azure_resource_group: String(connectivityPayload.azure_resource_group || curr.azure_resource_group || "").trim(),
      azure_service_bus_namespace: String(connectivityPayload.azure_service_bus_namespace || curr.azure_service_bus_namespace || "").trim(),
      azure_service_bus_topic: String(connectivityPayload.azure_service_bus_topic || curr.azure_service_bus_topic || "").trim(),
      azure_service_bus_subscription: String(connectivityPayload.azure_service_bus_subscription || curr.azure_service_bus_subscription || "").trim(),
      azure_content_safety_enabled: Boolean(connectivityPayload.azure_content_safety_enabled ?? curr.azure_content_safety_enabled),
      azure_content_safety_endpoint: String(connectivityPayload.azure_content_safety_endpoint || curr.azure_content_safety_endpoint || "").trim(),
      assignment_project: String(row.project_name || projectPayload.name || curr.name || "").trim(),
    }));
    setOnboardingProjectMode("existing");
    setExistingRulePipelineForm((curr) => ({
      ...curr,
      platform: monitoring.tool,
      connection_url: monitoring.url,
    }));
    setNewRulePipelineForm((curr) => ({
      ...curr,
      selected_tool: monitoring.tool,
    }));
    setOnboardingSourceDocs({ loading: false, rows: [], error: "" });
  }

  function resetNewProjectOnboardingDraft() {
    setSelectedOnboardingProject("");
    setOnboardingWorkflowSteps([]);
    setOnboardingGeneratedDocs([]);
    setOnboardingSourceDocs({ loading: false, rows: [], error: "" });
    setOnboardingDocApprovalState({ loading: false, error: "", success: "", approved: false });
    setOnboardingForm((curr) => ({
      ...curr,
      name: "",
      owner_team: "",
      environment: "prod",
      region: curr.region || "us-east-1",
      monitoring_tool: "prometheus",
      monitoring_url: "http://prometheus:9090",
      prometheus_url: "http://prometheus:9090",
      new_relic_url: "",
      datadog_url: "",
      assignment_username: "",
      assignment_project: "",
      onboarding_path: "setup_monitoring",
      start_rule_onboarding: true,
      service_knowledge_prompt: "",
      rule_onboarding_plain_language: "",
    }));
  }

  async function loadModelProviderStatus() {
    setModelProviderStatus((curr) => ({ ...curr, loading: true, error: "" }));
    try {
      const payload = await fetchJson("/api-gateway/model/providers/status");
      setModelProviderStatus({ loading: false, data: unwrap(payload), error: "" });
    } catch (error) {
      setModelProviderStatus({ loading: false, data: null, error: error.message });
    }
  }

  function currentOnboardedApplicationName() {
    return String(selectedOnboardingProject || onboardingForm.name || monitoringAppForm.name || "").trim();
  }

  function findMonitoringApplicationForName(name) {
    const normalized = String(name || "").trim().toLowerCase();
    if (!normalized) {
      return null;
    }
    return (Array.isArray(monitoringApps.rows) ? monitoringApps.rows : []).find((row) => {
      const candidates = [
        row?.id,
        row?.name,
        row?.application,
        row?.project_name,
        row?.service,
      ].map((value) => String(value || "").trim().toLowerCase()).filter(Boolean);
      return candidates.some((candidate) => candidate === normalized || candidate.includes(normalized) || normalized.includes(candidate));
    }) || null;
  }

  async function openOnboardedApplicationDashboard(url = "") {
    const appName = currentOnboardedApplicationName();
    if (appName) {
      setApplicationToMonitor(REAL_USE_CASE_SCOPE);
      const row = findMonitoringApplicationForName(appName);
      const appId = String(row?.id || "").trim();
      if (appId) {
        setSelectedMonitoringAppId(appId);
        loadMonitoringApplicationDetails(appId);
      }
    }
    setDashboardAlertFocus("all");
    setDashboardAlertQuery("");
    setActiveTab("home");
    if (url && typeof window !== "undefined") {
      window.open(url, "_blank", "noopener,noreferrer");
    }
  }

  async function ingestGeneratedOnboardingDocuments(documents) {
    const rows = Array.isArray(documents) ? documents : [];
    if (!rows.length) {
      return { total: 0, ingested: 0, failed: 0 };
    }

    let ingested = 0;
    let failed = 0;
    for (const row of rows) {
      try {
        await fetchJson("/api-gateway/rag/documents", authenticatedOptions({
          method: "POST",
          body: JSON.stringify(row),
        }));
        ingested += 1;
      } catch (_error) {
        failed += 1;
      }
    }
    if (ingested > 0) {
      await loadRagDocs();
    }
    return { total: rows.length, ingested, failed };
  }

  async function approveGeneratedOnboardingDocuments() {
    const docs = Array.isArray(onboardingGeneratedDocs) ? onboardingGeneratedDocs : [];
    if (!docs.length) {
      return;
    }
    setOnboardingDocApprovalState({ loading: true, error: "", success: "", approved: false });
    try {
      const summary = await ingestGeneratedOnboardingDocuments(docs);
      if (summary.failed > 0) {
        setOnboardingDocApprovalState({
          loading: false,
          error: `Approved, but ${summary.failed} document(s) failed to ingest.`,
          success: "",
          approved: false,
        });
        return;
      }
      setOnboardingDocApprovalState({
        loading: false,
        error: "",
        success: `Approved and ingested ${summary.ingested}/${summary.total} document(s).`,
        approved: true,
      });
      setOnboardingReviewAck((current) => ({ ...current, docs: true }));
      setOnboardingState((current) => ({ ...current, success: `Project onboarding saved. Documents approved: ${summary.ingested}/${summary.total}.` }));
      const appName = currentOnboardedApplicationName();
      if (appName) {
        setApplicationToMonitor(REAL_USE_CASE_SCOPE);
      }
      setProjectSetupStep("status");
    } catch (error) {
      setOnboardingDocApprovalState({ loading: false, error: error.message, success: "", approved: false });
    }
  }

  const onboardingDerivedRequirements = useMemo(() => {
    const rows = Array.isArray(onboardingSourceDocs.rows) ? onboardingSourceDocs.rows : [];
    const merged = [];
    rows.forEach((row) => {
      (Array.isArray(row?.derived_requirements) ? row.derived_requirements : []).forEach((item) => {
        const token = cleanRuleIntentLine(item);
        if (token && !merged.some((existing) => existing.toLowerCase() === token.toLowerCase())) {
          merged.push(token);
        }
      });
    });
    return merged;
  }, [onboardingSourceDocs.rows]);

  const onboardingKnowledgePack = knowledgePackState.draft?.knowledge_pack || knowledgePackState.draft || null;
  const onboardingKnowledgeFacts = onboardingKnowledgePack?.facts || {};
  const onboardingKnowledgeValidation = onboardingKnowledgePack?.validation || {};
  const KNOWLEDGE_LIST_FACTS = new Set(["dependencies", "alert_patterns", "commands", "rollback_plan", "validation_checks"]);
  const KNOWLEDGE_FACT_LABELS = {
    service: "Service",
    environment: "Environment",
    owner_team: "Owner team",
    dependencies: "Dependencies",
    alert_patterns: "Alert patterns",
    commands: "Commands or queries",
    rollback_plan: "Rollback or failback",
    validation_checks: "Validation checks",
  };
  const KNOWLEDGE_FACT_HINTS = {
    service: "Example: kaiops-core1 or checkout-api",
    environment: "Example: prod, qa, dev",
    dependencies: "Example: mysql, redis, rabbitmq, kafka",
    commands: "Example: kubectl logs deployment/service -n prod",
    rollback_plan: "Example: rollback deployment to previous version and restore config",
    validation_checks: "Example: verify /health, Prometheus target up, and error rate recovered",
    alert_patterns: "Example: alert when exporter is down for 5m",
    owner_team: "Example: platform-ops",
  };
  const KNOWLEDGE_FACT_QUESTIONS = {
    service: "Which service or application is this knowledge for?",
    environment: "Which environment should this apply to?",
    owner_team: "Which team owns this service?",
    dependencies: "Which upstream/downstream dependencies should KaiOps check during triage?",
    alert_patterns: "Which alert conditions should create monitoring rules?",
    commands: "Which commands, scripts, or queries are safe for operators to review?",
    rollback_plan: "What rollback or failback plan should be used if remediation fails?",
    validation_checks: "Which checks prove the service recovered?",
  };

  function knowledgeFactDisplayValue(fact) {
    const value = fact?.value;
    if (Array.isArray(value)) {
      return value.join(" | ") || "-";
    }
    return String(value || "-");
  }

  function normalizeKnowledgeCorrectionValue(key, value) {
    const text = String(value || "").trim();
    if (!text) {
      return KNOWLEDGE_LIST_FACTS.has(key) ? [] : "";
    }
    if (KNOWLEDGE_LIST_FACTS.has(key)) {
      return text.split(/\r?\n|,/).map((item) => item.trim()).filter(Boolean);
    }
    return text;
  }

  function knowledgeFactEditValue(key, fact) {
    if (Object.prototype.hasOwnProperty.call(knowledgePackCorrections, key)) {
      return knowledgePackCorrections[key] || "";
    }
    const value = fact?.value;
    if (Array.isArray(value)) {
      return value.join("\n");
    }
    return String(value || "");
  }

  function updateKnowledgeFactCorrection(key, value) {
    setKnowledgePackCorrections((current) => ({
      ...current,
      [key]: value,
    }));
    if (key === "service") {
      setOnboardingForm((current) => ({ ...current, name: value, assignment_project: value }));
    }
    if (key === "environment") {
      setOnboardingForm((current) => ({ ...current, environment: value || current.environment }));
    }
    if (key === "owner_team") {
      setOnboardingForm((current) => ({ ...current, owner_team: value }));
    }
  }

  const correctedKnowledgeFacts = useMemo(() => {
    const next = {};
    Object.entries(onboardingKnowledgeFacts).forEach(([key, fact]) => {
      const correction = knowledgePackCorrections[key];
      const hasCorrection = Object.prototype.hasOwnProperty.call(knowledgePackCorrections, key);
      const normalizedCorrection = normalizeKnowledgeCorrectionValue(key, correction);
      const correctionEmpty = Array.isArray(normalizedCorrection)
        ? normalizedCorrection.length === 0
        : !String(normalizedCorrection || "").trim();
      if (!hasCorrection) {
        next[key] = fact;
        return;
      }
      if (correctionEmpty) {
        next[key] = {
          ...(fact || {}),
          value: normalizedCorrection,
          confidence: 0,
          status: "needs_review",
          sources: Array.isArray(fact?.sources) ? fact.sources : [],
        };
        return;
      }
      // Only trust a backend-verified confidence/status if it was computed from
      // the exact text currently in the box. If the user has typed something
      // new since the last revalidation call, treat it as unverified again
      // rather than keep showing a stale "accepted" badge.
      const validatedSnapshot = knowledgePackRevalidation.validatedCorrections?.[key];
      const backendFact = validatedSnapshot === correction ? knowledgePackRevalidation.facts?.[key] : null;
      next[key] = backendFact
        ? {
          // Keep backendFact.value as-is (what the backend actually detected —
          // may legitimately be empty if the correction didn't match anything).
          // The edit textarea itself reads straight from knowledgePackCorrections,
          // so it still shows exactly what the user typed regardless of this.
          ...backendFact,
          sources: [...(Array.isArray(backendFact.sources) ? backendFact.sources : []), "user-confirmed"],
        }
        : {
          ...(fact || {}),
          value: normalizedCorrection,
          confidence: 0,
          status: "pending_validation",
          sources: [...(Array.isArray(fact?.sources) ? fact.sources : []), "user-confirmed"],
        };
    });
    return next;
  }, [knowledgePackCorrections, onboardingKnowledgeFacts, knowledgePackRevalidation]);
  const knowledgeReviewFields = useMemo(
    () => Object.entries(correctedKnowledgeFacts).filter(([, fact]) => {
      const value = fact?.value;
      const empty = Array.isArray(value) ? value.length === 0 : !String(value || "").trim();
      return empty || Number(fact?.confidence || 0) < 0.78 || String(fact?.status || "") === "needs_review";
    }),
    [correctedKnowledgeFacts],
  );
  const correctedKnowledgeConfidence = useMemo(() => {
    const rows = Object.values(correctedKnowledgeFacts);
    if (!rows.length) {
      return Number(onboardingKnowledgeValidation.overall_confidence || 0);
    }
    return rows.reduce((sum, fact) => sum + Number(fact?.confidence || 0), 0) / rows.length;
  }, [correctedKnowledgeFacts, onboardingKnowledgeValidation.overall_confidence]);
  const knowledgeReviewReady = Boolean(onboardingKnowledgePack) && knowledgeReviewFields.length === 0;
  const knowledgeHasUnvalidatedInput = Boolean(
    (Array.isArray(onboardingSourceDocs.rows) ? onboardingSourceDocs.rows : []).some((row) => String(row?.text || "").trim() && !String(row?.warning || "").trim())
    && onboardingKnowledgePack
    && !knowledgePackState.approved
  );
  const knowledgeReviewSummary = useMemo(() => {
    if (!onboardingKnowledgePack) {
      return "Describe the service, alerts, dependencies, checks, commands, rollback, and owner. KaiOps will extract the details for review.";
    }
    if (knowledgeReviewReady) {
      return "All required details are accepted. Review the table once, then approve Service Knowledge.";
    }
    return `${knowledgeReviewFields.length} detail${knowledgeReviewFields.length === 1 ? "" : "s"} need input before validation can pass.`;
  }, [knowledgeReviewFields.length, knowledgeReviewReady, onboardingKnowledgePack]);

  useEffect(() => {
    if (!onboardingKnowledgePack || !Object.keys(onboardingKnowledgeFacts).length) {
      return;
    }
    const factValue = (key) => {
      const fact = onboardingKnowledgeFacts[key] || {};
      const value = fact.value;
      if (Array.isArray(value)) {
        return String(value[0] || "").trim();
      }
      return String(value || "").trim();
    };
    const service = factValue("service");
    const environment = factValue("environment");
    const ownerTeam = factValue("owner_team");
    setOnboardingForm((current) => {
      const next = { ...current };
      if (service && (!String(current.name || "").trim() || ["kaiops-project", "service"].includes(String(current.name || "").trim().toLowerCase()))) {
        next.name = service;
        next.assignment_project = service;
      }
      if (environment && (!String(current.environment || "").trim() || String(current.environment || "").trim() === "prod")) {
        next.environment = environment;
      }
      if (ownerTeam && (!String(current.owner_team || "").trim() || String(current.owner_team || "").trim() === "platform-ops")) {
        next.owner_team = ownerTeam;
      }
      return next;
    });
  }, [onboardingKnowledgeFacts, onboardingKnowledgePack]);

  function buildKnowledgePackPayload(rows = onboardingSourceDocs.rows) {
    const validRows = (Array.isArray(rows) ? rows : []).filter((row) => String(row?.text || "").trim() && !String(row?.warning || "").trim());
    return {
      service: String(onboardingForm.name || monitoringAppForm.name || "kaiops-project").trim(),
      environment: String(onboardingForm.environment || monitoringAppForm.environment || "prod").trim(),
      owner_team: String(onboardingForm.owner_team || monitoringAppForm.owner_team || "platform-ops").trim(),
      documents: validRows.map((row) => ({
        name: String(row?.name || "uploaded-document").trim(),
        category: String(row?.category || "knowledge_pack").trim(),
        text: String(row?.text || ""),
        excerpt: String(row?.excerpt || ""),
      })),
    };
  }

  async function draftKnowledgePackFromPrompt() {
    const text = String(onboardingForm.service_knowledge_prompt || "").trim();
    if (!text) {
      setKnowledgePackState((current) => ({
        ...current,
        loading: false,
        error: "Describe the service knowledge first. Include service, owner, alerts, dependencies, checks, and rollback if known.",
        success: "",
        approved: false,
      }));
      return;
    }
    const serviceName = String(onboardingForm.name || monitoringAppForm.name || "service").trim() || "service";
    const promptRow = {
      category: "knowledge_pack",
      name: `${serviceName}-prompt-service-knowledge.md`,
      size: text.length,
      text,
      excerpt: summarizeUploadedDocument(text),
      derived_requirements: deriveMonitoringRequirementsFromDocument(`${serviceName}-prompt-service-knowledge.md`, text).map(cleanRuleIntentLine).filter(Boolean),
      warning: "",
      source: "prompt",
    };
    const existingRows = Array.isArray(onboardingSourceDocs.rows) ? onboardingSourceDocs.rows : [];
    const retainedRows = existingRows.filter((row) => String(row?.source || "") !== "prompt");
    const nextRows = [promptRow, ...retainedRows];
    setOnboardingSourceDocs({ loading: false, rows: nextRows, error: "" });
    await draftKnowledgePack(nextRows);
    if (promptRow.derived_requirements.length) {
      // Replace (not merge) with the current prompt's derived requirements.
      // The previous version folded in whatever was already sitting in
      // rule_onboarding_plain_language — which, after a prior Auto-Complete
      // run, was itself already the merged result of an even earlier run.
      // That let stale requirement lines from long-past prompts accumulate
      // indefinitely across re-runs in the same session, silently bleeding
      // into unrelated projects' generated rule summaries.
      const nextText = promptRow.derived_requirements
        .map(cleanRuleIntentLine)
        .filter(Boolean)
        .filter((line, index, array) => array.findIndex((item) => item.toLowerCase() === line.toLowerCase()) === index)
        .join("\n");
      setOnboardingForm((curr) => ({ ...curr, rule_onboarding_plain_language: nextText }));
      setNewRulePipelineForm((curr) => ({ ...curr, requirements_text: nextText }));
    }
  }

  async function draftKnowledgePack(rows = onboardingSourceDocs.rows) {
    const payload = buildKnowledgePackPayload(rows);
    if (!payload.documents.length) {
      setKnowledgePackState({ loading: false, draft: null, error: "", success: "", approved: false });
      setKnowledgePackCorrections({});
      return null;
    }
    setKnowledgePackState((current) => ({ ...current, loading: true, error: "", success: "", approved: false }));
    try {
      const response = unwrap(await fetchJson("/api-gateway/knowledge-pack/draft", authenticatedOptions({
        method: "POST",
        body: JSON.stringify(payload),
      })));
      setKnowledgePackCorrections({});
      setKnowledgePackRevalidation({ loading: false, error: "", facts: {}, validatedCorrections: {} });
      setKnowledgePackState({ loading: false, draft: response?.knowledge_pack ? response : { knowledge_pack: response }, error: "", success: "", approved: false });
      return response;
    } catch (error) {
      setKnowledgePackState((current) => ({ ...current, loading: false, error: error.message, success: "", approved: false }));
      return null;
    }
  }

  // Formats manual corrections into a synthetic document using the same
  // keyword vocabulary the backend's extractor looks for (service:, owner:,
  // dependency:, alert:, rollback:, validate:), so re-running extraction with
  // this text folded in can actually detect the corrected values.
  function knowledgePackCorrectionDocumentText() {
    const lines = [];
    const prefixByKey = {
      service: "service",
      environment: "environment",
      owner_team: "owner",
      dependencies: "dependency",
      alert_patterns: "alert",
      rollback_plan: "rollback",
      validation_checks: "validate",
    };
    Object.entries(knowledgePackCorrections).forEach(([key, rawValue]) => {
      const normalized = normalizeKnowledgeCorrectionValue(key, rawValue);
      const items = (Array.isArray(normalized) ? normalized : [normalized]).filter((item) => String(item || "").trim());
      items.forEach((item) => {
        // "commands" must be left as-is: the backend only recognizes lines that
        // already start with a real tool name (kubectl, helm, mysql, etc.).
        lines.push(key === "commands" ? item : `${prefixByKey[key] || key}: ${item}`);
      });
    });
    return lines.join("\n");
  }

  async function revalidateKnowledgeCorrections() {
    const correctionText = knowledgePackCorrectionDocumentText();
    if (!correctionText.trim()) {
      setKnowledgePackRevalidation((current) => ({ ...current, loading: false, error: "No manual edits to validate yet." }));
      return null;
    }
    const basePayload = buildKnowledgePackPayload(onboardingSourceDocs.rows);
    // service/environment/owner_team are matched by the backend from these
    // top-level request fields FIRST, before it ever looks at document text —
    // so a correction to one of these three has to override the field here,
    // not just get folded into the corrections document (which would be
    // silently ignored otherwise).
    const topLevelOverrides = {};
    ["service", "environment", "owner_team"].forEach((key) => {
      if (!Object.prototype.hasOwnProperty.call(knowledgePackCorrections, key)) {
        return;
      }
      const normalized = normalizeKnowledgeCorrectionValue(key, knowledgePackCorrections[key]);
      const text = String(normalized || "").trim();
      if (text) {
        topLevelOverrides[key] = text;
      }
    });
    const payload = {
      ...basePayload,
      ...topLevelOverrides,
      documents: [
        ...basePayload.documents,
        {
          name: "user-corrections.md",
          category: "knowledge_pack",
          text: correctionText,
          excerpt: correctionText.slice(0, 220),
        },
      ],
    };
    const validatedSnapshot = { ...knowledgePackCorrections };
    setKnowledgePackRevalidation((current) => ({ ...current, loading: true, error: "" }));
    try {
      const response = unwrap(await fetchJson("/api-gateway/knowledge-pack/validate", authenticatedOptions({
        method: "POST",
        body: JSON.stringify(payload),
      })));
      const facts = response?.knowledge_pack?.facts || response?.facts || {};
      setKnowledgePackRevalidation({ loading: false, error: "", facts, validatedCorrections: validatedSnapshot });
      return facts;
    } catch (error) {
      setKnowledgePackRevalidation((current) => ({ ...current, loading: false, error: error.message }));
      return null;
    }
  }

  async function approveKnowledgePack() {
    const payload = buildKnowledgePackPayload(onboardingSourceDocs.rows);
    if (!payload.documents.length) {
      setKnowledgePackState((current) => ({ ...current, error: "Upload at least one knowledge document before approval.", success: "" }));
      return;
    }
    setKnowledgePackState((current) => ({ ...current, loading: true, error: "", success: "" }));
    try {
      const acceptedFacts = Object.fromEntries(
        Object.entries(correctedKnowledgeFacts).map(([key, fact]) => [key, fact?.value]),
      );
      const response = unwrap(await fetchJson("/api-gateway/knowledge-pack/approve", authenticatedOptions({
        method: "POST",
        body: JSON.stringify({
          ...payload,
          accepted_facts: acceptedFacts,
          approved_by: currentRole || "administrator",
        }),
      })));
      setKnowledgePackState({
        loading: false,
        draft: response?.knowledge_pack ? response : { knowledge_pack: response },
        error: "",
        success: "Alert Knowledge validated and saved. Next, click Generate Documents & Rules to create reviewable artifacts.",
        approved: true,
      });
      setOnboardingReviewAck((current) => ({ ...current, docs: true }));
      applyUploadedDocumentsToRuleIntent();
      await Promise.all([loadRagDocs(), loadRecentAlerts()]);
    } catch (error) {
      setKnowledgePackState((current) => ({ ...current, loading: false, error: error.message, success: "", approved: false }));
    }
  }

  function buildServiceKnowledgeGeneratedDocs({ projectName, selectedTool }) {
    if (!onboardingKnowledgePack || !onboardingSourceDocRows.length) {
      return [];
    }
    const factValue = (key, fallback = "") => {
      const value = correctedKnowledgeFacts?.[key]?.value;
      return value == null || value === "" ? fallback : value;
    };
    const asList = (value) => Array.isArray(value) ? value.filter((item) => String(item || "").trim()) : [value].filter((item) => String(item || "").trim());
    const service = String(factValue("service", projectName || onboardingForm.name || "service")).trim();
    const environment = String(factValue("environment", onboardingForm.environment || "prod")).trim();
    const owner = String(factValue("owner_team", onboardingForm.owner_team || "platform-ops")).trim();
    const alertPatterns = asList(factValue("alert_patterns", []));
    const dependencies = asList(factValue("dependencies", []));
    const commands = asList(factValue("commands", []));
    const rollback = asList(factValue("rollback_plan", []));
    const checks = asList(factValue("validation_checks", []));
    const sourceLines = onboardingSourceDocRows.map((row) => `- ${String(row?.name || "service-knowledge").trim()}: ${String(row?.excerpt || "").trim()}`).join("\n");
    const bulletSection = (title, rows, empty = "Not provided") => `${title}:\n${rows.length ? rows.map((item) => `- ${item}`).join("\n") : `- ${empty}`}`;
    const metadata = {
      project_name: String(projectName || service).trim(),
      owner_team: owner,
      environment,
      selected_monitoring_tool: String(selectedTool || onboardingForm.monitoring_tool || "prometheus").trim(),
      source_system: "service-knowledge",
      knowledge_confidence: String(correctedKnowledgeConfidence || ""),
    };
    return [
      {
        kind: "runbook",
        alert_id: `${service}-service-knowledge-runbook`,
        alert_type: "service-knowledge-onboarding",
        severity: "high",
        title: `${service} Service Knowledge Runbook`,
        summary: "Generated from uploaded Service Knowledge for triage, RCA, and remediation.",
        content: [
          `Service ${service} in ${environment}.`,
          bulletSection("Alert patterns", alertPatterns),
          bulletSection("Dependencies", dependencies),
          bulletSection("Validation checks", checks),
          bulletSection("Rollback plan", rollback),
          "Source evidence:",
          sourceLines || "- Uploaded Service Knowledge",
        ].join("\n\n"),
        services: [service],
        deployment: environment,
        dependencies,
        commands,
        queries: checks,
        recommended_action: "Use this runbook during alert triage and update it after the first live incident.",
        source_system: "service-knowledge",
        resolved_by: owner,
        metadata,
      },
      {
        kind: "incident",
        alert_id: `${service}-service-knowledge-incident`,
        alert_type: "service-knowledge-baseline",
        severity: "warning",
        title: `${service} Service Knowledge Incident Baseline`,
        summary: "Incident baseline generated from uploaded Service Knowledge.",
        content: [
          `Baseline incident guidance for ${service}.`,
          bulletSection("Expected alert patterns", alertPatterns),
          bulletSection("Known dependencies", dependencies),
          bulletSection("Evidence", [sourceLines].filter(Boolean), "Uploaded Service Knowledge"),
        ].join("\n\n"),
        services: [service],
        deployment: environment,
        source_system: "service-knowledge",
        resolved_by: owner,
        metadata,
      },
    ];
  }

  async function handleOnboardingSourceDocuments(files, category = "other") {
    const rows = Array.from(files || []);
    if (!rows.length) {
      return;
    }
    setOnboardingSourceDocs((current) => ({ ...current, loading: true, error: "" }));
    try {
      const parsedRows = await Promise.all(rows.map(async (file) => {
        const fileName = String(file?.name || "uploaded-document").trim() || "uploaded-document";
        const extension = fileName.includes(".") ? fileName.split(".").pop().toLowerCase() : "";
        if (!ONBOARDING_SOURCE_DOC_EXTENSIONS.has(extension)) {
          return {
            category,
            name: fileName,
            size: Number(file?.size || 0),
            text: "",
            excerpt: "",
            derived_requirements: [],
            warning: `Unsupported file type .${extension || "unknown"}. Use text-based docs such as .md, .txt, .json, .csv, .yaml.`,
          };
        }
        const text = await file.text();
        return {
          category,
          name: fileName,
          size: Number(file?.size || 0),
          text,
          excerpt: summarizeUploadedDocument(text),
          derived_requirements: deriveMonitoringRequirementsFromDocument(fileName, text),
          warning: "",
        };
      }));
      const existingRows = Array.isArray(onboardingSourceDocs.rows) ? onboardingSourceDocs.rows : [];
      const retainedRows = existingRows.filter((row) => String(row?.category || "other") !== category);
      const nextRows = [...retainedRows, ...parsedRows];
      setOnboardingSourceDocs({ loading: false, rows: nextRows, error: "" });
      await draftKnowledgePack(nextRows);
      const derived = parsedRows.flatMap((row) => (Array.isArray(row.derived_requirements) ? row.derived_requirements : []));
      if (derived.length) {
        const manual = String(onboardingForm.rule_onboarding_plain_language || "")
          .split(/\r?\n/)
          .map((line) => line.trim())
          .filter(Boolean);
        const combined = [...manual, ...derived].filter(
          (line, index, array) => array.findIndex((item) => item.toLowerCase() === line.toLowerCase()) === index,
        );
        const nextText = combined.join("\n");
        setOnboardingForm((curr) => ({ ...curr, rule_onboarding_plain_language: nextText }));
        setNewRulePipelineForm((curr) => ({ ...curr, requirements_text: nextText }));
      }
    } catch (error) {
      setOnboardingSourceDocs((current) => ({
        loading: false,
        rows: Array.isArray(current?.rows) ? current.rows : [],
        error: String(error?.message || "Failed to read uploaded documents."),
      }));
    }
  }

  async function handleAlertKnowledgeSourceDocument(files) {
    const file = Array.from(files || [])[0];
    if (!file) {
      return;
    }
    const fileName = String(file?.name || "uploaded-document").trim() || "uploaded-document";
    const extension = fileName.includes(".") ? fileName.split(".").pop().toLowerCase() : "";
    setAlertKnowledgeSourceDoc((current) => ({ ...current, loading: true, error: "" }));
    try {
      if (!ONBOARDING_SOURCE_DOC_EXTENSIONS.has(extension)) {
        setAlertKnowledgeSourceDoc({
          loading: false,
          name: fileName,
          size: Number(file?.size || 0),
          text: "",
          excerpt: "",
          error: `Unsupported file type .${extension || "unknown"}. Upload a text-based file such as .md, .txt, .json, .csv, .yaml, or .log.`,
        });
        return;
      }
      const text = await file.text();
      const excerpt = summarizeUploadedDocument(text);
      const derivedRequirements = deriveMonitoringRequirementsFromDocument(fileName, text);
      setAlertKnowledgeSourceDoc({
        loading: false,
        name: fileName,
        size: Number(file?.size || 0),
        text,
        excerpt,
        error: "",
      });
      if (!String(alertKnowledgePrompt || "").trim() && derivedRequirements.length) {
        setAlertKnowledgePrompt(derivedRequirements.slice(0, 6).join("\n"));
      }
    } catch (error) {
      setAlertKnowledgeSourceDoc({
        loading: false,
        name: fileName,
        size: Number(file?.size || 0),
        text: "",
        excerpt: "",
        error: String(error?.message || "Failed to read the uploaded alert knowledge document."),
      });
    }
  }

  function buildAlertKnowledgePromptInput() {
    const prompt = String(alertKnowledgePrompt || "").trim();
    const sourceText = String(alertKnowledgeSourceDoc?.text || "").trim();
    if (!sourceText) {
      return prompt;
    }
    const sourceName = String(alertKnowledgeSourceDoc?.name || "uploaded alert knowledge document").trim();
    const sourceExcerpt = String(alertKnowledgeSourceDoc?.excerpt || "").trim();
    const sourceBlock = [
      `Supporting document: ${sourceName}`,
      sourceExcerpt ? `Extracted summary: ${sourceExcerpt}` : "",
      "Document content:",
      sourceText.slice(0, 12000),
    ].filter(Boolean).join("\n");
    return [prompt, sourceBlock].filter(Boolean).join("\n\n");
  }

  function clearAlertKnowledgeSourceDocument() {
    setAlertKnowledgeSourceDoc({ loading: false, name: "", size: 0, text: "", excerpt: "", error: "" });
  }

  function applyUploadedDocumentsToRuleIntent() {
    if (!onboardingDerivedRequirements.length) {
      return;
    }
    const manual = String(onboardingForm.rule_onboarding_plain_language || "").trim();
    const combined = [
      ...manual.split(/\r?\n/).map(cleanRuleIntentLine).filter(Boolean),
      ...onboardingDerivedRequirements,
    ].map(cleanRuleIntentLine).filter(Boolean).filter((line, index, array) => array.findIndex((item) => item.toLowerCase() === line.toLowerCase()) === index);
    const nextText = combined.join("\n");
    setOnboardingForm((curr) => ({ ...curr, rule_onboarding_plain_language: nextText }));
    setNewRulePipelineForm((curr) => ({ ...curr, requirements_text: nextText }));
  }

  function openRuleWorkflowEditor(row) {
    const connectivityPayload = row?.connectivity_payload && typeof row.connectivity_payload === "object" ? row.connectivity_payload : {};
    const workflowId = String(connectivityPayload.workflow_id || "").trim();
    const resultPayload = connectivityPayload.result && typeof connectivityPayload.result === "object" ? connectivityPayload.result : {};
    setOnboardingRuleEditor({
      workflow_id: workflowId,
      project_name: String(row?.project_name || "").trim(),
      payload_json: JSON.stringify(resultPayload, null, 2),
    });
    setOnboardingRuleEditorState({ loading: false, error: "", success: "" });
    setOnboardingRuleLookup((current) => ({ ...current, workflow_id: workflowId }));
  }

  async function saveRuleWorkflowEditor(event) {
    event.preventDefault();
    const workflowId = String(onboardingRuleEditor.workflow_id || "").trim();
    const projectName = String(onboardingRuleEditor.project_name || onboardingForm.name || "").trim();
    if (!workflowId || !projectName) {
      setOnboardingRuleEditorState({ loading: false, error: "Workflow ID and project name are required.", success: "" });
      return;
    }
    setOnboardingRuleEditorState({ loading: true, error: "", success: "" });
    try {
      const parsedResult = JSON.parse(String(onboardingRuleEditor.payload_json || "{}").trim() || "{}");
      await fetchJson(`/api-gateway/onboarding/rules/pipeline/${encodeURIComponent(workflowId)}`, authenticatedOptions({
        method: "PUT",
        body: JSON.stringify({
          project_name: projectName,
          result: parsedResult,
          status: "updated",
        }),
      }));
      await loadOnboardingAdminData();
      setOnboardingRuleEditorState({ loading: false, error: "", success: "Rule workflow updated." });
    } catch (error) {
      setOnboardingRuleEditorState({ loading: false, error: error.message, success: "" });
    }
  }

  async function deleteRuleWorkflow(workflowId) {
    const normalizedWorkflowId = String(workflowId || "").trim();
    if (!normalizedWorkflowId) {
      return;
    }
    setOnboardingRuleEditorState({ loading: true, error: "", success: "" });
    try {
      await fetchJson(`/api-gateway/onboarding/rules/pipeline/${encodeURIComponent(normalizedWorkflowId)}`, authenticatedOptions({
        method: "DELETE",
      }));
      await loadOnboardingAdminData();
      setOnboardingRuleEditor((current) => (
        String(current.workflow_id || "") === normalizedWorkflowId
          ? { workflow_id: "", project_name: "", payload_json: "" }
          : current
      ));
      setOnboardingRuleEditorState({ loading: false, error: "", success: "Rule workflow deleted." });
    } catch (error) {
      setOnboardingRuleEditorState({ loading: false, error: error.message, success: "" });
    }
  }

  async function deleteProjectOnboarding(projectName) {
    const normalizedProject = String(projectName || "").trim();
    if (!normalizedProject) {
      return;
    }
    setOnboardingState((current) => ({ ...current, loading: true, error: "", success: "" }));
    try {
      await fetchJson(`/api-gateway/onboarding/state/${encodeURIComponent(normalizedProject)}`, authenticatedOptions({
        method: "DELETE",
      }));
      await loadOnboardingAdminData();
      await refreshViewsAfterSubmit();
      setOnboardingState((current) => ({ ...current, success: "Project onboarding deleted." }));
    } catch (error) {
      setOnboardingState((current) => ({ ...current, loading: false, error: error.message, success: "" }));
    }
  }

  async function loadOnboardingAdminData() {
    setOnboardingState((current) => ({ ...current, loading: true, error: "", success: "" }));
    try {
      const [connectivityPayload, statePayload] = await Promise.all([
        fetchJson("/api-gateway/onboarding/connectivity", authenticatedOptions()),
        fetchJson("/api-gateway/onboarding/state", authenticatedOptions()),
      ]);
      const connectivity = connectivityPayload?.data?.connectivity || connectivityPayload?.connectivity || {};
      const rows = statePayload?.data?.rows || statePayload?.rows || [];
      const project = connectivity?.project || {};
      const allRows = Array.isArray(rows) ? rows : [];
      const projectRows = allRows.filter((row) => extractOnboardingProjectName(row));
      const preferredProjectName = String(project?.name || selectedOnboardingProject || "").trim();
      const preferredProjectRow = projectRows.find((row) => extractOnboardingProjectName(row) === preferredProjectName)
        || projectRows[0]
        || null;
      const monitoring = extractMonitoringToolAndUrl(connectivity);
      setOnboardingForm((curr) => ({
        ...curr,
        name: String(project?.name || curr.name || "").trim(),
        owner_team: String(project?.owner_team || curr.owner_team || "").trim(),
        environment: String(project?.environment || curr.environment || "prod").trim(),
        region: String(project?.region || curr.region || "").trim(),
        deployment_mode: String(connectivity?.deployment_mode || curr.deployment_mode || "on_prem").trim(),
        monitoring_tool: monitoring.tool,
        monitoring_url: monitoring.url,
        prometheus_url: monitoring.tool === "prometheus" ? monitoring.url : "",
        new_relic_url: monitoring.tool === "new_relic" ? monitoring.url : "",
        datadog_url: monitoring.tool === "datadog" ? monitoring.url : "",
        azure_subscription_id: String(connectivity?.azure_subscription_id || curr.azure_subscription_id || "").trim(),
        azure_resource_group: String(connectivity?.azure_resource_group || curr.azure_resource_group || "").trim(),
        azure_service_bus_namespace: String(connectivity?.azure_service_bus_namespace || curr.azure_service_bus_namespace || "").trim(),
        azure_service_bus_topic: String(connectivity?.azure_service_bus_topic || curr.azure_service_bus_topic || "").trim(),
        azure_service_bus_subscription: String(connectivity?.azure_service_bus_subscription || curr.azure_service_bus_subscription || "").trim(),
        azure_content_safety_enabled: Boolean(connectivity?.azure_content_safety_enabled ?? curr.azure_content_safety_enabled),
        azure_content_safety_endpoint: String(connectivity?.azure_content_safety_endpoint || curr.azure_content_safety_endpoint || "").trim(),
        assignment_project: String(project?.name || curr.name || "").trim(),
      }));
      setExistingRulePipelineForm((curr) => ({ ...curr, platform: monitoring.tool, connection_url: monitoring.url }));
      setNewRulePipelineForm((curr) => ({ ...curr, selected_tool: monitoring.tool }));
      if (preferredProjectRow && onboardingProjectMode !== "new") {
        applyProjectOnboardingRow(preferredProjectRow);
      } else if (String(project?.name || "").trim()) {
        setSelectedOnboardingProject(String(project.name).trim());
      }
      setOnboardingState({ loading: false, connectivity, rows: allRows, error: "", success: "" });
    } catch (error) {
      setOnboardingState({ loading: false, connectivity: {}, rows: [], error: error.message, success: "" });
    }
  }

  async function saveOnboardingConnectivity(event) {
    event.preventDefault();
    const pendingApprovalDocs = Array.isArray(onboardingGeneratedDocs) ? onboardingGeneratedDocs : [];
    const hasPendingApproval = pendingApprovalDocs.length > 0 && !Boolean(onboardingDocApprovalState.approved);
    if (hasPendingApproval) {
      setOnboardingState((current) => ({
        ...current,
        loading: false,
        error: "Please review and approve generated documents before creating/updating another project.",
        success: "",
      }));
      return;
    }
    if (knowledgeHasUnvalidatedInput) {
      setOnboardingState((current) => ({
        ...current,
        loading: false,
        error: "Review the extracted Alert Knowledge, answer missing details, then click Validate & Save Knowledge before generating documents and rules.",
        success: "",
      }));
      return;
    }
    setOnboardingState((current) => ({ ...current, loading: true, error: "", success: "" }));
    setOnboardingGeneratedDocs([]);
    setOnboardingDocApprovalState({ loading: false, error: "", success: "", approved: false });
    setOnboardingReviewAck({ rules: false, docs: false, metadata: false });
    try {
      const onboardingPath = String(onboardingForm.onboarding_path || "setup_monitoring").trim().toLowerCase();
      const selectedMonitoringTool = onboardingPath === "setup_monitoring"
        ? "prometheus"
        : String(onboardingForm.monitoring_tool || "prometheus").trim().toLowerCase();
      const monitoringUrl = simplifyMonitoringUrl(onboardingForm.monitoring_url || (onboardingPath === "setup_monitoring" ? "http://prometheus:9090" : ""));
      const username = String(onboardingForm.assignment_username || "").trim();
      const assignmentProject = String(onboardingForm.name || "").trim();
      const userAssignments = username && assignmentProject ? { [username]: [assignmentProject] } : {};
      const monitoringUrls = {
        prometheus_url: selectedMonitoringTool === "prometheus" ? monitoringUrl : "",
        new_relic_url: selectedMonitoringTool === "new_relic" ? monitoringUrl : "",
        datadog_url: selectedMonitoringTool === "datadog" ? monitoringUrl : "",
      };
      const payload = {
        project: {
          name: String(onboardingForm.name || "").trim(),
          owner_team: String(onboardingForm.owner_team || "").trim(),
          environment: String(onboardingForm.environment || "prod").trim(),
          region: String(onboardingForm.region || "").trim(),
        },
        deployment_mode: String(onboardingForm.deployment_mode || "on_prem").trim(),
        ...monitoringUrls,
        azure_subscription_id: String(onboardingForm.azure_subscription_id || "").trim(),
        azure_resource_group: String(onboardingForm.azure_resource_group || "").trim(),
        azure_service_bus_namespace: String(onboardingForm.azure_service_bus_namespace || "").trim(),
        azure_service_bus_topic: String(onboardingForm.azure_service_bus_topic || "").trim(),
        azure_service_bus_subscription: String(onboardingForm.azure_service_bus_subscription || "").trim(),
        azure_content_safety_enabled: Boolean(onboardingForm.azure_content_safety_enabled),
        azure_content_safety_endpoint: String(onboardingForm.azure_content_safety_endpoint || "").trim(),
        user_assignments: userAssignments,
        active_provider: selectedMonitoringTool,
      };

      const plainLanguageRequirements = [
        ...String(onboardingForm.rule_onboarding_plain_language || "")
          .split(/\r?\n/)
          .map(cleanRuleIntentLine)
          .filter(Boolean),
        ...onboardingDerivedRequirements,
      ].map(cleanRuleIntentLine).filter(Boolean).filter((line, index, array) => array.findIndex((item) => item.toLowerCase() === line.toLowerCase()) === index);
      const shouldStartRuleOnboarding = plainLanguageRequirements.length > 0;

      const response = await fetchJson("/api-gateway/onboarding/complete", authenticatedOptions({
        method: "POST",
        body: JSON.stringify({
          project_mode: onboardingProjectMode === "new" ? "new" : "existing",
          onboarding_path: onboardingPath,
          connectivity: payload,
          start_rules_onboarding: shouldStartRuleOnboarding,
          plain_language_requirements: plainLanguageRequirements,
          source_documents: onboardingSourceDocRows.map((row) => ({
            name: String(row?.name || "uploaded-document").trim() || "uploaded-document",
            kind: String(row?.category || classifyOnboardingDocumentType(row?.name, row?.text)).trim().toLowerCase() || "other",
            excerpt: String(row?.excerpt || "").trim(),
            content: String(row?.text || "").slice(0, 12000),
            size: Number(row?.size || 0),
          })),
          selected_monitoring_tool: selectedMonitoringTool,
          generate_documents: true,
        }),
      }));

      const completePayload = unwrap(response);
      const workflowSteps = Array.isArray(completePayload?.workflow_steps) ? completePayload.workflow_steps : [];
      const landingPadSummary = completePayload?.landing_pad_ingestion && typeof completePayload.landing_pad_ingestion === "object"
        ? completePayload.landing_pad_ingestion
        : {};
      setOnboardingWorkflowSteps(workflowSteps);
      setOnboardingLandingPadSummary(landingPadSummary);
      setOnboardingForm((curr) => ({
        ...curr,
        monitoring_tool: selectedMonitoringTool,
        monitoring_url: monitoringUrl,
        assignment_project: String(curr.name || "").trim(),
        ...monitoringUrls,
      }));

      const rulesOnboarding = completePayload?.rules_onboarding || {};
      if (rulesOnboarding?.started && rulesOnboarding?.result) {
        const ruleResult = rulesOnboarding.result;
        setOnboardingRuleRunState({ loading: false, result: ruleResult, error: "" });
        setOnboardingRuleLookup((current) => ({
          ...current,
          workflow_id: String(rulesOnboarding.workflow_id || ruleResult?.workflow_id || current.workflow_id || "").trim(),
        }));
      } else {
        setOnboardingRuleRunState((current) => ({ ...current, loading: false }));
      }
      const backendGeneratedDocs = Array.isArray(completePayload?.rag_documents) ? completePayload.rag_documents : [];
      const generatedDocs = backendGeneratedDocs.length
        ? backendGeneratedDocs
        : buildServiceKnowledgeGeneratedDocs({ projectName: payload.project.name, selectedTool: selectedMonitoringTool });
      setOnboardingGeneratedDocs(generatedDocs);

      setSelectedOnboardingProject(String(payload.project.name || "").trim());
      if (onboardingProjectMode === "new") {
        setOnboardingProjectMode("existing");
      }
      await loadOnboardingAdminData();
      const knowledgeAutoGenerated = onboardingSourceDocCount > 0
        ? await autoGenerateAlertKnowledgeFromSourceDocs({ projectName: payload.project.name, onboardingPath })
        : false;
      await refreshViewsAfterSubmit();
      setOnboardingState((current) => ({
        ...current,
        success: shouldStartRuleOnboarding
          ? generatedDocs.length
            ? `Workflow completed through step ${workflowSteps.length || 0}. Review generated documents and click Approve.`
            : onboardingSourceDocCount > 0
              ? `Workflow completed through step ${workflowSteps.length || 0}. Generated ${generatedDocs.length} Service Knowledge document(s) for review.`
              : `Workflow completed through step ${workflowSteps.length || 0}. No Service Knowledge file was uploaded.`
          : onboardingSourceDocCount > 0
            ? knowledgeAutoGenerated
              ? "Project onboarding saved. Alert Knowledge Onboarding draft was auto-generated from Service Knowledge."
              : "Project onboarding saved. Service Knowledge was detected, but Alert Knowledge auto-generation failed; use manual prompt flow below."
            : "Project onboarding saved. No Service Knowledge uploaded; continue with manual Alert Knowledge prompt and click Create Alert Onboarding Doc.",
      }));
      if (adminWorkspace === "project" && projectSetupStep === "setup") {
        setProjectSetupStep("docs_rules");
      }
      if (onboardingSourceDocCount === 0) {
        setAlertKnowledgeView("onboarding");
      }
    } catch (error) {
      setOnboardingState((current) => ({ ...current, loading: false, error: error.message, success: "" }));
      setOnboardingRuleRunState((current) => ({ ...current, loading: false }));
    }
  }

  function onboardingProjectSeed() {
    const projectName = String(selectedOnboardingProject || onboardingForm.name || "").trim();
    const selectedMonitoringTool = String(onboardingForm.monitoring_tool || "prometheus").trim().toLowerCase();
    return {
      project_name: projectName,
      description: "",
      business_unit: "",
      environment: String(onboardingForm.environment || "prod").trim().toLowerCase(),
      criticality: "high",
      sla: "",
      support_team: String(onboardingForm.owner_team || "").trim(),
      business_owner: "",
      technical_owner: "",
      technology_stack: [],
      cloud_provider: onboardingForm.deployment_mode === "azure_cloud" ? "azure" : "on_prem",
      region: String(onboardingForm.region || "").trim(),
      monitoring_platforms: MONITORING_TOOL_OPTIONS.includes(selectedMonitoringTool) ? [selectedMonitoringTool] : ["prometheus"],
      notification_platforms: ["slack", "teams", "pagerduty"],
    };
  }

  async function loadOnboardingRuleCapabilities() {
    setOnboardingRuleCapabilities((current) => ({ ...current, loading: true, error: "" }));
    try {
      const response = await fetchJson("/api-gateway/onboarding/rules/capabilities", authenticatedOptions());
      const payload = unwrap(response);
      const rows = Array.isArray(payload?.rows) ? payload.rows : [];
      setOnboardingRuleCapabilities({ loading: false, rows, error: "" });
    } catch (error) {
      setOnboardingRuleCapabilities({ loading: false, rows: [], error: error.message });
    }
  }

  async function runExistingRulePipeline(event) {
    event.preventDefault();
    setOnboardingRuleRunState({ loading: true, result: null, error: "" });
    try {
      let rulesToPush = [];
      const rawRules = String(existingRulePipelineForm.rules_json || "").trim();
      if (rawRules) {
        const parsed = JSON.parse(rawRules);
        if (!Array.isArray(parsed)) {
          throw new Error("Rules JSON must be an array of rule objects.");
        }
        rulesToPush = parsed;
      }

      const payload = {
        project: onboardingProjectSeed(),
        platform: String(existingRulePipelineForm.platform || "prometheus").trim(),
        mode: String(existingRulePipelineForm.mode || "bidirectional").trim(),
        rules_to_push: rulesToPush,
        connection_profile: {
          endpoint_url: String(existingRulePipelineForm.connection_url || "").trim(),
        },
      };

      const response = await fetchJson("/api-gateway/onboarding/rules/pipeline/existing", authenticatedOptions({
        method: "POST",
        body: JSON.stringify(payload),
      }));
      const result = unwrap(response);
      setOnboardingRuleRunState({ loading: false, result, error: "" });
      setOnboardingRuleLookup((current) => ({
        ...current,
        workflow_id: String(result?.workflow_id || current.workflow_id || "").trim(),
      }));
      await loadOnboardingAdminData();
    } catch (error) {
      setOnboardingRuleRunState({ loading: false, result: null, error: error.message });
    }
  }

  async function runNewRulePipeline(event) {
    event.preventDefault();
    setOnboardingRuleRunState({ loading: true, result: null, error: "" });
    try {
      const requirements = String(newRulePipelineForm.requirements_text || "")
        .split(/\r?\n/)
        .map((line) => line.trim())
        .filter(Boolean);
      if (!requirements.length) {
        throw new Error("Provide at least one monitoring requirement.");
      }

      const selectedTool = String(newRulePipelineForm.selected_tool || onboardingForm.monitoring_tool || "prometheus").trim().toLowerCase();
      const targetPlatforms = MONITORING_TOOL_OPTIONS.includes(selectedTool) ? [selectedTool] : ["prometheus"];
      const discoveryInputs = {
        endpoint_url: simplifyMonitoringUrl(onboardingForm.monitoring_url),
        deployment_mode: String(onboardingForm.deployment_mode || "on_prem").trim(),
        environment: String(onboardingForm.environment || "prod").trim(),
        generated_from_plain_language: true,
      };

      const payload = {
        project: onboardingProjectSeed(),
        monitoring_requirements: requirements,
        target_platforms: targetPlatforms,
        discovery_inputs: discoveryInputs,
      };

      const response = await fetchJson("/api-gateway/onboarding/rules/pipeline/new", authenticatedOptions({
        method: "POST",
        body: JSON.stringify(payload),
      }));
      const result = unwrap(response);
      setOnboardingRuleRunState({ loading: false, result, error: "" });
      setOnboardingRuleLookup((current) => ({
        ...current,
        workflow_id: String(result?.workflow_id || current.workflow_id || "").trim(),
      }));
      await loadOnboardingAdminData();
    } catch (error) {
      setOnboardingRuleRunState({ loading: false, result: null, error: error.message });
    }
  }

  async function lookupOnboardingRuleWorkflow(event) {
    event.preventDefault();
    const workflowId = String(onboardingRuleLookup.workflow_id || "").trim();
    if (!workflowId) {
      setOnboardingRuleLookup((current) => ({ ...current, error: "Workflow ID is required." }));
      return;
    }
    setOnboardingRuleLookup((current) => ({ ...current, loading: true, result: null, error: "" }));
    try {
      const response = await fetchJson(`/api-gateway/onboarding/rules/pipeline/${encodeURIComponent(workflowId)}`, authenticatedOptions());
      const result = unwrap(response);
      setOnboardingRuleLookup((current) => ({ ...current, loading: false, result, error: "" }));
    } catch (error) {
      setOnboardingRuleLookup((current) => ({ ...current, loading: false, result: null, error: error.message }));
    }
  }

  function normalizeDocumentToken(value) {
    return String(value || "")
      .trim()
      .toLowerCase()
      .replace(/[\s_]+/g, "-")
      .replace(/-+/g, "-");
  }

  function collectDocumentTokens(...values) {
    const tokens = new Set();
    values.forEach((value) => {
      if (Array.isArray(value)) {
        value.forEach((item) => collectDocumentTokens(item).forEach((token) => tokens.add(token)));
        return;
      }
      const raw = String(value || "").trim();
      if (!raw) {
        return;
      }
      const normalizedRaw = normalizeDocumentToken(raw);
      if (normalizedRaw) {
        tokens.add(normalizedRaw);
      }
      raw
        .split(/[,;|\s]+/)
        .map(normalizeDocumentToken)
        .filter(Boolean)
        .forEach((token) => tokens.add(token));
    });
    return tokens;
  }

  function getAlertDocumentMatchContext(alertRow) {
    const labels = typeof alertRow?.labels === "object" && alertRow?.labels ? alertRow.labels : {};
    const metadata = typeof alertRow?.metadata === "object" && alertRow?.metadata ? alertRow.metadata : {};
    const ids = collectDocumentTokens(
      alertRow?.alert_id,
      alertRow?.id,
      alertRow?.incident_id,
      metadata?.alert_id,
      metadata?.incident_id,
      labels?.alert_id,
    );
    const alertTypes = collectDocumentTokens(
      alertRow?.alert_type,
      alertRow?.name,
      alertRow?.alert_name,
      alertRow?.alertname,
      labels?.alertname,
      labels?.alert_type,
      labels?.rule,
    );
    const services = collectDocumentTokens(
      alertRow?.service,
      alertRow?.application,
      alertRow?.project,
      alertRow?.project_name,
      alertRow?.component,
      metadata?.service,
      metadata?.application,
      metadata?.project,
      labels?.service,
      labels?.job,
      labels?.application,
      labels?.project,
      labels?.project_name,
      labels?.deployment,
      labels?.namespace,
      labels?.instance,
    );
    const genericServiceDocsAllowed = alertRow?.document_available === true || Boolean(metadata?.runbook_hint);
    return { ids, alertTypes, services, genericServiceDocsAllowed };
  }

  function ragDocumentMatchesAlert(doc, context) {
    const docIds = collectDocumentTokens(doc?.alert_id, doc?.id, doc?.metadata?.alert_id, doc?.metadata?.incident_id);
    if ([...context.ids].some((id) => docIds.has(id))) {
      return true;
    }
    const docAlertTypes = collectDocumentTokens(doc?.alert_type, doc?.alert_name, doc?.alertname, doc?.metadata?.alert_type);
    const docServices = collectDocumentTokens(doc?.services, doc?.service, doc?.metadata?.service, doc?.metadata?.services);
    const hasAlertTypeMatch = [...context.alertTypes].some((type) => docAlertTypes.has(type));
    const hasServiceMatch = [...context.services].some((service) => docServices.has(service));
    if (hasAlertTypeMatch && hasServiceMatch) {
      return true;
    }
    const docKind = String(doc?.kind || doc?.document_kind || "").trim().toLowerCase();
    const isGenericServiceDoc = !docIds.size && hasServiceMatch && ["runbook", "incident", "sop", "onboarding"].includes(docKind);
    return Boolean(context.genericServiceDocsAllowed && isGenericServiceDoc);
  }

  function findMatchingRagDocument(alertRow, preferredKind = "") {
    const context = getAlertDocumentMatchContext(alertRow);
    const normalizedKind = String(preferredKind || "").trim().toLowerCase();
    const docs = Array.isArray(ragDocs.rows) ? ragDocs.rows : [];
    return docs.find((doc) => {
      const docKind = String(doc?.kind || doc?.document_kind || "").trim().toLowerCase();
      if (normalizedKind && docKind && docKind !== normalizedKind) {
        return false;
      }
      return ragDocumentMatchesAlert(doc, context);
    }) || null;
  }

  function findAlertRagDocuments(alertRow) {
    if (!alertRow || typeof alertRow !== "object") {
      return [];
    }
    const context = getAlertDocumentMatchContext(alertRow);
    const docs = Array.isArray(ragDocs.rows) ? ragDocs.rows : [];
    return docs.filter((doc) => ragDocumentMatchesAlert(doc, context));
  }

  async function downloadRagDocument(doc) {
    const path = String(doc?.path || "").trim();
    try {
      const full = path
        ? unwrap(await fetchJson(`/api-gateway/rag/documents/content?path=${encodeURIComponent(path)}`, authenticatedOptions()))
        : doc;
      const title = String(full?.title || doc?.title || (path ? path.split(/[\\/]/).pop() : "") || "alert-document").trim();
      const content = [
        `# ${title}`,
        "",
        full?.summary ? `Summary: ${String(full.summary).trim()}` : "",
        full?.kind || doc?.kind ? `Kind: ${String(full?.kind || doc?.kind).trim()}` : "",
        full?.alert_id || doc?.alert_id ? `Alert ID: ${String(full?.alert_id || doc?.alert_id).trim()}` : "",
        doc?.match_reason ? `Context match: ${String(doc.match_reason).trim()}` : "",
        doc?.match_confidence ? `Match confidence: ${Math.round(Number(doc.match_confidence) * 100)}%` : "",
        "",
        String(full?.content || doc?.content || doc?.recommended_action || doc?.summary || "").trim(),
      ].filter((line) => line !== "").join("\n");
      const safeName = `${title || "alert-document"}`.replace(/[^a-zA-Z0-9._-]+/g, "-").replace(/^-+|-+$/g, "") || "alert-document";
      const blob = new Blob([content || JSON.stringify(full || doc, null, 2)], { type: "text/markdown;charset=utf-8" });
      const objectUrl = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = objectUrl;
      anchor.download = `${safeName}.md`;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(objectUrl);
    } catch (error) {
      setRagDocs((current) => ({ ...current, error: `Download failed: ${String(error?.message || "Unknown error")}` }));
    }
  }

  async function loadRagDocumentContent(doc) {
    const path = String(doc?.path || "").trim();
    if (!path) {
      return doc;
    }
    const full = unwrap(await fetchJson(`/api-gateway/rag/documents/content?path=${encodeURIComponent(path)}`, authenticatedOptions()));
    return {
      ...doc,
      ...(full && typeof full === "object" ? full : {}),
      path: full?.path || doc?.path || path,
    };
  }

  function backendDocumentPreview(doc) {
    const summary = String(doc?.summary || "").trim();
    const action = String(doc?.recommended_action || "").trim();
    const content = String(doc?.content || "").trim();
    const rootCause = String(doc?.root_cause || "").trim();
    const impact = String(doc?.impact || "").trim();
    const fallback = [rootCause, impact, action].filter(Boolean).join(" ");
    return String(summary || content || fallback || "Open the document view to inspect backend metadata and download the document.")
      .replace(/\s+/g, " ")
      .slice(0, 240);
  }

  async function downloadConsolidatedAlertDocument(docs) {
    const rows = Array.isArray(docs) ? docs.filter(Boolean) : [];
    if (!rows.length) {
      return;
    }
    const alertName = String(selectedAlertRow?.name || selectedAlertId || "alert").trim();
    const service = String(selectedAlertRow?.service || rows[0]?.services?.[0] || rows[0]?.service || "service").trim();
    try {
      const sections = [];
      for (const [index, doc] of rows.entries()) {
        const path = String(doc?.path || "").trim();
        let full = {};
        if (path) {
          try {
            full = unwrap(await fetchJson(`/api-gateway/rag/documents/content?path=${encodeURIComponent(path)}`, authenticatedOptions()));
          } catch (_error) {
            full = {};
          }
        }
        const title = String(full?.title || doc?.title || `Document ${index + 1}`).trim();
        sections.push([
          `## ${title}`,
          "",
          `Kind: ${String(full?.kind || doc?.kind || doc?.document_kind || "document").trim()}`,
          doc?.match_reason ? `Match reason: ${String(doc.match_reason).trim()}` : "",
          doc?.match_confidence ? `Match confidence: ${Math.round(Number(doc.match_confidence) * 100)}%` : "",
          full?.summary || doc?.summary ? `Summary: ${String(full?.summary || doc?.summary).trim()}` : "",
          "",
          String(full?.content || doc?.content || doc?.recommended_action || "Document content is available in backend metadata.").trim(),
        ].filter((line) => line !== "").join("\n"));
      }
      const content = [
        `# ${service} Alert Knowledge Document`,
        "",
        `Alert: ${alertName}`,
        `Service: ${service}`,
        `Linked backend documents: ${rows.length}`,
        "",
        ...sections,
      ].join("\n\n");
      const safeName = `${service || "service"}-${alertName || "alert"}-knowledge`
        .replace(/[^a-zA-Z0-9._-]+/g, "-")
        .replace(/^-+|-+$/g, "") || "alert-knowledge";
      const blob = new Blob([content], { type: "text/markdown;charset=utf-8" });
      const objectUrl = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = objectUrl;
      anchor.download = `${safeName}.md`;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(objectUrl);
    } catch (error) {
      setRagDocs((current) => ({ ...current, error: `Download failed: ${String(error?.message || "Unknown error")}` }));
    }
  }

  function hasAlertDocuments(alertRow) {
    if (!alertRow || typeof alertRow !== "object") {
      return false;
    }
    const explicitFlag = alertRow.document_available === true;
    if (explicitFlag) {
      return true;
    }
    return Boolean(findMatchingRagDocument(alertRow));
  }

  function buildAlertDocumentDraft(alertRow, workflowPayload, preferredKind = "runbook") {
    const allDrafts = buildAlertDocumentDrafts(alertRow, workflowPayload);
    const kind = String(preferredKind || "runbook").trim().toLowerCase();
    return allDrafts[kind] || allDrafts.runbook;
  }

  async function buildAlertDocumentDraftWithAnalysis(alertRow, preferredKind = "runbook") {
    const alertId = String(alertRow?.alert_id || alertRow?.id || "").trim();
    let workflowPayload = {};
    if (alertId && String(selectedAlertData?.alertId || "").trim() === alertId && selectedAlertData?.payload) {
      workflowPayload = selectedAlertData.payload?.data || selectedAlertData.payload;
    } else if (alertId) {
      try {
        const payload = await fetchJson(`/monitoring-adapter/alerts/${alertId}/processed-result`);
        workflowPayload = payload?.data || payload;
      } catch (_error) {
        workflowPayload = {};
      }
    }
    return buildAlertDocumentDraft(alertRow, workflowPayload, preferredKind);
  }

  function buildDocPayloadFromDraft(draft) {
    const toPlanLines = (value) => {
      if (Array.isArray(value)) {
        return value.map((item) => String(item || "").trim()).filter(Boolean);
      }
      return String(value || "")
        .split(/\r?\n/)
        .map((item) => item.trim())
        .filter(Boolean);
    };

    const commands = toPlanLines(draft.remediation_commands_text ?? draft.commands);
    const scripts = toPlanLines(draft.remediation_scripts_text ?? draft.scripts);
    const queries = toPlanLines(draft.remediation_queries_text ?? draft.queries);
    const executionPlan = String(draft.execution_plan || "").trim() || [
      commands.length ? `Commands:\n${commands.map((item) => `- ${item}`).join("\n")}` : "",
      scripts.length ? `Remediation Script:\n${scripts.map((item) => `- ${item}`).join("\n")}` : "",
      queries.length ? `Queries:\n${queries.map((item) => `- ${item}`).join("\n")}` : "",
    ].filter(Boolean).join("\n\n");

    return {
      kind: draft.kind,
      title: draft.title,
      summary: draft.summary || null,
      content: draft.content,
      services: String(draft.services || "")
        .split(",")
        .map((item) => item.trim())
        .filter(Boolean),
      severity: draft.severity,
      alert_type: draft.alert_type,
      alert_id: draft.alert_id || null,
      root_cause: draft.root_cause || null,
      impact: draft.impact || null,
      execution_plan: executionPlan || null,
      commands,
      scripts,
      queries,
      recommended_action: draft.recommended_action || null,
    };
  }

  async function setDocPromptDraftForKind(row, kind) {
    const normalizedKind = String(kind || "runbook").trim().toLowerCase();
    const alertId = String(row?.alert_id || row?.id || "").trim();
    const existingDoc = findMatchingRagDocument(row, normalizedKind);
    setDocPromptKind(normalizedKind);
    setDocPromptExistingDoc(existingDoc);
    setDocPromptMode(existingDoc?.path ? "update" : "create");

    if (existingDoc?.path) {
      // Show the real saved document instead of a freshly generated draft.
      setAlertOnboardingState({ loading: true, result: null, error: "" });
      try {
        const full = unwrap(await fetchJson(`/api-gateway/rag/documents/content?path=${encodeURIComponent(existingDoc.path)}`));
        setAlertOnboarding((curr) => ({
          ...curr,
          kind: normalizedKind,
          title: String(full.title || existingDoc.title || "Alert Document").slice(0, 160),
          summary: String(full.summary || "").trim(),
          content: String(full.content || "").trim(),
          services: Array.isArray(full.services) ? full.services.join(", ") : String(full.services || "").trim(),
          severity: String(full.severity || "high").toLowerCase(),
          alert_type: String(full.alert_type || "").trim(),
          alert_id: alertId,
        }));
        setAlertOnboardingState({ loading: false, result: null, error: "" });
      } catch (error) {
        setAlertOnboardingState({ loading: false, result: null, error: error.message });
      }
      return;
    }

    const selectedPayload = String(selectedAlertData?.alertId || "").trim() === alertId
      ? (selectedAlertData.payload?.data || selectedAlertData.payload || {})
      : {};
    const draft = buildAlertDocumentDraft(row, selectedPayload, normalizedKind);
    setAlertOnboarding((curr) => ({
      ...curr,
      kind: draft.kind,
      title: String(draft.title || "Alert Document").slice(0, 160),
      summary: String(draft.summary || "").trim(),
      content: String(draft.content || "Provide troubleshooting and escalation steps for this alert scenario.").trim(),
      services: String(draft.services || "").trim(),
      severity: String(draft.severity || "high").toLowerCase(),
      alert_type: String(draft.alert_type || "").trim(),
      alert_id: alertId,
      execution_plan: String(draft.execution_plan || "").trim(),
      remediation_commands_text: Array.isArray(draft.commands) ? draft.commands.join("\n") : "",
      remediation_scripts_text: Array.isArray(draft.scripts) ? draft.scripts.join("\n") : "",
      remediation_queries_text: Array.isArray(draft.queries) ? draft.queries.join("\n") : "",
    }));
  }

  async function autoGenerateRemediationPlan(alertRow = null) {
    const sourceRow = alertRow && typeof alertRow === "object"
      ? alertRow
      : {
          alert_id: alertOnboarding.alert_id,
          name: alertOnboarding.alert_type || alertOnboarding.title || "Alert",
          service: String(alertOnboarding.services || "").split(",")[0]?.trim() || "unknown-service",
          severity: alertOnboarding.severity || "high",
        };
    const draft = alertRow && typeof alertRow === "object"
      ? await buildAlertDocumentDraftWithAnalysis(sourceRow, "remediation")
      : buildAlertDocumentDraft(sourceRow, {}, "remediation");
    setAlertOnboarding((curr) => ({
      ...curr,
      kind: "remediation",
      title: String(draft.title || curr.title || "Remediation Plan").slice(0, 160),
      summary: String(draft.summary || curr.summary || "").trim(),
      content: String(draft.content || curr.content || "").trim(),
      services: String(draft.services || curr.services || "").trim(),
      severity: String(draft.severity || curr.severity || "high").toLowerCase(),
      alert_type: String(draft.alert_type || curr.alert_type || "").trim(),
      alert_id: String(draft.alert_id || curr.alert_id || "").trim(),
      execution_plan: String(draft.execution_plan || "").trim(),
      remediation_commands_text: Array.isArray(draft.commands) ? draft.commands.join("\n") : "",
      remediation_scripts_text: Array.isArray(draft.scripts) ? draft.scripts.join("\n") : "",
      remediation_queries_text: Array.isArray(draft.queries) ? draft.queries.join("\n") : "",
    }));
  }

  function parseAiDraftContent(content) {
    const text = String(content || "").trim();
    if (!text) {
      return null;
    }
    const candidates = [text];
    const fenced = text.match(/```json\s*([\s\S]*?)```/i);
    if (fenced?.[1]) {
      candidates.push(String(fenced[1]).trim());
    }
    const objectBlock = text.match(/\{[\s\S]*\}/);
    if (objectBlock?.[0]) {
      candidates.push(String(objectBlock[0]).trim());
    }
    for (const candidate of candidates) {
      try {
        const parsed = JSON.parse(candidate);
        if (parsed && typeof parsed === "object") {
          return parsed;
        }
      } catch (_error) {
        // Try next extraction candidate.
      }
    }
    return null;
  }

  function normalizeDraftList(value) {
    if (Array.isArray(value)) {
      return value.map((item) => String(item || "").trim()).filter(Boolean);
    }
    return String(value || "")
      .split(/\r?\n/)
      .map((item) => item.replace(/^[-*]\s*/, "").trim())
      .filter(Boolean);
  }

  async function generateAlertKnowledgeDraftFromPrompt() {
    const prompt = buildAlertKnowledgePromptInput();
    if (!prompt) {
      setAlertOnboardingState({ loading: false, result: null, error: "Enter a prompt or upload a supporting document to generate the document draft." });
      return;
    }

    const normalizedKind = String(alertOnboarding.kind || "incident").trim().toLowerCase();
    const sourceDocName = String(alertKnowledgeSourceDoc?.name || "").trim();
    const lines = prompt
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter(Boolean);
    const sentences = prompt
      .split(/(?<=[.!?])\s+/)
      .map((item) => item.trim())
      .filter(Boolean);
    const summary = String(sentences[0] || lines[0] || prompt).slice(0, 260);
    const titleSeed = String(lines[0] || prompt)
      .replace(/^[-*#\d.\s]+/, "")
      .split(/\s+/)
      .slice(0, 8)
      .join(" ")
      .trim();
    const fallbackTitle = `${normalizedKind[0]?.toUpperCase() || "D"}${normalizedKind.slice(1)} Doc`;
    const generatedTitle = titleSeed ? titleSeed.slice(0, 160) : fallbackTitle;

    const commandMatches = [];
    const scriptMatches = [];
    const queryMatches = [];

    const cleanToken = (value) => String(value || "").trim().replace(/^[-*]\s*/, "");
    const pushUnique = (target, value) => {
      const normalized = cleanToken(value);
      if (!normalized) {
        return;
      }
      if (!target.some((item) => item.toLowerCase() === normalized.toLowerCase())) {
        target.push(normalized);
      }
    };

    const extractTaggedValues = (inputText, tagPattern) => {
      const regex = new RegExp(`\\b(?:${tagPattern})\\s*[:\\-]\\s*([^\\n;|]+)`, "ig");
      const values = [];
      let match = regex.exec(inputText);
      while (match) {
        values.push(match[1]);
        match = regex.exec(inputText);
      }
      return values;
    };

    const shellLike = /^(kubectl|kubeadm|helm|docker|docker-compose|compose|terraform|ansible|oc|az|aws|gcloud|systemctl|journalctl|curl|wget|psql|mysql|redis-cli|kafka-|python\s+|pip\s+|npm\s+|node\s+|pwsh\s+|powershell\s+|bash\s+)/i;
    const sqlLike = /\b(select|update|delete|insert|with|merge|create\s+table|drop\s+table|alter\s+table)\b/i;

    extractTaggedValues(prompt, "cmd|command").forEach((value) => pushUnique(commandMatches, value));
    extractTaggedValues(prompt, "script|ps1|sh|bash").forEach((value) => pushUnique(scriptMatches, value));
    extractTaggedValues(prompt, "query|sql").forEach((value) => pushUnique(queryMatches, value));

    const codeFenceRegex = /```([a-zA-Z0-9_-]*)\n([\s\S]*?)```/g;
    let fenceMatch = codeFenceRegex.exec(prompt);
    while (fenceMatch) {
      const lang = String(fenceMatch[1] || "").trim().toLowerCase();
      const body = String(fenceMatch[2] || "")
        .split(/\r?\n/)
        .map((line) => line.trim())
        .filter(Boolean)
        .join(" ; ");
      if (body) {
        if (lang.includes("sql") || sqlLike.test(body)) {
          pushUnique(queryMatches, body);
        } else if (lang.includes("bash") || lang.includes("sh") || lang.includes("ps") || lang.includes("powershell")) {
          pushUnique(scriptMatches, body);
        } else if (shellLike.test(body)) {
          pushUnique(commandMatches, body);
        }
      }
      fenceMatch = codeFenceRegex.exec(prompt);
    }

    const taggedSegment = /\b(cmd|command|script|query|sql|ps1|bash|sh)\s*[:\-]/i;
    const fallbackSegments = prompt
      .split(/[\r\n;]+/)
      .map((item) => item.trim())
      .filter(Boolean);

    fallbackSegments.forEach((segment) => {
      if (taggedSegment.test(segment)) {
        return;
      }
      if (shellLike.test(segment)) {
        pushUnique(commandMatches, segment);
        return;
      }
      if (sqlLike.test(segment)) {
        pushUnique(queryMatches, segment);
      }
    });

    const narrativeSegments = fallbackSegments.filter((segment) => {
      if (taggedSegment.test(segment)) {
        return false;
      }
      if (shellLike.test(segment) || sqlLike.test(segment)) {
        return false;
      }
      return true;
    });

    const sentenceTail = sentences
      .slice(1, 4)
      .map((item) => item.trim())
      .filter(Boolean)
      .join(" ");

    const narrativeDetail = [
      ...narrativeSegments,
      sentenceTail,
    ]
      .map((item) => String(item || "").trim())
      .filter(Boolean)
      .filter((item, index, arr) => arr.findIndex((other) => other.toLowerCase() === item.toLowerCase()) === index)
      .join("\n");

    const contentBody = [
      summary,
      narrativeDetail,
    ].filter(Boolean).join("\n\n");

    let aiDraft = null;
    let aiUsage = null;
    try {
      const aiResponseRaw = await fetchJson("/api-gateway/model/route", authenticatedOptions({
        method: "POST",
        body: JSON.stringify({
          severity: String(alertOnboarding.severity || "high").trim().toLowerCase(),
          task: normalizedKind === "remediation" ? "fix" : "summarization",
          prompt: [
            `Generate a meaningful ${normalizedKind} document draft for SRE operations from user input.`,
            "Return ONLY valid JSON with keys: title, summary, content, commands, scripts, queries, metadata.",
            "For remediation, prefer one guarded script with connection details over scattered command/query fragments.",
          ].join(" "),
          payload: {
            kind: normalizedKind,
            alert_type: String(alertOnboarding.alert_type || "").trim(),
            services: String(alertOnboarding.services || "").trim(),
            user_prompt: prompt,
            source_document: sourceDocName || null,
          },
        }),
      }));
      const aiResponse = aiResponseRaw?.data && typeof aiResponseRaw.data === "object"
        ? aiResponseRaw.data
        : aiResponseRaw;
      aiUsage = aiResponse?.usage || null;
      aiDraft = parseAiDraftContent(aiResponse?.content || "");
    } catch (_error) {
      aiDraft = null;
    }

    const mergeUnique = (base, extra) => {
      const out = [];
      [...normalizeDraftList(base), ...normalizeDraftList(extra)].forEach((item) => {
        if (!out.some((existing) => existing.toLowerCase() === item.toLowerCase())) {
          out.push(item);
        }
      });
      return out;
    };

    const aiCommands = normalizeDraftList(aiDraft?.commands);
    const aiScripts = normalizeDraftList(aiDraft?.scripts);
    const aiQueries = normalizeDraftList(aiDraft?.queries);
    const mergedCommands = mergeUnique(aiCommands, commandMatches);
    const mergedScripts = mergeUnique(aiScripts, scriptMatches);
    const mergedQueries = mergeUnique(aiQueries, queryMatches);
    const serviceForScript = String(alertOnboarding.services || alertOnboarding.alert_type || applicationToMonitor || "kaiops-service")
      .split(",")
      .map((item) => item.trim())
      .filter(Boolean)[0] || "kaiops-service";
    const environmentForScript = String(alertOnboarding.environment || onboardingForm.environment || "prod").trim() || "prod";
    const generatedScript = buildKaiOpsRemediationScript({
      service: serviceForScript,
      environment: environmentForScript,
      apiGatewayUrl: "http://api-gateway:8000",
      prometheusUrl: onboardingForm.prometheus_url || onboardingForm.monitoring_url || "http://prometheus:9090",
      mysqlHost: "mysql",
      mysqlDatabase: "kaiops",
      mysqlUser: "kaiops",
    });
    const finalCommands = normalizedKind === "remediation" ? [] : mergedCommands;
    const finalQueries = normalizedKind === "remediation" ? [] : mergedQueries;
    const finalScripts = normalizedKind === "remediation"
      ? [generatedScript]
      : mergedScripts;
    const mergedExecutionPlan = [
      finalCommands.length ? `Commands:\n${finalCommands.map((item) => `- ${item}`).join("\n")}` : "",
      finalScripts.length ? `Remediation Script:\n${finalScripts.map((item) => `- ${item}`).join("\n")}` : "",
      finalQueries.length ? `Queries:\n${finalQueries.map((item) => `- ${item}`).join("\n")}` : "",
    ].filter(Boolean).join("\n\n");

    setAlertOnboarding((curr) => ({
      ...curr,
      title: String(aiDraft?.title || generatedTitle).slice(0, 160),
      summary: String(aiDraft?.summary || summary).trim(),
      content: String(aiDraft?.content || contentBody || prompt).trim(),
      execution_plan: normalizedKind === "remediation" ? mergedExecutionPlan : curr.execution_plan,
      remediation_commands_text: normalizedKind === "remediation" ? finalCommands.join("\n") : curr.remediation_commands_text,
      remediation_scripts_text: normalizedKind === "remediation" ? finalScripts.join("\n") : curr.remediation_scripts_text,
      remediation_queries_text: normalizedKind === "remediation" ? finalQueries.join("\n") : curr.remediation_queries_text,
    }));

    setAlertOnboardingState({
      loading: false,
      result: {
        message: aiDraft
          ? `Draft generated from ${sourceDocName ? "prompt + document" : "prompt"} using AI + heuristics. Review and click Create Alert Onboarding Doc.`
          : `Draft generated from ${sourceDocName ? "prompt + document" : "prompt"} using heuristics fallback. Review and click Create Alert Onboarding Doc.`,
        source_document: sourceDocName || null,
        ai_usage: aiUsage,
      },
      error: "",
    });
  }

  async function autoCreateAlertDocument(alertRow, preferredKind = "runbook") {
    if (!alertRow || alertOnboardingState.loading) {
      return;
    }
    setAlertOnboardingState({ loading: true, result: null, error: "" });
    try {
      const draft = await buildAlertDocumentDraftWithAnalysis(alertRow, preferredKind);
      const existingDoc = findMatchingRagDocument(alertRow, draft.kind);
      const payload = buildDocPayloadFromDraft(draft);
      const response = await fetchJson("/api-gateway/rag/documents", authenticatedOptions({
        method: existingDoc?.path ? "PUT" : "POST",
        body: JSON.stringify(existingDoc?.path ? { ...payload, path: existingDoc.path } : payload),
      }));
      const responseData = response?.data || response || {};
      setAlertOnboardingState({
        loading: false,
        error: "",
        result: {
          ...response,
          message: existingDoc?.path
            ? `${draft.kind} document updated from alert analysis.`
            : `${draft.kind} document created from alert analysis.`,
        },
      });
      await Promise.all([loadRagDocs(), loadRecentAlerts()]);
      if (docPromptAlert) {
        const mergedDoc = {
          ...(existingDoc || {}),
          ...(typeof responseData === "object" && responseData ? responseData : {}),
          kind: draft.kind,
          path: responseData?.path || existingDoc?.path,
          alert_id: draft.alert_id || existingDoc?.alert_id || null,
        };
        setDocPromptDocsByKind((curr) => ({ ...curr, [draft.kind]: mergedDoc }));
        if (String(docPromptKind || "").trim().toLowerCase() === draft.kind) {
          setDocPromptExistingDoc(mergedDoc);
          setDocPromptMode(mergedDoc?.path ? "update" : "create");
        }
      }
    } catch (error) {
      setAlertOnboardingState({ loading: false, result: null, error: error.message });
    }
  }

  async function autoCreateAllAlertDocuments(alertRow) {
    if (!alertRow || alertOnboardingState.loading) {
      return;
    }
    setAlertOnboardingState({ loading: true, result: null, error: "" });
    try {
      const results = [];
      for (const kind of ALERT_DOC_KIND_OPTIONS) {
        const draft = await buildAlertDocumentDraftWithAnalysis(alertRow, kind);
        const existingDoc = findMatchingRagDocument(alertRow, kind);
        const payload = buildDocPayloadFromDraft(draft);
        const response = await fetchJson("/api-gateway/rag/documents", authenticatedOptions({
          method: existingDoc?.path ? "PUT" : "POST",
          body: JSON.stringify(existingDoc?.path ? { ...payload, path: existingDoc.path } : payload),
        }));
        results.push({ kind, path: response?.data?.path || response?.path || existingDoc?.path || "" });
      }
      await Promise.all([loadRagDocs(), loadRecentAlerts()]);
      setAlertOnboardingState({
        loading: false,
        error: "",
        result: {
          message: `Created/updated ${results.length} document types: ${results.map((item) => item.kind).join(", ")}`,
          results,
        },
      });
      if (docPromptAlert) {
        const refreshedByKind = {};
        ALERT_DOC_KIND_OPTIONS.forEach((kind) => {
          const matched = findMatchingRagDocument(docPromptAlert, kind);
          if (matched) {
            refreshedByKind[kind] = matched;
          }
        });
        setDocPromptDocsByKind(refreshedByKind);
        setDocPromptExistingDoc(refreshedByKind[docPromptKind] || null);
        setDocPromptMode(refreshedByKind[docPromptKind]?.path ? "update" : "create");
      }
    } catch (error) {
      setAlertOnboardingState({ loading: false, result: null, error: error.message });
    }
  }

  async function addRuleFromAlertPrompt() {
    const row = docPromptAlert;
    const requirement = String(alertRuleDraft.requirement || "").trim();
    if (!row || !requirement) {
      setAlertRuleState({ loading: false, result: null, error: "Provide a rule requirement first." });
      return;
    }
    setAlertRuleState({ loading: true, result: null, error: "" });
    try {
      const service = String(row?.service || "unknown-service").trim();
      const projectName = String(row?.application || row?.project_name || service || "alert-onboarding").trim();
      const platform = String(alertRuleDraft.platform || "prometheus").trim().toLowerCase();
      const payload = {
        project: {
          project_name: projectName,
          environment: String(row?.environment || onboardingForm.environment || "prod").trim().toLowerCase(),
          criticality: String(row?.severity || "high").trim().toLowerCase() === "critical" ? "high" : "medium",
          support_team: String(onboardingForm.owner_team || "platform-ops").trim(),
          region: String(onboardingForm.region || "us-east-1").trim(),
          cloud_provider: onboardingForm.deployment_mode === "azure_cloud" ? "azure" : "on_prem",
          monitoring_platforms: [platform],
          notification_platforms: ["slack", "teams"],
        },
        monitoring_requirements: [requirement],
        target_platforms: [platform],
        discovery_inputs: {
          source_alert_id: String(row?.alert_id || row?.id || "").trim(),
          alert_type: String(row?.name || row?.alert_name || "").trim(),
          service,
          severity: String(row?.severity || "high").trim().toLowerCase(),
          endpoint_url: simplifyMonitoringUrl(onboardingForm.monitoring_url),
          generated_from_alert_analysis: true,
        },
      };
      const response = await fetchJson("/api-gateway/onboarding/rules/pipeline/create", authenticatedOptions({
        method: "POST",
        body: JSON.stringify(payload),
      }));
      const data = unwrap(response);
      const workflowId = String(data?.workflow_id || "").trim();
      if (workflowId) {
        setOnboardingRuleLookup((current) => ({ ...current, workflow_id: workflowId }));
      }
      setAlertRuleState({ loading: false, result: data, error: "" });
    } catch (error) {
      setAlertRuleState({ loading: false, result: null, error: error.message });
    }
  }

  async function submitAlertOnboarding(event) {
    event.preventDefault();
    setAlertOnboardingState({ loading: true, result: null, error: "" });
    try {
      const payload = {
        ...buildDocPayloadFromDraft(alertOnboarding),
        kind: String(alertOnboarding.kind || "incident").trim(),
        title: String(alertOnboarding.title || "").trim(),
        content: String(alertOnboarding.content || "").trim(),
        severity: String(alertOnboarding.severity || "").trim(),
      };
      const isUpdate = docPromptMode === "update" && Boolean(docPromptExistingDoc?.path);
      const response = await fetchJson("/api-gateway/rag/documents", authenticatedOptions({
        method: isUpdate ? "PUT" : "POST",
        body: JSON.stringify(isUpdate ? { ...payload, path: docPromptExistingDoc.path } : payload),
      }));
      const responseData = response?.data || response || {};
      const normalizedKind = String(payload.kind || docPromptKind || "runbook").trim().toLowerCase();
      const mergedDoc = {
        ...(docPromptExistingDoc || {}),
        ...(typeof responseData === "object" && responseData ? responseData : {}),
        kind: normalizedKind,
        alert_id: payload.alert_id,
        alert_type: payload.alert_type,
        services: payload.services,
        path: responseData?.path || docPromptExistingDoc?.path,
      };
      setAlertOnboardingState({
        loading: false,
        result: {
          ...response,
          message: isUpdate ? `${normalizedKind} document updated.` : `${normalizedKind} document created.`,
        },
        error: "",
      });
      setDocPromptDocsByKind((curr) => ({ ...curr, [normalizedKind]: mergedDoc }));
      setDocPromptExistingDoc(mergedDoc);
      setDocPromptMode(mergedDoc?.path ? "update" : "create");
      await Promise.all([loadRagDocs(), loadRecentAlerts()]);
      await refreshViewsAfterSubmit();
    } catch (error) {
      setAlertOnboardingState({ loading: false, result: null, error: error.message });
    }
  }

  async function autoGenerateAlertKnowledgeFromSourceDocs({ projectName, onboardingPath }) {
    const sourceRows = onboardingSourceDocRows;
    if (!sourceRows.length) {
      return false;
    }

    const safeProject = String(projectName || onboardingForm.name || "").trim() || "Project";
    const summary = `Auto-generated from ${sourceRows.length} uploaded source document(s).`;
    const evidenceLines = sourceRows.slice(0, 8).map((row) => {
      const label = onboardingSourceDocCategoryLabel(row?.category);
      const excerpt = String(row?.excerpt || "").trim();
      return `- [${label}] ${String(row?.name || "uploaded-document").trim()}${excerpt ? `: ${excerpt}` : ""}`;
    });
    const requirementLines = onboardingDerivedRequirements.slice(0, 8).map((line) => `- ${line}`);
    const content = [
      `Auto-generated alert onboarding for ${safeProject}.`,
      "",
      "Source evidence:",
      ...evidenceLines,
      "",
      "Derived requirements:",
      ...(requirementLines.length ? requirementLines : ["- No derived requirements captured."]),
      "",
      "Use this draft to refine final triage and remediation guidance.",
    ].join("\n");

    const autoDraft = {
      kind: "runbook",
      title: `${safeProject} Alert Knowledge Onboarding`,
      summary,
      content,
      services: safeProject,
      severity: "high",
      alert_type: onboardingPath === "setup_monitoring" ? "configuration" : "availability",
      alert_id: "",
      root_cause: "",
      impact: "",
      execution_plan: "",
      remediation_commands_text: "",
      remediation_scripts_text: "",
      remediation_queries_text: "",
      recommended_action: "Review generated draft and finalize onboarding knowledge.",
    };

    try {
      const response = await fetchJson("/api-gateway/rag/documents", authenticatedOptions({
        method: "POST",
        body: JSON.stringify(buildDocPayloadFromDraft(autoDraft)),
      }));
      setAlertOnboarding((curr) => ({ ...curr, ...autoDraft }));
      setAlertOnboardingState({
        loading: false,
        result: {
          ...response,
          message: "Alert Knowledge Onboarding auto-generated from Service Knowledge.",
        },
        error: "",
      });
      setAlertKnowledgeView("onboarding");
      return true;
    } catch (error) {
      setAlertOnboardingState({
        loading: false,
        result: null,
        error: `Automatic Alert Knowledge generation failed: ${String(error?.message || "Unknown error")}`,
      });
      setAlertKnowledgeView("onboarding");
      return false;
    }
  }

  function openDocumentPrompt(row) {
    if (!canProvideAlertDocuments) {
      setDocPromptAlert(null);
      return;
    }
    const byKind = {};
    ALERT_DOC_KIND_OPTIONS.forEach((kind) => {
      const doc = findMatchingRagDocument(row, kind);
      if (doc) {
        byKind[kind] = doc;
      }
    });
    setDocPromptDocsByKind(byKind);
    setDocPromptAlert(row);
    // If documents already exist for this alert, open on the first available
    // one so the real saved content is shown; otherwise default to runbook
    // for creating a new document.
    const initialKind = ALERT_DOC_KIND_OPTIONS.find((kind) => byKind[kind]) || "runbook";
    setDocPromptDraftForKind(row, initialKind);
    const defaultRequirement = `Create a ${String(row?.severity || "high").toLowerCase()} alert rule for ${String(row?.service || "this service").trim()} based on ${String(row?.name || row?.alert_name || "service degradation").trim()} and route incidents to on-call.`;
    setAlertRuleDraft({ platform: String(onboardingForm.monitoring_tool || "prometheus").trim().toLowerCase(), requirement: defaultRequirement });
    setAlertRuleState({ loading: false, result: null, error: "" });
    setAlertOnboardingState({ loading: false, result: null, error: "" });
    setTimeout(() => {
      docPromptRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
    }, 50);
  }

  function closeDocumentPrompt() {
    setDocPromptAlert(null);
    setDocPromptExistingDoc(null);
    setDocPromptDocsByKind({});
    setDocPromptKind("runbook");
    setDocPromptMode("create");
    setAlertRuleState({ loading: false, result: null, error: "" });
  }


  async function refreshAll() {
    if (!Boolean(String(adminSession.accessToken || "").trim())) {
      return;
    }
    // Stage loading so login does not blast all heavy endpoints concurrently.
    await Promise.allSettled([
      checkHealth(),
      loadRecentAlerts(),
      loadFlows(),
    ]);
    window.setTimeout(() => {
      Promise.allSettled([
        loadMonitorApplications(),
        loadAlertSeverityOverrides(),
        loadModelProviderStatus(),
        loadLandingPadRecent(),
        loadRagDocs(),
      ]).catch(() => {});
    }, 250);

    window.setTimeout(() => {
      Promise.allSettled([
        loadGatewaySummary(),
        loadGatewayRecent(),
        loadIncidentMetadata(),
      ]).catch(() => {});
    }, 1500);
  }

  async function refreshViewsAfterSubmit() {
    await Promise.allSettled([
      refreshAll(),
      loadOnboardingAdminData(),
      loadMonitoringApplications(),
    ]);
    if (selectedMonitoringAppId) {
      await loadMonitoringApplicationDetails(selectedMonitoringAppId);
    }
  }

  useEffect(() => {
    if (typeof window === "undefined") {
      return;
    }
    try {
      const raw = window.localStorage.getItem(PREFERENCE_STORAGE_KEY);
      if (!raw) {
        return;
      }
      const prefs = JSON.parse(raw);
      if (prefs && typeof prefs === "object") {
        if (typeof prefs.applicationToMonitor === "string" && prefs.applicationToMonitor.trim()) {
          setApplicationToMonitor(prefs.applicationToMonitor);
        }
        if (prefs.uiDensity === "comfortable" || prefs.uiDensity === "compact") {
          setUiDensity(prefs.uiDensity);
        }
        if (typeof prefs.uiTheme === "string" && UI_THEME_VALUES.has(prefs.uiTheme)) {
          setUiTheme(prefs.uiTheme);
        }
        if (typeof prefs.selectedFlow === "string" && prefs.selectedFlow.trim()) {
          setSelectedFlow(prefs.selectedFlow);
        }
        if (typeof prefs.activeTab === "string" && VALID_TABS.has(prefs.activeTab)) {
          setActiveTab(prefs.activeTab);
        }
        if (prefs.metadataFilters && typeof prefs.metadataFilters === "object") {
          setMetadataFilters((current) => ({ ...current, ...prefs.metadataFilters }));
        }
        if (prefs.closedFilters && typeof prefs.closedFilters === "object") {
          setClosedFilters((current) => ({ ...current, ...prefs.closedFilters }));
        }
      }
    } catch (_error) {
      // Ignore malformed preference payloads and continue with defaults.
    }
  }, []);

  useEffect(() => {
    if (typeof window === "undefined") {
      return;
    }
    const root = window.document?.documentElement;
    if (!root) {
      return;
    }
    root.classList.remove("dm-theme-light", "dm-theme-dark");
    if (uiTheme === "light") {
      root.classList.add("dm-theme-light");
    } else if (uiTheme === "dark") {
      root.classList.add("dm-theme-dark");
    }
    root.setAttribute("data-ui-theme", uiTheme);
  }, [uiTheme]);

  useEffect(() => {
    if (typeof window === "undefined") {
      return;
    }
    const payload = {
      applicationToMonitor,
      uiDensity,
      uiTheme,
      selectedFlow,
      activeTab,
      metadataFilters,
      closedFilters,
    };
    window.localStorage.setItem(PREFERENCE_STORAGE_KEY, JSON.stringify(payload));
  }, [applicationToMonitor, uiDensity, uiTheme, selectedFlow, activeTab, metadataFilters, closedFilters]);

  useEffect(() => {
    const onKeyDown = (event) => {
      const authenticated = Boolean(String(adminSession.accessToken || "").trim());
      if (!authenticated) {
        return;
      }
      const roleName = normalizeRoleName(adminSession?.user?.role_name);
      const roleTabs = ROLE_ALLOWED_TABS[roleName] || ["home"];
      if (!event.altKey) {
        return;
      }
      const target = event.target;
      const tagName = String(target?.tagName || "").toLowerCase();
      if (tagName === "input" || tagName === "textarea" || tagName === "select" || target?.isContentEditable) {
        return;
      }
      const tabId = TAB_SHORTCUT_MAP[event.code];
      if (!tabId) {
        return;
      }
      if (!roleTabs.includes(tabId)) {
        return;
      }
      event.preventDefault();
      setActiveTab(tabId);
    };

    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [adminSession.accessToken, adminSession?.user?.role_name]);

  useEffect(() => {
    if (!Boolean(String(adminSession.accessToken || "").trim())) {
      return;
    }
    refreshAll();
  }, [adminSession.accessToken]);

  useEffect(() => {
    if (!Boolean(String(adminSession.accessToken || "").trim())) {
      return;
    }
    if (alertsLimit === 50) {
      return;
    }
    loadRecentAlerts();
  }, [adminSession.accessToken, alertsLimit]);

  useEffect(() => {
    if (!Boolean(String(adminSession.accessToken || "").trim())) {
      return;
    }
    if (activeTab !== "home") {
      return undefined;
    }
    const refreshAlertStream = async () => {
      if (typeof document !== "undefined" && document.visibilityState === "hidden") {
        return;
      }
      if (alertStreamRefreshInFlight.current) {
        return;
      }
      alertStreamRefreshInFlight.current = true;
      try {
        const tasks = [loadRecentAlerts({ background: true })];
        await Promise.allSettled(tasks);
      } finally {
        alertStreamRefreshInFlight.current = false;
      }
    };
    const timer = window.setInterval(refreshAlertStream, 30000);
    return () => window.clearInterval(timer);
  }, [adminSession.accessToken, activeTab, alertsLimit, applicationToMonitor]);

  useEffect(() => {
    if (activeTab !== "home") {
      return;
    }
    const onVisibilityChange = () => {
      if (document.visibilityState === "visible") {
        loadRecentAlerts({ background: true });
      }
    };
    document.addEventListener("visibilitychange", onVisibilityChange);
    return () => document.removeEventListener("visibilitychange", onVisibilityChange);
  }, [activeTab]);

  useEffect(() => {
    if (activeTab !== "home") {
      return;
    }
    const timer = window.setInterval(() => {
      const requestState = recentAlertsRequestRef.current;
      const ageMs = Date.now() - Number(requestState.startedAt || 0);
      if (!requestState.inFlight || ageMs <= 16000) {
        return;
      }
      recentAlertsRequestRef.current = { inFlight: false, requestId: "", startedAt: 0 };
      setAlerts((prev) => ({
        ...prev,
        loading: false,
        error: prev.error || "Alert stream refresh timed out. Retrying in background.",
      }));
    }, 4000);
    return () => window.clearInterval(timer);
  }, [activeTab]);

  useEffect(() => {
    if (!Boolean(String(adminSession.accessToken || "").trim())) {
      return;
    }
    if (activeTab !== "summary") {
      return;
    }
    loadIncidentMetadata();
  }, [
    activeTab,
    metadataFilters.risk_tier,
    metadataFilters.execution_mode,
    metadataFilters.transport_provider,
    metadataFilters.status,
    metadataFilters.service,
    adminSession.accessToken,
  ]);

  useEffect(() => {
    if (!Boolean(String(adminSession.accessToken || "").trim())) {
      return;
    }
    if (activeTab !== "admin") {
      return;
    }
    loadOnboardingAdminData();
  }, [adminSession.accessToken, activeTab]);

  useEffect(() => {
    if (!Boolean(String(adminSession.accessToken || "").trim())) {
      return;
    }
    if (activeTab !== "admin" || adminWorkspace !== "project") {
      return;
    }
    loadOnboardingRuleCapabilities();
  }, [adminSession.accessToken, activeTab, adminWorkspace]);

  useEffect(() => {
    if (monitorApplications.includes(applicationToMonitor)) {
      return;
    }
    setApplicationToMonitor(monitorApplications[0] || REAL_USE_CASE_SCOPE);
  }, [alerts.rows, monitorApplications, applicationToMonitor]);

  useEffect(() => {
    if (!adminSession.accessToken || activeTab !== "admin") {
      return;
    }
    loadAdminUsersAndRoles();
  }, [adminSession.accessToken, activeTab]);

  useEffect(() => {
    if (!Boolean(String(adminSession.accessToken || "").trim())) {
      return;
    }
    loadMonitorApplications();
  }, [adminSession.accessToken]);

  useEffect(() => {
    if (
      activeTab !== "stream"
      || !Boolean(String(adminSession.accessToken || "").trim())
    ) {
      return undefined;
    }
    loadLandingPadRecent();
    const timer = window.setInterval(() => {
      loadLandingPadRecent();
    }, 10_000);
    return () => window.clearInterval(timer);
  }, [activeTab, adminSession.accessToken]);

  const latestWorkflow = useMemo(() => {
    return workflowState?.result?.data || {};
  }, [workflowState]);

  const latestIncidentId = useMemo(() => {
    return String(latestWorkflow?.incident?.id || latestWorkflow?.incident_id || "").trim();
  }, [latestWorkflow]);

  const latestRecommendationId = useMemo(() => {
    return String(latestWorkflow?.recommendation?.id || latestWorkflow?.recommendation_id || "").trim();
  }, [latestWorkflow]);

  const monitorScopedAlerts = useMemo(() => {
    return filterAlertsForMonitor(alerts.rows, applicationToMonitor);
  }, [alerts.rows, applicationToMonitor]);

  const monitorScopedRecentClosedAlerts = useMemo(() => {
    return filterRowsForMonitor(closedIncidents.rows, applicationToMonitor);
  }, [closedIncidents.rows, applicationToMonitor]);

  const visibleAlerts = useMemo(() => {
    return mergeAlertStreamRows(monitorScopedAlerts, monitorScopedRecentClosedAlerts);
  }, [monitorScopedAlerts, monitorScopedRecentClosedAlerts]);

  const dashboardAlertSummary = useMemo(() => {
    const summary = { total: visibleAlerts.length, ops: 0, test: 0, critical: 0, high: 0, awaiting: 0, active: 0, closed: 0 };
    visibleAlerts.forEach((row) => {
      const severity = String(row?.severity || "").toLowerCase();
      const status = String(row?.status || row?.state || "open").toLowerCase();
      if (isGeneratedOrTestAlert(row)) {
        summary.test += 1;
      } else {
        summary.ops += 1;
      }
      if (severity === "critical") {
        summary.critical += 1;
      }
      if (severity === "high") {
        summary.high += 1;
      }
      if (status === "awaiting_approval") {
        summary.awaiting += 1;
      }
      if (status === "open" || status === "pending" || status === "investigating") {
        summary.active += 1;
      }
      if (isApprovalResolvedStatus(status) || row?._closed_incident) {
        summary.closed += 1;
      }
    });
    return summary;
  }, [visibleAlerts]);

  const dashboardVisibleAlerts = useMemo(() => {
    const query = String(dashboardAlertQuery || "").trim().toLowerCase();
    return visibleAlerts.filter((row) => {
      const severity = String(row?.severity || "").toLowerCase();
      const status = String(row?.status || row?.state || "open").toLowerCase();
      const generatedOrTest = isGeneratedOrTestAlert(row);
      if (dashboardAlertFocus === "ops" && generatedOrTest) {
        return false;
      }
      if (dashboardAlertFocus === "test" && !generatedOrTest) {
        return false;
      }
      if (dashboardAlertFocus === "critical" && severity !== "critical") {
        return false;
      }
      if (dashboardAlertFocus === "high" && severity !== "high") {
        return false;
      }
      if (dashboardAlertFocus === "awaiting" && status !== "awaiting_approval") {
        return false;
      }
      if (dashboardAlertFocus === "active" && !["open", "pending", "investigating"].includes(status)) {
        return false;
      }
      if (dashboardAlertFocus === "closed" && !(isApprovalResolvedStatus(status) || row?._closed_incident)) {
        return false;
      }
      if (!query) {
        return true;
      }
      const haystack = [
        row?.alert_id,
        row?.id,
        row?.incident_id,
        row?.name,
        row?.alert_name,
        row?.service,
        row?.application,
        row?.project_name,
        row?.project,
      ]
        .map((value) => String(value || "").toLowerCase())
        .join(" ");
      return haystack.includes(query);
    });
  }, [visibleAlerts, dashboardAlertFocus, dashboardAlertQuery]);

  const monitorScopedIncidentMetadata = useMemo(() => {
    return filterRowsForMonitor(incidentMetadata.rows, applicationToMonitor);
  }, [incidentMetadata.rows, applicationToMonitor]);

  const selectedMonitorScopeLabel = useMemo(
    () => monitorScopeLabel(applicationToMonitor),
    [applicationToMonitor],
  );

  const visibleAlertSourceSummary = useMemo(() => {
    return summarizeAlertSources(visibleAlerts);
  }, [visibleAlerts]);

  const allApplicationAlertSourceSummary = useMemo(
    () => summarizeAlertSources(mergeAlertStreamRows(alerts.rows, closedIncidents.rows)),
    [alerts.rows, closedIncidents.rows],
  );

  const selectedAlertRow = useMemo(() => {
    return visibleAlerts.find((row) => String(row?.alert_id || row?.id || row?.incident_id || "") === selectedAlertId) || null;
  }, [visibleAlerts, selectedAlertId]);

  const selectedAlertPayload = useMemo(() => {
    return selectedAlertData?.payload?.data || selectedAlertData?.payload || {};
  }, [selectedAlertData]);

  const selectedAlertWorkflow = useMemo(() => {
    return selectedAlertPayload?.workflow || selectedAlertPayload || {};
  }, [selectedAlertPayload]);

  const selectedAlertEvents = useMemo(() => {
    const events =
      selectedAlertWorkflow?.events
      || selectedAlertWorkflow?.workflow_events
      || selectedAlertWorkflow?.agent_events
      || [];
    return Array.isArray(events) ? events : [];
  }, [selectedAlertWorkflow]);

  const selectedAlertEventTrace = useMemo(() => {
    const rows =
      selectedAlertWorkflow?.event_trace
      || selectedAlertWorkflow?.trace_events
      || selectedAlertWorkflow?.trace?.events
      || [];
    if (!Array.isArray(rows)) {
      return [];
    }
    return rows
      .filter((row) => row && typeof row === "object")
      .sort((a, b) => {
        const aTime = parseUtcTimestamp(a.timestamp)?.getTime() || 0;
        const bTime = parseUtcTimestamp(b.timestamp)?.getTime() || 0;
        return aTime - bTime;
      })
      .slice(-300);
  }, [selectedAlertWorkflow]);

  const selectedAlertEventsDisplay = useMemo(() => {
    const buildBackgroundDetailText = (event) => {
      const items = [
        ["event_type", event?.event_type],
        ["event_stage", event?.event_stage],
        ["status", event?.status],
        ["source_channel", event?.source_channel],
        ["transport_channel", event?.transport_channel],
        ["transport_provider", event?.transport_provider],
        ["risk_tier", event?.risk_tier],
        ["execution_mode", event?.execution_mode],
        ["policy_reason", event?.policy_reason],
        ["trace_id", event?.trace_id],
      ]
        .map(([key, value]) => [key, String(value || "").trim()])
        .filter(([, value]) => value && value !== "-")
        .map(([key, value]) => `${key}: ${value}`);
      return items.join("\n");
    };

    const mappedEvents = selectedAlertEvents.map((event, index) => {
      const decision = event?.decision;
      const inputValue = extractEventInput(event);
      const outputValue = extractEventOutput(event);
      const input = typeof inputValue === "object" && inputValue ? inputValue : {};
      return {
        sequence: event?.sequence || index + 1,
        agent: displayAgentName(event?.agent || normalizeTraceServiceName(event) || "-"),
        action: event?.action || event?.event_type || event?.status || "-",
        eventType: event?.event_type || "",
        timestamp: event?.timestamp || "",
        decision: decision && typeof decision === "object" ? JSON.stringify(decision) : String(decision || "-"),
        output: stringifyTimelineValue(outputValue) || String(event?.event_type || "-"),
        communicates_to: event?.communicates_to || event?.transport_channel || input?.transport_channel || "-",
        inputValueText: stringifyTimelineValue(inputValue),
        outputValueText: stringifyTimelineValue(outputValue),
        errorValueText: extractEventError(event),
        backgroundDetailText: buildBackgroundDetailText(event),
      };
    });

    const traceRows = selectedAlertEventTrace.map((row, index) => {
      const inputValue = extractEventInput(row);
      const outputValue = extractEventOutput(row);
      return {
        sequence: index + 1,
        agent: displayAgentName(normalizeTraceServiceName(row)),
        action: summarizeEventType(row?.event_type),
        eventType: row?.event_type || "",
        timestamp: row?.timestamp || "",
        decision: row?.policy_reason || row?.status || row?.event_stage || "-",
        output: stringifyTimelineValue(outputValue) || row?.event_type || "-",
        communicates_to: row?.transport_channel || "-",
        inputValueText: stringifyTimelineValue(inputValue),
        outputValueText: stringifyTimelineValue(outputValue),
        errorValueText: extractEventError(row),
        backgroundDetailText: buildBackgroundDetailText(row),
      };
    });

    if (!traceRows.length) {
      return mappedEvents.map((row, index) => ({
        ...row,
        sequence: index + 1,
      }));
    }

    const mergedRows = [...mappedEvents];
    const seen = new Set(
      mappedEvents.map((row) => `${String(row.agent || "").toLowerCase()}|${String(row.action || "").toLowerCase()}|${String(row.decision || "").toLowerCase()}`)
    );

    traceRows.forEach((row) => {
      const key = `${String(row.agent || "").toLowerCase()}|${String(row.action || "").toLowerCase()}|${String(row.decision || "").toLowerCase()}`;
      if (!seen.has(key)) {
        seen.add(key);
        mergedRows.push(row);
      }
    });

    return mergedRows
      .map((row, index) => ({ ...row, sequence: index + 1 }))
      .slice(0, 300);
  }, [selectedAlertEvents, selectedAlertEventTrace]);

  const selectedAlertRagDocuments = useMemo(
    () => {
      if (Array.isArray(selectedAlertDocumentLinks.rows) && selectedAlertDocumentLinks.rows.length) {
        return selectedAlertDocumentLinks.rows;
      }
      return findAlertRagDocuments(selectedAlertRow);
    },
    [selectedAlertDocumentLinks.rows, selectedAlertRow, ragDocs.rows],
  );

  const selectedAlertKnowledgeDocument = useMemo(() => {
    const seen = new Set();
    const docs = selectedAlertRagDocuments.filter((doc) => {
      const key = String(doc?.path || doc?.title || doc?.document_id || "").trim().toLowerCase();
      if (!key) {
        return true;
      }
      if (seen.has(key)) {
        return false;
      }
      seen.add(key);
      return true;
    });
    if (!docs.length) {
      return null;
    }
    const first = docs[0] || {};
    const service = Array.isArray(first.services) ? first.services.join(", ") : String(first.services || selectedAlertRow?.service || "-");
    const severity = String(first.severity || selectedAlertRow?.severity || "-").toLowerCase();
    const kinds = Array.from(new Set(docs.map((doc) => String(doc?.kind || doc?.document_kind || "document").trim()).filter(Boolean)));
    const reasons = Array.from(new Set(docs.map((doc) => String(doc?.match_reason || "").trim()).filter(Boolean)));
    const confidence = docs
      .map((doc) => Number(doc?.match_confidence || 0))
      .filter((value) => Number.isFinite(value) && value > 0)
      .sort((a, b) => b - a)[0];
    return {
      title: docs.length === 1
        ? String(first.title || first.path || "Alert Knowledge Document").trim()
        : `${selectedAlertRow?.service || service || "Alert"} Knowledge Document`,
      summary: docs.length === 1
        ? String(first.summary || first.recommended_action || "Backend-linked document is available for download.").trim()
        : `Single dashboard document composed from ${docs.length} backend-linked knowledge source(s).`,
      service,
      severity,
      kinds,
      reasons,
      confidence,
      docs,
    };
  }, [selectedAlertRagDocuments, selectedAlertRow]);

  const selectedAlertDocumentContract = selectedAlertDocumentLinks.contract;

  const selectedAlertDetailsSource = useMemo(() => {
    if (selectedAlertData.loading) {
      if (selectedAlertData.payload) {
        return "Refreshing processed workflow result from monitoring-adapter.";
      }
      return "Loading processed result from monitoring adapter.";
    }
    if (selectedAlertData.payload) {
      return "Canonical processed workflow result; Discovery and Resolution LLM outputs are shown when available.";
    }
    if (selectedAlertData.error) {
      return "Processed workflow result unavailable; showing alert-stream fallback fields only.";
    }
    return "Alert-stream row selected; processed workflow result has not loaded yet.";
  }, [selectedAlertData.loading, selectedAlertData.payload, selectedAlertData.error]);

  const selectedAlertUsage = useMemo(() => {
    const rows = [];
    const appendUsage = (candidate) => {
      if (!Array.isArray(candidate)) {
        return;
      }
      candidate.forEach((item) => rows.push(normalizeUsageRow(item)));
    };

    const appendErrorUsage = (candidate) => {
      if (!Array.isArray(candidate)) {
        return;
      }
      candidate
        .filter((item) => item && typeof item === "object")
        .forEach((item) => {
          rows.push(normalizeUsageRow({
            task: item.task || item.agent || "llm-error",
            provider: item.provider || item.model_provider || "router",
            model: item.model || item.model_name || "-",
            note: item.error || item.message || item.reason || JSON.stringify(item),
            estimated: true,
          }));
        });
    };

    appendUsage(selectedAlertWorkflow?.recommendation?.metadata?.model_usage);
    appendUsage(selectedAlertWorkflow?.finops?.calls);
    appendUsage(selectedAlertWorkflow?.recommendation?.metadata?.llm_calls);
    appendErrorUsage(selectedAlertWorkflow?.finops?.errors);

    selectedAlertEventTrace.forEach((event) => {
      const payload = event?.payload && typeof event.payload === "object" ? event.payload : {};
      appendUsage(payload?.model_usage);
      appendUsage(payload?.llm_calls);
      appendUsage(payload?.finops?.calls);
      appendErrorUsage(payload?.finops?.errors);
    });

    return dedupeUsageRows(rows.filter((row) => isMeaningfulUsageRow(row)));
  }, [selectedAlertWorkflow, selectedAlertEventTrace]);

  const selectedFinopsDiagnostics = useMemo(() => {
    const workflowCalls = Array.isArray(selectedAlertWorkflow?.finops?.calls)
      ? selectedAlertWorkflow.finops.calls.length
      : 0;
    const workflowErrors = Array.isArray(selectedAlertWorkflow?.finops?.errors)
      ? selectedAlertWorkflow.finops.errors.length
      : 0;
    const recommendationUsage = Array.isArray(selectedAlertWorkflow?.recommendation?.metadata?.model_usage)
      ? selectedAlertWorkflow.recommendation.metadata.model_usage.length
      : 0;

    let traceCalls = 0;
    let traceErrors = 0;
    selectedAlertEventTrace.forEach((row) => {
      const payload = row?.payload && typeof row.payload === "object" ? row.payload : {};
      traceCalls += Array.isArray(payload?.finops?.calls) ? payload.finops.calls.length : 0;
      traceErrors += Array.isArray(payload?.finops?.errors) ? payload.finops.errors.length : 0;
    });

    return {
      usageRows: selectedAlertUsage.length,
      fallbackRows: selectedAlertUsage.filter((row) => row.fallback).length,
      workflowCalls,
      workflowErrors,
      recommendationUsage,
      traceCalls,
      traceErrors,
    };
  }, [selectedAlertWorkflow, selectedAlertEventTrace, selectedAlertUsage]);

  const selectedModelProviderRows = useMemo(() => {
    const providers = modelProviderStatus?.data?.providers && typeof modelProviderStatus.data.providers === "object"
      ? modelProviderStatus.data.providers
      : {};
    return Object.entries(providers).map(([name, value]) => ({
      name,
      configured: Boolean(value?.configured),
      healthy: Boolean(value?.healthy),
      model: String(value?.model || name),
      circuitOpen: Boolean(value?.circuit_open),
      failures: Number(value?.failure_count || 0),
      reason: String(value?.reason || ""),
    }));
  }, [modelProviderStatus]);

  const selectedAlertRouting = useMemo(() => extractObservedRoutingMetrics(selectedAlertWorkflow), [selectedAlertWorkflow]);

  const selectedAlertEvaluation = useMemo(() => {
    const recommendation = selectedAlertWorkflow?.recommendation && typeof selectedAlertWorkflow.recommendation === "object"
      ? selectedAlertWorkflow.recommendation
      : {};
    const metadata = recommendation?.metadata && typeof recommendation.metadata === "object" ? recommendation.metadata : {};
    const evaluation = metadata?.evaluation && typeof metadata.evaluation === "object" ? metadata.evaluation : {};
    const ragMatches = Array.isArray(metadata.rag_matches) ? metadata.rag_matches : [];
    const bestRagMatch = ragMatches.reduce((best, row) => {
      const value = Number(row?.match_confidence ?? row?._similarity ?? row?.similarity ?? row?.score ?? 0);
      return Number.isFinite(value) ? Math.max(best, value) : best;
    }, Number(metadata.rag_top_similarity || 0) || 0);
    const citations = Array.isArray(metadata.citations) ? metadata.citations : [];
    return normalizeEvaluationEnvelope(evaluation, {
      confidence: recommendation?.confidence,
      ragMatchScore: bestRagMatch,
      citationCoverage: Math.min(citations.length / 3, 1),
      evidenceCoverage: Math.min(
        (metadata.runbook_found ? 0.35 : 0)
        + (ragMatches.length ? 0.4 : 0)
        + (selectedAlertRagDocuments.length ? 0.25 : 0),
        1,
      ),
    });
  }, [selectedAlertWorkflow, selectedAlertRagDocuments.length]);

  const selectedIncidentId = useMemo(() => {
    return String(selectedAlertWorkflow?.incident?.id || selectedAlertWorkflow?.incident_id || "").trim();
  }, [selectedAlertWorkflow]);

  const selectedIncidentMetadataRow = useMemo(() => {
    if (!selectedIncidentId) {
      return null;
    }
    const scoped = monitorScopedIncidentMetadata.find(
      (row) => String(row?.incident_id || "").trim() === selectedIncidentId
    );
    if (scoped) {
      return scoped;
    }
    return incidentMetadata.rows.find((row) => String(row?.incident_id || "").trim() === selectedIncidentId) || null;
  }, [selectedIncidentId, monitorScopedIncidentMetadata, incidentMetadata.rows]);

  const selectedCanonicalIncidentStatus = useMemo(
    () => canonicalIncidentStatus(
      selectedStageCompleteness.data?.status,
      selectedIncidentMetadataRow?.status,
      selectedAlertWorkflow?.incident?.status,
      selectedAlertRow?.status,
      selectedAlertRow?.state,
    ),
    [
      selectedStageCompleteness.data?.status,
      selectedIncidentMetadataRow?.status,
      selectedAlertWorkflow?.incident?.status,
      selectedAlertRow?.status,
      selectedAlertRow?.state,
    ],
  );

  const selectedAlertRecommendationId = useMemo(() => {
    if (!selectedIncidentId) {
      return "";
    }
    return (
      approvalRecommendationId(selectedIncidentMetadataRow)
      || approvalRecommendationFromPayload(selectedAlertWorkflow)
      || approvalRecommendationFromPayload(selectedAlertData?.payload)
      || ""
    );
  }, [selectedIncidentId, selectedIncidentMetadataRow, selectedAlertWorkflow, selectedAlertData?.payload]);

  const selectedExecutionPlan = useMemo(() => {
    const projectionPayload =
      selectedIncidentMetadataRow?.projection_payload && typeof selectedIncidentMetadataRow.projection_payload === "object"
        ? selectedIncidentMetadataRow.projection_payload
        : {};
    const recommendation =
      typeof selectedAlertWorkflow?.recommendation === "object" && selectedAlertWorkflow.recommendation
        ? selectedAlertWorkflow.recommendation
        : {};
    const recommendationMetadata =
      typeof recommendation?.metadata === "object" && recommendation.metadata
        ? recommendation.metadata
        : {};
    const decision =
      (typeof selectedAlertWorkflow?.decision === "object" && selectedAlertWorkflow.decision)
      || (typeof selectedAlertWorkflow?.orchestration_decision === "object" && selectedAlertWorkflow.orchestration_decision)
      || (typeof recommendationMetadata?.orchestration_decision === "object" && recommendationMetadata.orchestration_decision)
      || {};
    const remediationAction =
      typeof selectedAlertWorkflow?.remediation_action === "object" && selectedAlertWorkflow.remediation_action
        ? selectedAlertWorkflow.remediation_action
        : typeof projectionPayload?.remediation_action === "object" && projectionPayload.remediation_action
          ? projectionPayload.remediation_action
          : {};
    const approval =
      typeof selectedAlertWorkflow?.approval === "object" && selectedAlertWorkflow.approval
        ? selectedAlertWorkflow.approval
        : typeof projectionPayload?.approval === "object" && projectionPayload.approval
          ? projectionPayload.approval
        : {};
    const workflowForExecution = {
      ...(projectionPayload && typeof projectionPayload === "object" ? projectionPayload : {}),
      ...(selectedAlertWorkflow && typeof selectedAlertWorkflow === "object" ? selectedAlertWorkflow : {}),
      remediation_action: remediationAction,
      approval,
    };
    const commands = deriveExecutionCommands(workflowForExecution, selectedAlertEventTrace);

    return {
      action:
        recommendation?.recommended_action
        || remediationAction?.action
        || selectedAlertRouting?.next_action
        || selectedAlertWorkflow?.next_step
        || "-",
      rationale:
        recommendation?.rationale
        || remediationAction?.reason
        || selectedAlertRouting?.policy_reason
        || recommendation?.policy_reason
        || "-",
      requiresApproval:
        selectedAlertRouting?.requires_approval
        ?? decision?.requires_approval
        ?? selectedAlertWorkflow?.approval?.required
        ?? "-",
      workflow: selectedAlertRouting?.workflow || decision?.workflow || selectedAlertWorkflow?.scenario?.id || "-",
      executionMode: selectedAlertRouting?.execution_mode || decision?.execution_mode || "-",
      riskTier: selectedAlertRouting?.risk_tier || decision?.risk_tier || "-",
      provider: selectedAlertRouting?.message_bus_provider || decision?.message_bus_provider || "-",
      incidentStatus: selectedCanonicalIncidentStatus,
      approvalStatus: approval?.status || projectionPayload?.approval_status || "pending",
      commands,
      remediationAction,
    };
  }, [selectedAlertWorkflow, selectedAlertRouting, selectedAlertEventTrace, selectedIncidentMetadataRow, selectedCanonicalIncidentStatus]);
  const selectedExecutionBreakdown = useMemo(() => {
    const grouped = { commands: [], scripts: [], queries: [] };
    (Array.isArray(selectedExecutionPlan.commands) ? selectedExecutionPlan.commands : []).forEach((item) => {
      const line = String(item || "").trim();
      if (!line) {
        return;
      }
      const normalized = line
        .replace(/^\s*(cmd|command)\s*:/i, "")
        .replace(/^\s*script\s*:/i, "script: ")
        .replace(/^\s*query\s*:/i, "query: ")
        .trim();
      if (!normalized || /^#/.test(normalized) || /^preview only/i.test(normalized) || /^recommended_action/i.test(normalized)) {
        return;
      }
      if (/^script\s*:/i.test(normalized)) {
        grouped.scripts.push(normalized.replace(/^script\s*:/i, "").trim());
        return;
      }
      if (/^query\s*:/i.test(normalized)) {
        grouped.queries.push(normalized.replace(/^query\s*:/i, "").trim());
        return;
      }
      grouped.commands.push(normalized);
    });
    const hasPlan = grouped.commands.length > 0 || grouped.scripts.length > 0 || grouped.queries.length > 0;
    return {
      ...grouped,
      hasPlan,
      incidentStatus: String(selectedExecutionPlan.incidentStatus || "-").trim().toLowerCase(),
      approvalStatus: normalizeApprovalStatus(selectedExecutionPlan.approvalStatus || "pending"),
    };
  }, [selectedExecutionPlan]);
  const selectedRemediationOutcome = useMemo(() => {
    const latestResponse = unwrap(remediationExecutionState.result);
    const responseOutcome = remediationOutcomeFromAction(latestResponse);
    if (responseOutcome) {
      return responseOutcome;
    }
    return remediationOutcomeFromAction(selectedExecutionPlan.remediationAction);
  }, [remediationExecutionState.result, selectedExecutionPlan.remediationAction]);

  const selectedApplicationConnection = useMemo(() => {
    const workflowContext = typeof selectedAlertWorkflow?.context === "object" && selectedAlertWorkflow.context
      ? selectedAlertWorkflow.context
      : {};
    const incident = typeof selectedAlertWorkflow?.incident === "object" && selectedAlertWorkflow.incident
      ? selectedAlertWorkflow.incident
      : {};
    const recommendation = typeof selectedAlertWorkflow?.recommendation === "object" && selectedAlertWorkflow.recommendation
      ? selectedAlertWorkflow.recommendation
      : {};
    const metadata = typeof recommendation?.metadata === "object" && recommendation.metadata ? recommendation.metadata : {};
    const service = String(
      selectedAlertRow?.service
      || incident?.service
      || selectedIncidentMetadataRow?.service
      || metadata?.service
      || workflowContext?.service
      || ""
    ).trim();
    const application = String(
      selectedAlertRow?.application
      || selectedAlertRow?.project_name
      || selectedAlertRow?.project
      || selectedIncidentMetadataRow?.application
      || applicationToMonitor
      || ""
    ).trim();
    const appRow = monitoringApps.rows.find((row) => {
      const rowName = String(row?.name || "").trim().toLowerCase();
      const rowService = String(row?.service || row?.labels?.service || "").trim().toLowerCase();
      return (application && rowName === application.toLowerCase()) || (service && rowService === service.toLowerCase());
    }) || {};
    const endpoint = String(
      metadata?.connection_url
      || metadata?.endpoint_url
      || workflowContext?.deployment
      || workflowContext?.observability?.metrics_endpoint
      || appRow?.metrics_endpoint
      || onboardingForm.monitoring_url
      || onboardingForm.prometheus_url
      || ""
    ).trim();
    const environment = String(
      selectedAlertRow?.environment
      || incident?.environment
      || selectedIncidentMetadataRow?.environment
      || metadata?.environment
      || appRow?.environment
      || "prod"
    ).trim();
    const namespace = String(metadata?.namespace || appRow?.namespace || environment || "prod").trim();
    return {
      application: application || "-",
      service: service || "-",
      environment: environment || "prod",
      namespace,
      endpoint: endpoint || "Not configured",
      connection_type: endpoint ? "metrics/application endpoint" : "missing connection details",
      source: endpoint ? "onboarding/application metadata" : "missing",
    };
  }, [
    selectedAlertWorkflow,
    selectedAlertRow,
    selectedIncidentMetadataRow,
    monitoringApps.rows,
    onboardingForm.monitoring_url,
    onboardingForm.prometheus_url,
    applicationToMonitor,
  ]);

  useEffect(() => {
    const suggestedScript = selectedExecutionBreakdown.scripts.length
      ? selectedExecutionBreakdown.scripts.join("\n")
      : selectedExecutionBreakdown.hasPlan
        ? buildKaiOpsRemediationScript({
            service: selectedApplicationConnection.service !== "-" ? selectedApplicationConnection.service : selectedApplicationConnection.application,
            environment: selectedApplicationConnection.environment,
            apiGatewayUrl: "http://api-gateway:8000",
            prometheusUrl: selectedApplicationConnection.endpoint !== "Not configured"
              ? selectedApplicationConnection.endpoint
              : onboardingForm.prometheus_url || onboardingForm.monitoring_url || "http://prometheus:9090",
            mysqlHost: "mysql",
            mysqlDatabase: "kaiops",
            mysqlUser: "kaiops",
          })
        : "";
    setRemediationPlanEditor({
      commands: suggestedScript ? "" : selectedExecutionBreakdown.commands.join("\n"),
      scripts: suggestedScript,
      queries: suggestedScript ? "" : selectedExecutionBreakdown.queries.join("\n"),
      connection_url: selectedApplicationConnection.endpoint === "Not configured" ? "" : selectedApplicationConnection.endpoint,
      connection_type: selectedApplicationConnection.connection_type || "application",
      namespace: selectedApplicationConnection.namespace || "",
      notes: "",
    });
    setRemediationExecutionState({ loading: false, result: null, error: "" });
  }, [
    selectedAlertId,
    selectedExecutionBreakdown.commands,
    selectedExecutionBreakdown.scripts,
    selectedExecutionBreakdown.queries,
    selectedApplicationConnection.endpoint,
    selectedApplicationConnection.connection_type,
    selectedApplicationConnection.namespace,
    selectedApplicationConnection.service,
    selectedApplicationConnection.application,
    selectedApplicationConnection.environment,
    onboardingForm.prometheus_url,
    onboardingForm.monitoring_url,
  ]);

  const selectedAlertTimelineRows = useMemo(() => {
    const ingestAt =
      selectedAlertWorkflow?.alert?.created_at ||
      selectedAlertRow?.created_at ||
      selectedAlertRow?.starts_at ||
      "";
    const incidentCreatedAt = selectedAlertWorkflow?.incident?.created_at || selectedIncidentMetadataRow?.created_at || "";

    const workflowRows = selectedAlertEvents
      .filter((event) => event && typeof event === "object")
      .sort((a, b) => {
        const aSeq = Number(a.sequence || 0);
        const bSeq = Number(b.sequence || 0);
        if (aSeq && bSeq && aSeq !== bSeq) {
          return aSeq - bSeq;
        }
        const aTime = parseUtcTimestamp(a.timestamp)?.getTime() || 0;
        const bTime = parseUtcTimestamp(b.timestamp)?.getTime() || 0;
        return aTime - bTime;
      })
      .map((event, index) => {
        const route = routeForAgent(event.agent);
        const inputPayload = extractEventInput(event);
        const outputPayload = extractEventOutput(event);
        const inputObject = typeof inputPayload === "object" && inputPayload ? inputPayload : {};
        const outputObject = typeof outputPayload === "object" && outputPayload ? outputPayload : {};
        const tableHints = [
          ...(Array.isArray(outputObject.table_hints) ? outputObject.table_hints : []),
          ...(Array.isArray(event?.metrics?.table_hints) ? event.metrics.table_hints : []),
        ].filter(Boolean);
        const consumes =
          String(inputObject.source_channel || inputObject.topic || inputObject.from_topic || route?.consumes || "").trim() || "-";
        const publishes =
          String(
            event.communicates_to
            || inputObject.transport_channel
            || inputObject.to_topic
            || outputObject.transport_channel
            || route?.publishes
            || ""
          ).trim() || "-";
        const actionLabel = String(event.action || event.event_type || "").trim();
        const stageName = actionLabel ? summarizeEventType(actionLabel) : `Workflow Event ${index + 1}`;
        const detailParts = [
          compactText(event.status, 40),
          compactText(
            event.decision && typeof event.decision === "object"
              ? JSON.stringify(event.decision)
              : event.decision,
            120
          ),
        ].filter(Boolean);

        return {
          stage: stageName,
          sequence: event.sequence || index + 1,
          agent: displayAgentName(event.agent || "-"),
          service: route?.service || event.service || "-",
          consumes,
          publishes,
          timestamp: event.timestamp || "",
          elapsed: elapsedSeconds(ingestAt || incidentCreatedAt, event.timestamp || ""),
          detail: detailParts.join(" | ") || "Workflow event recorded.",
          tables: tableHints.length ? tableHints.join(", ") : "-",
          inputValueText: stringifyTimelineValue(inputPayload),
          outputValueText: stringifyTimelineValue(outputPayload),
          errorValueText: extractEventError(event),
          backendEvents: [String(event?.event_type || "").trim()].filter(Boolean),
        };
      });

    const traceRows = selectedAlertEventTrace.map((event, index) => {
      const stageName = summarizeEventType(event.event_type);
      const tableHints = Array.isArray(event.table_hints) ? event.table_hints.filter(Boolean) : [];
      const detailParts = [
        compactText(event.event_stage, 40),
        compactText(event.status, 40),
        compactText(event.policy_reason, 120),
      ].filter(Boolean);
      return {
        stage: `${stageName}${index + 1 <= 9 ? ` (${index + 1})` : ""}`,
        sequence: index + 1,
        agent: displayAgentName(normalizeTraceServiceName(event)),
        service: normalizeTraceServiceName(event),
        consumes: event.source_channel || "-",
        publishes: event.transport_channel || "-",
        timestamp: event.timestamp || "",
        elapsed: elapsedSeconds(ingestAt, event.timestamp || ""),
        detail: detailParts.join(" | ") || "Trace event recorded.",
        tables: tableHints.join(", ") || "-",
        inputValueText: stringifyTimelineValue(
          hasMeaningfulValue(event.input_value)
            ? event.input_value
            : {
                source_channel: event.source_channel,
                transport_provider: event.transport_provider,
                risk_tier: event.risk_tier,
                execution_mode: event.execution_mode,
                trace_id: event.trace_id,
              }
        ),
        outputValueText: stringifyTimelineValue(
          hasMeaningfulValue(event.output_value)
            ? { trace_id: event.trace_id, ...event.output_value }
            : {
                event_type: event.event_type,
                event_stage: event.event_stage,
                status: event.status,
                transport_channel: event.transport_channel,
                table_hints: event.table_hints,
                query_hint: event.query_hint,
                trace_id: event.trace_id,
              }
        ),
        errorValueText: stringifyTimelineValue(event.error) || extractEventError(event),
        backendEvents: [String(event?.event_type || "").trim()].filter(Boolean),
      };
    });

    const syntheticRows = buildSyntheticFlowRows({
      workflow: selectedAlertWorkflow,
      events: selectedAlertEvents,
      traceRows: selectedAlertEventTrace,
      ingestAt,
      incidentCreatedAt,
    });
    const discoveryEvidence =
      selectedAlertWorkflow?.context?.metadata?.discovery_evidence
      || selectedAlertWorkflow?.recommendation?.metadata?.discovery_evidence
      || null;
    const discoveryMcp =
      selectedAlertWorkflow?.context?.metadata?.discovery_report
      || selectedAlertWorkflow?.recommendation?.metadata?.discovery_report
      || null;
    const contextMetadata =
      selectedAlertWorkflow?.context?.metadata
      || selectedAlertWorkflow?.recommendation?.metadata
      || {};
    const contextRagMatches =
      (Array.isArray(contextMetadata?.rag_matches) && contextMetadata.rag_matches)
      || [];
    if (discoveryMcp && typeof discoveryMcp === "object") {
      const stages = Array.isArray(discoveryMcp.retrieval_stages) ? discoveryMcp.retrieval_stages : [];
      stages.forEach((stage, index) => {
        syntheticRows.push({
          stage: `Discovery Agent · ${String(stage.stage || "stage").replaceAll("_", " ")}`,
          sequence: 80 + index,
          agent: "Discovery Agent",
          service: "context-agent",
          consumes: index === 0 ? "orchestration-events" : "discovery-mcp",
          publishes: stage.stage === "discovery_completed" ? "context-events" : "discovery-evidence",
          timestamp: selectedAlertWorkflow?.context?.created_at || incidentCreatedAt || ingestAt,
          elapsed: elapsedSeconds(ingestAt, selectedAlertWorkflow?.context?.created_at || incidentCreatedAt || ingestAt),
          detail: `${stage.status || "unknown"}${Number.isFinite(Number(stage.result_count)) ? ` · ${stage.result_count} result(s)` : ""}`,
          tables: "-",
          inputValueText: stringifyTimelineValue({ protocol: discoveryMcp.protocol, server: discoveryMcp.server }),
          outputValueText: stringifyTimelineValue(stage),
          errorValueText: stage.error || "",
          backendEvents: [`discovery.${stage.stage || "stage"}`],
        });
      });
    }
    if (discoveryEvidence && typeof discoveryEvidence === "object") {
      const codeCount = Array.isArray(discoveryEvidence.code_matches) ? discoveryEvidence.code_matches.length : 0;
      const logCount = Array.isArray(discoveryEvidence.log_matches) ? discoveryEvidence.log_matches.length : 0;
      syntheticRows.push({
        stage: "Discovery Agent Retrieved Code And Log Context",
        sequence: 85,
        agent: "Discovery Agent",
        service: "context-agent",
        consumes: "orchestration-events",
        publishes: "context-evidence",
        timestamp: selectedAlertWorkflow?.context?.created_at || incidentCreatedAt || ingestAt,
        elapsed: elapsedSeconds(ingestAt, selectedAlertWorkflow?.context?.created_at || incidentCreatedAt || ingestAt),
        detail: `${codeCount} code match${codeCount === 1 ? "" : "es"} and ${logCount} log match${logCount === 1 ? "" : "es"} retrieved.`,
        tables: "-",
        inputValueText: stringifyTimelineValue({
          query_terms: discoveryEvidence.query_terms || [],
          code_roots: discoveryEvidence.code_roots || [],
          log_roots: discoveryEvidence.log_roots || [],
        }),
        outputValueText: stringifyTimelineValue(discoveryEvidence),
        errorValueText: "",
        backendEvents: ["context.discovery.completed"],
      });
    }
    if (contextMetadata && typeof contextMetadata === "object") {
      const queryTerms = Array.isArray(discoveryEvidence?.query_terms) ? discoveryEvidence.query_terms : [];
      syntheticRows.push({
        stage: "Context Agent Merged Alert And Onboarding Inputs",
        sequence: 86,
        agent: "Context Agent",
        service: "context-agent",
        consumes: "orchestration-events",
        publishes: "context-events",
        timestamp: selectedAlertWorkflow?.context?.created_at || incidentCreatedAt || ingestAt,
        elapsed: elapsedSeconds(ingestAt, selectedAlertWorkflow?.context?.created_at || incidentCreatedAt || ingestAt),
        detail: `${queryTerms.length || 0} query term(s) with alert labels, service, and onboarding profile were merged.`,
        tables: "-",
        inputValueText: stringifyTimelineValue({
          alert_id: selectedAlertWorkflow?.alert?.id || selectedAlertRow?.alert_id || selectedAlertRow?.id || "",
          service: selectedAlertWorkflow?.alert?.service || selectedAlertRow?.service || "",
          query_terms: queryTerms,
        }),
        outputValueText: stringifyTimelineValue({
          metadata_keys: Object.keys(contextMetadata || {}),
          rag_matches: contextRagMatches.length,
        }),
        errorValueText: "",
        backendEvents: ["context.input.merged"],
      });
      syntheticRows.push({
        stage: "Context Agent Published RCA Context",
        sequence: 87,
        agent: "Context Agent",
        service: "context-agent",
        consumes: "context-events",
        publishes: "resolution-events",
        timestamp: selectedAlertWorkflow?.context?.created_at || incidentCreatedAt || ingestAt,
        elapsed: elapsedSeconds(ingestAt, selectedAlertWorkflow?.context?.created_at || incidentCreatedAt || ingestAt),
        detail: `${contextRagMatches.length} RAG match(es) and ${Array.isArray(discoveryMcp?.retrieval_stages) ? discoveryMcp.retrieval_stages.length : 0} discovery stage(s) were propagated to downstream RCA evaluation.`,
        tables: "-",
        inputValueText: stringifyTimelineValue({
          discovery_protocol: discoveryMcp?.protocol || "-",
          rag_top_similarity: contextMetadata?.rag_top_similarity ?? contextMetadata?.rag_top_match_confidence ?? "-",
        }),
        outputValueText: stringifyTimelineValue({
          root_cause: selectedAlertWorkflow?.recommendation?.root_cause || "",
          impact: selectedAlertWorkflow?.recommendation?.impact || "",
          recommended_action: selectedAlertWorkflow?.recommendation?.recommended_action || "",
        }),
        errorValueText: "",
        backendEvents: ["context.output.published"],
      });
    }

    const baseRows = traceRows.length ? traceRows : workflowRows;
    const orderedRows = [...syntheticRows, ...baseRows]
      .map((row, index) => ({ ...row, __rowIndex: index }))
      .sort((left, right) => {
        const leftPhase = timelinePhaseOrder(left);
        const rightPhase = timelinePhaseOrder(right);
        if (leftPhase !== rightPhase) {
          return leftPhase - rightPhase;
        }

        const leftTime = parseUtcTimestamp(left.timestamp)?.getTime();
        const rightTime = parseUtcTimestamp(right.timestamp)?.getTime();
        const leftHasTime = Number.isFinite(leftTime);
        const rightHasTime = Number.isFinite(rightTime);

        if (leftHasTime && rightHasTime && leftTime !== rightTime) {
          return leftTime - rightTime;
        }

        if (leftHasTime !== rightHasTime) {
          return leftHasTime ? -1 : 1;
        }

        const leftSeq = Number(left.sequence || 0);
        const rightSeq = Number(right.sequence || 0);
        if (leftSeq && rightSeq && leftSeq !== rightSeq) {
          return leftSeq - rightSeq;
        }

        return Number(left.__rowIndex || 0) - Number(right.__rowIndex || 0);
      });

    const rows = orderedRows.filter(
      (row, index, allRows) => {
        const stage = String(row.stage || "").trim();
        const agent = String(row.agent || "").trim();
        const timestamp = String(row.timestamp || "").trim();
        const key = `${stage}|${agent}|${timestamp}`;
        return allRows.findIndex((candidate) => {
          const cStage = String(candidate.stage || "").trim();
          const cAgent = String(candidate.agent || "").trim();
          const cTime = String(candidate.timestamp || "").trim();
          return `${cStage}|${cAgent}|${cTime}` === key;
        }) === index;
      }
    ).map((row) => {
      const { __rowIndex, ...rest } = row;
      return rest;
    });

    if (rows.length) {
      return rows;
    }

    const fallbackStatus = String(selectedIncidentMetadataRow?.status || selectedAlertWorkflow?.incident?.status || "").trim();
    if (!fallbackStatus) {
      return [];
    }

    return [
      {
        stage: "Current Incident Status",
        agent: "incident-projection",
        service: "monitoring-adapter",
        consumes: "-",
        publishes: "-",
        timestamp: selectedIncidentMetadataRow?.updated_at || selectedIncidentMetadataRow?.latest_event_at || incidentCreatedAt || ingestAt,
        elapsed: "-",
        detail: fallbackStatus,
        tables: "-",
        inputValueText: "",
        outputValueText: stringifyTimelineValue(selectedIncidentMetadataRow),
        errorValueText: "",
      },
    ];
  }, [selectedAlertWorkflow, selectedAlertRow, selectedIncidentMetadataRow, selectedAlertEvents, selectedAlertEventTrace]);

  const selectedWorkflowFlowStages = useMemo(
    () => buildWorkflowFlowStages(selectedAlertWorkflow, selectedAlertTimelineRows),
    [selectedAlertWorkflow, selectedAlertTimelineRows],
  );

  const hasSelectedWorkflowData = useMemo(() => {
    if (!selectedAlertWorkflow || typeof selectedAlertWorkflow !== "object") {
      return false;
    }
    const events = Array.isArray(selectedAlertWorkflow.events) ? selectedAlertWorkflow.events : [];
    return Boolean(events.length || selectedAlertWorkflow.incident || selectedAlertWorkflow.recommendation);
  }, [selectedAlertWorkflow]);

  const panelWorkflow = useMemo(() => {
    return hasSelectedWorkflowData ? selectedAlertWorkflow : latestWorkflow;
  }, [hasSelectedWorkflowData, selectedAlertWorkflow, latestWorkflow]);

  const globalWorkflowFlowStages = useMemo(
    () => buildWorkflowFlowStages(panelWorkflow, selectedAlertTimelineRows),
    [panelWorkflow, selectedAlertTimelineRows],
  );

  const panelWorkflowEvents = useMemo(() => {
    const events = panelWorkflow?.events || [];
    return Array.isArray(events) ? events : [];
  }, [panelWorkflow]);

  const panelWorkflowUsage = useMemo(() => {
    const directUsage = panelWorkflow?.recommendation?.metadata?.model_usage;
    if (Array.isArray(directUsage) && directUsage.length) {
      return directUsage;
    }
    const finopsCalls = panelWorkflow?.finops?.calls;
    if (Array.isArray(finopsCalls)) {
      return finopsCalls;
    }
    return [];
  }, [panelWorkflow]);

  const allUsageRows = useMemo(() => {
    const merged = [];

    const appendUsage = (candidate) => {
      if (!Array.isArray(candidate)) {
        return;
      }
      candidate.forEach((row) => {
        merged.push(normalizeUsageRow(row));
      });
    };

    appendUsage(panelWorkflowUsage);
    appendUsage(selectedAlertUsage);
    appendUsage(latestWorkflow?.finops?.calls);
    appendUsage(latestWorkflow?.recommendation?.metadata?.model_usage);
    appendUsage(latestWorkflow?.recommendation?.metadata?.llm_calls);

    monitorScopedIncidentMetadata.forEach((row) => {
      appendUsage(row?.finops?.calls);
      appendUsage(row?.model_usage);
      appendUsage(row?.llm_usage);

      const synthetic = normalizeUsageRow({
        task: row?.latest_event_type || "incident",
        provider: row?.provider || row?.llm_provider,
        model: row?.model || row?.llm_model,
        input_tokens: row?.input_tokens,
        output_tokens: row?.output_tokens,
        total_tokens: row?.total_tokens,
        total_cost_usd: row?.total_cost_usd || row?.cost_usd,
      });
      if (isMeaningfulUsageRow(synthetic)) {
        merged.push(synthetic);
      }
    });

    gatewayRecent.rows.forEach((row) => {
      appendUsage(row?.finops?.calls);
      appendUsage(row?.model_usage);
      appendUsage(row?.llm_usage);
    });

    return merged.filter((row) => isMeaningfulUsageRow(row));
  }, [panelWorkflowUsage, selectedAlertUsage, latestWorkflow, monitorScopedIncidentMetadata, gatewayRecent.rows]);

  useEffect(() => {
    if (diagnosticsDetailTab === "application" || diagnosticsDetailTab === "topics") {
      setDiagnosticsDetailTab("processing");
    }
  }, [diagnosticsDetailTab]);

  useEffect(() => {
    if (activeTab !== "home" || homeDetailTab !== "diagnostics" || diagnosticsDetailTab !== "api") {
      return;
    }
    loadGatewayRecent();
  }, [activeTab, homeDetailTab, diagnosticsDetailTab]);

  const workflowEventRows = useMemo(() => {
    const mapped = panelWorkflowEvents
      .filter((event) => event && typeof event === "object")
      .sort((a, b) => Number(a.sequence || 0) - Number(b.sequence || 0))
      .map((event) => {
        const decisionValue = event.decision;
        const outputValue = event.output;
        return {
          sequence: event.sequence || "-",
            agent: displayAgentName(event.agent || "-"),
          action: event.action || "-",
          decision: typeof decisionValue === "object" ? JSON.stringify(decisionValue) : String(decisionValue || "-"),
          output: typeof outputValue === "object" ? JSON.stringify(outputValue) : String(outputValue || "-"),
          communicates_to: event.communicates_to || "-",
        };
      });
    if (mapped.length) {
      return mapped;
    }
    return gatewayRecent.rows.slice(0, 80).map((event, index) => ({
      sequence: index + 1,
      agent: displayAgentName("API Gateway"),
      action: event.path || "gateway.event",
      decision: event?.safety?.decision || "-",
      output: String(event.status_code || "-") + (event.trace_id ? ` | trace ${event.trace_id}` : ""),
      communicates_to: event.target_url || "monitoring-adapter",
    }));
  }, [panelWorkflowEvents, gatewayRecent.rows]);

  const observedRouting = useMemo(() => extractObservedRoutingMetrics(panelWorkflow), [panelWorkflow]);

  const messageBusTopicRows = useMemo(() => {
    return SERVICE_TOPIC_FLOW.map((row) => ({
      service: row.service,
      consumes: row.consumes === "-" ? "-" : `${row.consumes} (enabled transports)`,
      publishes: row.publishes,
    }));
  }, []);

  const messageBusActual = useMemo(() => {
    const workflow = panelWorkflow;
    const events = Array.isArray(workflow.events) ? workflow.events : [];
    const traceRows = Array.isArray(workflow.event_trace) ? workflow.event_trace : [];
    const observedAgents = new Set(events.map((item) => String(item?.agent || "").trim()));
    const observedServices = new Set(traceRows.map((item) => String(item?.service || "").trim()));
    const observedProvider = String(observedRouting?.message_bus_provider || "").trim().toUpperCase() || "N/A";
    const approval = typeof workflow.approval === "object" ? workflow.approval : {};
    const remediation = typeof workflow.remediation_action === "object" ? workflow.remediation_action : {};
    const closure = typeof workflow.closure_report === "object" ? workflow.closure_report : {};
    const hasWorkflow = Boolean(workflow.alert || workflow.incident || events.length);
    const observedChannels = new Set();
    traceRows.forEach((row) => {
      const source = String(row?.source_channel || "").trim();
      const transport = String(row?.transport_channel || "").trim();
      if (source) {
        observedChannels.add(source);
      }
      if (transport) {
        observedChannels.add(transport);
      }
    });

    const published = [];
    const consumed = [];
    const rows = SERVICE_TOPIC_FLOW.map((row) => {
      let isObserved = false;
      if (row.agent === "alert") {
        isObserved = hasWorkflow;
      } else if (observedAgents.has(row.agent)) {
        isObserved = true;
      } else if (observedServices.has(row.service)) {
        isObserved = true;
      } else if (row.agent === "Human Approval Layer" && Object.keys(approval).length) {
        isObserved = true;
      } else if (row.agent === "Remediation Automation Engine" && Object.keys(remediation).length) {
        isObserved = true;
      } else if (row.agent === "Closure & Validation" && Object.keys(closure).length) {
        isObserved = true;
      }

      if (isObserved) {
        if (row.consumes !== "-" && !consumed.includes(row.consumes)) {
          consumed.push(row.consumes);
        }
        if (!published.includes(row.publishes)) {
          published.push(row.publishes);
        }
      }

      return {
        service: row.service,
        consumed: isObserved ? row.consumes : "-",
        published: isObserved ? row.publishes : "-",
        provider: observedProvider,
        status: isObserved ? "Observed" : "Not reached",
      };
    });

    observedChannels.forEach((channel) => {
      if (!published.includes(channel)) {
        published.push(channel);
      }
      if (!consumed.includes(channel)) {
        consumed.push(channel);
      }
    });

    return { published, consumed, rows };
  }, [panelWorkflow, observedRouting]);

  const executiveMetrics = useMemo(() => {
    const rows = Array.isArray(gatewayRecent.rows) ? gatewayRecent.rows : [];
    const summaryTotal = toFiniteNumber(gatewaySummary.data?.window_events || gatewaySummary.data?.total_events || 0);
    const recentSuccess = rows.filter((row) => {
      const status = Number(row?.status_code || 0);
      return status >= 200 && status < 400;
    }).length;
    const recentFailure = rows.filter((row) => Number(row?.status_code || 0) >= 400).length;
    const totalRequests = rows.length || summaryTotal;
    const successRequests = rows.length ? recentSuccess : toFiniteNumber(gatewaySummary.data?.allowed || 0);
    const failedRequests = rows.length
      ? recentFailure
      : toFiniteNumber(gatewaySummary.data?.blocked || 0) + toFiniteNumber(gatewaySummary.data?.review || 0);
    const latencyValues = rows
      .map((row) => Number(row?.latency_ms ?? row?.gateway?.latency_ms ?? row?.latency ?? 0))
      .filter((value) => Number.isFinite(value) && value > 0);
    const avgLatencyMs = latencyValues.length
      ? latencyValues.reduce((sum, value) => sum + value, 0) / latencyValues.length
      : 0;
    const p95LatencyMs = percentile(latencyValues, 0.95);

    const latencyTrend = rows
      .slice(0, 12)
      .reverse()
      .map((row, index) => {
        const value = Number(row?.latency_ms ?? row?.gateway?.latency_ms ?? row?.latency ?? 0);
        const status = Number(row?.status_code || 0);
        return {
          label: `${index + 1}`,
          value: Number.isFinite(value) ? value : 0,
          displayValue: `${Number.isFinite(value) ? value.toFixed(1) : "0.0"} ms`,
          tone: status >= 400 ? "risk" : "ops",
        };
      });

    const finopsTotals =
      panelWorkflow?.finops?.totals
      || selectedAlertWorkflow?.finops?.totals
      || latestWorkflow?.finops?.totals
      || {};
    const finopsCalls = toFiniteNumber(finopsTotals?.calls || allUsageRows.length);
    const finopsTokens = toFiniteNumber(finopsTotals?.total_tokens || allUsageRows.reduce((sum, row) => sum + toFiniteNumber(row?.total_tokens), 0));
    const finopsCost = toFiniteNumber(finopsTotals?.total_cost_usd || allUsageRows.reduce((sum, row) => sum + toFiniteNumber(row?.total_cost_usd), 0));

    return {
      totalRequests,
      successRequests,
      failedRequests,
      avgLatencyMs,
      p95LatencyMs,
      latencyTrend,
      finopsCalls,
      finopsTokens,
      finopsCost,
    };
  }, [gatewayRecent.rows, gatewaySummary.data, panelWorkflow, selectedAlertWorkflow, latestWorkflow, allUsageRows]);

  const finopsByProvider = useMemo(() => {
    const grouped = new Map();
    allUsageRows.forEach((row) => {
      const key = String(row?.provider || "unknown");
      const current = grouped.get(key) || { provider: key, calls: 0, total_tokens: 0, total_cost_usd: 0 };
      current.calls += 1;
      current.total_tokens += Number(row?.total_tokens || 0);
      current.total_cost_usd += Number(row?.total_cost_usd || 0);
      grouped.set(key, current);
    });
    return Array.from(grouped.values());
  }, [allUsageRows]);

  const closedRiskOptions = useMemo(() => {
    return Array.from(
      new Set(closedIncidents.rows.map((row) => String(row?.risk_tier || row?.risk || "unknown").toLowerCase()))
    ).sort();
  }, [closedIncidents.rows]);

  const closedModeOptions = useMemo(() => {
    return Array.from(
      new Set(closedIncidents.rows.map((row) => String(row?.execution_mode || "unknown").toLowerCase()))
    ).sort();
  }, [closedIncidents.rows]);

  const filteredClosedRows = useMemo(() => {
    return closedIncidents.rows.filter((row) => {
      const risk = String(row?.risk_tier || row?.risk || "unknown").toLowerCase();
      const mode = String(row?.execution_mode || "unknown").toLowerCase();
      const riskPass = closedFilters.risk === "all" || closedFilters.risk === risk;
      const modePass = closedFilters.mode === "all" || closedFilters.mode === mode;
      return riskPass && modePass;
    });
  }, [closedIncidents.rows, closedFilters]);

  const executiveClosedSummary = useMemo(() => {
    const rows = Array.isArray(closedIncidents.rows) ? closedIncidents.rows : [];
    const restored = rows.filter((row) => row?.health_restored === true).length;
    const byRisk = new Map();
    const byMode = new Map();

    rows.forEach((row) => {
      const risk = String(row?.risk_tier || row?.risk || row?.severity || "unknown").toLowerCase();
      const mode = String(row?.execution_mode || "unknown").toLowerCase();
      byRisk.set(risk, (byRisk.get(risk) || 0) + 1);
      byMode.set(mode, (byMode.get(mode) || 0) + 1);
    });

    const riskItems = Array.from(byRisk.entries()).map(([label, value]) => ({ label, value, tone: "risk" }));
    const modeItems = Array.from(byMode.entries()).map(([label, value]) => ({ label, value, tone: "meta" }));

    return {
      total: rows.length,
      restored,
      closureRate: rows.length ? (restored / rows.length) * 100 : 0,
      riskItems,
      modeItems,
      recentRows: rows.slice(0, 15),
    };
  }, [closedIncidents.rows]);

  useEffect(() => {
    if (!latestIncidentId && !latestRecommendationId) {
      return;
    }
    setApprovalForm((current) => ({
      ...current,
      incident_id: latestIncidentId || current.incident_id,
      recommendation_id: latestRecommendationId || current.recommendation_id,
    }));
  }, [latestIncidentId, latestRecommendationId]);

  function approvalIncidentId(row) {
    return String(row?.incident_id || row?.id || row?.alert_id || "").trim();
  }

  function approvalRecommendationId(row) {
    const candidates = [
      row?.recommendation_id,
      row?.recommendation?.id,
      row?.remediation_recommendation_id,
      row?.recommended_action_id,
    ];
    for (const candidate of candidates) {
      const token = String(candidate || "").trim();
      if (looksLikeUuid(token)) {
        return token;
      }
    }
    return "";
  }

  function approvalFlowId(row) {
    return String(row?.flow_id || row?.workflow_id || row?.flow || "").trim();
  }

  function approvalTraceId(row) {
    return String(row?.trace_id || row?.correlation_id || "").trim();
  }

  function approvalRecommendationFromPayload(payload) {
    const normalized = payload && typeof payload === "object" ? payload : {};
    const data = normalized.data && typeof normalized.data === "object" ? normalized.data : {};
    const recommendation = normalized.recommendation && typeof normalized.recommendation === "object"
      ? normalized.recommendation
      : data.recommendation && typeof data.recommendation === "object"
        ? data.recommendation
        : {};
    const approval = normalized.approval && typeof normalized.approval === "object"
      ? normalized.approval
      : data.approval && typeof data.approval === "object"
        ? data.approval
        : {};
    const sourcePayload = normalized.source_payload && typeof normalized.source_payload === "object"
      ? normalized.source_payload
      : data.source_payload && typeof data.source_payload === "object"
        ? data.source_payload
        : {};
    const sourceRecommendation = sourcePayload.recommendation && typeof sourcePayload.recommendation === "object"
      ? sourcePayload.recommendation
      : {};
    const candidates = [
      normalized.recommendation_id,
      data.recommendation_id,
      recommendation.id,
      approval.recommendation_id,
      normalized.remediation_recommendation_id,
      data.remediation_recommendation_id,
      normalized.recommended_action_id,
      data.recommended_action_id,
      sourcePayload.recommendation_id,
      sourceRecommendation.id,
    ];
    for (const candidate of candidates) {
      const token = String(candidate || "").trim();
      if (looksLikeUuid(token)) {
        return token;
      }
    }
    return "";
  }

  function mergeRecommendationIdIntoApprovalRow(incidentId, recommendationId) {
    const normalizedIncidentId = String(incidentId || "").trim();
    const normalizedRecommendationId = String(recommendationId || "").trim();
    if (!normalizedIncidentId || !looksLikeUuid(normalizedRecommendationId)) {
      return;
    }
    const patchRow = (row) => {
      const rowIncidentId = approvalIncidentId(row);
      if (rowIncidentId !== normalizedIncidentId) {
        return row;
      }
      return {
        ...row,
        recommendation_id: normalizedRecommendationId,
        remediation_recommendation_id: row?.remediation_recommendation_id || normalizedRecommendationId,
      };
    };
    setIncidentMetadata((prev) => ({
      ...prev,
      rows: Array.isArray(prev.rows) ? prev.rows.map(patchRow) : prev.rows,
    }));
    setAlerts((prev) => ({
      ...prev,
      rows: Array.isArray(prev.rows) ? prev.rows.map(patchRow) : prev.rows,
    }));
  }

  function approvalFlowFromPayload(payload) {
    const normalized = payload && typeof payload === "object" ? payload : {};
    const decision = normalized.decision && typeof normalized.decision === "object" ? normalized.decision : {};
    const recommendation = normalized.recommendation && typeof normalized.recommendation === "object"
      ? normalized.recommendation
      : {};
    return String(
      normalized.flow_id
      || decision.flow_id
      || recommendation.flow_id
      || normalized.trace_id
      || recommendation.trace_id
      || normalized.correlation_id
      || recommendation.correlation_id
      || ""
    ).trim();
  }

  async function loadApprovalIncidentContext(incidentId, options = {}) {
    const forceRefresh = Boolean(options?.force);
    const normalized = String(incidentId || "").trim();
    if (!normalized) {
      return;
    }
    const now = Date.now();
    const requestState = approvalIncidentRequestRef.current;
    if (requestState.inFlight && requestState.incidentId === normalized) {
      return;
    }
    if (!forceRefresh && (
      approvalIncidentContext.incident_id === normalized
      && approvalIncidentContext.payload
      && now - requestState.lastFetchedAt < 10000
    )) {
      return;
    }

    approvalIncidentRequestRef.current = { ...requestState, incidentId: normalized, inFlight: true };
    setApprovalIncidentContext((current) => ({
      loading: true,
      incident_id: normalized,
      payload: current.incident_id === normalized ? current.payload : null,
      error: "",
    }));
    try {
      const options = adminHeaders().Authorization ? authenticatedOptions() : {};
      const response = await fetchJson(`/api-gateway/approval/incident/${encodeURIComponent(normalized)}`, options);
      const payload = unwrap(response);
      const recommendationId = approvalRecommendationFromPayload(payload);
      setApprovalIncidentContext({ loading: false, incident_id: normalized, payload, error: "" });
      approvalIncidentRequestRef.current = {
        incidentId: normalized,
        inFlight: false,
        lastFetchedAt: Date.now(),
      };
      if (recommendationId) {
        mergeRecommendationIdIntoApprovalRow(normalized, recommendationId);
        setApprovalForm((current) => ({
          ...current,
          incident_id: normalized || current.incident_id,
          recommendation_id: recommendationId || current.recommendation_id,
        }));
      }
    } catch (error) {
      const raw = String(error?.message || "");
      const brief = raw.includes("HTTP 502") || raw.includes("500 Internal Server Error")
        ? "Approval context service is temporarily unavailable. You can continue using selected incident details."
        : raw;
      approvalIncidentRequestRef.current = {
        incidentId: normalized,
        inFlight: false,
        lastFetchedAt: Date.now(),
      };
      setApprovalIncidentContext({ loading: false, incident_id: normalized, payload: null, error: brief });
    }
  }

  const pendingApprovals = useMemo(() => {
    return monitorScopedIncidentMetadata.filter((row) => {
      const mode = String(row?.execution_mode || "").toLowerCase();
      const status = String(row?.status || "").toLowerCase();
      if (isApprovalPendingStatus(status)) {
        return true;
      }
      return mode === "human-approval" && !isApprovalResolvedStatus(status);
    });
  }, [monitorScopedIncidentMetadata]);

  const filteredPendingApprovals = useMemo(() => {
    return pendingApprovals.filter((row) => {
      if (approvalFilter === "all") {
        return true;
      }
      const severity = String(row?.severity || row?.risk_tier || "").toLowerCase();
      const status = String(row?.status || "").toLowerCase();
      if (approvalFilter === "awaiting_approval") {
        return status === "awaiting_approval";
      }
      return severity === approvalFilter;
    });
  }, [pendingApprovals, approvalFilter]);

  const pendingApprovalByIncidentId = useMemo(() => {
    const index = new Map();
    pendingApprovals.forEach((row) => {
      const incidentId = approvalIncidentId(row);
      if (incidentId) {
        index.set(incidentId, row);
      }
    });
    return index;
  }, [pendingApprovals]);

  const executiveInsights = useMemo(() => {
    const openRows = monitorScopedIncidentMetadata.filter((row) => !isApprovalResolvedStatus(row?.status || row?.state));
    const slaAtRisk = openRows.filter((row) => {
      const risk = String(row?.risk_tier || row?.risk || row?.severity || "").toLowerCase();
      const mode = String(row?.execution_mode || "").toLowerCase();
      return risk === "high" || risk === "critical" || mode.includes("manual");
    }).length;

    const pendingApprovalAges = pendingApprovals
      .map((row) => parseUtcTimestamp(row?.created_at || row?.updated_at || row?.timestamp)?.getTime() || 0)
      .filter((value) => value > 0)
      .map((time) => Math.max(0, (Date.now() - time) / 60000));
    const avgApprovalWaitMinutes = pendingApprovalAges.length
      ? pendingApprovalAges.reduce((sum, value) => sum + value, 0) / pendingApprovalAges.length
      : 0;

    const closedRows = Array.isArray(closedIncidents.rows) ? closedIncidents.rows : [];
    const autoClosed = closedRows.filter((row) => String(row?.execution_mode || "").toLowerCase().includes("auto")).length;
    const automationRate = closedRows.length ? (autoClosed / closedRows.length) * 100 : 0;

    const dayBuckets = Array.from({ length: 7 }).map((_, idx) => {
      const date = new Date();
      date.setHours(0, 0, 0, 0);
      date.setDate(date.getDate() - (6 - idx));
      const key = date.toISOString().slice(0, 10);
      return { key, label: date.toLocaleDateString(undefined, { month: "short", day: "numeric" }), open: 0, closed: 0 };
    });
    const bucketMap = new Map(dayBuckets.map((item) => [item.key, item]));

    monitorScopedAlerts.forEach((row) => {
      const parsed = parseUtcTimestamp(row?.created_at || row?.starts_at);
      if (!parsed) {
        return;
      }
      const key = parsed.toISOString().slice(0, 10);
      const bucket = bucketMap.get(key);
      if (bucket) {
        bucket.open += 1;
      }
    });

    closedRows.forEach((row) => {
      const parsed = parseUtcTimestamp(row?.closed_at || row?.updated_at || row?.created_at);
      if (!parsed) {
        return;
      }
      const key = parsed.toISOString().slice(0, 10);
      const bucket = bucketMap.get(key);
      if (bucket) {
        bucket.closed += 1;
      }
    });

    const weeklyOpenTrend = dayBuckets.map((item) => ({ label: item.label, value: item.open, tone: "risk" }));
    const weeklyClosedTrend = dayBuckets.map((item) => ({ label: item.label, value: item.closed, tone: "ops" }));

    return {
      openIncidents: openRows.length,
      slaAtRisk,
      avgApprovalWaitMinutes,
      automationRate,
      weeklyOpenTrend,
      weeklyClosedTrend,
    };
  }, [monitorScopedIncidentMetadata, pendingApprovals, closedIncidents.rows, monitorScopedAlerts]);

  const selectedApprovalRow = useMemo(() => {
    return filteredPendingApprovals.find((row) => approvalIncidentId(row) === selectedApprovalIncidentId) || null;
  }, [filteredPendingApprovals, selectedApprovalIncidentId]);

  const selectedApprovalRecommendationId = useMemo(() => {
    if (selectedApprovalRow) {
      const rowRecommendationId = approvalRecommendationId(selectedApprovalRow);
      if (rowRecommendationId) {
        return rowRecommendationId;
      }
    }
    if (approvalIncidentContext.incident_id && approvalIncidentContext.incident_id === selectedApprovalIncidentId) {
      return approvalRecommendationFromPayload(approvalIncidentContext.payload);
    }
    return "";
  }, [selectedApprovalRow, approvalIncidentContext, selectedApprovalIncidentId]);

  const selectedApprovalFlowContext = useMemo(() => {
    if (selectedApprovalRow) {
      const rowFlow = approvalFlowId(selectedApprovalRow) || approvalTraceId(selectedApprovalRow);
      if (rowFlow) {
        return rowFlow;
      }
    }
    if (approvalIncidentContext.incident_id && approvalIncidentContext.incident_id === selectedApprovalIncidentId) {
      return approvalFlowFromPayload(approvalIncidentContext.payload);
    }
    return "";
  }, [selectedApprovalRow, approvalIncidentContext, selectedApprovalIncidentId]);

  useEffect(() => {
    if (!selectedApprovalIncidentId) {
      return;
    }
    setApprovalForm((current) => {
      const nextIncidentId = String(selectedApprovalIncidentId || "").trim() || current.incident_id;
      const nextRecommendationId = String(selectedApprovalRecommendationId || "").trim() || current.recommendation_id;
      if (nextIncidentId === current.incident_id && nextRecommendationId === current.recommendation_id) {
        return current;
      }
      return {
        ...current,
        incident_id: nextIncidentId,
        recommendation_id: nextRecommendationId,
      };
    });
  }, [selectedApprovalIncidentId, selectedApprovalRecommendationId]);

  useEffect(() => {
    if (activeTab === "home" && homeDetailTab === "timeline" && selectedIncidentId) {
      return;
    }
    if (!filteredPendingApprovals.length) {
      if (selectedApprovalIncidentId) {
        setSelectedApprovalIncidentId("");
      }
      return;
    }
    const selectedExists = filteredPendingApprovals.some((row) => approvalIncidentId(row) === selectedApprovalIncidentId);
    if (selectedExists) {
      return;
    }
    setSelectedApprovalIncidentId(approvalIncidentId(filteredPendingApprovals[0]));
  }, [activeTab, filteredPendingApprovals, homeDetailTab, selectedApprovalIncidentId, selectedIncidentId]);

  useEffect(() => {
    if (!selectedApprovalIncidentId) {
      return;
    }
    loadApprovalIncidentContext(selectedApprovalIncidentId);
  }, [selectedApprovalIncidentId]);

  useEffect(() => {
    if (activeTab !== "home" || homeDetailTab !== "actions" || !selectedIncidentId) {
      return;
    }
    setSelectedApprovalIncidentId((current) => current === selectedIncidentId ? current : selectedIncidentId);
    setApprovalForm((current) => {
      const nextRecommendationId = selectedAlertRecommendationId || current.recommendation_id;
      if (current.incident_id === selectedIncidentId && current.recommendation_id === nextRecommendationId) {
        return current;
      }
      return {
        ...current,
        incident_id: selectedIncidentId,
        recommendation_id: nextRecommendationId,
      };
    });
    loadApprovalIncidentContext(selectedIncidentId);
  }, [activeTab, homeDetailTab, selectedIncidentId, selectedAlertRecommendationId]);

  function selectApprovalIncident(row) {
    const incidentId = approvalIncidentId(row);
    const recommendationId = approvalRecommendationId(row);
    if (!incidentId) {
      return;
    }
    setSelectedApprovalIncidentId(incidentId);
    setApprovalForm((current) => ({
      ...current,
      incident_id: incidentId || current.incident_id,
      recommendation_id: recommendationId || current.recommendation_id,
    }));
    setApprovalState({ loading: false, result: null, error: "" });
    loadApprovalIncidentContext(incidentId);
  }

  function resolvePendingApprovalFromAlertRow(alertRow) {
    const directIncidentId = approvalIncidentId(alertRow);
    if (directIncidentId && pendingApprovalByIncidentId.has(directIncidentId)) {
      return pendingApprovalByIncidentId.get(directIncidentId) || null;
    }

    const service = String(alertRow?.service || "").trim().toLowerCase();
    const severity = String(alertRow?.severity || "").trim().toLowerCase();
    if (!service) {
      return null;
    }

    const byServiceAndSeverity = pendingApprovals.find((row) => {
      const rowService = String(row?.service || "").trim().toLowerCase();
      const rowSeverity = String(row?.severity || row?.risk_tier || "").trim().toLowerCase();
      return rowService === service && (!severity || !rowSeverity || rowSeverity === severity);
    });
    if (byServiceAndSeverity) {
      return byServiceAndSeverity;
    }

    return pendingApprovals.find((row) => String(row?.service || "").trim().toLowerCase() === service) || null;
  }

  // Single source of truth for "what is the approval status of the selected alert" so the
  // Decision Gate, Decision & Approval section, and any other view agree instead of each
  // computing their own answer from a different subset of fields.
  const selectedMatchedApproval = useMemo(
    () => resolvePendingApprovalFromAlertRow(selectedAlertRow),
    [selectedAlertRow, pendingApprovals, pendingApprovalByIncidentId],
  );

  const selectedApprovalStatus = useMemo(
    () => normalizeApprovalStatus(selectedMatchedApproval?.status || selectedAlertWorkflow?.approval?.status),
    [selectedMatchedApproval, selectedAlertWorkflow?.approval?.status],
  );

  function selectApprovalFromAlertRow(alertRow) {
    const matchedRow = resolvePendingApprovalFromAlertRow(alertRow);
    if (!matchedRow) {
      setApprovalState((current) => ({
        ...current,
        error: "No pending approval incident matched this alert. Open incident details or adjust the pending filter.",
      }));
      return null;
    }
    selectApprovalIncident(matchedRow);
    approvalQueueRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
    return matchedRow;
  }

  function applyApprovalResolutionToUi(incidentId, nextStatus, comment = "") {
    const normalizedIncidentId = String(incidentId || "").trim();
    const normalizedStatus = String(nextStatus || "").trim().toLowerCase();
    if (!normalizedIncidentId || !normalizedStatus) {
      return;
    }

    const patchIncidentRow = (row) => {
      const rowIncidentId = String(row?.incident_id || row?.id || row?.alert_id || "").trim();
      if (rowIncidentId !== normalizedIncidentId) {
        return row;
      }
      return {
        ...row,
        status: normalizedStatus,
        approval_status: normalizedStatus,
        updated_at: new Date().toISOString(),
        latest_comment: comment || row?.latest_comment || "",
      };
    };

    setIncidentMetadata((prev) => ({
      ...prev,
      rows: Array.isArray(prev.rows) ? prev.rows.map(patchIncidentRow) : prev.rows,
    }));

    setAlerts((prev) => ({
      ...prev,
      rows: Array.isArray(prev.rows)
        ? prev.rows.map((row) => {
            const rowIncidentId = String(row?.incident_id || row?.id || row?.alert_id || "").trim();
            if (rowIncidentId !== normalizedIncidentId) {
              return row;
            }
            return {
              ...row,
              status: normalizedStatus,
              state: normalizedStatus,
              updated_at: new Date().toISOString(),
            };
          })
        : prev.rows,
    }));

    setSelectedAlertData((prev) => {
      const payloadRoot = prev?.payload?.data || prev?.payload;
      if (!payloadRoot || typeof payloadRoot !== "object") {
        return prev;
      }
      const workflow = payloadRoot?.workflow || payloadRoot;
      const workflowIncidentId = String(
        workflow?.incident?.id
        || workflow?.incident_id
        || payloadRoot?.incident?.id
        || payloadRoot?.incident_id
        || ""
      ).trim();
      if (workflowIncidentId !== normalizedIncidentId) {
        return prev;
      }

      const nextWorkflow = {
        ...(workflow || {}),
        incident: {
          ...(workflow?.incident || {}),
          status: normalizedStatus,
          updated_at: new Date().toISOString(),
        },
        approval: {
          ...(workflow?.approval || {}),
          status: normalizedStatus,
          comment: comment || workflow?.approval?.comment || "",
        },
      };

      if (prev?.payload?.data && typeof prev.payload === "object") {
        return {
          ...prev,
          payload: {
            ...prev.payload,
            data: {
              ...payloadRoot,
              workflow: nextWorkflow,
            },
          },
        };
      }

      return {
        ...prev,
        payload: {
          ...payloadRoot,
          workflow: nextWorkflow,
        },
      };
    });

    setApprovalIncidentContext((prev) => {
      if (String(prev?.incident_id || "").trim() !== normalizedIncidentId) {
        return prev;
      }
      const root = prev?.payload && typeof prev.payload === "object" ? prev.payload : {};
      const data = root?.data && typeof root.data === "object" ? root.data : root;
      const patched = {
        ...data,
        status: normalizedStatus,
        state: normalizedStatus,
        approval_status: normalizedStatus,
        updated_at: new Date().toISOString(),
      };
      return {
        ...prev,
        payload: root?.data ? { ...root, data: patched } : patched,
        error: "",
      };
    });
  }

  const approvalReady = useMemo(() => {
    const cockpitIncidentId = activeTab === "home" && homeDetailTab === "timeline" ? selectedIncidentId : "";
    const hasBase = String(cockpitIncidentId || approvalForm.incident_id || selectedApprovalIncidentId || "").trim() && String(approvalForm.approver || "").trim();
    if (!hasBase) {
      return false;
    }
    if (approvalForm.action !== "modify") {
      return true;
    }
    return String(approvalForm.modified_action || "").trim().length > 0;
  }, [activeTab, approvalForm, homeDetailTab, selectedApprovalIncidentId, selectedIncidentId]);

  async function executeApprovalAction({
    incidentId,
    recommendationId,
    action,
    approver,
    channel,
    comment,
    modifiedAction,
  }) {
    const normalizedIncidentId = String(incidentId || "").trim();
    const normalizedRecommendationId = String(recommendationId || "").trim();
    const normalizedAction = String(action || "approve").trim().toLowerCase() || "approve";

    if (!looksLikeUuid(normalizedIncidentId)) {
      throw new Error("Approval requires a valid incident_id. Select a pending approval incident first.");
    }

    const payload = {
      incident_id: normalizedIncidentId,
      approver: String(approver || "").trim(),
      channel: String(channel || "web").trim(),
      comment: String(comment || "").trim() || null,
    };
    if (looksLikeUuid(normalizedRecommendationId)) {
      payload.recommendation_id = normalizedRecommendationId;
    }

    if (normalizedAction === "modify") {
      payload.modified_action = String(modifiedAction || "").trim();
    }

    return fetchJson(`/api-gateway/approval/${normalizedAction}`, authenticatedOptions({
      method: "POST",
      body: JSON.stringify(payload),
    }));
  }

  async function resolveRecommendationIdForIncident(incidentId, preferredRecommendationId = "") {
    const normalizedIncidentId = String(incidentId || "").trim();
    const preferred = String(preferredRecommendationId || "").trim();
    if (looksLikeUuid(preferred)) {
      return preferred;
    }

    if (approvalIncidentContext.incident_id === normalizedIncidentId) {
      const fromContext = approvalRecommendationFromPayload(approvalIncidentContext.payload);
      if (looksLikeUuid(fromContext)) {
        return fromContext;
      }
    }

    const options = adminHeaders().Authorization ? authenticatedOptions() : {};
    const response = await fetchJson(`/api-gateway/approval/incident/${encodeURIComponent(normalizedIncidentId)}`, options);
    const payload = unwrap(response);
    const resolved = approvalRecommendationFromPayload(payload);
    if (looksLikeUuid(resolved)) {
      setApprovalIncidentContext({ loading: false, incident_id: normalizedIncidentId, payload, error: "" });
      mergeRecommendationIdIntoApprovalRow(normalizedIncidentId, resolved);
      setApprovalForm((current) => ({
        ...current,
        incident_id: normalizedIncidentId || current.incident_id,
        recommendation_id: resolved || current.recommendation_id,
      }));
      return resolved;
    }
    return "";
  }

  function buildEditedRemediationPlan() {
    return {
      commands: toPlanLines(remediationPlanEditor.commands),
      scripts: toPlanLines(remediationPlanEditor.scripts),
      queries: toPlanLines(remediationPlanEditor.queries),
    };
  }

  function buildRemediationExecutionPayload({ incidentId, recommendationId, approver, action, comment, editedPlan }) {
    const decision = action === "modify" ? "modified" : "approved";
    const planText = [
      editedPlan.commands.length ? `Commands:\n${editedPlan.commands.map((item) => `- ${item}`).join("\n")}` : "",
      editedPlan.scripts.length ? `Scripts:\n${editedPlan.scripts.map((item) => `- ${item}`).join("\n")}` : "",
      editedPlan.queries.length ? `Queries:\n${editedPlan.queries.map((item) => `- ${item}`).join("\n")}` : "",
    ].filter(Boolean).join("\n\n");

    return {
      incident_id: incidentId,
      recommendation_id: recommendationId,
      decision,
      approver,
      channel: approvalForm.channel || "web",
      comment: String(comment || remediationPlanEditor.notes || "approved remediation execution").trim(),
      modified_action: planText,
      metadata: {
        recommended_action: selectedExecutionPlan.action,
        recommended_commands: [
          ...editedPlan.commands,
          ...editedPlan.scripts.map((item) => `script: ${item}`),
          ...editedPlan.queries.map((item) => `query: ${item}`),
        ],
        execution_plan: editedPlan,
        service: selectedApplicationConnection.service !== "-" ? selectedApplicationConnection.service : undefined,
        environment: selectedApplicationConnection.environment,
        remediation_target: selectedApplicationConnection.service !== "-" ? selectedApplicationConnection.service : selectedApplicationConnection.application,
        connection_profile: {
          application: selectedApplicationConnection.application,
          service: selectedApplicationConnection.service,
          environment: selectedApplicationConnection.environment,
          namespace: String(remediationPlanEditor.namespace || selectedApplicationConnection.namespace || "").trim(),
          endpoint_url: String(remediationPlanEditor.connection_url || "").trim(),
          connection_type: String(remediationPlanEditor.connection_type || selectedApplicationConnection.connection_type || "").trim(),
          source: selectedApplicationConnection.source,
        },
        ui_edited: true,
      },
    };
  }

  async function postRemediationExecution(payload, incidentId, comment) {
    const response = await fetchJson("/api-gateway/remediation/execute", authenticatedOptions({
      method: "POST",
      body: JSON.stringify(payload),
    }));
    const action = unwrap(response);
    setRemediationExecutionState({ loading: false, result: response, error: "" });
    const status = String(action?.status || "").toLowerCase();
    applyApprovalResolutionToUi(
      incidentId,
      status === "succeeded" ? "validating" : status === "failed" || status === "skipped" ? "failed" : "remediating",
      comment
    );
    await refreshApprovalDrivenViews(incidentId);
    return response;
  }

  async function approveIncidentRow(row) {
    const incidentId = approvalIncidentId(row);
    const rowRecommendationId = approvalRecommendationId(row);
    setSelectedApprovalIncidentId(incidentId);
    setApprovalForm((current) => ({
      ...current,
      action: "approve",
      incident_id: incidentId || current.incident_id,
      recommendation_id: rowRecommendationId || current.recommendation_id,
    }));
    setApprovalState({ loading: true, result: null, error: "" });

    try {
      const recommendationId = await resolveRecommendationIdForIncident(incidentId, rowRecommendationId);
      const response = await executeApprovalAction({
        incidentId,
        recommendationId,
        action: "approve",
        approver: approvalForm.approver,
        channel: approvalForm.channel,
        comment: approvalForm.comment,
      });
      setRemediationExecutionState({ loading: true, result: null, error: "" });
      const remediationResponse = await postRemediationExecution(unwrap(response), incidentId, approvalForm.comment);
      const remediationStatus = String(unwrap(remediationResponse)?.status || "").toLowerCase();
      setApprovalForm((current) => ({
        ...current,
        action: "approve",
        incident_id: incidentId || current.incident_id,
        recommendation_id: recommendationId || current.recommendation_id,
      }));
      applyApprovalResolutionToUi(
        incidentId,
        remediationStatus === "succeeded" ? "validating" : remediationStatus === "failed" || remediationStatus === "skipped" ? "failed" : "remediating",
        approvalForm.comment
      );
      setApprovalState({ loading: false, result: { approval: response, remediation: remediationResponse }, error: "" });
      loadApprovalIncidentContext(incidentId, { force: true });
      await refreshApprovalDrivenViews(incidentId);
    } catch (error) {
      const raw = String(error?.message || "");
      const concise = raw.includes("HTTP 422")
        ? "Inline approve could not submit because this incident has no linked remediation recommendation yet. Re-run the incident workflow to generate a recommendation."
        : raw;
      setApprovalState({ loading: false, result: null, error: concise });
      setRemediationExecutionState((current) => current.loading ? { loading: false, result: null, error: concise } : current);
    }
  }

  async function rejectIncidentRow(row) {
    const incidentId = approvalIncidentId(row);
    const rowRecommendationId = approvalRecommendationId(row);
    setSelectedApprovalIncidentId(incidentId);
    setApprovalForm((current) => ({
      ...current,
      action: "reject",
      incident_id: incidentId || current.incident_id,
      recommendation_id: rowRecommendationId || current.recommendation_id,
    }));
    setApprovalState({ loading: true, result: null, error: "" });

    try {
      const recommendationId = await resolveRecommendationIdForIncident(incidentId, rowRecommendationId);
      const response = await executeApprovalAction({
        incidentId,
        recommendationId,
        action: "reject",
        approver: approvalForm.approver,
        channel: approvalForm.channel,
        comment: inlineRejectState.comment,
      });
      setApprovalForm((current) => ({
        ...current,
        action: "reject",
        incident_id: incidentId || current.incident_id,
        recommendation_id: recommendationId || current.recommendation_id,
        comment: inlineRejectState.comment || current.comment,
      }));
      applyApprovalResolutionToUi(incidentId, "failed", inlineRejectState.comment);
      setInlineRejectState({ incidentId: "", comment: "" });
      setApprovalState({ loading: false, result: response, error: "" });
      loadApprovalIncidentContext(incidentId, { force: true });
      await refreshApprovalDrivenViews(incidentId);
    } catch (error) {
      const raw = String(error?.message || "");
      const concise = raw.includes("HTTP 422")
        ? "Inline reject could not submit because this incident has no linked remediation recommendation yet. Re-run the incident workflow to generate a recommendation."
        : raw;
      setApprovalState({ loading: false, result: null, error: concise });
    }
  }

  async function submitApproval(event) {
    event.preventDefault();
    setApprovalState({ loading: true, result: null, error: "" });
    try {
      const cockpitIncidentId = activeTab === "home" && homeDetailTab === "timeline" ? selectedIncidentId : "";
      const incidentId = String(cockpitIncidentId || approvalForm.incident_id || selectedApprovalIncidentId || "").trim();
      const approver = String(approvalForm.approver || adminSession?.user?.username || "admin").trim();
      if (!looksLikeUuid(incidentId)) {
        throw new Error("Select a valid incident first from the approval queue.");
      }
      if (!approver) {
        throw new Error("Approver is required.");
      }
      const recommendationIdCandidate = String(
        (cockpitIncidentId ? selectedAlertRecommendationId : "")
        || approvalForm.recommendation_id
        || selectedApprovalRecommendationId
        || approvalRecommendationFromPayload(approvalIncidentContext.payload)
        || ""
      ).trim();
      const recommendationId = await resolveRecommendationIdForIncident(incidentId, recommendationIdCandidate);
      const response = await executeApprovalAction({
        incidentId,
        recommendationId,
        action: approvalForm.action,
        approver,
        channel: approvalForm.channel,
        comment: approvalForm.comment,
        modifiedAction: approvalForm.modified_action,
      });
      let remediationResponse = null;
      let actionStatus = approvalForm.action === "reject" ? "failed" : "remediating";
      if (approvalForm.action === "approve" || approvalForm.action === "modify") {
        const editedPlan = buildEditedRemediationPlan();
        const hasPlan = editedPlan.commands.length || editedPlan.scripts.length || editedPlan.queries.length;
        if (hasPlan) {
          setRemediationExecutionState({ loading: true, result: null, error: "" });
          const executionPayload = buildRemediationExecutionPayload({
            incidentId,
            recommendationId,
            approver,
            action: approvalForm.action,
            comment: approvalForm.comment,
            editedPlan,
          });
          remediationResponse = await postRemediationExecution(executionPayload, incidentId, approvalForm.comment);
          const remediationStatus = String(unwrap(remediationResponse)?.status || "").toLowerCase();
          actionStatus = remediationStatus === "succeeded"
            ? "validating"
            : remediationStatus === "failed" || remediationStatus === "skipped"
              ? "failed"
              : "remediating";
        } else {
          setRemediationExecutionState({
            loading: false,
            result: null,
            error: "Approval was recorded, but no remediation commands, script, or validation query were available to execute.",
          });
        }
      }
      applyApprovalResolutionToUi(incidentId, actionStatus, approvalForm.comment);
      setApprovalState({ loading: false, result: remediationResponse ? { approval: response, remediation: remediationResponse } : response, error: "" });
      loadApprovalIncidentContext(incidentId, { force: true });
      await refreshApprovalDrivenViews(incidentId);
    } catch (error) {
      const raw = String(error?.message || "");
      const concise = raw.includes("HTTP 422")
        ? "Approval was rejected because this incident has no linked remediation recommendation yet. Re-run the incident workflow to generate one."
        : raw;
      setApprovalState({ loading: false, result: null, error: concise });
      setRemediationExecutionState((current) => current.loading ? { loading: false, result: null, error: concise } : current);
    }
  }

  async function executeApprovedRemediationPlan() {
    const incidentId = String(approvalForm.incident_id || selectedIncidentId || selectedApprovalIncidentId || "").trim();
    const recommendationIdCandidate = String(
      approvalForm.recommendation_id
      || selectedApprovalRecommendationId
      || approvalRecommendationFromPayload(approvalIncidentContext.payload)
      || selectedAlertWorkflow?.recommendation?.id
      || ""
    ).trim();
    const approver = String(approvalForm.approver || adminSession?.user?.username || "admin").trim();
    const approvalStatus = normalizeApprovalStatus(selectedExecutionPlan.approvalStatus || approvalForm.action);
    const editedPlan = buildEditedRemediationPlan();
    const hasPlan = editedPlan.commands.length || editedPlan.scripts.length || editedPlan.queries.length;

    setRemediationExecutionState({ loading: true, result: null, error: "" });
    try {
      if (!looksLikeUuid(incidentId)) {
        throw new Error("Remediation execution requires a valid incident_id. Select an alert with an incident or sync approval context.");
      }
      const recommendationId = await resolveRecommendationIdForIncident(incidentId, recommendationIdCandidate);
      if (!looksLikeUuid(recommendationId)) {
        throw new Error("Remediation execution requires a valid recommendation_id from the approved incident.");
      }
      if (!hasPlan) {
        throw new Error("Add at least one command, script, or validation query before executing.");
      }
      if (!["approved", "modified"].includes(approvalStatus) && approvalForm.action !== "approve" && approvalForm.action !== "modify") {
        throw new Error("Approve or modify the remediation first, then execute the approved plan.");
      }

      if (!["approved", "modified"].includes(approvalStatus) && (approvalForm.action === "approve" || approvalForm.action === "modify")) {
        const approvalResponse = await executeApprovalAction({
          incidentId,
          recommendationId,
          action: approvalForm.action,
          approver,
          channel: approvalForm.channel,
          comment: approvalForm.comment,
          modifiedAction: approvalForm.modified_action,
        });
        setApprovalState({ loading: false, result: approvalResponse, error: "" });
      }

      const payload = buildRemediationExecutionPayload({
        incidentId,
        recommendationId,
        action: approvalForm.action,
        approver,
        comment: String(approvalForm.comment || remediationPlanEditor.notes || "approved remediation execution").trim(),
        editedPlan,
      });
      await postRemediationExecution(payload, incidentId, approvalForm.comment);
    } catch (error) {
      setRemediationExecutionState({ loading: false, result: null, error: String(error?.message || error) });
    }
  }

  const tabs = [
    { id: "home", label: "Dashboard" },
    { id: "stream", label: "Alert Ingestion Stream" },
    { id: "copilot", label: "Copilot Studio" },
    { id: "executive", label: "Executive Dashboard" },
    { id: "admin", label: "Admin Center" },
    { id: "trace", label: "Agent Flow" },
    { id: "safety", label: "Gateway Safety" },
    { id: "rag", label: "Message Bus" },
    { id: "closed", label: "Closed Tickets" },
    { id: "summary", label: "Incident Metadata Explorer" },
    { id: "approval", label: "Approval Queue (Legacy)" },
  ];

  const sidebarSections = [
    { id: "home", icon: "DB", shortLabel: "Dashboard", label: "Dashboard", tone: "ops" },
    { id: "stream", icon: "LS", shortLabel: "Live Stream", label: "Alert Ingestion Stream", tone: "meta" },
    { id: "approval", icon: "AL", shortLabel: "Approval", label: "Human Approval", tone: "risk" },
    { id: "executive", icon: "EX", shortLabel: "Executive", label: "Executive Dashboard", tone: "meta" },
    { id: "admin", icon: "AD", shortLabel: "Admin", label: "Admin Center", tone: "bus" },
  ];

  const currentRole = useMemo(() => normalizeRoleName(adminSession?.user?.role_name), [adminSession?.user?.role_name]);
  const projectOnboardingRows = useMemo(
    () => (onboardingState.rows || []).filter((row) => String(row?.provider_name || "").trim().toLowerCase() === "project"),
    [onboardingState.rows],
  );
  const onboardingProjectRowOptions = useMemo(() => {
    const names = new Set();
    (onboardingState.rows || []).forEach((row) => {
      const name = extractOnboardingProjectName(row);
      if (name) {
        names.add(name);
      }
    });
    return Array.from(names).sort((a, b) => a.localeCompare(b));
  }, [onboardingState.rows]);
  const monitoringProjectOptions = useMemo(() => {
    const names = new Set();
    (monitoringApps.rows || []).forEach((row) => {
      const name = String(row?.name || "").trim();
      if (name) {
        names.add(name);
      }
    });
    return Array.from(names).sort((a, b) => a.localeCompare(b));
  }, [monitoringApps.rows]);
  const onboardingProjectOptions = useMemo(() => {
    const names = new Set();
    onboardingProjectRowOptions.forEach((name) => names.add(name));
    monitoringProjectOptions.forEach((name) => names.add(name));
    return Array.from(names).sort((a, b) => a.localeCompare(b));
  }, [onboardingProjectRowOptions, monitoringProjectOptions]);
  const ruleOnboardingRows = useMemo(
    () => (onboardingState.rows || []).filter((row) => {
      const provider = String(row?.provider_name || "").trim().toLowerCase();
      return provider === "existing_rule_sync" || provider === "new_rule_onboarding";
    }),
    [onboardingState.rows],
  );
  const allowedTabs = useMemo(() => ROLE_ALLOWED_TABS[currentRole] || ["home"], [currentRole]);
  const visibleSidebarSections = useMemo(
    () => sidebarSections.filter((tab) => {
      if (!allowedTabs.includes(tab.id)) {
        return false;
      }
      if (tab.id === "approval" && !APPROVAL_NAV_PRIMARY_ROLES.has(currentRole)) {
        return false;
      }
      return true;
    }),
    [sidebarSections, allowedTabs, currentRole],
  );
  const ingestionStreamRows = useMemo(
    () => (Array.isArray(landingPadRecent.rows) ? landingPadRecent.rows : [])
      .map((row, index) => {
        const mapped = mapLandingPadRowToAlertStreamRow(row, index);
        return {
          ...mapped,
          file: row?.file || "-",
          path: row?.path || "",
          error: row?.error || "",
          source_channel: normalizeAlertChannel(mapped),
        };
      })
      .sort((left, right) => alertTimeMs(right) - alertTimeMs(left)),
    [landingPadRecent.rows],
  );
  const ingestionStreamCounts = useMemo(() => {
    const counts = { all: ingestionStreamRows.length, email: 0, log: 0, prometheus: 0, telemetry: 0, ticket: 0, failed: 0 };
    ingestionStreamRows.forEach((row) => {
      const channel = String(row?.source_channel || "prometheus");
      counts[channel] = Number(counts[channel] || 0) + 1;
      if (String(row?.status || "").toLowerCase() === "failed" || row?.error) {
        counts.failed += 1;
      }
    });
    return counts;
  }, [ingestionStreamRows]);
  const visibleIngestionStreamRows = useMemo(() => {
    const query = String(ingestionStreamQuery || "").trim().toLowerCase();
    return ingestionStreamRows.filter((row) => {
      const failed = String(row?.status || "").toLowerCase() === "failed" || Boolean(row?.error);
      if (ingestionStreamChannel === "failed" && !failed) {
        return false;
      }
      if (!["all", "failed"].includes(ingestionStreamChannel) && row.source_channel !== ingestionStreamChannel) {
        return false;
      }
      if (!query) {
        return true;
      }
      return [
        row.name,
        row.service,
        row.application,
        row.project_name,
        row.source,
        row.file,
        row.status,
        row.error,
      ].map((value) => String(value || "").toLowerCase()).join(" ").includes(query);
    });
  }, [ingestionStreamRows, ingestionStreamChannel, ingestionStreamQuery]);
  const isAuthenticated = Boolean(String(adminSession.accessToken || "").trim());
  const isAdministrator = currentRole === "administrator";
  const canUseApprovalActions = allowedTabs.includes("approval");
  const canManageSeverityOverride = ["administrator", "l2_engineer", "l3_engineer", "p2", "p3"].includes(currentRole);
  const canProvideAlertDocuments = DOCUMENT_PROVIDER_ROLES.has(currentRole);
  const onboardingSourceDocRows = useMemo(
    () => (Array.isArray(onboardingSourceDocs.rows) ? onboardingSourceDocs.rows : []).filter((row) => {
      const text = String(row?.text || "").trim();
      const warning = String(row?.warning || "").trim();
      return Boolean(text) && !warning;
    }),
    [onboardingSourceDocs.rows],
  );
  const onboardingSourceDocCount = onboardingSourceDocRows.length;
  const severityOverrideByKey = useMemo(() => {
    const map = new Map();
    (alertSeverityOverrides.rows || []).forEach((row) => {
      const key = severityOverrideKey(row?.name, row?.service, row?.environment);
      if (key) {
        map.set(key, row);
      }
    });
    return map;
  }, [alertSeverityOverrides.rows]);
  const selectedAlertActionContext = useMemo(() => {
    if (!selectedAlertRow) {
      return null;
    }
    const status = selectedCanonicalIncidentStatus;
    const alertName = String(selectedAlertRow?.name || selectedAlertRow?.alert_name || "").trim();
    const service = String(selectedAlertRow?.service || "").trim();
    const environment = String(selectedAlertRow?.environment || "").trim();
    const overrideKey = severityOverrideKey(alertName, service, environment);
    const overrideRow = severityOverrideByKey.get(overrideKey);
    return {
      status,
      alertName,
      overrideKey,
      overrideRow,
      documentAvailable: hasAlertDocuments(selectedAlertRow),
      alertClosed: isApprovalResolvedStatus(status),
      draftSeverity: String(
        alertSeverityDrafts[overrideKey]
          || overrideRow?.severity
          || String(selectedAlertRow?.severity || "warning").toLowerCase()
      ).toLowerCase(),
      overrideSaving: alertSeverityOverrides.savingKey === overrideKey,
    };
  }, [selectedAlertRow, selectedCanonicalIncidentStatus, severityOverrideByKey, alertSeverityDrafts, alertSeverityOverrides.savingKey]);
  const selectedAlertRuleSummary = useMemo(
    () => summarizeAlertRuleContext(selectedAlertRow, selectedAlertWorkflow),
    [selectedAlertRow, selectedAlertWorkflow],
  );
  const onboardingValidationErrors = useMemo(() => {
    const errors = [];
    if (!String(onboardingForm.name || "").trim()) {
      errors.push("Project name is required.");
    }
    if (!String(onboardingForm.owner_team || "").trim()) {
      errors.push("Owner team is required.");
    }
    if (!String(onboardingForm.region || "").trim()) {
      errors.push("Region is required.");
    }
    if (String(onboardingForm.deployment_mode || "").trim() === "azure_cloud") {
      if (!String(onboardingForm.azure_subscription_id || "").trim()) {
        errors.push("Azure Subscription ID is required for Azure Cloud deployment.");
      }
      if (!String(onboardingForm.azure_service_bus_namespace || "").trim()) {
        errors.push("Azure Service Bus Namespace is required for Azure Cloud deployment.");
      }
      if (!String(onboardingForm.azure_service_bus_topic || "").trim()) {
        errors.push("Azure Service Bus Topic is required for Azure Cloud deployment.");
      }
      if (!String(onboardingForm.azure_service_bus_subscription || "").trim()) {
        errors.push("Azure Service Bus Subscription is required for Azure Cloud deployment.");
      }
    }
    const isSetupMonitoringPath = String(onboardingForm.onboarding_path || "setup_monitoring").trim() === "setup_monitoring";
    const derivedRequirementCount = (Array.isArray(onboardingSourceDocs.rows) ? onboardingSourceDocs.rows : []).reduce(
      (count, row) => count + (Array.isArray(row?.derived_requirements) ? row.derived_requirements.length : 0),
      0,
    );
    if (isSetupMonitoringPath && !String(onboardingForm.rule_onboarding_plain_language || "").trim() && derivedRequirementCount === 0) {
      errors.push("Add plain-English rule intent or upload one Service Knowledge file that produces derived requirements.");
    }
    if (isSetupMonitoringPath && !String(onboardingForm.monitoring_url || "").trim()) {
      errors.push("Prometheus endpoint URL is required for Configure Prometheus Monitoring path.");
    }
    return errors;
  }, [
    onboardingForm.name,
    onboardingForm.owner_team,
    onboardingForm.region,
    onboardingForm.deployment_mode,
    onboardingForm.azure_subscription_id,
    onboardingForm.azure_service_bus_namespace,
    onboardingForm.azure_service_bus_topic,
    onboardingForm.azure_service_bus_subscription,
    onboardingForm.onboarding_path,
    onboardingForm.monitoring_url,
    onboardingForm.rule_onboarding_plain_language,
    onboardingSourceDocs.rows,
    onboardingSourceDocCount,
  ]);
  const onboardingAdvisory = useMemo(() => {
    const onboardingPath = String(onboardingForm.onboarding_path || "setup_monitoring").trim();
    if (onboardingPath === "existing_monitoring") {
      return "Existing monitoring path: upload one Service Knowledge file, save project, then send alerts to /alerts/alertmanager to trigger workflow.";
    }
    if (String(onboardingForm.deployment_mode || "").trim() !== "on_prem") {
      return "";
    }
    if (String(onboardingForm.monitoring_url || "").trim()) {
      return "";
    }
    return "Tool endpoint URL is optional now, but recommended for connectivity and rule simulation quality.";
  }, [onboardingForm.deployment_mode, onboardingForm.monitoring_url, onboardingForm.onboarding_path]);
  const onboardingLandingPadDetails = useMemo(() => {
    const summary = onboardingLandingPadSummary && typeof onboardingLandingPadSummary === "object" ? onboardingLandingPadSummary : {};
    const landingPadPath = String(summary?.landing_pad_endpoint || "/alerts/alertmanager").trim() || "/alerts/alertmanager";
    const selectedTool = String(summary?.selected_monitoring_tool || onboardingForm.monitoring_tool || "prometheus").trim().toLowerCase();
    const configuredEndpoint = String(summary?.configured_monitoring_endpoint || onboardingForm.monitoring_url || "").trim();
    const projectName = String(summary?.project_name || onboardingForm.name || "").trim() || "<project-name>";
    const browserOrigin = typeof window !== "undefined" && window?.location?.origin ? window.location.origin : "http://localhost:8501";
    const onboardingPath = String(onboardingForm.onboarding_path || "setup_monitoring").trim().toLowerCase();
    const routeMessage = String(summary?.message || "").trim() || "Send alerts from your monitoring platform to this landing pad endpoint to trigger workflow execution.";

    const samplePayload = {
      receiver: "kaiops",
      status: "firing",
      alerts: [
        {
          status: "firing",
          labels: {
            alertname: `${projectName}-high-latency`,
            severity: "critical",
            service: projectName,
          },
          annotations: {
            summary: "P95 latency exceeded threshold",
            description: "Checkout latency above 2s for 5 minutes",
          },
          startsAt: "2026-01-01T00:00:00Z",
        },
      ],
    };

    return {
      onboardingPath,
      routeMessage,
      selectedTool,
      configuredEndpoint: configuredEndpoint || "Not set",
      externalIngestionEndpoint: `${browserOrigin}/api-gateway${landingPadPath}`,
      internalIngestionEndpoint: `http://monitoring-adapter:8000${landingPadPath}`,
      method: "POST",
      contentType: "application/json",
      traceHeader: "x-trace-id (optional)",
      samplePayload: JSON.stringify(samplePayload, null, 2),
    };
  }, [onboardingLandingPadSummary, onboardingForm.monitoring_tool, onboardingForm.monitoring_url, onboardingForm.name, onboardingForm.onboarding_path]);
  const onboardingHasPendingDocumentApproval = useMemo(
    () => onboardingGeneratedDocs.length > 0 && !onboardingDocApprovalState.approved,
    [onboardingGeneratedDocs.length, onboardingDocApprovalState.approved],
  );
  const onboardingDocumentSummary = useMemo(
    () => ({
      total: onboardingGeneratedDocs.length,
      approved: onboardingDocApprovalState.approved,
    }),
    [onboardingGeneratedDocs.length, onboardingDocApprovalState.approved],
  );
  const onboardingWizardSteps = useMemo(() => {
    const docsUploaded = onboardingSourceDocCount > 0;
    const requirementsDerived = onboardingDerivedRequirements.length > 0
      || String(onboardingForm.rule_onboarding_plain_language || "").trim().length > 0;
    const ruleGenerated = Boolean(
      onboardingRuleRunState?.result
      || onboardingRuleLookup?.result
      || String(onboardingRuleLookup?.workflow_id || "").trim(),
    );
    const docsApproved = Boolean(onboardingDocApprovalState.approved);
    const metadataStored = String(onboardingState.success || "").toLowerCase().includes("saved")
      || projectOnboardingRows.some((row) => {
        const name = String(row?.project_name || "").trim();
        return name && name === String(selectedOnboardingProject || onboardingForm.name || "").trim();
      });

    return [
      { id: "docs_uploaded", label: "Docs Uploaded", complete: docsUploaded },
      { id: "requirements", label: "Requirements Derived", complete: requirementsDerived },
      { id: "rules", label: "Rules Generated", complete: ruleGenerated },
      { id: "docs_approved", label: "Docs Approved", complete: docsApproved },
      { id: "metadata", label: "Metadata Stored", complete: metadataStored },
    ];
  }, [
    onboardingSourceDocCount,
    onboardingDerivedRequirements.length,
    onboardingForm.rule_onboarding_plain_language,
    onboardingRuleRunState?.result,
    onboardingRuleLookup?.result,
    onboardingRuleLookup?.workflow_id,
    onboardingDocApprovalState.approved,
    onboardingState.success,
    projectOnboardingRows,
    selectedOnboardingProject,
    onboardingForm.name,
  ]);
  const onboardingGeneratedRuleRows = useMemo(() => {
    const primary = normalizeGeneratedRuleRows(onboardingRuleRunState?.result);
    if (primary.length) {
      return primary;
    }
    return normalizeGeneratedRuleRows(onboardingRuleLookup?.result);
  }, [onboardingRuleRunState?.result, onboardingRuleLookup?.result]);
  const onboardingRulePromptLines = useMemo(
    () => String(onboardingForm.rule_onboarding_plain_language || "")
      .split(/\r?\n/)
      .map(cleanRuleIntentLine)
      .filter(Boolean),
    [onboardingForm.rule_onboarding_plain_language],
  );
  const onboardingPrometheusRulePreview = useMemo(() => buildPrometheusRulePreview({
    projectName: onboardingForm.name || selectedOnboardingProject,
    serviceName: onboardingForm.name || selectedOnboardingProject || "kaiops-service",
    environment: onboardingForm.environment || "prod",
    requirements: onboardingRulePromptLines,
  }), [
    onboardingForm.name,
    selectedOnboardingProject,
    onboardingForm.environment,
    onboardingRulePromptLines,
  ]);
  const onboardingRulePromptVisible = onboardingSourceDocCount > 0 || onboardingRulePromptLines.length > 0 || onboardingGeneratedRuleRows.length > 0;
  const onboardingMetadataRows = useMemo(() => {
    const currentProject = String(selectedOnboardingProject || onboardingForm.name || "").trim();
    const rows = Array.isArray(onboardingState.rows) ? onboardingState.rows : [];
    return rows
      .filter((row) => {
        const projectName = String(row?.project_name || "").trim();
        return currentProject ? projectName === currentProject : true;
      })
      .map((row, index) => ({
        id: `${String(row?.provider_name || "provider")}-${index}`,
        provider: String(row?.provider_name || "-").trim(),
        project: String(row?.project_name || "-").trim(),
        status: String(row?.test_status || row?.status || "-").trim(),
        updated_at: String(row?.updated_at || row?.created_at || "-").trim(),
      }));
  }, [onboardingState.rows, selectedOnboardingProject, onboardingForm.name]);
  const onboardingReviewGate = useMemo(() => {
    const needsRules = onboardingGeneratedRuleRows.length > 0;
    const needsDocs = onboardingGeneratedDocs.length > 0;
    const needsMetadata = onboardingMetadataRows.length > 0;
    const rulesOk = !needsRules || onboardingReviewAck.rules;
    const docsOk = !needsDocs || onboardingReviewAck.docs;
    const metadataOk = !needsMetadata || onboardingReviewAck.metadata;
    return {
      needsRules,
      needsDocs,
      needsMetadata,
      allReviewed: rulesOk && docsOk && metadataOk,
    };
  }, [
    onboardingGeneratedRuleRows.length,
    onboardingGeneratedDocs.length,
    onboardingMetadataRows.length,
    onboardingReviewAck.rules,
    onboardingReviewAck.docs,
    onboardingReviewAck.metadata,
  ]);
  const onboardingNextAction = useMemo(() => {
    const onboardingPath = String(onboardingForm.onboarding_path || "setup_monitoring").trim();
    if (onboardingState.loading) {
      return "Saving setup and generating onboarding artifacts...";
    }
    if (onboardingHasPendingDocumentApproval) {
      return "Review generated documents below, then click Approve Documents.";
    }
    if (onboardingDocumentSummary.approved) {
      return "Documents approved. You can continue with another update or proceed to advanced workflow management.";
    }
    return onboardingPath === "setup_monitoring"
      ? "Step 1: save monitoring setup. Step 2: add Service Knowledge and generate rules."
      : "Step 1: save monitoring setup and landing pad. Step 2: add Service Knowledge and generate documents.";
  }, [
    onboardingState.loading,
    onboardingHasPendingDocumentApproval,
    onboardingDocumentSummary.approved,
    onboardingForm.onboarding_path,
  ]);

  const adminWorkspaceCaptions = useMemo(() => ({
    users: "Manage users, roles, and credentials.",
    monitoring: "Setup monitoring foundations, landing pad routing, and rule/doc generation.",
    project: "Two-step setup: connect monitoring first, then add documents and rules.",
    alerts: "Alert knowledge onboarding and bulk document ingestion.",
  }), []);
  const adminJourneyStep = useMemo(() => {
    if (adminWorkspace === "users") {
      return "access";
    }
    if (adminWorkspace === "alerts" || (adminWorkspace === "project" && projectSetupStep === "knowledge")) {
      return "knowledge";
    }
    return "setup";
  }, [adminWorkspace, projectSetupStep]);
  const adminJourneyCards = useMemo(() => {
    const setupSaved = Boolean(String(onboardingState.success || "").trim()) && !onboardingState.loading && !onboardingState.error;
    const setupComplete = Boolean(onboardingDocumentSummary.approved) || setupSaved || onboardingWorkflowSteps.length > 0;
    const knowledgeComplete = Boolean(alertOnboardingState.result);
    const setupTone = onboardingState.error
      ? "error"
      : onboardingHasPendingDocumentApproval
          ? "warning"
          : setupComplete
            ? "success"
            : "info";
    const knowledgeHasError = Boolean(alertOnboardingState.error);
    const knowledgeTone = knowledgeHasError
      ? "error"
      : knowledgeComplete
        ? "success"
        : "info";
    return [
      {
        id: "access",
        title: "1. Access",
        hint: "Users, roles, session security",
        status: adminUsers.loading
          ? "Loading users and roles..."
          : adminUsers.error
            ? "Unable to load users"
            : adminUsers.rows.length
              ? `${adminUsers.rows.length} users loaded`
              : "No users returned yet. Click Refresh.",
        complete: Boolean(adminUsers.rows.length),
        tone: adminUsers.error ? "error" : adminUsers.rows.length ? "success" : adminUsers.loading ? "warning" : "info",
        cta: "Open access controls",
      },
      {
        id: "setup",
        title: "2. Guided Setup",
        hint: "Prompt, auto-complete, score, validate",
        status: onboardingHasPendingDocumentApproval
          ? "Setup saved. Review generated documents to finalize."
          : onboardingDocumentSummary.approved
            ? "Project docs approved"
            : (setupSaved || onboardingWorkflowSteps.length > 0)
              ? "Project setup saved and synced."
              : onboardingNextAction,
        complete: setupComplete,
        tone: setupTone,
        cta: onboardingHasPendingDocumentApproval
          ? "Review generated artifacts"
          : setupComplete
            ? "Open workflow status"
            : "Continue guided setup",
      },
      {
        id: "knowledge",
        title: "3. Knowledge",
        hint: "Alert docs onboarding",
        status: knowledgeComplete ? "Knowledge artifacts created" : "Pending knowledge curation",
        complete: knowledgeComplete,
        tone: knowledgeTone,
        cta: knowledgeComplete ? "Review stored knowledge" : "Open knowledge onboarding",
      },
    ];
  }, [
    adminUsers.rows.length,
    adminUsers.loading,
    adminUsers.error,
    onboardingDocumentSummary.approved,
    onboardingNextAction,
    onboardingState.error,
    onboardingState.loading,
    onboardingState.success,
    onboardingHasPendingDocumentApproval,
    onboardingWorkflowSteps.length,
    alertOnboardingState.result,
    alertOnboardingState.error,
  ]);
  const projectStepCards = useMemo(() => {
    const setupSaved = Boolean(String(onboardingState.success || "").trim()) && !onboardingState.loading && !onboardingState.error;
    const monitoringDone = Boolean(String(onboardingForm.name || "").trim())
      && Boolean(String(onboardingForm.owner_team || "").trim())
      && Boolean(String(onboardingForm.region || "").trim());
    const docsRulesDone = Boolean(onboardingSourceDocCount > 0 || onboardingRulePromptLines.length > 0 || onboardingGeneratedDocs.length > 0 || setupSaved);
    return [
      { id: "docs_rules", label: "1. Guided Setup", hint: "Describe, auto-complete, score, approve", complete: docsRulesDone },
      { id: "setup", label: "2. Connection Setup", hint: "Monitoring tool, endpoint, landing pad", complete: monitoringDone },
    ];
  }, [
    onboardingForm.name,
    onboardingForm.owner_team,
    onboardingForm.region,
    onboardingSourceDocCount,
    onboardingRulePromptLines.length,
    onboardingState.success,
    onboardingState.loading,
    onboardingState.error,
    onboardingGeneratedDocs.length,
  ]);
  const showProjectStep = (stepId) => adminWorkspace !== "project" || projectSetupShowAll || projectSetupStep === stepId;
  const navigateAdminJourney = (stepId) => {
    if (stepId === "access") {
      setAdminWorkspace("users");
      return;
    }
    if (stepId === "knowledge") {
      setAdminWorkspace("alerts");
      setProjectSetupShowAll(false);
      setAlertKnowledgeView("onboarding");
      return;
    }
    setAdminWorkspace("project");
    setProjectSetupShowAll(false);
  };
  const triggerAdminJourneyCta = (stepId) => {
    if (stepId === "setup") {
      setAdminWorkspace("project");
      setProjectSetupShowAll(false);
      if (onboardingHasPendingDocumentApproval) {
        setProjectSetupStep("review");
        return;
      }
      if (onboardingDocumentSummary.approved) {
        setProjectSetupStep("status");
        return;
      }
      setProjectSetupStep("docs_rules");
      return;
    }
    navigateAdminJourney(stepId);
  };

  useEffect(() => {
    if (adminWorkspace !== "project" || projectSetupShowAll) {
      return;
    }
    if (projectSetupStep !== "docs_rules") {
      return;
    }
    if (onboardingState.loading || onboardingState.error) {
      return;
    }
    const success = String(onboardingState.success || "").trim();
    if (!success) {
      return;
    }
    if (success.toLowerCase().includes("documents approved")) {
      return;
    }
    if (onboardingGeneratedDocs.length > 0) {
      setProjectSetupStep("review");
      return;
    }
    if (onboardingSourceDocCount === 0) {
      setProjectSetupStep("docs_rules");
      setAlertKnowledgeView("onboarding");
      alertKnowledgeRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
      return;
    }
    setProjectSetupStep("status");
  }, [
    adminWorkspace,
    projectSetupShowAll,
    projectSetupStep,
    onboardingState.loading,
    onboardingState.error,
    onboardingState.success,
    onboardingGeneratedDocs.length,
    onboardingSourceDocCount,
  ]);

  useEffect(() => {
    if (adminWorkspace !== "project" || projectSetupShowAll) {
      return;
    }
    if (projectSetupStep !== "review") {
      return;
    }
    if (onboardingDocApprovalState.approved) {
      setProjectSetupStep("status");
    }
  }, [adminWorkspace, projectSetupShowAll, projectSetupStep, onboardingDocApprovalState.approved]);

  useEffect(() => {
    if (!isAuthenticated || (adminWorkspace !== "monitoring" && adminWorkspace !== "project")) {
      return;
    }
    loadMonitoringApplications();
  }, [isAuthenticated, adminWorkspace]);

  useEffect(() => {
    if (!selectedMonitoringAppId) {
      return;
    }
    loadMonitoringApplicationDetails(selectedMonitoringAppId);
    loadRagDocs();
  }, [selectedMonitoringAppId]);

  useEffect(() => {
    if (!selectedMonitoringAppId || adminWorkspace !== "monitoring") {
      return;
    }
    if (typeof window === "undefined") {
      return;
    }
    window.requestAnimationFrame(() => {
      monitoringInspectRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
    });
  }, [selectedMonitoringAppId, adminWorkspace]);

  useEffect(() => {
    if (activeTab !== "admin" || adminWorkspace !== "alerts") {
      return;
    }
    if (typeof window === "undefined") {
      return;
    }
    window.requestAnimationFrame(() => {
      alertKnowledgeRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
    });
  }, [activeTab, adminWorkspace]);

  useEffect(() => {
    if (onboardingProjectMode === "new" || selectedOnboardingProject || !onboardingProjectOptions.length) {
      return;
    }
    const firstProjectName = onboardingProjectRowOptions[0] || onboardingProjectOptions[0];
    const firstProjectRow = (onboardingState.rows || []).find((row) => extractOnboardingProjectName(row) === firstProjectName);
    if (firstProjectRow) {
      applyProjectOnboardingRow(firstProjectRow);
      return;
    }
    setSelectedOnboardingProject(firstProjectName);
    setOnboardingForm((curr) => ({
      ...curr,
      name: firstProjectName,
      assignment_project: firstProjectName,
    }));
  }, [onboardingProjectMode, selectedOnboardingProject, onboardingProjectOptions, onboardingProjectRowOptions, onboardingState.rows]);

  useEffect(() => {
    if (!isAuthenticated) {
      return;
    }
    if (allowedTabs.includes(activeTab)) {
      return;
    }
    setActiveTab(allowedTabs[0] || "approval");
  }, [isAuthenticated, allowedTabs, activeTab]);

  function openSection(tabId) {
    if (!allowedTabs.includes(tabId)) {
      return;
    }
    setActiveTab(tabId);
  }

  function openCopilotWorkspace(workspace) {
    if (workspace === "users" && !isAdministrator) {
      return;
    }
    if (workspace === "users") {
      setAdminWorkspace("users");
    } else if (workspace === "monitoring") {
      setAdminWorkspace("project");
    } else if (workspace === "project") {
      setAdminWorkspace("project");
    } else if (workspace === "alerts") {
      setAdminWorkspace("alerts");
      setAlertKnowledgeView("onboarding");
    }
    setActiveTab("admin");
  }

  const reportConfig = useMemo(() => {
    const config = {
      home: {
        title: "Dashboard",
        caption: "Operational dashboard with alert stream and incident overview.",
        metrics: [
          ["Recent Alerts", monitorScopedAlerts.length],
          ["Flows", flows.rows.length],
          ["Gateway Events", gatewayRecent.rows.length],
          ["Health", health.ok ? "OK" : "CHECK"],
        ],
        refresh: refreshAll,
      },
      copilot: {
        title: "Copilot Studio",
        caption: "Guided workspace for project onboarding, alert docs, and user management.",
        metrics: [
          ["Projects", onboardingState.rows.length],
          ["Alert Docs", ragDocs.rows.length],
          ["Users", adminUsers.rows.length],
          ["Ready", health.ok ? "Yes" : "Check"],
        ],
        refresh: refreshAll,
      },
      executive: {
        title: "Executive Dashboard",
        caption: "Leadership KPIs for reliability posture, risk, and closure outcomes.",
        metrics: [
          ["Open Alerts", monitorScopedAlerts.length],
          [
            "Critical Open",
            monitorScopedAlerts.filter((row) => String(row?.severity || "").toLowerCase() === "critical").length,
          ],
          ["Closed Incidents", closedIncidents.rows.length],
          ["Health Restored", closedIncidents.rows.filter((row) => row?.health_restored === true).length],
          ["SLA At Risk", executiveInsights.slaAtRisk],
          ["Avg Approval Wait", `${executiveInsights.avgApprovalWaitMinutes.toFixed(1)} min`],
          ["Auto Remediation Rate", `${executiveInsights.automationRate.toFixed(1)}%`],
          ["LLM Cost (USD)", executiveMetrics.finopsCost.toFixed(6)],
        ],
        refresh: refreshAll,
      },
      admin: {
        title: "Admin Center",
        caption: "Administrative controls, system health, and approval operations.",
        metrics: [
          ["Pending Approvals", pendingApprovals.length],
          ["Gateway", health.ok ? "Healthy" : "Check"],
          ["Metadata Rows", incidentMetadata.rows.length],
          ["Monitoring Target", selectedMonitorScopeLabel],
        ],
        refresh: async () => {
          await Promise.all([checkHealth(), loadIncidentMetadata(), loadGatewaySummary(), loadGatewayRecent()]);
        },
      },
      summary: {
        title: "Incident Metadata Explorer",
        caption: "Filter the incident projection layer across policy, transport, and operational dimensions.",
        metrics: [
          ["Incidents", incidentMetadata.rows.length],
          ["Human Approval", pendingApprovals.length],
          ["Closed", closedIncidents.rows.length],
          ["Monitoring", selectedMonitorScopeLabel],
        ],
        refresh: loadIncidentMetadata,
      },
      approval: {
        title: "Human Approval & Alerts",
        caption: "Pending approvals, live incident feed, and quick guidance workspace.",
        metrics: [
          ["Recent Alerts", monitorScopedAlerts.length],
          ["Pending", pendingApprovals.length],
          ["Guidance Matches", guidanceState.rows.length],
          ["Last Incident", latestIncidentId || "-"],
        ],
        refresh: async () => {
          await Promise.all([loadIncidentMetadata(), loadGatewayRecent(), loadGatewaySummary()]);
        },
      },
      trace: {
        title: "Agent Flow",
        caption: "Agent execution timeline, decisions, outputs, and handoffs.",
        metrics: [
          ["Workflow Events", workflowEventRows.length],
          ["Gateway Events", gatewayRecent.rows.length],
          ["Latest Incident", latestIncidentId || "-"],
          ["Latest Flow", selectedFlow || "-"],
        ],
        refresh: async () => {
          await Promise.all([loadGatewayRecent(), loadGatewaySummary()]);
        },
      },
      finops: {
        title: "LLM FinOps",
        caption: "Token usage, provider costs, and model-level breakdown.",
        metrics: [
          ["LLM Calls", allUsageRows.length],
          [
            "Total Cost (USD)",
            allUsageRows
              .reduce((sum, row) => sum + Number(row?.total_cost_usd || 0), 0)
              .toFixed(6),
          ],
          ["Providers", new Set(allUsageRows.map((row) => row.provider).filter(Boolean)).size],
          ["Models", new Set(allUsageRows.map((row) => row.model).filter(Boolean)).size],
        ],
        refresh: async () => {
          await Promise.all([loadIncidentMetadata(), loadGatewaySummary(), loadGatewayRecent(), loadClosedIncidents(), loadRecentAlerts()]);
        },
      },
      rag: {
        title: "Message Bus",
        caption: "Configured routing plus latest observed published versus consumed topics.",
        metrics: [
          ["Published Topics", messageBusActual.published.length],
          ["Consumed Topics", messageBusActual.consumed.length],
          ["Observed Provider", observedRouting?.message_bus_provider || "N/A"],
          ["Workflow", observedRouting?.workflow || "N/A"],
        ],
        refresh: () => runWorkflow(selectedFlow),
      },
      safety: {
        title: "Gateway Safety",
        caption: "Review gateway decision, policy reasons, and safety metrics before closure.",
        metrics: [
          ["Events", gatewaySummary.data.total_events || 0],
          ["Allowed", gatewaySummary.data.allowed || 0],
          ["Review", gatewaySummary.data.review || 0],
          ["Blocked", gatewaySummary.data.blocked || 0],
        ],
        refresh: async () => {
          await Promise.all([loadGatewaySummary(), loadGatewayRecent()]);
        },
      },
      closed: {
        title: "Closed Tickets",
        caption: "Closed tickets plus current closure report details.",
        metrics: [
          ["Closed", closedIncidents.rows.length],
          [
            "Health Restored",
            closedIncidents.rows.filter((row) => row?.health_restored === true).length,
          ],
          ["Monitoring", selectedMonitorScopeLabel],
          ["Gateway", health.ok ? "OK" : "CHECK"],
        ],
        refresh: loadClosedIncidents,
      },
    };

    return config[activeTab] || config.home;
  }, [
    activeTab,
    monitorScopedAlerts.length,
    flows.rows.length,
    gatewayRecent.rows,
    health.ok,
    monitorScopedIncidentMetadata.length,
    pendingApprovals.length,
    guidanceState.rows.length,
    closedIncidents.rows,
    applicationToMonitor,
    selectedMonitorScopeLabel,
    latestIncidentId,
    latestRecommendationId,
    approvalForm.action,
    workflowEventRows.length,
    selectedFlow,
    allUsageRows,
    messageBusActual,
    observedRouting,
    gatewaySummary.data,
    executiveMetrics.finopsCost,
    executiveInsights.slaAtRisk,
    executiveInsights.avgApprovalWaitMinutes,
    executiveInsights.automationRate,
  ]);

  const workflowGuide = useMemo(() => {
    const unresolvedAlerts = monitorScopedAlerts.filter((row) => !isApprovalResolvedStatus(row?.status || row?.state));
    const agentNames = new Set(
      (selectedAlertEventsDisplay || []).map((row) => String(row?.agent || "").trim().toLowerCase()).filter(Boolean),
    );
    const resolutionSeen = Array.from(agentNames).some((name) => name.includes("resolution intelligence") || name.includes("resolution-agent"));
    const remediationSeen = Array.from(agentNames).some((name) => name.includes("remediation automation") || name.includes("remediation-engine"));

    const cards = [
      {
        id: "alerts",
        label: "Alert Intake",
        status: unresolvedAlerts.length ? "active" : "idle",
        detail: unresolvedAlerts.length
          ? `${unresolvedAlerts.length} open alerts ready for triage.`
          : "No open alerts in the current monitoring scope.",
      },
      {
        id: "approval",
        label: "Approval Queue",
        status: pendingApprovals.length ? "attention" : "clear",
        detail: pendingApprovals.length
          ? `${pendingApprovals.length} incidents are waiting for a user decision.`
          : "No incidents are waiting for human approval.",
      },
      {
        id: "resolution",
        label: "Resolution Intelligence",
        status: resolutionSeen ? "active" : "attention",
        detail: resolutionSeen
          ? "Root-cause and recommendation evidence found for selected alert."
          : "No resolution trace detected for selected alert yet.",
      },
      {
        id: "remediation",
        label: "Remediation Automation",
        status: remediationSeen ? "active" : "attention",
        detail: remediationSeen
          ? "Remediation execution trace detected in agent timeline."
          : "No remediation execution trace detected yet.",
      },
    ];

    let nextAction = "Open an alert row to inspect timeline, then route to approval if required.";
    if (!unresolvedAlerts.length) {
      nextAction = "Generate or ingest a fresh alert to validate the end-to-end agent workflow.";
    } else if (pendingApprovals.length) {
      nextAction = "Use Human Approval to approve or reject pending recommendations and unblock remediation.";
    } else if (!resolutionSeen) {
      nextAction = "Inspect Cockpit and review Evidence or Timeline for Resolution Intelligence output.";
    } else if (!remediationSeen) {
      nextAction = "Approve the recommendation or verify auto-execution policy to trigger remediation.";
    }

    return { cards, nextAction };
  }, [monitorScopedAlerts, pendingApprovals.length, selectedAlertEventsDisplay]);

  function downloadFullHtmlReportPack() {
    const now = new Date();
    const generatedAt = formatIstTimestamp(now.toISOString());
    const homeMetrics = [
      ["Recent Alerts", monitorScopedAlerts.length],
      ["Flows", flows.rows.length],
      ["Gateway Events", gatewayRecent.rows.length],
      ["Health", health.ok ? "OK" : "CHECK"],
    ];
    const executiveMetrics = [
      ["Open Alerts", monitorScopedAlerts.length],
      ["Critical Open", monitorScopedAlerts.filter((row) => String(row?.severity || "").toLowerCase() === "critical").length],
      ["Closed Incidents", closedIncidents.rows.length],
      ["Health Restored", closedIncidents.rows.filter((row) => row?.health_restored === true).length],
      ["SLA At Risk", executiveInsights.slaAtRisk],
      ["Avg Approval Wait (min)", executiveInsights.avgApprovalWaitMinutes.toFixed(1)],
      ["Auto Remediation Rate", `${executiveInsights.automationRate.toFixed(1)}%`],
    ];
    const safetyMetrics = [
      ["Total", gatewaySummary.data.total_events || 0],
      ["Allowed", gatewaySummary.data.allowed || 0],
      ["Review", gatewaySummary.data.review || 0],
      ["Blocked", gatewaySummary.data.blocked || 0],
    ];

    const monitorAlertsRows = monitorScopedAlerts.slice(0, 200).map((row, index) => [
      row.alert_id || row.id || row.incident_id || index,
      formatUtcTimestamp(row.created_at || row.starts_at),
      row.name || row.alert_name || "-",
      row.application || row.project_name || row.project || row.service || "-",
      row.service || "-",
      String(row.severity || "-").toUpperCase(),
      row.status || row.state || "open",
    ]);
    const metadataRows = monitorScopedIncidentMetadata.slice(0, 250).map((row, index) => [
      row.incident_id || row.id || index,
      row.service || "-",
      row.risk_tier || "-",
      row.execution_mode || "-",
      row.transport_provider || "-",
      row.status || "-",
    ]);
    const pendingApprovalRows = pendingApprovals.slice(0, 200).map((row, index) => [
      row.incident_id || index,
      row.service || "-",
      row.severity || row.risk_tier || "-",
      row.execution_mode || "-",
      row.status || "pending",
    ]);
    const guidanceRows = guidanceState.rows.slice(0, 200).map((row, index) => [
      row.kind || row.document_kind || "-",
      row.score ?? "-",
      row.title || row.id || `match-${index}`,
      row.path || "-",
    ]);
    const traceRows = workflowEventRows.slice(0, 250).map((row) => [
      row.sequence,
      row.agent,
      row.action,
      row.decision,
      row.output,
      row.communicates_to,
    ]);
    const finopsProviderRows = finopsByProvider.map((row) => [
      row.provider,
      row.calls,
      row.total_tokens,
      Number(row.total_cost_usd || 0).toFixed(6),
    ]);
    const finopsUsageRows = panelWorkflowUsage.slice(0, 250).map((row) => [
      row.task || "-",
      row.provider || "-",
      row.model || "-",
      row.input_tokens || "-",
      row.output_tokens || "-",
      row.total_cost_usd || "-",
    ]);
    const gatewayRows = gatewayRecent.rows.slice(0, 250).map((row, index) => [
      formatIstTimestamp(row.created_at || row.timestamp) || index,
      row.path || "-",
      row.status_code || "-",
      row?.safety?.decision || "-",
      row.trace_id || "-",
    ]);
    const busActualRows = messageBusActual.rows.map((row) => [
      row.service,
      row.consumed,
      row.published,
      row.provider,
      row.status,
    ]);
    const busConfigRows = messageBusTopicRows.map((row) => [row.service, row.consumes, row.publishes]);
    const closedRows = filteredClosedRows.slice(0, 300).map((row, index) => [
      row.incident_id || index,
      row.service || "-",
      row.severity || "-",
      row.status || "closed",
      formatIstTimestamp(row.closed_at || row.updated_at),
    ]);

    const selectedCanonicalAnalysis = canonicalIncidentAnalysis(selectedAlertWorkflow, selectedAlertRow);
    const selectedSummaryRows = selectedAlertRow
      ? [
          ["Alert ID", selectedAlertId],
          ["Name", selectedAlertRow?.name || selectedAlertWorkflow?.alert?.name || "-"],
          ["Service", selectedAlertRow?.service || selectedAlertWorkflow?.alert?.service || "-"],
          ["Incident", selectedAlertWorkflow?.incident?.id || selectedAlertWorkflow?.incident_id || "-"],
          ["Analysis Status", selectedCanonicalAnalysis.status],
          ["Root Cause", selectedCanonicalAnalysis.rootCause],
          ["Recommended Action", selectedCanonicalAnalysis.action],
          ["Impact", selectedCanonicalAnalysis.impact],
          ["External Knowledge", selectedCanonicalAnalysis.externalKnowledgeStatus],
        ]
      : [];
    const selectedEventsRows = selectedAlertEvents.slice(0, 250).map((event) => [
      event.sequence || "-",
      event.agent || "-",
      event.action || "-",
      typeof event.decision === "object" ? JSON.stringify(event.decision) : String(event.decision || "-"),
      typeof event.output === "object" ? JSON.stringify(event.output) : String(event.output || "-"),
      event.communicates_to || "-",
    ]);
    const selectedUsageRows = selectedAlertUsage.slice(0, 250).map((row) => [
      row.task || "-",
      row.provider || "-",
      row.model || "-",
      row.input_tokens || "-",
      row.output_tokens || "-",
      row.total_cost_usd || "-",
    ]);
    const selectedRoutingRows = selectedAlertRow
      ? [
          ["Observed Provider", (hasSelectedWorkflowData ? selectedAlertRouting?.message_bus_provider : observedRouting?.message_bus_provider) || "-"],
          ["Workflow", (hasSelectedWorkflowData ? selectedAlertRouting?.workflow : observedRouting?.workflow) || "-"],
          ["Next Action", (hasSelectedWorkflowData ? selectedAlertRouting?.next_action : observedRouting?.next_action) || "-"],
          ["Execution Mode", (hasSelectedWorkflowData ? selectedAlertRouting?.execution_mode : observedRouting?.execution_mode) || "-"],
          ["Risk Tier", (hasSelectedWorkflowData ? selectedAlertRouting?.risk_tier : observedRouting?.risk_tier) || "-"],
        ]
      : [];

    const sections = [
      `<section><h2>Report Context</h2>${renderHtmlTable(["Field", "Value"], [["Generated At", generatedAt], ["Application Scope", selectedMonitorScopeLabel], ["Active Tab", activeTab], ["Health", health.message]])}</section>`,
      `<section><h2>Dashboard Metrics</h2>${renderHtmlTable(["Metric", "Value"], homeMetrics)}</section>`,
      `<section><h2>Alert Stream</h2>${renderHtmlTable(["Alert ID", "Time (UTC)", "Name", "Application", "Service", "Severity", "Status"], monitorAlertsRows)}</section>`,
      `<section><h2>Alert Details Cockpit</h2>${renderHtmlTable(["Field", "Value"], selectedSummaryRows)}${renderHtmlTable(["Step", "Agent", "Action", "Decision", "Output", "Communicates To"], selectedEventsRows)}${renderHtmlTable(["Task", "Provider", "Model", "Input", "Output", "Cost USD"], selectedUsageRows)}${renderHtmlTable(["Field", "Value"], selectedRoutingRows)}<h3>Raw Payload</h3><pre>${htmlEscape(JSON.stringify(selectedAlertData.payload || {}, null, 2))}</pre></section>`,
      `<section><h2>Executive Dashboard</h2>${renderHtmlTable(["Metric", "Value"], executiveMetrics)}${renderHtmlTable(["Incident", "Service", "Risk", "Execution Mode", "Provider", "Status"], metadataRows)}</section>`,
      `<section><h2>Incident Metadata Explorer</h2>${renderHtmlTable(["Incident", "Service", "Risk", "Execution Mode", "Provider", "Status"], metadataRows)}</section>`,
      `<section><h2>Alerts and Quick Docs</h2>${renderHtmlTable(["Incident", "Service", "Severity", "Execution Mode", "Status"], pendingApprovalRows)}${renderHtmlTable(["Kind", "Score", "Title", "Path"], guidanceRows)}</section>`,
      `<section><h2>Agent Flow</h2>${renderHtmlTable(["Step", "Agent", "Action", "Decision", "Output", "Handoff"], traceRows)}${renderHtmlTable(["Time", "Path", "Status", "Decision", "Trace"], gatewayRows)}</section>`,
      `<section><h2>FinOps</h2>${renderHtmlTable(["Provider", "Calls", "Tokens", "Cost USD"], finopsProviderRows)}${renderHtmlTable(["Task", "Provider", "Model", "Input Tokens", "Output Tokens", "Total Cost USD"], finopsUsageRows)}</section>`,
      `<section><h2>Message Bus</h2>${renderHtmlTable(["Service", "Consumed", "Published", "Provider", "Status"], busActualRows)}${renderHtmlTable(["Service", "Consumes", "Publishes"], busConfigRows)}<h3>Observed Topics</h3><p>Published: ${htmlEscape(messageBusActual.published.join(", ") || "none")}</p><p>Consumed: ${htmlEscape(messageBusActual.consumed.join(", ") || "none")}</p></section>`,
      `<section><h2>Gateway Safety</h2>${renderHtmlTable(["Metric", "Value"], safetyMetrics)}${renderHtmlTable(["Time", "Path", "Status", "Decision", "Trace"], gatewayRows)}</section>`,
      `<section><h2>Closed Incidents</h2>${renderHtmlTable(["Incident", "Service", "Severity", "Status", "Closed At"], closedRows)}</section>`,
      `<section><h2>Admin Snapshot</h2>${renderHtmlTable(["Field", "Value"], [["Signed In User", adminSession?.user?.username || "-"], ["Users Loaded", adminUsers.rows.length], ["Onboarding Rows", onboardingState.rows.length]])}</section>`,
      `<section><h2>Workflow Raw Result</h2><pre>${htmlEscape(JSON.stringify(workflowState.result || {}, null, 2))}</pre></section>`,
    ];

    const documentHtml = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>KaiOps Report Pack - ${htmlEscape(selectedMonitorScopeLabel)}</title>
  <style>
    :root { color-scheme: light; }
    body { margin: 0; padding: 24px; font-family: "Segoe UI", Tahoma, sans-serif; background: #f5f8fb; color: #10233b; }
    h1, h2, h3 { margin: 0 0 10px; }
    h1 { font-size: 26px; }
    h2 { font-size: 19px; margin-top: 18px; }
    h3 { font-size: 15px; margin-top: 12px; }
    .meta { margin: 8px 0 18px; color: #42566e; }
    section { background: #fff; border: 1px solid #dbe7f3; border-radius: 14px; padding: 14px; margin-bottom: 12px; box-shadow: 0 8px 20px rgba(16, 35, 59, 0.06); }
    table { width: 100%; border-collapse: collapse; margin: 8px 0 14px; }
    th, td { border: 1px solid #dbe7f3; text-align: left; padding: 7px 8px; font-size: 12px; vertical-align: top; }
    th { background: #eef4fb; }
    pre { margin: 8px 0 0; padding: 10px; background: #0f172a; color: #e2e8f0; border-radius: 10px; overflow: auto; font-size: 11px; }
  </style>
</head>
<body>
  <h1>KaiOps Full HTML Report Pack</h1>
  <p class="meta">Application: ${htmlEscape(selectedMonitorScopeLabel)} | Generated: ${htmlEscape(generatedAt)}</p>
  ${sections.join("\n")}
</body>
</html>`;

    const blob = new Blob([documentHtml], { type: "text/html;charset=utf-8" });
    const objectUrl = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = objectUrl;
    anchor.download = `kaiops-report-pack-${String(selectedMonitorScopeLabel || "all").replace(/[^a-zA-Z0-9_-]+/g, "-")}-${generatedAt.replace(/[:.]/g, "-")}.html`;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(objectUrl);
  }

  if (!isAuthenticated) {
    return (
      <main className={`app-shell density-${uiDensity}`}>
        <section className="grid single-col">
          <article className="panel" style={{ maxWidth: 560, margin: "48px auto" }}>
            <div className="panel-head">
              <div>
                <h2>Login</h2>
                <p>Sign in to access role-based KaiOps workspaces.</p>
              </div>
            </div>
            <form className="form" onSubmit={adminLogin}>
              <label>Username<input value={adminAuthForm.username} onChange={(e) => setAdminAuthForm((curr) => ({ ...curr, username: e.target.value }))} /></label>
              <label>Password<input type="password" value={adminAuthForm.password} onChange={(e) => setAdminAuthForm((curr) => ({ ...curr, password: e.target.value }))} /></label>
              <button className="button-primary" type="submit" disabled={adminSession.loading}>{adminSession.loading ? "Signing in..." : "Sign In"}</button>
            </form>
            {adminSession.error ? <p className="error">{adminSession.error}</p> : null}
            <p className="subtitle">Role access: Admin = all screens and document provisioning, L3/L2 = investigations plus Provide Documents, L1 = monitoring dashboard and escalation.</p>
          </article>
        </section>
      </main>
    );
  }

  return (
    <main className={`app-shell density-${uiDensity}`}>
      <div className="app-layout">
        <aside className="sidebar panel sidebar-panel">
          <div className="sidebar-head">
            <h2>Control Panel</h2>
            <p className="subtitle">Essential navigation.</p>
          </div>

          <div className="sidebar-group">
            <h3>Monitor</h3>
            <label>
              Application
              <select value={applicationToMonitor} onChange={(e) => setApplicationToMonitor(e.target.value)}>
                {monitorApplications.map((app) => (
                  <option key={app} value={app}>{monitorScopeLabel(app)}</option>
                ))}
              </select>
            </label>
            <HealthBadge ok={health.ok} label={health.message} />
          </div>

          <div className="sidebar-group">
            <h3>View Density</h3>
            <div className="density-switch" role="group" aria-label="Density options">
              <button
                type="button"
                className={`density-option ${uiDensity === "comfortable" ? "active" : ""}`}
                onClick={() => setUiDensity("comfortable")}
              >
                Comfortable
              </button>
              <button
                type="button"
                className={`density-option ${uiDensity === "compact" ? "active" : ""}`}
                onClick={() => setUiDensity("compact")}
              >
                Compact
              </button>
            </div>
            <h3 style={{ marginTop: 10 }}>Theme</h3>
            <div className="theme-switch" role="group" aria-label="Theme options">
              <button
                type="button"
                className={`density-option ${uiTheme === "auto" ? "active" : ""}`}
                onClick={() => setUiTheme("auto")}
              >
                Auto
              </button>
              <button
                type="button"
                className={`density-option ${uiTheme === "light" ? "active" : ""}`}
                onClick={() => setUiTheme("light")}
              >
                Light
              </button>
              <button
                type="button"
                className={`density-option ${uiTheme === "dark" ? "active" : ""}`}
                onClick={() => setUiTheme("dark")}
              >
                Dark
              </button>
            </div>
          </div>

          <div className="sidebar-group">
            <h3>Sections</h3>
            <div className="sidebar-sections-wrap">
              <div className="sidebar-sections">
                {visibleSidebarSections.map((tab) => (
                  <button
                    key={`sidebar-${tab.id}`}
                    type="button"
                    className={`sidebar-section ${activeTab === tab.id ? "active" : ""}`}
                    onClick={() => openSection(tab.id)}
                    title={tab.label}
                  >
                    <span className={`sidebar-icon sidebar-icon-${tab.tone || "ops"}`} aria-hidden="true">{tab.icon}</span>
                    <span>{tab.shortLabel}</span>
                  </button>
                ))}
              </div>
            </div>
          </div>

          <div className="sidebar-group compact-tools">
            <button className="button-secondary" onClick={refreshAll}>Refresh</button>
            <button className="button-secondary" onClick={checkHealth} disabled={health.loading}>
              {health.loading ? "Checking..." : "Health"}
            </button>
          </div>
        </aside>

        <section className="content-area">
          <header className="hero">
            <p className="eyebrow">KaiMS</p>
            <h1>Operational Workspace</h1>
            <p className="subtitle">Business-level view of reliability, risk, and cost.</p>
            <div className="hero-actions">
              <HealthBadge ok={health.ok} label={health.message} />
              <span className="subtitle">Monitoring: {selectedMonitorScopeLabel}</span>
              <span className="subtitle">Signed in: {adminSession?.user?.username || "-"} ({adminSession?.user?.role_name || "-"})</span>
              <button className="button-secondary" type="button" onClick={adminLogout}>Logout</button>
            </div>
          </header>

          <section className="report-banner panel">
            <div className="panel-head">
              <div>
                <h2>{reportConfig.title}</h2>
                <p>{reportConfig.caption}</p>
                <p className="scope-note">Scope: {selectedMonitorScopeLabel}</p>
              </div>
            </div>
            <div className="report-tools">
              <button className="button-secondary" type="button" onClick={reportConfig.refresh}>
                Refresh Report
              </button>
              {activeTab === "home" ? (
                <button className="button-secondary" type="button" onClick={downloadFullHtmlReportPack}>
                  Export Incident Report
                </button>
              ) : null}
            </div>
            <div className="report-metrics">
              {reportConfig.metrics.map(([label, value]) => (
                <div className="report-metric" key={`metric-${label}`}>
                  <strong>{label}</strong>
                  <span>{String(value)}</span>
                </div>
              ))}
            </div>
            <div className="global-flow-strip" aria-label="Workflow flow visible across all pages">
              {globalWorkflowFlowStages.map((stage) => (
                <div key={`global-flow-${stage.id}`} className={`global-flow-stage is-${stage.status}`}>
                  <strong>{stage.label}</strong>
                  <small>{String(stage.detail || "-")}</small>
                </div>
              ))}
            </div>
            {!health.ok ? (
              <div className="health-advisory">
                <strong>Health needs attention</strong>
                <span>{health.message || "Gateway status is not available."}</span>
                <button className="button-secondary" type="button" onClick={checkHealth} disabled={health.loading}>
                  {health.loading ? "Checking..." : "Recheck"}
                </button>
              </div>
            ) : null}
          </section>

          {activeTab === "stream" ? (
            <section className="grid single-col ingestion-stream-page">
              <article className="ingestion-stream-hero">
                <div>
                  <span className="discovery-eyebrow">Live multi-source intake</span>
                  <h2>Alert Ingestion Stream</h2>
                  <p>Email, logs, Prometheus, Telemetry, and ticketing events as they land in KaiOps.</p>
                </div>
                <div className="ingestion-live-state">
                  <span className={`ingestion-live-dot ${landingPadRecent.loading ? "is-loading" : ""}`} aria-hidden="true" />
                  <div>
                    <strong>{landingPadRecent.loading ? "Syncing now" : "Live · 10s refresh"}</strong>
                    <small>{visibleIngestionStreamRows.length} of {ingestionStreamRows.length} arrivals shown</small>
                  </div>
                  <button type="button" className="button-secondary" onClick={loadLandingPadRecent} disabled={landingPadRecent.loading}>
                    {landingPadRecent.loading ? "Refreshing..." : "Refresh now"}
                  </button>
                </div>
              </article>

              <div className="ingestion-channel-grid" aria-label="Alert source counts">
                {[
                  ["all", "ALL", "All arrivals", ingestionStreamCounts.all],
                  ["prometheus", "PR", "Prometheus", ingestionStreamCounts.prometheus],
                  ["telemetry", "OT", "Telemetry", ingestionStreamCounts.telemetry],
                  ["email", "EM", "Email", ingestionStreamCounts.email],
                  ["log", "LG", "Logs / OpenSearch", ingestionStreamCounts.log],
                  ["ticket", "TK", "Tickets / Jira", ingestionStreamCounts.ticket],
                  ["failed", "!", "Failed intake", ingestionStreamCounts.failed],
                ].map(([channel, icon, label, count]) => (
                  <button
                    type="button"
                    key={`stream-channel-${channel}`}
                    className={`ingestion-channel-card channel-${channel} ${ingestionStreamChannel === channel ? "is-active" : ""}`}
                    onClick={() => setIngestionStreamChannel(channel)}
                    aria-pressed={ingestionStreamChannel === channel}
                  >
                    <span>{icon}</span>
                    <div><strong>{count}</strong><small>{label}</small></div>
                  </button>
                ))}
              </div>

              <article className="panel ingestion-stream-panel">
                <div className="ingestion-stream-toolbar">
                  <div>
                    <span className="discovery-eyebrow">Landing-pad events</span>
                    <h3>
                      {ingestionStreamChannel === "all"
                        ? "All source activity"
                        : ingestionStreamChannel === "failed"
                          ? "Failed ingestion activity"
                          : `${sourceChannelLabel(ingestionStreamChannel)} activity`}
                    </h3>
                  </div>
                  <label>
                    <span>Search stream</span>
                    <input
                      value={ingestionStreamQuery}
                      onChange={(event) => setIngestionStreamQuery(event.target.value)}
                      placeholder="Alert, service, project, source, file"
                    />
                  </label>
                </div>
                {landingPadRecent.error ? <p className="error">{landingPadRecent.error}</p> : null}
                <div className="ingestion-stream-list">
                  {visibleIngestionStreamRows.map((row, index) => {
                    const channel = row.source_channel || "prometheus";
                    const failed = String(row.status || "").toLowerCase() === "failed" || Boolean(row.error);
                    return (
                      <article className={`ingestion-event channel-${channel} ${failed ? "is-failed" : ""}`} key={`${row.file || row.id || "arrival"}-${index}`}>
                        <div className="ingestion-event-marker">
                          <span>{channel === "email" ? "EM" : channel === "log" ? "LG" : channel === "ticket" ? "TK" : channel === "telemetry" ? "OT" : "PR"}</span>
                          <i aria-hidden="true" />
                        </div>
                        <div className="ingestion-event-main">
                          <header>
                            <div>
                              <strong>{row.name || row.alert_name || "Unnamed alert"}</strong>
                              <span className={`source-badge source-${channel}`}>{sourceChannelLabel(channel)}</span>
                              <span className={`pill ${failed ? "status-failed" : statusPillClass(row.status || "processed")}`}>{row.status || "processed"}</span>
                            </div>
                            <time>{formatIstTimestamp(row.received_at || row.created_at || row.modified_at)}</time>
                          </header>
                          <p>{row.description || row.annotations?.description || row.error || "Alert received and normalized by the landing pad."}</p>
                          <footer>
                            <span><b>Service</b>{row.service || "-"}</span>
                            <span><b>Project</b>{row.application || row.project_name || row.project || "-"}</span>
                            <span><b>Severity</b>{String(row.severity || "-").toUpperCase()}</span>
                            <span title={row.file}><b>File</b>{compactText(row.file, 44)}</span>
                          </footer>
                          {row.error ? <small className="ingestion-event-error">{row.error}</small> : null}
                        </div>
                      </article>
                    );
                  })}
                  {!visibleIngestionStreamRows.length && !landingPadRecent.loading ? (
                    <div className="ingestion-stream-empty">
                      <strong>No arrivals match this view.</strong>
                      <p>Choose another source, clear the search, or verify that its connector is delivering files or webhooks to the landing pad.</p>
                    </div>
                  ) : null}
                </div>
              </article>
            </section>
          ) : null}

          {activeTab === "home" ? (
            <section className="grid single-col">
              <article className="panel monitoring-projects-panel">
                <div className="panel-head">
                  <div>
                    <span className="discovery-eyebrow">Monitoring projects</span>
                    <h2>KaiOps + Telemetry</h2>
                    <p>Select a project to scope alerts, incidents, discovery evidence, and timeline events.</p>
                  </div>
                  <button type="button" className="button-secondary" onClick={loadMonitorApplications}>Refresh Projects</button>
                </div>
                <div className="monitoring-project-grid">
                  {CORE_MONITOR_PROJECTS.map((projectName) => {
                    const project = (monitoringApps.rows || []).find(
                      (row) => String(row?.name || "").trim().toLowerCase() === projectName.toLowerCase()
                    );
                    const selected = String(applicationToMonitor || "").toLowerCase() === projectName.toLowerCase();
                    return (
                      <button
                        type="button"
                        className={`monitoring-project-card ${selected ? "is-selected" : ""}`}
                        key={projectName}
                        onClick={() => setApplicationToMonitor(projectName)}
                      >
                        <span className="monitoring-project-icon">{projectName === "Telemetry" ? "OT" : "KO"}</span>
                        <span className="monitoring-project-copy">
                          <strong>{projectName}</strong>
                          <small>{project?.namespace || (projectName === "Telemetry" ? "telemetry" : "kaiops")} namespace</small>
                          <code>{project?.metrics_endpoint || (projectName === "Telemetry" ? "Prometheus :19090" : "API Gateway metrics")}</code>
                        </span>
                        <span className={`pill ${String(project?.status || "").includes("failed") ? "status-failed" : "status-closed"}`}>
                          {project?.status || "registered"}
                        </span>
                      </button>
                    );
                  })}
                </div>
              </article>
              <article className="panel workflow-guide-panel">
                <div className="panel-head">
                  <h2>Workflow Health & Next Action</h2>
                </div>
                <p className="subtitle">Fast status across intake, resolution, approval, and remediation.</p>
                <div className="workflow-guide-grid">
                  {workflowGuide.cards.map((card) => (
                    <div className="workflow-guide-card" key={card.id}>
                      <strong>{card.label}</strong>
                      <span className={`workflow-pill workflow-pill-${card.status}`}>{card.status.toUpperCase()}</span>
                      <p>{card.detail}</p>
                    </div>
                  ))}
                </div>
                <p className="scope-note">Recommended next step: {workflowGuide.nextAction}</p>
              </article>

              <article className="panel">
                <div className="panel-head">
                  <h2>Alert Stream</h2>
                  <label className="alerts-limit-select">
                    Show
                    <select
                      value={alertsLimit}
                      disabled={alerts.loading}
                      onChange={(event) => setAlertsLimit(Number(event.target.value))}
                    >
                      <option value={25}>25</option>
                      <option value={50}>50</option>
                      <option value={100}>100</option>
                      <option value={200}>200</option>
                      <option value={500}>500</option>
                    </select>
                    alerts
                  </label>
                  <button className="button-secondary" onClick={loadRecentAlerts} disabled={alerts.loading}>
                    {alerts.loading ? "Loading..." : "Refresh"}
                  </button>
                </div>
                {alerts.error ? <p className="error">{alerts.error}</p> : null}
                {alertSeverityOverrides.error ? <p className="error">{alertSeverityOverrides.error}</p> : null}
                <div className="dashboard-alert-toolbar">
                  <div className="dashboard-alert-focus" role="tablist" aria-label="Alert triage focus">
                    <button type="button" className={`dashboard-focus-chip ${dashboardAlertFocus === "ops" ? "active" : ""}`} onClick={() => setDashboardAlertFocus("ops")}>Ops {dashboardAlertSummary.ops}</button>
                    <button type="button" className={`dashboard-focus-chip ${dashboardAlertFocus === "all" ? "active" : ""}`} onClick={() => setDashboardAlertFocus("all")}>All {dashboardAlertSummary.total}</button>
                    <button type="button" className={`dashboard-focus-chip ${dashboardAlertFocus === "critical" ? "active" : ""}`} onClick={() => setDashboardAlertFocus("critical")}>Critical {dashboardAlertSummary.critical}</button>
                    <button type="button" className={`dashboard-focus-chip ${dashboardAlertFocus === "high" ? "active" : ""}`} onClick={() => setDashboardAlertFocus("high")}>High {dashboardAlertSummary.high}</button>
                    <button type="button" className={`dashboard-focus-chip ${dashboardAlertFocus === "awaiting" ? "active" : ""}`} onClick={() => setDashboardAlertFocus("awaiting")}>Awaiting {dashboardAlertSummary.awaiting}</button>
                    <button type="button" className={`dashboard-focus-chip ${dashboardAlertFocus === "active" ? "active" : ""}`} onClick={() => setDashboardAlertFocus("active")}>Active {dashboardAlertSummary.active}</button>
                    <button type="button" className={`dashboard-focus-chip ${dashboardAlertFocus === "closed" ? "active" : ""}`} onClick={() => setDashboardAlertFocus("closed")}>Closed {dashboardAlertSummary.closed}</button>
                    <button type="button" className={`dashboard-focus-chip ${dashboardAlertFocus === "test" ? "active" : ""}`} onClick={() => setDashboardAlertFocus("test")}>Test {dashboardAlertSummary.test}</button>
                  </div>
                  <div className="dashboard-alert-search">
                    <input
                      value={dashboardAlertQuery}
                      onChange={(event) => setDashboardAlertQuery(event.target.value)}
                      placeholder="Search alert name, service, app, id"
                    />
                    {dashboardAlertQuery ? (
                      <button type="button" className="button-secondary" onClick={() => setDashboardAlertQuery("")}>Clear</button>
                    ) : null}
                  </div>
                </div>
                <p className="subtitle">
                  Showing {dashboardVisibleAlerts.length} of {visibleAlerts.length} alerts for {selectedMonitorScopeLabel}.
                  {dashboardAlertFocus === "ops" && dashboardAlertSummary.test > 0 ? ` ${dashboardAlertSummary.test} smoke/stress alerts are hidden in Ops view.` : ""}
                  {monitorScopedRecentClosedAlerts.length > 0 ? ` Includes ${monitorScopedRecentClosedAlerts.length} recent closed incident(s).` : ""}
                </p>
                <div className="alert-source-breakdown" aria-label="Alert source visibility">
                  <span className="source-badge source-prometheus">Prometheus {visibleAlertSourceSummary.prometheus}</span>
                  <span className="source-badge source-telemetry">Telemetry {visibleAlertSourceSummary.telemetry}</span>
                  <span className="source-badge source-email">Email {visibleAlertSourceSummary.email}</span>
                  <span className="source-badge source-ticket">Ticket {visibleAlertSourceSummary.ticket}</span>
                  <span className="source-badge source-log">Logs {visibleAlertSourceSummary.log}</span>
                </div>
                {String(applicationToMonitor || "").toLowerCase() !== REAL_USE_CASE_SCOPE ? (
                  <div className="alert-source-breakdown" aria-label="All application source availability">
                    <span className="subtitle">Available across all applications:</span>
                    <span className="source-badge source-prometheus">Prometheus {allApplicationAlertSourceSummary.prometheus}</span>
                    <span className="source-badge source-telemetry">Telemetry {allApplicationAlertSourceSummary.telemetry}</span>
                    <span className="source-badge source-email">Email {allApplicationAlertSourceSummary.email}</span>
                    <span className="source-badge source-ticket">Ticket {allApplicationAlertSourceSummary.ticket}</span>
                    <span className="source-badge source-log">Logs {allApplicationAlertSourceSummary.log}</span>
                    <button type="button" className="button-secondary" onClick={() => setApplicationToMonitor(REAL_USE_CASE_SCOPE)}>
                      View all applications
                    </button>
                  </div>
                ) : null}
                {canManageSeverityOverride ? (
                  <p className="subtitle">L2/L3/Admin can set future severity overrides by alert name + service + environment.</p>
                ) : null}
                <div className="table-wrap table-wrap-scroll-x alert-stream-wrap">
                  <table className="alert-stream-table">
                    <thead>
                      <tr>
                        <th>Alert ID</th>
                        <th>Time (UTC)</th>
                        <th className="alert-name-col">Name</th>
                        <th>Rule</th>
                        <th>Application</th>
                        <th>Service</th>
                        <th>Source</th>
                        <th>Severity</th>
                        <th>Tier</th>
                        <th>Status</th>
                        <th>Action</th>
                      </tr>
                    </thead>
                    <tbody>
                      {dashboardVisibleAlerts.map((row, index) => {
                        const rowId = String(row.alert_id || row.id || row.incident_id || index);
                        const fullAlertId = String(row.alert_id || row.id || row.incident_id || "-");
                        const compactAlertId = fullAlertId.length > 16 ? `${fullAlertId.slice(0, 8)}...${fullAlertId.slice(-6)}` : fullAlertId;
                        const severity = String(row.severity || "-").toUpperCase();
                        const supportTier = String(row.labels?.support_tier || "-");
                        const status = String(row.status || row.state || "open");
                        const application = row.application || row.project_name || row.project || row.service || "-";
                        const sourceChannels = Array.isArray(row?.source_channels) && row.source_channels.length
                          ? row.source_channels
                          : [normalizeAlertChannel(row)];
                        const alertRuleName = String(
                          row.rule_name
                          || row.rule
                          || row.alert_rule
                          || row.labels?.alertname
                          || row.name
                          || row.alert_name
                          || "-"
                        ).trim();
                        return (
                          <tr
                            key={rowId}
                            className={`alert-row ${selectedAlertId === rowId ? "row-selected" : ""}`}
                            onClick={() => openAlertDetails(row)}
                            onKeyDown={(event) => {
                              if (event.key === "Enter" || event.key === " ") {
                                event.preventDefault();
                                openAlertDetails(row);
                              }
                            }}
                            tabIndex={0}
                            role="button"
                            aria-label={`Open alert ${rowId}`}
                          >
                            <td title={fullAlertId}>{compactAlertId}</td>
                            <td>{formatUtcTimestamp(row.created_at || row.starts_at || row.closed_at)}</td>
                            <td className="alert-name-col">{row.name || row.alert_name || "-"}</td>
                            <td title={String(row.expression || row.expr || row.query || row.description || row.annotations?.description || "").trim()}>{alertRuleName}</td>
                            <td>{application}</td>
                            <td>{row.service || "-"}</td>
                            <td>
                              <div className="alert-source-chips">
                                {sourceChannels.map((sourceChannel) => {
                                  const sourceKey = String(sourceChannel || "").toLowerCase();
                                  return (
                                    <span key={`${rowId}-${sourceKey}`} className={`source-badge source-${sourceKey}`}>
                                      {sourceChannelLabel(sourceKey)}
                                    </span>
                                  );
                                })}
                              </div>
                            </td>
                            <td><span className={`pill severity-${severity.toLowerCase()}`}>{severity}</span></td>
                            <td><span className={`pill tier-${supportTier.toLowerCase().replace("/", "-")}`}>{supportTier}</span></td>
                            <td><span className={`pill status-${status.toLowerCase()}`}>{status}</span></td>
                            <td>
                              <button
                                type="button"
                                className="button-secondary"
                                onClick={(event) => {
                                  event.stopPropagation();
                                  openAlertDetails(row);
                                }}
                              >
                                Inspect
                              </button>
                            </td>
                          </tr>
                        );
                      })}
                      {!dashboardVisibleAlerts.length && !alerts.loading ? (
                        <tr>
                          <td colSpan={10}>No alerts match current filters for {selectedMonitorScopeLabel}.</td>
                        </tr>
                      ) : null}
                    </tbody>
                  </table>
                </div>
              </article>

              {selectedAlertRow ? (
                <article className="panel">
                  <div className="panel-head">
                    <h3>Guided Incident Cockpit</h3>
                    <p>Selected alert actions, evidence, documents, approval, and remediation stay in one workspace.</p>
                  </div>
                  <div className="filter-grid">
                    <label>Alert
                      <input value={String(selectedAlertRow?.name || selectedAlertRow?.alert_name || "-")} readOnly />
                    </label>
                    <label>Service
                      <input value={String(selectedAlertRow?.service || "-")} readOnly />
                    </label>
                    <label>Status
                      <input value={selectedCanonicalIncidentStatus} readOnly />
                    </label>
                    <label>Current Severity
                      <input value={String(selectedAlertRow?.severity || "-").toUpperCase()} readOnly />
                    </label>
                  </div>
                  <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 10 }}>
                    <button type="button" className="button-primary" onClick={() => openAlertDetails(selectedAlertRow)}>Inspect Cockpit</button>
                    <span className="cockpit-action-note">
                      Evidence, documents, approval, remediation, and timeline are inside the cockpit.
                    </span>
                  </div>
                  <div className="alert-rule-summary-grid">
                    <article className="alert-rule-summary-card">
                      <span>Raised By Rule{selectedAlertRuleSummary.rules.length > 1 ? "s" : ""}</span>
                      <strong>{selectedAlertRuleSummary.rules.length} matched rule{selectedAlertRuleSummary.rules.length === 1 ? "" : "s"}</strong>
                      <div className="alert-rule-match-list">
                        {selectedAlertRuleSummary.rules.map((rule, index) => (
                          <div key={`selected-alert-rule-${index}-${rule.name}`}>
                            <b>{index + 1}. {rule.name}</b>
                            <small>{rule.expression || "Expression was not included in the event payload."}</small>
                          </div>
                        ))}
                      </div>
                    </article>
                    <article className="alert-rule-summary-card">
                      <span>Rule Source</span>
                      <strong>{selectedAlertRuleSummary.source}</strong>
                      <small>{selectedAlertRuleSummary.note}</small>
                    </article>
                    <article className="alert-rule-summary-card">
                      <span>Rule Severity</span>
                      <strong>{selectedAlertRuleSummary.severity.toUpperCase()}</strong>
                      <small>This rule context stays visible beside the live remediation actions.</small>
                    </article>
                    <article className="alert-rule-summary-card">
                      <span>Incident Summary</span>
                      <strong>{selectedAlertRuleSummary.ruleName}</strong>
                      <small>{selectedAlertRuleSummary.summary}</small>
                    </article>
                  </div>
                  {selectedAlertActionContext ? (
                    <>
                      <p className="subtitle">
                        Docs: {selectedAlertActionContext.alertClosed ? "Closed" : selectedAlertActionContext.documentAvailable ? "Ready" : "Missing"}
                        {selectedAlertActionContext.overrideRow ? ` | Future Severity: ${String(selectedAlertActionContext.overrideRow.severity || "-").toUpperCase()}` : ""}
                      </p>
                      {canManageSeverityOverride ? (
                        <div className="filter-grid">
                          <label>Future Severity Override
                            <select
                              value={selectedAlertActionContext.draftSeverity}
                              onChange={(event) => {
                                const next = String(event.target.value || "warning").toLowerCase();
                                setAlertSeverityDrafts((current) => ({ ...current, [selectedAlertActionContext.overrideKey]: next }));
                              }}
                            >
                              <option value="info">info</option>
                              <option value="warning">warning</option>
                              <option value="high">high</option>
                              <option value="critical">critical</option>
                            </select>
                          </label>
                          <div style={{ display: "flex", alignItems: "end", gap: 8 }}>
                            <button
                              type="button"
                              className="button-secondary"
                              onClick={() => applyAlertSeverityOverrideRule(selectedAlertRow)}
                              disabled={selectedAlertActionContext.overrideSaving || alertSeverityOverrides.loading || !selectedAlertActionContext.alertName}
                            >
                              {selectedAlertActionContext.overrideSaving ? "Saving..." : "Apply Override"}
                            </button>
                            <button
                              type="button"
                              className="button-secondary"
                              onClick={() => clearAlertSeverityOverrideRule(selectedAlertRow)}
                              disabled={selectedAlertActionContext.overrideSaving || !selectedAlertActionContext.overrideRow}
                            >
                              Clear Override
                            </button>
                          </div>
                        </div>
                      ) : null}
                    </>
                  ) : null}
                </article>
              ) : null}

              {docPromptAlert && canProvideAlertDocuments ? (
                <article className="panel" role="dialog" aria-label="Provide documents for alert" ref={docPromptRef}>
                  <div className="panel-head">
                    <h3>Provide Documents</h3>
                    <button type="button" className="button-secondary" onClick={closeDocumentPrompt}>Close</button>
                  </div>
                  <p className="subtitle">
                    Configure documentation for alert{" "}
                    <strong>{String(docPromptAlert.name || docPromptAlert.alert_name || docPromptAlert.alert_id || docPromptAlert.id || "-")}</strong>.
                    All document types are available as tabs below.
                  </p>
                  <div className="detail-tabs sticky-controls" style={{ marginBottom: 10 }}>
                    {ALERT_DOC_KIND_OPTIONS.map((kind) => {
                      const existing = docPromptDocsByKind[kind];
                      const selected = docPromptKind === kind;
                      const label = existing?.path ? `${kind} *` : kind;
                      return (
                        <button
                          key={`doc-kind-${kind}`}
                          type="button"
                          className={selected ? "button-primary" : "button-secondary"}
                          onClick={() => setDocPromptDraftForKind(docPromptAlert, kind)}
                        >
                          {label}
                        </button>
                      );
                    })}
                  </div>
                  <div className="filter-grid">
                    <label>
                      Mode
                      <select value={docPromptMode} onChange={(e) => setDocPromptMode(e.target.value)}>
                        <option value="create">Create New</option>
                        <option value="update" disabled={!docPromptExistingDoc?.path}>Update Existing</option>
                      </select>
                    </label>
                    <div style={{ display: "flex", alignItems: "end", gap: 8 }}>
                      <button
                        type="button"
                        className="button-secondary"
                        onClick={async () => {
                          const draft = await buildAlertDocumentDraftWithAnalysis(docPromptAlert, docPromptKind);
                          setAlertOnboarding((curr) => ({
                            ...curr,
                            kind: draft.kind,
                            title: draft.title,
                            summary: draft.summary,
                            content: draft.content,
                            services: draft.services,
                            severity: draft.severity,
                            alert_type: draft.alert_type,
                            alert_id: draft.alert_id,
                            execution_plan: String(draft.execution_plan || "").trim(),
                            remediation_commands_text: Array.isArray(draft.commands) ? draft.commands.join("\n") : "",
                            remediation_scripts_text: Array.isArray(draft.scripts) ? draft.scripts.join("\n") : "",
                            remediation_queries_text: Array.isArray(draft.queries) ? draft.queries.join("\n") : "",
                          }));
                        }}
                        disabled={alertOnboardingState.loading}
                      >
                        Re-Analyze Alert
                      </button>
                      <button
                        type="button"
                        className="button-secondary"
                        onClick={() => autoCreateAlertDocument(docPromptAlert, docPromptKind)}
                        disabled={alertOnboardingState.loading}
                      >
                        Create Selected Doc
                      </button>
                      <button
                        type="button"
                        className="button-secondary"
                        onClick={() => autoCreateAllAlertDocuments(docPromptAlert)}
                        disabled={alertOnboardingState.loading}
                      >
                        Create All Docs
                      </button>
                    </div>
                  </div>
                  {docPromptExistingDoc?.path ? <p className="subtitle">Existing document: {docPromptExistingDoc.path}</p> : null}
                  <form className="form" onSubmit={submitAlertOnboarding}>
                    <div className="filter-grid">
                      <label>Kind
                        <select value={alertOnboarding.kind} onChange={(e) => setAlertOnboarding((curr) => ({ ...curr, kind: e.target.value }))}>
                          <option value="incident">incident</option>
                          <option value="runbook">runbook</option>
                          <option value="deployment">deployment</option>
                          <option value="change">change</option>
                          <option value="dependency">dependency</option>
                          <option value="remediation">remediation</option>
                        </select>
                      </label>
                      <label>Title<input value={alertOnboarding.title} onChange={(e) => setAlertOnboarding((curr) => ({ ...curr, title: e.target.value }))} /></label>
                      <label>Severity<select value={alertOnboarding.severity} onChange={(e) => setAlertOnboarding((curr) => ({ ...curr, severity: e.target.value }))}><option value="critical">critical</option><option value="high">high</option><option value="medium">medium</option><option value="low">low</option></select></label>
                    </div>
                    <label>Services (comma separated)<input value={alertOnboarding.services} onChange={(e) => setAlertOnboarding((curr) => ({ ...curr, services: e.target.value }))} /></label>
                    <label>Summary<textarea rows={2} value={alertOnboarding.summary} onChange={(e) => setAlertOnboarding((curr) => ({ ...curr, summary: e.target.value }))} /></label>
                    <label>Content<textarea rows={5} value={alertOnboarding.content} onChange={(e) => setAlertOnboarding((curr) => ({ ...curr, content: e.target.value }))} /></label>
                    {String(alertOnboarding.kind || "").trim().toLowerCase() === "remediation" ? (
                      <>
                        <div style={{ display: "flex", alignItems: "end", gap: 8 }}>
                          <button
                            type="button"
                            className="button-secondary"
                            onClick={() => autoGenerateRemediationPlan(docPromptAlert)}
                            disabled={alertOnboardingState.loading}
                          >
                            Auto-Generate Commands/Scripts/Queries
                          </button>
                        </div>
                        <label>Execution Plan<textarea rows={4} value={alertOnboarding.execution_plan} onChange={(e) => setAlertOnboarding((curr) => ({ ...curr, execution_plan: e.target.value }))} /></label>
                        <div className="filter-grid">
                          <label>Additional Commands<textarea rows={5} value={alertOnboarding.remediation_commands_text} onChange={(e) => setAlertOnboarding((curr) => ({ ...curr, remediation_commands_text: e.target.value }))} /></label>
                          <label>Single Remediation Script<textarea rows={5} value={alertOnboarding.remediation_scripts_text} onChange={(e) => setAlertOnboarding((curr) => ({ ...curr, remediation_scripts_text: e.target.value }))} /></label>
                          <label>Additional Validation Queries<textarea rows={5} value={alertOnboarding.remediation_queries_text} onChange={(e) => setAlertOnboarding((curr) => ({ ...curr, remediation_queries_text: e.target.value }))} /></label>
                        </div>
                      </>
                    ) : null}
                    <button className="button-primary" type="submit" disabled={alertOnboardingState.loading}>
                      {alertOnboardingState.loading ? "Saving..." : docPromptMode === "update" && docPromptExistingDoc?.path ? "Update Document" : "Upload Document"}
                    </button>
                  </form>
                  {alertOnboardingState.error ? <p className="error">{alertOnboardingState.error}</p> : null}
                  {alertOnboardingState.result ? <p className="subtitle">{alertOnboardingState.result?.message || "Document saved."}</p> : null}

                  <article className="panel" style={{ marginTop: 10 }}>
                    <div className="panel-head">
                      <h3>Add Rule From Alert</h3>
                    </div>
                    <p className="subtitle">Use plain language like earlier flow; the system generates and stores a rule workflow.</p>
                    <div className="filter-grid">
                      <label>
                        Monitoring Platform
                        <select value={alertRuleDraft.platform} onChange={(e) => setAlertRuleDraft((curr) => ({ ...curr, platform: e.target.value }))}>
                          <option value="prometheus">prometheus</option>
                          <option value="new_relic">new_relic</option>
                          <option value="datadog">datadog</option>
                        </select>
                      </label>
                    </div>
                    <label>
                      Rule Requirement (Plain English)
                      <textarea rows={3} value={alertRuleDraft.requirement} onChange={(e) => setAlertRuleDraft((curr) => ({ ...curr, requirement: e.target.value }))} />
                    </label>
                    <button type="button" className="button-primary" onClick={addRuleFromAlertPrompt} disabled={alertRuleState.loading}>
                      {alertRuleState.loading ? "Creating Rule..." : "Add Rule"}
                    </button>
                    {alertRuleState.error ? <p className="error">{alertRuleState.error}</p> : null}
                    {alertRuleState.result?.workflow_id ? <p className="subtitle">Rule workflow created: {alertRuleState.result.workflow_id}</p> : null}
                  </article>
                </article>
              ) : null}

              {selectedAlertRow ? (
                <article className="panel alert-details-cockpit" ref={alertDetailsRef}>
                  <div className="panel-head">
                    <div>
                      <h2>Alert Details Cockpit</h2>
                      <p>One guided workspace for evidence, documents, approval, remediation, and timeline review.</p>
                    </div>
                  </div>
                  <div className="detail-context">
                    <span><strong>ID:</strong> {selectedAlertId}</span>
                    <span><strong>Service:</strong> {selectedAlertRow?.service || "-"}</span>
                    <span><strong>Severity:</strong> {String(selectedAlertRow?.severity || "-").toUpperCase()}</span>
                    <span>
                      <strong>Status:</strong>{" "}
                      <span className={`pill ${statusPillClass(selectedCanonicalIncidentStatus)}`}>
                        {selectedCanonicalIncidentStatus}
                      </span>
                    </span>
                  </div>

                  {(() => {
                    const matchedApproval = selectedMatchedApproval;
                    const incidentId = approvalIncidentId(matchedApproval)
                      || selectedAlertWorkflow?.incident?.id
                      || selectedAlertWorkflow?.incident_id
                      || "";
                    const approvalStatus = selectedApprovalStatus;
                    const isResolved = isApprovalResolvedStatus(approvalStatus);
                    const requiresApproval = Boolean(
                      matchedApproval
                      || selectedExecutionPlan?.requiresApproval
                      || selectedAlertRouting?.requires_approval
                      || selectedAlertWorkflow?.approval?.required
                      || selectedAlertWorkflow?.decision?.requires_approval
                      || isApprovalPendingStatus(approvalStatus)
                    );
                    const hasActionableApproval = Boolean(matchedApproval && !isResolved);

                    if (!requiresApproval) {
                      return null;
                    }

                    return (
                      <article
                        className="panel"
                        style={{
                          marginBottom: 10,
                          borderColor: hasActionableApproval ? "#ef9a9a" : "#c7d7ea",
                          boxShadow: hasActionableApproval ? "0 10px 24px rgba(183, 28, 28, 0.14)" : "none",
                        }}
                      >
                        <div className="panel-head">
                          <h3>Decision Gate</h3>
                        </div>
                        <p className="subtitle">
                          {hasActionableApproval
                            ? `Matched incident ${incidentId || "-"} with approval status ${approvalStatus || "pending"}.`
                            : matchedApproval
                              ? `Approval is already ${approvalStatus || "resolved"} for this incident.`
                              : `Incident is ${selectedCanonicalIncidentStatus}; no active pending approval is linked.`}
                        </p>
                        <div className="table-wrap">
                          <table>
                            <tbody>
                              <tr><th>Incident</th><td>{incidentId || "-"}</td></tr>
                              <tr>
                                <th>Incident Status</th>
                                <td><span className={`pill ${statusPillClass(selectedCanonicalIncidentStatus)}`}>{selectedCanonicalIncidentStatus}</span></td>
                              </tr>
                              <tr><th>Approval Status</th><td>{approvalStatus || (hasActionableApproval ? "pending" : "not active")}</td></tr>
                              <tr><th>Role Eligible</th><td>{canUseApprovalActions ? "yes" : "no"}</td></tr>
                            </tbody>
                          </table>
                        </div>
                        {hasActionableApproval ? (
                          <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                          <button
                            type="button"
                            className="button-secondary"
                            onClick={() => {
                              const matched = selectApprovalFromAlertRow(selectedAlertRow);
                              if (matched) {
                              setActiveTab("approval");
                              }
                            }}
                          >
                            Open Queue
                          </button>
                          <button
                            type="button"
                            className="button-primary"
                            onClick={() => setHomeDetailTab("timeline")}
                          >
                            Review Decision
                          </button>
                          {canUseApprovalActions ? (
                            <button
                              type="button"
                              className="button-secondary"
                              onClick={() => selectApprovalIncident(matchedApproval)}
                              disabled={approvalState.loading}
                            >
                              Load Decision Form
                            </button>
                          ) : null}
                          </div>
                        ) : null}
                      </article>
                    );
                  })()}

                  <div className="detail-tabs">
                    {["timeline", "discovery", "raw"].map((tab) => (
                      <button
                        key={`detail-${tab}`}
                        type="button"
                        className={`detail-tab ${homeDetailTab === tab ? "active" : ""}`}
                        onClick={() => setHomeDetailTab(tab)}
                      >
                        {tab === "timeline" ? "Incident Workspace" : tab === "discovery" ? "Discovery + Context" : "Raw Data"}
                      </button>
                    ))}
                  </div>

                  {false && homeDetailTab === "diagnostics" ? (
                    <div className="detail-tabs" style={{ marginTop: 8 }}>
                      {["processing", "timeline", "context", "events", "finops", "api", "raw", "pipeline"].map((tab) => (
                        <button
                          key={`diag-${tab}`}
                          type="button"
                          className={`detail-tab ${diagnosticsDetailTab === tab ? "active" : ""}`}
                          onClick={() => setDiagnosticsDetailTab(tab)}
                        >
                          {tab === "pipeline" ? "Pipeline" : tab === "processing" ? "Processing Flow" : tab === "timeline" ? "Flow Timeline" : tab === "context" ? "Context Flow" : tab === "events" ? "Agent Events" : tab === "finops" ? "FinOps" : tab === "api" ? "API Gateway" : "Raw Payload"}
                        </button>
                      ))}
                    </div>
                  ) : null}

                  {selectedAlertData.loading ? <p className="subtitle">Loading selected alert details...</p> : null}
                  {selectedAlertData.error ? <p className="error">{selectedAlertData.error}</p> : null}
                  {selectedAlertId ? (
                    <div style={{ marginBottom: 8 }}>
                      <button
                        type="button"
                        className="button-secondary"
                        onClick={() => loadAlertDetails(selectedAlertId)}
                        disabled={selectedAlertData.loading}
                      >
                        {selectedAlertData.loading ? "Refreshing..." : "Reload Alert Details"}
                      </button>
                    </div>
                  ) : null}

                  {homeDetailTab === "discovery" ? (
                    <section className="combined-analysis-page">
                      <header className="combined-analysis-hero">
                        <div>
                          <span className="discovery-eyebrow">Investigation overview</span>
                          <h3>Discovery + Context</h3>
                          <p>See what KaiOps found, what it means, and what to do next.</p>
                        </div>
                        <div className="combined-analysis-kpis">
                          <span><strong>{selectedAlertTimelineRows.length}</strong> timeline stages</span>
                          <span><strong>{selectedAlertRagDocuments.length}</strong> linked docs</span>
                          <span><strong>{formatQualityPercent(selectedAlertEvaluation.overallScore)}</strong> quality</span>
                          <span><strong>{Array.isArray(selectedAlertRow?.source_channels) ? selectedAlertRow.source_channels.map(sourceChannelLabel).join(" + ") : sourceChannelLabel(normalizeAlertChannel(selectedAlertRow))}</strong> sources</span>
                        </div>
                      </header>
                      <div className="combined-analysis-source-rail">
                        <strong>Connected evidence</strong>
                        <span className="source-badge source-prometheus">Prometheus</span>
                        <span className="source-badge">Jaeger traces</span>
                        <span className="source-badge">OpenSearch logs</span>
                        <span className="source-badge source-email">Email</span>
                        <span className="source-badge source-ticket">Jira / tickets</span>
                        <span className="source-badge">Source code</span>
                      </div>
                      <IntelligenceConnectionView
                        workflow={selectedAlertWorkflow}
                        documents={selectedAlertRagDocuments}
                        onDownloadDocument={downloadRagDocument}
                      />
                      <details className="investigation-deep-dive">
                        <summary>
                          <span>
                            <strong>Open technical retrieval trace</strong>
                            <small>Inspect every discovery query, context lookup, document score, agent handoff, and raw evidence record</small>
                          </span>
                          <b>Expand</b>
                        </summary>
                        <div className="combined-analysis-grid">
                          <article className="combined-analysis-card combined-analysis-discovery">
                            <DiscoveryFlowView
                              workflow={selectedAlertWorkflow}
                              timelineRows={selectedAlertTimelineRows}
                              selectedAlert={selectedAlertRow}
                              compact
                            />
                          </article>
                          <article className="combined-analysis-card combined-analysis-context">
                            <ContextRetrievalGraph
                              workflow={selectedAlertWorkflow}
                              timelineRows={selectedAlertTimelineRows}
                              documents={selectedAlertRagDocuments}
                              evaluation={selectedAlertEvaluation}
                              documentContract={selectedAlertDocumentContract}
                              onLoadDocumentContent={loadRagDocumentContent}
                              onDownloadDocument={downloadRagDocument}
                              compact
                            />
                          </article>
                        </div>
                      </details>
                    </section>
                  ) : null}

                  {homeDetailTab === "timeline" ? (
                    <>
                      <header className="incident-workspace-hero">
                        <div>
                          <span className="discovery-eyebrow">Unified response cockpit</span>
                          <h3>Incident Workspace</h3>
                          <p>Follow the incident, verify the evidence, make the decision, and execute recovery without switching tabs.</p>
                        </div>
                        <div className="incident-workspace-kpis">
                          <span><strong>{selectedCanonicalIncidentStatus}</strong> lifecycle</span>
                          <span><strong>{selectedAlertTimelineRows.length}</strong> events</span>
                          <span><strong>{selectedAlertRagDocuments.length}</strong> documents</span>
                          <span><strong>{formatQualityPercent(selectedAlertEvaluation.groundingScore)}</strong> grounded</span>
                        </div>
                      </header>
                      <UnifiedIncidentTimeline
                        workflow={selectedAlertWorkflow}
                        rows={selectedAlertTimelineRows}
                        documents={selectedAlertRagDocuments}
                      />
                      <details className="panel incident-workspace-section workspace-collapsible" open>
                      <summary className="panel-head">
                        <div>
                          <span className="workspace-section-number">01</span>
                          <h3>Incident Overview</h3>
                          <p>Alert identity, status, root cause, quality metrics, and stage completeness.</p>
                        </div>
                        <span className="section-toggle-indicator" />
                      </summary>
                      <div className="table-wrap table-wrap-scroll-x incident-overview-table">
                        <table>
                          <tbody>
                            <tr><th>Alert</th><td>{selectedAlertRow?.name || selectedAlertWorkflow?.alert?.name || "-"}</td></tr>
                            <tr><th>Details Source</th><td>{selectedAlertDetailsSource}</td></tr>
                            <tr><th>Incident</th><td>{selectedAlertWorkflow?.incident?.id || selectedAlertWorkflow?.incident_id || "-"}</td></tr>
                            <tr>
                              <th>Persisted Incident Status</th>
                              <td>
                                <span className={`pill ${statusPillClass(selectedCanonicalIncidentStatus)}`}>
                                  {selectedCanonicalIncidentStatus}
                                </span>
                              </td>
                            </tr>
                            <tr><th>Closed At</th><td>{formatIstTimestamp(selectedAlertWorkflow?.incident?.closed_at)}</td></tr>
                            <tr><th>Service</th><td>{selectedAlertRow?.service || selectedAlertWorkflow?.alert?.service || "-"}</td></tr>
                            <tr><th>Analysis Status</th><td>{canonicalIncidentAnalysis(selectedAlertWorkflow, selectedAlertRow).status}</td></tr>
                            <tr><th>Root Cause</th><td>{canonicalIncidentAnalysis(selectedAlertWorkflow, selectedAlertRow).rootCause}</td></tr>
                            <tr><th>Recommended Action</th><td>{canonicalIncidentAnalysis(selectedAlertWorkflow, selectedAlertRow).action}</td></tr>
                            <tr><th>Impact</th><td>{canonicalIncidentAnalysis(selectedAlertWorkflow, selectedAlertRow).impact}</td></tr>
                            <tr><th>External Knowledge</th><td>{canonicalIncidentAnalysis(selectedAlertWorkflow, selectedAlertRow).externalKnowledgeStatus}</td></tr>
                          </tbody>
                        </table>
                      </div>

                      <h3>AI Evaluation Metrics</h3>
                      <div className="alert-rule-summary-grid">
                        <article className="alert-rule-summary-card">
                          <span>Overall Quality</span>
                          <strong>{formatQualityPercent(selectedAlertEvaluation.overallScore)}</strong>
                          <small>{selectedAlertEvaluation.qualityLabel} | {selectedAlertEvaluation.provider}</small>
                        </article>
                        <article className="alert-rule-summary-card">
                          <span>Confidence</span>
                          <strong>{formatQualityPercent(selectedAlertEvaluation.confidenceScore)}</strong>
                          <small>Recommendation certainty</small>
                        </article>
                        <article className="alert-rule-summary-card">
                          <span>Grounding</span>
                          <strong>{formatQualityPercent(selectedAlertEvaluation.groundingScore)}</strong>
                          <small>Evidence and context support</small>
                        </article>
                        <article className="alert-rule-summary-card">
                          <span>Hallucination Risk</span>
                          <strong>{formatQualityPercent(selectedAlertEvaluation.hallucinationRisk)}</strong>
                          <small>{selectedAlertEvaluation.requiresReview ? "review recommended" : "within guardrail"}</small>
                        </article>
                        <article className="alert-rule-summary-card">
                          <span>Citation Coverage</span>
                          <strong>{formatQualityPercent(selectedAlertEvaluation.citationCoverage)}</strong>
                          <small>{selectedAlertEvaluation.signals?.citations ?? "-"} citation(s)</small>
                        </article>
                        <article className="alert-rule-summary-card">
                          <span>Evidence Coverage</span>
                          <strong>{formatQualityPercent(selectedAlertEvaluation.evidenceCoverage)}</strong>
                          <small>{selectedAlertEvaluation.signals?.rag_matches ?? selectedAlertRagDocuments.length} RAG match(es)</small>
                        </article>
                      </div>

                      {selectedAlertDocumentContract ? (
                        <>
                          <h3>Enterprise Controls</h3>
                          <div className="alert-rule-summary-grid">
                            <article className="alert-rule-summary-card">
                              <span>Canonical Contract</span>
                              <strong>{selectedAlertDocumentContract.canonical_alert?.schema_version || "-"}</strong>
                              <small>{selectedAlertDocumentContract.canonical_alert?.alert_uid || selectedAlertId}</small>
                            </article>
                            <article className="alert-rule-summary-card">
                              <span>Governance</span>
                              <strong>{selectedAlertDocumentContract.governance?.agent_contract_version || "-"}</strong>
                              <small>Approval gate: {selectedAlertDocumentContract.governance?.approval_gate_required ? "required" : "not required"}</small>
                            </article>
                            <article className="alert-rule-summary-card">
                              <span>RBAC</span>
                              <strong>{selectedAlertDocumentContract.rbac?.risk_tier || "-"}</strong>
                              <small>Tenant: {selectedAlertDocumentContract.rbac?.tenant || "default"} | Env: {selectedAlertDocumentContract.rbac?.environment || "-"}</small>
                            </article>
                            <article className="alert-rule-summary-card">
                              <span>Trace Quality</span>
                              <strong>{selectedAlertDocumentContract.observability?.trace_id || "-"}</strong>
                              <small>{selectedAlertDocumentContract.observability?.quality_gate || "-"}</small>
                            </article>
                            <article className="alert-rule-summary-card">
                              <span>RAG Quality</span>
                              <strong>{selectedAlertDocumentContract.rag_quality?.contract_version || "-"}</strong>
                              <small>Linked docs: {selectedAlertDocumentContract.document_link_summary?.count ?? 0}</small>
                            </article>
                            <article className="alert-rule-summary-card">
                              <span>Remediation Safety</span>
                              <strong>{selectedAlertDocumentContract.remediation_safety?.contract_version || "-"}</strong>
                              <small>Dry run: {selectedAlertDocumentContract.remediation_safety?.dry_run_required ? "required" : "optional"}</small>
                            </article>
                          </div>
                        </>
                      ) : null}

                      <h3>Persisted Stage Completeness</h3>
                      {selectedStageCompleteness.loading ? <p className="subtitle">Loading stage completeness...</p> : null}
                      {selectedStageCompleteness.error ? <p className="error">{selectedStageCompleteness.error}</p> : null}
                      {selectedStageCompleteness.data ? (
                        <div className="table-wrap">
                          <table>
                            <thead>
                              <tr>
                                <th>Stage</th>
                                <th>Persisted</th>
                                <th>Matched Event Types</th>
                              </tr>
                            </thead>
                            <tbody>
                              {(selectedStageCompleteness.data?.stages || []).map((row, index) => (
                                <tr key={`stage-${row.stage || index}`}>
                                  <td>{row.label || row.stage || "-"}</td>
                                  <td>{row.persisted ? "yes" : "no"}</td>
                                  <td>{Array.isArray(row.matched_event_types) && row.matched_event_types.length ? row.matched_event_types.join(" | ") : "-"}</td>
                                </tr>
                              ))}
                              {!Array.isArray(selectedStageCompleteness.data?.stages) || !selectedStageCompleteness.data.stages.length ? (
                                <tr><td colSpan={3}>No persisted stage rows found for incident.</td></tr>
                              ) : null}
                            </tbody>
                          </table>
                        </div>
                      ) : null}

                      {selectedStageCompleteness.data ? (
                        <p className="subtitle">
                          Completion: {selectedStageCompleteness.data?.stage_completion?.completed ?? 0}/{selectedStageCompleteness.data?.stage_completion?.total ?? 0}
                          {" "}({selectedStageCompleteness.data?.stage_completion?.percentage ?? 0}%)
                        </p>
                      ) : null}
                      </details>
                    </>
                  ) : null}

                  {homeDetailTab === "timeline" ? (
                    <details className="panel incident-workspace-section workspace-collapsible evidence-workspace">
                      <summary className="panel-head">
                        <div>
                          <span className="workspace-section-number">02</span>
                          <h3>Evidence & Trust</h3>
                          <p>Canonical identity, traceability, linked knowledge, and evaluation quality.</p>
                        </div>
                        <span className="section-toggle-indicator" />
                      </summary>
                      <div className="table-wrap table-wrap-scroll-x">
                        <table>
                          <tbody>
                            <tr><th>Canonical Alert UID</th><td>{selectedAlertDocumentContract?.canonical_alert?.alert_uid || selectedAlertId || "-"}</td></tr>
                            <tr><th>Alert Type</th><td>{selectedAlertDocumentContract?.canonical_alert?.alert_type || selectedAlertRow?.name || "-"}</td></tr>
                            <tr><th>Service</th><td>{selectedAlertDocumentContract?.canonical_alert?.service || selectedAlertRow?.service || "-"}</td></tr>
                            <tr><th>Tenant / Environment</th><td>{selectedAlertDocumentContract?.canonical_alert?.tenant || "default"} / {selectedAlertDocumentContract?.canonical_alert?.environment || selectedAlertRow?.environment || "-"}</td></tr>
                            <tr><th>Trace ID</th><td>{selectedAlertDocumentContract?.observability?.trace_id || selectedAlertRow?.trace_id || "-"}</td></tr>
                            <tr><th>Correlation ID</th><td>{selectedAlertDocumentContract?.canonical_alert?.correlation_id || selectedAlertRow?.correlation_id || "-"}</td></tr>
                            <tr><th>Document Link Contract</th><td>{selectedAlertDocumentContract?.document_link_summary?.contract_version || "-"}</td></tr>
                            <tr><th>Linked Document Count</th><td>{selectedAlertRagDocuments.length}</td></tr>
                            <tr><th>Evaluation Contract</th><td>{selectedAlertEvaluation.contractVersion}</td></tr>
                            <tr><th>Overall Evaluation</th><td>{formatQualityPercent(selectedAlertEvaluation.overallScore)} ({selectedAlertEvaluation.qualityLabel})</td></tr>
                            <tr><th>Confidence Score</th><td>{formatQualityPercent(selectedAlertEvaluation.confidenceScore)}</td></tr>
                            <tr><th>Grounding Score</th><td>{formatQualityPercent(selectedAlertEvaluation.groundingScore)}</td></tr>
                            <tr><th>Hallucination Risk</th><td>{formatQualityPercent(selectedAlertEvaluation.hallucinationRisk)}</td></tr>
                            <tr><th>Citation Coverage</th><td>{formatQualityPercent(selectedAlertEvaluation.citationCoverage)}</td></tr>
                            <tr><th>Evidence Coverage</th><td>{formatQualityPercent(selectedAlertEvaluation.evidenceCoverage)}</td></tr>
                            <tr><th>External Judge</th><td>{selectedAlertEvaluation.externalJudge?.metric ? `${selectedAlertEvaluation.externalJudge.metric}: ${formatQualityPercent(selectedAlertEvaluation.externalJudge.score)}` : "not configured"}</td></tr>
                          </tbody>
                        </table>
                      </div>
                    </details>
                  ) : null}

                  {homeDetailTab === "timeline" ? (
                    <details className="panel incident-workspace-section workspace-collapsible approval-workspace" open>
                      <summary className="panel-head">
                        <div>
                          <span className="workspace-section-number">03</span>
                          <h3>Decision & Approval</h3>
                          <p>Review evidence quality and approve, reject, or modify the proposed response.</p>
                        </div>
                        <span className="section-toggle-indicator" />
                      </summary>
                      <div className="table-wrap">
                        <table>
                          <tbody>
                            <tr><th>Incident</th><td>{approvalForm.incident_id || selectedAlertWorkflow?.incident?.id || "-"}</td></tr>
                            <tr><th>Recommendation</th><td>{approvalForm.recommendation_id || "-"}</td></tr>
                            <tr><th>Current Approval Status</th><td>{selectedApprovalStatus || (selectedMatchedApproval ? "pending" : "not active")}</td></tr>
                            <tr><th>Role Eligible</th><td>{canUseApprovalActions ? "yes" : "no"}</td></tr>
                            <tr><th>Evaluation Quality</th><td>{formatQualityPercent(selectedAlertEvaluation.overallScore)} ({selectedAlertEvaluation.qualityLabel})</td></tr>
                            <tr><th>Grounding / Hallucination Risk</th><td>{formatQualityPercent(selectedAlertEvaluation.groundingScore)} / {formatQualityPercent(selectedAlertEvaluation.hallucinationRisk)}</td></tr>
                            <tr><th>Review Required</th><td>{selectedAlertEvaluation.requiresReview ? "yes" : "no"}</td></tr>
                          </tbody>
                        </table>
                      </div>
                      {canUseApprovalActions ? (
                        <form className="form" onSubmit={submitApproval}>
                          <div className="filter-grid">
                            <label>Action
                              <select value={approvalForm.action} onChange={(e) => setApprovalForm({ ...approvalForm, action: e.target.value })}>
                                <option value="approve">approve</option>
                                <option value="reject">reject</option>
                                <option value="modify">modify</option>
                              </select>
                            </label>
                            <label>Channel
                              <select value={approvalForm.channel} onChange={(e) => setApprovalForm({ ...approvalForm, channel: e.target.value })}>
                                <option value="web">web</option>
                                <option value="slack">slack</option>
                                <option value="teams">teams</option>
                                <option value="email">email</option>
                              </select>
                            </label>
                          </div>
                          {approvalForm.action === "modify" ? (
                            <label>Modified Action<textarea rows={2} value={approvalForm.modified_action} onChange={(e) => setApprovalForm({ ...approvalForm, modified_action: e.target.value })} /></label>
                          ) : null}
                          <label>Comment<textarea rows={2} value={approvalForm.comment} onChange={(e) => setApprovalForm({ ...approvalForm, comment: e.target.value })} /></label>
                          <button className="button-primary" type="submit" disabled={!approvalReady || approvalState.loading}>
                            {approvalState.loading ? "Submitting..." : "Submit Approval Action"}
                          </button>
                        </form>
                      ) : (
                        <p className="subtitle">Login with an approval-eligible role to submit actions. You can still view full approval context here.</p>
                      )}
                    </details>
                  ) : null}

                  {homeDetailTab === "timeline" ? (
                    <details className="panel alert-documents-panel incident-workspace-section workspace-collapsible">
                      <summary className="panel-head">
                        <div>
                          <h3>Alert Documents</h3>
                          <p>Download backend-linked documents for the selected alert.</p>
                        </div>
                        <span className="section-toggle-indicator" />
                      </summary>
                      {ragDocs.error ? <p className="error">{ragDocs.error}</p> : null}
                      {selectedAlertDocumentLinks.error ? (
                        <p className="subtitle">Backend document-link contract unavailable; using local fallback matcher. {selectedAlertDocumentLinks.error}</p>
                      ) : null}
                      {selectedAlertDocumentLinks.loading ? <p className="subtitle">Resolving linked documents from backend contract...</p> : null}
                      {selectedAlertDocumentContract?.document_link_summary ? (
                        <p className="subtitle">
                          Source: {selectedAlertDocumentContract.document_link_summary.source}
                          {" | "}Matches: {selectedAlertRagDocuments.length}
                          {" | "}Reasons: {(selectedAlertDocumentContract.document_link_summary.match_reasons || []).join(", ") || "-"}
                        </p>
                      ) : null}
                      {selectedAlertKnowledgeDocument ? (
                        <article className="alert-document-download-card alert-document-download-card-single">
                          <div>
                            <span className="workflow-pill workflow-pill-clear">knowledge document</span>
                            <span className="workflow-pill workflow-pill-idle" style={{ marginLeft: 6 }}>
                              {selectedAlertKnowledgeDocument.docs.length} source{selectedAlertKnowledgeDocument.docs.length === 1 ? "" : "s"}
                            </span>
                            <h4>{selectedAlertKnowledgeDocument.title}</h4>
                            <p>{selectedAlertKnowledgeDocument.summary}</p>
                          </div>
                          <div className="alert-document-meta">
                            <span>Alert: {selectedAlertId || "-"}</span>
                            <span>Service: {selectedAlertKnowledgeDocument.service || "-"}</span>
                            <span>Severity: {selectedAlertKnowledgeDocument.severity !== "-" ? selectedAlertKnowledgeDocument.severity : "-"}</span>
                            <span>Types: {selectedAlertKnowledgeDocument.kinds.join(", ") || "document"}</span>
                            <span>Match: {selectedAlertKnowledgeDocument.reasons.join(", ") || "backend-linked"} {selectedAlertKnowledgeDocument.confidence ? `(${Math.round(Number(selectedAlertKnowledgeDocument.confidence) * 100)}%)` : ""}</span>
                          </div>
                          <details className="alert-document-source-list">
                            <summary>Included backend document metadata</summary>
                            <div className="table-wrap" style={{ marginTop: 8 }}>
                              <table>
                                <thead>
                                  <tr><th>Type</th><th>Title</th><th>Path</th></tr>
                                </thead>
                                <tbody>
                                  {selectedAlertKnowledgeDocument.docs.map((doc, index) => (
                                    <tr key={`${doc?.path || doc?.title || "doc"}-${index}`}>
                                      <td>{doc?.kind || doc?.document_kind || "document"}</td>
                                      <td>{doc?.title || "-"}</td>
                                      <td>{doc?.path || "-"}</td>
                                    </tr>
                                  ))}
                                </tbody>
                              </table>
                            </div>
                          </details>
                          <button
                            type="button"
                            className="button-primary"
                            onClick={() => downloadConsolidatedAlertDocument(selectedAlertKnowledgeDocument.docs)}
                          >
                            Download Single Document
                          </button>
                        </article>
                      ) : (
                        <div className="alert-documents-empty">
                          <div>
                            <strong>No alert documents linked yet.</strong>
                            <p className="subtitle">
                              Use the same Provide Documents workflow for this alert to review the generated draft, upload content,
                              and save downloadable documents back to this tab.
                            </p>
                          </div>
                          <div className="alert-documents-kind-row">
                            {ALERT_DOC_KIND_OPTIONS.map((kind) => (
                              <span key={`empty-doc-kind-${kind}`}>{kind}</span>
                            ))}
                          </div>
                          <div className="alert-documents-empty-actions">
                            {canProvideAlertDocuments ? (
                              <button
                                type="button"
                                className="button-primary"
                                onClick={() => selectedAlertRow && openDocumentPrompt(selectedAlertRow)}
                                disabled={!selectedAlertRow || selectedAlertActionContext?.alertClosed}
                              >
                                Provide Documents
                              </button>
                            ) : (
                              <button type="button" className="button-secondary" onClick={() => setHomeDetailTab("timeline")}>
                                Escalate To L2/L3
                              </button>
                            )}
                          </div>
                          {selectedAlertActionContext?.alertClosed ? (
                            <p className="subtitle">This alert is closed, so document creation is disabled.</p>
                          ) : null}
                          {!canProvideAlertDocuments ? (
                            <p className="subtitle">L1 operators can monitor and escalate this alert. L2, L3, and Admin users can provide alert documents.</p>
                          ) : null}
                        </div>
                      )}
                    </details>
                  ) : null}

                  {homeDetailTab === "diagnostics" && diagnosticsDetailTab === "pipeline" ? (
                    <ApplicationSankeyFlow
                      workflow={selectedAlertWorkflow}
                      timelineRows={selectedAlertTimelineRows}
                      routing={selectedAlertRouting}
                      alertRows={monitorScopedAlerts}
                      selectedAlert={selectedAlertRow}
                      selectedAlertId={selectedAlertId}
                      onDrillTimeline={() => setDiagnosticsDetailTab("timeline")}
                    />
                  ) : null}

                  {homeDetailTab === "diagnostics" && diagnosticsDetailTab === "processing" ? (
                    <ProcessingFlowMap
                      workflow={selectedAlertWorkflow}
                      timelineRows={selectedAlertTimelineRows}
                      routing={selectedAlertRouting}
                      selectedAlert={selectedAlertRow}
                      selectedAlertId={selectedAlertId}
                      onDrillTimeline={() => setDiagnosticsDetailTab("timeline")}
                    />
                  ) : null}

                  {homeDetailTab === "diagnostics" && diagnosticsDetailTab === "timeline" ? (
                    <FlowTimelineGraph rows={selectedAlertTimelineRows} />
                  ) : null}

                  {homeDetailTab === "diagnostics" && diagnosticsDetailTab === "context" ? (
                    <ContextRetrievalGraph
                      workflow={selectedAlertWorkflow}
                      timelineRows={selectedAlertTimelineRows}
                      documents={selectedAlertRagDocuments}
                      evaluation={selectedAlertEvaluation}
                      documentContract={selectedAlertDocumentContract}
                      onLoadDocumentContent={loadRagDocumentContent}
                      onDownloadDocument={downloadRagDocument}
                    />
                  ) : null}

                  {homeDetailTab === "diagnostics" && diagnosticsDetailTab === "events" ? (
                    <AgentEventsGraph rows={selectedAlertEventsDisplay} />
                  ) : null}

                  {homeDetailTab === "diagnostics" && diagnosticsDetailTab === "finops" ? (
                    <>
                      <div className="metric-grid">
                        <div className="metric-card">
                          <span>Selected Router</span>
                          <strong>{modelProviderStatus?.data?.selected?.default || "-"}</strong>
                          <small>Default provider for new calls</small>
                        </div>
                        <div className="metric-card">
                          <span>Critical Provider</span>
                          <strong>{modelProviderStatus?.data?.selected?.critical || "-"}</strong>
                          <small>Used for critical incidents</small>
                        </div>
                        <div className="metric-card">
                          <span>Provider Health</span>
                          <strong>
                            {selectedModelProviderRows.filter((row) => row.configured && row.healthy && !row.circuitOpen).length}
                            /
                            {selectedModelProviderRows.filter((row) => row.configured).length}
                          </strong>
                          <small>{modelProviderStatus.error || "configured providers available"}</small>
                        </div>
                        <div className="metric-card">
                          <span>Fallback Rows</span>
                          <strong>{selectedFinopsDiagnostics.fallbackRows}</strong>
                          <small>Historical or deterministic fallback calls</small>
                        </div>
                      </div>
                      <div className="chip-row" style={{ margin: "10px 0 12px" }}>
                        {selectedModelProviderRows.map((row) => {
                          const ok = row.configured && row.healthy && !row.circuitOpen;
                          const label = ok ? "ready" : row.configured ? "degraded" : "not configured";
                          return (
                            <span
                              className={`workflow-pill ${ok ? "workflow-pill-active" : "workflow-pill-idle"}`}
                              key={`provider-${row.name}`}
                              title={row.reason || `${row.model}; failures=${row.failures}`}
                            >
                              {row.name}: {label}
                            </span>
                          );
                        })}
                      </div>
                      <div className="table-wrap table-wrap-scroll-x">
                        <table>
                          <thead>
                            <tr>
                              <th>Task</th>
                              <th>Provider</th>
                              <th>Model</th>
                              <th>Status</th>
                              <th>Input</th>
                              <th>Output</th>
                              <th>Cost USD</th>
                              <th>Notes</th>
                            </tr>
                          </thead>
                          <tbody>
                            {selectedAlertUsage.map((row, index) => (
                              <tr key={`usage-${index}`}>
                                <td>{row.task || "-"}</td>
                                <td>{row.provider || "-"}</td>
                                <td>{row.model || "-"}</td>
                                <td>
                                  <span className={`pill ${row.fallback ? "status-failed" : "status-approved"}`}>
                                    {row.fallback ? "fallback" : row.estimated ? "estimated" : "live"}
                                  </span>
                                </td>
                                <td>{row.input_tokens || "-"}</td>
                                <td>{row.output_tokens || "-"}</td>
                                <td>{row.total_cost_usd || "-"}</td>
                                <td>{compactText(row.note || (row.estimated ? "estimated usage" : ""), 140) || "-"}</td>
                              </tr>
                            ))}
                            {!selectedAlertUsage.length ? (
                              <tr>
                                <td colSpan={8}>No FinOps usage rows rendered for selected alert.</td>
                              </tr>
                            ) : null}
                          </tbody>
                        </table>
                      </div>
                      <p className="subtitle">
                        FinOps diagnostics: rendered={selectedFinopsDiagnostics.usageRows}, fallback_rows={selectedFinopsDiagnostics.fallbackRows}, workflow_calls={selectedFinopsDiagnostics.workflowCalls}, workflow_errors={selectedFinopsDiagnostics.workflowErrors}, recommendation_usage={selectedFinopsDiagnostics.recommendationUsage}, trace_calls={selectedFinopsDiagnostics.traceCalls}, trace_errors={selectedFinopsDiagnostics.traceErrors}
                      </p>
                      {!selectedAlertUsage.length ? (
                        <p className="subtitle">No usage rows means upstream services did not persist model usage/cost entries for this alert payload.</p>
                      ) : null}
                    </>
                  ) : null}

                  {homeDetailTab === "diagnostics" && diagnosticsDetailTab === "api" ? (
                    <div className="table-wrap">
                      <table>
                        <thead>
                          <tr>
                            <th>Time</th>
                            <th>Path</th>
                            <th>Status</th>
                            <th>Decision</th>
                            <th>Trace</th>
                          </tr>
                        </thead>
                        <tbody>
                          {gatewayRecent.rows.slice(0, 20).map((row, index) => (
                            <tr key={`api-${index}`}>
                              <td>{formatIstTimestamp(row.created_at)}</td>
                              <td>{row.path || "-"}</td>
                              <td>{row.status_code || "-"}</td>
                              <td>{row?.safety?.decision || "-"}</td>
                              <td>{row.trace_id || "-"}</td>
                            </tr>
                          ))}
                          {!gatewayRecent.rows.length ? (
                            <tr>
                              <td colSpan={5}>No API gateway events found. Refresh or invoke a gateway endpoint.</td>
                            </tr>
                          ) : null}
                        </tbody>
                      </table>
                    </div>
                  ) : null}

                  {homeDetailTab === "timeline" ? (
                    <>
                      <details className="panel remediation-workspace incident-workspace-section workspace-collapsible" open>
                        <summary className="panel-head">
                          <div>
                            <span className="workspace-section-number">04</span>
                            <h3>Resolution & Remediation</h3>
                            <p>Confirm the decision, review the guarded plan, execute, and validate recovery.</p>
                          </div>
                          <span className="section-toggle-indicator" />
                        </summary>
                        <div className="workflow-guide-grid remediation-flow-grid">
                          {selectedWorkflowFlowStages.map((stage) => (
                            <div className="workflow-guide-card remediation-flow-card" key={stage.id}>
                              <strong>{stage.label}</strong>
                              <span className={`workflow-pill workflow-pill-${stage.status}`}>{stage.status.toUpperCase()}</span>
                              <p>{stage.detail}</p>
                            </div>
                          ))}
                        </div>
                        <div className="table-wrap table-wrap-scroll-x remediation-service-flow">
                          <table>
                            <thead>
                              <tr>
                                <th>Backend Service</th>
                                <th>Consumes</th>
                                <th>Publishes</th>
                                <th>Processing Agent</th>
                              </tr>
                            </thead>
                            <tbody>
                              {SERVICE_TOPIC_FLOW.map((stage) => (
                                <tr key={`service-flow-${stage.service}`}>
                                  <td>{stage.service}</td>
                                  <td>{stage.consumes}</td>
                                  <td>{stage.publishes}</td>
                                  <td>{stage.agent}</td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                        <div className="filter-grid remediation-kpi-grid">
                          <div className="remediation-kpi">
                            <span>Incident</span>
                            <p>
                              <span className={`pill ${statusPillClass(selectedExecutionBreakdown.incidentStatus)}`}>
                                {selectedExecutionPlan.incidentStatus || "-"}
                              </span>
                            </p>
                          </div>
                          <div className="remediation-kpi">
                            <span>Approval</span>
                            <p>
                              <span className={`pill ${statusPillClass(selectedExecutionBreakdown.approvalStatus)}`}>
                                {selectedExecutionPlan.approvalStatus || "pending"}
                              </span>
                            </p>
                          </div>
                          <div className="remediation-kpi">
                            <span>Commands</span>
                            <p>{selectedExecutionBreakdown.commands.length}</p>
                          </div>
                          <div className="remediation-kpi">
                            <span>Scripts</span>
                            <p>{selectedExecutionBreakdown.scripts.length}</p>
                          </div>
                          <div className="remediation-kpi">
                            <span>Queries</span>
                            <p>{selectedExecutionBreakdown.queries.length}</p>
                          </div>
                        </div>
                        <p className="subtitle">
                          {selectedExecutionBreakdown.hasPlan
                            ? "Plan is ready. Modify commands, scripts, or validation queries before executing the approved run path."
                            : "No remediation plan is available yet. Ensure recommendation and workflow events have been generated."}
                        </p>
                        {selectedRemediationOutcome ? (
                          <div className={`remediation-outcome remediation-outcome-${selectedRemediationOutcome.status}`}>
                            <div>
                              <strong>{selectedRemediationOutcome.title}</strong>
                              <p>{selectedRemediationOutcome.detail}</p>
                            </div>
                            <dl>
                              <dt>Action</dt>
                              <dd>{selectedRemediationOutcome.actionType}</dd>
                              <dt>Target</dt>
                              <dd>{selectedRemediationOutcome.target}</dd>
                            </dl>
                          </div>
                        ) : null}
                        <article className="panel remediation-connection-panel">
                          <div className="panel-head">
                            <h3>Application Connection Details</h3>
                            <p>Execution target used for approval, dry-run context, and live executor dispatch.</p>
                          </div>
                          <div className="filter-grid">
                            <label>Application<input value={selectedApplicationConnection.application} readOnly /></label>
                            <label>Service<input value={selectedApplicationConnection.service} readOnly /></label>
                            <label>Environment<input value={selectedApplicationConnection.environment} readOnly /></label>
                            <label>Source<input value={selectedApplicationConnection.source} readOnly /></label>
                            <label>Connection Type<input value={remediationPlanEditor.connection_type} onChange={(e) => setRemediationPlanEditor((curr) => ({ ...curr, connection_type: e.target.value }))} /></label>
                            <label>Endpoint URL<input value={remediationPlanEditor.connection_url} placeholder="https://app-or-metrics-endpoint" onChange={(e) => setRemediationPlanEditor((curr) => ({ ...curr, connection_url: e.target.value }))} /></label>
                            <label>Namespace / Runtime<input value={remediationPlanEditor.namespace} placeholder="prod / namespace / resource group" onChange={(e) => setRemediationPlanEditor((curr) => ({ ...curr, namespace: e.target.value }))} /></label>
                          </div>
                        </article>
                        <article className="panel remediation-editor-panel">
                          <div className="panel-head">
                            <h3>Editable Remediation Script</h3>
                            <p>Review one guarded script with connection details. The approved edited script is submitted to the remediation engine.</p>
                          </div>
                          <div className="remediation-editor-grid">
                            <label>Single Remediation Script<textarea rows={8} value={remediationPlanEditor.scripts} onChange={(e) => setRemediationPlanEditor((curr) => ({ ...curr, scripts: e.target.value }))} /></label>
                            <label>Additional Commands<textarea rows={8} value={remediationPlanEditor.commands} onChange={(e) => setRemediationPlanEditor((curr) => ({ ...curr, commands: e.target.value }))} /></label>
                            <label>Additional Validation Queries<textarea rows={8} value={remediationPlanEditor.queries} onChange={(e) => setRemediationPlanEditor((curr) => ({ ...curr, queries: e.target.value }))} /></label>
                          </div>
                          <label>Execution Notes<textarea rows={2} value={remediationPlanEditor.notes} onChange={(e) => setRemediationPlanEditor((curr) => ({ ...curr, notes: e.target.value }))} /></label>
                          <div className="remediation-execute-row">
                            <button
                              type="button"
                              className="button-primary"
                              onClick={executeApprovedRemediationPlan}
                              disabled={remediationExecutionState.loading || !canUseApprovalActions}
                              title={canUseApprovalActions ? "Execute the approved edited plan through remediation-engine" : "Approval-eligible role required"}
                            >
                              {remediationExecutionState.loading ? "Executing..." : "Execute Approved Plan"}
                            </button>
                            <button
                              type="button"
                              className="button-secondary"
                              onClick={() => setRemediationPlanEditor((curr) => ({
                                ...curr,
                                commands: "",
                                scripts: selectedExecutionBreakdown.scripts.length
                                  ? selectedExecutionBreakdown.scripts.join("\n")
                                  : buildKaiOpsRemediationScript({
                                      service: selectedApplicationConnection.service !== "-" ? selectedApplicationConnection.service : selectedApplicationConnection.application,
                                      environment: selectedApplicationConnection.environment,
                                      apiGatewayUrl: "http://api-gateway:8000",
                                      prometheusUrl: selectedApplicationConnection.endpoint !== "Not configured"
                                        ? selectedApplicationConnection.endpoint
                                        : onboardingForm.prometheus_url || onboardingForm.monitoring_url || "http://prometheus:9090",
                                      mysqlHost: "mysql",
                                      mysqlDatabase: "kaiops",
                                      mysqlUser: "kaiops",
                                    }),
                                queries: "",
                              }))}
                              disabled={remediationExecutionState.loading}
                            >
                              Reset To Suggested Plan
                            </button>
                          </div>
                          {remediationExecutionState.error ? <p className="error">{remediationExecutionState.error}</p> : null}
                          {remediationExecutionState.result ? (
                            <pre className="result">{JSON.stringify(unwrap(remediationExecutionState.result), null, 2)}</pre>
                          ) : null}
                        </article>
                        <div className="table-wrap remediation-step-table" style={{ marginTop: 8 }}>
                          <table>
                            <thead>
                              <tr><th>Type</th><th>Step</th><th>Action</th></tr>
                            </thead>
                            <tbody>
                              {selectedExecutionBreakdown.commands.map((step, index) => (
                                <tr key={`summary-command-${index}`}>
                                  <td>Command</td>
                                  <td>{step}</td>
                                  <td><button type="button" className="button-secondary" onClick={() => copyPlanStep(step)}>Copy</button></td>
                                </tr>
                              ))}
                              {selectedExecutionBreakdown.scripts.map((step, index) => (
                                <tr key={`summary-script-${index}`}>
                                  <td>Script</td>
                                  <td>{step}</td>
                                  <td><button type="button" className="button-secondary" onClick={() => copyPlanStep(step)}>Copy</button></td>
                                </tr>
                              ))}
                              {selectedExecutionBreakdown.queries.map((step, index) => (
                                <tr key={`summary-query-${index}`}>
                                  <td>Query</td>
                                  <td>{step}</td>
                                  <td><button type="button" className="button-secondary" onClick={() => copyPlanStep(step)}>Copy</button></td>
                                </tr>
                              ))}
                              {!selectedExecutionBreakdown.hasPlan ? <tr><td colSpan={3}>No remediation steps available.</td></tr> : null}
                            </tbody>
                          </table>
                        </div>
                      </details>
                      <ExecutionPlanGraph plan={selectedExecutionPlan} />
                    </>
                  ) : null}

                  {homeDetailTab === "raw" ? (
                    <pre className="result">{JSON.stringify(selectedAlertData.payload || {}, null, 2)}</pre>
                  ) : null}
                </article>
              ) : (
                <article className="panel">
                  <p className="subtitle">Select an alert in Alert Stream to open the detail tabs workspace.</p>
                </article>
              )}
            </section>
          ) : null}

          {activeTab === "copilot" ? (
            <section className="grid single-col">
              <article className="panel copilot-panel">
                <div className="panel-head">
                  <h2>Copilot Studio</h2>
                  <p>One guided place to onboard projects, create alert documents, and manage users.</p>
                  <button className="button-secondary" onClick={refreshAll}>Refresh</button>
                </div>

                <div className="copilot-summary-grid">
                  <div className="copilot-summary-card copilot-tone-ops">
                    <strong>Project Onboarding</strong>
                    <span>Set project identity, environment, and monitoring endpoints.</span>
                    <button type="button" className="button-primary" onClick={() => openCopilotWorkspace("project")}>Open Unified Setup</button>
                  </div>
                  <div className="copilot-summary-card copilot-tone-bus">
                    <strong>Alert Documents</strong>
                    <span>Create onboarding docs and bulk alert knowledge from one place.</span>
                    <button type="button" className="button-primary" onClick={() => openCopilotWorkspace("alerts")}>Open Docs</button>
                  </div>
                  <div className={`copilot-summary-card ${isAdministrator ? "copilot-tone-meta" : "copilot-tone-muted"}`}>
                    <strong>User Management</strong>
                    <span>{isAdministrator ? "Create, edit, and reset users." : "Administrator-only control."}</span>
                    <button type="button" className="button-primary" onClick={() => openCopilotWorkspace("users")} disabled={!isAdministrator}>Open Users</button>
                  </div>
                </div>

                <div className="copilot-flow-grid">
                  <div className="copilot-flow-card">
                    <span className="copilot-step">1</span>
                    <div>
                      <strong>Start from a project</strong>
                      <p>Use the project onboarding form to register monitoring details and assignments.</p>
                    </div>
                  </div>
                  <div className="copilot-flow-card">
                    <span className="copilot-step">2</span>
                    <div>
                      <strong>Generate alert docs</strong>
                      <p>Write onboarding docs or bulk import runbook-style alert guidance.</p>
                    </div>
                  </div>
                  <div className="copilot-flow-card">
                    <span className="copilot-step">3</span>
                    <div>
                      <strong>Manage access</strong>
                      <p>Keep user roles, statuses, and passwords in the same workspace.</p>
                    </div>
                  </div>
                </div>

                <div className="copilot-shortcuts">
                  <button type="button" className="button-secondary" onClick={() => openCopilotWorkspace("project")}>Monitoring + Landing Pad Setup</button>
                  <button type="button" className="button-secondary" onClick={() => openCopilotWorkspace("alerts")}>Alert Documents</button>
                  <button type="button" className="button-secondary" onClick={() => openCopilotWorkspace("users")} disabled={!isAdministrator}>User Management</button>
                  <button type="button" className="button-secondary" onClick={() => setActiveTab("summary")}>Incident Metadata</button>
                </div>
              </article>
            </section>
          ) : null}

          {activeTab === "executive" ? (
            <section className="grid single-col">
              <article className="panel">
                <div className="panel-head">
                  <h2>Executive Dashboard</h2>
                  <p>Leadership-level snapshot of reliability, risk, and closure trend.</p>
                </div>
                <div className="stat-grid">
                  <div className="stat-card"><strong>Open Alerts</strong><span>{monitorScopedAlerts.length}</span></div>
                  <div className="stat-card"><strong>Total Requests</strong><span>{executiveMetrics.totalRequests}</span></div>
                  <div className="stat-card"><strong>Failures</strong><span>{executiveMetrics.failedRequests}</span></div>
                  <div className="stat-card"><strong>P95 Latency</strong><span>{executiveMetrics.p95LatencyMs.toFixed(1)} ms</span></div>
                  <div className="stat-card"><strong>Closed Tickets</strong><span>{executiveClosedSummary.total}</span></div>
                  <div className="stat-card"><strong>Closure Rate</strong><span>{executiveClosedSummary.closureRate.toFixed(1)}%</span></div>
                  <div className="stat-card"><strong>Pending Approvals</strong><span>{pendingApprovals.length}</span></div>
                  <div className="stat-card"><strong>SLA At Risk</strong><span>{executiveInsights.slaAtRisk}</span></div>
                  <div className="stat-card"><strong>Avg Approval Wait</strong><span>{executiveInsights.avgApprovalWaitMinutes.toFixed(1)} min</span></div>
                  <div className="stat-card"><strong>Auto Remediation</strong><span>{executiveInsights.automationRate.toFixed(1)}%</span></div>
                  <div className="stat-card"><strong>LLM Cost</strong><span>${executiveMetrics.finopsCost.toFixed(6)}</span></div>
                </div>

                <div className="executive-chart-grid">
                  <HorizontalBarChart
                    title="Request Volume"
                    subtitle="Observed API gateway events in current window"
                    items={[
                      { label: "Total", value: executiveMetrics.totalRequests, tone: "meta" },
                      { label: "Success", value: executiveMetrics.successRequests, tone: "ops" },
                      { label: "Failure", value: executiveMetrics.failedRequests, tone: "risk" },
                    ]}
                  />
                  <SuccessFailureDonut
                    success={executiveMetrics.successRequests}
                    failure={executiveMetrics.failedRequests}
                  />
                  <HorizontalBarChart
                    title="Latency Trend"
                    subtitle={`Avg ${executiveMetrics.avgLatencyMs.toFixed(1)} ms | P95 ${executiveMetrics.p95LatencyMs.toFixed(1)} ms`}
                    items={executiveMetrics.latencyTrend}
                  />
                  <HorizontalBarChart
                    title="FinOps Overview"
                    subtitle="Aggregated LLM usage and spend"
                    items={[
                      { label: "Model Calls", value: executiveMetrics.finopsCalls, tone: "meta" },
                      { label: "Tokens", value: executiveMetrics.finopsTokens, tone: "cost" },
                      {
                        label: "Cost USD",
                        value: executiveMetrics.finopsCost,
                        displayValue: `$${executiveMetrics.finopsCost.toFixed(6)}`,
                        tone: "bus",
                      },
                    ]}
                  />
                  <HorizontalBarChart
                    title="Closed Tickets by Risk"
                    subtitle="Recent closure distribution"
                    items={executiveClosedSummary.riskItems}
                  />
                  <HorizontalBarChart
                    title="Closed Tickets by Execution Mode"
                    subtitle="How incidents were handled"
                    items={executiveClosedSummary.modeItems}
                  />
                  <HorizontalBarChart
                    title="Weekly Open Incident Trend"
                    subtitle="Open incidents observed per day (7-day window)"
                    items={executiveInsights.weeklyOpenTrend}
                  />
                  <HorizontalBarChart
                    title="Weekly Closed Incident Trend"
                    subtitle="Closed incidents per day (7-day window)"
                    items={executiveInsights.weeklyClosedTrend}
                  />
                </div>

                <article className="panel executive-flow-panel">
                  <div className="panel-head">
                    <h3>End-to-End Processing + FinOps</h3>
                    <p>Landing pad ingestion, parallel worker processing, remediation execution, and cost visibility in one leadership view.</p>
                  </div>
                  <div className="workflow-guide-grid executive-flow-grid">
                    {selectedWorkflowFlowStages.map((stage) => (
                      <div className="workflow-guide-card executive-flow-card" key={`exec-flow-${stage.id}`}>
                        <strong>{stage.label}</strong>
                        <span className={`workflow-pill workflow-pill-${stage.status}`}>{stage.status.toUpperCase()}</span>
                        <p>{stage.detail}</p>
                      </div>
                    ))}
                  </div>
                  <div className="table-wrap table-wrap-scroll-x">
                    <table>
                      <thead>
                        <tr>
                          <th>Backend Service</th>
                          <th>Consumes</th>
                          <th>Publishes</th>
                          <th>Processing Agent</th>
                        </tr>
                      </thead>
                      <tbody>
                        {SERVICE_TOPIC_FLOW.map((stage) => (
                          <tr key={`exec-service-flow-${stage.service}`}>
                            <td>{stage.service}</td>
                            <td>{stage.consumes}</td>
                            <td>{stage.publishes}</td>
                            <td>{stage.agent}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                  <div className="table-wrap">
                    <table>
                      <thead>
                        <tr>
                          <th>Provider</th>
                          <th>Calls</th>
                          <th>Tokens</th>
                          <th>Cost USD</th>
                        </tr>
                      </thead>
                      <tbody>
                        {finopsByProvider.map((row, index) => (
                          <tr key={`exec-finops-${row.provider}-${index}`}>
                            <td>{row.provider}</td>
                            <td>{row.calls}</td>
                            <td>{row.total_tokens}</td>
                            <td>{Number(row.total_cost_usd || 0).toFixed(6)}</td>
                          </tr>
                        ))}
                        {!finopsByProvider.length ? (
                          <tr>
                            <td colSpan={4}>No model calls recorded yet.</td>
                          </tr>
                        ) : null}
                      </tbody>
                    </table>
                  </div>
                </article>

                <h3>Executive Risk & Operations Report</h3>
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th>Metric</th>
                        <th>Value</th>
                        <th>Interpretation</th>
                      </tr>
                    </thead>
                    <tbody>
                      <tr>
                        <td>SLA At Risk</td>
                        <td>{executiveInsights.slaAtRisk}</td>
                        <td>Open high/critical or manual-mode incidents that may affect business SLO/SLA outcomes.</td>
                      </tr>
                      <tr>
                        <td>Average Approval Wait</td>
                        <td>{executiveInsights.avgApprovalWaitMinutes.toFixed(1)} min</td>
                        <td>Mean time pending in approval queue; useful for governance and response speed tracking.</td>
                      </tr>
                      <tr>
                        <td>Auto Remediation Rate</td>
                        <td>{executiveInsights.automationRate.toFixed(1)}%</td>
                        <td>Share of closed incidents resolved using automatic execution modes.</td>
                      </tr>
                    </tbody>
                  </table>
                </div>

                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th>Incident</th>
                        <th>Service</th>
                        <th>Risk</th>
                        <th>Status</th>
                        <th>Execution Mode</th>
                        <th>Action</th>
                      </tr>
                    </thead>
                    <tbody>
                      {monitorScopedIncidentMetadata.slice(0, 20).map((row, index) => (
                        <tr key={`exec-${row.incident_id || index}`}>
                          <td>{row.incident_id || "-"}</td>
                          <td>{row.service || "-"}</td>
                          <td>{row.risk_tier || "-"}</td>
                          <td><span className={`pill ${statusPillClass(row.status)}`}>{row.status || "-"}</span></td>
                          <td>{row.execution_mode || "-"}</td>
                          <td>
                            <button type="button" className="button-secondary" onClick={() => openAlertDetailsFromIncident(row)}>
                              Open
                            </button>
                          </td>
                        </tr>
                      ))}
                      {!monitorScopedIncidentMetadata.length ? (
                        <tr>
                          <td colSpan={6}>No executive rows available for {applicationToMonitor}.</td>
                        </tr>
                      ) : null}
                    </tbody>
                  </table>
                </div>

                <h3>Recently Closed Tickets</h3>
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th>Incident</th>
                        <th>Service</th>
                        <th>Risk</th>
                        <th>Execution Mode</th>
                        <th>Status</th>
                        <th>Closed At</th>
                      </tr>
                    </thead>
                    <tbody>
                      {executiveClosedSummary.recentRows.map((row, index) => (
                        <tr key={`exec-closed-${row.incident_id || index}`}>
                          <td>{row.incident_id || "-"}</td>
                          <td>{row.service || "-"}</td>
                          <td>{row.risk_tier || row.risk || row.severity || "-"}</td>
                          <td>{row.execution_mode || "-"}</td>
                          <td><span className={`pill ${statusPillClass(row.status || "closed")}`}>{row.status || "closed"}</span></td>
                          <td>{formatIstTimestamp(row.closed_at || row.updated_at)}</td>
                        </tr>
                      ))}
                      {!executiveClosedSummary.recentRows.length ? (
                        <tr>
                          <td colSpan={6}>No closed tickets are available yet.</td>
                        </tr>
                      ) : null}
                    </tbody>
                  </table>
                </div>
              </article>
            </section>
          ) : null}

          {activeTab === "admin" && isAdministrator ? (
            <section className="grid single-col">
              <article className="panel admin-center-panel">
                <div className="panel-head">
                  <h2>Admin Center</h2>
                  <p>Three-step workspace for access, setup, and alert knowledge.</p>
                </div>

                <div className="admin-journey-grid">
                  {adminJourneyCards.map((step) => (
                    <article
                      key={`admin-journey-${step.id}`}
                      className={`admin-journey-card ${adminJourneyStep === step.id ? "active" : ""}`}
                    >
                      <strong>{step.title}</strong>
                      <span>{step.hint}</span>
                      <small>{step.status}</small>
                      <div className="admin-journey-meta">
                        <span className={`admin-journey-chip admin-journey-chip-${step.tone || "info"}`}>{step.tone || "info"}</span>
                        <span className={`workflow-pill ${step.complete ? "workflow-pill-active" : "workflow-pill-idle"}`}>
                          {step.complete ? "done" : "pending"}
                        </span>
                      </div>
                      <button
                        type="button"
                        className="button-secondary admin-journey-cta"
                        onClick={() => triggerAdminJourneyCta(step.id)}
                      >
                        {step.cta}
                      </button>
                    </article>
                  ))}
                </div>

                <p className="subtitle">Navigate by stage: Access handles identity, Setup covers landing pad and approvals, Knowledge stores alert intelligence.</p>
                <p className="subtitle"><strong>Current Stage:</strong> {adminWorkspaceCaptions[adminWorkspace] || "Administrative workspace controls."}</p>

                {adminWorkspace === "users" ? (
                  <div className="grid single-col">
                    <article className="panel">
                      <h3>Session</h3>
                      {adminSession.user ? <p className="subtitle">Signed in as {adminSession.user.username} ({adminSession.user.role_name})</p> : null}
                      {adminSession.error ? <p className="error">{adminSession.error}</p> : null}
                    </article>

                    <article className="panel">
                      <div className="panel-head">
                        <h3>Users</h3>
                        <button className="button-secondary" type="button" onClick={loadAdminUsersAndRoles} disabled={!adminSession.accessToken || adminUsers.loading}>Refresh</button>
                      </div>
                      {adminUsers.error ? <p className="error">{adminUsers.error}</p> : null}
                      {adminUsers.loading ? <p className="subtitle">Loading users and roles...</p> : null}
                      {!adminUsers.loading && !adminUsers.error && !adminUsers.rows.length ? (
                        <div className="empty-state-panel">
                          <strong>No users are shown yet</strong>
                          <span>Refresh access controls to load seeded users, or create a new user below.</span>
                          <button className="button-secondary" type="button" onClick={loadAdminUsersAndRoles} disabled={!adminSession.accessToken}>
                            Refresh Users
                          </button>
                        </div>
                      ) : null}
                      <div className="table-wrap table-wrap-scroll-x">
                        <table>
                          <thead>
                            <tr><th>ID</th><th>Username</th><th>Email</th><th>Role</th><th>Status</th><th>Active</th><th>Actions</th></tr>
                          </thead>
                          <tbody>
                            {adminUsers.rows.map((row, index) => (
                              <tr key={`admin-user-${row.id || index}`}>
                                <td>{row.id || "-"}</td><td>{row.username || "-"}</td><td>{row.email || "-"}</td><td>{row.role_name || row.role_id || "-"}</td><td>{row.status || "-"}</td><td>{row.is_active ? "yes" : "no"}</td>
                                <td><button type="button" className="button-secondary" onClick={() => selectAdminUserForEdit(row)}>Edit</button></td>
                              </tr>
                            ))}
                            {!adminUsers.rows.length && adminUsers.loading ? <tr><td colSpan={7}>Loading users...</td></tr> : null}
                            {!adminUsers.rows.length && !adminUsers.loading && adminUsers.error ? <tr><td colSpan={7}>Unable to load users. Review the error above.</td></tr> : null}
                            {!adminUsers.rows.length && !adminUsers.loading && !adminUsers.error ? <tr><td colSpan={7}>No users returned yet. Use Refresh Users or create a user.</td></tr> : null}
                          </tbody>
                        </table>
                      </div>
                    </article>

                    <article className="panel">
                      <h3>Create User</h3>
                      <details className="admin-collapsible" open>
                        <summary>Create New User</summary>
                        <form className="form" onSubmit={createAdminUser}>
                          <div className="filter-grid">
                            <label>Username<input value={adminCreateUser.username} onChange={(e) => setAdminCreateUser((curr) => ({ ...curr, username: e.target.value }))} /></label>
                            <label>Email<input value={adminCreateUser.email} onChange={(e) => setAdminCreateUser((curr) => ({ ...curr, email: e.target.value }))} /></label>
                            <label>First Name<input value={adminCreateUser.first_name} onChange={(e) => setAdminCreateUser((curr) => ({ ...curr, first_name: e.target.value }))} /></label>
                            <label>Last Name<input value={adminCreateUser.last_name} onChange={(e) => setAdminCreateUser((curr) => ({ ...curr, last_name: e.target.value }))} /></label>
                          </div>
                          <div className="filter-grid">
                            <label>Password<input type="password" value={adminCreateUser.password} onChange={(e) => setAdminCreateUser((curr) => ({ ...curr, password: e.target.value }))} /></label>
                            <label>Role
                              <select value={adminCreateUser.role_id} onChange={(e) => setAdminCreateUser((curr) => ({ ...curr, role_id: Number(e.target.value) }))}>
                                {(adminRoles.length ? adminRoles : [{ id: 1, name: "administrator" }]).map((role) => (
                                  <option key={`role-${role.id}`} value={role.id}>{role.name}</option>
                                ))}
                              </select>
                            </label>
                            <label>Status<input value={adminCreateUser.status} onChange={(e) => setAdminCreateUser((curr) => ({ ...curr, status: e.target.value }))} /></label>
                            <label>Active
                              <select value={String(adminCreateUser.is_active)} onChange={(e) => setAdminCreateUser((curr) => ({ ...curr, is_active: e.target.value === "true" }))}>
                                <option value="true">true</option><option value="false">false</option>
                              </select>
                            </label>
                          </div>
                          <button className="button-primary" type="submit" disabled={!adminSession.accessToken || adminUsers.loading}>Create User</button>
                        </form>
                      </details>
                    </article>

                    <article className="panel">
                      <h3>Modify User</h3>
                      <details className="admin-collapsible" open={adminEditPanelOpen} onToggle={(event) => setAdminEditPanelOpen(event.currentTarget.open)}>
                        <summary>Edit Existing User</summary>
                        <form className="form" onSubmit={updateAdminUser}>
                          <div className="filter-grid">
                            <label>User ID<input value={adminEditUser.id || ""} readOnly /></label>
                            <label>Username<input value={adminEditUser.username} readOnly /></label>
                            <label>Email<input value={adminEditUser.email} onChange={(e) => setAdminEditUser((curr) => ({ ...curr, email: e.target.value }))} /></label>
                            <label>Role
                              <select value={adminEditUser.role_id} onChange={(e) => setAdminEditUser((curr) => ({ ...curr, role_id: Number(e.target.value) }))}>
                                {(adminRoles.length ? adminRoles : [{ id: 1, name: "Administrator" }]).map((role) => (
                                  <option key={`edit-role-${role.id}`} value={role.id}>{role.name}</option>
                                ))}
                              </select>
                            </label>
                          </div>
                          <div className="filter-grid">
                            <label>First Name<input value={adminEditUser.first_name} onChange={(e) => setAdminEditUser((curr) => ({ ...curr, first_name: e.target.value }))} /></label>
                            <label>Last Name<input value={adminEditUser.last_name} onChange={(e) => setAdminEditUser((curr) => ({ ...curr, last_name: e.target.value }))} /></label>
                            <label>Status
                              <select value={adminEditUser.status} onChange={(e) => setAdminEditUser((curr) => ({ ...curr, status: e.target.value, is_active: e.target.value === "active" }))}>
                                <option value="active">active</option>
                                <option value="inactive">inactive</option>
                                <option value="suspended">suspended</option>
                              </select>
                            </label>
                            <label>Active
                              <select value={String(adminEditUser.is_active)} onChange={(e) => {
                                const isActive = e.target.value === "true";
                                setAdminEditUser((curr) => ({ ...curr, is_active: isActive, status: isActive ? "active" : "inactive" }));
                              }}>
                                <option value="true">true</option><option value="false">false</option>
                              </select>
                            </label>
                          </div>
                          <button className="button-primary" type="submit" disabled={!adminSession.accessToken || adminUsers.loading || !adminEditUser.id}>Update User</button>
                        </form>
                      </details>
                    </article>

                    <article className="panel">
                      <h3>Reset Password</h3>
                      <details className="admin-collapsible">
                        <summary>Reset User Password</summary>
                        <form className="form" onSubmit={resetAdminUserPassword}>
                          <div className="filter-grid">
                            <label>User ID<input value={adminResetPasswordForm.user_id || ""} readOnly /></label>
                            <label>New Password<input type="password" value={adminResetPasswordForm.new_password} onChange={(e) => setAdminResetPasswordForm((curr) => ({ ...curr, new_password: e.target.value }))} /></label>
                          </div>
                          <button className="button-primary" type="submit" disabled={!adminSession.accessToken || adminUsers.loading || !adminResetPasswordForm.user_id || !String(adminResetPasswordForm.new_password || "").trim()}>Reset Password</button>
                        </form>
                      </details>
                    </article>
                  </div>

                ) : null}

                {adminWorkspace === "project" ? (
                  <div className="grid single-col admin-flow-section admin-flow-project">
                    <article className="panel project-stepper-panel">
                      <div className="panel-head">
                        <div>
                          <h3>Setup Wizard</h3>
                          <p>Start with one plain-English setup prompt. KaiOps auto-completes details, scores the document, asks for missing values, then validates and updates knowledge/rules.</p>
                        </div>
                        <button
                          type="button"
                          className={`setup-section-icon-button ${projectSetupShowAll ? "active" : ""}`}
                          aria-label={projectSetupShowAll ? "Focus current setup step" : "Show full setup"}
                          title={projectSetupShowAll ? "Focus current step" : "Show full setup"}
                          onClick={() => setProjectSetupShowAll((current) => !current)}
                        />
                      </div>
                      <div className="setup-wizard-summary">
                        <div>
                          <span>Project</span>
                          <strong>{String(onboardingForm.name || selectedOnboardingProject || "Not selected")}</strong>
                        </div>
                        <div>
                          <span>Path</span>
                          <strong>{onboardingForm.onboarding_path === "setup_monitoring" ? "Prometheus setup" : "Existing monitoring"}</strong>
                        </div>
                        <div>
                          <span>Service Knowledge</span>
                          <strong>{knowledgePackState.approved ? "approved" : onboardingKnowledgePack?.status || (onboardingSourceDocCount > 0 ? "added" : "missing")}</strong>
                        </div>
                        <div>
                          <span>Generated Rules</span>
                          <strong>{onboardingGeneratedRuleRows.length}</strong>
                        </div>
                      </div>
                      <div className="project-stepper-grid">
                        {projectStepCards.map((card) => (
                          <button
                            key={`project-step-${card.id}`}
                            type="button"
                            className={`project-step-card ${projectSetupStep === card.id ? "active" : ""}`}
                            onClick={() => {
                              setProjectSetupStep(card.id);
                              setProjectSetupShowAll(false);
                              if (card.id === "knowledge") {
                                setAlertKnowledgeView("onboarding");
                              }
                            }}
                          >
                            <strong>{card.label}</strong>
                            <span>{card.hint}</span>
                            <span className={`workflow-pill ${card.complete ? "workflow-pill-active" : "workflow-pill-idle"}`}>
                              {card.complete ? "done" : "pending"}
                            </span>
                          </button>
                        ))}
                      </div>
                    </article>
                    {showProjectStep("setup") ? (
                    <article className="panel">
                      <div className="panel-head">
                        <div>
                          <h3>Setup Monitoring</h3>
                          <p>Choose the monitoring path, enter the tool endpoint, and save the landing-pad setup.</p>
                        </div>
                        <div style={{ display: "flex", gap: 8 }}>
                          <button type="button" className="button-secondary" onClick={loadOnboardingAdminData}>Refresh</button>
                          <button
                            type="button"
                            className="button-secondary"
                            onClick={() => deleteProjectOnboarding(selectedOnboardingProject || onboardingForm.name)}
                            disabled={onboardingProjectMode === "new" || onboardingState.loading || !String(selectedOnboardingProject || onboardingForm.name || "").trim()}
                          >
                            Delete Project
                          </button>
                        </div>
                      </div>
                      <div className="filter-grid">
                        <label>
                          Project Mode
                          <select
                            value={onboardingProjectMode}
                            onChange={(e) => {
                              const nextMode = e.target.value;
                              setOnboardingProjectMode(nextMode);
                              if (nextMode === "new") {
                                resetNewProjectOnboardingDraft();
                              }
                            }}
                          >
                            <option value="existing">Update Existing Project</option>
                            <option value="new">Create New Project</option>
                          </select>
                        </label>
                        <div style={{ display: "flex", alignItems: "end" }}>
                          <button type="button" className="button-secondary" onClick={resetNewProjectOnboardingDraft}>
                            Clear Form
                          </button>
                        </div>
                      </div>
                      <p className="subtitle"><strong>Next:</strong> Save monitoring, then add Service Knowledge in Documents & Rules.</p>
                      {onboardingDocumentSummary.total > 0 ? <p className="subtitle"><strong>Docs:</strong> {onboardingDocumentSummary.total} generated ({onboardingDocumentSummary.approved ? "approved" : "pending"}).</p> : null}
                      {onboardingProjectMode === "existing" ? (
                        <div className="filter-grid">
                        <label>
                          Select Existing Project
                          <select
                            value={selectedOnboardingProject}
                            onChange={(e) => {
                              const nextProjectName = e.target.value;
                              setSelectedOnboardingProject(nextProjectName);
                              const row = (onboardingState.rows || []).find((item) => extractOnboardingProjectName(item) === nextProjectName);
                              if (row) {
                                applyProjectOnboardingRow(row);
                                return;
                              }
                              setOnboardingForm((curr) => ({
                                ...curr,
                                name: nextProjectName,
                                assignment_project: nextProjectName,
                              }));
                            }}
                          >
                            <option value="">Select project</option>
                            {onboardingProjectOptions.map((name, index) => (
                              <option key={`project-select-${name}-${index}`} value={name}>{name}</option>
                            ))}
                          </select>
                        </label>
                        </div>
                      ) : null}
                      <form className="form" onSubmit={saveOnboardingConnectivity}>
                        {onboardingValidationErrors.length ? (
                          <div>
                            {onboardingValidationErrors.map((msg, index) => <p key={`onboarding-error-${index}`} className="error">{msg}</p>)}
                          </div>
                        ) : null}
                        {onboardingHasPendingDocumentApproval ? (
                          <p className="error">Approve pending generated documents before submitting another Create/Update.</p>
                        ) : null}
                        {onboardingAdvisory ? <p className="subtitle">{onboardingAdvisory}</p> : null}
                        <details className="setup-form-section" open>
                          <summary>
                            <span>Project Details</span>
                            <small>Required identity fields</small>
                          </summary>
                        <div className="filter-grid">
                          <label>Project Name *<input placeholder="example-payments" value={onboardingForm.name} onChange={(e) => setOnboardingForm((curr) => ({ ...curr, name: e.target.value, assignment_project: e.target.value }))} /></label>
                          <label>Owner Team *<input placeholder="sre-platform" value={onboardingForm.owner_team} onChange={(e) => setOnboardingForm((curr) => ({ ...curr, owner_team: e.target.value }))} /></label>
                          <label>Environment<select value={onboardingForm.environment} onChange={(e) => setOnboardingForm((curr) => ({ ...curr, environment: e.target.value }))}><option value="dev">dev</option><option value="staging">staging</option><option value="prod">prod</option></select></label>
                          <label>Region *<input placeholder="ap-south-1" value={onboardingForm.region} onChange={(e) => setOnboardingForm((curr) => ({ ...curr, region: e.target.value }))} /></label>
                        </div>
                        <details className="setup-nested-details">
                          <summary>Advanced Settings (Optional)</summary>
                          <div className="filter-grid" style={{ marginTop: 10 }}>
                            <label>Deployment
                              <select value={onboardingForm.deployment_mode} onChange={(e) => setOnboardingForm((curr) => ({ ...curr, deployment_mode: e.target.value }))}>
                                <option value="on_prem">On-Prem</option>
                                <option value="azure_cloud">Azure Cloud</option>
                              </select>
                            </label>
                            <label>Assign User (optional)<input placeholder="username" value={onboardingForm.assignment_username} onChange={(e) => setOnboardingForm((curr) => ({ ...curr, assignment_username: e.target.value }))} /></label>
                          </div>
                          {onboardingForm.deployment_mode === "azure_cloud" ? (
                            <div className="filter-grid" style={{ marginTop: 10 }}>
                              <label>Azure Subscription ID<input value={onboardingForm.azure_subscription_id} onChange={(e) => setOnboardingForm((curr) => ({ ...curr, azure_subscription_id: e.target.value }))} /></label>
                              <label>Azure Resource Group<input value={onboardingForm.azure_resource_group} onChange={(e) => setOnboardingForm((curr) => ({ ...curr, azure_resource_group: e.target.value }))} /></label>
                              <label>Service Bus Namespace<input value={onboardingForm.azure_service_bus_namespace} onChange={(e) => setOnboardingForm((curr) => ({ ...curr, azure_service_bus_namespace: e.target.value }))} /></label>
                              <label>Service Bus Topic<input value={onboardingForm.azure_service_bus_topic} onChange={(e) => setOnboardingForm((curr) => ({ ...curr, azure_service_bus_topic: e.target.value }))} /></label>
                              <label>Service Bus Subscription<input value={onboardingForm.azure_service_bus_subscription} onChange={(e) => setOnboardingForm((curr) => ({ ...curr, azure_service_bus_subscription: e.target.value }))} /></label>
                            </div>
                          ) : null}
                          {onboardingForm.deployment_mode === "azure_cloud" ? (
                            <div className="filter-grid" style={{ marginTop: 10 }}>
                              <label>Azure Content Safety
                                <select value={String(onboardingForm.azure_content_safety_enabled)} onChange={(e) => setOnboardingForm((curr) => ({ ...curr, azure_content_safety_enabled: e.target.value === "true" }))}>
                                  <option value="false">disabled</option>
                                  <option value="true">enabled</option>
                                </select>
                              </label>
                              <label>Content Safety Endpoint<input value={onboardingForm.azure_content_safety_endpoint} onChange={(e) => setOnboardingForm((curr) => ({ ...curr, azure_content_safety_endpoint: e.target.value }))} /></label>
                            </div>
                          ) : null}
                        </details>
                        </details>
                        <details className="setup-form-section" open>
                          <summary>
                            <span>Monitoring Option</span>
                            <small>Choose one</small>
                          </summary>
                          <div className="panel-head">
                            <h3>Monitoring Option</h3>
                          </div>
                          <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                            <button
                              type="button"
                              className={onboardingForm.onboarding_path === "setup_monitoring" ? "button-primary" : "button-secondary"}
                              onClick={() => {
                                setOnboardingForm((curr) => ({
                                  ...curr,
                                  onboarding_path: "setup_monitoring",
                                  start_rule_onboarding: true,
                                  monitoring_tool: "prometheus",
                                  prometheus_url: curr.monitoring_url,
                                }));
                                setNewRulePipelineForm((curr) => ({ ...curr, selected_tool: "prometheus" }));
                                setExistingRulePipelineForm((curr) => ({ ...curr, platform: "prometheus" }));
                              }}
                            >
                              Configure Prometheus Rules
                            </button>
                            <button
                              type="button"
                              className={onboardingForm.onboarding_path === "existing_monitoring" ? "button-primary" : "button-secondary"}
                              onClick={() => setOnboardingForm((curr) => ({ ...curr, onboarding_path: "existing_monitoring", start_rule_onboarding: false }))}
                            >
                              Use Existing Monitoring Tool
                            </button>
                          </div>
                          <p className="subtitle" style={{ marginTop: 8 }}>
                            {onboardingForm.onboarding_path === "setup_monitoring"
                              ? "KaiOps will generate Prometheus rules from the Documents & Rules step."
                              : "Keep your current monitoring tool and send alert webhooks to KaiOps landing pad."}
                          </p>
                          <div className="setup-message-bus-preview">
                            <div className="setup-route-strip" aria-label="Landing pad event route">
                              <span>Monitoring Tool</span>
                              <i />
                              <span>Landing Pad</span>
                              <i />
                              <span>Alert Workflow</span>
                              <i />
                              <span>Workers</span>
                            </div>
                            <p className="subtitle">
                              Routing is configured after this setup is saved.
                            </p>
                            <details className="setup-bus-details">
                              <summary>Event Bus Topology</summary>
                              <MessageBusTopology
                                actual={messageBusActual}
                                configuredRows={messageBusTopicRows}
                                routing={observedRouting}
                                primaryTopic={onboardingForm.azure_service_bus_topic || "raw-alerts"}
                                compact
                              />
                            </details>
                            <details className="setup-bus-details">
                              <summary>Scale And VM Config</summary>
                              <div className="scale-current-config">
                                <strong>Current Compose Default</strong>
                                <span>1 orchestrator/master container with <code>MESSAGE_BUS_WORKER_COUNT=1</code> per service. The scale overlay raises service worker counts without changing onboarding flow.</span>
                              </div>
                              <div className="scale-guide-grid">
                                {SCALE_CAPACITY_GUIDE.map((row) => (
                                  <div className="scale-guide-card" key={row.rate}>
                                    <div className="scale-guide-rate">
                                      <strong>{row.rate}</strong>
                                      <span>{row.perSecond}</span>
                                    </div>
                                    <dl>
                                      <div>
                                        <dt>Masters</dt>
                                        <dd>{row.masters}</dd>
                                      </div>
                                      <div>
                                        <dt>Workers</dt>
                                        <dd>{row.workers}</dd>
                                      </div>
                                      <div>
                                        <dt>VM Config</dt>
                                        <dd>{row.vm}</dd>
                                      </div>
                                      <div>
                                        <dt>Runtime Config</dt>
                                        <dd><code>{row.config}</code></dd>
                                      </div>
                                      <div>
                                        <dt>State Services</dt>
                                        <dd>{row.state}</dd>
                                      </div>
                                    </dl>
                                  </div>
                                ))}
                              </div>
                              <div className="scale-guide-command">
                                <strong>Compose overlay</strong>
                                <code>docker compose --env-file .env -f docker-compose.yml -f docker-compose.external-state.yml -f docker-compose.scale.yml up -d --build</code>
                              </div>
                            </details>
                          </div>
                        </details>
                        <details className="setup-form-section">
                          <summary>
                            <span>Landing Pad Details</span>
                            <small>Endpoint and sample payload for alert ingestion</small>
                          </summary>
                          <div className="panel-head">
                            <h3>Landing Pad Details</h3>
                            <p>Endpoint and payload guidance for alert ingestion into KaiOps workflow. Troubleshooting runbooks for ingested alerts are managed under Alert Knowledge.</p>
                          </div>
                          <div className="filter-grid">
                            <label>Ingestion Endpoint (UI/Gateway)
                              <input value={onboardingLandingPadDetails.externalIngestionEndpoint} readOnly />
                            </label>
                            <label>Ingestion Endpoint (Container Network)
                              <input value={onboardingLandingPadDetails.internalIngestionEndpoint} readOnly />
                            </label>
                            <label>Method
                              <input value={onboardingLandingPadDetails.method} readOnly />
                            </label>
                            <label>Content Type
                              <input value={onboardingLandingPadDetails.contentType} readOnly />
                            </label>
                            {onboardingForm.onboarding_path === "existing_monitoring" ? (
                              <>
                                <label>Selected Monitoring Tool
                                  <input value={onboardingLandingPadDetails.selectedTool} readOnly />
                                </label>
                                <label>Configured Tool Endpoint
                                  <input value={onboardingLandingPadDetails.configuredEndpoint} readOnly />
                                </label>
                              </>
                            ) : null}
                          </div>
                          <p className="subtitle"><strong>Optional Header:</strong> {onboardingLandingPadDetails.traceHeader}</p>
                          <p className="subtitle"><strong>Required Body:</strong> JSON payload with an alerts array.</p>
                          <p className="subtitle"><strong>Flow Note:</strong> {onboardingLandingPadDetails.routeMessage}</p>
                          {onboardingLandingPadDetails.onboardingPath === "existing_monitoring" ? (
                            <p className="subtitle">Use this endpoint from your monitoring platform webhook to start landing-pad ingestion.</p>
                          ) : (
                            <p className="subtitle">Rule setup path is selected; this endpoint becomes active after rule and monitoring setup are completed.</p>
                          )}
                          <pre className="result">{onboardingLandingPadDetails.samplePayload}</pre>
                        </details>
                        <details className="setup-form-section">
                          <summary>
                            <span>Connection Details</span>
                            <small>Endpoint metadata</small>
                          </summary>
                        <div className="filter-grid">
                          {onboardingForm.onboarding_path === "existing_monitoring" ? (
                            <label>
                              Monitoring Tool
                              <select
                                value={onboardingForm.monitoring_tool}
                                onChange={(e) => {
                                  const nextTool = e.target.value;
                                  setOnboardingForm((curr) => ({
                                    ...curr,
                                    monitoring_tool: nextTool,
                                    prometheus_url: nextTool === "prometheus" ? curr.monitoring_url : "",
                                    new_relic_url: nextTool === "new_relic" ? curr.monitoring_url : "",
                                    datadog_url: nextTool === "datadog" ? curr.monitoring_url : "",
                                  }));
                                  setNewRulePipelineForm((curr) => ({ ...curr, selected_tool: nextTool }));
                                  setExistingRulePipelineForm((curr) => ({ ...curr, platform: nextTool }));
                                }}
                              >
                                <option value="prometheus">Prometheus</option>
                                <option value="new_relic">New Relic</option>
                                <option value="datadog">Datadog</option>
                              </select>
                            </label>
                          ) : (
                            <label>
                              Monitoring Tool
                              <input value="prometheus" readOnly />
                            </label>
                          )}
                          <label>
                            {onboardingForm.onboarding_path === "setup_monitoring" ? "Prometheus Endpoint URL" : "Tool Endpoint URL (optional)"}
                            <input
                              value={onboardingForm.monitoring_url}
                              placeholder="http://prometheus:9090"
                              onBlur={(e) => {
                                const normalized = simplifyMonitoringUrl(e.target.value);
                                setOnboardingForm((curr) => ({
                                  ...curr,
                                  monitoring_url: normalized,
                                  prometheus_url: curr.monitoring_tool === "prometheus" ? normalized : "",
                                  new_relic_url: curr.monitoring_tool === "new_relic" ? normalized : "",
                                  datadog_url: curr.monitoring_tool === "datadog" ? normalized : "",
                                }));
                                setExistingRulePipelineForm((curr) => ({ ...curr, connection_url: normalized }));
                              }}
                              onChange={(e) => setOnboardingForm((curr) => ({ ...curr, monitoring_url: e.target.value }))}
                            />
                            <span className="field-hint">
                              {onboardingForm.onboarding_path === "setup_monitoring"
                                ? "Required for Prometheus rule setup. In Docker Compose, use http://prometheus:9090."
                                : "Optional. If provided, KaiOps stores endpoint metadata for your existing monitoring tool."}
                            </span>
                          </label>
                        </div>
                        {onboardingForm.onboarding_path !== "setup_monitoring" ? (
                          <p className="subtitle">Alerts from your configured monitoring tool can be ingested into landing pad to trigger the remaining workflow.</p>
                        ) : null}
                        </details>
                        <button className="button-primary" type="submit" disabled={onboardingState.loading || onboardingValidationErrors.length > 0 || onboardingHasPendingDocumentApproval}>
                          {onboardingState.loading ? "Saving..." : onboardingProjectMode === "new" ? "Create Monitoring Setup" : "Save Monitoring Setup"}
                        </button>
                      </form>
                      {onboardingState.error ? <p className="error">{onboardingState.error}</p> : null}
                      {onboardingState.success ? <p className="subtitle">{onboardingState.success}</p> : null}
                    </article>
                    ) : null}

                    {showProjectStep("docs_rules") ? (
                    <article className="panel">
                      <div className="panel-head">
                        <div>
                          <h3>Guided Setup</h3>
                          <p>Enter the service details once. KaiOps extracts project, monitoring, alert, remediation, rollback, and validation facts.</p>
                        </div>
                        <button type="button" className="button-secondary" onClick={() => setProjectSetupStep("setup")}>Connection Setup</button>
                      </div>
                      <form className="form" onSubmit={saveOnboardingConnectivity}>
                        {onboardingValidationErrors.length ? (
                          <div>
                            {onboardingValidationErrors.map((msg, index) => <p key={`docs-rules-error-${index}`} className="error">{msg}</p>)}
                          </div>
                        ) : null}
                        {onboardingHasPendingDocumentApproval ? (
                          <p className="error">Approve pending generated documents before submitting another update.</p>
                        ) : null}
                        <section className="panel guided-setup-project-panel">
                          <div className="panel-head">
                            <div>
                              <h3>Project & Connection</h3>
                              <p>Select an existing project or create a new one. Prometheus is used when KaiOps creates monitoring rules.</p>
                            </div>
                            <span className={`workflow-pill ${onboardingProjectMode === "new" ? "workflow-pill-active" : "workflow-pill-idle"}`}>
                              {onboardingProjectMode === "new" ? "new project" : "existing project"}
                            </span>
                          </div>
                          <div className="filter-grid">
                            <label>
                              Project Mode
                              <select
                                value={onboardingProjectMode}
                                onChange={(e) => {
                                  const nextMode = e.target.value;
                                  setOnboardingProjectMode(nextMode);
                                  if (nextMode === "new") {
                                    resetNewProjectOnboardingDraft();
                                  }
                                }}
                              >
                                <option value="existing">Update Existing Project</option>
                                <option value="new">Create New Project</option>
                              </select>
                            </label>
                            {onboardingProjectMode === "existing" ? (
                              <label>
                                Select Project
                                <select
                                  value={selectedOnboardingProject}
                                  onChange={(e) => {
                                    const nextProjectName = e.target.value;
                                    setSelectedOnboardingProject(nextProjectName);
                                    const row = (onboardingState.rows || []).find((item) => extractOnboardingProjectName(item) === nextProjectName);
                                    if (row) {
                                      applyProjectOnboardingRow(row);
                                      return;
                                    }
                                    setOnboardingForm((curr) => ({
                                      ...curr,
                                      name: nextProjectName,
                                      assignment_project: nextProjectName,
                                    }));
                                  }}
                                >
                                  <option value="">Select project</option>
                                  {onboardingProjectOptions.map((name, index) => (
                                    <option key={`guided-project-select-${name}-${index}`} value={name}>{name}</option>
                                  ))}
                                </select>
                              </label>
                            ) : null}
                            <label>Project Name *<input placeholder="mysql-exporter" value={onboardingForm.name} onChange={(e) => setOnboardingForm((curr) => ({ ...curr, name: e.target.value, assignment_project: e.target.value }))} /></label>
                            <label>Owner Team *<input placeholder="data-platform" value={onboardingForm.owner_team} onChange={(e) => setOnboardingForm((curr) => ({ ...curr, owner_team: e.target.value }))} /></label>
                            <label>Environment<select value={onboardingForm.environment} onChange={(e) => setOnboardingForm((curr) => ({ ...curr, environment: e.target.value }))}><option value="dev">dev</option><option value="staging">staging</option><option value="prod">prod</option></select></label>
                            <label>Region *<input placeholder="ap-south-1" value={onboardingForm.region} onChange={(e) => setOnboardingForm((curr) => ({ ...curr, region: e.target.value }))} /></label>
                            <label>
                              Setup Path
                              <select
                                value={onboardingForm.onboarding_path}
                                onChange={(e) => {
                                  const nextPath = e.target.value;
                                  const defaultUrl = nextPath === "setup_monitoring" ? "http://prometheus:9090" : onboardingForm.monitoring_url;
                                  setOnboardingForm((curr) => ({
                                    ...curr,
                                    onboarding_path: nextPath,
                                    start_rule_onboarding: nextPath === "setup_monitoring",
                                    monitoring_tool: nextPath === "setup_monitoring" ? "prometheus" : curr.monitoring_tool,
                                    monitoring_url: simplifyMonitoringUrl(defaultUrl || curr.monitoring_url),
                                    prometheus_url: nextPath === "setup_monitoring" ? simplifyMonitoringUrl(defaultUrl || curr.monitoring_url) : curr.prometheus_url,
                                  }));
                                  if (nextPath === "setup_monitoring") {
                                    setNewRulePipelineForm((curr) => ({ ...curr, selected_tool: "prometheus" }));
                                    setExistingRulePipelineForm((curr) => ({ ...curr, platform: "prometheus", connection_url: simplifyMonitoringUrl(defaultUrl || "") }));
                                  }
                                }}
                              >
                                <option value="setup_monitoring">Create Prometheus Rules</option>
                                <option value="existing_monitoring">Use Existing Monitoring Webhook</option>
                              </select>
                            </label>
                            {onboardingForm.onboarding_path === "existing_monitoring" ? (
                              <label>
                                Monitoring Tool
                                <select
                                  value={onboardingForm.monitoring_tool}
                                  onChange={(e) => {
                                    const nextTool = e.target.value;
                                    setOnboardingForm((curr) => ({
                                      ...curr,
                                      monitoring_tool: nextTool,
                                      prometheus_url: nextTool === "prometheus" ? curr.monitoring_url : "",
                                      new_relic_url: nextTool === "new_relic" ? curr.monitoring_url : "",
                                      datadog_url: nextTool === "datadog" ? curr.monitoring_url : "",
                                    }));
                                    setNewRulePipelineForm((curr) => ({ ...curr, selected_tool: nextTool }));
                                    setExistingRulePipelineForm((curr) => ({ ...curr, platform: nextTool }));
                                  }}
                                >
                                  <option value="prometheus">Prometheus</option>
                                  <option value="new_relic">New Relic</option>
                                  <option value="datadog">Datadog</option>
                                </select>
                              </label>
                            ) : (
                              <label>Monitoring Tool<input value="Prometheus" readOnly /></label>
                            )}
                            <label>
                              Prometheus / Tool URL
                              <input
                                value={onboardingForm.monitoring_url}
                                placeholder="http://prometheus:9090"
                                onBlur={(e) => {
                                  const normalized = simplifyMonitoringUrl(e.target.value || (onboardingForm.onboarding_path === "setup_monitoring" ? "http://prometheus:9090" : ""));
                                  setOnboardingForm((curr) => ({
                                    ...curr,
                                    monitoring_url: normalized,
                                    prometheus_url: curr.monitoring_tool === "prometheus" ? normalized : "",
                                    new_relic_url: curr.monitoring_tool === "new_relic" ? normalized : "",
                                    datadog_url: curr.monitoring_tool === "datadog" ? normalized : "",
                                  }));
                                  setExistingRulePipelineForm((curr) => ({ ...curr, connection_url: normalized }));
                                }}
                                onChange={(e) => setOnboardingForm((curr) => ({ ...curr, monitoring_url: e.target.value }))}
                              />
                            </label>
                          </div>
                        </section>
                        <details className="setup-form-section setup-source-doc-panel knowledge-guided-panel" open>
                          <summary>
                            <span>Setup Prompt</span>
                            <small>Describe, auto-complete, score, validate</small>
                          </summary>
                          <div className="panel-head">
                            <div>
                              <h3>Tell KaiOps What To Set Up</h3>
                              <p>Paste a short description or runbook notes. KaiOps will complete the setup form and ask only for missing or low-confidence fields.</p>
                            </div>
                            <button
                              type="button"
                              className="button-secondary"
                              onClick={applyUploadedDocumentsToRuleIntent}
                              disabled={!onboardingDerivedRequirements.length}
                            >
                              Apply To Rules
                            </button>
                          </div>
                          <div className="setup-flow-rail">
                            <div className={`setup-flow-node ${onboardingSourceDocCount > 0 ? "complete" : "active"}`}>
                              <strong>Describe</strong>
                              <span>{onboardingSourceDocCount > 0 ? "Input captured" : "Prompt or file"}</span>
                            </div>
                            <div className={`setup-flow-node ${onboardingKnowledgePack ? "complete" : ""}`}>
                              <strong>Score</strong>
                              <span>{onboardingKnowledgePack ? `${Math.round(Number(correctedKnowledgeConfidence || 0) * 100)}% document score` : "Waiting"}</span>
                            </div>
                            <div className={`setup-flow-node ${knowledgePackState.approved ? "complete" : ""}`}>
                              <strong>Update</strong>
                              <span>{knowledgePackState.approved ? "Knowledge updated" : knowledgeReviewReady ? "Ready to validate" : "Needs placeholders"}</span>
                            </div>
                          </div>
                          <div className="knowledge-guided-prompt">
                            <label>
                              Setup Details
                              <textarea
                                rows={7}
                                placeholder="Example: Set up monitoring for mysql-exporter in prod. Owner is data-platform. Prometheus URL is http://prometheus:9090. Alert when exporter is down for 5 minutes or table rows grow unexpectedly. Dependencies are MySQL, Prometheus, and Grafana. Validate /metrics, Prometheus target up, DB connectivity, and row-count query. Rollback by restoring previous exporter config and restarting exporter."
                                value={onboardingForm.service_knowledge_prompt}
                                onChange={(event) => setOnboardingForm((curr) => ({ ...curr, service_knowledge_prompt: event.target.value }))}
                              />
                              <span className="field-hint">Use plain English. KaiOps extracts setup fields, creates placeholders for missing values, and prepares rules from this prompt.</span>
                            </label>
                            <button
                              type="button"
                              className="button-primary"
                              onClick={draftKnowledgePackFromPrompt}
                              disabled={knowledgePackState.loading || !String(onboardingForm.service_knowledge_prompt || "").trim()}
                            >
                              {knowledgePackState.loading ? "Extracting..." : "Auto-Complete Setup"}
                            </button>
                          </div>
                          <p className="knowledge-review-status">{knowledgeReviewSummary}</p>
                          {onboardingKnowledgePack ? (
                            <div className="alert-rule-summary-grid">
                              <article className="alert-rule-summary-card">
                                <span>Document Score</span>
                                <strong>{Math.round(Number(correctedKnowledgeConfidence || 0) * 100)}%</strong>
                                <small>{knowledgeReviewReady ? "ready to validate" : `${knowledgeReviewFields.length} placeholder(s) need input`}</small>
                              </article>
                              <article className="alert-rule-summary-card">
                                <span>Setup Identity</span>
                                <strong>{onboardingForm.name || "-"}</strong>
                                <small>{onboardingForm.owner_team || "-"} | {onboardingForm.environment || "-"}</small>
                              </article>
                              <article className="alert-rule-summary-card">
                                <span>Rules Draft</span>
                                <strong>{onboardingRulePromptLines.length}</strong>
                                <small>plain-English rule intent(s)</small>
                              </article>
                            </div>
                          ) : null}
                          <details className="admin-collapsible knowledge-supporting-docs">
                            <summary>Optional supporting file</summary>
                            <div className="knowledge-pack-panel">
                              <div className="knowledge-pack-upload">
                              <label className="source-doc-upload-card source-doc-upload-card-wide">
                                <span>Add a runbook, ticket export, or notes file</span>
                                <input
                                  type="file"
                                  accept=".txt,.md,.markdown,.json,.csv,.log,.yaml,.yml"
                                  onChange={(e) => handleOnboardingSourceDocuments(e.target.files, "knowledge_pack")}
                                />
                                <small>Optional. Use this only when the prompt does not contain enough detail.</small>
                              </label>
                              <div className="knowledge-pack-samples">
                                <a className="source-doc-download" href={ONBOARDING_SOURCE_DOC_SAMPLE_FILES.troubleshooting.href} download>
                                  Download sample file
                                </a>
                              </div>
                            </div>
                            <div className="knowledge-pack-status">
                              <span className={`workflow-pill ${onboardingKnowledgePack?.status === "ready" || knowledgePackState.approved ? "workflow-pill-active" : "workflow-pill-idle"}`}>
                                {knowledgePackState.approved ? "approved" : onboardingKnowledgePack?.status || "waiting"}
                              </span>
                              <strong>{onboardingSourceDocCount > 0 ? "Input ready" : "No supporting file"}</strong>
                              <small>Confidence {Math.round(Number(correctedKnowledgeConfidence || 0) * 100)}%</small>
                            </div>
                            </div>
                          </details>
                          {onboardingSourceDocs.loading ? <p className="subtitle">Reading uploaded file...</p> : null}
                          {onboardingSourceDocs.error ? <p className="error">{onboardingSourceDocs.error}</p> : null}
                          {knowledgePackState.loading ? <p className="subtitle">Validating Service Knowledge...</p> : null}
                          {knowledgePackState.error ? <p className="error">{knowledgePackState.error}</p> : null}
                          {knowledgePackState.success ? <p className="subtitle">{knowledgePackState.success}</p> : null}
                          {onboardingKnowledgePack ? (
                            <div className="knowledge-pack-review">
                              <div className="panel-head">
                                <div>
                                  <h3>Review Extracted Details</h3>
                                  <p>Fill placeholders or correct extracted details. Validation updates trusted Alert Knowledge and unlocks document/rule generation.</p>
                                </div>
                                <button
                                  type="button"
                                  className="button-secondary"
                                  onClick={revalidateKnowledgeCorrections}
                                  disabled={knowledgePackRevalidation.loading || !Object.keys(knowledgePackCorrections).length}
                                  title="Re-check your manual edits against the uploaded documents before approving."
                                >
                                  {knowledgePackRevalidation.loading ? "Checking against document..." : "Check Edits Against Document"}
                                </button>
                                <button
                                  type="button"
                                  className="button-primary"
                                  onClick={approveKnowledgePack}
                                  disabled={knowledgePackState.loading || !onboardingSourceDocCount || !knowledgeReviewReady}
                                  title={!knowledgeReviewReady ? "Fill the requested missing details, then Check Edits Against Document before approving." : ""}
                                >
                                  Validate & Update Knowledge
                                </button>
                              </div>
                              {knowledgePackRevalidation.error ? (
                                <p className="error">{knowledgePackRevalidation.error}</p>
                              ) : null}
                              {knowledgeReviewFields.length ? (
                                <div className="knowledge-pack-fix-panel">
                                  <div>
                                    <strong>Questions To Complete Validation</strong>
                                    <span>Complete these placeholders so the saved document has enough evidence and operator-safe remediation context.</span>
                                  </div>
                                  <div className="knowledge-pack-fix-grid">
                                    {knowledgeReviewFields.map(([key, fact]) => (
                                      <label key={`docs-rules-fix-${key}`}>
                                        {KNOWLEDGE_FACT_QUESTIONS[key] || `Provide ${KNOWLEDGE_FACT_LABELS[key] || key.replaceAll("_", " ")}`}
                                        <textarea
                                          rows={KNOWLEDGE_LIST_FACTS.has(key) ? 3 : 2}
                                          placeholder={KNOWLEDGE_FACT_HINTS[key] || "Provide the correct value"}
                                          value={knowledgeFactEditValue(key, fact)}
                                          onChange={(event) => updateKnowledgeFactCorrection(key, event.target.value)}
                                        />
                                        <small>Extracted: {knowledgeFactDisplayValue(fact)} | confidence {Math.round(Number(fact?.confidence || 0) * 100)}%</small>
                                      </label>
                                    ))}
                                  </div>
                                </div>
                              ) : (
                                <p className="subtitle">All required details are accepted. You can approve Service Knowledge.</p>
                              )}
                              <div className="table-wrap">
                                <table>
                                  <thead>
                                    <tr><th>Detail</th><th>Editable Value</th><th>Confidence</th><th>Status</th></tr>
                                  </thead>
                                  <tbody>
                                    {Object.entries(correctedKnowledgeFacts).map(([key, fact]) => (
                                      <tr key={`docs-rules-fact-${key}`}>
                                        <td>{key.replaceAll("_", " ")}</td>
                                        <td>
                                          <textarea
                                            className="inline-table-editor"
                                            rows={KNOWLEDGE_LIST_FACTS.has(key) ? 3 : 1}
                                            placeholder={KNOWLEDGE_FACT_HINTS[key] || "Provide the correct value"}
                                            value={knowledgeFactEditValue(key, fact)}
                                            onChange={(event) => updateKnowledgeFactCorrection(key, event.target.value)}
                                          />
                                        </td>
                                        <td>{Math.round(Number(fact?.confidence || 0) * 100)}%</td>
                                        <td>{String(fact?.status || "needs_review").replaceAll("_", " ")}</td>
                                      </tr>
                                    ))}
                                  </tbody>
                                </table>
                              </div>
                            </div>
                          ) : null}
                        </details>
                        <details className={`setup-form-section rule-prompt-panel ${onboardingRulePromptVisible ? "ready" : "locked"}`} open={onboardingRulePromptVisible}>
                          <summary>
                            <span>Rules</span>
                            <small>{onboardingRulePromptVisible ? "Review and edit before generating" : "Upload Service Knowledge or type rule intent"}</small>
                          </summary>
                          <div className="panel-head">
                            <div>
                              <h3>Rule Intent</h3>
                              <p>Use extracted hints or type plain-English rules. KaiOps previews the Prometheus format before generation.</p>
                            </div>
                            <span className={`workflow-pill ${onboardingRulePromptVisible ? "workflow-pill-active" : "workflow-pill-idle"}`}>
                              {onboardingRulePromptVisible ? "ready" : "optional"}
                            </span>
                          </div>
                          {onboardingRulePromptLines.length ? (
                            <div className="generated-rule-preview">
                              {onboardingRulePromptLines.slice(0, 4).map((line, index) => (
                                <span key={`docs-rules-prompt-line-${index}`}>{line}</span>
                              ))}
                            </div>
                          ) : null}
                          <label>
                            Rule Intent
                            <textarea
                              rows={5}
                              placeholder="Example: Alert when mysql exporter is down for 5 minutes."
                              value={onboardingForm.rule_onboarding_plain_language}
                              onChange={(e) => {
                                const nextText = e.target.value;
                                setOnboardingForm((curr) => ({ ...curr, rule_onboarding_plain_language: nextText }));
                                setNewRulePipelineForm((curr) => ({ ...curr, requirements_text: nextText }));
                              }}
                            />
                          </label>
                          {onboardingForm.onboarding_path === "setup_monitoring" ? (
                            <div className="knowledge-pack-review">
                              <div className="panel-head">
                                <div>
                                  <h3>Prometheus Rule Preview</h3>
                                  <p>Final rules are validated by the backend and written to the Prometheus rules workspace.</p>
                                </div>
                                <span className="workflow-pill workflow-pill-active">yaml</span>
                              </div>
                              <pre className="result">{onboardingPrometheusRulePreview}</pre>
                            </div>
                          ) : null}
                        </details>
                        <button
                          className="button-primary"
                          type="submit"
                          disabled={onboardingState.loading || onboardingValidationErrors.length > 0 || onboardingHasPendingDocumentApproval || knowledgeHasUnvalidatedInput}
                          title={knowledgeHasUnvalidatedInput ? "Validate and save extracted Alert Knowledge first." : ""}
                        >
                          {onboardingState.loading ? "Generating..." : "Generate Documents & Rules"}
                        </button>
                        {knowledgeHasUnvalidatedInput ? (
                          <p className="subtitle onboarding-review-warning">Validation required: answer the questions above and click Validate & Save Knowledge before generating artifacts.</p>
                        ) : null}
                        {!knowledgeHasUnvalidatedInput && onboardingValidationErrors.length > 0 ? (
                          <p className="subtitle onboarding-review-warning">{onboardingValidationErrors[0]}</p>
                        ) : null}
                      </form>
                      {onboardingState.error ? <p className="error">{onboardingState.error}</p> : null}
                      {onboardingState.success ? <p className="subtitle">{onboardingState.success}</p> : null}
                    </article>
                    ) : null}

                    {(showProjectStep("review") || (adminWorkspace === "project" && projectSetupStep === "docs_rules" && onboardingGeneratedDocs.length > 0)) ? (
                    <article className="panel onboarding-review-panel">
                      <div className="panel-head">
                        <h3>Generated Rules, Docs, and Metadata Review (Required)</h3>
                        <div style={{ display: "flex", gap: 8 }}>
                          <button
                            type="button"
                            className="button-secondary"
                            onClick={() => {
                              setOnboardingGeneratedDocs([]);
                              setOnboardingDocApprovalState({ loading: false, error: "", success: "", approved: false });
                            }}
                            disabled={!onboardingGeneratedDocs.length || onboardingDocApprovalState.loading}
                          >
                            Clear
                          </button>
                          <button
                            type="button"
                            className="button-primary"
                            onClick={approveGeneratedOnboardingDocuments}
                            disabled={!onboardingGeneratedDocs.length || onboardingDocApprovalState.loading || onboardingDocApprovalState.approved || !onboardingReviewGate.allReviewed}
                          >
                            {onboardingDocApprovalState.loading ? "Approving..." : onboardingDocApprovalState.approved ? "Approved" : "Approve Documents"}
                          </button>
                        </div>
                      </div>
                      <p className="subtitle">After Create/Update Project: review generated artifacts, confirm each checklist item, then click Approve Documents.</p>
                      <div className="filter-grid onboarding-review-checklist" style={{ marginBottom: 8 }}>
                        <label>
                          <input
                            type="checkbox"
                            checked={onboardingReviewAck.rules}
                            onChange={(e) => setOnboardingReviewAck((current) => ({ ...current, rules: e.target.checked }))}
                            disabled={!onboardingGeneratedRuleRows.length}
                          />
                          I reviewed generated rules
                        </label>
                        <label>
                          <input
                            type="checkbox"
                            checked={onboardingReviewAck.docs}
                            onChange={(e) => setOnboardingReviewAck((current) => ({ ...current, docs: e.target.checked }))}
                            disabled={!onboardingGeneratedDocs.length}
                          />
                          I reviewed generated docs
                        </label>
                        <label>
                          <input
                            type="checkbox"
                            checked={onboardingReviewAck.metadata}
                            onChange={(e) => setOnboardingReviewAck((current) => ({ ...current, metadata: e.target.checked }))}
                            disabled={!onboardingMetadataRows.length}
                          />
                          I reviewed generated metadata
                        </label>
                      </div>
                      {!onboardingReviewGate.allReviewed ? <p className="subtitle onboarding-review-warning">Approval is locked until all available review checkboxes are confirmed.</p> : null}
                      {onboardingDocApprovalState.error ? <p className="error">{onboardingDocApprovalState.error}</p> : null}
                      {onboardingDocApprovalState.success ? <p className="subtitle">{onboardingDocApprovalState.success}</p> : null}
                      {!onboardingGeneratedDocs.length ? (
                        <p className="subtitle">No documents pending review.</p>
                      ) : (
                        <div className="table-wrap">
                          <table>
                            <thead>
                              <tr>
                                <th>Kind</th>
                                <th>Title</th>
                                <th>Summary</th>
                              </tr>
                            </thead>
                            <tbody>
                              {onboardingGeneratedDocs.map((doc, index) => (
                                <tr key={`onboarding-doc-${index}`}>
                                  <td>{String(doc?.kind || "-")}</td>
                                  <td>{String(doc?.title || "-")}</td>
                                  <td>{String(doc?.summary || "-")}</td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      )}
                      {onboardingGeneratedDocs.length ? (
                        <details style={{ marginTop: 12 }}>
                          <summary style={{ cursor: "pointer" }}>View Full Documents JSON</summary>
                          <pre className="result">{JSON.stringify(onboardingGeneratedDocs, null, 2)}</pre>
                        </details>
                      ) : null}
                      <details className="onboarding-review-details" style={{ marginTop: 12 }}>
                        <summary style={{ cursor: "pointer" }}>Generated Rules Review ({onboardingGeneratedRuleRows.length})</summary>
                        <div className="table-wrap" style={{ marginTop: 8 }}>
                          <table>
                            <thead>
                              <tr>
                                <th>Name</th>
                                <th>Platform</th>
                                <th>Adapter</th>
                                <th>Severity</th>
                                <th>Status</th>
                                <th>Expression / Query</th>
                              </tr>
                            </thead>
                            <tbody>
                              {onboardingGeneratedRuleRows.map((row) => (
                                <tr key={`generated-rule-${row.id}`}>
                                  <td>{row.name}</td>
                                  <td>{row.platform}</td>
                                  <td>{row.contractMode !== "-" ? `${row.contractMode} / ${row.contractStatus}` : "-"}</td>
                                  <td>{row.severity}</td>
                                  <td>{row.status}</td>
                                  <td>{row.expression || "-"}</td>
                                </tr>
                              ))}
                              {!onboardingGeneratedRuleRows.length ? <tr><td colSpan={6}>No generated rule rows found in latest workflow payload.</td></tr> : null}
                            </tbody>
                          </table>
                        </div>
                      </details>
                      <details className="onboarding-review-details" style={{ marginTop: 12 }}>
                        <summary style={{ cursor: "pointer" }}>Generated Metadata Review ({onboardingMetadataRows.length})</summary>
                        <div className="table-wrap" style={{ marginTop: 8 }}>
                          <table>
                            <thead>
                              <tr>
                                <th>Provider</th>
                                <th>Project</th>
                                <th>Status</th>
                                <th>Updated</th>
                              </tr>
                            </thead>
                            <tbody>
                              {onboardingMetadataRows.map((row) => (
                                <tr key={`generated-meta-${row.id}`}>
                                  <td>{row.provider}</td>
                                  <td>{row.project}</td>
                                  <td>{row.status}</td>
                                  <td>{formatIstTimestamp(row.updated_at)}</td>
                                </tr>
                              ))}
                              {!onboardingMetadataRows.length ? <tr><td colSpan={4}>No metadata rows found for selected project yet.</td></tr> : null}
                            </tbody>
                          </table>
                        </div>
                      </details>
                      <div style={{ display: "flex", justifyContent: "flex-end", marginTop: 10 }}>
                        <button type="button" className="button-secondary" onClick={() => setProjectSetupStep("status")}>Next: Workflow Status</button>
                      </div>
                    </article>
                    ) : null}

                    {showProjectStep("status") ? (
                    <article className="panel">
                      <h3>Rule Onboarding Status</h3>
                      <p className="subtitle">Rule onboarding is optional. If enabled above, plain-language requirements are converted into tool-specific rules and documentation automatically.</p>
                      {onboardingDocApprovalState.approved || knowledgePackState.approved || onboardingWorkflowSteps.length > 0 ? (
                        <div className="setup-complete-panel">
                          <div>
                            <span className="workflow-pill workflow-pill-active">ready</span>
                            <h3>{currentOnboardedApplicationName() || "Application"} setup is ready</h3>
                            <p>
                              Monitoring setup, Service Knowledge, generated rules, and approved documents are now connected to the selected application workspace.
                            </p>
                          </div>
                          <div className="setup-complete-actions">
                            <button type="button" className="button-primary" onClick={() => openOnboardedApplicationDashboard()}>
                              Open Application Dashboard
                            </button>
                            <button type="button" className="button-secondary" onClick={() => setProjectSetupStep("docs_rules")}>
                              Back To Documents & Rules
                            </button>
                          </div>
                        </div>
                      ) : null}
                      <HistoricalTicketDiscoveryPanel
                        applicationId={selectedMonitoringAppId}
                        applicationName={currentOnboardedApplicationName() || onboardingForm.name}
                        documents={ragDocs.rows}
                        loading={ragDocs.loading}
                      />
                      <h3>Step-by-Step Workflow Progress</h3>
                      <div className="monitoring-dashboard-cards">
                        {monitoringAppDetails.dashboards.map((row, index) => (
                          <article className="monitoring-dashboard-card" key={`monitoring-dashboard-card-${row.id || index}`}>
                            <span>Generated Dashboard</span>
                            <strong>{row.title || row.dashboard_uid || "Dashboard"}</strong>
                            <small>UID: {row.dashboard_uid || "-"}</small>
                            <small>Updated: {formatIstTimestamp(row.updated_at)}</small>
                            {row.url ? (
                              <button type="button" className="button-secondary" onClick={() => openOnboardedApplicationDashboard(row.url)}>Open Dashboard</button>
                            ) : (
                              <button type="button" className="button-secondary" onClick={() => openOnboardedApplicationDashboard()}>Open Dashboard</button>
                            )}
                          </article>
                        ))}
                        {!monitoringAppDetails.dashboards.length ? (
                          <article className="monitoring-dashboard-card empty">
                            <span>Dashboard Status</span>
                            <strong>No dashboards generated yet</strong>
                            <small>Register an application and validate metrics to generate dashboard references.</small>
                            <button type="button" className="button-secondary" onClick={() => openOnboardedApplicationDashboard()}>Open Application Dashboard</button>
                          </article>
                        ) : null}
                      </div>
                      <div className="table-wrap">
                        <table>
                          <thead>
                            <tr>
                              <th>Step</th>
                              <th>Status</th>
                              <th>What Happened</th>
                              <th>Background</th>
                            </tr>
                          </thead>
                          <tbody>
                            {(() => {
                              const isSetupMonitoring = String(onboardingForm.onboarding_path || "setup_monitoring").trim() === "setup_monitoring";
                              const selectedName = currentOnboardedApplicationName() || onboardingForm.name;
                              const discoveryDoc = findHistoricalTicketDiscoveryDocument(ragDocs.rows, selectedMonitoringAppId, selectedName);
                              const discoveredCount = Number(discoveryDoc?.metadata?.historical_ticket_count || 0);
                              const rows = [];
                              onboardingWorkflowSteps.forEach((row) => rows.push({
                                ...row,
                                source: "workflow",
                                background: explainOnboardingStepBackground(row.step, isSetupMonitoring),
                              }));
                              monitoringAppDetails.history.forEach((row) => {
                                const output = row?.output && typeof row.output === "object" ? row.output : {};
                                rows.push({
                                  step: rows.length + 1,
                                  title: row.event_type || row.agent || "Application audit event",
                                  status: row.status || row.decision || "completed",
                                  source: "audit",
                                  timestamp: row.created_at,
                                  details: {
                                    message: output.message || output.status || `${row.agent || "backend"} recorded ${row.event_type || "an event"}.`,
                                  },
                                  background: `Live application audit event from ${row.agent || "backend"}${row.created_at ? ` at ${formatIstTimestamp(row.created_at)}` : ""}.`,
                                });
                              });
                              if (monitoringAppDetails.validations.length) {
                                const latestValidation = monitoringAppDetails.validations[0];
                                rows.push({
                                  step: rows.length + 1,
                                  title: "Monitoring Validation",
                                  status: latestValidation.metrics_available && latestValidation.target_up ? "completed" : "needs_attention",
                                  source: "validation",
                                  details: {
                                    message: `Target up: ${Boolean(latestValidation.target_up)}; metrics: ${Boolean(latestValidation.metrics_available)}; service discovery: ${Boolean(latestValidation.service_discovery_ok)}.`,
                                  },
                                  background: "Live validation result loaded from the selected application's validation endpoint.",
                                });
                              }
                              if (discoveryDoc) {
                                rows.push({
                                  step: rows.length + 1,
                                  title: "Discover Similar Historical Tickets",
                                  status: "completed",
                                  source: "rag",
                                  details: { message: `${discoveredCount} similar incident match${discoveredCount === 1 ? "" : "es"} used before runbook generation.` },
                                  background: `Dynamic RAG metadata from ${discoveryDoc.title || "the generated runbook"}; strategy: similar-historical-tickets-first.`,
                                });
                                rows.push({
                                  step: rows.length + 1,
                                  title: "Generate Ticket-Grounded Runbook",
                                  status: "completed",
                                  source: "rag",
                                  details: { message: discoveryDoc.title || "Historical-ticket-grounded runbook generated." },
                                  background: "The runbook was generated after incident-only similarity search and context extraction.",
                                });
                              }
                              monitoringAppDetails.dashboards.forEach((row) => rows.push({
                                step: rows.length + 1,
                                title: "Dashboard Generated",
                                status: "completed",
                                source: "dashboard",
                                details: { message: row.title || row.dashboard_uid || "Dashboard reference generated." },
                                background: `Live dashboard record${row.updated_at ? ` updated ${formatIstTimestamp(row.updated_at)}` : ""}.`,
                              }));
                              const dedupedRows = rows.filter((row, index, allRows) => {
                                const identity = `${String(row.title || "").toLowerCase()}|${String(row.timestamp || row?.details?.workflow_id || "")}`;
                                return allRows.findIndex((candidate) => `${String(candidate.title || "").toLowerCase()}|${String(candidate.timestamp || candidate?.details?.workflow_id || "")}` === identity) === index;
                              });
                              if (!dedupedRows.length) {
                                return <tr><td colSpan={4}>No backend workflow activity is available for this project yet.</td></tr>;
                              }
                              return dedupedRows.map((row, index) => {
                                const message = row?.details?.message
                                  || row?.details?.summary
                                  || row?.details?.choice
                                  || row?.details?.path
                                  || row?.details?.workflow_id
                                  || `Requirements: ${Number(row?.details?.requirements_count || 0)}`;
                                return (
                                  <tr key={`workflow-step-${row.step || index}-${row.title}`}>
                                    <td>{index + 1}. {row.title}</td>
                                    <td>{row.status || "pending"}</td>
                                    <td>{String(message || "-")}</td>
                                    <td>
                                      <details>
                                        <summary>How This Worked In Background</summary>
                                        <pre className="result">{row.background || explainOnboardingStepBackground(row.step, isSetupMonitoring)}</pre>
                                      </details>
                                    </td>
                                  </tr>
                                );
                              });
                            })()}
                          </tbody>
                        </table>
                      </div>
                      <div className="filter-grid">
                        <label>
                          Current Project
                          <input value={onboardingForm.name} readOnly />
                        </label>
                        <label>
                          Monitoring Tool
                          <input value={onboardingForm.monitoring_tool} readOnly />
                        </label>
                        <label>
                          Last Workflow ID
                          <input value={String(onboardingRuleLookup.workflow_id || onboardingRuleRunState?.result?.workflow_id || "").trim()} readOnly />
                        </label>
                      </div>
                      {onboardingRuleRunState.error ? <p className="error">{onboardingRuleRunState.error}</p> : null}
                      {onboardingRuleRunState.result?.knowledge_documents?.length ? (
                        <div className="table-wrap">
                          <h4>Documents Saved To System</h4>
                          <p className="subtitle">For transparency: every knowledge document persisted by this run, with its metadata.</p>
                          <table>
                            <thead>
                              <tr>
                                <th>Title</th>
                                <th>Project</th>
                                <th>Platform</th>
                                <th>Owner</th>
                                <th>Created</th>
                                <th>Document ID</th>
                              </tr>
                            </thead>
                            <tbody>
                              {onboardingRuleRunState.result.knowledge_documents.map((doc) => (
                                <tr key={doc.document_id || doc.title}>
                                  <td>{doc.title || "-"}</td>
                                  <td>{doc.project || "-"}</td>
                                  <td>{doc.platform || "-"}</td>
                                  <td>{doc.owner || "-"}</td>
                                  <td>{formatIstTimestamp(doc.created_at)}</td>
                                  <td>{doc.document_id || "-"}</td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      ) : null}
                      {onboardingRuleRunState.result ? <pre className="result">{JSON.stringify(onboardingRuleRunState.result, null, 2)}</pre> : null}
                      <div style={{ display: "flex", justifyContent: "flex-end", marginTop: 10 }}>
                        <button type="button" className="button-secondary" onClick={() => setProjectSetupStep("advanced")}>Next: Advanced Tools</button>
                      </div>
                    </article>
                    ) : null}

                    {showProjectStep("advanced") ? (
                    <article className="panel">
                      <h3>Advanced Rule Workflow Management</h3>
                      <details>
                        <summary style={{ cursor: "pointer", marginBottom: 12 }}>Open Advanced Tools</summary>

                        <form className="form" onSubmit={lookupOnboardingRuleWorkflow}>
                          <div className="filter-grid">
                            <label>
                              Workflow ID
                              <input
                                value={onboardingRuleLookup.workflow_id}
                                placeholder="Paste workflow id"
                                onChange={(e) => setOnboardingRuleLookup((curr) => ({ ...curr, workflow_id: e.target.value }))}
                              />
                            </label>
                          </div>
                          <button className="button-secondary" type="submit" disabled={onboardingRuleLookup.loading}>
                            {onboardingRuleLookup.loading ? "Fetching..." : "Lookup Workflow"}
                          </button>
                        </form>
                        {onboardingRuleLookup.error ? <p className="error">{onboardingRuleLookup.error}</p> : null}
                        {onboardingRuleLookup.result ? <pre className="result">{JSON.stringify(onboardingRuleLookup.result, null, 2)}</pre> : null}
                        <div className="table-wrap" style={{ marginTop: 12 }}>
                          <table>
                            <thead>
                              <tr>
                                <th>Project</th>
                                <th>Pipeline</th>
                                <th>Workflow ID</th>
                                <th>Status</th>
                                <th>Updated</th>
                                <th>Action</th>
                              </tr>
                            </thead>
                            <tbody>
                              {ruleOnboardingRows.slice(0, 100).map((row, index) => {
                                const payload = row.connectivity_payload && typeof row.connectivity_payload === "object" ? row.connectivity_payload : {};
                                const workflowId = String(payload.workflow_id || "").trim();
                                return (
                                  <tr key={`rule-workflow-row-${index}`}>
                                    <td>{row.project_name || "-"}</td>
                                    <td>{row.provider_name || payload.pipeline || "-"}</td>
                                    <td>{workflowId || "-"}</td>
                                    <td>{payload.status || row.test_status || "-"}</td>
                                    <td>{formatIstTimestamp(row.updated_at || row.created_at)}</td>
                                    <td>
                                      <div style={{ display: "flex", gap: 8 }}>
                                        <button type="button" className="button-secondary" onClick={() => openRuleWorkflowEditor(row)} disabled={!workflowId}>
                                          Edit
                                        </button>
                                        <button type="button" className="button-secondary" onClick={() => deleteRuleWorkflow(workflowId)} disabled={!workflowId || onboardingRuleEditorState.loading}>
                                          Delete
                                        </button>
                                      </div>
                                    </td>
                                  </tr>
                                );
                              })}
                              {!ruleOnboardingRows.length ? (
                                <tr>
                                  <td colSpan={6}>No saved rule workflows available.</td>
                                </tr>
                              ) : null}
                            </tbody>
                          </table>
                        </div>

                        <h3>Edit Rule Workflow Result</h3>
                        <form className="form" onSubmit={saveRuleWorkflowEditor}>
                          <div className="filter-grid">
                            <label>
                              Workflow ID
                              <input
                                value={onboardingRuleEditor.workflow_id}
                                onChange={(e) => setOnboardingRuleEditor((current) => ({ ...current, workflow_id: e.target.value }))}
                                placeholder="Workflow ID"
                              />
                            </label>
                            <label>
                              Project Name
                              <input
                                value={onboardingRuleEditor.project_name}
                                onChange={(e) => setOnboardingRuleEditor((current) => ({ ...current, project_name: e.target.value }))}
                                placeholder="Project name"
                              />
                            </label>
                          </div>
                          <label>
                            Workflow Result JSON
                            <textarea
                              rows={10}
                              value={onboardingRuleEditor.payload_json}
                              onChange={(e) => setOnboardingRuleEditor((current) => ({ ...current, payload_json: e.target.value }))}
                              placeholder="Paste workflow result JSON"
                            />
                          </label>
                          <button className="button-primary" type="submit" disabled={onboardingRuleEditorState.loading}>
                            {onboardingRuleEditorState.loading ? "Saving..." : "Save Workflow Changes"}
                          </button>
                        </form>
                        {onboardingRuleEditorState.error ? <p className="error">{onboardingRuleEditorState.error}</p> : null}
                        {onboardingRuleEditorState.success ? <p className="subtitle">{onboardingRuleEditorState.success}</p> : null}

                        <div className="panel-head" style={{ marginTop: 12 }}>
                          <h3>Monitoring Platform Capabilities</h3>
                          <button type="button" className="button-secondary" onClick={loadOnboardingRuleCapabilities}>
                            Refresh
                          </button>
                        </div>
                        {onboardingRuleCapabilities.error ? <p className="error">{onboardingRuleCapabilities.error}</p> : null}
                        <div className="table-wrap">
                          <table>
                            <thead>
                              <tr>
                                <th>Platform</th>
                                <th>Pull Rules</th>
                                <th>Push Rules</th>
                                <th>Adapter</th>
                                <th>Simulation</th>
                                <th>Dashboards</th>
                              </tr>
                            </thead>
                            <tbody>
                              {onboardingRuleCapabilities.rows.map((row, index) => (
                                <tr key={`capability-${row.platform || index}`}>
                                  <td>{row.platform || "-"}</td>
                                  <td>{String(Boolean(row.can_pull_rules))}</td>
                                  <td>{String(Boolean(row.can_push_rules))}</td>
                                  <td title={row.contract_label || ""}>{row.contract_mode || "-"} / {row.contract_status || "-"}</td>
                                  <td>{String(Boolean(row.supports_simulation))}</td>
                                  <td>{String(Boolean(row.supports_dashboard_refs))}</td>
                                </tr>
                              ))}
                              {!onboardingRuleCapabilities.rows.length && !onboardingRuleCapabilities.loading ? (
                                <tr>
                                  <td colSpan={6}>No capabilities loaded yet.</td>
                                </tr>
                              ) : null}
                            </tbody>
                          </table>
                        </div>
                      </details>
                    </article>
                    ) : null}
                  </div>

                ) : null}

                {adminWorkspace === "monitoring" ? (
                  <div className="grid single-col admin-flow-section admin-flow-monitoring">
                    <article className="panel">
                      <div className="panel-head">
                        <h3>Setup Monitoring</h3>
                        <button className="button-secondary" type="button" onClick={loadMonitoringApplications} disabled={monitoringApps.loading}>Refresh</button>
                      </div>
                      <p className="subtitle">Start here. Register an application and inspect the end-to-end onboarding chain (discovery, validation, rules, Prometheus update, dashboard).</p>
                      <p className="subtitle"><strong>Alert Knowledge:</strong> Included in Setup Monitoring + Landing Pad. Use the unified setup tab for one continuous workflow.</p>
                      <form className="form" onSubmit={submitMonitoringApplication}>
                        <div className="filter-grid">
                          <label>Tenant<input value={monitoringAppForm.tenant_id} onChange={(e) => setMonitoringAppForm((curr) => ({ ...curr, tenant_id: e.target.value }))} /></label>
                          <label>Application Name<input value={monitoringAppForm.name} onChange={(e) => setMonitoringAppForm((curr) => ({ ...curr, name: e.target.value }))} /></label>
                          <label>Owner Team<input value={monitoringAppForm.owner_team} onChange={(e) => setMonitoringAppForm((curr) => ({ ...curr, owner_team: e.target.value }))} /></label>
                          <label>Owner Email<input value={monitoringAppForm.owner_email} onChange={(e) => setMonitoringAppForm((curr) => ({ ...curr, owner_email: e.target.value }))} /></label>
                        </div>
                        <div className="filter-grid">
                          <label>Environment<select value={monitoringAppForm.environment} onChange={(e) => setMonitoringAppForm((curr) => ({ ...curr, environment: e.target.value }))}><option value="dev">dev</option><option value="staging">staging</option><option value="prod">prod</option></select></label>
                          <label>Namespace<input value={monitoringAppForm.namespace} onChange={(e) => setMonitoringAppForm((curr) => ({ ...curr, namespace: e.target.value }))} /></label>
                          <label>Region<input value={monitoringAppForm.region} onChange={(e) => setMonitoringAppForm((curr) => ({ ...curr, region: e.target.value }))} /></label>
                          <label>Technology<input value={monitoringAppForm.technology} onChange={(e) => setMonitoringAppForm((curr) => ({ ...curr, technology: e.target.value }))} /></label>
                        </div>
                        <label>Metrics Endpoint<input placeholder="http://api-gateway:8000/metrics" value={monitoringAppForm.metrics_endpoint} onChange={(e) => setMonitoringAppForm((curr) => ({ ...curr, metrics_endpoint: e.target.value }))} /></label>
                        <label>Labels (comma-separated key=value)<input value={monitoringAppForm.labels_text} onChange={(e) => setMonitoringAppForm((curr) => ({ ...curr, labels_text: e.target.value }))} /></label>
                        <button className="button-primary" type="submit" disabled={monitoringAppSubmit.loading}>{monitoringAppSubmit.loading ? "Submitting..." : "Register Application"}</button>
                      </form>
                      {monitoringAppSubmit.error ? <p className="error">{monitoringAppSubmit.error}</p> : null}
                      {monitoringAppSubmit.success ? <p className="subtitle">{monitoringAppSubmit.success}</p> : null}
                      <article className="panel monitoring-doc-gate" style={{ marginTop: 10, borderStyle: "dashed" }}>
                        <div className="panel-head">
                          <h3>Service Knowledge Status</h3>
                          <button type="button" className="button-secondary" onClick={applyUploadedDocumentsToRuleIntent} disabled={!onboardingDerivedRequirements.length}>Apply To Rules</button>
                        </div>
                        <p className="subtitle">Use the Service Knowledge upload above. KaiOps extracts and validates the important details in one flow.</p>
                        <div className="approval-steps" style={{ marginTop: 10 }}>
                          <div className="approval-step">
                            <strong>Extract</strong>
                            <span>Service, owner, environment, dependencies, alerts, commands, rollback, and validation checks.</span>
                          </div>
                          <div className="approval-step">
                            <strong>Validate</strong>
                            <span>Flags missing or low-confidence fields before the details are trusted.</span>
                          </div>
                          <div className="approval-step">
                            <strong>Approve</strong>
                            <span>Stores the reviewed pack in Alert Knowledge for RAG and future incidents.</span>
                          </div>
                        </div>
                        {onboardingSourceDocs.loading ? <p className="subtitle">Reading uploaded file...</p> : null}
                        {onboardingSourceDocs.error ? <p className="error">{onboardingSourceDocs.error}</p> : null}
                        <p className="subtitle monitoring-doc-gate-count">
                          Uploaded file: <strong>{onboardingSourceDocCount > 0 ? "yes" : "no"}</strong> | Service Knowledge: <strong>{knowledgePackState.approved ? "approved" : onboardingKnowledgePack?.status || "waiting"}</strong>
                        </p>
                      </article>
                    </article>

                    <article className="panel">
                      <h3>Applications</h3>
                      {monitoringApps.error ? <p className="error">{monitoringApps.error}</p> : null}
                      <div className="table-wrap">
                        <table>
                          <thead>
                            <tr><th>Name</th><th>Tenant</th><th>Namespace</th><th>Environment</th><th>Technology</th><th>Status</th><th>Metrics Endpoint</th><th>Action</th></tr>
                          </thead>
                          <tbody>
                            {monitoringApps.rows.map((row, index) => (
                              <tr key={`monitoring-app-${row.id || index}`}>
                                <td>{row.name || "-"}</td>
                                <td>{row.tenant_id || "default"}</td>
                                <td>{row.namespace || "-"}</td>
                                <td>{row.environment || "-"}</td>
                                <td>{row.technology || "-"}</td>
                                <td><span className={`pill ${String(row.status || "").includes("failed") ? "status-failed" : "status-closed"}`}>{row.status || "-"}</span></td>
                                <td>{row.metrics_endpoint || "-"}</td>
                                <td><button type="button" className="button-secondary" onClick={() => setSelectedMonitoringAppId(String(row.id || ""))}>Inspect</button></td>
                              </tr>
                            ))}
                            {!monitoringApps.rows.length ? <tr><td colSpan={8}>No monitoring applications registered yet.</td></tr> : null}
                          </tbody>
                        </table>
                      </div>
                    </article>

                    <article className="panel" ref={monitoringInspectRef}>
                      <div className="panel-head">
                        <h3>Selected Application Timeline</h3>
                        <p className="subtitle">{selectedMonitoringAppId || "Select an application to inspect stage history, validations, and dashboards."}</p>
                      </div>
                      {monitoringAppDetails.error ? <p className="error">{monitoringAppDetails.error}</p> : null}
                      <HistoricalTicketDiscoveryPanel
                        applicationId={selectedMonitoringAppId}
                        applicationName={monitoringApps.rows.find((row) => String(row?.id || "").trim() === String(selectedMonitoringAppId || "").trim())?.name}
                        documents={ragDocs.rows}
                        loading={ragDocs.loading}
                      />
                      <div className="table-wrap">
                        <table>
                          <thead>
                            <tr><th>Event</th><th>Agent</th><th>Decision</th><th>Status</th><th>Execution (ms)</th><th>Timestamp</th></tr>
                          </thead>
                          <tbody>
                            {monitoringAppDetails.history.map((row, index) => (
                              <tr key={`monitoring-history-${row.id || index}`}>
                                <td>{row.event_type || "-"}</td>
                                <td>{row.agent || "-"}</td>
                                <td>{row.decision || "-"}</td>
                                <td>{row.status || "-"}</td>
                                <td>{asDisplayValue(row.execution_time_ms)}</td>
                                <td>{formatIstTimestamp(row.created_at)}</td>
                              </tr>
                            ))}
                            {!monitoringAppDetails.history.length ? <tr><td colSpan={6}>No stage history available yet.</td></tr> : null}
                          </tbody>
                        </table>
                      </div>
                      <div className="table-wrap">
                        <table>
                          <thead>
                            <tr><th>Target Up</th><th>Metrics</th><th>Alerts Loaded</th><th>Recording Rules</th><th>Service Discovery</th><th>Timestamp</th></tr>
                          </thead>
                          <tbody>
                            {monitoringAppDetails.validations.map((row, index) => (
                              <tr key={`monitoring-validation-${row.id || index}`}>
                                <td>{String(Boolean(row.target_up))}</td>
                                <td>{String(Boolean(row.metrics_available))}</td>
                                <td>{String(Boolean(row.alerts_loaded))}</td>
                                <td>{String(Boolean(row.recording_rules_loaded))}</td>
                                <td>{String(Boolean(row.service_discovery_ok))}</td>
                                <td>{formatIstTimestamp(row.created_at)}</td>
                              </tr>
                            ))}
                            {!monitoringAppDetails.validations.length ? <tr><td colSpan={6}>No validation records available yet.</td></tr> : null}
                          </tbody>
                        </table>
                      </div>
                      <div className="table-wrap">
                        <table>
                          <thead>
                            <tr><th>Dashboard UID</th><th>Title</th><th>URL</th><th>Updated</th></tr>
                          </thead>
                          <tbody>
                            {monitoringAppDetails.dashboards.map((row, index) => (
                              <tr key={`monitoring-dashboard-${row.id || index}`}>
                                <td>{row.dashboard_uid || "-"}</td>
                                <td>{row.title || "-"}</td>
                                <td>{row.url || "-"}</td>
                                <td>{formatIstTimestamp(row.updated_at)}</td>
                              </tr>
                            ))}
                            {!monitoringAppDetails.dashboards.length ? <tr><td colSpan={4}>No dashboards generated yet.</td></tr> : null}
                          </tbody>
                        </table>
                      </div>
                    </article>
                  </div>
                ) : null}

                {(adminWorkspace === "alerts" || (adminWorkspace === "project" && showProjectStep("knowledge"))) ? (
                  <div className="grid single-col admin-flow-section admin-flow-knowledge">
                    <article className="panel">
                      <div className="panel-head">
                        <h3>{adminWorkspace === "project" ? "Knowledge: Alert Documents" : "Alert Knowledge Onboarding"}</h3>
                        <p>{adminWorkspace === "project" ? "Create and review alert knowledge here in the same setup workspace." : "Standalone alert knowledge workspace for focused onboarding and review."}</p>
                      </div>
                      <div className="detail-tabs" style={{ marginBottom: 0 }}>
                        <button
                          type="button"
                          className={alertKnowledgeView === "onboarding" ? "button-primary" : "button-secondary"}
                          onClick={() => setAlertKnowledgeView("onboarding")}
                        >
                          Guided Onboarding
                        </button>
                        <button
                          type="button"
                          className={alertKnowledgeView === "backend" ? "button-primary" : "button-secondary"}
                          onClick={() => setAlertKnowledgeView("backend")}
                        >
                          Stored Docs & Metadata
                        </button>
                      </div>
                    </article>

                    {alertKnowledgeView === "onboarding" ? (
                    <article className="panel" ref={alertKnowledgeRef}>
                      <h3>Alert Knowledge Onboarding</h3>
                      <p className="subtitle">Add monitoring/troubleshooting knowledge as part of the same onboarding flow.</p>
                      <form className="form" onSubmit={submitAlertOnboarding}>
                        <label>
                          Prompt For Document Generation
                          <textarea
                            rows={4}
                            placeholder="Describe the alert scenario, triage steps, impact, and expected remediation. Optional prefixes: cmd:, script:, query:."
                            value={alertKnowledgePrompt}
                            onChange={(e) => setAlertKnowledgePrompt(e.target.value)}
                          />
                        </label>
                        <div className="alert-knowledge-source">
                          <label>
                            Supporting Document
                            <input
                              type="file"
                              accept=".md,.markdown,.txt,.json,.csv,.yaml,.yml,.log"
                              onChange={(e) => handleAlertKnowledgeSourceDocument(e.target.files)}
                            />
                          </label>
                          <div className="alert-knowledge-source-status">
                            {alertKnowledgeSourceDoc.loading ? <span>Reading document...</span> : null}
                            {alertKnowledgeSourceDoc.error ? <span className="error">{alertKnowledgeSourceDoc.error}</span> : null}
                            {alertKnowledgeSourceDoc.name && !alertKnowledgeSourceDoc.error ? (
                              <>
                                <div>
                                  <strong>{alertKnowledgeSourceDoc.name}</strong>
                                  <small>{alertKnowledgeSourceDoc.size ? `${Math.ceil(alertKnowledgeSourceDoc.size / 1024)} KB` : "uploaded"}</small>
                                </div>
                                {alertKnowledgeSourceDoc.excerpt ? <p>{alertKnowledgeSourceDoc.excerpt}</p> : null}
                                <button type="button" className="button-secondary" onClick={clearAlertKnowledgeSourceDocument}>
                                  Clear Document
                                </button>
                              </>
                            ) : !alertKnowledgeSourceDoc.loading && !alertKnowledgeSourceDoc.error ? (
                              <span>Upload runbook, RCA, logs, support notes, or troubleshooting docs. The draft uses this together with the prompt.</span>
                            ) : null}
                          </div>
                        </div>
                        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                          <button
                            type="button"
                            className="button-secondary"
                            onClick={generateAlertKnowledgeDraftFromPrompt}
                            disabled={alertOnboardingState.loading}
                          >
                            Generate Draft From Prompt + Document
                          </button>
                        </div>
                        <div className="detail-tabs" style={{ marginBottom: 10 }}>
                          {ALERT_DOC_KIND_OPTIONS.map((kind) => (
                            <button
                              key={`onboard-kind-${kind}`}
                              type="button"
                              className={String(alertOnboarding.kind || "").trim().toLowerCase() === kind ? "button-primary" : "button-secondary"}
                              onClick={() => setAlertOnboarding((curr) => ({ ...curr, kind }))}
                            >
                              {kind}
                            </button>
                          ))}
                        </div>
                        <div className="filter-grid">
                          <label>Kind
                            <select value={alertOnboarding.kind} onChange={(e) => setAlertOnboarding((curr) => ({ ...curr, kind: e.target.value }))}>
                              <option value="incident">incident</option>
                              <option value="runbook">runbook</option>
                              <option value="deployment">deployment</option>
                              <option value="change">change</option>
                              <option value="dependency">dependency</option>
                              <option value="remediation">remediation</option>
                            </select>
                          </label>
                          <label>Title<input value={alertOnboarding.title} onChange={(e) => setAlertOnboarding((curr) => ({ ...curr, title: e.target.value }))} /></label>
                          <label>Alert Type<input value={alertOnboarding.alert_type} onChange={(e) => setAlertOnboarding((curr) => ({ ...curr, alert_type: e.target.value }))} /></label>
                          <label>Severity<select value={alertOnboarding.severity} onChange={(e) => setAlertOnboarding((curr) => ({ ...curr, severity: e.target.value }))}><option value="critical">critical</option><option value="high">high</option><option value="medium">medium</option><option value="low">low</option></select></label>
                        </div>
                        <label>Services (comma separated)<input value={alertOnboarding.services} onChange={(e) => setAlertOnboarding((curr) => ({ ...curr, services: e.target.value }))} /></label>
                        <label>Summary<textarea rows={2} value={alertOnboarding.summary} onChange={(e) => setAlertOnboarding((curr) => ({ ...curr, summary: e.target.value }))} /></label>
                        <label>Content<textarea rows={5} value={alertOnboarding.content} onChange={(e) => setAlertOnboarding((curr) => ({ ...curr, content: e.target.value }))} /></label>
                        {String(alertOnboarding.kind || "").trim().toLowerCase() === "remediation" ? (
                          <>
                            <div style={{ display: "flex", alignItems: "end", gap: 8 }}>
                              <button
                                type="button"
                                className="button-secondary"
                                onClick={() => autoGenerateRemediationPlan()}
                                disabled={alertOnboardingState.loading}
                              >
                                Auto-Generate Commands/Scripts/Queries
                              </button>
                            </div>
                            <label>Execution Plan<textarea rows={4} value={alertOnboarding.execution_plan} onChange={(e) => setAlertOnboarding((curr) => ({ ...curr, execution_plan: e.target.value }))} /></label>
                            <div className="filter-grid">
                              <label>Additional Commands<textarea rows={5} value={alertOnboarding.remediation_commands_text} onChange={(e) => setAlertOnboarding((curr) => ({ ...curr, remediation_commands_text: e.target.value }))} /></label>
                              <label>Single Remediation Script<textarea rows={5} value={alertOnboarding.remediation_scripts_text} onChange={(e) => setAlertOnboarding((curr) => ({ ...curr, remediation_scripts_text: e.target.value }))} /></label>
                              <label>Additional Validation Queries<textarea rows={5} value={alertOnboarding.remediation_queries_text} onChange={(e) => setAlertOnboarding((curr) => ({ ...curr, remediation_queries_text: e.target.value }))} /></label>
                            </div>
                          </>
                        ) : null}
                        <button className="button-primary" type="submit" disabled={alertOnboardingState.loading}>{alertOnboardingState.loading ? "Saving..." : "Create Alert Onboarding Doc"}</button>
                      </form>
                      {alertOnboardingState.error ? <p className="error">{alertOnboardingState.error}</p> : null}
                      {alertOnboardingState.result ? <pre className="result">{JSON.stringify(alertOnboardingState.result, null, 2)}</pre> : null}
                    </article>
                    ) : null}

                    {alertKnowledgeView === "backend" ? (
                      <article className="panel">
                        <div className="panel-head">
                          <h3>Stored Backend Documents</h3>
                          <button className="button-secondary" type="button" onClick={loadRagDocs}>Refresh</button>
                        </div>
                        <p className="subtitle">Documents currently stored in backend with metadata details.</p>
                        {ragDocs.error ? <p className="error">{ragDocs.error}</p> : null}
                        <div className="table-wrap">
                          <table>
                            <thead>
                              <tr>
                                <th>Title</th>
                                <th>Kind</th>
                                <th>Alert Type</th>
                                <th>Severity</th>
                                <th>Services</th>
                                <th>Document View</th>
                                <th>Updated</th>
                                <th>Metadata</th>
                              </tr>
                            </thead>
                            <tbody>
                              {ragDocs.rows.map((doc, index) => (
                                <tr key={`backend-doc-${doc.path || doc.title || index}`}>
                                  <td>{doc.title || "-"}</td>
                                  <td>{doc.kind || doc.document_kind || "-"}</td>
                                  <td>{doc.alert_type || "-"}</td>
                                  <td>{doc.severity || "-"}</td>
                                  <td>{Array.isArray(doc.services) ? doc.services.join(", ") : (doc.services || "-")}</td>
                                  <td>
                                    <details className="backend-document-view">
                                      <summary>
                                        <span>{backendDocumentPreview(doc)}</span>
                                      </summary>
                                      <div>
                                        <p>{doc.summary || doc.recommended_action || "Document details are available from backend metadata."}</p>
                                        {doc.root_cause ? <p><strong>Root cause:</strong> {doc.root_cause}</p> : null}
                                        {doc.impact ? <p><strong>Impact:</strong> {doc.impact}</p> : null}
                                        {doc.execution_plan ? <pre className="result">{String(doc.execution_plan)}</pre> : null}
                                        <div className="backend-document-actions">
                                          <button
                                            type="button"
                                            className="button-secondary"
                                            onClick={() => downloadRagDocument(doc)}
                                            disabled={!doc.path}
                                          >
                                            Download
                                          </button>
                                        </div>
                                      </div>
                                    </details>
                                  </td>
                                  <td>{formatIstTimestamp(doc.updated_at || doc.modified_at || doc.created_at)}</td>
                                  <td>
                                    <details>
                                      <summary style={{ cursor: "pointer" }}>view</summary>
                                      <pre className="result" style={{ marginTop: 8 }}>{JSON.stringify({
                                        path: doc.path || null,
                                        alert_id: doc.alert_id || null,
                                        root_cause: doc.root_cause || null,
                                        impact: doc.impact || null,
                                        execution_plan: doc.execution_plan || null,
                                        recommended_action: doc.recommended_action || null,
                                        source_system: doc.source_system || null,
                                        source_ref: doc.source_ref || null,
                                        tags: doc.tags || null,
                                        metadata: doc.metadata || null,
                                      }, null, 2)}</pre>
                                    </details>
                                  </td>
                                </tr>
                              ))}
                              {!ragDocs.rows.length && !ragDocs.loading ? <tr><td colSpan={8}>No documents found in backend.</td></tr> : null}
                            </tbody>
                          </table>
                        </div>
                      </article>
                    ) : null}
                  </div>
                ) : null}
              </article>
            </section>
          ) : null}

          {activeTab === "summary" ? (
            <section className="grid single-col">
              <article className="panel">
                <div className="panel-head">
                  <h2>Incident Metadata</h2>
                  <p>Incident metadata explorer with policy, transport, and status context.</p>
                  <button className="button-secondary" onClick={loadIncidentMetadata}>Refresh</button>
                </div>
                <div className="filter-grid sticky-controls">
                  <label>
                    Risk Tier
                    <select
                      value={metadataFilters.risk_tier}
                      onChange={(e) => setMetadataFilters((curr) => ({ ...curr, risk_tier: e.target.value }))}
                    >
                      <option value="all">all</option>
                      <option value="high">high</option>
                      <option value="medium">medium</option>
                      <option value="low">low</option>
                    </select>
                  </label>
                  <label>
                    Execution Mode
                    <select
                      value={metadataFilters.execution_mode}
                      onChange={(e) => setMetadataFilters((curr) => ({ ...curr, execution_mode: e.target.value }))}
                    >
                      <option value="all">all</option>
                      <option value="human-approval">human-approval</option>
                      <option value="guided-auto">guided-auto</option>
                      <option value="auto-execute">auto-execute</option>
                    </select>
                  </label>
                  <label>
                    Transport
                    <select
                      value={metadataFilters.transport_provider}
                      onChange={(e) => setMetadataFilters((curr) => ({ ...curr, transport_provider: e.target.value }))}
                    >
                      <option value="all">all</option>
                      <option value="kafka">kafka</option>
                      <option value="rabbitmq">rabbitmq</option>
                    </select>
                  </label>
                  <label>
                    Status
                    <select
                      value={metadataFilters.status}
                      onChange={(e) => setMetadataFilters((curr) => ({ ...curr, status: e.target.value }))}
                    >
                      <option value="all">all</option>
                      <option value="open">open</option>
                      <option value="investigating">investigating</option>
                      <option value="awaiting_approval">awaiting_approval</option>
                      <option value="remediating">remediating</option>
                      <option value="validating">validating</option>
                      <option value="closed">closed</option>
                      <option value="failed">failed</option>
                    </select>
                  </label>
                </div>
                <label>
                  Service contains
                  <input
                    value={metadataFilters.service}
                    placeholder="payments"
                    onChange={(e) => setMetadataFilters((curr) => ({ ...curr, service: e.target.value }))}
                  />
                </label>
                {incidentMetadata.error ? <p className="error">{incidentMetadata.error}</p> : null}
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th>Incident</th>
                        <th>Service</th>
                        <th>Risk</th>
                        <th>Execution Mode</th>
                        <th>Provider</th>
                        <th>Status</th>
                        <th>Action</th>
                      </tr>
                    </thead>
                    <tbody>
                      {monitorScopedIncidentMetadata.map((row, index) => (
                        <tr key={row.incident_id || row.id || index}>
                          <td>{row.incident_id || row.id || "-"}</td>
                          <td>{row.service || "-"}</td>
                          <td>{row.risk_tier || "-"}</td>
                          <td>{row.execution_mode || "-"}</td>
                          <td>{row.transport_provider || "-"}</td>
                          <td><span className={`pill ${statusPillClass(row.status)}`}>{row.status || "-"}</span></td>
                          <td>
                            <button type="button" className="button-secondary" onClick={() => openAlertDetailsFromIncident(row)}>
                              Open
                            </button>
                          </td>
                        </tr>
                      ))}
                      {!monitorScopedIncidentMetadata.length && !incidentMetadata.loading ? (
                        <tr>
                          <td colSpan={7}>No incidents available for {applicationToMonitor}. Run one sample flow from Home.</td>
                        </tr>
                      ) : null}
                    </tbody>
                  </table>
                </div>
              </article>
            </section>
          ) : null}

          {activeTab === "approval" ? (
            <section className="grid single-col">
              <article className="panel">
                <div className="panel-head">
                  <h2>Human Approval Queue (Legacy)</h2>
                  <p>Primary approval actions now run inside the Alert Details Cockpit on Dashboard for eligible roles.</p>
                </div>
                <p className="subtitle">Use this queue for cross-incident triage, bulk-style review, or manual fallback operations.</p>

                <div className="search-row sticky-controls">
                  <label>
                    Search Guidance
                    <input
                      value={guidanceQuery}
                      onChange={(e) => setGuidanceQuery(e.target.value)}
                      placeholder="payments timeout rollback"
                    />
                  </label>
                  <button className="button-secondary" type="button" onClick={searchGuidanceDocs} disabled={guidanceState.loading}>
                    {guidanceState.loading ? "Searching..." : "Search Guidance"}
                  </button>
                </div>
                {guidanceState.error ? <p className="error">{guidanceState.error}</p> : null}
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th>Kind</th>
                        <th>Score</th>
                        <th>Title</th>
                        <th>Path</th>
                      </tr>
                    </thead>
                    <tbody>
                      {guidanceState.rows.map((row, index) => (
                        <tr key={`${row.path || row.title || "match"}-${index}`}>
                          <td>{row.kind || row.document_kind || "-"}</td>
                          <td>{row.score ?? "-"}</td>
                          <td>{row.title || row.id || "-"}</td>
                          <td>{row.path || "-"}</td>
                        </tr>
                      ))}
                      {!guidanceState.rows.length && !guidanceState.loading ? (
                        <tr>
                          <td colSpan={4}>Search guidance to view matching runbooks and incidents.</td>
                        </tr>
                      ) : null}
                    </tbody>
                  </table>
                </div>

                <div className="approval-steps">
                  <div className="approval-step">
                    <strong>Step 1</strong>
                    <span>Select a pending incident from the table below.</span>
                  </div>
                  <div className="approval-step">
                    <strong>Step 2</strong>
                    <span>Review flow context and action details.</span>
                  </div>
                  <div className="approval-step">
                    <strong>Step 3</strong>
                    <span>Submit approve, reject, or modify.</span>
                  </div>
                </div>

                <div className="filter-grid sticky-controls approval-controls">
                  <label>
                    Pending Filter
                    <select value={approvalFilter} onChange={(e) => setApprovalFilter(e.target.value)}>
                      <option value="all">all</option>
                      <option value="awaiting_approval">awaiting_approval</option>
                      <option value="critical">critical</option>
                      <option value="high">high</option>
                      <option value="medium">medium</option>
                      <option value="low">low</option>
                    </select>
                  </label>
                  <label>
                    Selected Incident
                    <input value={selectedApprovalRow ? approvalIncidentId(selectedApprovalRow) : ""} readOnly placeholder="Select from table" />
                  </label>
                  <label>
                    Selected Recommendation
                    <input value={selectedApprovalRecommendationId} readOnly placeholder="Autofills from selected incident" />
                  </label>
                  <label>
                    Flow Context
                    <input value={selectedApprovalFlowContext} readOnly placeholder="flow_id, trace_id, or correlation_id" />
                  </label>
                </div>

                <div className="approval-nav-actions">
                  <button className="button-secondary" type="button" onClick={() => setActiveTab("summary")}>Open Incident Metadata</button>
                  <button className="button-secondary" type="button" onClick={() => setActiveTab("trace")}>Open Agent Flow</button>
                  <button className="button-secondary" type="button" onClick={() => selectedApprovalIncidentId && loadApprovalIncidentContext(selectedApprovalIncidentId)} disabled={!selectedApprovalIncidentId || approvalIncidentContext.loading}>
                    {approvalIncidentContext.loading ? "Syncing..." : "Sync From Approval API"}
                  </button>
                  <button className="button-secondary" type="button" onClick={() => setShowAdvancedApprovalForm((current) => !current)}>
                    {showAdvancedApprovalForm ? "Hide Advanced Approval Form" : "Show Advanced Approval Form"}
                  </button>
                </div>
                {approvalIncidentContext.error ? <p className="error">{approvalIncidentContext.error}</p> : null}

                <p className="subtitle">Latest workflow incident: {latestIncidentId || "not available"}</p>
                <div className="table-wrap" ref={approvalQueueRef}>
                  <table>
                    <thead>
                      <tr>
                        <th>Select</th>
                        <th>Incident</th>
                        <th>Recommendation</th>
                        <th>Service</th>
                        <th>Severity</th>
                        <th>Execution Mode</th>
                        <th>Status</th>
                        <th>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredPendingApprovals.map((row, index) => {
                        const incidentId = approvalIncidentId(row);
                        const recommendationId = approvalRecommendationId(row);
                        const selected = incidentId && incidentId === selectedApprovalIncidentId;
                        const rowStatus = normalizeApprovalStatus(row?.status);
                        const rowResolved = isApprovalResolvedStatus(rowStatus);
                        const canQuickApprove = !rowResolved && looksLikeUuid(incidentId);
                        const quickApproveBusy = approvalState.loading && selected && approvalForm.action === "approve";
                        const quickRejectBusy = approvalState.loading && selected && approvalForm.action === "reject";
                        const rejectExpanded = !rowResolved && inlineRejectState.incidentId === incidentId;
                        return (
                        <tr key={incidentId || index} className={selected ? "row-selected" : ""}>
                          <td>
                            <button className="button-secondary" type="button" onClick={() => selectApprovalIncident(row)}>
                              {selected ? "Selected" : "Use"}
                            </button>
                          </td>
                          <td>{incidentId || "-"}</td>
                          <td>{recommendationId || "-"}</td>
                          <td>{row.service || "-"}</td>
                          <td>{row.severity || row.risk_tier || "-"}</td>
                          <td>{row.execution_mode || "-"}</td>
                          <td><span className={`pill ${statusPillClass(rowStatus)}`}>{rowStatus || "pending"}</span></td>
                          <td>
                            <button className="button-secondary" type="button" onClick={() => openAlertDetailsFromIncident(row)}>
                              Open
                            </button>
                            {!rowResolved ? (
                              <>
                                <button
                                  className="button-primary"
                                  type="button"
                                  onClick={() => approveIncidentRow(row)}
                                  disabled={!canQuickApprove || approvalState.loading}
                                  title={canQuickApprove ? "Approve this incident directly" : "Recommendation ID unavailable. Use Sync From Approval API first."}
                                  style={{ marginLeft: 8 }}
                                >
                                  {quickApproveBusy ? "Approving..." : "Approve"}
                                </button>
                                <button
                                  className="button-secondary"
                                  type="button"
                                  onClick={() => {
                                    setApprovalState({ loading: false, result: null, error: "" });
                                    setInlineRejectState((current) => current.incidentId === incidentId ? { incidentId: "", comment: "" } : { incidentId, comment: "" });
                                  }}
                                  disabled={!canQuickApprove || approvalState.loading}
                                  title={canQuickApprove ? "Reject this incident with a comment" : "Recommendation ID unavailable. Use Sync From Approval API first."}
                                  style={{ marginLeft: 8 }}
                                >
                                  {rejectExpanded ? "Cancel Reject" : "Reject"}
                                </button>
                              </>
                            ) : (
                              <span className={`pill ${statusPillClass(rowStatus)}`} style={{ marginLeft: 8 }}>
                                {rowStatus}
                              </span>
                            )}
                            {rejectExpanded ? (
                              <div style={{ marginTop: 8, display: "grid", gap: 8 }}>
                                <textarea
                                  rows={2}
                                  placeholder="Add rejection comment"
                                  value={inlineRejectState.comment}
                                  onChange={(e) => setInlineRejectState({ incidentId, comment: e.target.value })}
                                />
                                <button
                                  className="button-primary"
                                  type="button"
                                  onClick={() => rejectIncidentRow(row)}
                                  disabled={!String(inlineRejectState.comment || "").trim() || approvalState.loading}
                                >
                                  {quickRejectBusy ? "Rejecting..." : "Confirm Reject"}
                                </button>
                              </div>
                            ) : null}
                          </td>
                        </tr>
                      )})}
                      {!filteredPendingApprovals.length ? (
                        <tr>
                          <td colSpan={8}>No pending approvals for this filter and monitor scope.</td>
                        </tr>
                      ) : null}
                    </tbody>
                  </table>
                </div>
                {showAdvancedApprovalForm ? (
                  <>
                    <form className="form" onSubmit={submitApproval}>
                      <label>
                        Action
                        <select value={approvalForm.action} onChange={(e) => setApprovalForm({ ...approvalForm, action: e.target.value })}>
                          <option value="approve">approve</option>
                          <option value="reject">reject</option>
                          <option value="modify">modify</option>
                        </select>
                      </label>
                      <label>
                        Incident ID
                        <input value={approvalForm.incident_id} onChange={(e) => setApprovalForm({ ...approvalForm, incident_id: e.target.value })} />
                      </label>
                      <label>
                        Recommendation ID
                        <input value={approvalForm.recommendation_id} onChange={(e) => setApprovalForm({ ...approvalForm, recommendation_id: e.target.value })} />
                      </label>
                      <label>
                        Approver
                        <input value={approvalForm.approver} onChange={(e) => setApprovalForm({ ...approvalForm, approver: e.target.value })} />
                      </label>
                      <label>
                        Channel
                        <select value={approvalForm.channel} onChange={(e) => setApprovalForm({ ...approvalForm, channel: e.target.value })}>
                          <option value="web">web</option>
                          <option value="slack">slack</option>
                          <option value="teams">teams</option>
                          <option value="email">email</option>
                        </select>
                      </label>
                      {approvalForm.action === "modify" ? (
                        <label>
                          Modified Action
                          <textarea rows={3} value={approvalForm.modified_action} onChange={(e) => setApprovalForm({ ...approvalForm, modified_action: e.target.value })} />
                        </label>
                      ) : null}
                      <label>
                        Comment
                        <textarea rows={3} value={approvalForm.comment} onChange={(e) => setApprovalForm({ ...approvalForm, comment: e.target.value })} />
                      </label>
                      <button className="button-primary" type="submit" disabled={!approvalReady || approvalState.loading}>
                        {approvalState.loading ? "Submitting..." : "Submit Approval Action"}
                      </button>
                    </form>
                    {!String(approvalForm.recommendation_id || "").trim() ? (
                      <p className="subtitle">Recommendation will be resolved automatically from the selected incident during submission.</p>
                    ) : null}
                  </>
                ) : (
                  <p className="subtitle">Use inline Approve or Reject for common actions. Open the advanced form for modify or manual approval payload editing.</p>
                )}
                {approvalState.error ? <p className="error">{approvalState.error}</p> : null}
                {approvalState.result ? <pre className="result">{JSON.stringify(approvalState.result, null, 2)}</pre> : null}
              </article>
            </section>
          ) : null}

          {activeTab === "trace" ? (
            <section className="grid single-col">
              <article className="panel">
                <div className="panel-head">
                  <h2>Agent Flow</h2>
                  <p>Agent flow with decisions, outputs, and communication handoffs.</p>
                </div>
                <h3>Workflow Event Timeline</h3>
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th>Step</th>
                        <th>Agent</th>
                        <th>Action</th>
                        <th>Decision</th>
                        <th>Output</th>
                        <th>Handoff</th>
                      </tr>
                    </thead>
                    <tbody>
                      {workflowEventRows.map((row, index) => (
                        <tr key={`${row.sequence}-${index}`}>
                          <td>{row.sequence}</td>
                          <td>{row.agent}</td>
                          <td>{row.action}</td>
                          <td>{row.decision}</td>
                          <td>{row.output}</td>
                          <td>{row.communicates_to}</td>
                        </tr>
                      ))}
                      {!workflowEventRows.length ? (
                        <tr>
                          <td colSpan={6}>Run a workflow to populate detailed agent timeline.</td>
                        </tr>
                      ) : null}
                    </tbody>
                  </table>
                </div>

                <h3>Gateway Audit Events</h3>
                {gatewayRecent.error ? <p className="error">{gatewayRecent.error}</p> : null}
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th>Time</th>
                        <th>Path</th>
                        <th>Status</th>
                        <th>Decision</th>
                        <th>Trace ID</th>
                      </tr>
                    </thead>
                    <tbody>
                      {gatewayRecent.rows.slice(0, 30).map((row, index) => (
                        <tr key={row.id || index}>
                          <td>{formatIstTimestamp(row.created_at)}</td>
                          <td>{row.path || "-"}</td>
                          <td>{row.status_code || "-"}</td>
                          <td>{row?.safety?.decision || "-"}</td>
                          <td>{row.trace_id || "-"}</td>
                        </tr>
                      ))}
                      {!gatewayRecent.rows.length && !gatewayRecent.loading ? (
                        <tr>
                          <td colSpan={5}>No recent gateway trace entries.</td>
                        </tr>
                      ) : null}
                    </tbody>
                  </table>
                </div>
                {workflowState.result ? <pre className="result">{JSON.stringify(workflowState.result, null, 2)}</pre> : null}
              </article>
            </section>
          ) : null}

          {activeTab === "finops" ? (
            <section className="grid single-col">
              <article className="panel">
                <div className="panel-head">
                  <h2>FinOps</h2>
                  <p>LLM FinOps with provider cost breakdown and per-call model usage.</p>
                </div>
                <h3>Provider Cost Breakdown</h3>
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th>Provider</th>
                        <th>Calls</th>
                        <th>Tokens</th>
                        <th>Cost USD</th>
                      </tr>
                    </thead>
                    <tbody>
                      {finopsByProvider.map((row, index) => (
                        <tr key={`${row.provider}-${index}`}>
                          <td>{row.provider}</td>
                          <td>{row.calls}</td>
                          <td>{row.total_tokens}</td>
                          <td>{Number(row.total_cost_usd || 0).toFixed(6)}</td>
                        </tr>
                      ))}
                      {!finopsByProvider.length ? (
                        <tr>
                          <td colSpan={4}>No successful model calls recorded yet.</td>
                        </tr>
                      ) : null}
                    </tbody>
                  </table>
                </div>

                <h3>Per-call Model Usage</h3>
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th>Task</th>
                        <th>Provider</th>
                        <th>Model</th>
                        <th>Input Tokens</th>
                        <th>Output Tokens</th>
                        <th>Total Cost (USD)</th>
                      </tr>
                    </thead>
                    <tbody>
                      {allUsageRows.map((row, index) => (
                        <tr key={`${row.task || "task"}-${index}`}>
                          <td>{row.task || "-"}</td>
                          <td>{row.provider || "-"}</td>
                          <td>{row.model || "-"}</td>
                          <td>{row.input_tokens || "-"}</td>
                          <td>{row.output_tokens || "-"}</td>
                          <td>{row.total_cost_usd || "-"}</td>
                        </tr>
                      ))}
                      {!allUsageRows.length ? (
                        <tr>
                          <td colSpan={6}>No usage yet. Run a sample workflow from Home or open a processed alert to populate FinOps data.</td>
                        </tr>
                      ) : null}
                    </tbody>
                  </table>
                </div>
              </article>
            </section>
          ) : null}

          {activeTab === "rag" ? (
            <section className="grid single-col">
              <article className="panel">
                <div className="panel-head">
                  <h2>Message Bus</h2>
                  <button className="button-secondary" onClick={() => runWorkflow(selectedFlow)}>Refresh Activity</button>
                </div>

                <MessageBusTopology
                  actual={messageBusActual}
                  configuredRows={messageBusTopicRows}
                  routing={observedRouting}
                  primaryTopic={onboardingForm.azure_service_bus_topic}
                />

                <h3>Latest Workflow Topic Activity</h3>
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th>Service</th>
                        <th>Consumed</th>
                        <th>Published</th>
                        <th>Provider</th>
                        <th>Status</th>
                      </tr>
                    </thead>
                    <tbody>
                      {messageBusActual.rows.map((row, index) => (
                        <tr key={`${row.service}-${index}`}>
                          <td>{row.service}</td>
                          <td>{row.consumed}</td>
                          <td>{row.published}</td>
                          <td>{row.provider}</td>
                          <td>{row.status}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>

                <div className="dual-col">
                  <article className="panel">
                    <h3>Actual Topics Published</h3>
                    <ul className="flow-list">
                      {messageBusActual.published.map((topic) => <li key={`pub-${topic}`}>{topic}</li>)}
                      {!messageBusActual.published.length ? <li>No published topics observed yet.</li> : null}
                    </ul>
                  </article>
                  <article className="panel">
                    <h3>Actual Topics Consumed</h3>
                    <ul className="flow-list">
                      {messageBusActual.consumed.map((topic) => <li key={`con-${topic}`}>{topic}</li>)}
                      {!messageBusActual.consumed.length ? <li>No consumed topics observed yet.</li> : null}
                    </ul>
                  </article>
                </div>

                <h3>Configured Topic Topology</h3>
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th>Service</th>
                        <th>Consumes</th>
                        <th>Publishes</th>
                      </tr>
                    </thead>
                    <tbody>
                      {messageBusTopicRows.map((row, index) => (
                        <tr key={`${row.service}-${index}`}>
                          <td>{row.service}</td>
                          <td>{row.consumes}</td>
                          <td>{row.publishes}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>

                <h3>Routing Rule</h3>
                <p className="subtitle">When dynamic routing is enabled: if stream_count exceeds threshold, provider is kafka; otherwise rabbitmq.</p>
                <p className="subtitle">Observed workflow: {observedRouting?.workflow || "N/A"} | next action: {observedRouting?.next_action || "N/A"}</p>
              </article>
            </section>
          ) : null}

          {activeTab === "safety" ? (
            <section className="grid single-col">
              <article className="panel">
                <div className="panel-head">
                  <h2>Gateway Safety</h2>
                  <p>Review gateway decision, policy reasons, and safety metrics before closure.</p>
                  <button className="button-secondary" onClick={() => { loadGatewaySummary(); loadGatewayRecent(); loadLandingPadRecent(); }}>
                    Refresh
                  </button>
                </div>
                {gatewaySummary.error ? <p className="error">{gatewaySummary.error}</p> : null}
                <div className="stat-grid">
                  <div className="stat-card"><strong>Total</strong><span>{gatewaySummary.data.total_events || 0}</span></div>
                  <div className="stat-card"><strong>Allowed</strong><span>{gatewaySummary.data.allowed || 0}</span></div>
                  <div className="stat-card"><strong>Review</strong><span>{gatewaySummary.data.review || 0}</span></div>
                  <div className="stat-card"><strong>Blocked</strong><span>{gatewaySummary.data.blocked || 0}</span></div>
                </div>
                <p className="subtitle">Latest trace: {gatewaySummary.data.latest_trace_id || "-"}</p>
                <h3>Recent Gateway Events</h3>
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th>Path</th>
                        <th>Status</th>
                        <th>Decision</th>
                        <th>Score</th>
                        <th>Latency ms</th>
                        <th>Reasons</th>
                      </tr>
                    </thead>
                    <tbody>
                      {gatewayRecent.rows.map((row, index) => (
                        <tr key={`${row.trace_id || "gw"}-${index}`}>
                          <td>{row.path || "-"}</td>
                          <td>{row.status_code || "-"}</td>
                          <td>{row?.safety?.decision || "-"}</td>
                          <td>{row?.safety?.score ?? "-"}</td>
                          <td>{row.latency_ms || "-"}</td>
                          <td>{Array.isArray(row?.safety?.reasons) ? row.safety.reasons.join("; ") : "-"}</td>
                        </tr>
                      ))}
                      {!gatewayRecent.rows.length ? (
                        <tr>
                          <td colSpan={6}>No gateway events yet.</td>
                        </tr>
                      ) : null}
                    </tbody>
                  </table>
                </div>

                <h3>Landing Pad Realtime Ingestion</h3>
                {landingPadRecent.error ? <p className="error">{landingPadRecent.error}</p> : null}
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th>Received At (IST)</th>
                        <th>Alert</th>
                        <th>Service</th>
                        <th>Severity</th>
                        <th>Status</th>
                        <th>File</th>
                      </tr>
                    </thead>
                    <tbody>
                      {landingPadRecent.rows.map((row, index) => (
                        <tr key={`${row.file || "landing-pad"}-${index}`}>
                          <td>{formatIstTimestamp(row.received_at || row.modified_at)}</td>
                          <td>{row.name || row.alertname || "-"}</td>
                          <td>{row.service || "-"}</td>
                          <td>{String(row.severity || "-").toUpperCase()}</td>
                          <td>{row.alert_status || "-"}</td>
                          <td>{row.file || "-"}</td>
                        </tr>
                      ))}
                      {!landingPadRecent.rows.length ? (
                        <tr>
                          <td colSpan={6}>No realtime landing-pad ingestion records yet.</td>
                        </tr>
                      ) : null}
                    </tbody>
                  </table>
                </div>
              </article>
            </section>
          ) : null}

          {activeTab === "closed" ? (
            <section className="grid single-col">
              <article className="panel">
                <div className="panel-head">
                  <h2>Closed Tickets</h2>
                  <p>Closed tickets and current closure report summary.</p>
                  <button className="button-secondary" onClick={loadClosedIncidents}>Refresh</button>
                </div>
                <div className="filter-grid sticky-controls">
                  <label>
                    Filter by Risk Tier
                    <select
                      value={closedFilters.risk}
                      onChange={(e) => setClosedFilters((curr) => ({ ...curr, risk: e.target.value }))}
                    >
                      <option value="all">all</option>
                      {closedRiskOptions.map((option) => (
                        <option key={`risk-${option}`} value={option}>{option}</option>
                      ))}
                    </select>
                  </label>
                  <label>
                    Filter by Execution Mode
                    <select
                      value={closedFilters.mode}
                      onChange={(e) => setClosedFilters((curr) => ({ ...curr, mode: e.target.value }))}
                    >
                      <option value="all">all</option>
                      {closedModeOptions.map((option) => (
                        <option key={`mode-${option}`} value={option}>{option}</option>
                      ))}
                    </select>
                  </label>
                </div>
                <p className="subtitle">Showing {filteredClosedRows.length} filtered records</p>
                {closedIncidents.error ? <p className="error">{closedIncidents.error}</p> : null}
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th>Incident</th>
                        <th>Service</th>
                        <th>Severity</th>
                        <th>Status</th>
                        <th>Closed At</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredClosedRows.map((row, index) => (
                        <tr key={row.incident_id || index}>
                          <td>{row.incident_id || "-"}</td>
                          <td>{row.service || "-"}</td>
                          <td>{row.severity || "-"}</td>
                          <td><span className={`pill ${statusPillClass(row.status || "closed")}`}>{row.status || "closed"}</span></td>
                          <td>{formatIstTimestamp(row.closed_at || row.updated_at)}</td>
                        </tr>
                      ))}
                      {!filteredClosedRows.length && !closedIncidents.loading ? (
                        <tr>
                          <td colSpan={5}>No closed incidents available.</td>
                        </tr>
                      ) : null}
                    </tbody>
                  </table>
                </div>
              </article>
            </section>
          ) : null}
        </section>
      </div>
    </main>
  );
}
