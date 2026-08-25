# KaiMS Resolution Cycle Current-State Review

Branch baseline: `main` at the start of P0 hardening.

## Executive assessment

KaiMS has a broad event-driven AIOps skeleton and increasingly evidence-aware AI flows, but several resolution-path behaviors on `main` are unsafe for production autonomy. This review classifies code behavior, not service names or architecture documents.

## Capability classification

| Capability | Classification | Current-state finding |
|---|---|---|
| Alert intake and normalization | NEEDS_HARDENING | Multiple intake paths exist, but scope/idempotency and canonical identity remain inconsistent. |
| Incident correlation | PARTIALLY_IMPLEMENTED | Heuristic/correlation logic exists; problem-centric topology-aware clustering is not complete. |
| Context collection | UNSAFE_FOR_PRODUCTION | Default context-agent connector list includes static/demo ServiceNow, Prometheus, Kubernetes, Jenkins, GitHub and CMDB responses. |
| Local/MCP evidence | NEEDS_HARDENING | Evidence IDs, bounded search and insufficient-evidence handling exist and are reusable. |
| Investigation/RCA | PARTIALLY_IMPLEMENTED | Evidence-aware prompts and hypotheses exist, but a durable iterative falsification engine is incomplete. |
| Impact analysis | PARTIALLY_IMPLEMENTED | Some impact information exists, but topology-driven deterministic blast-radius analysis is incomplete. |
| Orchestration | NEEDS_HARDENING | Workflow selection exists; durable incident workflow orchestration does not. |
| Policy | UNSAFE_FOR_PRODUCTION | Severity/confidence compatibility policy can authorize too much without structured action risk and independent PDP. |
| Approval | UNSAFE_FOR_PRODUCTION | Pending state is partly in memory and approver identity can be supplied in request data. Immutable plan binding is absent. |
| Remediation planning | UNSAFE_FOR_PRODUCTION | Legacy engine infers action type and target from free-form text/commands; unknown action falls back to rollback. |
| Remediation executors | PLACEHOLDER | Most provider executors fail closed as not configured; local script execution is the primary real execution path. |
| Closure validation | UNSAFE_FOR_PRODUCTION | Main branch equates executor `SUCCEEDED` with latency/CPU/error/alert recovery. |
| Rollback/Saga | MISSING | No complete compensation workflow driven by validation outcome. |
| Learning | UNSAFE_FOR_PRODUCTION | Closure path writes reports to knowledge even when recovery is not independently verified. |
| Multi-tenancy | UNSAFE_FOR_PRODUCTION | Several lifecycle events use `tenant_id=default`; environment fallbacks can become `prod`. |
| Event architecture | NEEDS_HARDENING | Kafka/RabbitMQ/Azure Service Bus abstractions exist, but canonical Kafka/outbox/inbox/schema governance is incomplete. |
| Digital Twin | PARTIALLY_IMPLEMENTED | Discovery and relationships exist, but stable execution-grade resource identity is not yet authoritative. |
| Observability | NEEDS_HARDENING | Metrics/tracing hooks exist; full resolution-quality and false-automation telemetry is incomplete. |

## P0 defects confirmed in code

### Fabricated production evidence

The context connector module contains static/demo responses for ServiceNow changes, Prometheus metrics, Kubernetes, Jenkins deployments, GitHub commits and CMDB dependencies. These are useful fixtures but unsafe as implicit production defaults.

Invariant introduced by the hardening branch:

> No data is better than fake data.

Production defaults now use only evidence paths that can return real/retrieved data; demo connectors remain explicitly instantiable for tests/simulation.

### Unknown action defaults to rollback

The legacy remediation inference returns `rollback_deployment` when no known text pattern matches. This is unsafe because ambiguity becomes a destructive operational choice.

Invariant introduced:

> Unknown or ambiguous operations resolve to `unsupported_capability`, never rollback.

### Command success equals recovery

The legacy closure validator derives latency recovery, CPU normalization, error-rate recovery and cleared alerts from `RemediationStatus.SUCCEEDED`.

Invariant introduced:

> Execution success is not recovery evidence.

Closure now requires independent post-action evidence and mandatory recovery checks.

### Unverified knowledge poisoning

The legacy closure path writes every resolution report to the knowledge base.

Invariant introduced:

> Positive resolution knowledge is written only after independently verified recovery.

### Unsafe scope fallbacks

The current event path includes `tenant_id=default` and environment fallback to `prod` in multiple places.

P0 begins migration by making canonical orchestration and closure paths resolve tenant/environment explicitly in production-like deployments. Local/test mode uses explicit `local` scope for compatibility.

### Confidence-driven permissive policy

The compatibility policy previously allowed missing confidence to become `guided-auto` without approval.

P0 changes this to fail closed to HITL and keeps high-risk routing under human approval until the structured risk/PDP migration is implemented.

## Architecture debt intentionally not hidden by P0

The following are not claimed complete by this safety wave:

- authenticated approval identity from OIDC/JWT context
- immutable `plan_hash` approval binding
- OPA-backed Policy Decision Point
- production Target Resolver backed by the Operational Digital Twin
- Temporal durable workflows
- Kafka transactional outbox/inbox and schema registry
- full iterative Investigation Engine
- deterministic topology-driven impact engine
- production connector certification
- real Kubernetes/Jenkins/Ansible/Terraform/database executors
- stabilization windows and multi-sample validation
- Saga compensation and reinvestigation
- capability trust promotion/calibration
- complete removal of legacy `tenant_id=default` from every service

These remain subsequent migration waves and must not be represented as production-ready merely because the P0 compatibility safeguards exist.
