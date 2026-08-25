# KaiMS Resolution Safety Hardening — Implementation Summary

## Scope

This branch implements the first production-safety wave against the resolution lifecycle. It intentionally hardens unsafe behavior before introducing larger architectural migrations such as Temporal, OPA, Digital Twin execution identity and full connector replacement.

## Implemented

### Production-safe context defaults

Added `context_agent.safe_context.ProductionContextIntelligenceAgent` and made it the package default.

Default production context no longer implicitly enables static/demo connectors for:

- ServiceNow
- Prometheus
- Kubernetes
- Jenkins
- GitHub
- CMDB

The live/retrieved context paths retained by default are:

- Discovery MCP
- bounded local evidence
- vector/RAG retrieval

Static connectors remain available only when explicitly instantiated, which preserves test/simulation compatibility.

### Independent closure validation

Replaced the old success-by-status validator with a fail-closed validation contract.

Without a configured live evidence provider the result is:

`VALIDATION_DATA_UNAVAILABLE`

and:

- `health_restored = false`
- `alerts_cleared = false`
- no positive closure claim is made

Recovery requires live evidence plus mandatory checks for original-alert clearance, service-health recovery and error-rate recovery.

### Verified learning gate

Closure continues to persist the resolution report for audit/history, but positive knowledge is saved only when:

- recovery is independently validated
- validation has evidence
- validation outcome is recovered/succeeded

Failed/unverified attempts therefore cannot become successful-resolution RAG examples through this path.

### Unknown-action safety

Added `SafeRemediationEngine` as the exported engine compatibility layer.

Legacy action inference remains available only as a temporary compatibility bridge. If legacy inference lands on rollback without explicit rollback intent, the result becomes:

`unsupported_capability`

and the existing execution allowlist blocks execution.

### Capability Registry foundation

Added `common.capability_registry` with initial canonical capabilities and trust metadata.

Legacy actions are explicitly mapped to registered capability IDs. The compatibility engine records:

- capability ID
- capability version
- risk class
- trust level
- validation requirement

Unknown legacy actions with no capability mapping are blocked.

### Fail-closed compatibility policy

The current policy layer now requires HITL when:

- risk tier is high
- confidence is absent
- confidence is below the auto threshold

This is intentionally conservative until the structured remediation risk model and independent OPA/PDP are implemented.

### Scope hardening

Canonical orchestration and closure paths no longer invent production scope by silently using:

- `tenant_id=default`
- `environment=prod`

Production-like deployments require resolved scope. Local/test/simulation modes may use explicit `local` scope for backward compatibility.

## Tests added or updated

Regression coverage now verifies:

- static demo connectors are not production defaults
- unknown remediation does not become rollback
- closure fails closed without independent evidence
- capability mappings resolve only to registered capabilities
- unknown capabilities are rejected
- production scope fails when tenant/environment are missing
- development mode uses explicit local scope
- compatibility policy fails closed for missing/guided confidence

## Remaining migration waves

This branch does not claim completion of:

1. OIDC-derived approver identity and step-up authorization
2. immutable remediation plan snapshots and plan hashes
3. structured `RemediationPlan`, `RiskAssessment`, `ValidationPlan` and `RollbackPlan` persistence
4. execution-grade Target Resolver backed by the Operational Digital Twin
5. OPA policy service
6. Temporal durable incident workflow
7. iterative multi-hypothesis Investigation Engine
8. production execution workers and signed execution jobs
9. stabilization windows and repeated telemetry validation
10. rollback/Saga and reinvestigation
11. Kafka transactional outbox/inbox and Schema Registry
12. tenant-hardening of every remaining service/event producer
13. capability trust promotion and confidence calibration

## Migration principle

This branch preserves deployability by introducing safety wrappers and compatibility bridges instead of performing a big-bang rewrite.

The next wave should replace free-form approval/remediation contracts with immutable structured plans and authenticated approval identity, then introduce the independent risk/PDP layer before enabling broader autonomous execution.
