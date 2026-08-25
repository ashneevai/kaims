# KaiMS Resolution Modernization — Wave 2 + Wave 3

## Status

Wave 2 (canonical resolution models and durable canonical state) and Wave 3 (capability-governed planning, target resolution and preflight) are implemented incrementally on top of the Wave 1 safety hardening branch.

The migration rule is now explicit:

`AI recommendation -> registered capability -> stable Kai target -> parameter validation -> preflight -> risk -> immutable RemediationPlan -> governance`

A legacy text recommendation is never execution authority.

## Wave 2 — canonical resolution models

The shared `common.resolution_models` module defines the authoritative contracts for:

- `Evidence` with tenant, incident, resource, provider, provenance, immutable content hash, quality, trust and explicit LIVE/SIMULATION/DEGRADED/UNAVAILABLE mode.
- `EvidenceAssessment`.
- `CausalRelationship`.
- `Hypothesis` with supporting and contradicting evidence and explicit lifecycle status.
- `InvestigationIteration` and `Investigation` with bounded LLM/query/iteration/cost budgets.
- `InvestigationConclusion` with CONFIRMED/LIKELY/INCONCLUSIVE/INSUFFICIENT_EVIDENCE/BUDGET_EXHAUSTED outcomes.
- `ValidationPlan` and `ValidationCheck`.
- `RollbackPlan` including pre-action state.
- `PreflightAssessment`.
- `RiskAssessment`.
- `RemediationPlan`.
- `PlanSnapshot` with canonical SHA-256 plan binding.

Simulation evidence is structurally distinguishable and cannot be treated as production-usable evidence through `Evidence.usable_for_production_rca`.

### Durable canonical state

`common.resolution_store.CanonicalResolutionStore` persists canonical objects in a versioned system-of-record envelope keyed by object type, object ID and revision.

The migration store currently persists:

- Evidence
- Investigation
- RemediationPlan revisions
- immutable PlanSnapshot revisions

Every persisted plan is checked against its snapshot before write. Tenant scope is mandatory. Plans can be retrieved by tenant and plan ID, and all canonical objects for an incident can be enumerated for audit/replay.

A single migration envelope is intentional for this phase: it makes Wave 2 durable without forcing all existing services through a disruptive schema rewrite. Dedicated high-volume tables can replace the envelope later behind the same repository contract.

## Wave 3 — authoritative capability registry and structured planning

The Capability Registry is the governed allowlist for operational actions. It now includes initial cross-platform definitions for:

- Kubernetes restart, rollback and scale
- Linux and Windows service restart
- application recovery endpoints
- database diagnostics, session termination and failover
- Kafka consumer restart and rebalance
- Airflow task retry and DAG restart
- cloud VM restart and instance-group scaling
- scoped cache keyspace invalidation
- Jenkins rollback
- Terraform rollback

A capability declares:

- stable capability ID and version
- provider
- description
- supported resource types
- required permissions
- input schema
- preconditions
- dry-run support
- validation requirement/template
- rollback capability and reversibility
- allowed environments
- blast-radius limit
- trust level and approval requirement
- timeout
- retry strategy
- idempotency strategy
- per-target concurrency limit

Unknown capability IDs fail closed with `UNSUPPORTED_CAPABILITY`.

Capability input schemas are validated deterministically before a plan is created. Missing required parameters, wrong primitive types and invalid numeric bounds are rejected before governance.

`TargetResolver` is the execution identity authority for this migration wave. It requires stable `kai://` identity, verified/non-stale provenance, >=0.90 confidence, matching connector and unchanged resource version.

`PreflightEngine` checks before governance/execution:

- stable target identity
- target version freshness
- connector availability
- credential validity
- permission sufficiency
- capability/resource compatibility
- environment allowlist
- preconditions
- incident still active
- conflicting remediation
- change freeze
- validation availability
- rollback availability for high/critical reversible actions

`StructuredResolutionPlanner` composes the safe planning sequence:

`CapabilityRegistry -> Parameter validation -> TargetResolver -> Capability/Target validation -> Preflight -> RiskEngine -> Autonomy restriction -> PlanSnapshot`

It does not generate shell, kubectl, SQL, Terraform or cloud commands.

## Resolution-agent migration

The resolution-agent now contains `StructuredPlanBridge`.

After AI reasoning, the bridge may produce a governance-ready plan only when all of the following are supplied by trusted operational context:

- an exact registered capability ID
- an exact stable `kai://` target resource ID
- an Operational Digital Twin/resource-catalog record for that target
- connector identity
- connector readiness
- credential readiness
- permission readiness
- precondition result
- current resource version
- validation definition

It never infers a target from service display names or model-generated command text.

When the facts are complete, the agent emits and persists:

- `remediation_plan`
- `plan_hash`
- `plan_revision`
- `recommended_capability`
- `target_resource_id`
- `connector_id`
- `planning_status=STRUCTURED_PLAN_READY`
- `governance_status=POLICY_EVALUATION_REQUIRED`

`execution_allowed` remains false. Wave 3 creates a governance-ready plan; it does not authorize itself.

When execution-grade facts are incomplete, the agent emits states such as:

- `CAPABILITY_SELECTION_REQUIRED`
- `TARGET_RESOLUTION_REQUIRED`
- `VALIDATION_PLAN_REQUIRED`
- `BLOCKED_PRE_GOVERNANCE`

No missing fact is replaced with a guessed namespace, environment, connector, target or permission result.

The resolution event path also no longer persists `tenant_id=default` or an invented production environment for this governed path. Missing tenant/environment scope fails persistence rather than creating ambiguous production state.

## Safety behavior

A structured plan is rejected when:

- capability is not registered
- capability parameters violate its schema
- target is not a stable Kai resource identity
- topology/identity is inferred, stale or low-confidence
- target version changed after planning
- connector identity does not match
- target resource type or environment is not permitted by the capability
- mandatory preflight fails
- required validation is unavailable
- high/critical reversible action lacks rollback
- high/critical planning requires a dry run that the capability cannot support

High/critical risk or HITL-only capabilities are forced to `HITL_REQUIRED` by the structured planner. Policy-as-code remains a later independent governance wave; this planner does not self-authorize execution.

## Backward compatibility

Legacy recommendation/action contracts remain temporarily available for migration and UI display. The existing safe remediation bridge validates structured plans when present and blocks unsupported/ambiguous actions rather than defaulting them to rollback.

The new path is authoritative whenever a structured plan exists. Legacy commands remain display-only and must not grant execution authority.

## Tests

Wave 2/3 coverage includes:

- simulation evidence is not production RCA evidence
- multiple hypotheses remain explicit
- structured planning resolves the stable target
- preflight and deterministic risk execute before snapshot creation
- stale target versions are blocked
- missing validation is blocked
- immutable snapshots detect executable plan tampering
- the resolution-agent builds a plan only from verified target/preflight context
- missing connector/preflight evidence fails closed
- display text is never used to infer an execution target
- capability parameter schemas are enforced
- the cross-platform capability catalog is registered

## Deferred to later waves

Not claimed complete in Wave 2/3:

- OPA policy service and PolicyDecisionPoint/PolicyEnforcementPoint
- authenticated immutable approval identity and approval persistence migration
- Temporal durable workflow
- real stabilization-window telemetry validation
- signed isolated execution jobs/workers
- persistent idempotency/resource locks
- full Operational Digital Twin database implementation behind `TargetResolver`
- iterative hypothesis-generation/falsification engine
- Saga rollback and reinvestigation

The recommended next milestone is Wave 4: independent validation with stabilization windows and repeated telemetry checks, followed by Wave 5 policy/approval hardening.
