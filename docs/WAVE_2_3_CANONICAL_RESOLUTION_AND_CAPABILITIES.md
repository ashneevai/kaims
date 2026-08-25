# KaiMS Resolution Modernization — Wave 2 + Wave 3

## Status

Wave 2 (canonical resolution models) and Wave 3 (capability-governed planning foundation) are implemented incrementally on top of the Wave 1 safety hardening branch.

## Wave 2 — canonical resolution models

The shared `common.resolution_models` module now defines the authoritative contracts for:

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

## Wave 3 — capability registry and structured planning

The Capability Registry is now the governed allowlist for operational actions. A capability declares:

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

`TargetResolver` remains the execution identity authority for this migration wave. It requires stable `kai://` identity, verified/non-stale provenance, >=0.90 confidence, matching connector and unchanged resource version.

`PreflightEngine` now checks before governance/execution:

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

`CapabilityRegistry -> TargetResolver -> Capability/Target validation -> Preflight -> RiskEngine -> Autonomy restriction -> PlanSnapshot`

It does not generate shell, kubectl, SQL, Terraform or cloud commands.

## Safety behavior

A structured plan is rejected when:

- capability is not registered
- target is not a stable Kai resource identity
- topology/identity is inferred, stale or low-confidence
- target version changed after planning
- target resource type or environment is not permitted by the capability
- mandatory preflight fails
- required validation is unavailable
- high/critical reversible action lacks rollback

High/critical risk or HITL-only capabilities are forced to `HITL_REQUIRED` by the structured planner. Policy-as-code remains a later independent governance wave; this planner does not self-authorize execution.

## Backward compatibility

Legacy recommendation/action contracts remain temporarily available for migration. They are not the target architecture. The existing safe remediation bridge already validates structured plans when present and blocks unsupported/ambiguous actions rather than defaulting them to rollback.

The next migration step is to make the resolution agent emit registered capability intent and persisted `RemediationPlan` records by default, then make the legacy text-action bridge opt-in only for migration/test environments.

## Tests

`backend/tests/test_wave2_wave3_resolution.py` verifies:

- simulation evidence is not production RCA evidence
- multiple hypotheses remain explicit
- structured planning resolves the stable target
- preflight and deterministic risk execute before snapshot creation
- stale target versions are blocked
- missing validation is blocked
- immutable snapshots detect executable plan tampering

## Deferred to later waves

Not claimed complete in Wave 2/3:

- database persistence/migrations for every new canonical aggregate
- OPA policy service
- authenticated immutable approval records
- Temporal durable workflow
- real stabilization-window validation
- execution worker signing/idempotency persistence
- full Operational Digital Twin repository backing `TargetResolver`
- iterative hypothesis-generation engine
- Saga rollback/reinvestigation
