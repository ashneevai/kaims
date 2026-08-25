# KaiMS Closed-Loop Validation

## Purpose

Wave 4 separates remediation execution from incident recovery. An executor reporting success proves only that the requested capability completed from the executor's perspective. KaiMS closes an incident automatically only after independent live validation proves recovery.

## Validation contract

Every structured `RemediationPlan` carries a pre-execution `ValidationPlan`. The plan defines:

- baseline window
- stabilization period
- validation interval
- maximum validation window
- required consecutive successful windows
- required and optional validation checks

A validation check identifies its provider, signal/query, operator, expected value, resource identity, and whether it is mandatory.

KaiMS does not invent success criteria after execution. A remediation action with no pre-existing validation plan fails closed with `VALIDATION_DATA_UNAVAILABLE` and `PLAN_MISSING`.

## Runtime flow

```text
Execution completes
  -> stabilization timer
  -> collect independent live observations
  -> evaluate required checks
  -> persist validation window
  -> wait validation interval
  -> repeat
  -> require N consecutive fully healthy windows
  -> classify final outcome
```

The current live provider supports Prometheus instant queries. For a Prometheus validation check, `ValidationCheck.signal` is PromQL. The provider records the query URL, query, returned value, evidence identifier, and response content hash. Unsupported providers do not produce synthetic observations; mandatory missing observations make validation inconclusive or unavailable.

## Outcomes

`RECOVERED`
: Every mandatory check is present and healthy for the configured number of consecutive windows. This is the only automated outcome that may close an incident or write positive resolution knowledge.

`PARTIALLY_RECOVERED`
: Some mandatory recovery checks pass while others remain unhealthy. The incident returns to assessment/investigation.

`UNCHANGED`
: Live evidence is available but required recovery checks do not show recovery. The next action is reinvestigation or an alternative remediation plan.

`WORSE`
: Independent validation detects a post-action regression. The next action is `ROLLBACK_REQUIRED`. Rollback orchestration is implemented in a later migration wave.

`INCONCLUSIVE`
: Evidence is incomplete/conflicting, or healthy observations occurred without satisfying the required consecutive-window threshold. KaiMS extends validation or requests HITL rather than claiming recovery.

`VALIDATION_DATA_UNAVAILABLE`
: Independent validation evidence cannot be obtained, the provider is unavailable/simulation-only, or the validation plan is missing. KaiMS never claims recovery.

## Incident-state mapping

| Validation outcome | Incident state | Next workflow intent |
| --- | --- | --- |
| RECOVERED | CLOSED | close |
| PARTIALLY_RECOVERED | INVESTIGATING | reassess |
| UNCHANGED | INVESTIGATING | reinvestigate |
| WORSE | REMEDIATING | rollback required |
| INCONCLUSIVE | VALIDATING | extend validation / HITL |
| VALIDATION_DATA_UNAVAILABLE | VALIDATING | obtain telemetry / HITL |

Execution status is intentionally not part of the recovery decision. A failed execution may still be followed by natural recovery and can therefore produce `RECOVERED` if independent evidence proves it. Conversely, a successful execution cannot produce recovery while the original alert, SLO, health, or other mandatory validation check remains unhealthy.

## Persistence and audit

Each complete validation cycle creates a canonical `ValidationAssessment` containing:

- incident and remediation-action identifiers
- validation-plan identifier
- outcome
- stabilization and interval configuration
- consecutive-success target and achieved count
- every validation window
- normalized observations
- evidence identifiers
- reason
- next workflow action

Assessments are persisted through `CanonicalResolutionStore` as `validation_assessment` objects. Closure events expose the validation outcome, window count, evidence count, and next action.

## Positive-learning gate

KaiMS writes a `ResolutionReport` to positive knowledge only when all of the following are true:

1. independent validation is enabled;
2. the validation plan is present;
3. independent evidence exists;
4. the required consecutive healthy-window threshold is met; and
5. the final outcome is exactly `RECOVERED`.

All other outcomes remain non-positive operational history.

## Safety invariants

- Never infer recovery from exit code, API success, or remediation status.
- Never fabricate validation observations.
- Never use simulation-only evidence to prove production recovery.
- Never close with missing mandatory validation checks.
- Never close after only a transient healthy sample when multiple windows are required.
- Never publish positive resolution knowledge without independently verified recovery.
- Treat telemetry unavailability as uncertainty, not success.

## Wave boundary

Wave 4 establishes independent evidence-backed recovery validation and workflow intent. Full Saga rollback/compensation and iterative reinvestigation execution are intentionally deferred to Wave 8. OPA and immutable approval enforcement are Wave 5; Temporal durable lifecycle orchestration is Wave 6.
