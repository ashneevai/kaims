# KaiMS Dual-View Product Experience

## Product principle

KaiMS must keep operational complexity underneath and present clarity on the surface.

Every major screen supports two information densities:

- **Simple View** — default. Answers what is happening, why it matters, what Kai believes, what needs a decision, and whether recovery worked. Uses visual explanations and progressive disclosure.
- **Detail View** — engineer view. Exposes complete evidence, telemetry, topology, payloads, policy decisions, connector detail, execution diagnostics, validation data and audit metadata.

The two views are not separate products and must never disagree. They are two presentations of the same underlying state.

## Global rules

1. Simple View is the default for new users.
2. View preference persists locally and may later be moved into the user profile API.
3. Simple View never hides a critical warning, approval requirement, blocked state, contradictory evidence, failed validation or rollback condition.
4. Detail View never changes authorization or execution capability. It only changes information density.
5. Raw JSON, stack traces, connector payloads and long technical records belong in Detail View or explicit advanced disclosures.
6. Long text is replaced by a visual summary plus short explanatory copy wherever the underlying data supports it.
7. No chart may imply data that KaiMS did not actually receive.

## Visual representation policy

Prefer the following representation before long prose or large tables:

| Information | Preferred representation |
| --- | --- |
| Overall health/readiness | segmented score ring + status label |
| Incident lifecycle | horizontal/vertical lifecycle rail |
| RCA confidence | confidence meter + evidence count + uncertainty state |
| Competing hypotheses | ranked bars/cards with supporting/contradicting evidence |
| Causality | causal evidence graph |
| Topology/dependencies | resource graph / dependency map |
| Blast radius | topology highlight + impacted service count |
| Recent changes | correlated change timeline |
| Telemetry change | compact trend/sparkline with baseline |
| Risk | risk meter + contributing-factor chips |
| Approval | decision card showing effect/risk/rollback/validation |
| Execution | step timeline with deterministic capability status |
| Validation | before/after metric comparison + consecutive healthy windows |
| Onboarding | progress journey + readiness rings + connection map |
| Connector health | provider grid with connected/degraded/failed states |
| Estate composition | hierarchy map / compact distribution visual |
| SLO coverage | coverage bars/rings and gap list |

Tables remain appropriate for exact comparison, sorting, filtering and audit records, particularly in Detail View.

## Page model

### Operations Command Center

**Simple View**

Show one operational story:

- estate health
- production applications at risk
- active critical incidents
- incidents Kai resolved safely
- decisions waiting for a human
- most important recent change
- autonomy/readiness score
- MTTR or recovery trend where real data exists

Use status rings, small trends, a production-health map and a short attention queue. Avoid architecture internals.

**Detail View**

Add per-environment health, connector freshness, queue/event lag, model/agent performance, automation rates, validation rate, cost, and technical drilldowns.

### Incidents list

**Simple View**

Each incident row/card answers:

- severity
- affected application
- plain-language symptom
- affected users/services if known
- Kai investigation state
- leading cause state
- action required
- elapsed time

**Detail View**

Add resource IDs, correlation IDs, signal counts, evidence source counts, confidence dimensions, workflow IDs, event versions and connector status.

### Incident Workspace

**Simple View**

Use a seven-stage visual story:

`Observe → Understand → Reason → Govern → Act → Verify → Learn`

Primary modules:

1. What happened
2. Impact map
3. What changed
4. Kai diagnosis and confidence
5. Evidence graph
6. Recommended recovery and risk
7. Decision required, if any
8. Execution/validation timeline
9. Recovery outcome

Alternative hypotheses and contradictory evidence remain visible when material.

**Detail View**

Expose correlated signals, raw evidence, provider queries, topology metadata, hypothesis assessments, causal edges, preflight, risk factors, OPA decision, immutable plan hash, execution output, stabilization checks, validation windows, rollback records and learning/audit entries.

### Approvals

**Simple View**

A single decision card:

- what happened
- why Kai recommends this action
- exact affected target in human-readable form
- expected effect
- confidence
- risk
- blast radius
- rollback available yes/no
- validation plan
- Approve / Modify / Reject

**Detail View**

Add full structured remediation plan, preconditions, target resource IDs/version, connector, policy version/rules, plan hash, dry-run output and audit metadata.

### Applications

**Simple View**

Application card/overview should show:

- health
- environments
- critical dependencies
- current incidents
- monitoring coverage
- readiness/autonomy score
- top gap to fix

**Detail View**

Expose resources, cloud accounts, namespaces, workloads, endpoints, databases, queues, owners, SLOs, connector mappings and identifiers.

### Estate / Resource Explorer

**Simple View**

Use a navigable visual hierarchy and health topology. Default to business application → service → runtime/dependency.

**Detail View**

Expose all entity types, IDs, source/provenance, last verified time, inferred relationships, metadata and advanced filtering.

### Changes

**Simple View**

Use a timeline with change type, service, environment and correlation to active incidents. Highlight only relevant changes.

**Detail View**

Expose commits, deployments, configuration changes, IaC records, provider references, temporal score, topology score and causal confidence separately.

### Knowledge

**Simple View**

Show coverage, freshness, trusted/verified material and the most important missing operational knowledge.

**Detail View**

Expose document metadata, chunks/retrieval diagnostics, provenance, verification status and failed/unconfirmed learning records.

### Automation / Capabilities

**Simple View**

Show capability, trust level, environment scope, recent verified success rate and whether HITL is required.

**Detail View**

Expose schemas, permissions, preconditions, idempotency, blast-radius limits, policy, rollback, validation and execution history.

### Integrations

**Simple View**

Provider cards show Connected / Degraded / Failed / Pending and what capability the integration enables.

**Detail View**

Expose endpoint, secret reference, permission diagnostics, latency, rate limits, last success/failure and supported read/write capabilities.

### Onboarding

**Simple View**

Use a guided visual journey with progressive disclosure. Each step answers one decision only. Discovery results appear as a visual estate/dependency map. Finish with readiness rings and concrete gaps.

**Detail View**

Expose full connector parameters, discovery metadata, resource mappings, custom policy, technical monitoring recommendations and test diagnostics.

## Explainability pattern

Every consequential Kai conclusion uses the same hierarchy:

1. **Conclusion** — one sentence.
2. **Confidence** — visual meter plus calibrated state.
3. **Why** — 2–4 strongest evidence points.
4. **What conflicts** — contradictory evidence, if any.
5. **What is missing** — data gaps.
6. **Technical detail** — available in Detail View / disclosure.

Never force an RCA when evidence is insufficient.

## Implementation sequence

1. Global Simple/Detail experience shell and persistence.
2. Shared visual primitives.
3. Operations Command Center migration.
4. Incident list and Incident Workspace migration.
5. Approval migration.
6. Onboarding/readiness migration.
7. Applications and Estate/Resource Explorer migration.
8. Changes, Knowledge, Capabilities and Integrations migration.
9. Remove duplicate legacy layouts after parity tests.
10. Split monolithic `App.jsx` into page/domain components as each screen migrates.

## Architectural cleanup requirement

The current React frontend is heavily concentrated in `App.jsx`. Do not grow that file further. Every redesigned screen must be extracted into page/domain components and use shared design-system/experience primitives. The migration should reduce `App.jsx` progressively while preserving existing API contracts and behavior.

## Quality gates

Every migrated screen must pass:

- Simple View usability review
- Detail View completeness review
- no critical state hidden by Simple View
- keyboard navigation
- WCAG 2.2 AA contrast/focus
- reduced-motion behavior
- 1280px and 1440–1920px desktop layouts
- tablet approval/review layout
- loading/empty/error/partial-data states
- visual regression tests
- existing functional E2E tests

The final experience should make KaiMS understandable to an operations leader in seconds and useful to an SRE without sacrificing evidence or control.
