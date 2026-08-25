# KaiMS Production Readiness & Release Certification

## Decision model

KaiMS releases are classified as `GO`, `CONDITIONAL_GO`, or `NO_GO`. A critical gate failure always results in `NO_GO`, regardless of aggregate score. Autonomous production remediation is permitted only for a full `GO` certification.

## Certification gates

| Gate | Weight | Critical |
|---|---:|---|
| Unit/integration tests | 10 | Yes |
| Architecture contract tests | 8 | Yes |
| Security tests | 12 | Yes |
| Tenant isolation tests | 10 | Yes |
| Immutable audit verification | 10 | Yes |
| Chaos/recovery certification | 12 | Yes |
| Connector certification | 8 | No |
| SLO certification | 10 | Yes |
| Load/performance certification | 8 | No |
| Rollback/recovery scenarios | 7 | Yes |
| Autonomous-resolution scenarios | 5 | No |

## Required evidence

Evidence must be tied to the exact release SHA and environment. It should include test reports, security results, tenant boundary tests, audit-chain verification, Wave 8-C chaos results, Kubernetes/Jenkins/Terraform connector certification, Wave 8-D SLO snapshot, load/latency results, rollback exercises, autonomous-resolution scenarios, and unresolved defects/exceptions.

## Promotion rules

1. Any critical gate failure or missing critical evidence = `NO_GO`.
2. Score >= 95 with no critical failures = `GO`.
3. Score >= 85 with no critical failures = `CONDITIONAL_GO`; autonomous production execution remains disabled and exceptions require explicit owners/expiry.
4. Score < 85 = `NO_GO`.
5. A `GO` release still starts at `HITL_ONLY` after deployment until runtime SLO health and recovery certification are confirmed; runtime autonomy may then be promoted through the Wave 8-D control plane.
6. Any post-release critical SLO breach immediately degrades autonomy regardless of release certification.

## Final certification report

The release record should contain release SHA, image digests/SBOM references, environment/region, certification timestamp, score, decision, each gate result, evidence links, open risks, exception owner/expiry, approved autonomy ceiling, approvers, and immutable audit ledger reference.
