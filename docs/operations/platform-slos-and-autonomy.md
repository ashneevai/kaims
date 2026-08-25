# KaiMS Platform SLOs & Autonomy Control

KaiMS autonomy is a runtime privilege, not a static configuration. The platform may operate in `AUTONOMOUS`, `GUIDED`, `HITL_ONLY`, or `KILL_SWITCH` mode based on live reliability and safety signals.

## SLO gates

| SLO | Target | Critical |
|---|---:|---|
| Alert to triage P95 | <= 30s | No |
| Triage to RCA P95 | <= 180s | No |
| Approval wait P95 | <= 600s | No |
| Remediation to validation P95 | <= 300s | No |
| Event processing success | >= 99.9% | Yes |
| Audit chain validity | 100% | Yes |
| Duplicate production effect | 0% | Yes |
| Unsafe action escape | 0% | Yes |
| Autonomous recovery success | >= 95% | No |
| Validation evidence coverage | >= 99% | Yes |

## Automatic degradation

- `AUTONOMOUS`: all required SLOs are healthy. Policy-approved low-risk actions may execute without HITL.
- `GUIDED`: a non-critical SLO is breached. Production-changing actions require approval.
- `HITL_ONLY`: any critical SLO is breached/missing, a critical dependency is unavailable, or audit integrity is broken. Read-only diagnosis remains available but production changes require HITL.
- `KILL_SWITCH`: explicit operator emergency stop. No autonomous workflow action is permitted until cleared through governed operations.

Autonomy must never automatically increase immediately after a single healthy sample. Promotion back to a higher autonomy level should require a sustained healthy window and recovery certification; degradation is immediate.

## Golden signals

The operations control plane should expose request/event rate, error rate, latency, queue lag/backlog, DLQ depth, consumer retries, Redis replay-guard health, DB pool/failover state, LLM/model errors and latency, remediation success/failure/abort, validation result distribution, HITL queue age, audit-chain validity, duplicate-prevention count, unsafe-action prevention count, and recovery certification status.

## Promotion rule

A release or runtime environment cannot enter `AUTONOMOUS` mode unless Wave 8-C chaos certification is valid, the immutable audit chain is healthy, replay/idempotency coordination is available, validation evidence coverage is within SLO, and no critical SLO is breached.
