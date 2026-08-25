# KaiMS Chaos & Recovery Certification

## Promotion rule

A production release MUST NOT be certified for autonomous remediation unless every required chaos scenario ends in exactly one safe terminal state:

- `RECOVERED`
- `ROLLED_BACK`
- `HITL`
- `QUARANTINED`

The run fails certification if an incident is silently lost, a production effect executes twice, the immutable audit chain is invalid, replay coordination is unverified, or a recovered/rolled-back state lacks independent validation evidence.

## Required scenarios

| Scenario | Fault injection | Required invariant |
|---|---|---|
| pod-kill-context | Terminate context-agent during evidence collection | Event and trace survive; evidence collection can resume |
| pod-kill-remediation | Terminate remediation-engine during execution | No duplicate production effect; lock/idempotency/audit remain authoritative |
| redis-outage | Remove Redis during a privileged execution path | Autonomous execution fails closed |
| rabbitmq-partition | Interrupt RabbitMQ connectivity | Durable event is replayed after recovery; no silent loss |
| kafka-rebalance | Force consumer rebalance during processing | Offset is not committed before durable completion |
| database-failover | Fail primary database during lifecycle persistence | Recovery satisfies declared RPO/RTO and integrity gates |
| executor-timeout | Timeout Kubernetes/Jenkins/Terraform executor | Stage aborts or holds; no uncontrolled next stage |
| duplicate-delivery | Deliver the same remediation event twice | Exactly one production effect |
| audit-chain-tamper | Modify an immutable audit record | Chain verification fails and recovery/promotion is blocked |
| network-partition | Partition lifecycle controller from broker | No lifecycle event loss; processing resumes safely |

## Evidence required per run

Each scenario must retain the incident ID, flow/trace/correlation IDs, injected fault timestamps, broker delivery identity/offset or delivery tag, replay/idempotency key, remediation action IDs, pre-execution snapshot hash, audit ledger chain head, validation evidence IDs, terminal state, observed RPO, observed RTO, and certification result.

## Certification gates

1. No event loss.
2. No duplicate production effect.
3. No unresolved processing lease after recovery window.
4. Immutable audit chain verifies.
5. Recovered or rolled-back states have independent live validation evidence.
6. Action execution count does not exceed the approved retry/remediation budget.
7. Stateful dependency recovery meets the Wave 8-C2 RPO/RTO contract.
8. Any ambiguous state is `HITL` or `QUARANTINED`, never silently closed.

## Recommended execution environments

Run the suite first against the fault lab, then a dedicated non-production Kubernetes environment with the same RabbitMQ/Kafka/Redis/database topology as production. Production fault injection requires an approved change window and separate operator/approver identities.
