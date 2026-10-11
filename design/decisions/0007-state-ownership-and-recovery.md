# ADR 0007: Use transactional group state ownership

Status: Accepted design direction. Protocol implementation: pending.

## Decision

Normal pipeline stages retain their per-layer state. Prefill/decode handoff reserves every destination shard, validates compatibility and integrity, commits a placement epoch, fences stale output and releases source ownership in declared order.

Independent prefill and decode placements must fit simultaneously when that schedule requires them. Use a smaller checkpoint for the first handoff demonstration if the capacity model occupies the four-device pool.

## Consequences

Transport completion alone does not make a partially received group executable. Retries and cancellation must be idempotent across coordinator changes.

Control quorum is not model-state replication. Resume requires committed/reconstructable state and sufficient surviving or replacement capacity. Otherwise expose a capacity or partial-response outcome.

Client streams identify committed token positions and placement generations. Cancellation acknowledgment, output fencing and memory reclamation are separate events.

## Acceptance link

[Distributed inference](../distributed-inference.md), DIST01/DIST03/DIST04 in [the backlog](../../planning/backlog.json).

