# Distributed inference contract

Tessryn ships clustering and inference placement as native OS services. Stable membership and desired-state coordination remain outside the per-token execution path. This document describes the proposed contract; implementation and hardware results are pending.

## Membership and worker eligibility

Enrollment authenticates an owner-approved machine. Eligibility for a particular shard or task additionally requires compatible native drivers, kernels, formats, current resources and measured links.

A profile records usable memory, declared reserves, actual prefill/decode shapes, sustained performance, power/thermal state, availability, link latency/bandwidth/jitter and device-to-device transfer paths. Profiles expire or are refreshed when conditions change.

Use measured topology groups rather than permanent chassis categories. Stable workers, committed notebook workers and opportunistic workers can receive different leases and role budgets. A wired mains-powered notebook can be a synchronous model shard once qualified. Wi-Fi, remote links and battery operation are evaluated by measurements rather than categorical permission or speed claims.

Three stable nodes provide the first control quorum. The notebook does not need to become a voting control replica to contribute inference capacity.

## Model and layout identity

A placement identifies model/checkpoint hashes, tokenizer and positional configuration, shard boundaries, operator versions, activation precision, quantization/scales, KV or recurrent-state representation and executable backend targets.

Model identity alone does not establish state compatibility. Conversion paths must be declared, bounded and numerically qualified. Unsupported combinations are rejected before transfer or execution.

Artifacts and reusable state are tenant-scoped unless sharing is explicitly authorized. Ordinary layer sharding does not hide sensitive activations or state from the workers executing those layers.

## Memory admission

Reserve the complete execution footprint before placement:

- weights and quantization metadata;
- per-layer KV or recurrent state at declared context/concurrency limits;
- temporary operator and graph workspace;
- command queues and transport/encryption buffers;
- state transfer duplication and maximum output growth;
- firmware, OS and fragmentation reserves.

Report physical capacity and admitted capacity separately. No worker may advertise memory already reserved by another placement as independently available.

## Partition choices

Pipeline placement keeps contiguous layers, weights and per-layer state resident. Normal prefill/decode execution transfers boundary activations; it does not move the full model's KV on every token.

Partition by measured stage completion times and link costs, including sustained thermal behavior. Equal layer counts and memory-proportional splits are comparison baselines, not default optimality assumptions.

Tensor placement requires qualified collective arithmetic and measured link costs. Compare actual ring, tree and star algorithms where applicable. Homa transports messages; it does not implement reduction arithmetic or guarantee collective speedup.

Hybrid placement can use tensor parallelism inside a fast measured group and pipeline boundaries between groups. Capacity enablement, single-request latency and concurrent goodput are separate objectives. Microbatching can improve pipeline utilization while adding waiting time to individual requests.

## State ownership and handoff

Prefill and decode groups must each be independently feasible. A transfer begins only after every destination shard has reserved the required regions and execution capacity.

1. Reserve destination resources and bind model/layout identity.
2. Transfer required missing state through bounded registered buffers.
3. Verify byte integrity and declared numerical conversions.
4. Commit a placement epoch and destination ownership.
5. Fence stale source output and release source state after the required acknowledgment.

The protocol must be idempotent across retries, cancellation and coordinator changes. A partially received state object cannot become executable merely because transport completed for another shard. Control records carry group ownership; per-token work uses prepared group authority rather than global consensus for each token.

For the first demonstration, use a smaller checkpoint of the same architecture for separate prefill/decode groups if the capacity model occupies the four-device pool. More hardware is an alternative only after complete reservations are demonstrated.

## Transport path and budgets

Use one registered-region, submission and completion contract with separately qualified transport adapters. The initial accelerator path can stage through pinned host buffers with explicit copies and fences. Direct peer DMA is an optional hardware-specific program.

A pinned independently implemented Homa version must pass wire interoperability. Current and historical scheduling behavior cannot be mixed implicitly. Logical region size, transport message size and packet MTU are distinct.

Control/cancellation, decode activations/collectives and bulk model/state traffic have bounded budgets. Account bulk segmentation to its parent request and tenant. Overlap bounded outstanding messages, grants, encryption and copies where useful; do not assume one serialized round trip per chunk.

Cloud paths require an explicit permitted adapter and measured authentication/encryption overhead. Raw protocol support and switch queue priorities are not presumed.

## Client and failure semantics

Every placement carries a generation/epoch. Workers and output aggregation reject stale authority. Previously committed client-visible tokens remain part of stream history; subsequent output must not silently combine incompatible placement state.

Planned departure drains or migrates admitted work. Abrupt sleep, unplug, thermal failure or link loss triggers fencing and recovery decisions. Control quorum survival does not recreate missing model state.

Resume requires committed state or reconstructable context and enough surviving/replacement capacity. Otherwise return an explicit capacity or partial-response outcome. The stream protocol defines request identity, committed token position and replay/deduplication behavior.

Cancellation receipt, stopping future launches, stopping accepted output and releasing memory are separate measurable events. A backend cannot promise immediate interruption of a hardware kernel it cannot preempt.

## Positive first product gate

Four supported small machines, including one exact wired mains-powered native-OS notebook, each execute a resident shard. The model exceeds every worker's realistic admitted local capacity but fits the group with declared headroom. Three stable nodes maintain control quorum.

Evidence must show notebook contribution to model execution, not only discovery, drafting or cache assistance. A failed placement may correctly refuse admission, but that result does not satisfy this positive gate.

Publish first-token and per-token distributions, concurrent goodput, complete memory accounting, actual transport traces and failure outcomes. Register numeric service targets and workload/load/thermal conditions before execution. Compare against feasible smaller groups and a tuned same-hardware reference where available.

## Research basis and limits

- [Kafila](https://arxiv.org/abs/2609.34045) studies heterogeneous trusted-device partitioning and separates network effects from stage balancing.
- [TPI-LLM](https://arxiv.org/abs/2410.00531) provides evidence for CPU-oriented tensor parallelism on small devices; it is not a universal GPU/Wi-Fi scaling result.
- [Prima.cpp](https://arxiv.org/abs/2504.08791) demonstrates heterogeneous home-cluster capacity and workload-specific performance.
- [Distributed Internet inference](https://arxiv.org/abs/2312.08361) provides fault-tolerant placement research, with performance measured against its chosen baselines.
- [Homa 2018](https://people.csail.mit.edu/alizadeh/papers/homa-sigcomm18.pdf) motivates receiver scheduling and message priorities; accelerator state lifecycle and collectives require additional mechanisms.

These papers supply principles and evidence, not implementation dependencies or proof of Tessryn performance. There is no established one-prefill-chunk bound for end-to-end p99 latency.

