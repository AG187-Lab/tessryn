# Memory, scheduling, and state transfer

Status: proposed native services. The privileged kernel supplies capabilities, execution budgets, address spaces, registered-memory isolation, and asynchronous completion. Tokenization, parsing, placement, and membership run as native services with bounded authority. Prepared accelerator schedules and persistent queues keep ordinary coordination away from the per-token path.

## Admission and memory

Reserve actual bytes for weights, quantization scales/metadata, KV or recurrent state, activations/workspace, transport buffers, firmware, and OS/services. Raw parameter size is insufficient: a hypothetical 70-billion-parameter four-bit model starts at 35 GB decimal before these additions. Aggregate capacity alone does not prove a feasible shard plan.

Use per-model, per-request, and per-tenant budgets with headroom. Track allocated physical cache blocks, shared references, and copy-on-write expansion. Keep cache identities tied to model/checkpoint, tokenizer/template, adapters, positional configuration, numerical representation, and token sequence. Cross-tenant reuse requires an explicitly authorized sharing domain. SSD or remote tiers have measured restore costs and bounded occupancy; offload is not free memory.

Qualify nodes with model-shaped compute, memory bandwidth, sustained power/thermals, link latency/jitter, and availability. Compare pipeline cuts against tensor star/tree/ring and hybrid plans. A notebook can qualify for synchronous shards; a chassis label does not decide its role. Cache-affinity routing must also consider queue load and hotspot formation, as illustrated by [Dynamo's KV-aware routing](https://docs.dynamo.nvidia.com/dynamo/dev/knowledge-base/concepts/system-architecture/kv-aware-routing).

## Concurrent serving

Combine bounded prefill chunks, continuous batching, decode deadlines, and weighted tenant service. Adapt chunk/batch sizes to observed time-to-first-token and inter-token SLOs; long prompts must not monopolize compute. Limit retries and canceled-work retention. Separate bounded cancellation/control, decode/collective, and bulk queues. Charge a large logical transfer to its originating request and tenant across every transport chunk, so splitting does not gain priority.

Prefill/decode placement compares saved computation/queueing against cache reuse, copy/transfer, and destination admission costs. Reserve destination state before beginning handoff. Colocation remains a valid measured outcome.

## Transfer contract

KV is not universally portable. [vLLM's NIXL compatibility matrix](https://docs.vllm.ai/en/latest/features/nixl_connector_compatibility/) documents model, dtype, attention backend, layout, and feature constraints. Matching model names across arbitrary engines is insufficient.

Tessryn must specify checkpoint/layout hashes, layer ownership, token positions, KV/recurrent-state schema, quantization/scales, adapter identity, sequence epoch, integrity, and lifetime. Import only a supported compatible representation or a validated conversion. Preserve source ownership until the destination acknowledges validated state; reject stale completions. Cancellation revokes future work and releases buffers after in-flight DMA is safely complete.

Pipeline registered buffers, accelerator copies, encryption, credits, and network transfer with explicit completion ordering. Direct peer DMA is optional and profile-qualified. A logical object, transport message, and MTU are different units. Account total bytes and measure overlap rather than assuming serialized grant overhead.

Prefer locality and independent request routing across geographic regions. A WAN handoff or remote synchronous shard requires measured whole-request benefit, security, availability, and sufficient capacity; bandwidth headlines alone do not justify placement.
