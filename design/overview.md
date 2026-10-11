# Product scope

Tessryn is a complete original kernel and operating system for AI agents and inference. Its central abstraction is bounded execution over owned local resources and explicitly placed distributed work. Native cluster services ship with the OS, so an authorized worker can join, advertise qualified capabilities and receive work without assembling a separate orchestration stack.

## Required outcomes

1. Boot on qualified physical servers and laptops, with installable images and recoverable updates.
2. Execute models through native CPU and accelerator backends, beginning with modern Intel/AMD x86-64 CPUs and one exact NVIDIA hardware family.
3. Form authenticated clusters, distribute verified model artifacts, reserve resources, place shards and replicas, and reconcile desired state.
4. Serve mixed short and long prompts using continuous batching, bounded prefill work, prompt/state reuse where valid, cancellation and tenant budgets.
5. Support pipeline, tensor and feasible hybrid inference based on measured compute and communication costs.
6. Let qualified laptops participate as real model shards. Intermittent workers can contribute independent inference, evaluation, verified drafting or artifact caching.
7. Support cloud images and geographic operation through independently qualified boot, virtual-device, network and accelerator profiles.
8. Provide native task submission, fan-out/join, identities, durable task metadata and bounded capabilities for agents. Inference is the first workload, not the entire long-term agent API.
9. Evaluate recursively generated software improvements under independent numerical, performance and recovery checks.

Literal 32-bit i386 is outside the initial target. Intel/AMD CPU support is distinct from AMD GPU support. Apple M5 is an AArch64 platform and needs independent platform, GPU and transport bring-up.

## First demonstration

Three stable small nodes and one qualified wired laptop all boot Tessryn and execute resident shards of the same model. Its complete admitted state exceeds every participant's local capacity and fits the group with explicit headroom. The notebook must be on the live inference path.

Measure capacity enablement, first-token latency, token latency and concurrent goodput separately. Compare feasible placement strategies and an appropriate reference stack on the same hardware/model/precision. Demonstrate authenticated joining, cancellation, planned drain, abrupt worker loss, tenant isolation and recoverable updates.

Prefill/decode separation has an additional feasible-memory gate. Use a smaller checkpoint for that demonstration if two independent placements of the capacity model cannot coexist. Coordination surviving a notebook loss does not imply inference can continue without its state; recovery needs a replica, sufficient surviving resources or a qualified replacement.

## Open implementation choices

The primary language, bootloader/toolchain, first exact hardware profiles, model architecture/precision and numeric service targets are resolved by the initial platform and contract issues. Rust with a small assembly boundary and stable C-compatible interfaces is a candidate, not an approved implementation claim. Protocol and binary targets are pinned before interoperability or support is claimed.
