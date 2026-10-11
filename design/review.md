# Adversarial review findings

Two design-review passes ran through Grok Build using the verified `grok-4.7-build` model at xhigh effort on October 11, 2026. Independent reviews checked networking arithmetic, native CUDA, numerical quality and milestone fidelity. These were design reviews, not source-code audits or hardware experiments. This document records the conclusions rather than private prompts, execution traces or account metadata.

| Finding | Severity | Resolution |
| --- | --- | --- |
| Memory pooling was conflated with token speed and concurrent throughput | Critical | Report capacity, first-token/token latency and goodput separately |
| One transport profile assumed cloud NAT and controlled-fabric priorities | Critical | Qualify native, routed/cloud and accelerator paths independently |
| Laptop-only helper role failed the intended sharded-model demonstration | High | Require a qualified laptop to execute a resident shard on the live path |
| A four-rank ring example became a universal tensor admission rule | High | Use measured compute and actual collective algorithms; compare feasible alternatives |
| Full KV handoff was treated as mandatory in every schedule | High | Account actual missing state, reuse, ownership, compression and overlap |
| CUDA execution and full stock ecosystem compatibility were conflated | High | Separate cubins, Driver API subset, Runtime, PTX/JIT and library compatibility |
| CUDA was mistaken for proof of direct NIC-to-VRAM DMA | High | Keep measured pinned-host staging and independently qualify peer DMA |
| Temperature-zero token equality was treated as a universal quality gate | Medium | Use operator/logit tolerances and task quality; exact replay has its own deterministic contract |
| A prefill chunk was claimed to bound complete p99 interference | Medium | Register end-to-end targets under declared queues, workload and thermal conditions |
| Candidate evaluation required separate physical machines in all cases | Medium | Require independent authority; VM isolation can suffice, bare-metal DMA needs recoverable lab hardware |
| Control quorum survival was conflated with model state survival | High | Restore missing state only when a replica or qualified capacity exists; otherwise fail explicitly |

## Retained conclusions

Homa is a credible native transport candidate, with version and fabric qualification. It does not implement GPU collectives or universal remote memory. Native NVIDIA execution has positive engineering precedents in device-only cubins, non-Linux CUDA and independent command-submission implementations. None supplies a complete driver for this OS.

Laptops qualify by measured behavior. Wired, thermally stable devices may be synchronous shards; intermittent devices have independent-work roles. Thunderbolt RDMA is a useful hardware opportunity, with native driver and reliability work remaining.

The corrected positive milestone uses four original-OS workers, including the laptop, serving a model larger than any worker alone. Prefill/decode groups need complete independent memory reservations. Failure drills distinguish safe fencing, control availability and inference recovery.

## Decisions and unresolved questions

See [decision records](decisions/) for the chosen architecture and reconsideration conditions, [research](research.md) for primary evidence, and [roadmap](roadmap.md) for experiments. Exact hardware, primary language/toolchain, protocol pin, model/precision and numeric performance targets remain initial engineering deliverables.
