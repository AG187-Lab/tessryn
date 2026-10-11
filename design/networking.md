# Networking

The network contract separates transport, accelerator-buffer movement and collective algorithms. A fast message protocol does not by itself partition a model or perform an all-reduce.

## Transport profiles

**Controlled native fabric:** independently implement one pinned Homa version and verify wire interoperability, loss/reordering behavior, receiver grants and queue priorities. The [2018 paper](https://people.csail.mit.edu/alizadeh/papers/homa-sigcomm18.pdf) and the [October 2026 working draft](https://github.com/johnousterhout/homa-rfc/blob/df4bc0d7a1d5c30292e47f474a85c3669dce8612/draft-ousterhout-tsvwg-homa-00.md) describe different scheduling details. The current draft announces scheduled messages with `START_MSG`; do not mix this with an older initial unscheduled-data prefix.

**Cloud and routed paths:** qualify an explicit supported protocol/encapsulation, authentication, encryption, MTU and measured path behavior. The current Homa draft describes UDP encapsulation as unfinished and security as largely unaddressed. [AWS NAT](https://docs.aws.amazon.com/vpc/latest/userguide/nat-gateway-basics.html) supports TCP, UDP and ICMP; [ENA Express](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ena-express.html) documents TCP/UDP acceleration. Neither establishes raw Homa or switch-priority support. EFA/SRD is a distinct adapter and qualification effort, not a synonym for Homa.

**Accelerator and local interconnect paths:** use the same ownership/completion contract with explicitly qualified adapters. GPUDirect, NVLink and Thunderbolt each have separate hardware requirements. Their existence does not prove native support in Tessryn.

## Transfer scheduling

Use reusable registered buffers, persistent queues and bounded receiver credits. Overlap outstanding messages, grants, encryption, device copies and NIC transfer. Measure granted/in-flight bytes, window depth, bandwidth-delay product, stalls and full completion latency. A serialized `chunk_count × RTT` formula models stop-and-wait; it is not a general Homa transfer bound.

The [current reference cap](https://github.com/PlatformLab/HomaModule/blob/65cecd7831e8b24ba7bcd967288bb7ce26fe8eba/homa.h#L19) is **1,000,000 bytes per message**, smaller than 1 MiB. Logical object size, message size and packet MTU are distinct. A large-region interface can packetize compatibly; extensions require separate compatibility claims. Attribute every chunk to its parent request and tenant to prevent a bulk transfer from exploiting short-message priority.

Cancellation/control, critical decode/collective traffic and bulk state/model transfers have separate bounded budgets. Hardware priorities are claimed only on a verified fabric. Sender pacing cannot guarantee priority across an uncontrolled underlay.

The portable device path stages through pinned host buffers: GPU to host to NIC, and the reverse. Reuse and overlap these copies. Direct peer DMA is enabled only after validating the exact GPU/NIC/PCIe topology, lifetime, ordering and isolation. [NVIDIA documents DGX Spark as lacking GPUDirect RDMA](https://nvidia.custhelp.com/app/answers/detail/a_id/5780/), demonstrating that CUDA capability alone is insufficient.

## Partition-aware communication

Pipeline execution keeps contiguous stages and their per-layer state resident, sending activations between stages. Tensor execution splits work but introduces repeated collectives. Benchmark native ring, tree and star reduction plans at the actual shapes and topology. Hybrid placement can combine tensor groups and pipeline boundaries.

[TPI-LLM](https://arxiv.org/abs/2410.00531) reports tensor-parallel benefits on compute-limited CPU laptops with star all-reduce. It is a counterexample to rejecting tensor parallelism solely by chassis or nominal link speed, not proof of arbitrary GPU/Wi-Fi scalability. Admit a worker by sustained measured compute, memory, transfer, jitter and availability.

Apple's [TN3205](https://developer.apple.com/documentation/technotes/tn3205-low-latency-communication-with-rdma-over-thunderbolt) documents eligible Thunderbolt 5 hardware and macOS Verbs independent of MLX. Two-sided send/receive, controller-specific registrations, UC queue limits and physical topology constrain a future native adapter. UC send completion does not prove receiver delivery; the adapter needs acknowledgement, integrity and retry semantics. No Tessryn Thunderbolt driver exists yet.

## Analytical example

Assume batch one, 80 layers, hidden width 8192, eight KV heads of width 128, context 8192, and two-byte activations and KV. A decode boundary is `8192 × 2 = 16384` bytes. A complete prefill boundary is `8192 × 8192 × 2 = 134217728` bytes. Full KV is `2 × 80 × 8 × 128 × 2 × 8192 = 2684354560` bytes.

| Payload | Size | Ideal 1 Gb/s | Ideal 10 Gb/s | Ideal 100 Gb/s |
| --- | ---: | ---: | ---: | ---: |
| Decode activation, one boundary | 16 KiB | 0.131 ms | 0.0131 ms | 0.00131 ms |
| Whole prefill activation, one boundary | 128 MiB | 1.074 s | 107.4 ms | 10.74 ms |
| Full uncached KV, one bottleneck | 2.5 GiB | 21.475 s | 2.147 s | 214.7 ms |

These are bytes/rate floors, excluding startup, copies, encryption, loss, queues and compute. Streaming overlaps production and transfer. Prefix reuse, missing-state transfer, shard ownership and declared compression change bytes and critical-path timing. A cold full-state example is not a universal prefill/decode invoice.

A conventional four-rank ring with two all-reduces per layer has `80 × 2 × 2 × (4 − 1) = 960` algorithm steps per token. This is sensitivity analysis for one algorithm. Measure actual collective completion; Ethernet RTT is not per-step launch latency. Compare feasible placements when the model cannot fit on one worker.
