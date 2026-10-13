# Research and evidence

Status: research and implementation guidance; refreshed 2026-10-12. Tessryn has original-kernel boot evidence and a first scoped memory-protection slice in the public implementation work. Accelerator execution and measured Tessryn inference/kernel performance remain unavailable. Published experiments and vendor reports motivate tests; they do not establish Tessryn's performance.

## Kernel research and inference priorities

[Inference-oriented kernel performance](inference-performance.md) converts the following sources into staged experiments and benchmark gates. The mechanisms below are reported source facts; their application to Tessryn is an engineering inference. Recent sources supplement established work rather than making old results applicable to new hardware by assumption.

| Primary source | Date | Mechanism and applicability |
| --- | --- | --- |
| [Shenango](https://www.usenix.org/conference/nsdi19/presentation/ousterhout), [Caladan](https://www.usenix.org/conference/osdi20/presentation/fried) | 2019–2020 | Rapid core allocation and contention feedback motivate burst/load and interference tests; dedicated scheduler/polling cores have an explicit cost. |
| [Shinjuku](https://www.usenix.org/conference/nsdi19/presentation/kaffes) | 2019 | CPU preemption addresses head-of-line blocking. Measure quantum/overhead; it provides no GPU preemption bound. |
| [SBB](https://www.usenix.org/conference/osdi26/presentation/hu-kang) | OSDI 2026 | Decentralized scheduling, flow migration and stealing address scaling; its user-interrupt mechanism needs separately qualified CPU support. |
| [Asterinas](https://www.usenix.org/conference/atc25/presentation/peng-yuke) | USENIX ATC 2025 | A small unsafe Rust substrate motivates auditable CPU/MMU/DMA boundaries. Types alone do not qualify protection or concurrency. |
| [EEVDF](https://docs.kernel.org/scheduler/sched-eevdf.html), [sched_ext](https://docs.kernel.org/scheduler/sched-ext.html) | Documentation checked 2026-10-12 | Fair eligibility and virtual deadlines, policy replacement and fallback inform comparisons; Tessryn's budget enforcement stays authoritative. No Linux ABI or BPF port is implied. |

## Serving and distribution

The 2025–2026 refresh below adds explicit experiment directions to the older serving foundations. Publication dates refer to the named venue or preprint; the ideas remain unimplemented Tessryn candidates.

| Primary source | Date | Tessryn experiment and boundary |
| --- | --- | --- |
| [ServeGen](https://www.usenix.org/conference/nsdi26/presentation/xiang-servegen) | NSDI 2026 | Replay per-client burst/length patterns and inaccurate estimates; naive workloads can choose the wrong serving configuration. It supplies no Tessryn timing or model evidence. |
| [JITServe](https://www.usenix.org/conference/nsdi26/presentation/zhang-wei) | NSDI 2026 | Compare streaming, full-response and dependent-request SLOs under uncertain work lengths. Estimates and batch policy belong in native services; kernel budgets remain enforced. |
| [vAttention](https://www.microsoft.com/en-us/research/publication/vattention-dynamic-memory-management-for-serving-llms-without-pagedattention/) | ASPLOS 2025 | Compare block layouts with contiguous virtual reservation and advance physical commitment. Its CUDA virtual-memory-management mechanism does not follow from CPU paging; required GPU backing must exist before dispatch. |
| [Mooncake](https://www.usenix.org/conference/fast25/presentation/qin) | FAST 2025 | Compare KV tiers, locality and asynchronous batched transfer against explicit-copy/colocated references. Charge memory, restore/copy time and in-flight ownership; offload is not free capacity. |
| [SIRD](https://www.usenix.org/conference/nsdi25/presentation/prasopoulos) | NSDI 2025 | Compare receiver scheduling with sender-pressure feedback under constrained uplinks and incast; this is downstream of native NIC/transport bring-up. |
| [TENT](https://arxiv.org/abs/2604.00368) | Author preprint, April 2026; revised July 2026 | Backend-neutral transfer intent and late path selection motivate future failure/duplicate-completion tests. The inspected record establishes no peer-reviewed venue or qualified Tessryn path. |

Start with public synthetic or permissioned anonymized traces: [ServeGen's artifact](https://github.com/alibaba/ServeGen) and [Mooncake's FAST 2025 trace release](https://github.com/kvcache-ai/Mooncake/tree/main/FAST25-release). Pin hashes, licenses and transformation rules before use; do not publish private prompts or tenant content. [Vidur](https://github.com/microsoft/vidur) can inform scheduling experiments, but its model predictions are simulation results until calibrated and validated against the exact native hardware.

| Primary source | Date | Evidence and design implication |
| --- | --- | --- |
| [PagedAttention](https://arxiv.org/abs/2309.06180) | 2023 | Block allocation and sharing reduce KV fragmentation. Account physical blocks and copy-on-write growth. |
| [SGLang](https://arxiv.org/abs/2312.07104) | 2023 | RadixAttention reuses shared prefixes across structured workloads. Cache identity must include actual execution semantics. |
| [DistServe](https://arxiv.org/abs/2401.09670), [Splitwise](https://arxiv.org/abs/2311.18677) | 2023–2024 | Prefill and decode separation can improve serving under particular compute, network, and latency constraints. Compare against colocated serving. |
| [Sarathi-Serve](https://arxiv.org/abs/2403.02310) | 2024 | Chunked prefill limits interference with decode. Tune chunks against observed deadlines. |
| [Mooncake](https://arxiv.org/abs/2407.00079), [LMCache](https://arxiv.org/abs/2510.09665) | 2024–2025 | KV placement, reuse, and offload are substantial serving decisions. Transport alone does not provide cache interoperability. |
| [TPI-LLM](https://arxiv.org/abs/2410.00531), [Kafila](https://arxiv.org/abs/2609.34045) | 2024, 2026 | Heterogeneous placement and collective topology deserve measurement. CPU edge results do not predict GPU cluster scaling. |
| [PrfaaS](https://arxiv.org/abs/2604.15039), [PDD](https://arxiv.org/abs/2609.13161) | 2026 | Geographic placement and staged handoffs explore WAN tradeoffs. Compare whole-request latency and transfer volume. |
| [Homa paper](https://people.csail.mit.edu/alizadeh/papers/homa-sigcomm18.pdf) | 2018 | Receiver scheduling and message priorities motivate native transport research. Pin a contemporary wire specification separately. |

## Current products and runtimes

[oMLX at e02ae514](https://github.com/jundot/omlx/blob/e02ae5147b03733214082273d7a247790a354dda/README.md) documents continuous batching, RAM/SSD KV tiers, and model memory limits. Its [distributed preview](https://github.com/jundot/omlx/blob/e02ae5147b03733214082273d7a247790a354dda/docs/experimental/distributed-cluster.md) describes unequal-memory pipeline ranks and explicitly requires physical Thunderbolt/JACCL validation. Treat these as project-documented capabilities, with that limitation retained.

[BaseRT at 24badc8d](https://github.com/basecompute/baseRT/blob/24badc8dd173e4111b64996a718d0e056405ea62/README.md) documents Metal and GB10 CUDA backends, continuous batching, paged KV, and prefix caching. Its public CLI, format, headers, and bindings are Apache-2.0; the [prebuilt engine is proprietary](https://github.com/basecompute/baseRT/blob/24badc8dd173e4111b64996a718d0e056405ea62/docs/reference/engine-releases.md). Its performance superlatives are project claims, not independent findings or an available native port.

The inspected [inco.ai homepage](https://inco.ai/) is a landing page. It does not substantiate engine internals, disaggregation, memory layout, or speed. [Positron's Atlas page](https://www.positron.ai/atlas) reports an HBM-based inference system and favorable selected GPU comparisons. Those vendor claims motivate memory-bandwidth and energy measurements; the page does not establish comparable Tessryn performance.

## Evidence policy

Every future result must identify hardware, firmware, software revision, model, numerical format, workload, and measurement method. Record contradicted hypotheses as well as improvements. [Platform constraints](platforms.md), [native CUDA](native-cuda.md), and [benchmark gates](benchmarks.md) distinguish supported APIs from proposed implementation work.

These original documents use the repository's [Apache-2.0 license](../LICENSE). External code, firmware, model weights, and documentation retain their own terms; this research imports none of them.
