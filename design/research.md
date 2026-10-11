# Research and evidence

Status: design proposal; checked 2026-10-11. Tessryn has no implemented kernel, accelerator backend, or benchmark results. Published experiments and vendor reports motivate tests; they do not establish Tessryn's performance.

## Serving and distribution

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
