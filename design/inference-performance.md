# Inference-oriented kernel performance

Status: accepted engineering direction; mechanisms and performance qualification remain staged. Primary sources reviewed on 2026-10-12. No Tessryn inference, GPU or native kernel performance result is available. The K01 boot proof and K02 protection probes establish correctness within their recorded scopes, not speed.

## Objective and boundary

Optimize completed inference requests that meet registered time-to-first-token and inter-token SLOs under realistic contention. Report latency, goodput, memory, CPU consumption and energy together. A faster context switch or isolated GPU kernel is useful only when it improves the admitted inference path without breaking isolation, cancellation or numerical quality.

The kernel supplies bounded scheduling, memory ownership, clocks, interrupts and device authority. Native services choose batches, model partitions, KV placement and prepared graphs. Keep model parsing, learned scheduling policies and control quorum outside privileged code and ordinary token execution. This follows the existing [architecture](architecture.md) and [native interface](native-abi.md); it adds no Linux ABI, scheduler extension or new device authority.

## Research translated into experiments

The source column records published mechanisms. Each Tessryn choice is an engineering inference to test, not a reproduced paper result or imported implementation.

| Primary source | Published mechanism | Tessryn experiment and limitation |
| --- | --- | --- |
| [Shenango, NSDI 2019](https://www.usenix.org/conference/nsdi19/presentation/ousterhout) and [Caladan, OSDI 2020](https://www.usenix.org/conference/osdi20/presentation/fried) | Rapid core allocation and contention feedback for bursty latency-sensitive work. | Compare fixed CPU reservations with bounded elastic allocation. Measure idle polling cost, wakeup tails and cache/memory interference; dedicate a coordinator core only if its benefit exceeds its cost. |
| [Shinjuku, NSDI 2019](https://www.usenix.org/conference/nsdi19/presentation/kaffes) | Fine-grained preemption addresses long-request blocking on CPUs. | Sweep CPU quantum under mixed short/long tasks. Measure preemption cost and starvation; CPU preemption does not establish interruption of an in-flight GPU kernel. |
| [SBB, OSDI 2026](https://www.usenix.org/conference/osdi26/presentation/hu-kang) | Decentralized runtime scheduling combines flow migration and task stealing; user interrupts support its mechanism. | Compare a simple scheduler with per-CPU queues, bounded stealing and topology-aware migration after SMP is correct. Treat user interrupts as an optional exact-CPU feature; retain ordinary interrupt support. |
| [Linux EEVDF](https://docs.kernel.org/scheduler/sched-eevdf.html) and [sched_ext](https://docs.kernel.org/scheduler/sched-ext.html), documentation reviewed 2026-10-12 | Eligibility/virtual deadlines and replaceable scheduling policy with fallback. | Compare fair-service and deadline-aware policies behind a fixed budget-enforcement boundary. Preserve accounting across sleep, cancellation and migration; a failed policy must not strand runnable work. These are inspirations, not a Linux dependency. |
| [Asterinas, USENIX ATC 2025](https://www.usenix.org/conference/atc25/presentation/peng-yuke) | A Rust framekernel concentrates the unsafe memory-safety boundary. | Keep unsafe CPU/MMU/DMA operations small and auditable. Benchmark authority checks without removing them; Rust types do not replace hardware isolation or concurrency validation. |

Recent serving, memory and transport sources are maintained in [research](research.md). Apply their request-level policies in native services; expose their needs through bounded kernel mechanisms.

## Implementation priorities

1. **Finish correctness and observability.** K02 protection, revocation and safe reuse precede memory fast paths. K03 needs a qualified monotonic clock, task accounting, timer/preemption and SMP evidence before native scheduling claims. Simulated clocks and host policy tests remain correctness evidence.
2. **Separate latency classes with bounded fairness.** Reserve cancellation/control progress; distinguish decode/collective work from bulk prefill and loading. Enforce one aggregate domain budget across cores: reserve grants before dispatch, charge full observed CPU time and retain context ownership until trusted stop. Preserve tenant/request accounting across task splitting, wakeups and migrations; fail closed on late enforcement. Charge enforcement and attributable interrupt/completion work. Bound priority inversion and best-effort starvation. A service cannot obtain unlimited priority by declaring every task urgent.
3. **Make the steady token path reuse resources.** Prepare graphs, registration and buffer pools before admission; reuse mappings and bounded submission/completion descriptors. Account pool reservations, metadata, copy-on-write growth and retained canceled work. Cache authority only with validated generation/lifetime rules; stale or revoked handles remain rejected. No unbounded allocation, page faults, global lock or control-plane round trip is an intended per-token dependency.
4. **Preserve CPU/device locality.** Record CPU topology, NUMA memory and qualified PCI/device proximity. Prefer local ownership of queues and registered buffers; measure cross-core migrations, remote memory and cache-line contention before choosing topology policies. Huge pages, PCID and selective TLB invalidation are optional experiments after exact mapping/revocation qualification. The current one-CPU CR3 fence and page scrubbing remain the correctness reference.
5. **Tune batching and completion delivery together.** Sweep descriptor batch size, polling budget, interrupt/coalescing policy and prefill chunks. Prefer bounded adaptive polling over assuming permanent busy polling is free. Include low load, bursts, saturation, thermal steady state and notebook power limits. Reserve headroom so bulk work cannot prevent cancellation or decode progress.
6. **Count actual data movement.** Attribute CPU copies, GPU copies, encryption, NIC bytes and KV migration to the parent request/tenant. Compare explicit pinned-host copies with optional direct DMA only after device/IOMMU lifetime and reset gates pass. GPU graph replay and asynchronous overlap are candidates, not compatibility promises or universal wins.

## Staged benchmark plan

| Stage and owner | Workload and comparison | Required observations |
| --- | --- | --- |
| K02 native isolation owner | Map/unmap, authenticated bounds checks, revoke/drain/reuse, scrub; compare optimization with the conservative native reference. | Exact authority/fault outcomes first; allocated/reserved bytes, TLB work, cycles and elapsed time only on a calibrated native measurement profile. |
| K03 scheduling owner | Bursty short work beside long CPU work, blocked/waking tasks, multiple tenants, contention and cancellation; simple FIFO/round-robin reference versus bounded fair/deadline policy. | Runnable-to-running p50/p95/p99, budget overshoot, CPU time by tenant, starvation, migration, interrupt and idle/polling cost. Host traces and QEMU timing cannot qualify production latency. |
| K04 queues and native device owners | Submission/completion round trips and descriptor batches; local/remote CPU placement and polling/interrupt variants. | Queue depth, backpressure, drops/overflow, wakeup delay, cycles per descriptor, cache contention and copied bytes with clock and instrumentation overhead recorded. |
| GPU/serving owners | Same model/precision on qualified hardware: mixed prefill/decode, cold/warm prefixes, variable output lengths and cancel storms; colocated versus split serving. | Full TTFT/inter-token/completion distributions, SLO goodput, GPU idle gaps, kernel/copy timeline, KV/workspace peaks, quality and power. |
| Transport/distributed owners | Decode-sized messages beside bulk activations/KV; equal topology, encryption and precision; pipeline/tensor/hybrid placements. | Parent-transfer fairness, loss/cancellation outcomes, complete bytes/copies, tail latency and memory reservations. Compare transport and placement independently. |

Use the authority and preregistration rules in [evaluation evidence](evaluation-evidence.md). Its v1 `measured_performance` record requires a real inference workload; it cannot represent a passing CPU-only, mapping or queue microbenchmark. Early stages need separately registered, explicitly scoped measurement reports with source/artifact bindings and retained observations. Define and review a stage-specific format before using those reports for native performance acceptance; do not relabel them as inference, fabricate model fields or relax the v1 fixture rules. End-to-end inference uses the existing v1 performance record.

Before collecting a candidate result, register named hardware/firmware, artifacts, workload hashes, offered load, absolute SLOs, resource limits, acceptable regression margins, run/sample counts and confidence methodology. Select numerical targets from a baseline and the intended service objective on that exact profile; the AWS boot sample supplies none. Register an accounting partition for task, kernel, interrupt and enforcement time: charge each interval once and report unassigned system overhead, rather than adding costs already included in elapsed CPU time.

Keep a minimal unchanged reference. Randomize or interleave baseline/candidate runs, preserve raw timestamps and all outcomes, and replay identical workloads across independent runs. Use scheduled arrivals under overload and include admission/queue delay; completion-triggered load alone can hide stalls. Report instrumentation overhead, clock source/calibration and synchronization error. Per-node monotonic durations do not imply synchronized clocks across a cluster.

Public traces use synthetic or permissioned anonymized metadata. Keep sensitive originals under protected access; no private prompts, KV payloads, plaintext tenant content or reversible/stable user identifiers belong in public benchmark artifacts. Record licenses, hashes and anonymization rules so a replay remains reproducible without exposing source content.

An optimization is accepted only after all applicable correctness, authority, cancellation, recovery and numerical gates pass, and the registered objective improves with the declared uncertainty while all resource/SLO and regression limits hold. Inference qualification always requires the full numerical and held-out quality gates. Retain losses and neutral results. Synthetic CPU/queue improvements remain microbenchmarks until model-shaped end-to-end tests confirm them; a Linux reference is comparison evidence, not native Tessryn qualification.

## Coordination and release gate

The native K02 session owns protection code and its evidence; the K03 session owns host scheduling/budget preparation. This document requests instrumentation and controlled experiments in their own lanes, not an overlapping implementation or a rewrite of their current PRs. K04, native devices and serving take their respective stages after prerequisites pass.

Before qualifying a performance-sensitive implementation, its PR must link a registered baseline/candidate comparison or explicitly remain preparation-only with the unfulfilled native gate recorded. Advertised inference speed requires the complete [benchmark and correctness contract](benchmarks.md), not boot success, fewer code lines or another system's reported speedup.
