# Host policy and overhead benchmark executable

This original Rust executable measures host-executed ownership/scheduling policy and isolated queue/byte-buffer fixtures. It performs no native context switch, physical erasure, MMU protection, DMA or inference.

Run it through [the Python runner and reproduction guide](../design/kernel-benchmarks.md), which retains sources, compilation, registration, raw observations and bounded failure evidence. Direct Rust invocation alone does not produce a complete verified packet.

The executable uses no external crates. It links the existing `kernel-core` as a host library; an optional adapter links only the pinned reviewed K03 policy. Setup/reset is outside each timed sample. Warmups are excluded. Every sampled result carries explicit operation count, unit, bytes and deterministic workload checksum.

`ring.rs` is a sequential bounded reference fixture, not the K04 channel implementation. `tests.rs` checks wraparound/full/empty behavior, authority outcomes, work bounds, measurement metadata and the optional logical scheduling replay. Native implementation owners retain separate source and evidence paths.
