# ADR 0001: Build an original kernel and operating system

Status: Accepted design commitment. Initial CPU kernel boot/fault evidence exists
for [K01's emulator profile](../first-kernel.md); physical platforms, native
services and device drivers remain pending.

## Decision

Tessryn will boot its own kernel and ship native platform drivers, storage, networking, accelerator execution, cluster control and serving services. An existing deployment kernel or its device drivers do not satisfy the product gate.

Use research principles, standards and independently verified interfaces to design the system. Keep source and artifact provenance explicit. Development compilers, vendor device firmware and model artifacts are distinct from deployment-kernel dependencies and must have declared compatibility and distribution constraints.

## Consequences

CPU bring-up can establish interfaces, but the first product requires native accelerator inference. A companion process on an existing OS may help development and comparison; it does not count as a native Tessryn worker.

The initial support matrix is deliberately narrow. Advertised device support requires exact-profile boot and execution evidence. Installation, updates and recovery are part of the OS rather than external runtime assumptions.

## Acceptance link

[Roadmap](../roadmap.md), G01, K01–K05, IO01–IO05 and DEMO01 in [the backlog](../../planning/backlog.json).

