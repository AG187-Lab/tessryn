# ADR 0002: Propose a Rust core, small assembly layer and C ABI

Status: Proposed. This is not a frozen language or toolchain decision.

## Proposal

Use Rust for the kernel and core native services, a small assembly layer for boot/exception/context-switch boundaries, and a versioned C ABI for source-compiled native components and the required CUDA Driver API surface.

Keep stable descriptors independent of language object layouts. Review unsafe memory, atomics, interrupt, DMA and foreign-function boundaries explicitly.

Device-only CUDA kernels may be compiled with nvcc on a development machine for exact targets. Deployment does not depend on a foreign host kernel or stock host driver library.

## Decision gate

G02 and G03 must validate target/toolchain availability, build reproducibility, debugging, binary layout and runtime requirements. Record the selected compiler versions and any accepted portable components with their provenance and license constraints.

Do not interpret C ABI as POSIX compatibility, arbitrary foreign binary execution or full CUDA ecosystem support.

## References

[Native ABI](../native-abi.md) and [NVCC documentation](https://docs.nvidia.com/cuda/cuda-compiler-driver-nvcc/index.html).

