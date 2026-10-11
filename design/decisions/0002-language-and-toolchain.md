# ADR 0002: Propose a Rust core, small assembly layer and C ABI

Status: Proposed. This is not a frozen language or toolchain decision.

## Proposal

Use Rust for the kernel and core native services, a small assembly layer for boot/exception/context-switch boundaries, and a versioned C ABI for source-compiled native components and the required CUDA Driver API surface.

Keep stable descriptors independent of language object layouts. Review unsafe memory, atomics, interrupt, DMA and foreign-function boundaries explicitly.

Device-only CUDA kernels may be compiled with nvcc on a development machine for exact targets. Deployment does not depend on a foreign host kernel or stock host driver library.

## Decision gate

G02 and G03 must validate target/toolchain availability, build reproducibility, debugging, binary layout and runtime requirements. Record the selected compiler versions and any accepted portable components with their provenance and license constraints.

Do not interpret C ABI as POSIX compatibility, arbitrary foreign binary execution or full CUDA ecosystem support.

## G03 validation profile

G03 selects upstream Rust 1.96.0 with bundled rust-lld and the
`x86_64-unknown-none` target for a freestanding ELF64 compiler/layout/debug probe.
QEMU 11.1.2 TCG executes a separate original reset-ROM fixture. Exact hashes,
commands, provenance and limits are recorded by the
[build and evaluation workflow](../build-and-evaluation.md). This validates the
development-tool availability and reproducible fixture binary inputs. The Rust
probe is not booted; kernel runtime/debugger behavior, native-service C ABI and
exact GPU device compilation remain unvalidated. The whole-kernel language and
interface proposal remains Proposed pending G02 and implementation evidence.

## K01 implementation profile

K01 executes original Rust `no_std` kernel code with small x86 assembly boundaries
using the separately pinned `x86_64-unknown-uefi` library for the same compiler.
This demonstrates actual firmware handoff, owned CPU state, exception diagnostics,
Rust panic and reset under QEMU/OVMF. It strengthens the kernel language evidence;
the native-service C ABI and GPU compiler/interface contracts remain G02 work.
See [ADR 0010](0010-first-uefi-kernel.md) and [the kernel workflow](../first-kernel.md).

## References

[Native ABI](../native-abi.md) and [NVCC documentation](https://docs.nvidia.com/cuda/cuda-compiler-driver-nvcc/index.html).

