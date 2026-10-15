# ADR 0018: Bounded region service with resumable CPL3 tasks

Status: accepted and observed on the bounded single-CPU emulator profile on
October 15, 2026; see the [service report](../k02-region-service.md) and
[original execution packet](../../evidence/k02-region-service/README.md).

## Context

The ten-case memory matrix proves specific original-kernel caller, permission,
revocation and reuse behavior on one emulated CPU. Its request records are
kernel-selected recipes, and its probes return to the kernel rather than
continuing as persistent programs. The scheduler policy and raw-counter guest
benchmarks do not supply a general protected task/service boundary.

## Decision

Implement a bounded region dispatcher reused by two separately bound image
programs. Retain one boot CPU, masked interrupts, the pinned QEMU/OVMF profile,
fixed quotas and the existing owned-memory policy as the correctness reference.
Initial domain and capability admission remain privileged.

Accept a versioned 96-byte descriptor copied once from a validated single-page
user buffer. Derive caller identity from protected active task/root state, not
descriptor fields. Ordinary replies use declared registers and resume the
submitting program. Require nonzero, strictly increasing IDs per caller; copied
malformed requests consume fresh IDs, while pre-copy buffer errors can leave
gaps. Cooperative yield allows the peer to run; exit is terminal. Only the two
declared B protection faults allow this fixture to stop B and continue A; all
other exceptions fail the experiment. No request directly supplies an internal
lease or trusted quiescence acknowledgment.

Kernel bootstrap provisions A's owner capability and delivers A's delegated
capability in B's initial registers. This does not provide IPC. A retires its
writable lease before remapping read-only and sharing. The backend capability
journal excludes private baseline stack/request capabilities from user service
operations, even when the submitting domain owns them.

Retain a protected per-task general-register, privilege-frame and legacy FP
context. Capture FP in assembly before Rust uses it; sanitize first entry and
preserve each task's state on later resumes. End mutable Rust borrows before user
entry and keep trap-capture, kernel dispatch and resume ownership explicit.

Expose only the declared allocation, mapping, read-only delegation, revocation,
unmapping, release, accounting, yield and exit operations. Enforce exact bounds,
quotas, stale generations and failure atomicity. Revoke must retire affected
translations through fencing, PTE removal, actual CR3 invalidation and trusted
quiescence before backing release or reuse. A stopped domain's Busy capabilities
stay journaled and charged until a live peer releases its leases. The two
baseline pages per domain remain retained until global cleanup. A stopped task
cannot falsely release its mappings or resume after its declared terminal fault.

Admit only the saved CPU-state profile. Extended XSAVE state, TLS/FSGSBASE,
task debugging/tracing, protection keys, CET and SGX are unsupported. Alternate
privileged entry paths must not bypass the declared INT80 gate. No PCID, global
translations, LA57, timer-driven preemption, SMP or DMA quiescence is assumed.
The service report specifies the admission and evidence requirements in detail.

## Acceptance and consequences

Require actual multi-request/resume execution, successful delegated reads and
read-only write faults, owner revocation followed by stale-access faults,
malformed/forged request rejection without ownership mutation, private-capability
and stale/cross-domain mapping-token rejection, actual erased-page reuse, and
A-to-B-to-A general/FP state preservation. A terminated task stays stopped while
its peer completes.
Source-bound twin builds, raw frames, program results, backing/accounting checks
and the independent verifier must agree. Full verification requires the original
policy host receipt through `--host-result`, with its exact inputs, compiler and
retained logs; host tests do not replace guest execution. Retain K01 and both earlier K02 suites
as regressions. Clean implementation `bf9c82528f83e25814334c696a02aff86120fa21`
passed that bounded acceptance: three fresh guest captures cover 66 submitted
requests and 68 actual traps, with four context switches per case and final zero
ownership. Twin builds matched all ten artifacts and the independent verifier
bound 22 compiler dependencies, 27 runtime files and the 21-test host receipt.
All 658 Python tests and the same-source K01, earlier K02 and guest-benchmark
regressions passed. Original successful text records and notices are public;
complete artifact verification requires the retained binaries or fresh rebuilds,
the reviewed source checkout and matching current-host tools. Offline capture
authentication remains unverified.

This step advances [K02](https://github.com/AG187-Lab/tessryn/issues/5) and prepares
the execution adapter for [K03](https://github.com/AG187-Lab/tessryn/issues/6).
It does not close arbitrary-program isolation, a production native ABI, native
multicore scheduling, physical hardware, devices, GPU or inference qualification.
No new rental or cloud operation is required.

The conservative ownership/CR3/scrub implementation remains the performance
reference. A preregistered qualified native comparison under the
[inference performance contract](../inference-performance.md) is pending; no
latency, throughput or inference speedup is claimed.
