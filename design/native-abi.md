# Native OS interface and ABI proposal

Status: proposed interface specification. Tessryn has no implemented or frozen ABI yet. G02 and K01–K05 in [the backlog](../planning/backlog.json) turn this proposal into tested interfaces.

The native interfaces describe ownership, authority and completion explicitly. They are not a promise of a POSIX syscall ABI, an existing deployment kernel ABI or unrestricted CUDA binary compatibility.

## Kernel mechanisms

The privileged core owns address spaces, CPU scheduling, clocks, interrupts, physical memory and device/DMA authority. Parsing model files, selecting workers and deciding batch policy run in native services with bounded authority.

| Object | Contract |
| --- | --- |
| Isolation domain | Own address space and capability namespace; fault and resource accounting boundary |
| Capability | Unforgeable domain-local handle with rights, owner, generation and optional expiry; delegation cannot increase authority |
| Memory arena | Charged allocation with declared lifetime, bounds, placement and maximum growth |
| Registered region | Capability-scoped view of memory admitted for a particular service/device mapping |
| Submission queue | Bounded descriptors owned by an authorized producer; consumption does not imply completion |
| Completion queue | Bounded results carrying request ID, status, sequence and ownership generation |
| Execution reservation | CPU/memory/device budget and deadline parameters, with explicit enforcement limits |
| Device lease | Authority for an exact device/queue and registered mappings; teardown has declared ordering |
| Native task | Service-level task object owning child work, budgets, cancellation and event streams |
| Prepared graph | Service-level dependency graph of qualified operators and transfers; model semantics stay outside the kernel |

Device time reservations do not imply universal hardware preemption. Every backend declares the bounds it can enforce, including maximum outstanding kernels and memory limits.

## Capability and lifetime rules

1. A handle is meaningful only in its owning namespace and generation.
2. A service validates descriptor bounds and authority before acting.
3. Delegated child capabilities carry no broader rights or resource ceilings than their parent.
4. A buffer cannot be freed or reused while an authorized device or transfer still owns it.
5. Revocation prevents new work and follows a defined drain/reset path for outstanding work.
6. Kernel memory and signing/enrollment authority are never inferred from access to an inference queue.

Memory accounting includes committed and reserved growth. Transfer duplication, persistent command buffers and quantization/state metadata are charged before admission. Short-message segmentation retains parent request and tenant accounting.

## Queue descriptors

The wire/native layout must use explicit-width integers, version and size fields, documented alignment and validated offsets. Do not place language-specific object layouts, process pointers or mutable strings in cross-domain descriptors.

A submission identifies its operation, request, task, region capabilities, offsets/lengths, dependency events, placement epoch and bounded completion destination. A completion identifies the request and sequence, returns status and produced-region metadata, and records an ownership generation.

G02 chooses byte order and version negotiation. K04 specifies producer/consumer memory ordering, wraparound, backpressure and crash behavior. DMA mappings and device cache synchronization use backend-specific fences under the common ownership contract.

## Service interface shape

The following are interface families rather than finalized syscall names:

- Create an isolated native domain and derive bounded capabilities.
- Allocate, register, map, share and release owned regions.
- Submit bounded descriptors and wait/poll for completions.
- Reserve resources and submit/cancel native task graphs.
- Attach qualified devices and receive interrupts/fault notifications.
- Load a signed model artifact and request a qualified execution layout.
- Start a streamed inference request with explicit budgets and client sequence state.
- Reserve and commit a distributed placement/state handoff.

The kernel implements mechanisms. Native services expose higher-level operations through the same capability and queue framework.

## Proposed language boundary

The current proposal is a Rust core with a small assembly layer and a versioned C ABI for native services and source-compiled compatibility components. It is not yet an accepted toolchain decision; see [ADR 0002](decisions/0002-language-and-toolchain.md).

Language runtime details must not enter stable descriptors. Unsafe hardware access, atomics, DMA ownership and foreign-function boundaries need focused review. A C ABI does not establish an existing host OS ABI or provide dynamic linking of arbitrary foreign applications.

## Native CUDA scope

The first execution proof initializes an exact NVIDIA device/firmware and launches an exact-target device-only cubin compiled on a development machine. The native engine uses a documented CUDA Driver API subset for discovery, contexts, allocation/copies, modules/functions, launches, streams, events and synchronization.

Unsupported calls return explicit errors. PTX JIT, CUDA Runtime host registration, full CUDA Graph API compatibility, stock libraries and unmodified host application binaries are separate scopes. Native prepared graph replay does not require compatibility with the whole CUDA Graph API.

Each backend declares GPU ISA, artifact compiler version, firmware constraints, operator support, precision/quantization formats, resource metadata and recovery behavior. CUDA device binaries do not establish an Apple or AMD execution backend.

## Error and cancellation semantics

Errors distinguish invalid authority, stale handle/epoch, incompatible format, insufficient capacity, admission rejection, deadline expiry, device fault and partial-stream termination.

A cancellation acknowledgment has a defined meaning. Receiving the request, stopping new launches, fencing further output and reclaiming device memory are different milestones and must not share an ambiguous completion status. Measure each required bound.

Fault handlers can isolate a domain or reset a device where supported. They must not report successful continuation after losing required model state. Clients receive resumable sequence metadata or an explicit partial-response outcome.

## Verification evidence

ABI changes require versioned examples, negative authority/bounds tests, lifetime and queue-ordering tests, and supported-backend conformance traces. Memory and DMA isolation are tested independently of inference correctness. Implementation evidence is pending.

