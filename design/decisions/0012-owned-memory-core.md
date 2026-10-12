# ADR 0012: Build the independent owned-memory core before native integration

- Date: 2026-10-11
- Status: Proposed; host policy implementation, native K02 acceptance pending
- Scope: bounded memory ownership and capability policy

## Context

[K02](https://github.com/AG187-Lab/tessryn/issues/5) depends on
[K01](https://github.com/AG187-Lab/tessryn/issues/4), whose boot and CPU work is
still in [PR 53](https://github.com/AG187-Lab/tessryn/pull/53). G02 supplies a
provisional portable capability reference but no privileged capability table.
Ownership policy can be implemented and tested independently while the kernel
chat continues its work. Native enforcement requires K01 and later integration.

## Decision

Implement the original `no_std` policy in a new [kernel-core](../../kernel-core/README.md)
directory, without modifying the active boot/kernel sources. Use fixed-capacity
private tables, exclusive mutation, overflow-checked extents, explicit exclusion
ranges, preflighted committed/reserved charges and a trusted scrub operation
before exposing authority. Reuse G02's canonical capability reference.

Attenuate delegated rights and bounds, revoke descendants, and retire exhausted
generations. Retain operation and mapping ownership in one absolute-interval
ledger. Completion and fencing retain memory until a trusted quiescence
acknowledgment; release the original charge only after the final capability.
Require whole authorized pages for mapping intents, with data-only permissions
and read authority for writable x86 mappings. Keep raw frame release internal
so callers cannot use a recycled physical range as a lifetime identity.

Execute adversarial host tests against this exact Rust implementation and compile
it freestanding with the existing pinned compiler. Supplement G03's target-only
libraries with separately checksum-pinned official host test libraries. Retain
source, compiler, library and artifact hashes, explicit failures and unavailable
native properties. Keep K02 open and preserve its K01 dependency.

## Alternatives and consequences

Waiting for K01 delays reviewable ownership policy that does not need a boot
entry point. Modifying K01's page tables now overlaps active work and lacks
authenticated domains. A separate policy core allows review and adversarial
testing while preserving that integration boundary.

Fixed capacity bounds memory use and avoids a bootstrap allocator dependency,
at the cost of explicit capacity rejection and conservative shared-region
release. Every rejection preserves policy state. The trusted scrub callback
and backend acknowledgments need real native implementations; their host mocks
cannot establish erasure, protection or hardware quiescence. Numerical caller
identities require protected dispatch and cannot authenticate untrusted callers.

Revisit this policy when K01 integrates it, a native fault test exposes a missing
invariant, reserved growth is implemented, domains need destruction, or device
and SMP execution require stronger lifetime/synchronization semantics.
