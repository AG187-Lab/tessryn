# Owned-memory policy core

This original, allocation-free Rust `no_std` library is an independent foundation
for [K02](https://github.com/AG187-Lab/tessryn/issues/5). The same implementation
runs in host adversarial tests and compiles for `x86_64-unknown-none`. Neither
result demonstrates native CPU isolation. K02 remains open and its native
integration remains dependent on [K01](https://github.com/AG187-Lab/tessryn/issues/4).
[ADR 0012](../design/decisions/0012-owned-memory-core.md) records this boundary.

## Policy and trusted boundary

`MemoryPolicy<D,R,C,O,F>` owns fixed-capacity tables for domains, physical backing
regions, capability slots per domain, outstanding owners, and physical extents.
Every mutation requires exclusive access. The future privileged dispatcher must
supply the authenticated caller identity; a descriptor's numeric domain is never
authentication. Domain creation, free-memory inventory, scrubbing, fencing and
quiescence acknowledgments are trusted kernel operations. The library does not
provide an untrusted syscall surface.

The physical inventory accepts complete, disjoint 4 KiB extents within the
declared physical address width and outside explicit exclusions. The caller must
derive eligible memory from a validated firmware handoff and quarantine kernel,
loader, firmware, ACPI, MMIO and reserved memory. This core cannot establish that
a supplied extent is real RAM. Extent metadata capacity is checked before
splitting; each live allocation retains capacity for eventual release. Adjacent
free extents coalesce.

`BootInventory<F>::plan` prepares this inventory from copied `BootDescriptor`
scalars and explicit `BootReservations`. It validates all descriptor classes,
admits only non-runtime conventional RAM below 4 GiB, and subtracts live kernel
and handoff allocations before coalescing complete 4 KiB extents. Required image,
stack, retained-map and scratch ranges are disjoint; optional and additional
exclusions normalize conservatively. Byte-sized exclusions round outward;
eligible memory never expands. Fixed-capacity rejection publishes no partial
policy. `into_policy` constructs a fresh `MemoryPolicy` only from a complete
plan. Empty eligible inventories are valid and cannot allocate backing.

The privileged adapter must supply the final successful firmware-exit map after
CPU ownership. Earlier retry maps cannot authorize an allocator. The numeric
planner performs no firmware access, establishes no successful exit, and cannot
authenticate a map. Its implementation and test boundaries are recorded in
[ADR 0014](../design/decisions/0014-boot-inventory-and-native-protocol.md).
[Preparation evidence](../evidence/k02-native-preparation/README.md) binds the
host policy and offline protocol results separately from native qualification.

Allocation charges committed plus reserved pages against the original owner's
budget before admission. Both occupy physical backing; only committed bytes are
accessible. A trusted scrub callback must erase the entire backing allocation,
including reservations, before authority is installed. A scrub failure leaves
all policy tables, charges and generations unchanged. The callback's success is
a trusted assertion, tested with mock backing bytes; actual native erasure is
still an integration obligation.

`activate_reserved` converts already charged reserved pages into committed pages
without changing the backing allocation, budget or total charge. Only the active
original root and its charge owner may request this trusted administrative
operation. Any retained alias or operation/mapping owner blocks activation,
including revoked aliases and completed/fenced owners awaiting quiescence.
Every bounds, generation and accounting check precedes scrubbing of the exact
newly exposed tail. A scrub failure leaves policy state unchanged.

Successful activation preserves rights and replaces the root in its existing
slot with the next generation; callers must use the returned handle. Old handles
cannot authorize, activate or release the replacement. Generation exhaustion
rejects activation without wrapping. Delegated views never widen automatically.
[ADR 0013](../design/decisions/0013-reserved-memory-activation.md) records this
conservative lifecycle, and [activation evidence](../evidence/k02-reserved/README.md)
separates its host policy checks from native enforcement.

Capabilities reuse the [G02 `CapabilityRef`](../interfaces/abi-v1/native.rs) type:
slot zero is valid, while generation and domain must be nonzero. Delegation may
reduce rights and bounds, and sharing retains the original owner's charge.
Revocation propagates through descendants and blocks further authorization,
delegation and completion publication. Capability and ownership generations are
separate; exhausted slots retire rather than wrap. Domains are not recycled.
Rights cover read, write, map, submit and delegate; there is no execute permission.

`authorize` returns only a checked numerical view. It creates no mapping or
ownership lease and must not be used by a backend as a substitute for `acquire`
or `map_intent`. Those methods retain absolute backing intervals in one owner
ledger, so aliases in different domains participate in the same conflict check.
Concurrent reads may overlap; an overlapping write is denied. Mapping intents
require complete authorized 4 KiB pages and never round a byte view outward.
Writable mapping intents also require read authority, since ordinary writable
x86 pages permit reads. Write-only service operations remain possible without
creating a CPU mapping. These rules are conservative ownership policy, without
PTE installation. Raw frame allocation/release stays internal to the policy;
the public allocator inspection cannot release a replacement using a stale range.

Execution completion, output fencing and quiescence are distinct transitions.
Completion or fencing retains the interval and charge. Only a trusted backend
acknowledgment of completed teardown/drain permits quiescence. A live owner
blocks capability release; descendants are released before parents. Physical
backing and its charge return only after the final reference is released.
Stale lease acknowledgments cannot affect replacement owners.

## Reproduction

Use Python 3.12 or newer on the pinned macOS ARM64 or Linux x86-64 host profile:

```sh
python3 tools/setup_k02_toolchain.py
python3 -m unittest discover -s tests -p 'test_k02*.py' -v
python3 tools/check_k02_core.py
python3 tools/validate_design.py
```

The separate [native test protocol](../design/k02-native-preparation.md) has a
[case contract](../planning/k02-native-cases.json) and offline checker at
`tools/k02_native_protocol.py`. It requires independently supplied expectations
and checks exact ordered evidence records. Its output is always protocol
validation; neither synthetic nor externally captured JSON proves authenticated
hardware execution. Native CPU fault and isolation qualification remain pending.

The supplementary profile pins official host test libraries for the existing
G03 compiler revision. It changes only this checkout's ignored installation and
adds a separate receipt; G03 source and lock files remain unchanged. Verification
rejects copied installer manifests that point into another checkout; create a
fresh local setup rather than moving an installed toolchain between checkouts.
Result paths cannot overwrite the retained library, and artifact/result
publication replaces aliases atomically. Verification
checks both receipts against compiler and library hashes, executes all Rust
tests without filters or ignored cases, and compiles the freestanding library
twice for identical output. The portable receipt and freestanding artifact are
under `build/k02/` and uploaded by the new K02 CI job.
[Retained evidence](../evidence/k02-core/README.md) binds clean source inputs.

## Native integration still required

K01 must supply the validated physical inventory and protect these tables. K02
must add authenticated domain dispatch, separate user address spaces, exact page
permissions, real scrub operations, revocation serialized with mapping install,
unmap/TLB teardown, concurrency control, and hardware access/fault traces. A
mapping lease must survive until translations can no longer access the backing.
Device ownership additionally requires qualified DMA authority and actual device
drain/reset evidence. This library has no CPU memory access, page tables, IRQs,
hardware fences, clocks/expiry, task scheduler, queue replay handling or distributed
placement-epoch enforcement. Those facts must be integrated and tested before
claiming the full K02 acceptance criteria.
