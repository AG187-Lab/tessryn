# Native K02 preparation

Status: independent implementation and protocol preparation, 2026-10-11. No new native execution or
isolation result is claimed. [K02](https://github.com/AG187-Lab/tessryn/issues/5)
remains open and depends on [K01](https://github.com/AG187-Lab/tessryn/issues/4).

This packet uses K01 [PR 53](https://github.com/AG187-Lab/tessryn/pull/53) at
`bf079253b0f39b6abf3a1ab764e48916e3f11399` and the merged K02 core at
`112936d5f3644de1dd63ed69c4284e24737a70a8`. Recheck the handoff and paging
assumptions against the eventual K01 merge before integrating.

## Independent work boundary

The independent implementation prepares boot-memory admission and an isolation
evidence protocol. Both stay in this checkout while the
kernel, AWS operator and infrastructure sessions finish their current work.

| Work | Files | Result and limit |
| --- | --- | --- |
| Admission planner | New `kernel-core/boot_inventory.rs` and dedicated tests; small integration into `kernel-core/lib.rs` and the K02 source manifest | Validated numeric inventory for the existing `MemoryPolicy`; no memory access or firmware calls |
| Qualification protocol | New case manifest, native trace verifier and malformed-fixture tests under K02-specific paths | Tests of the evidence protocol; synthetic input cannot qualify native isolation |
| Native adapter and execution | Later coordinated changes to the kernel after K01 lands | Actual user address spaces, protected dispatch, physical scrubbing and translation teardown |

The first two steps must avoid the K01-owned `kernel/main.rs`, `kernel/cpu.rs`,
`kernel/paging.rs`, `kernel/uefi.rs`, `kernel/entry.S`, K01 build/boot/capture
tools and workflows, and all AWS or infrastructure files. Recheck active
sessions and open PR paths before implementation. Reuse existing `FrameRange`,
`MemoryPolicy`, G02 `CapabilityRef` and `LeaseId`; introduce no new wire ABI.

## Boot-memory admission contract

The privileged adapter will copy bounded descriptor facts from the validated
[K01 handoff](https://github.com/AG187-Lab/tessryn/blob/bf079253b0f39b6abf3a1ab764e48916e3f11399/kernel/uefi.rs#L215).
The policy core receives integers and slices, never firmware pointers. K01 has
no typed marker proving firmware exit, so the adapter must enforce publication
only after successful `ExitBootServices` and CPU ownership. Build from the final
`Handoff` returned by `leave_firmware` after `cpu::take_ownership`. If planning
before exit is ever needed, rebuild against each refreshed map and discard the
plan on every failed exit attempt: K01 reuses and refreshes the retained map
buffer. A prepared plan before that point grants no authority. Firmware owns
resources during boot;
the transition is defined in [UEFI 2.11, boot services](https://uefi.org/specs/UEFI/2.11/07_Services_Boot_Services.html).

The planner must:

1. Validate physical width, nonzero page counts, page alignment, multiplication
   and endpoint overflow, and descriptor overlap across every memory class.
   Accept unsorted descriptors; malformed input rejects the whole plan.
2. Admit only kind `7` conventional RAM with the runtime attribute clear,
   following K01's conservative quarantine. Loader, boot-service, runtime,
   ACPI, MMIO, reserved and unrecognized types stay unavailable.
3. Intersect eligible RAM with K01's current low identity aperture below 4 GiB.
   Ordinary high RAM remains quarantined even when special high handoff ranges
   are mapped. Do not derive extents or authority from `Handoff.free_pages`.
4. Subtract image, stack, the complete retained-map allocation, optional
   framebuffer, optional high scratch, and the baseline scratch page. The
   baseline scratch is selected from conventional RAM and remains live during
   K01's probe; treating its descriptor as entirely free would double-own it.
5. Round byte-sized live exclusions outward to 4 KiB with checked arithmetic.
   Never widen usable extents. Normalize overlapping/adjacent exclusions so
   input ordering does not change admission or consume arbitrary capacity.
   Required image, stack, retained-map and scratch pages must be disjoint;
   optional high scratch may duplicate the scratch page in K01's high profile.
6. Preflight every bound, resulting extent and metadata capacity. Construct a
   complete new policy before publication; on rejection expose no partial
   allocator. Retain explicit exclusions and checked admitted-page totals.
   An empty eligible inventory is valid; it supplies no allocatable backing.

K01 checks its static page-table pool is inside the loaded image; the image
exclusion also protects its descriptor tables and exception stack. Future
allocator metadata, user page-table pages and probe code/stack allocations need
their own protected ownership before execution begins.

Planner tests must cover unsorted and adjacent ranges; overlaps across eligible
and quarantined classes; zero, unaligned and overflowing descriptors; runtime
conventional RAM; every excluded memory class; nested and byte-sized exclusions;
exclusions spanning multiple extents; baseline and high scratch; clipping across
4 GiB; physical-width endpoints; deterministic coalescing; and capacity failures
that leave no published policy. The future native adapter test must change the
map between firmware-exit attempts and prove the earlier inventory cannot be
published. Passing proves inventory policy only.

## Native backend obligations

The frozen K01 mapper installs
[writable supervisor 2 MiB leaves](https://github.com/AG187-Lab/tessryn/blob/bf079253b0f39b6abf3a1ab764e48916e3f11399/kernel/paging.rs#L106).
Its GDT contains kernel segments and it has one active page-table root. Its
supervisor guard-page fault does not exercise an untrusted isolation domain.

Native K02 must supply protected caller identity, distinct user address spaces,
exact 4 KiB mapping permissions, protected policy/table storage and real scrub
operations. A descriptor's domain field cannot authenticate the caller. A
numeric `authorize` result cannot substitute for a retained mapping lease.
Writable x86 mappings require existing READ, WRITE and MAP authority; byte-only
delegation must not be rounded into page authority. Data mappings need an
explicit non-executable profile; executable test code needs separate trusted
ownership rather than a new data-capability execute right.

Serialize capability validation, lease acquisition, PTE publication and
revocation. Retain the lease and original charge through fencing, PTE removal,
the required address-space translation invalidation and trusted quiescence.
Reclaim backing only after final capability release. Partial install/teardown
failure must retain enough ownership to prevent reuse until cleanup succeeds.
Initially constrain the qualified profile to one boot CPU with declared paging,
PCID/global-translation and NX settings; choose invalidation from that profile.
SMP shootdowns and device/DMA isolation require separate implementation and
qualification. The [Intel system programming manuals](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html)
define paging, fault records and translation invalidation.

## Native negative-test contract

Each case uses an independent fresh original-kernel boot, with a distinct
context identifier and retained capture hash. Reusing numeric fixture identities
is valid across those independent boots; resetting policy generations inside a
continuing untrusted runtime is not a substitute for that boundary. Each run
binds the kernel/core/adapter source commits, image and evaluator
hashes, toolchain, execution environment, probe instruction addresses and CPU
profile. Record actual trap CS, RIP, CR2 and the complete page-fault error code;
check all bits expected by the declared profile and reject unrelated exceptions.
Recovery accepts only known test probe instructions and expected faults.

The initial offline contract fixes a single CPU, four-level x86 paging, 48-bit
physical addresses, NX enabled, and PCID/global translations disabled. Its
teardown protocol requires a CR3 reload under that profile. Other profiles need
a reviewed contract change and their corresponding invalidation evidence.

| Case | Required execution evidence |
| --- | --- |
| Caller forgery | Domain B submits A's handle and claimed identity; protected dispatch records B and rejects before publishing a mapping |
| Trusted-operation forgery | B attempts user-originated fencing, quiescence or allocator administration; dispatch rejects, and a submitted lease/completion ID cannot release live backing or activate reservations |
| Unauthorized read | B directly loads A's absent virtual page and receives a CPL3 non-present read fault at the exact probe instruction/address |
| Read-only sharing | B reads A's sentinel through a delegated full page; B's store receives a present user write fault and A's bytes remain unchanged |
| Exact bounds | Adjacent guard page faults; byte-slice mapping and WRITE+MAP without READ reject before PTE installation |
| Kernel isolation | B's read and write probes against selected supervisor aliases of kernel/policy/page-table memory fault without modifying bytes |
| Data NX | Instruction fetch from data faults when NX is verified supported and enabled; an unavailable NX profile cannot pass this case |
| Recursive revocation | Install separately primed mappings in B and D through A→B→D delegation; revoke A's descendants, deny fresh requests/completions, and prove teardown reaches every descendant root and alias before release |
| Writable reuse | Prime a writable mapping through real read/write access, revoke and retain ownership through teardown, then scrub/reassign the exact frame to C; resumed stale read and store probes both fault, and C's bytes remain unchanged after the attempted store |
| Stale identities | Prior capability and lease generations cannot mutate or release replacement ownership |

For page faults, present, write, user and instruction-fetch flags have the
meanings specified by the Intel manual. The expected instruction-fetch flag
depends on the verified NX configuration. A kernel-generated string alone is
insufficient: retain raw execution logs and artifact-bound trap evidence.

The later verifier must reject missing, duplicate or reordered cases, wrong
artifact/profile bindings, wrong fault registers, timeouts, unexpected traps,
premature charge release and changed victim bytes. Revocation records must show
fencing, PTE removal, translation invalidation and trusted quiescence before
release/reuse. Synthetic fixtures receive only a protocol-validation result.
Original-kernel CPU execution in an emulator and physical hardware execution
receive distinct evidence labels; neither implies DMA or SMP qualification.

The implemented offline checker is `tools/k02_native_protocol.py`, using
[the case contract](../planning/k02-native-cases.json). Run it with
`--input <transcript.json> --expectations <independent-expectations.json>`.
The transcript cannot supply its own expected hashes, probe addresses or fault
fields. Input files must be bounded regular files; the checker prints a result
to standard output and never publishes a native qualification. Its fixture
suite supplies synthetic expectations and adversarial record mutations.

## Integration gate

The inventory planner and offline evidence protocol are prepared independently
of K01's active files. Once K01 lands, confirm the adapter location with its owner
and revalidate this source pin. Integrate on a branch from current main, add the
user mapper/dispatch/teardown backend, and execute the full negative-test matrix
in the original kernel. Keep K02 open until its native acceptance evidence is
reviewed. The existing host core results remain useful regressions, while this
packet supplies the integration contract. Independent implementation results
must retain their exact source and toolchain bindings, while native execution
and qualification remain unavailable.
