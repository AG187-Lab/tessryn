# ADR 0014: Prepare boot-memory inventory and native isolation evidence independently

- Date: 2026-10-11
- Status: Proposed; independent preparation, native K02 acceptance pending
- Scope: numeric inventory admission and offline evidence protocol

## Context

The merged [K02 core](../../kernel-core/README.md) implements ownership policy
but relies on a trusted source of physical free extents. The active
[K01 PR](https://github.com/AG187-Lab/tessryn/pull/53) validates a firmware memory
map and owns boot allocations. Its current supervisor page tables cannot enforce
user capability mappings. Independent preparation can reduce integration risk
without changing that session's boot, capture or AWS files.

## Decision

Add an allocation-free numeric `BootInventory` planner using the existing
`FrameRange` and `MemoryPolicy`. Receive copied descriptor scalars and typed
required live reservations; validate physical width, alignment, arithmetic,
overlap and bounded input before admission. Quarantine every class except
non-runtime conventional RAM and restrict admission to the existing low 4 GiB
identity aperture. Protect image, stack, retained-map allocation, scratch,
optional framebuffer/high scratch and extra live exclusions. Normalize byte
exclusions to full pages and coalesce output without widening authority.
Construct a fresh policy only from a complete capacity-checked plan.

The adapter must use the final map associated with successful firmware exit and
CPU ownership. A pre-exit plan must be discarded on every failed exit and rebuilt
after every refresh. The planner does not parse firmware pointers, establish
exit success, scrub bytes or install page tables. Numeric inventories are
trusted input facts rather than proof of physical RAM.

Prepare an offline native test protocol with independent expected artifact and
probe bindings, exact ordered cases, bounded strict parsing and adversarial
fixture tests. Require protected caller identity, actual CPL3 fault fields,
unchanged victim data, recursive descendant teardown, stale writable translation
denials and ownership held through translation invalidation and quiescence.
The checker always reports protocol validation, with native qualification
unavailable. An internally consistent transcript cannot authenticate hardware.
Reuse the existing capability and lease identities; this evidence schema is
not a new native service ABI.

The pre-landing adversarial review tightened this protocol on 2026-10-12.
Anchor the loaded checker identity before validation and hash/parse the same
retained contract bytes. Bind observed generation/rights errors and valid
owner/current-generation controls; unrelated denial guards cannot establish
the intended isolation property. These corrections change the offline evidence
contract and leave native enforcement pending.

## Alternatives and consequences

Seeding from K01's free-page count loses physical ranges and live exclusions.
Admitting loader and boot-service memory immediately would require additional
release proofs. Keeping the current quarantine and explicit scratch exclusion
avoids reclaiming live boot state. Fixed arrays and bounded input retain a
bootstrap-friendly core while requiring explicit capacity errors.

Implementing user page tables or syscall entry in parallel would overlap K01's
active code and assume unsettled runtime details. Synthetic fault records can
exercise a strict protocol today but cannot replace actual user execution.
After K01 lands, recheck its source pin and integrate the protected dispatch,
scrub, exact page mapper and teardown backend through the
[native preparation packet](../k02-native-preparation.md). Keep
[K02](https://github.com/AG187-Lab/tessryn/issues/5) open with its K01 dependency.

Revisit the low aperture, quarantine classes or evidence profile only when
native integration supplies the additional ownership, reachability and
execution evidence. SMP and DMA isolation need separate qualification.
