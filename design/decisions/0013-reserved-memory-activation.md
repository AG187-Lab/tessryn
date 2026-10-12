# ADR 0013: Activate reserved memory with a replacement root capability

- Date: 2026-10-11
- Status: Proposed; host policy implementation, native K02 acceptance pending
- Scope: activation of already charged physical reservations

## Context

[PR 55](https://github.com/AG187-Lab/tessryn/pull/55) implements the independent
[K02 ownership core](../../kernel-core/README.md). Allocation charges and scrubs
committed plus reserved physical backing, but initially exposes only committed
bytes. The core needs a bounded way to activate that reservation.
[K01](https://github.com/AG187-Lab/tessryn/issues/4) is still the prerequisite for
native isolation; K03 and K04 remain dependent on unfinished K02. This follow-up
stays within K02's existing policy files and avoids active boot/hardware work.

## Decision

Add `activate_reserved(caller, root, pages, scrub)` to the serialized policy.
Require the active original full-region root and authenticated charge owner.
Reject any other retained capability or outstanding owner on the region,
including revoked descendants and completed/fenced leases. Preflight positive
page count, reservation bounds, nonwrapping generation and all accounting and
tail arithmetic before invoking the trusted scrubber.

Scrub exactly the newly committed tail. On success, convert reserved counters
to committed counters while preserving physical backing, original charge,
budget, rights and frame-pool state. Replace the root in the same slot with its
next generation and return that handle. Prior handles become stale; no delegated
view or installed mapping is widened. A failed scrub changes no policy ledger.

## Alternatives and consequences

Reallocating a larger region would require additional backing and a copy, despite
already charged reservations. Widening live aliases or mappings would require
native synchronization and an explicit agreement among their owners. Updating a
root in place would leave old numeric references silently authorizing more bytes.
The replacement generation and exclusive-region requirement keep those changes
explicit, at the cost of waiting for aliases and owners to release.

Activation is a trusted allocator operation, scoped to original root ownership;
it introduces no new data-access right or cross-domain descriptor field. Native
dispatch must authenticate the caller, actual scrubbing must erase the tail,
and mapping publication must obey protected ownership and translation teardown.
Host mock bytes cannot prove native erasure, page protection or hardware faults.
Keep [K02](https://github.com/AG187-Lab/tessryn/issues/5) open with its K01 dependency.

Revisit when native mapping integration needs concurrent growth, domains need
destruction, reservations require additional backing, or device/SMP execution
exposes a missing synchronization or lifetime requirement.
