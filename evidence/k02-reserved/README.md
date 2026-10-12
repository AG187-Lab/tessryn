# K02 reserved-memory activation evidence

This follows the merged independent core in
[PR 55](https://github.com/AG187-Lab/tessryn/pull/55) and tests the
[activation policy](../../design/decisions/0013-reserved-memory-activation.md).
The receipt records clean source inputs, pinned compiler/library identities,
every Rust test, and identical repeated freestanding artifact hashes. An
evidence-only commit follows the measured implementation revision.

The ten added activation traces check repeated growth, stale generations,
unchanged accounting/backing/rights, exact tail scrubbing, rejection of forged
callers and delegated/revoked authority, alias/lease blocking through quiescence,
generation exhaustion, and scrub-failure atomicity. They run against the same
Rust implementation compiled freestanding. Reproduce using the commands in the
[core README](../../kernel-core/README.md).

This is host policy execution and compilation. Protected dispatch, actual
native erasure, page-table/TLB enforcement, CPU fault traces, SMP and device
quiescence remain unavailable. K02 stays open and dependent on K01.
