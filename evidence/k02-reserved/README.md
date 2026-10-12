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

The [clean-source result](result.json) measures `dd89ed6a4b8c9091b93229caeda513c5e37c291a`: **40 Rust
tests** (30 existing plus ten activation traces), [207 repository tests](python-tests.log),
and [design validation](design.log). The repeated freestanding library hash is
`794a79540ee7c104c0cec7dbae27d8def7c495ecad9aa7ef058d53e28f7f2918`. CI retains its own Linux result and matching library.
