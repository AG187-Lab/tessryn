# K03 scheduler policy preparation evidence

## Successful Git diagnostics correction

The completed external CLI review reproduced a provenance defect: successful
Git stderr warnings could be appended to the recorded revision and make a clean
checkout appear dirty. The checker now parses only stdout for Git bindings,
requires a complete object identity and retains portable warnings on stderr.
Two regression tests cover successful warnings and invalid successful output.
No scheduler policy behavior changed.

The [corrected clean receipt](git-diagnostics-20261014/result.json) binds
`3f7274c57ab58c2d2f75a1303c69c237065a2353` and **11 source inputs**;
all **42 Rust host tests** pass and the repeated library digest remains
`3d0d3ce160c0a149da5eced6a3ebf7df6f1710dc3fd94d06afe1207920a03f3b`.
The [corrected repository log](git-diagnostics-20261014/python-tests.log) records
**526 tests: 525 passed, one skipped**, including **26 passing K03 tooling
tests**. The unrelated synthetic K01 paging skip still reflects the absent
separate UEFI compiler. The [design log](git-diagnostics-20261014/design.log)
records current documentation validation.

## October 14 main refresh

After merging current `main` (`d6bf5e82dad6e6347238e1d6c683f5a6cdb1a5f6`),
the [fresh clean receipt](main-refresh-20261014/result.json) binds merge revision
`15a2e1f55740c4e224d2876689f9368bfa28395a`. All **42 Rust host tests** pass;
its **11 input hashes** and repeated freestanding library digest match the
original preparation below. No scheduler policy or tooling source changed in
this refresh.

The [fresh repository log](main-refresh-20261014/python-tests.log) records
**524 tests: 523 passed, one skipped**. All **24 K03 tooling tests** ran and
passed. The skip is an unrelated synthetic K01 paging test whose separate
`build/uefi` development compiler is absent; no K03 check was skipped.
The [fresh design log](main-refresh-20261014/design.log) validates the refreshed
documentation. These results retain the same host-policy scope and remaining
native integration gates described below.

Fresh full-diff/tooling review and an independent scheduler-core review found
no new concrete defects. The independent pass checked shared reservations,
full interval charging/refunds, overdue peer retention, outcome precedence,
rejection atomicity and task/CPU generation retirement against the integration
contract and boundary tests. It did not claim native execution qualification.

## Original preparation

The [clean-source receipt](result.json) binds implementation revision
`c8b46a94ec8269c630b491e038d953cda7c66b87`, **11 source inputs**, pinned
compiler/library identities and **42 passing Rust host tests**. Repeated
freestanding builds of the same retained source bytes produce the same
`x86_64-unknown-none` library digest:
`3d0d3ce160c0a149da5eced6a3ebf7df6f1710dc3fd94d06afe1207920a03f3b`.
An evidence-only commit follows; CI retains a separate Linux receipt/library.

Tests cover overlapping CPU intervals, shared domain/task reservations and
refunds, task splitting and round-robin selection, block/wake/failure,
inclusive deadlines, exact budget completion/exhaustion, overdue-domain
admission halts, peer stop acknowledgment, identity replay, generation
retirement and complete rejection atomicity. These are numerical CPU
interleavings through the actual original Rust policy, rather than execution
of isolated tasks on native cores.

The [repository log](python-tests.log) records **255 passing Python tests**,
including **24 K03 tooling tests**. Checker regressions cover retained-source
bindings, cached/foreign Python dependencies and poisoned bytecode, source
replacement during compilation, bounded inputs, process failure/timeout,
changed compiler/setup identity, result/artifact aliases, initialization and
publication failure, stale artifact invalidation and portable public logs.

Pre-landing independent review found and fixed overdue-domain admission and
executed-source binding gaps. Fresh reviews confirmed the fixes. Two additional
CLI review attempts exceeded their five-minute limit and supplied no final
verdict; the completed independent reviews and executable regression tests
provide the review evidence. No native or performance verdict is inferred.

The [design log](design.log) validates the final document set. Reproduce using
[the core README](../../scheduler-core/README.md). The source and remaining
integration gate are documented in [ADR 0016](../../design/decisions/0016-scheduler-policy-core.md)
and [the preparation contract](../../design/k03-preparation.md).

[K03](https://github.com/AG187-Lab/tessryn/issues/6) remains open for actual
isolated SMP execution, qualified clocks/timer enforcement, native
synchronization and cross-core accounting/timing traces after
[K02](https://github.com/AG187-Lab/tessryn/issues/5). This evidence establishes
host policy behavior and freestanding compilation. It establishes no native
CPU isolation/preemption, GPU/bandwidth preemption or inference speedup.
