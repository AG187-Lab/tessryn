# K03 scheduler policy preparation evidence

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
