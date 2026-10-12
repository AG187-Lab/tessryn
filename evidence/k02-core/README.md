# K02 independent core evidence

This directory retains evidence for the original
[owned-memory policy](../../kernel-core/README.md). Host policy execution and
freestanding compilation do not establish native CPU isolation or complete
[K02](https://github.com/AG187-Lab/tessryn/issues/5).

The result receipt records the clean source revision, every relevant input hash,
both pinned setup receipts, compiler and library identities, all Rust test names,
and the repeated freestanding artifact hash. CI uploads the matching library
and receipt. Hardware faults, protected dispatch, actual mappings, TLB teardown,
SMP and device quiescence remain unavailable and are recorded explicitly.

Reproduce from the implementation revision identified in the result using the
commands in the core README. The evidence-only commit is subsequent to that
revision so adding this receipt does not dirty its measured source inputs.

The [macOS ARM64 result](result.json) measures clean implementation commit
`cd6ae218851f04b3eda033e2a1c3954686c190f7`: **30 Rust adversarial tests**, plus
[200 passing repository tests](python-tests.log) and
[design validation](design.log). The repeated `x86_64-unknown-none` library hash
is `2a52d4fdf307b580ec5cc6b991faa5f545cb3836f382dd7ac79ef8f58bb0513d`.
The local library is retained in the ignored build output; CI publishes its own
Linux host result and matching freestanding library. Host-specific library and
compiler identities are expected to differ between these pinned host profiles.
