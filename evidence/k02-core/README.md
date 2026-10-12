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
