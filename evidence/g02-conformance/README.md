# G02 portable native contract evidence

This is host conformance evidence for a provisional interface profile. It is
not native service, kernel isolation, DMA, Homa, CUDA or model-execution evidence.
Full [G02](https://github.com/AG187-Lab/tessryn/issues/3) remains open, including
its G01 physical qualification dependency and native runtime gates.

## Verified implementation

Source revision: `ae041f61a926571326f8f3415d5245db444c2a55`.
The checker observed a clean source tree. The later evidence-only commit adds
these receipts without changing their hashed implementation inputs.

- Full Python suite: **185 tests passed**, including **43 G02 tests**.
- Literal byte frames: **7 accepted and 35 rejected**.
- C11: host execution verified scalar byte roundtrips against literal vectors;
  generated checks compare field types, sizes, alignments, offsets and exported
  constants with the JSON contract.
- Rust 1.96.0: checksum-verified G03 installation; `no_std` compilation for
  `x86_64-unknown-none` verified matching layouts/types/constants and byte-vector
  assertions at compile time. No Rust service or executable was run.
- Design validation: **44 documents**, 10 milestones, 49 acyclic work items.

[result.json](result.json) retains source, evaluator, vector, probe and compiler
hashes, compiler/library identities, C probe output, rejection reasons and the
G02 test log. [tests.log](tests.log) contains the complete repository suite;
[design.log](design.log) contains documentation validation.

## Reproduce

From the repository root, using a C11 compiler on a supported G03 host:

```sh
python3 tools/setup_toolchain.py --rust-only
python3 -m unittest discover -s tests -v
python3 tools/validate_design.py
python3 tools/check_native_abi.py --output build/g02-result.json
```

An existing verified G03 installation can be selected with `--rustc`; the
checker still verifies its receipt, binary and runtime/target-library digests.
Missing or inconsistent tool profiles fail explicitly. A failed run replaces
an earlier passed receipt with a failed/incomplete result.

## Negative evidence and remaining limits

Tests reject malformed widths/frames, stale and cross-domain authority,
replayed requests/completions, unsafe overlapping writes, premature release,
cancellation skips, epoch reuse, overflow and inconsistent model/state
formats. Invalid actions preserve reference state. Compiler tests deliberately
corrupt native layouts, signedness and constants and require compilation to
fail against the independently generated JSON assertions.

The lifecycle model assumes a trusted single-threaded host, explicit caller
domains and externally reported quiescence. Authenticated task/budget lookup,
expiry/deadline enforcement, protected namespaces, native mapping/queue
ordering, device fences, actual operators, transport and recovery remain
unimplemented. Model hashes and memory totals validate declarations; they do
not verify artifact contents or measured capacity. See the
[contract](../../design/native-contract-v1.md) and
[proposed ADR](../../design/decisions/0009-native-contract-profile.md).
