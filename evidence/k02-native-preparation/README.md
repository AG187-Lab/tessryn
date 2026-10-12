# K02 boot inventory and native protocol preparation evidence

The [clean-source receipt](result.json) binds implementation revision
`7a6899bf55648a4af6213d19f2e4515cae1ce1c3`, 19 source inputs, pinned compiler and
library identities, all **57 Rust tests**, and identical repeated freestanding
artifacts. The retained library digest is
`64860d27491e438296115291058c5ea66699702e609de0605574833b1cd7a72f`.
An evidence-only commit follows this implementation revision. CI retains its
own Linux receipt and library.

The 17 new inventory tests include 576 descriptor/exclusion permutations checked
against an independent per-page oracle, quarantine and physical-width checks,
live handoff reservations, normalization/capacity boundaries, and scrub/reuse
traces proving excluded mock bytes remain untouched. They exercise the same
allocation-free Rust implementation compiled for `x86_64-unknown-none`.

The [repository log](python-tests.log) records **224 passing Python tests**,
including 17 native-protocol fixture tests. The separate
[synthetic protocol result](protocol-fixture-result.json) validates all ten case
contexts and binds the offline checker and contract hashes. Its verdict is
always protocol validation, with native qualification not established and
hardware authentication unavailable. The fixture uses deliberately synthetic
source, artifact and capture bindings; no kernel executed those fixture records.

Protocol negatives cover ambiguous/malformed JSON, wrong probes/fault fields,
identity and privilege mismatches, missing descendant teardown, exact reused
frame binding, premature reclamation, changed victim bytes, source mutation,
and nonregular/oversized input files. Byte-only capabilities, writable mappings
without READ authority and forged quiescence of a retained fenced mapping each
have explicit rejection obligations.

The [design validation log](design.log) covers the final document set. Reproduce using the commands in the
[core README](../../kernel-core/README.md). The implementation and remaining
native gate are documented in
[ADR 0014](../../design/decisions/0014-boot-inventory-and-native-protocol.md) and
the [integration packet](../../design/k02-native-preparation.md).

These results prove numeric admission policy, host ownership rules and offline
protocol validation. Firmware exit, real RAM/scrubbing, protected dispatch,
user address spaces, PTE/TLB enforcement, CPU faults, SMP and DMA qualification
remain unavailable. [K02](https://github.com/AG187-Lab/tessryn/issues/5) stays open
and dependent on [K01](https://github.com/AG187-Lab/tessryn/issues/4).
