# G01 PR #52 review verification, 2026-10-11

The evaluated implementation is clean revision
`0dbd7e86b5017799f43e188fc5f945f6f7e90187`, including the review fixes and the
existing rental research. Collector SHA-256:
`4c4bf2a62d476c54c08061d8003885dc6b1d61611e8746643b6973b2a56c27ad`.
This evidence record was added afterward. [Verification metadata](verification.json)
binds source files, reports and logs by byte count and SHA-256; it excludes
the manifest itself. The [original evidence](../g01-verification/README.md)
retains its original revision and hashes and is not relabeled as this run.

## Fixes and actual results

The collector anchors traversal to directory descriptors, rejecting swapped
ancestors and escaped symlinks. It rejects unrelated driver targets and
non-device block entries, omits rejected partition facts, and emits only fixed
diagnostic labels. It freezes the source digest at startup and checks for
changes before and after collection and before publication. Source-read and
deferred stdout failures return explicit exit 2 without local paths or
tracebacks. These checks assume a trusted checkout and operator; they do not
attest physical custody or authenticate a running Python environment.

The numeric verifier checks the complete v1 publication contract, supplied
evidence kind, collector identity, strict bounded types, fixed labels and
retained PCI/IOMMU consistency. Full identity reports, unexpected fields,
malformed/duplicate/deep JSON, nonregular inputs and false native-support
claims fail explicitly. CI now runs this verifier before uploading a report.

All **142 combined tests passed** on Darwin/arm64 with Python **3.14.6** and
**3.12.7**: 32 collector tests, 10 numeric-verifier tests and 100 inherited
G03 tooling tests. Raw logs are [Python 3.14](unit-tests-python314.log) and
[Python 3.12](unit-tests-python312.log). Independent review also reproduced
the ancestor race, dangling partition and unavailable startup-source failures.
The [design log](design-validation.log) records documentation/planning validation.
Test durations are implementation results, not performance measurements.

The original fixture driver created **one invented filesystem dataset** and
ran the full and numeric collection CLIs with a **10-second deadline per
invocation**. Both exited **0**; repeating an output path exited **2** and
preserved its original bytes. [Full](synthetic-full.json) and
[numeric](synthetic-public.json) reports, the [CLI log](fixture-cli.log) and
[failure log](cli-failure.log) are retained. Numeric verification exited **0**;
passing the full identity report to the numeric verifier exited **1** with an
explicit fixed error. See [verification](numeric-verification.log) and
[expected rejection](identity-rejection.log).

## Exact reproduction

From the repository root, using Python 3.12 or later:

```sh
python3 --version
python3 -m unittest discover -s tests -v
python3.12 -m unittest discover -s tests -v
python3 tools/validate_design.py
python3 evidence/g01-verification/reproduce_fixture.py build/g01-review-reproduction
python3 tools/verify_platform_inventory.py build/g01-review-reproduction/synthetic-public.json --expected-kind synthetic_fixture
python3 tools/verify_platform_inventory.py build/g01-review-reproduction/synthetic-full.json --expected-kind synthetic_fixture
```

The second interpreter is optional when only one supported Python is installed.
The output directory must be new. The final command intentionally exits 1:
full identity reports require manual public-content review. Reproduction
timestamps and report hashes vary; compare semantics and source identity,
not fixture output hashes from a different run.

Verify the retained source and evidence hashes without recollecting:

```sh
python3 - <<'PY'
import hashlib, json, subprocess
from pathlib import Path
record = json.loads(Path('evidence/g01-review/verification.json').read_text())
for name, item in record['source_files'].items():
    data = subprocess.check_output(['git', 'show', record['evaluated_implementation_revision'] + ':' + name])
    assert len(data) == item['bytes']
    assert hashlib.sha256(data).hexdigest() == item['sha256']
for name, item in record['record_files'].items():
    data = Path(name).read_bytes()
    assert len(data) == item['bytes']
    assert hashlib.sha256(data).hexdigest() == item['sha256']
print('Retained source and evidence hashes match.')
PY
```

## Acceptance disposition and limits

| Issue #1 criterion | Current disposition | Remaining G01 evidence |
| --- | --- | --- |
| UEFI/CPU, PCIe, IOMMU, interrupts, storage/NIC/GPU and notebook prerequisites | Partial: sourced candidates and tested partial reference collector | Exact physical stable-node/lab and notebook inventories, firmware versions, topology/BAR/interrupt metadata, notebook ACPI/power/sensor prerequisites |
| Acquisition and redistribution constraints; facts versus assumptions | Partial: versioned source terms and explicit research/assumption boundaries | Target-specific artifact requirements, access/acquisition and rights feasibility; hashes/notices for artifacts actually acquired |
| Initial exact profiles and device/compiler targets after critical access evidence | Unmet: engineering targets remain unselected | Critical boot, console/recovery and device-access evidence, analytical memory estimates with reserves/unknowns, then a recorded initial target decision |
| Support status per profile; no family/nameplate execution proof | Unqualified status recorded for every candidate | Preserve explicit per-capability status in the engineering decision; G01 completion cannot imply execution support |

G01 remains open. Missing physical inventory, exact notebook access, critical
access/artifact answers and the initial engineering-target decision are its
blockers. Native kernel boot, native drivers/DMA/reset execution, GPU
initialization/compute, inference, measured admission and sustained
thermal/load performance are **later implementation and support gates**.
They must not become circular prerequisites for G01 completion.

This local record has **zero** physical inventories, rentals/recovery tests,
native boot, GPU, inference or performance samples. It contains no real
topology diagram or measured memory-admission result. Native capabilities
remain unavailable. Thermal and background-load conditions were not measured;
held-out model workloads and numerical inference references are inapplicable
because no inference experiment ran. Fixtures and virtual Linux reference
inventories establish tooling behavior, never Tessryn hardware support.

## Separate hosted Linux reference result

[Platform CI run 38170742906](https://github.com/AG187-Lab/tessryn/actions/runs/38170742906)
passed all **142 tests** on Python **3.12.13**, collected under a **30-second
external deadline**, verified the numeric report and uploaded its artifact.
It tested PR head `8380b6de55dc050b5c3c5af0ef85cd631655c3a8` through temporary
merge checkout `47875b49b2bce511e38b9e96acf5e56a3b7ec79f`; this does not merge
the PR. The collector bytes match the evaluated implementation above.

The unmodified [numeric Linux report](ci-linux-reference.json),
[test-result excerpt](ci-unit-tests.log), [verification log](ci-numeric-verification.log)
and [CI metadata](ci-verification.json) are retained permanently because the
uploaded artifact expires after 14 days. The excerpt preserves all test-result
lines and removes timestamps, CI prefixes and runner/access configuration.
Report SHA-256:
`6e287180353a9923b630ef07322e08a1c00369f103983f9f775d981c482aa49a`.

This separate record adds **one virtual Linux reference inventory**. It
reports hypervisor presence, 64-bit UEFI and two PCI endpoints whose IOMMU
groups are unavailable. It adds **zero** physical rental/notebook inventories,
recovery, native boot, GPU, inference or performance samples. Neither Linux
device exposure nor a successful virtual reference collection qualifies an
engineering target for the physical G01 profiles.

```sh
python3 tools/verify_platform_inventory.py evidence/g01-review/ci-linux-reference.json --expected-kind linux_reference_inventory
```
