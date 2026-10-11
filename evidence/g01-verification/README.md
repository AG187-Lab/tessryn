# G01 tooling verification, 2026-10-11

The evaluated collector and unit tests are from implementation commit
`8e8b2cfb3cd0da7da73b82ff01032478220f87ed`. The original fixture driver and
this evidence record were added afterward. [Verification metadata](verification.json)
binds the evaluated files and retained outputs by SHA-256.

The local run used Python 3.14.6 on Darwin/arm64. All 18 unit tests passed;
the [raw log](unit-tests.log) includes privacy, missing/malformed input,
symlink escape, FIFO rejection, file replacement, topology correlation and
output failure cases. The [design log](design-validation.log) records the
documentation/planning validator result. These are implementation results,
with zero performance samples or native capability claims.

The [fixture driver](reproduce_fixture.py) constructs an original synthetic
filesystem in a temporary directory and invokes the actual CLI with a
10-second deadline per invocation. Its CPU, firmware, NIC IDs, storage and
memory numbers are invented test inputs. The resulting
[full report](synthetic-full.json) and [numeric report](synthetic-public.json)
both exited 0. Repeating an output path exited 2, retained the original bytes
and produced an [explicit error](cli-failure.log). The [CLI log](fixture-cli.log)
records these results. These are not inventories of any actual machine.

Exact reproduction commands, from the repository root:

```sh
python3 --version
python3 -m unittest discover -s tests -v
python3 tools/validate_design.py
python3 evidence/g01-verification/reproduce_fixture.py build/g01-fixture-reproduction
```

The final command requires a new output directory; choose a fresh directory
for another run. Report timestamps change between runs, so their output hashes
also change. The implementation hash and semantics can be compared with the
retained metadata. The fixture driver uses only Python's standard library.

No server was rented, no physical inventory/recovery experiment ran, and no
vendor firmware/compiler artifact was acquired. Native Tessryn boot, GPU
execution and inference are unavailable; admitted memory and sustained
thermal/load performance are unknown. Unit-test duration is not a performance
measurement. Held-out model workloads and thermal/load conditions do not
apply to these collector tests; no inference samples were taken.

GitHub Actions separately exercises the collector on its hosted Linux runner
under a 30-second external deadline, using Python 3.12.13. Its numeric-only
`g01-ci-linux-reference` artifact expires after 14 days. Any such run is Linux
reference evidence, never bare-metal or native Tessryn qualification. The PR
links the actual run and reports its outcome after CI completes.
