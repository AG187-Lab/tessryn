# In-kernel benchmark integration review

The [validation record](result.json) binds clean committed source
`94b23a12ef4bc5025e7fc5e8994baf1a7d472bfb` after integrating corrected K02
`f27b3e7fa6b76918cc6f5ac8ec88579dd69174f0`. It retains 30 source input bindings,
15 actual compiler dependencies, four byte-identical twin artifacts and hashes
for two fresh original-kernel QEMU packets. Each independently verified packet
contains 13 cases, 208 raw-counter samples and exactly 55 files. The external
scheduler policy pin matches the reviewed policy now on main.

The [repository test log](python-tests.log) records 617 passing Python tests,
with no skips. The [clock log](clock-tests.log) records two passing pinned host
tests; [design validation](design.log) records documentation/dependency checks.
An earlier concurrent full-suite attempt hit the pre-existing host benchmark
log-budget fixture failure: capture failed closed with `fail` rather than the
expected `log_limit`. Its unchanged 20-test suite, five direct reproductions and
the final complete suite passed. The failed original remains private locally;
this branch changes no shared process launcher code.

Review reproduced and corrected two host capture boundaries. A self-consistent
manifest could import modified retained Python helpers before QEMU; all such
helpers now require equality with the reviewed checkout before import, with a
regression covering each helper. Failed exact host logs could contain workspace
paths; CI now publishes only fixed failure metadata and hashes/sizes, retaining
raw failures privately. The full 55-file packet is published only after successful
independent verification. An independent review also found and verified the
failure-summary parser depth correction. One optional external CLI review timed
out without a final verdict; it is not counted as a completed review.

Raw packet media and observations remain in the ignored repository-relative
paths recorded by the summary; CI retains its own complete successful packet.
This summary alone does not authenticate execution. Reproduce with the commands
in [the experiment contract](../../design/native-kernel-benchmarks.md), using new
output directories and the matching reviewed source checkout. TSC ticks remain
unqualified for frequency, CPU cycles, physical latency, scheduler enforcement,
SMP, GPU or inference performance.
