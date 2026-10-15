# In-kernel benchmark integration review

The [current validation record](main-refresh-result.json) binds clean committed
source `da2a4cf8364530e91ea6ce5f7a5b86aa149af625` after merging final main
`3e5a1254251038d26bd2a8c77c517607d842bdea`. Fresh twin builds retain the same
30 source input bindings and 15 compiler dependencies; all four artifacts are
byte-identical to each other and to the earlier reviewed kernel artifacts.
Both new original-kernel QEMU packets independently verify 13 cases, 208 raw
counter samples and exactly 55 files. Their registrations are recorded in the
summary. [All 622 Python tests pass](main-refresh-python-tests.log), with no
skips, including 42 focused benchmark tests and three design-validator tests.
[Two pinned clock tests](main-refresh-clock-tests.log) and
[76-document design validation](main-refresh-design.log) pass.

Final review reproduced an offline acceptance gap: a raw kernel exception
before the benchmark BEGIN could leave a successful summary unchanged. The
verifier now rejects exception-prefixed and mixed K02 markers anywhere in the
capture while retaining harmless startup output. Regressions cover all marker
positions and a self-consistently rebound packet with its former observed
result. Independent review reran the original four mutations and confirmed
rejection. The new twin captures bind this corrected verifier source.

The [earlier Linux artifact audit](linux-89413bb-audit.json) covers successful
CI [run 38686431509](https://github.com/AG187-Lab/tessryn/actions/runs/38686431509)
at `89413bb445ec63bb7dc6124dbda0646ad81415b4`, before that parser correction.
Its exact 55-file inventory, 30 source inputs, 15 compiler dependencies, all
four artifacts, 13 cases and 208 samples verified independently. Its artifact
ZIP hash matches GitHub's digest; its tested synthetic merge tree matches that
reviewed head. It remains pre-correction evidence, not the final source run.

The [earlier validation record](result.json) binds clean committed source
`94b23a12ef4bc5025e7fc5e8994baf1a7d472bfb` after integrating corrected K02
`f27b3e7fa6b76918cc6f5ac8ec88579dd69174f0`. It retains 30 source input bindings,
15 actual compiler dependencies, four byte-identical twin artifacts and hashes
for two fresh original-kernel QEMU packets. Each independently verified packet
contains 13 cases, 208 raw-counter samples and exactly 55 files. The external
scheduler policy pin matches the reviewed policy now on main.

The earlier K02 base refresh `709f67cd448fb8a088ac1ca5761c472656960709`
adds documentation and retained evidence only. After merging it, all 30 source
input hashes still match the verified twin builds, and both retained guest
packets pass independent verification again. The refreshed design log covers
76 Markdown documents, 10 milestones and 49 acyclic work items.

The [earlier repository test log](python-tests.log) records 617 passing Python tests,
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
