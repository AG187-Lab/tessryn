# Development coordination

The public [Tessryn development Project](https://github.com/orgs/AG187-Lab/projects/1) coordinates work across [GitHub Issues](https://github.com/AG187-Lab/tessryn/issues). The [milestones](https://github.com/AG187-Lab/tessryn/milestones) group work into evidence gates; the [roadmap](roadmap.md) explains their exit criteria. The machine-readable [backlog](../planning/backlog.json) records logical work IDs and the initial dependency graph; the [GitHub map](../planning/github-map.json) resolves them to live resource URLs.

## Current work and acceptance evidence

The initial backlog designated G01 and G03 as prerequisite-free P0 tasks with the `phase:Now` label. That planning graph does not establish their current execution state:

- [G01: Qualify the first stable-node and native notebook platforms](https://github.com/AG187-Lab/tessryn/issues/1) remains open. [PR #52](https://github.com/AG187-Lab/tessryn/pull/52) landed its inventory tooling and [qualification packet](platform-qualification.md); exact physical records, access/artifact constraints and the initial engineering-target decision remain qualification work. Fixtures and virtual reference inventory do not replace those gates.
- [G03: Establish reproducible builds and independent evaluation tooling](https://github.com/AG187-Lab/tessryn/issues/2) is complete through [PR #51](https://github.com/AG187-Lab/tessryn/pull/51). Its [tooling foundation](build-and-evaluation.md) provides pinned builds, provenance, bounded evaluation and evidence formats; numerical/model and performance observations remain unavailable.

Select an open task using its live state, prerequisites and acceptance evidence.
G01's independent physical inventory/access lane remains available; claim an
exact authorized target in the issue before collecting evidence. [G02's portable
host conformance foundation](https://github.com/AG187-Lab/tessryn/pull/54) is
merged; its wider interfaces, compatibility/runtime choices and target decisions
remain open with G01's platform dependency.

The [K01 implementation and evidence](first-kernel.md) landed through
[PR #53](https://github.com/AG187-Lab/tessryn/pull/53), and its three bounded emulator
bring-up criteria are complete in [issue #4](https://github.com/AG187-Lab/tessryn/issues/4).
The AWS CPU proof remains limited to its recorded boot/reprovisioning profile.
K01 does not complete G02's broader native-device contracts.

[K02 PR #58](https://github.com/AG187-Lab/tessryn/pull/58) merged the
[ten-case single-CPU matrix](k02-native-matrix.md), with
[clean execution evidence](../evidence/k02-native-matrix/README.md) and passing
historical slice/K01 regressions. The [resumable region service](k02-region-service.md)
now extends that baseline with reusable request dispatch and two CPL3 programs.
Its [clean evidence](../evidence/k02-region-service/README.md) records three accepted
boots, 68 actual traps, 21 service-policy host tests, 658 Python tests and passing
K01, four-probe, ten-case and guest-benchmark regressions. Arbitrary program
loading, production native services, SMP and device quiescence
remain open in [issue #5](https://github.com/AG187-Lab/tessryn/issues/5).

[K03 policy preparation](https://github.com/AG187-Lab/tessryn/pull/61) is merged.
The [single-CPU timer integration](k03-timer-preemption.md) now implements HPET
preemption and actual-time budget/deadline enforcement for the two image-bound
programs. Its [clean evidence](../evidence/k03-timer/README.md) records four accepted boots,
69 actual traps, matching 14-artifact twins, 90 focused host checks, 697 Python
tests and passing regressions. Physical clocks, native SMP, contention and general
idle/wakeup remain separate gates. [Issue #6](https://github.com/AG187-Lab/tessryn/issues/6)
remains open and dependent on K02. The [host benchmark harness](kernel-benchmarks.md)
is merged. The separate [in-kernel benchmark experiment](native-kernel-benchmarks.md)
executes 13 fixed cases and 208 raw-counter samples under single-CPU QEMU;
[PR #63](https://github.com/AG187-Lab/tessryn/pull/63) records its implementation
and source-bound review evidence. Hardware latency, native scheduling and
inference performance remain unqualified.

[Physical hardware requirements](hardware-intake.md) are ready through
[PR #64](https://github.com/AG187-Lab/tessryn/pull/64). No server has been rented or
qualified by that work; a machine, confirmed boot/console/recovery access and a
separate spending decision are still required before a physical trial.

Coordinate with the existing owner before overlapping kernel or evidence paths.
Independent preparation does not complete native implementation dependencies.
The [roadmap](roadmap.md) distinguishes landed foundations, observed execution and
remaining gates. The [inference performance plan](inference-performance.md)
records proposed downstream research and experiments; optimization claims require
the [benchmark contract](benchmarks.md).

Take ownership in the issue and agree on its acceptance evidence. G01's scope is
exact inventories, access/artifact constraints and engineering-target selection.
Native initialization, supported physical platforms and measured inference
require subsequent implementation evidence.

## Track execution

Every planned issue has a stable logical ID in its title and managed body, a milestone, workstream labels, priority, horizon, deliverable, acceptance checkboxes and required evidence. Native GitHub blocked-by relationships record prerequisites. Review both the relationships and the acceptance evidence before treating an issue as ready.

Use **Todo**, **In Progress** and **Done** for execution state; **P0**, **P1** and **P2** for priority; **Now**, **Next** and **Later** for planning horizon. Horizon is a planning choice and must be updated when work becomes ready. The [Project configuration](../planning/project.json) defines four views:

| View | Purpose |
| --- | --- |
| Development board | Track execution by status across all planned work |
| Ready to start | Open items labeled `phase:Now`; inspect live issue state and native dependencies, and maintain the label as work becomes ready |
| First product | Initial-product work, excluding `phase:Later` programs |
| Roadmap | Unscheduled planning view; dates follow credible qualification evidence |

Keep changes focused. Reference the issue from the pull request, attach its requested evidence and update affected design/decision records. A milestone closes when its exit gate is demonstrated, not when a calendar date arrives. No delivery dates are assigned before hardware and bring-up evidence support them.

## Reconcile planning safely

The authenticated `gh` CLI provisions and reconciles Issues, labels, milestones and native dependencies from the backlog:

```sh
python3 tools/validate_design.py
python3 tools/sync_github.py
```

The second command is a read-only dry-run. Review its planned changes before using `--apply`. The synchronizer preserves issue state, assignees, additional human labels and notes outside its managed boundaries. It does not close, reopen or delete resources. Keep human discussion outside the generated blocks and reconcile live scope/dependency changes into the backlog before merging.

See [Contributing](../CONTRIBUTING.md) for review expectations and [Governance](../GOVERNANCE.md) for decision authority.
