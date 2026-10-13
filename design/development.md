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

The [K01 implementation and evidence](first-kernel.md), recorded in
[PR #53](https://github.com/AG187-Lab/tessryn/pull/53) under
[ADR 0010](decisions/0010-first-uefi-kernel.md), cover a bounded original UEFI CPU
bring-up profile with reproducible QEMU boot/exception/panic/reset and actual high
image/handoff evidence. The [AWS CPU profile](aws-boot-and-recovery.md#observed-cpu-qualification)
records two owner-accepted native `t3a.small` CPU boots separated by independent
Ubuntu recovery, with cleanup complete. K01 does not complete G02 or native-device
contracts. [K02 PR #58](https://github.com/AG187-Lab/tessryn/pull/58) builds on K01
and records four single-CPU CPL3 protection probes; the full native isolation
matrix remains open. As of October 12, 2026, K03 scheduling/budget host-policy
preparation is active under [issue #6](https://github.com/AG187-Lab/tessryn/issues/6),
with an [owner scope notice](https://github.com/AG187-Lab/tessryn/issues/6#issuecomment-6139885186)
but no public implementation PR or acceptance result; native SMP, clocks and
enforcement remain gated by K02.

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
