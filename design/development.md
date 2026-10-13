# Development coordination

The public [Tessryn development Project](https://github.com/orgs/AG187-Lab/projects/1) coordinates work across [GitHub Issues](https://github.com/AG187-Lab/tessryn/issues). The [milestones](https://github.com/AG187-Lab/tessryn/milestones) group work into evidence gates; the [roadmap](roadmap.md) explains their exit criteria. The machine-readable [backlog](../planning/backlog.json) records logical work IDs and the initial dependency graph; the [GitHub map](../planning/github-map.json) resolves them to live resource URLs.

## Current work and ready lanes

G01 is the remaining open P0 task with no prerequisites, labeled `phase:Now`:

- [G01: Qualify the first stable-node and native notebook platforms](https://github.com/AG187-Lab/tessryn/issues/1). Establish exact hardware, firmware, native-access constraints and the recoverable laboratory profile.

[PR #52](https://github.com/AG187-Lab/tessryn/pull/52) merged G01's inventory tooling and qualification packet. Its fixtures and virtual reference inventory do not replace the missing physical stable-node/notebook records or initial engineering-target decision. This independent physical inventory/access lane remains available; claim an exact authorized target in the issue before collecting evidence. G01 remains open.

[G03](https://github.com/AG187-Lab/tessryn/issues/2) is complete through [PR #51](https://github.com/AG187-Lab/tessryn/pull/51) for its fixture profile. [G02's portable host conformance foundation](https://github.com/AG187-Lab/tessryn/pull/54) is merged; the wider contract and target decisions remain open with G01's dependency.

As of October 12, 2026, [K01 PR #53](https://github.com/AG187-Lab/tessryn/pull/53) has reproducible original-kernel QEMU boot/exception/reset evidence and two owner-accepted native AWS `t3a.small` CPU boots separated by independent Ubuntu recovery, with cleanup complete. Its landing remains pending. [K02 draft PR #58](https://github.com/AG187-Lab/tessryn/pull/58) adds four single-CPU CPL3 protection probes and depends on K01 landing. The full native isolation matrix remains open. K03 scheduling/budget host-policy preparation is active under [issue #6](https://github.com/AG187-Lab/tessryn/issues/6), with an [owner scope notice](https://github.com/AG187-Lab/tessryn/issues/6#issuecomment-6139885186) but no public implementation PR or acceptance result yet; native SMP, clocks and enforcement remain gated by K02.

Coordinate with the existing owner before overlapping kernel or evidence paths. Independent preparation does not complete native implementation dependencies. The [roadmap](roadmap.md) distinguishes landed foundations, observed execution and remaining gates. The [inference performance plan](inference-performance.md) records proposed downstream research and experiments; optimization claims require the [benchmark contract](benchmarks.md).

Take ownership in the issue and agree on its acceptance evidence. G01's scope
is exact inventories, access/artifact constraints and engineering-target
selection. Native initialization and measured inference belong to subsequent
implementation issues; advertised support requires their execution evidence.

## Track execution

Every planned issue has a stable logical ID in its title and managed body, a milestone, workstream labels, priority, horizon, deliverable, acceptance checkboxes and required evidence. Native GitHub blocked-by relationships record prerequisites. Review both the relationships and the acceptance evidence before treating an issue as ready.

Use **Todo**, **In Progress** and **Done** for execution state; **P0**, **P1** and **P2** for priority; **Now**, **Next** and **Later** for planning horizon. Horizon is a planning choice and must be updated when work becomes ready. The [Project configuration](../planning/project.json) defines four views:

| View | Purpose |
| --- | --- |
| Development board | Track execution by status across all planned work |
| Ready to start | Open `phase:Now` tasks; check native dependencies and maintain this label as work becomes ready |
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
