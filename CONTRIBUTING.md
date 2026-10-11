# Contributing

Tessryn welcomes original kernel, driver, inference, distributed-systems and measurement work. Begin with the [design](design/README.md), [roadmap](design/roadmap.md) and open issues.

## Work coordination

Use the public [development board](https://github.com/orgs/AG187-Lab/projects/1) and its Ready to start view to find work. The [development guide](design/development.md) explains the initial tasks and planning reconciliation.

1. Select an unblocked issue and discuss its deliverable and acceptance criteria before expanding scope.
2. Record dependencies using GitHub's native blocked-by relationships. A milestone is an exit gate, not a delivery-date promise.
3. Keep issue state and Project fields current: Todo, In Progress and Done; priority P0/P1/P2; horizon Now/Next/Later.
4. Open a focused branch and pull request. Reference the issue and attach the evidence its acceptance criteria require.
5. Update affected design documents and decision records with implementation changes. Reconcile planning/backlog.json with the live issue description and relationships.

Use the authenticated `gh` CLI for GitHub operations. Work is unassigned until a contributor takes ownership; no issue is automatically delegated to an external agent.

## Pull requests

Explain the problem, resulting behavior, validation and material limits. Tests should establish the interface or behavior, not mirror the implementation. Driver and performance work must identify exact hardware and report reproducible conditions. Do not claim support from emulation, another OS's driver or an unrelated vendor benchmark.

Architecture changes add or amend an ADR. All new interfaces state ownership, errors, cancellation and failure behavior. Imported artifacts need a provenance/license manifest before merging.

Run `python3 tools/validate_design.py` before submitting documentation or planning changes and `python3 -m unittest discover -s tests -v` for tooling changes. Follow the [build and emulator fixture workflow](design/build-and-evaluation.md) for clean reproductions and failure evidence. The [G01 qualification packet](design/platform-qualification.md) documents read-only Linux reference collection and rental prerequisites. Fixtures and reference inventories do not demonstrate Tessryn boot, GPU execution or inference. Kernel/device profiles remain unavailable until their implementation issues land.

Pull requests to `main` require the successful `design-integrity` check and resolved review conversations. Squash merging preserves linear history. Branch protection disables force pushes and branch deletion; administrators retain recovery authority.

## Licensing and conduct

Submit contributions you have the right to contribute under Apache-2.0 and preserve all third-party notices. Follow the [code of conduct](CODE_OF_CONDUCT.md). Report vulnerabilities using the [security process](SECURITY.md), not a public issue with private details.
