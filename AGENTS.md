# Contributor and agent instructions

- Read design/README.md and the issue's acceptance criteria before implementing.
- The product is an original kernel and OS. Deployment proofs execute through its kernel and native drivers.
- Use the installed authenticated gh CLI for GitHub research and operations.
- Delegate independent research/review when it improves quality; avoid overlapping file edits.
- Keep architecture, evidence, reported external results and measured project results distinct.
- Do not claim a supported platform, performance gain or compatibility level without its qualification evidence.
- Preserve memory ownership, cancellation, authentication, tenant isolation and placement epochs.
- Use capability-scoped device/DMA authority; ordinary storage and installation authority are separate from candidate experiment privileges.
- Public artifacts contain no credentials, private prompts, unrelated project content or local workspace paths.
- Keep changes focused. Update ADRs, affected docs and the issue when implementation changes the design.
- Run python3 tools/validate_design.py for documentation/planning changes and the relevant implementation checks once available.
