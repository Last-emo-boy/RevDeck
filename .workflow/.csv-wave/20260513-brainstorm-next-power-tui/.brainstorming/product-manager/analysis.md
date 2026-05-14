# Product Manager Analysis

## Product Thesis

RevDeck should become the fastest terminal cockpit for "what should I inspect next, why, and how do I preserve the conclusion." The next iteration should avoid broad RE-suite ambition and instead deepen three loops:

- Find suspicious evidence.
- Traverse why it matters.
- Promote analysis into durable findings.

## Priority

1. Graph Lab and Evidence Paths are the highest-value TUI feature because RevDeck already has object relations, xrefs, and inspector evidence. Making this visible as a workspace lens creates a clear power-user moment.
2. Command Deck is the second highest-value feature because current commands exist but are discoverability-heavy. A palette with preview would make the system feel more capable without adding much domain risk.
3. Adapter Runner and ObjectBatch Commit are the highest-value SDK feature because the manifest/dry-run preview is not yet useful against real external tool outputs.

## Milestone Recommendation

M2A: TUI Power Navigation.

- Add Graph Lab to the workspace.
- Add Command Deck with fuzzy object search and command preview.
- Add Binary Map 2.0 packer/format diagnostics.
- Add Triage Queue states and promote-to-finding workflow.

M2B: Adapter Commit Pipeline.

- Execute local adapters through the host.
- Commit validated ObjectBatch output.
- Ship one first-party adapter fixture path.

## Product Risks

- Too many Labs could make RevDeck look unfinished. Ship one excellent Graph Lab before adding Trace/Diff/Crash/Firmware tabs.
- Adapter execution without commit is demo-only; commit and provenance are required for real value.
- Scoring plugins should wait until suppression, provenance, and replay are ready.
