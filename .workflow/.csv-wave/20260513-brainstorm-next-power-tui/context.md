# Brainstorm Report -- RevDeck Next Powerful Features And TUI Optimization

## Summary

- Topic: RevDeck next powerful features and TUI optimization.
- Source context: current README, v0.1 Binary Triage execution, M1 Plugin SDK execution, current TUI/SDK code scan.
- Roles analyzed: product-manager, system-architect, ui-designer, ux-expert, test-strategist.
- Features decomposed: 8.
- Recommended next slice: M2A TUI Power Navigation, followed by M2B Adapter Commit Pipeline.

## Current Product Baseline

RevDeck already has a project database, ELF/PE import, stable objects and edges, Function Radar, findings, exports, a three-pane TUI, command parser/resolver/executor, and a plugin SDK preview with manifest validation plus ObjectBatch dry-run.

The code scan found a useful near-term opportunity: `NavigationLens::LocalGraph` and `render_local_graph` already exist, but Graph Lab is not exposed as a first-class workspace lens. This makes Graph Lab a strong first implementation candidate.

## Feature Index

| ID | Feature | Priority | Recommended Milestone |
| --- | --- | --- | --- |
| F-001 | Graph Lab And Evidence Paths | P0 | M2A |
| F-002 | Adapter Runner And ObjectBatch Commit | P0 | M2B |
| F-003 | Command Deck And Fuzzy Object Search | P0 | M2A |
| F-004 | Binary Map 2 Format Entropy Packer Diagnostics | P1 | M2A |
| F-005 | Triage Queue And Finding Promotion | P1 | M2A |
| F-006 | Rule Pack SDK And Scoring Controls | P1 | M3 |
| F-007 | First Party Adapter Proof Pack | P1 | M2B |
| F-008 | TUI Performance Layout And Visual Polish | P0 | M2A |

## Recommended Roadmap

### M2A TUI Power Navigation

Build visible product value without waiting for external adapters.

Exit criteria:

- Graph Lab is visible in the workspace and opens around the current object.
- Command Deck can search commands, objects, recent targets, and help.
- Binary Map explains file identity, parse health, and packed/unknown-file signals.
- Triage Queue can mark items reviewed and promote a lead into a finding draft.
- TUI has status chips, breadcrumbs, no-data panels, large-list guardrails, and stable small-terminal snapshots.

### M2B Adapter Commit Pipeline

Turn the plugin SDK preview into real extensibility.

Exit criteria:

- `revdeck plugin run` executes local adapters with audited process boundaries.
- Validated ObjectBatch output can commit transactionally through the host.
- Plugin contributions are recorded with provenance and source run IDs.
- At least one first-party adapter fixture imports external evidence into RevDeck.

### M3 Triage Intelligence

Only after provenance and commit are stable, add scoring extensibility.

Exit criteria:

- Rule packs emit structured score reasons.
- Users can suppress noisy providers or reason codes.
- Function Radar replay remains deterministic.

## Role Findings

### Product Manager

The strongest immediate value is Graph Lab plus Command Deck. SDK work remains important, but adapter execution and commit are what make the SDK useful.

### System Architect

The architecture should stay host-owned: no direct plugin SQLite writes, no arbitrary TUI renderers, and no opaque scoring. Add transactional ObjectBatch commit and contribution records.

### UI Designer

Keep the three-pane shell. Improve it with Graph Lab, Command Deck, status chips, breadcrumbs, compact score bars, and better empty/error states.

### UX Expert

Every screen should answer what is selected, why it matters, what can be done next, and how to promote evidence into a durable finding.

### Test Strategist

Use deterministic fixtures, reducer tests, render snapshots, ObjectBatch commit rollback tests, adapter permission matrix tests, and large-list performance guards.

## Artifacts

- Guidance: `.workflow/.csv-wave/20260513-brainstorm-next-power-tui/.brainstorming/guidance-specification.md`
- Feature index: `.workflow/.csv-wave/20260513-brainstorm-next-power-tui/.brainstorming/feature-index.json`
- Feature specs: `.workflow/.csv-wave/20260513-brainstorm-next-power-tui/.brainstorming/feature-specs/`
- Role analyses: `.workflow/.csv-wave/20260513-brainstorm-next-power-tui/.brainstorming/{role}/analysis.md`

## Next Step

Use `maestro-plan` for M2A TUI Power Navigation first.
