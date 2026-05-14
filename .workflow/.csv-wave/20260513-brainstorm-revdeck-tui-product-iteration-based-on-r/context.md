# Brainstorm Report -- RevDeck TUI product iteration based on RevDeck.txt

## Summary
- Topic: RevDeck TUI product iteration based on RevDeck.txt
- Source: RevDeck.txt
- Mode: auto, `-y --count 5`
- Roles analyzed: product-manager, system-architect, ui-designer, ux-expert, test-strategist
- Features decomposed: 8
- Recommended product slice: v0.1 Binary Triage

## Guidance Summary
RevDeck is a terminal-native reverse engineering workspace. Its differentiator is project-level analysis memory and cross-object navigation across binaries, firmware, traces, crashes, protocol samples, notes, findings, and reports. It should not begin as a full decompiler replacement or a bundle of disconnected tools.

## Role Analysis Results

### Product Manager
The highest-value MVP is a complete Binary Triage loop: open/import a target, index core structures, rank functions, jump through strings/imports/xrefs, preserve notes/tags, create findings, and export a report.

Analysis file: `.workflow/.csv-wave/20260513-brainstorm-revdeck-tui-product-iteration-based-on-r/.brainstorming/product-manager/analysis.md`

### System Architect
Use SQLite as the project source of truth, stable object IDs, a normalized object graph, adapter boundaries for external tools, and deterministic job records for index/analyzer runs. Keep plugin ambitions behind clear importer/analyzer interfaces.

Analysis file: `.workflow/.csv-wave/20260513-brainstorm-revdeck-tui-product-iteration-based-on-r/.brainstorming/system-architect/analysis.md`

### UI Designer
The TUI should use a stable three-pane structure: workspace nav, dense main lens, contextual inspector, and command bar. Function Radar and object inspector are the main first-run product signals.

Analysis file: `.workflow/.csv-wave/20260513-brainstorm-revdeck-tui-product-iteration-based-on-r/.brainstorming/ui-designer/analysis.md`

### UX Expert
The user experience should reduce uncertainty by continually surfacing what to inspect next and preserving analyst intent. Notes, tags, statuses, renames, and evidence links must feel integrated into every object.

Analysis file: `.workflow/.csv-wave/20260513-brainstorm-revdeck-tui-product-iteration-based-on-r/.brainstorming/ux-expert/analysis.md`

### Test Strategist
Quality should rely on deterministic fixture imports, scoring-reason assertions, database migration tests, command parser tests, TUI state tests, and export round trips. External tools should be mocked through adapter fixtures.

Analysis file: `.workflow/.csv-wave/20260513-brainstorm-revdeck-tui-product-iteration-based-on-r/.brainstorming/test-strategist/analysis.md`

## Synthesis
Consensus: RevDeck should start as a focused project workspace for binary triage rather than an all-in-one reverse engineering suite. The product should prioritize object graph persistence, Function Radar, universal jumps, analysis memory, and findings export.

Resolved conflicts:
- [RESOLVED] Broad Labs vs MVP scope: keep Labs as roadmap lenses, but build only Binary Triage plus minimal graph/xref navigation first.
- [RESOLVED] Native analyzers vs external tools: define adapters early, but make core schema and SQLite persistence the owned product asset.
- [RESOLVED] Dense TUI vs discoverability: use a stable three-pane shell with command palette and visible inspector context.

Unresolved items:
- [UNRESOLVED] Exact Rust crate stack for binary parsing and TUI should be selected during implementation planning.
- [UNRESOLVED] Initial disassembly/function boundary accuracy needs feasibility validation against chosen fixture binaries.

## Feature Index
Feature index is available at `.workflow/.csv-wave/20260513-brainstorm-revdeck-tui-product-iteration-based-on-r/.brainstorming/feature-index.json`.

## Next Steps
- Use a planning step to convert F-001 through F-006 into implementation milestones.
- Treat F-007 and F-008 as architectural hooks unless the first milestone has spare capacity.
- Do not execute implementation or verification from this brainstorm job.
