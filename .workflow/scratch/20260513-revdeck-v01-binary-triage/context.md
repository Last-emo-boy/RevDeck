# RevDeck v0.1 Binary Triage MVP

## Source
- Primary product source: `RevDeck.txt`
- Brainstorm session: `.workflow/.csv-wave/20260513-brainstorm-revdeck-tui-product-iteration-based-on-r`
- Feature index: `.workflow/.csv-wave/20260513-brainstorm-revdeck-tui-product-iteration-based-on-r/.brainstorming/feature-index.json`

## Product Goal
Build the first executable RevDeck slice as a terminal-native reverse engineering workspace focused on Binary Triage.

The product should prove the loop:

1. Create or open a project.
2. Import a binary artifact.
3. Persist indexed object data.
4. Show a dense three-pane TUI workspace.
5. Rank high-value functions with explainable scoring reasons.
6. Navigate between strings, imports, functions, xrefs, notes, tags, and findings.
7. Preserve analyst notes/tags/renames/statuses.
8. Export initial Markdown and JSON findings reports.

## In Scope For v0.1
- F-001 Project Ingest And Index.
- F-002 Terminal Workspace Shell.
- F-003 Function Radar.
- F-004 Universal Object Navigation.
- F-005 Analysis Memory.
- F-006 Findings And Report Export.
- Minimal F-007 hooks only when needed for xrefs and local object navigation.
- F-008 adapter boundary as schema/API design, not a plugin marketplace.

## Out Of Scope For v0.1
- Full decompiler replacement.
- Dynamic instrumentation.
- Trace Lab, Diff Lab, Firmware Lab, Crash Lab, Protocol Lab, Memory Lab as complete features.
- Plugin marketplace.
- Global graph rendering as a primary view.
- Exploit automation.

## Planning Constraints
- Prefer Rust + Ratatui + SQLite unless exploration finds a strong blocker.
- Keep tasks feature-level, not per-file.
- Prioritize deterministic fixtures and CLI/TUI state tests.
- Treat `RevDeck.txt` and brainstorm feature specs as product authority.
