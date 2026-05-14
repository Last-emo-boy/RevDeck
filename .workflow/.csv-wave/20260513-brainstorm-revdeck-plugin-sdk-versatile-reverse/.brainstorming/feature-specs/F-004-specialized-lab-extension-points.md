# F-004 Specialized Lab Extension Points

## Purpose

Expose specialized reverse-engineering workflows as lenses over the shared graph without letting plugins fragment the TUI or bypass core navigation.

## User Value

Trace, Crash, Firmware, Graph, Diff, Protocol, and Memory workflows become discoverable inside the same cockpit, with shared selection, Inspector, notes, tags, findings, commands, and evidence links.

## Requirements

- Lens plugins SHOULD start as declarative registry entries using host-owned templates.
- Each lens MUST declare supported object kinds, required schemas, row model, commands, selection behavior, inspector cards, and navigation targets.
- Custom renderers SHOULD remain experimental until common templates are insufficient.
- Labs MUST connect back to stable objects and evidence chains.

## Lens Templates

- Trace Lab: timeline table, event detail card, argument search, first-seen, run diff.
- Crash Lab: cluster table, stack frames, input samples, fixed/new/regressed state.
- Firmware Lab: file tree, component inventory, embedded binary links, route/config/key candidates.
- Protocol Lab: message list, byte ranges, field annotations, opcode/length candidates.
- Diff Lab: change table, before/after links, behavior deltas.
- Graph Lab: local neighborhood/path queries, not whole-program global graph by default.
- Memory Lab: process/module/region/handle/socket tables and dumped binary links.

## TUI/CLI Affordances

- Workspace groups: Core, Labs, Plugin Lenses, Experimental.
- Lens badges show empty, blocked, degraded, new, or experimental state.
- Command Deck is the discovery surface for lab commands.
- Inspector cards show provider, confidence, evidence refs, and run ID.

## Test Strategy

- Declarative lens contract tests.
- Small and wide terminal rendering tests using `ratatui::TestBackend`.
- Navigation target and selection behavior tests.
- Empty/error/permission-denied state tests.

## Rollout Notes

Start with Trace Lab and Crash Lab because they prove cross-artifact evidence chains quickly.
