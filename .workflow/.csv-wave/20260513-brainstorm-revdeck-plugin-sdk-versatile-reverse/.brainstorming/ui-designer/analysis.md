# UI Designer Analysis

Role: ui-designer  
Topic: RevDeck plugin SDK and specialized reverse-engineering extensions

## Summary

RevDeck already has a strong terminal information architecture: Cockpit, Workspace, Main View, Inspector, and Command / Status. The plugin UI should extend that structure instead of introducing free-form mini-apps. The core design decision is to make every plugin contribution visible through predictable slots: lens registry entries, command deck commands, inspector cards, cockpit status chips, triage rows, score reasons, draft findings, and help snippets.

Current implementation anchors reinforce this direction. `WORKSPACE_LENSES` is fixed in `crates/revdeck-tui/src/lib.rs:35`, focus is modeled as `Workspace -> Main -> Inspector`, the renderer switches between three-pane and stacked layout at narrow terminal sizes, and `Command Deck` already exists as the contextual help overlay. The SDK should turn those hard-coded surfaces into host-owned registries while preserving the same keyboard-first mental model.

## Feature Notes

### F-001 Plugin Manifest And Capability Model

The manifest should include a `ui` block for declared contributions:

- `lenses`: stable lens ID, label, 3-letter badge, capability category, supported object kinds, default sort, empty-state text, help text, and experimental/stable flag.
- `commands`: command namespace, examples, input target kinds, permissions required, and whether the command is context-sensitive.
- `inspector_cards`: card ID, supported object kinds, order hint, collapsed-by-default flag, and max height.
- `cockpit_chips`: short status indicators such as `RUN`, `WARN`, `SAFE`, `NET?`, or `EXP`.

Plugin manifests should not assign global one-letter shortcuts by default. Those keys are scarce and already carry muscle memory. Plugins may declare command aliases and suggested shortcuts, but activation should be host-managed or user-configured.

### F-002 Stable Schema And Object Graph SDK

The UI needs object identity more than raw plugin data. Every plugin-created row, score, diagnostic, and finding suggestion must resolve to a stable object ref, edge, run, or artifact. Inspector cards should render host-normalized fields first, then plugin-specific attributes in a bounded "Plugin Attributes" section. This keeps navigation, backlinks, and findings coherent.

### F-003 Importer And Adapter SDK

Adapters should surface in the TUI as import pathways, not as hidden CLI-only features. Empty states should say which plugin can populate a lens: for example, Trace Lab can show "No trace events. Run `:import trace <path>` or install/use a trace importer." Adapter runs need progress and diagnostics in the Cockpit and Inspector so users can distinguish "no data" from "plugin failed" or "permission denied."

### F-004 Specialized Lab Extension Points

Specialized labs should be registered lenses that use shared layout templates:

- Trace Lab: timeline table plus selected-event Inspector card.
- Crash Lab: cluster table plus stack/evidence Inspector cards.
- Firmware Lab: artifact tree plus binary summary cards.
- Protocol Lab: message list plus field grid and evidence links.
- Diff Lab: change table plus before/after object links.
- Graph Lab: local graph/path view, never a giant global graph by default.

The lens registry should support ordering by category: Core, Labs, Plugin Lenses, Experimental. Workspace should show badges for disabled, blocked, empty, or new plugin-provided lenses.

### F-005 Scoring Rule And Triage Pack SDK

Scores should be visually decomposable. Function Radar and Triage Board need provider badges next to reasons, for example `RAD core`, `SC ghidra-xref`, or `RULE firmware-risk`. Inspector score reasons should show contribution, provider, confidence, evidence count, and run ID. Opaque plugin scores should not be accepted into the primary triage list.

### F-006 Plugin Execution Safety And Permissions

Permission state is a UI feature, not only a runtime concern. The Cockpit should show compact chips for blocked, pending, failed, and running plugin jobs. Before execution, Command Deck should present a reviewable grant summary: artifact reads, project writes, filesystem paths, network, process spawn, secrets, timeout, and output scopes. Denied permissions should produce actionable empty or warning states inside affected lenses.

### F-007 Developer Tooling And Test Harness

The SDK should include TUI fixtures for plugin authors: manifest preview, lens registry preview, inspector card snapshot, command help rendering, empty/error states, and narrow-terminal screenshots. A plugin should fail validation if its labels overflow known terminal breakpoints or if help text lacks at least one command example.

### F-008 Plugin-Driven Finding And Report Workflow

Plugin-generated findings should enter as "suggestions" with provider, confidence, evidence chain, and review actions. Findings and Inspector should visually separate plugin suggestions from analyst-confirmed findings. Report-related UI should show which sections are plugin-generated, which are edited, and which are confirmed.

## Priority UI Decisions

1. Replace hard-coded workspace lens lists with a host lens registry, but keep the same pane model and navigation semantics.
2. Use constrained UI templates before allowing custom plugin renderers.
3. Treat Command Deck as the universal discovery layer for commands, plugins, permissions, and context help.
4. Make provenance visible everywhere a plugin affects triage, evidence, or reporting.
5. Define terminal breakpoints as SDK compatibility requirements, not late rendering polish.

## MVP Recommendation

For the first plugin-aware TUI release, ship three UI surfaces: plugin-provided commands in Command Deck, plugin score reasons in Function Radar/Inspector, and plugin lens registrations using host templates. Defer fully custom renderers until Trace Lab or Crash Lab proves which templates are insufficient.
