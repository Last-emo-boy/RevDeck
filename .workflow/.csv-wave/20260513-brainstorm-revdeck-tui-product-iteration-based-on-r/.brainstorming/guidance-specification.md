# Guidance Specification -- RevDeck TUI Product Iteration

## Positioning
RevDeck SHOULD be treated as a terminal-native reverse engineering workspace, not as a replacement for IDA, Ghidra, radare2, Frida, Volatility, binwalk, or tshark. Its core product value is to organize unknown binaries, firmware, traces, crashes, protocol samples, notes, and evidence into a searchable, navigable, persistent project.

The product MUST optimize for the analyst loop described in `RevDeck.txt`: import target, index automatically, surface high-value entry points, jump across related objects, preserve notes and tags, form findings, and export a report.

The MVP MUST focus on Binary Triage before broader labs. It SHOULD make the user feel that RevDeck reliably answers: "What should I inspect next, and what have I already learned?"

## Core Terms
- RevDeck: terminal-native reverse engineering workspace for authorized reverse engineering, security research, firmware analysis, crash triage, and unknown-code understanding.
- Project: persistent analysis container with artifacts, index, graph, lenses, notes, findings, and reports.
- Artifact: imported binary, firmware directory, trace, crash log, protocol capture, memory dump, or external-tool output.
- Lens: focused TUI view over the same project database, such as Binary Map, Function Radar, Graph Lab, Trace Lab, Diff Lab, Firmware Lab, Crash Lab, Protocol Lab, Notes, and Findings.
- Unified Object Graph: shared model connecting files, binaries, functions, strings, imports, traces, crashes, protocol messages, notes, tags, and findings.
- Function Radar: prioritized function triage surface that ranks functions by reasons such as dangerous APIs, sensitive strings, xrefs, size, change signals, traces, crashes, and analyst tags.
- Universal Jump: keyboard-first navigation from any object to related objects.
- Analysis Memory: persistent notes, tags, renames, statuses, hypotheses, evidence links, and backlinks.
- Finding: reportable conclusion with severity, summary, evidence chain, status, and tags.
- Adapter: importer or analyzer boundary that converts external tool output into RevDeck schema.

## Non-Goals
- RevDeck MUST NOT attempt to replace full interactive disassemblers or decompilers in v0.1.
- RevDeck MUST NOT ship every Lab from the source document in the first product slice.
- RevDeck SHOULD NOT require dynamic instrumentation to demonstrate early value.
- RevDeck SHOULD NOT make global graph rendering the primary interaction model; local graph navigation is more usable in a TUI.
- RevDeck MUST NOT blur authorized analysis workflows with exploit automation as a product promise.

## Feature Decomposition

### F-001 Project Ingest And Index
Priority: P0

RevDeck MUST create/open a project and import at least one binary target. It MUST persist extracted sections, symbols, strings, imports, functions, xrefs, and baseline file metadata. The storage model SHOULD start with SQLite and stable IDs for every indexed object.

### F-002 Terminal Workspace Shell
Priority: P0

RevDeck MUST provide a three-pane TUI shell: workspace navigation, main lens, and inspector, with a bottom command bar. It SHOULD expose dense, keyboard-first workflows for repeated analysis instead of marketing-style screens.

### F-003 Function Radar
Priority: P0

RevDeck MUST rank functions with visible scoring reasons. Initial scoring SHOULD include function size, calls/imports, sensitive strings, dangerous APIs, xrefs, entrypoint proximity, and user tags. It MAY later include trace, crash, and diff signals.

### F-004 Universal Object Navigation
Priority: P0

RevDeck MUST let analysts jump from strings to referencing functions, functions to imports/xrefs/notes, findings to evidence, and notes back to objects. Navigation state SHOULD support back/forward history.

### F-005 Analysis Memory
Priority: P0

RevDeck MUST persist notes, tags, renames, object status, TODOs, hypotheses, evidence links, and timestamps. Analysis memory SHOULD be first-class, not a side panel-only feature.

### F-006 Findings And Report Export
Priority: P1

RevDeck SHOULD let analysts promote evidence-linked objects into structured findings with severity, status, tags, summary, and evidence. Export SHOULD support Markdown and JSON first, with HTML/SARIF/project bundle later.

### F-007 Graph Lab Seed
Priority: P1

RevDeck SHOULD introduce local graph navigation for xrefs, call graph, simple CFG, and source-to-sink sketches. It MUST remain navigable in a terminal and avoid huge unreadable global graphs.

### F-008 External Tool Adapter Boundary
Priority: P1

RevDeck SHOULD define adapter contracts for external outputs such as Ghidra exports, radare2 JSON, Frida trace JSONL, Volatility JSON, pcap/tshark outputs, ASAN logs, and binwalk directories. The core engine MUST own normalized schema and persistence.

## Boundaries For Step 2 Planning
- Plan SHOULD start with v0.1 Binary Triage and include only the minimum Graph Lab hooks needed to support xrefs and object jumps.
- Product decisions SHOULD keep future Labs possible without building them yet.
- Technical decisions SHOULD prefer stable schemas, deterministic indexing, and testable fixtures over broad analyzer ambitions.
- TUI design SHOULD keep controls dense and predictable for SSH, containers, remote samples, and keyboard-heavy workflows.
