# Guidance Specification: RevDeck Next Powerful Features And TUI Optimization

## Positioning

RevDeck SHOULD continue to be a terminal-native reverse engineering workspace, not a full decompiler, debugger, or disassembler replacement. The next iteration SHOULD make the current Binary Triage loop deeper and faster while turning the Plugin SDK preview into a usable adapter path.

The strongest product direction is a two-track M2:

- M2A TUI Power Navigation: first-class Graph Lab, Command Deck, richer Binary Map, evidence paths, and workflow polish.
- M2B Adapter Commit Pipeline: process adapter runner, ObjectBatch commit, provenance/audit records, and first-party adapter fixtures.

## Core Terms

- Graph Lab: a first-class workspace lens for local object relations, xrefs, and source-to-sink evidence paths.
- Command Deck: searchable action palette combining commands, object search, recent targets, and previewed mutations.
- ObjectBatch Commit: host-mediated transaction that applies validated plugin graph facts to the project database.
- Adapter Runner: process-based plugin execution path with manifest permissions, timeouts, output caps, and audited diagnostics.
- Evidence Path: a navigable chain linking function, import, string, xref, note, finding, and plugin-produced evidence.
- Triage Queue: ordered review worklist derived from radar scores, diagnostics, weak boundaries, and finding gaps.
- Rule Pack: deterministic scoring extension that emits explainable score reasons rather than opaque scores.
- Binary Map 2.0: deeper format, section, import, entropy, packer, resource, and parse diagnostics view.

## Non-Goals

- MUST NOT implement full decompilation in this slice.
- MUST NOT add live debugging or binary patching before the project model is stronger.
- MUST NOT allow plugins to write SQLite directly.
- MUST NOT allow arbitrary custom TUI rendering before declarative host-owned slots are proven.
- SHOULD NOT build a public marketplace before runner, commit, signing, compatibility, and conformance gates.

## Feature Decomposition

1. F-001 Graph Lab And Evidence Paths.
2. F-002 Adapter Runner And ObjectBatch Commit.
3. F-003 Command Deck And Fuzzy Object Search.
4. F-004 Binary Map 2.0 And Packer Diagnostics.
5. F-005 Triage Queue And Finding Promotion.
6. F-006 Rule Pack SDK And Scoring Controls.
7. F-007 First-Party Adapter Proof Pack.
8. F-008 TUI Performance, Layout, And Visual Polish.

## Recommended Sequence

M2A SHOULD implement F-001, F-003, selected F-004, selected F-005, and F-008 because these improve the product immediately without waiting for external tools.

M2B SHOULD implement F-002 and F-007, then expose plugin-produced facts through the same Graph Lab and Command Deck surfaces.

M3 SHOULD implement F-006 after provenance and commit paths are stable, because scoring extensibility is dangerous if explainability, suppression, and replay are weak.
