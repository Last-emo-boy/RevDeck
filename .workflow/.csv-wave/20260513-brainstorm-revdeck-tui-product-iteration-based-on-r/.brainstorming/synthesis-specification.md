# Synthesis Specification

## Consensus
All role perspectives converge on a focused v0.1: RevDeck should first become a reliable terminal-native Binary Triage workspace. The most important product surfaces are project ingest/index, Function Radar, universal object navigation, analysis memory, and findings/report export.

## Product Shape
RevDeck should be positioned as the layer above specialized tools. It owns project organization, persistence, cross-object navigation, annotations, findings, and reports. It consumes or adapts analysis output from existing tools where practical.

## Prioritized Feature Set
1. F-001 Project Ingest And Index
2. F-002 Terminal Workspace Shell
3. F-003 Function Radar
4. F-004 Universal Object Navigation
5. F-005 Analysis Memory
6. F-006 Findings And Report Export
7. F-007 Graph Lab Seed
8. F-008 External Tool Adapter Boundary

## Conflict Resolution
- [RESOLVED] Scope breadth: Keep the full Lab vision as roadmap, but execute v0.1 around Binary Triage.
- [RESOLVED] Native parsing vs tool integration: Own the normalized schema and project DB; add adapters incrementally.
- [RESOLVED] Graph ambition: Use local graph/path navigation first; avoid large global graph rendering in TUI.
- [SUGGESTED] Report export timing: Include at least Markdown/JSON early so findings become deliverable.
- [UNRESOLVED] Exact parser/disassembly crate choices remain implementation-planning work.
- [UNRESOLVED] Function boundary accuracy must be validated against fixture binaries.

## Product Acceptance For Planning
A plan based on this brainstorm should be considered coherent if it can demonstrate:
- A project can be created and reopened.
- A target binary can be imported and indexed into persistent objects.
- Function Radar shows ranked functions with reasons.
- The user can jump across strings, xrefs, functions, imports, notes, and findings.
- Notes/tags/renames/status survive restart.
- A finding with evidence can be exported.

## Confidence
- role_coverage: 0.88
- cross_role_consistency: 0.86
- feature_completeness: 0.84
- spec_quality: 0.82
- design_feasibility: 0.78
- overall: 0.84
