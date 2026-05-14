# Product Manager Analysis

## Product Thesis
RevDeck should win by managing the reverse engineering project, not by competing feature-for-feature with mature disassemblers. The v0.1 promise should be: import a binary, understand its high-value surfaces quickly, preserve analyst work, and produce evidence-linked output.

## Target Users
- Security researchers triaging unknown binaries.
- Firmware analysts comparing embedded targets and extracted executables.
- Vulnerability researchers moving from suspicious function to evidence chain.
- Engineers reviewing crash or CI analysis outputs over SSH.

## MVP Slice
The MVP MUST complete the Binary Triage loop:
1. Create/open a project.
2. Import a binary artifact.
3. Index sections, symbols, imports, strings, functions, and xrefs.
4. Surface Function Radar with scoring reasons.
5. Navigate from function/string/import/xref to related objects.
6. Add tags, notes, renames, and review status.
7. Promote evidence to findings.
8. Export Markdown/JSON reports.

## Prioritization
P0:
- F-001 Project Ingest And Index
- F-002 Terminal Workspace Shell
- F-003 Function Radar
- F-004 Universal Object Navigation
- F-005 Analysis Memory

P1:
- F-006 Findings And Report Export
- F-007 Graph Lab Seed
- F-008 External Tool Adapter Boundary

## Roadmap Interpretation
`RevDeck.txt` contains a broad v0.1-v1.0 roadmap. Product planning should keep that as strategy, but the first execution milestone should be smaller than the full v0.1 list if implementation is starting from zero. A useful first milestone can still prove the product with fixture ELF import, scoring, navigation, notes, and export.

## Risks
- The product may become a disconnected toolkit if each Lab is built before the object graph is stable.
- Function Radar will disappoint if scores are opaque; every score needs explainable reasons.
- Report export is only credible if evidence links survive navigation and persistence.
