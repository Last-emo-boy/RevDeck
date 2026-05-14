# Brainstorm Report -- RevDeck Plugin SDK And Specialized RE Expansion

## Summary

- Topic: make RevDeck more versatile and more specialized, with plugin specification and SDK for extension.
- Roles analyzed: 6.
- Features decomposed: 8.
- Conflict gate: 0 unresolved conflicts.
- Confidence: 0.88 overall.

The strongest direction is **local SDK preview first, marketplace later**. RevDeck should become versatile by importing and normalizing evidence from mature external tools, then using its existing strengths: TUI navigation, Function Radar, Inspector, notes, findings, and reports.

## Product Direction

RevDeck should not try to replace IDA, Ghidra, radare2, Frida, Volatility, binwalk, tshark, fuzzers, or debuggers. It should be the project cockpit that turns their outputs into stable, searchable, navigable, provenance-rich evidence.

The first SDK should prove:

- A plugin can be validated from `revdeck-plugin.toml`.
- A plugin can run locally through a process boundary.
- A plugin can submit schema-validated ObjectBatch output.
- The host can commit graph facts with full provenance.
- Unsafe permissions are blocked by default.
- A plugin can be tested headlessly and replayed deterministically.

## Feature Index

| ID | Feature | Priority | Decision |
| --- | --- | --- | --- |
| F-001 | Plugin Manifest And Capability Model | P0 | First public contract |
| F-002 | Stable Schema And Object Graph SDK | P0 | Host-mediated ObjectBatch, no direct SQL |
| F-003 | Importer And Adapter SDK | P0 | Fastest user value |
| F-004 | Specialized Lab Extension Points | P1 | Declarative lenses before custom renderers |
| F-005 | Scoring Rule And Triage Pack SDK | P1 | Explainable score reasons only |
| F-006 | Plugin Execution Safety And Permissions | P0 | Required before useful plugin execution |
| F-007 | Developer Tooling And Test Harness | P1 | Ship with SDK preview |
| F-008 | Plugin Driven Finding And Report Workflow | P2 | Analyst-gated suggestions |

## Role Findings

### Product Manager

Prioritize a local SDK preview over marketplace. The highest-value early plugins are adapters and rule packs, not broad custom lenses. Plugin-generated findings need suggestion, draft, and confirmed trust states.

### System Architect

Use process-based, schema-validated plugins with host-mediated graph commits. Record deterministic run digests, plugin run state, permissions, diagnostics, metrics, and layered config.

### Data Architect

Keep the core object graph host-owned. Let plugins extend objects with schema-registered typed attributes and host-managed datasets. Use ObjectBatch transactions and contribution records for provenance.

### Subject Matter Expert

Adapter-first is the right RE strategy. Normalize address spaces carefully, model domain confidence, and connect firmware, traces, crashes, protocol, memory, diffs, notes, and findings into cross-lab evidence chains.

### UI Designer

Plugins should contribute through host-owned slots: lens registry entries, Command Deck commands, inspector cards, cockpit chips, triage reasons, and finding suggestions. Constrained templates come before custom rendering.

### Test Strategist

The SDK needs a conformance suite: manifest validation, graph-delta validation, golden fixtures, deterministic replay, sandbox permission matrix, compatibility tests, and reducer-first TUI regressions.

## Resolved Conflicts

- [RESOLVED] Public marketplace is deferred until local SDK, safety, signing, compatibility, and conformance gates are proven.
- [RESOLVED] Process-based plugin protocol comes before Rust dynamic library ABI.
- [RESOLVED] Plugins do not write private SQLite tables directly.
- [SUGGESTED] Use typed attributes and host-managed datasets before arbitrary custom object kinds.
- [SUGGESTED] Use declarative lens templates before custom renderers.
- [SUGGESTED] Host owns global shortcuts; plugins suggest aliases and Command Deck commands.

## Roadmap

### M1 SDK Contract Preview

Implement F-001, F-002, F-006, and the minimum of F-007.

Exit criteria:

- `revdeck-plugin.toml` validates.
- `revdeck plugin inspect` shows capabilities and permissions.
- ObjectBatch dry-run validates graph deltas.
- Process plugin runner records plugin runs and sanitized diagnostics.
- `revdeck plugin test` runs fixture replay and permission-denial tests.

### M2 Adapter Proof Pack

Implement F-003 with first-party examples.

Recommended plugins:

- Ghidra/rizin export adapter.
- Trace JSONL importer.
- ASAN/UBSAN/panic crash importer.
- binwalk firmware tree adapter.

### M3 Workflow Depth

Implement F-004, F-005, and later F-008.

Exit criteria:

- Trace/Crash lab templates are usable.
- Plugin score reasons show in Function Radar and Inspector.
- Plugin finding suggestions stay distinct from analyst-confirmed findings.

## Artifacts

- Guidance: `.brainstorming/guidance-specification.md`
- Feature index: `.brainstorming/feature-index.json`
- Synthesis changelog: `.brainstorming/synthesis-changelog.md`
- Feature specs: `.brainstorming/feature-specs/F-001-*.md` through `F-008-*.md`
- Role analyses: `.brainstorming/{role}/analysis.md`

## Next Steps

Recommended next skill: `maestro-plan` for M1 SDK Contract Preview.

Recommended first implementation slice:

1. Add `crates/revdeck-plugin-sdk` with manifest structs and schema validation.
2. Add `crates/revdeck-plugin-host` with process runner skeleton and dry-run ObjectBatch validation.
3. Add `revdeck plugin validate|inspect|test` CLI commands.
4. Add tests under `tests/plugin-sdk` with valid/invalid manifest fixtures.
