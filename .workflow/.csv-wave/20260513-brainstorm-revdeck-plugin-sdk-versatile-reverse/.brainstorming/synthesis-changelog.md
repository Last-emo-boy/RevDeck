# Synthesis Changelog

Generated: 2026-05-13T18:05:00+08:00

Topic: RevDeck plugin SDK and specialized reverse-engineering extension model.

## Inputs Read

- `.brainstorming/guidance-specification.md`
- `.brainstorming/product-manager/analysis.md`
- `.brainstorming/product-manager/analysis-cross-cutting.md`
- `.brainstorming/system-architect/analysis.md`
- `.brainstorming/system-architect/analysis-cross-cutting.md`
- `.brainstorming/data-architect/analysis.md`
- `.brainstorming/data-architect/analysis-cross-cutting.md`
- `.brainstorming/subject-matter-expert/analysis.md`
- `.brainstorming/subject-matter-expert/analysis-cross-cutting.md`
- `.brainstorming/ui-designer/analysis.md`
- `.brainstorming/ui-designer/analysis-cross-cutting.md`
- `.brainstorming/test-strategist/analysis.md`
- `.brainstorming/test-strategist/analysis-cross-cutting.md`
- `discoveries.ndjson`

## Consensus

1. RevDeck should become an evidence platform that integrates specialized tool output, not a monolithic replacement for IDA, Ghidra, Frida, binwalk, tshark, Volatility, or fuzzers.
2. The first SDK should be a local plugin SDK preview, not a public marketplace launch.
3. The stable runtime boundary should be manifest plus schema-validated process protocol. Native Rust helpers are useful, but Rust dynamic-library ABI should not be the first stable extension contract.
4. Plugins should emit validated graph deltas and output events. The host should commit those changes through `revdeck-db` repositories under one `analysis_run`.
5. Stable core object families, typed attributes, host-managed extension datasets, contribution records, and deterministic object keys are the practical data foundation.
6. Adapter-first work gives the fastest value: static exports, traces, crashes, firmware trees, pcap summaries, memory-forensics JSON, and generic JSONL evidence.
7. Least-privilege permissions, local-only defaults, redaction, audit trails, and deterministic replay are P0 adoption requirements.
8. Plugin UI should use declarative slots: lens registry entries, command actions, inspector cards, cockpit chips, triage reasons, finding suggestions, and help sections.
9. The conformance suite is part of the SDK contract, not optional developer convenience.

## Conflicts

- [RESOLVED] Marketplace timing: Defer public marketplace. Ship local plugins, first-party examples, conformance tests, permission UX, signing/trust metadata, and private distribution patterns before public plugin discovery.
- [RESOLVED] Custom object kinds: Use host-owned object families plus typed attributes in v0.9. Recurring plugin shapes can graduate into core schema migrations after query, export, navigation, and compatibility rules are proven.
- [RESOLVED] Arbitrary plugin tables: Do not allow plugin-owned raw DDL in the stable SDK. Use host-managed extension datasets with declarative schemas, host-approved indexes, and typed cursors.
- [SUGGESTED] Custom renderers: Stable plugins should use host templates. Fully custom terminal renderers can exist only as experimental plugins after renderer API, keyboard, accessibility, and snapshot tests exist.
- [SUGGESTED] Plugin shortcuts and styling: Host owns global shortcuts, focus behavior, and safety colors. Plugins can suggest aliases, labels, examples, provider badges, and opt-in bindings.
- [SUGGESTED] First-party adapter order: Build one static export adapter, one trace importer, one crash importer, one firmware tree importer, and one scoring pack. Choose Ghidra versus rizin first based on fixture availability and target users.
- [UNRESOLVED] Cross-platform sandbox strength: The synthesis can specify least-privilege policy and denial tests, but OS-specific enforcement depth on Windows, Linux, and macOS needs implementation research.

Unresolved count: 1. This is below the quality-gate warning threshold of more than 3 unresolved conflicts.

## Roadmap Sequencing

### M0: Schema And Manifest Lock

Features: F-001, F-002

Exit criteria:

- Manifest schema, normalized digest, capability taxonomy, and compatibility rules are fixed for preview.
- Core object and edge vocabulary covers artifacts, files, binaries, functions, strings, imports, traces, crashes, protocol messages, memory objects, diffs, notes, findings, and evidence links.
- Typed attribute registry, dataset registry, contribution records, and ObjectBatch validation are designed.

### M1: Local SDK Preview

Features: F-001, F-002, F-006, F-007

Exit criteria:

- Process-based plugin host can validate, launch, deny, timeout, collect events, buffer graph deltas, and commit atomically.
- `revdeck plugin validate`, `run --no-tui`, `test`, `replay`, `list`, `inspect`, and `doctor` exist.
- Sandbox denial tests prove denied filesystem, network, process, environment, database, timeout, and malformed protocol behavior is non-mutating and auditable.

### M2: Adapter Proof Pack

Features: F-003, F-007

Exit criteria:

- Static export adapter imports functions, symbols, strings, imports, xrefs, and call graph edges.
- Trace importer maps runtime events to stable trace objects and address spaces.
- Crash importer clusters stack signatures and links frames to functions where possible.
- Firmware importer maps extraction trees, file hashes, embedded binaries, and derived artifacts.
- Golden graph bundles validate counts, diagnostics, redaction, evidence links, and deterministic digest.

### M3: Workflow Depth

Features: F-004, F-005, F-008

Exit criteria:

- Trace Lab and Crash Lab use declarative lens templates and inspector cards.
- Function Radar and Triage Board show plugin score reasons with confidence, provider, rule ID, and evidence refs.
- Finding suggestions move through suggestion, draft, and confirmed states with analyst control.

### M4: Governed Distribution

Features: F-001, F-006, F-007

Exit criteria:

- Signing/trust policy, private registry metadata, uninstall/revocation semantics, audit export, and compatibility matrix are validated.

### M5: Marketplace Evaluation

Features: all platform surfaces

Exit criteria:

- Public distribution is evaluated only after safety, compatibility, provenance, conformance, and responsible-use review pass.

## Confidence Scoring

Overall confidence: 0.86

Dimension scores:

- Role coverage: 0.95. Six complementary roles participated and agreed on the main architecture.
- Cross-role consistency: 0.88. Major tensions converged on staged extensibility and local SDK preview first.
- Feature completeness: 0.87. The eight features cover manifest, schema, adapters, labs, scoring, safety, tooling, and findings.
- Spec quality: 0.84. Specs are implementable but still need codebase-specific crate and migration design.
- Design feasibility: 0.78. Process plugins, host-mediated commits, and tests are feasible; cross-platform sandboxing remains the largest unknown.

Weighted factors:

- Analysis depth: 0.90
- Evidence strength: 0.86
- Coverage breadth: 0.92
- User validation: 0.50
- Consistency: 0.88

## Artifacts Created

- `feature-index.json`
- `synthesis-specification.md`
- `feature-specs/F-001-plugin-manifest-and-capability-model.md`
- `feature-specs/F-002-stable-schema-and-object-graph-sdk.md`
- `feature-specs/F-003-importer-and-adapter-sdk.md`
- `feature-specs/F-004-specialized-lab-extension-points.md`
- `feature-specs/F-005-scoring-rule-and-triage-pack-sdk.md`
- `feature-specs/F-006-plugin-execution-safety-and-permissions.md`
- `feature-specs/F-007-developer-tooling-and-test-harness.md`
- `feature-specs/F-008-plugin-driven-finding-and-report-workflow.md`

## Implementation Guardrails

- Do not expose direct SQLite writes through supported plugin APIs.
- Do not let plugins silently access network, secrets, project databases, analyst notes, or unscoped filesystem paths.
- Do not let plugin suggestions become analyst-confirmed findings without explicit review.
- Do not promote custom object kinds, raw plugin tables, global shortcuts, or custom renderers into stable APIs before compatibility tests exist.
- Keep every plugin-created object, edge, attribute, score reason, dataset record, draft finding, and report fragment tied to plugin ID, version, analysis run, input digest, schema version, timestamp, and confidence.
