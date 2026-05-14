# Product Manager Cross-Cutting Decisions

## 1. Positioning Decision: Evidence Platform Before Tool Suite

RevDeck should not compete feature-by-feature with IDA, Ghidra, Frida, Volatility, binwalk, or tshark. The product story should be: keep using specialized tools, then use RevDeck to normalize outputs, connect evidence, prioritize review, and produce durable findings.

This decision favors F-001, F-002, F-003, and F-006 over broad F-004 Lab work. Specialized Labs should be consumers of the shared object graph, not separate products with separate data models.

## 2. Dependency Order

The marketable sequence should be:

1. Contract: F-001 manifest and F-002 schema.
2. Trust: F-006 safety, permissions, and audit.
3. Value: F-003 adapters that import real external-tool output.
4. Developer funnel: F-007 validation, fixtures, scaffolding, and CI examples.
5. Workflow depth: F-005 rule packs and selected F-004 labs.
6. Deliverable loop: F-008 draft findings and report proposals.
7. Ecosystem: signing, private registry, and eventual marketplace.

The key tradeoff is that F-007 appears less user-facing, but it directly affects plugin quality. A minimal headless test harness should ship with the first SDK preview.

## 3. Capability Taxonomy As Product Packaging

Plugin capabilities should map to both developer understanding and product packaging:

- Importer and Adapter: bring evidence into RevDeck.
- Analyzer: derive objects, edges, diagnostics, and tags.
- Scorer and Rule Pack: influence triage priority with explainable reasons.
- Exporter: produce reports or downstream files.
- Lens and Action: extend TUI workflows, initially experimental.

This taxonomy should appear consistently in docs, manifest validation, TUI permission prompts, plugin lists, and future gallery pages. Users should understand a plugin's role before they run it.

## 4. Schema Policy

For the first SDK, plugins should write stable core object families and typed extension attributes. Arbitrary custom object types are attractive for ecosystem growth but risky for search, reporting, migration, and Lab interoperability.

Recommended policy:

- P0: predefined object families for artifacts, files, binaries, functions, strings, imports, traces, crashes, protocol messages, memory objects, notes, tags, findings, and edges.
- P0: every plugin-created object carries plugin ID, plugin version, analysis run ID, source artifact, timestamp, and schema version.
- P1: typed extension attributes with JSON schema validation.
- P2: custom object families only after RevDeck has migration, indexing, and reporting rules for them.

## 5. First-Party Proof Plugins

The SDK should be proven by plugins that represent different user jobs rather than by toy examples only.

Recommended first-party set:

- Static adapter: Ghidra export or rizin/radare2 JSON importer.
- Dynamic adapter: Frida/syscall trace JSONL importer.
- Crash adapter: ASAN/UBSAN/panic log importer with stack-frame linking.
- Firmware adapter: binwalk directory importer that links embedded files and binaries.
- Scoring pack: Function Radar rule pack for dangerous imports, suspicious strings, and boundary confidence.

These plugins make the SDK concrete and create demos for binary triage, dynamic analysis, crash triage, and firmware workflows.

## 6. Specialized Lab Strategy

F-004 should be sold internally as "extension points for lenses" rather than "build every lab now." Product priority should follow evidence clarity:

- Trace Lab first: time-ordered events naturally link to functions, imports, strings, and findings.
- Crash Lab second: stack frames, crash signatures, and sanitizer logs create obvious triage queues.
- Firmware Lab third: directory trees and embedded binaries expand RevDeck from single-binary triage to case workspace.
- Diff, Protocol, and Memory Labs later: each needs stronger schema maturity and more domain-specific expectations.

Each Lab MUST reuse RevDeck navigation, Inspector, notes, tags, findings, evidence links, and command patterns. A Lab that cannot produce or consume evidence chains should not be prioritized.

## 7. Findings Trust Model

F-008 should protect analyst credibility. Plugin output should move through three states:

- Suggestion: plugin-created, unconfirmed, visibly attributed.
- Draft finding: analyst has accepted the topic but not finalized severity or evidence.
- Confirmed finding: analyst-owned deliverable item included in reports.

RevDeck should never blur plugin suggestions with analyst-confirmed conclusions. This is especially important if rule packs or marketplace plugins later produce risk labels.

## 8. Marketplace Readiness Gate

A public marketplace should be treated as a later product, not an SDK MVP requirement.

Marketplace readiness requires:

- Machine-validated manifests and compatibility ranges.
- Least-privilege permissions that users can understand.
- Plugin signing or trust metadata.
- Deterministic test fixtures and compatibility CI.
- Clear uninstall and run-revocation semantics.
- Provenance in reports and project history.
- Abuse-resistant positioning that avoids exploit automation branding.

Before that, ship a local plugin folder, first-party examples, and a curated plugin gallery document. Enterprise users will likely value private plugin distribution earlier than a public store.

## 9. Packaging Strategy

Core RevDeck should keep the current Binary Triage loop useful without plugins. Plugin support should extend that loop rather than make core feel incomplete.

Suggested packaging:

- Free or Core: local plugins, manifest validation, core importers, basic report export.
- Pro: first-party adapter pack, advanced Lab extension points, scoring packs, batch import, advanced report templates.
- Team: private registry, policy controls, signed plugins, audit export, shared fixtures, and organization rule packs.

This keeps individual analysts productive while giving teams a reason to pay for governance and shared extensions.

## 10. Product Risks And Mitigations

Risk: SDK breadth dilutes the v0.1 triage loop.
Mitigation: require every plugin feature to improve import, prioritization, navigation, findings, or reporting.

Risk: Marketplace plugins damage trust or leak sensitive samples.
Mitigation: local-only execution first, explicit permissions, no default network, audit trail, signing later.

Risk: Custom schemas fragment the product.
Mitigation: stable core schemas first, extension attributes second, custom object families later.

Risk: Specialized Labs become disconnected mini-tools.
Mitigation: shared object graph, common Inspector, command palette, notes, tags, and findings contracts.

Risk: Plugin-generated findings create false authority.
Mitigation: suggestion/draft/confirmed states with provenance and analyst confirmation.

## 11. Acceptance Criteria For Product Readiness

- A plugin author can scaffold, validate, run, and test a simple importer headlessly.
- A first-party adapter can import real external-tool output into stable RevDeck objects and edges.
- A plugin run records inputs, configuration, version, diagnostics, permissions, duration, and output counts.
- A user can inspect plugin-created evidence from the TUI and link it into a finding.
- A failed plugin does not corrupt the project and produces actionable diagnostics.
- A rerun with unchanged inputs produces deterministic object identities or explicit diff output.
- A report can show which plugin suggested or supported each evidence chain without exposing sensitive sample content by default.
