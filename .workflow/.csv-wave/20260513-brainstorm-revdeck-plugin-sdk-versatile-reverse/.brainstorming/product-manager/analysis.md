# Product Manager Analysis

## Product Thesis

RevDeck should productize plugin extensibility as the way to become more versatile without becoming a monolithic reverse-engineering suite. The strongest user value is not "run every analyzer inside RevDeck"; it is "bring evidence from many specialized tools into one persistent project, then help the analyst decide what to inspect, annotate, confirm, and report."

The plugin SDK should therefore be positioned as a controlled evidence-ingestion and workflow-extension platform. The first commercial and adoption value comes from adapters, scoring packs, and reportable evidence chains, not from a broad public marketplace on day one.

Primary users:

- Binary triage analysts who need faster prioritization across functions, strings, imports, and findings.
- Firmware and product-security researchers who need to connect many files, architectures, traces, crashes, and notes.
- Internal security teams that want to encode proprietary scoring rules and import pipelines.
- Tool authors who can turn Ghidra, rizin, Frida, binwalk, ASAN, tshark, or Volatility outputs into RevDeck project objects.

## Feature Product Readout

### F-001 Plugin Manifest And Capability Model

This is a P0 product gate. The manifest should be the store shelf, trust contract, and compatibility boundary in one file. It MUST describe capability, permission, supported inputs, SDK version, diagnostics, and provenance behavior before install or run.

Product decision: keep the capability taxonomy small for the first SDK: Importer, Adapter, Analyzer, Scorer, Exporter, Rule Pack. Custom Lens and Action can exist as experimental flags after the core contracts stabilize.

### F-002 Stable Schema And Object Graph SDK

This is the platform foundation. Without stable object identity, evidence links, analysis runs, and provenance, RevDeck cannot credibly support plugins, reports, or marketplace packaging.

Product decision: expose a stable core schema first, with typed extension attributes instead of arbitrary plugin-owned object families. This protects report quality and avoids marketplace fragmentation.

### F-003 Importer And Adapter SDK

This is the fastest path to user value. RevDeck can become more versatile by converting real-world outputs into its object graph before it builds every specialized analyzer itself.

MVP adapters SHOULD include:

- Ghidra or rizin/radare2 export importer for functions, symbols, xrefs, and comments.
- Frida/syscall JSONL trace importer for execution evidence.
- ASAN/UBSAN/panic log importer for crash evidence.
- binwalk directory importer for firmware files and embedded binaries.
- tshark/pcap summary adapter as a later P1 proof.

### F-004 Specialized Lab Extension Points

Specialized labs are retention and depth features, but they should not lead the SDK MVP. Lab extension points should reuse common object navigation, inspector panels, notes, tags, and findings.

Product priority: start with Trace Lab and Crash Lab extension points because they create clear evidence chains and can be proven through importer plugins. Firmware Lab follows because it multiplies artifacts. Protocol, Memory, and Diff Labs can wait until the shared graph and navigation contracts are stable.

### F-005 Scoring Rule And Triage Pack SDK

This is a strong differentiator for Function Radar. It lets teams encode domain expertise without forking RevDeck. Scores MUST be explainable by visible reasons, plugin run, confidence, and affected object.

Product decision: ship rule packs as local packages before allowing marketplace scoring packs. Opaque or unaudited scores would damage trust in triage.

### F-006 Plugin Execution Safety And Permissions

This is a P0 adoption blocker. Reverse-engineering projects often contain sensitive samples, customer data, credentials, and unpublished findings. RevDeck MUST default to local-only, least-privilege execution with explicit filesystem, network, process, artifact-read, and project-write scopes.

Product decision: public marketplace is not viable until this model is understandable to analysts and enforceable across platforms.

### F-007 Developer Tooling And Test Harness

This is the developer funnel. The SDK preview should include scaffolding, manifest validation, fixture projects, golden-output tests, and a headless runner. A plugin author should be able to build a "hello importer" without opening the TUI.

Product decision: include minimal tooling in the MVP even if the full harness is P1, because broken plugins will be blamed on RevDeck.

### F-008 Plugin-Driven Findings And Report Workflow

This is high-value but should remain P2 until provenance and safety are mature. Plugins MAY propose draft findings and report sections, but analyst confirmation MUST remain explicit.

Product decision: "draft finding suggested by plugin" should be visually and structurally distinct from "analyst-confirmed finding." This protects report credibility.

## Recommended MVP

The SDK MVP should be called a local plugin SDK preview, not a marketplace launch.

MUST include: F-001 manifest validation, F-002 core object graph writes, F-003 importer/adapter contract, F-006 local execution permissions and audit logs, and a thin F-007 headless test runner.

SHOULD include: one first-party static adapter, one dynamic trace importer, one crash importer, and one Function Radar rule pack.

MUST NOT include: public marketplace, remote plugin execution, arbitrary database writes, unrestricted network access, broad custom TUI lens APIs, or plugin-generated final findings.

## Roadmap

Milestone 1: SDK contract preview. Lock manifest, capabilities, core schemas, analysis run provenance, permission prompts, and headless validation.

Milestone 2: Adapter proof pack. Ship first-party plugins for Ghidra/rizin export, Frida/syscall JSONL, ASAN crash logs, and binwalk firmware directories.

Milestone 3: Workflow depth. Add explainable scoring packs, Trace Lab and Crash Lab extension points, draft finding suggestions, and report section proposals.

Milestone 4: Ecosystem readiness. Add plugin signing, compatibility registry, private plugin gallery, version migration tools, and enterprise policy controls.

Milestone 5: Marketplace evaluation. Consider a curated marketplace only after safety, compatibility, documentation, and first-party examples have proven stable.

## Packaging And Marketplace Viability

Recommended packaging:

- Core: Binary Triage, local project database, built-in import, findings, reports, and local plugin loading.
- Pro: advanced labs, first-party adapter pack, scoring packs, report templates, batch workflows, and compatibility tools.
- Team or Enterprise: private plugin registry, signing policy, audit export, offline package distribution, and shared rule packs.

Marketplace viability is real but delayed. The likely early "marketplace" is not a public store; it is a curated gallery of first-party and trusted community plugins plus a private registry pattern for internal teams. Public distribution should wait until RevDeck can answer: who wrote this plugin, what can it read, what can it write, what versions does it support, what evidence did it create, and how can a user reproduce or revoke the run?

## Success Metrics

- Time from installing SDK to a validated hello-importer run.
- Percentage of plugin runs with complete provenance and deterministic rerun output.
- Import success rate across fixture projects and real external-tool samples.
- Time from imported evidence to first analyst-confirmed finding.
- Plugin crash rate and diagnostic quality.
- Share of findings with plugin-supported evidence chains.
- Adoption of first-party adapter pack by repeat users.
