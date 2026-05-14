# Guidance Specification -- RevDeck Plugin SDK And Specialized Reverse Engineering

## 1. Positioning and scope

RevDeck SHOULD remain a terminal-native reverse engineering workspace that organizes binaries, firmware, traces, crashes, protocol captures, external-tool output, notes, and findings into one persistent project. The product direction for this brainstorm is to make RevDeck more versatile and more specialized without turning it into a monolithic replacement for IDA, Ghidra, radare2, Frida, Volatility, binwalk, or tshark.

The core scope is an extensible analysis platform with a stable object graph, normalized schemas, deterministic project storage, keyboard-first lenses, and evidence-linked findings. The plugin specification and SDK MUST let external analyzers, importers, scorers, lenses, exporters, and automation actions contribute data and UI affordances through explicit contracts rather than by mutating project internals directly.

The strongest product promise SHOULD be: RevDeck helps an authorized analyst decide what to inspect next, preserve what they learned, and connect specialized evidence across static analysis, dynamic traces, firmware layouts, crash clusters, protocol samples, memory artifacts, and third-party tool outputs.

This guidance assumes RevDeck already has the v0.1 Binary Triage loop from `README.md`: project database, ELF/PE import, Function Radar, TUI navigation, notes, findings, and Markdown/JSON reporting. New work SHOULD extend that loop through schema and SDK boundaries before building every specialized lab in full.

## 2. Core terminology

- Project: persistent RevDeck workspace containing artifacts, normalized objects, edges, notes, findings, reports, plugin runs, and configuration.
- Artifact: imported input or derived source of evidence, such as a binary, firmware directory, trace JSONL, crash log, pcap, memory dump, or external-tool export.
- Unified Object Graph: normalized graph of files, binaries, functions, strings, imports, traces, crashes, messages, memory objects, notes, tags, findings, and typed relationships.
- Lens: focused TUI view over project data, such as Binary Map, Function Radar, Graph Lab, Trace Lab, Diff Lab, Firmware Lab, Crash Lab, Protocol Lab, Memory Lab, Notes, or Findings.
- Plugin: versioned extension package that declares capabilities, permissions, input/output schemas, compatibility, commands, and lifecycle hooks.
- SDK: developer-facing libraries, CLI scaffolding, schemas, fixtures, test harnesses, and examples for building compliant RevDeck plugins.
- Capability: declared plugin role such as Importer, Analyzer, Lens, Scorer, Exporter, Action, Rule Pack, or Adapter.
- Adapter: plugin or built-in component that converts output from external tools into RevDeck schemas without making RevDeck depend on those tools internally.
- Evidence Chain: ordered set of objects, edges, notes, traces, diffs, or external references supporting a finding.
- Analysis Run: recorded execution of a built-in analyzer or plugin, including inputs, outputs, diagnostics, version, timing, and provenance.

## 3. Non-goals and responsible-use boundaries

- RevDeck MUST NOT position itself as an exploit framework, malware deployment platform, credential theft toolkit, or bypass automation product.
- Plugins MUST NOT be allowed to silently exfiltrate samples, project databases, findings, traces, credentials, or analyst notes.
- The SDK MUST NOT require plugin authors to understand RevDeck's private database layout for normal extension work.
- RevDeck SHOULD NOT expose direct arbitrary database writes as the standard plugin API.
- RevDeck SHOULD NOT promise complete decompilation, symbolic execution, dynamic instrumentation, memory forensics, or protocol inference in the core product.
- The first plugin SDK iteration MUST NOT require a public marketplace, remote package execution, or cross-user plugin sync.
- Specialized labs SHOULD NOT ship as disconnected mini-tools; they MUST connect back to project objects, navigation, notes, and findings.
- RevDeck MAY support offensive-security research workflows only when framed around authorized analysis, reproducible evidence, safe reporting, and analyst-controlled execution.

## 4. Feature decomposition

### F-001 plugin-manifest-and-capability-model

Priority: P0

Related roles: system-architect, product-manager, product-owner, test-strategist

Define a plugin manifest format with plugin ID, semantic version, RevDeck compatibility range, capabilities, permissions, inputs, outputs, commands, lens registrations, configuration schema, diagnostics, and provenance metadata. The manifest MUST be machine-validated before a plugin is installed or run.

### F-002 stable-schema-and-object-graph-sdk

Priority: P0

Related roles: data-architect, system-architect, subject-matter-expert, test-strategist

Publish SDK types for normalized objects, edges, artifacts, analysis runs, evidence links, diagnostics, and findings. Plugins MUST write through stable schema APIs that preserve object identity, provenance, and graph integrity.

### F-003 importer-and-adapter-sdk

Priority: P0

Related roles: system-architect, subject-matter-expert, product-owner, test-strategist

Provide importer and adapter contracts for ELF/PE/Mach-O metadata, Ghidra/radare2/rizin exports, Frida/QEMU/syscall traces, ASAN/UBSAN/panic logs, Volatility JSON, binwalk directories, pcap/tshark data, and generic JSONL evidence. This feature SHOULD prioritize converting real-world outputs into RevDeck's object graph over reimplementing every analyzer.

### F-004 specialized-lab-extension-points

Priority: P1

Related roles: product-manager, ux-expert, ui-designer, system-architect

Expose extension points for specialized lenses: Trace Lab, Diff Lab, Firmware Lab, Crash Lab, Protocol Lab, Memory Lab, and Graph Lab. Each lens extension MUST declare supported object types, navigation targets, commands, selection behavior, and inspector panels.

### F-005 scoring-rule-and-triage-pack-sdk

Priority: P1

Related roles: subject-matter-expert, product-manager, test-strategist, data-architect

Allow plugins to contribute scoring reasons, rule packs, risk tags, detector outputs, and triage queues for Function Radar and Triage Board. Scores MUST be explainable, attributable to a plugin/run, and decomposable into visible reasons rather than opaque numbers.

### F-006 plugin-execution-safety-and-permissions

Priority: P0

Related roles: system-architect, product-owner, test-strategist, scrum-master

Introduce a permission and execution model covering filesystem access, network access, external process execution, project write scopes, artifact read scopes, secret redaction, timeouts, resource limits, and crash isolation. RevDeck MUST default to least privilege and MUST record plugin runs for auditability.

### F-007 developer-tooling-and-test-harness

Priority: P1

Related roles: test-strategist, system-architect, product-owner, scrum-master

Ship SDK templates, schema validators, fixture projects, golden-output tests, CLI scaffolding, documentation, and compatibility checks. Plugin authors SHOULD be able to run local tests without opening the TUI, and CI SHOULD verify manifest validity, schema compatibility, and deterministic output.

### F-008 plugin-driven-finding-and-report-workflow

Priority: P2

Related roles: product-manager, subject-matter-expert, ux-expert, data-architect

Let plugins propose findings, evidence chains, report sections, and export formats while keeping analyst confirmation in the loop. Plugins MAY create draft findings, but RevDeck SHOULD distinguish plugin-generated suggestions from analyst-confirmed findings.

## 5. Cross-cutting requirements

- RevDeck MUST preserve the v0.1 Binary Triage loop while adding SDK surfaces.
- Plugin APIs MUST be versioned, documented, and validated with machine-readable schemas.
- Plugins MUST declare capabilities and permissions before execution.
- Plugins MUST NOT mutate private SQLite tables directly through the supported SDK path.
- All plugin-created objects, edges, scores, notes, and draft findings MUST carry provenance: plugin ID, plugin version, analysis run ID, source artifact, and timestamp.
- RevDeck MUST support deterministic re-runs where plugin inputs and configuration are unchanged.
- RevDeck MUST expose plugin diagnostics in the TUI and CLI without leaking sensitive sample contents by default.
- RevDeck MUST keep analyst-controlled confirmation for reportable findings that affect final deliverables.
- RevDeck SHOULD support both native Rust plugins and process-based adapters if the process boundary is the safer or more portable option.
- RevDeck SHOULD prefer normalized schema exchange over plugin-to-plugin direct coupling.
- RevDeck SHOULD provide fixtures for binaries, traces, crashes, firmware directories, pcap samples, and external-tool exports.
- RevDeck SHOULD let specialized labs reuse common navigation, inspector, command palette, notes, tags, findings, and evidence-link behavior.
- RevDeck SHOULD NOT require network access for plugin execution unless explicitly granted by the analyst.
- RevDeck SHOULD NOT treat plugin scores as authoritative without visible explanations and confidence signals.
- RevDeck MAY allow experimental plugins, but experimental capability flags MUST be visibly marked and excluded from stable SDK guarantees.
- RevDeck MAY introduce marketplace or package signing later, but local manifest validation and safe execution SHOULD come first.

## 6. Assumptions and open questions

Assumptions:

- RevDeck will continue to use SQLite-backed project storage for the near term.
- The first SDK target can support process-based plugins before committing to in-process ABI stability.
- Rust remains the core implementation language, but adapters may be written in other languages if they communicate through schema-stable files, streams, or subprocess protocols.
- The initial plugin contract can focus on importers, analyzers, scorers, exporters, and adapter-style actions before fully custom TUI lenses.
- Existing v0.1 concepts, including Function Radar, Notes, Findings, Inspector, command bar, and report export, remain core extension surfaces.

Open questions:

- Should plugin execution use WASI, subprocess JSON-RPC, dynamic libraries, or a hybrid model for v0.9?
- What is the minimum stable schema set needed before Trace Lab, Crash Lab, Protocol Lab, and Firmware Lab can share objects cleanly?
- How should RevDeck handle schema migrations for plugin-created object types?
- Should plugins be able to define custom object types, or only extend predefined object families with typed attributes?
- What level of sandboxing is realistic on Windows, Linux, and macOS for the first SDK release?
- How should signed plugins, trust levels, and marketplace metadata be handled after local plugin support works?
- Which first-party sample plugins should prove the SDK: Ghidra export importer, Frida trace importer, ASAN crash importer, pcap/tshark adapter, or Function Radar rule pack?
