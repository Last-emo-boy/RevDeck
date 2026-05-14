# Test Strategist Cross-Cutting Decisions

## 1. Test Architecture

The plugin SDK should publish a layered test suite:

- Unit tests for SDK structs, manifest normalization, stable keys, permissions, and schema validation.
- Contract tests for host/plugin protocol events: `handshake`, `diagnostic`, `artifact`, `object`, `edge`, `attribute`, `dataset_record`, `score_reason`, `draft_finding`, `report_section`, `progress`, `heartbeat`, and `finish`.
- Integration tests that run fake plugin executables against temporary RevDeck projects.
- Golden fixture replay for real reverse-engineering inputs and external-tool exports.
- TUI regression tests for plugin-contributed commands, inspector sections, lenses, and diagnostics.
- Compatibility tests across SDK versions, project schema versions, plugin manifest versions, and platform sandbox modes.

The test harness should verify public SDK behavior, not implementation details. Current database table assertions are useful for core tests, but SDK conformance should compare normalized graph bundles, accepted event digests, diagnostics, and query outputs so RevDeck can evolve SQLite internals.

## 2. Golden Fixtures

Fixtures should live in stable families:

- `fixtures/plugins/manifests`: valid and invalid manifests.
- `fixtures/plugins/packages`: minimal fake plugins for each capability.
- `fixtures/plugin-io`: JSONL host requests and plugin event outputs.
- `fixtures/external-tools`: Ghidra, radare2/rizin, Frida, QEMU/syscall, ASAN, binwalk tree, tshark, Volatility, and generic JSONL samples.
- `fixtures/projects`: tiny project bundles for import, migration, replay, and report tests.
- `fixtures/tui`: workspace snapshots with plugin diagnostics, draft findings, and lens contributions.

Each golden should include a machine-readable expectation file with object counts, edge counts, score counts, diagnostics, redaction state, permission expectations, and output digest. Avoid golden files that snapshot volatile timestamps, raw absolute paths, terminal colors, or unordered JSON maps.

## 3. Determinism And Replay

Determinism is a contract, not a nice-to-have. For the same plugin package digest, manifest digest, input artifact hashes, selected object refs, config hash, RevDeck schema version, and SDK version, a deterministic plugin should emit the same accepted event digest sequence.

Tests should run deterministic fixtures twice in fresh project directories, compare normalized bundles, then run once against an existing project to verify idempotency. Re-runs must not duplicate objects or edges. If a plugin declares non-determinism, tests should require a manifest reason and visible lower-trust labeling.

## 4. Sandbox And Permission Matrix

The permission test matrix should cover:

- Filesystem: no access, read artifact, read project snapshot, read declared external path, write derived output, path traversal denied.
- Network: denied by default, allowlisted host only, DNS or raw socket denied when not declared.
- Process: denied by default, declared external tool path only, argument escaping, non-zero exit, timeout.
- Environment and secrets: default redaction, allowlisted variables, credential-looking values blocked from diagnostics.
- Project writes: no write, graph delta only, score only, draft finding only, report section only.
- Resource limits: CPU timeout, memory limit where supported, output byte limit, event count limit, heartbeat timeout.

The suite should distinguish policy denial from plugin failure. Denials should be stable, auditable, and non-mutating; crashes should be isolated and recoverable.

## 5. Compatibility Strategy

Compatibility should be tested in four directions:

1. Old plugin on new RevDeck.
2. New plugin rejected by old RevDeck with a clear compatibility error.
3. Old project opened after core schema migration with plugin facts preserved.
4. Plugin upgrade where old facts remain queryable or migrate through declared host-approved steps.

Use a fixture matrix for SDK `0.x` preview versions and tighten guarantees at `1.0`. A manifest compatibility range should be tested against actual schema validators, not only string parsing.

## 6. Fuzzing And Property Tests

Fuzz targets should include manifest parser, JSONL protocol frame parser, stable object key parser, query filter parser, command parser for plugin commands, report fragment sanitizer, and adapter parsers for traces, crashes, packets, and memory JSON. Property tests should assert no panic, bounded diagnostics, no path traversal, deterministic normalization, and no accepted dangling references.

For high-volume domains, add stress fixtures: large trace JSONL, many packet messages, many duplicate crash frames, huge strings, deeply nested firmware paths, and malformed Unicode. These tests should protect TUI responsiveness and query pagination.

## 7. CLI And TUI Regression

The CLI should expose stable commands for test automation: `plugin validate`, `plugin run --no-tui`, `plugin test`, `plugin replay`, `plugin list`, and `plugin permissions`. CLI tests should assert exit codes, sanitized stderr, JSON output schema, and unchanged project state on failures.

TUI tests should remain reducer-first. Plugin UI tests should exercise command registration, command help, permission prompts, diagnostics panel, plugin-created evidence in Inspector, draft finding labels, and lens navigation. Use `ratatui::TestBackend` at 54x12, 80x24, 120x30, and 160x40 to guard small-terminal behavior without brittle pixel-perfect snapshots.

## 8. Cross-Role Conflicts

There is a useful tension between broad plugin flexibility and testable contracts. Arbitrary custom object kinds, raw plugin tables, and fully custom lens rendering are hard to validate, migrate, export, and regress. The test strategy supports the architecture/data recommendation: start with host-owned object families, typed attributes, declared datasets, and declarative UI contributions. Expand only when a compatibility suite exists for the new surface.

There is also a product tension between fast ecosystem growth and safety. A permissive SDK is easier to demo but harder to trust with malware samples, memory dumps, credentials, and private notes. The release gate should require least-privilege sandbox tests and deterministic replay before any marketplace or public plugin distribution.
