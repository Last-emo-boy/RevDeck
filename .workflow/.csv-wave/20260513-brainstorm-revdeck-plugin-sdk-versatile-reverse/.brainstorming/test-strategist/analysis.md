# Test Strategist Analysis

## Summary

RevDeck's plugin SDK should be released only with a conformance suite that is treated as part of the public contract. The current repository already has the right testing shape: small fixtures, isolated integration crates under `tests/*`, deterministic object-key assertions, TUI rendering through `ratatui::TestBackend`, command reducer tests, and SQLite-backed project tests. The SDK should extend that pattern with `tests/plugin-sdk`, `tests/plugin-sandbox`, `tests/plugin-compat`, and fixture packages rather than inventing a separate quality process.

The core test objective is simple: a plugin can be scaffolded, validated, run headlessly, denied unsafe permissions, and replayed deterministically without corrupting the project database or bypassing analyst-controlled findings.

## Feature Coverage

F-001 `plugin-manifest-and-capability-model`: Manifest validation needs negative-first tests. Golden manifests should cover importer, analyzer, scorer, exporter, lens, action, rule pack, and adapter capabilities. Invalid fixtures should include duplicate plugin IDs, bad semver, unsupported RevDeck ranges, unknown permissions, undeclared commands, config schema errors, mismatched input/output schemas, experimental flags used as stable APIs, and package digest mismatch. Compatibility tests should assert that install-time validation and run-time validation produce the same normalized manifest digest.

F-002 `stable-schema-and-object-graph-sdk`: The SDK contract suite should validate graph deltas before persistence. Tests must assert deterministic `ObjectRef` construction, stable sorting, idempotent re-runs, mandatory provenance, rejected dangling edges, rejected unknown object kinds, accepted typed attributes, rollback on partial batch failure, and no supported path to direct SQLite writes. Golden graph-delta fixtures should snapshot accepted JSONL events and the resulting normalized bundle, not raw internal tables.

F-003 `importer-and-adapter-sdk`: Adapter tests should be fixture-driven by domain: tiny Ghidra/radare2/rizin exports, Frida/QEMU/syscall JSONL traces, ASAN/UBSAN/panic logs, binwalk-like trees, tshark JSON, Volatility JSON, malformed JSON, missing symbols, rebased addresses, duplicate events, and unsupported tool versions. Every adapter fixture should have a golden graph summary: object counts by kind, edge counts by kind, diagnostics, redaction flags, evidence links, and deterministic output digest.

F-004 `specialized-lab-extension-points`: Lens plugins should be tested through declarative view contracts first. For each lab contribution, assert supported object kinds, query limits, command registration, selection behavior, inspector sections, and navigation targets. TUI regressions should use fixed terminal sizes including small fallback widths. Rendering tests should search for stable labels and object refs rather than brittle full-screen snapshots until the UI settles.

F-005 `scoring-rule-and-triage-pack-sdk`: Rule packs need explainability tests. A score is invalid if it has no visible reason, no evidence ref, no source run, or an opaque contribution. Golden triage fixtures should prove stable ordering, tie-breaking, confidence handling, multi-plugin contribution merge behavior, and suppression or withdrawal of stale plugin scores after a re-run.

F-006 `plugin-execution-safety-and-permissions`: Sandbox tests are P0. Use fake plugins that attempt denied filesystem reads, project database access, network calls, external process launch, environment variable reads, excessive stdout/stderr, long-running jobs, malformed protocol output, and crash-on-start. Expected outcomes: denial before launch where possible, run status recorded, sanitized diagnostics, no accepted output events, no project mutation, and a metric or event for the denial.

F-007 `developer-tooling-and-test-harness`: Ship `revdeck plugin test` as the public harness. It should run manifest validation, schema validation, fixture replay, deterministic digest comparison, permission simulation, and compatibility checks without the TUI. The SDK should also expose a minimal Rust test helper and a language-neutral JSONL fixture runner so Python or shell-based adapters can participate.

F-008 `plugin-driven-finding-and-report-workflow`: Tests must protect analyst authority. Plugin-created findings should remain suggestions or drafts until explicitly confirmed. Report export tests should assert visible plugin provenance, evidence-chain preservation, redaction defaults, and a clear distinction between plugin-suggested and analyst-confirmed findings.

## Release Gates

SDK preview should require passing conformance tests for one first-party importer, one adapter, one scorer, and one exporter. Stable SDK should add compatibility matrices across previous SDK minor versions, project schema migrations, Windows/Linux/macOS process behavior, and deterministic replay on the same fixtures.

Quality metrics should include manifest validation coverage, fixture pass rate, deterministic replay mismatch count, rejected output event count, sandbox denial coverage, plugin crash isolation pass rate, TUI regression pass rate, and compatibility matrix pass rate.
