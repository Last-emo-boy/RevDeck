# E4 Risk Exploration -- M1 SDK Contract Preview

## Scope Read

Inputs reviewed:

- Prior brainstorm report: `.workflow/.csv-wave/20260513-brainstorm-revdeck-plugin-sdk-versatile-reverse/context.md`
- M1 specs: `F-001`, `F-002`, `F-006`, `F-007`
- Current wave context: `E1-architecture.md`, `E2-implementation.md`, `discoveries.ndjson`
- Codebase searches for process execution, environment access, redaction, analysis runs, ObjectRef/StableObjectKey, migrations, CLI commands, and integration tests.

M1 needs to prove a local SDK contract preview, not a marketplace or full OS sandbox. The plan must explicitly gate claims around plugin execution safety, permission enforcement, deterministic replay, and schema compatibility.

## Current Risk-Relevant Code Patterns

- There is no existing product process runner or sandbox surface. Search for `std::process`, `Command::new`, spawn, timeout, child kill, and environment stripping found no product implementation.
- Workspace dependencies in `Cargo.toml:24` include serde, sha2, rusqlite, clap, thiserror, time, tempfile, assert_cmd, and predicates, but not explicit `toml`, `jsonschema`, `schemars`, or a process-timeout helper. `semver` appears only transitively in `Cargo.lock`.
- Core public wire enums follow stable snake_case serde patterns. `ObjectKind` and `EdgeKind` are in `crates/revdeck-core/src/object.rs:6` and `crates/revdeck-core/src/object.rs:76`.
- Stable identity exists, but it is strict. `StableObjectKey::new` rejects empty keys and backslashes (`crates/revdeck-core/src/object.rs:151`, `crates/revdeck-core/src/object.rs:405`). Component values are lowercased and normalize `\` to `/` (`crates/revdeck-core/src/object.rs:437`).
- Existing analysis audit is coarse. `AnalysisRunStatus` only supports `running`, `succeeded`, `failed`, and `canceled` (`crates/revdeck-core/src/analysis.rs:8`). The DB enforces the same CHECK constraint in `analysis_runs.status` (`crates/revdeck-db/migrations/0001_foundation.sql:20`).
- `AnalysisRunRepository::start` and `finish` are the current audit write API (`crates/revdeck-db/src/repo.rs:1493`, `crates/revdeck-db/src/repo.rs:1510`). They can hold plugin digest/audit JSON, but not the full F-006 lifecycle as queryable state.
- Object graph writes are direct repository upserts. `ObjectRepository::upsert_object` and `upsert_edge` write one statement at a time (`crates/revdeck-db/src/repo.rs:214`, `crates/revdeck-db/src/repo.rs:287`). Migrations use transactions, but normal object writes do not (`crates/revdeck-db/src/migrations.rs:41`).
- The native importer persists source paths in metadata and errors can include filesystem paths (`crates/revdeck-index/src/lib.rs:187`, `crates/revdeck-index/src/lib.rs:1203`). There is no general redaction helper for plugin diagnostics.
- CLI output is a single clap dispatcher in `crates/revdeck-cli/src/main.rs:20`, with JSON summaries for analysis/import and JSON validation errors for report generation (`crates/revdeck-cli/src/main.rs:84`, `crates/revdeck-cli/src/main.rs:206`).
- Existing tests are feature-specific workspace crates under `tests/*`. There is no `tests/plugin-sdk` crate and no current CLI binary integration test using `assert_cmd`.

## Risk Register

### 1. Process safety and permission enforcement

Risk: F-006 asks for denial of network, process spawn, secrets, environment, broad filesystem access, direct DB access, resource limits, sanitized diagnostics, and non-mutating failures. The current codebase has no sandbox or process-runner foundation. Rust `std::process::Command` can start a child and strip environment, but it does not provide cross-platform filesystem or network isolation, nor does it reliably clean up a child process tree on Windows.

Planning implications:

- Treat M1 runner as a "safety skeleton" unless a real sandbox backend is chosen. Do not claim OS-level sandboxing.
- Put default-deny permission evaluation before execution and before ObjectBatch acceptance.
- For M1, block all permissions except an explicit small local fixture/protocol path by default. Direct SQLite access must stay unsupported.
- Add a clear capability/permission report in `revdeck plugin inspect`.
- Runner tests should cover denied env access, denied process spawn, malformed protocol, timeout, output flood, crash behavior, and no DB mutation on failure.
- If process execution is included, host should set a controlled current directory, clear inherited environment unless allowed, avoid inherited stdin, cap stdout/stderr bytes, enforce timeout, and record sanitized diagnostics.

### 2. Windows process and path behavior

Risk: The workspace is being developed on Windows. Path normalization is already important: `StableObjectKey` forbids backslashes after final validation and normalizes component values. Process behavior differs from Unix: there is no signal semantics, child cleanup can leave descendants, environment keys are case-insensitive, quoting paths with spaces matters, and CRLF output can affect deterministic protocol parsing.

Planning implications:

- Add Windows-targeted tests for plugin paths with spaces, backslashes in input paths, CRLF JSONL output, env stripping, timeout, and child cleanup where feasible.
- Normalize plugin diagnostics and replay bundles using `/` paths and stable line endings.
- Treat child-process tree cleanup as a known M1 limitation if only `std::process` is used.
- Avoid using raw absolute sample paths in golden outputs.

### 3. ObjectBatch atomicity and no-mutation dry run

Risk: Object repository writes are upsert statements with no enclosing transaction in normal flows. A partial ObjectBatch commit could insert objects before a later dangling edge or metadata error fails. The native importer also calls `remove_indexed_facts_for_artifact`, which deletes broad artifact facts and is unsafe for plugin-scoped replace semantics.

Planning implications:

- Implement dry-run validation as a pure host phase that does not call `upsert_object`, `upsert_edge`, or importer deletion methods.
- Validate all object refs, edge refs, duplicate keys, dangling edges, confidence ranges, required provenance, permission scope, metadata JSON size, and known kind support before commit.
- If M1 includes commit, add an explicit transaction boundary around the whole accepted batch. Consider a host API that takes `&mut Connection` or a DB repository method that owns the transaction.
- Do not use `IndexRepository::remove_indexed_facts_for_artifact` for plugins in M1.

### 4. Audit model mismatch

Risk: F-006 describes lifecycle states from `discovered` through `superseded`, but current `analysis_runs` can only represent running/succeeded/failed/canceled. Storing all plugin run details only in `diagnostics_json` is quick but not queryable for later TUI chips or command filtering.

Planning implications:

- The plan must choose one M1 audit scope explicitly:
  - Minimal preview: store manifest digest, input digest, config digest, permissions, counts, timing, and sanitized diagnostics in `analysis_runs.diagnostics_json`.
  - Durable model: add migration 0005 with `plugin_runs` and a plugin state enum.
- If minimal preview is chosen, document that lifecycle states beyond `running/succeeded/failed/canceled` are diagnostic JSON only and defer queryable state to M2/M3.
- Tests must assert denied and failed plugin runs are audit-recorded and non-mutating.

### 5. Stable public schema and compatibility

Risk: Reusing `revdeck-core` enums in the SDK is pragmatic, but it turns object and edge kinds into public wire contracts. Unknown enum variants currently fail parsing, which is correct for validation but can make minor-version compatibility brittle. M1 also needs TOML parsing, semver `revdeck_compat`, and config schema handling, but those dependencies are not declared yet.

Planning implications:

- Add explicit workspace dependencies for `toml` and `semver`. Choose either full `jsonschema` validation or a clearly scoped config-schema structural validator for M1.
- Include `sdk_version`, ObjectBatch `schema_version`, and normalized manifest digest in public validation results.
- Golden tests should cover valid manifests, bad semver/ranges, unknown capabilities/permissions, duplicate IDs, unsupported SDK ranges, missing provenance, and invalid config schema.
- Prefer canonical JSON for digests: sorted/stable output, no runtime timestamps, no raw absolute paths.

### 6. Deterministic replay

Risk: Existing flows use `OffsetDateTime::now_utc()` and DB autoincrement run IDs. Some stable key helpers also include run IDs or timestamps for scores, annotations, and findings. If plugin replay compares raw SQLite rows or diagnostics with live timestamps, replay will be flaky.

Planning implications:

- `revdeck plugin test` should compare normalized graph bundles and accepted event digest sequences, not raw SQLite snapshots.
- ObjectBatch stable keys should be plugin-provided deterministic keys or host-normalized keys derived from stable input, not DB run IDs.
- Run ID, timing, and wall-clock timestamps belong in provenance/audit fields and should be normalized out of replay goldens.
- Add idempotent replay tests: same manifest + input + config + batch produces the same accepted digest sequence and same rejected-event report.

### 7. Diagnostics and data leakage

Risk: RevDeck handles binaries, traces, memory strings, notes, and findings. Existing import metadata can include source paths, and error messages can include filesystem paths. Plugin stdout/stderr and ObjectBatch values may contain credentials, private keys, packet payloads, memory strings, or raw sample paths.

Planning implications:

- Add a host redaction/sanitization module in M1, even if initially simple and conservative.
- Sanitize process stderr/stdout, manifest paths, diagnostics, and denied-permission messages before storing or printing.
- Cap diagnostic size and object-batch metadata size to prevent output flood and huge DB rows.
- Tests should include private-key-like text, token/password strings, absolute Windows paths, and oversized diagnostics.

### 8. Test gate gaps

Risk: The repo has good unit/integration patterns, but no plugin conformance suite. `assert_cmd` and `predicates` are available, yet current tests do not exercise the CLI binary. Without a dedicated suite, M1 can appear to work at library level while the CLI contract drifts.

Planning implications:

- Add `tests/plugin-sdk` as a workspace member with fixtures under `fixtures/plugins`.
- Cover manifest validation, inspect output, ObjectBatch dry-run rejection, permission-denial matrix, deterministic replay, and CLI command behavior.
- Keep tests platform-aware: isolate Windows process cleanup tests when they are not portable.
- Add build/test gates for new crates plus `cargo test -p revdeck-plugin-sdk -p revdeck-plugin-host -p revdeck-plugin-sdk-tests` or the equivalent workspace test targets.

## Must-Have Planning Mitigations

1. Start with schema/manifest validation and ObjectBatch dry-run before arbitrary process execution.
2. Make permission evaluation a typed host API, not CLI-only checks.
3. Keep direct SQL and private SQLite schema out of the public SDK.
4. Add redaction, output caps, and no-mutation failure tests before enabling `plugin run`.
5. Choose the audit storage model explicitly: minimal `analysis_runs` JSON or a new `plugin_runs` migration.
6. Treat Windows process cleanup and network/filesystem isolation as known limitations unless a real sandbox backend is added.
7. Use normalized replay bundles and accepted-event digests for `revdeck plugin test`.
8. Add explicit TOML/semver/schema validation dependency choices and compatibility fixtures.

## Recommended Plan Gates

- Gate 1: `revdeck-plugin-sdk` manifest parsing, normalized digest, permission enum, ObjectBatch DTOs, and validation reports all unit-tested.
- Gate 2: `revdeck-plugin-host` dry-run validator proves no DB mutation on rejected batches and denied permissions.
- Gate 3: Runner skeleton only executes fixture plugins under default-deny settings, with timeout, env stripping, output caps, and sanitized diagnostics.
- Gate 4: CLI `revdeck plugin validate|inspect|test|run --dry-run` returns stable JSON suitable for conformance tests.
- Gate 5: Cross-platform fixture replay and Windows path/process tests pass or limitations are explicitly marked and deferred.
