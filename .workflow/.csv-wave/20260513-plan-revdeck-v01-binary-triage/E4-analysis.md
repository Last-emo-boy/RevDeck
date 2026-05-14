# E4 Risk And Test Exploration

## Scope Anchors

- Product source: `RevDeck.txt`
- Phase context: `.workflow/scratch/20260513-revdeck-v01-binary-triage/context.md`
- Brainstorm inputs: `test-strategist/analysis.md`, `F-001-project-ingest-and-index.md`, `F-003-function-radar.md`, `F-006-findings-and-report-export.md`
- MVP boundary: RevDeck v0.1 proves binary triage only: project creation/open, binary import/index, Function Radar, object navigation, analysis memory, finding creation, Markdown/JSON export.

## Primary Risk Shape

The highest risks are not advanced reverse engineering gaps. They are trust breaks in the triage loop:

1. Re-indexing the same fixture yields different object IDs, scores, order, or reports.
2. Function boundaries are presented as precise when they are heuristic.
3. Score values are visible but not explainable enough to defend a finding.
4. Schema migrations preserve rows but break object links, notes, tags, or evidence.
5. TUI navigation state works manually but is not testable as deterministic state transitions.
6. The command parser mutates state before resolving ambiguity or invalid targets.
7. Markdown and JSON exports drift from the persisted finding/evidence graph.

## Binary Fixture Determinism

### Risks

- If fixtures are compiled during tests, section layout, symbol tables, imports, and function addresses can vary by compiler, target triple, flags, linker, OS, and timestamp metadata.
- Snapshot tests become noisy if expected counts are inferred from live tools rather than a checked manifest.
- Corrupt and unsupported artifacts can accidentally pass through as partial imports without structured error records.

### Architecture and Implementation Findings

- Treat binary fixtures as source-controlled artifacts with a fixture manifest, not as build products. Store the fixture SHA-256, format, arch, expected sections, expected strings, expected imports, expected symbols, expected functions, and expected xrefs.
- Add an `analysis_runs` row for every import/index attempt. Test determinism by importing the same artifact twice into a fresh project and once into an existing project; assert stable IDs, stable counts, stable errors, stable scoring, and stable report output.
- Keep unsupported/corrupt handling in F-001, not only CLI error text: structured errors should be persisted with artifact ID, stage, message, and recoverability.
- For Windows developer machines, avoid requiring ELF toolchains during unit tests. Prebuilt tiny ELF fixtures are safer; generated fixtures can be reserved for a separate fixture-maintenance task with checked SHA outputs.

### Test Requirements

- Golden fixture tests: minimal ELF, stripped ELF, sensitive-string/dangerous-import ELF, unsupported file, corrupt/truncated file.
- Determinism tests: same input creates identical object key sets and sorted Function Radar rows.
- Error tests: corrupt input stores a structured failed analysis run and leaves the project reopenable.

## Function Boundary Accuracy

### Risks

- RevDeck v0.1 cannot promise full decompiler-grade function recovery, especially for stripped binaries.
- Bad boundaries can inflate function size, misattribute strings/imports/xrefs, and produce misleading high-risk scores.
- Address-only identity is fragile when multiple artifacts or re-index runs are involved.

### Architecture and Implementation Findings

- Introduce a `boundary_confidence` or equivalent field for functions: `symbol`, `entrypoint`, `import_thunk`, `heuristic`, `external_adapter`.
- Keep v0.1 UI wording confidence-scoped. Function Radar can rank heuristic functions, but the inspector should surface boundary source/confidence so users understand why a score exists.
- Stable object IDs should not be SQLite row IDs. Prefer deterministic object keys derived from artifact identity plus object kind plus normalized address/range/name. Store row IDs only as internal database details.
- Function interval tests should assert no invalid overlaps inside the same artifact unless explicitly represented as aliases/thunks.

### Test Requirements

- Boundary fixture tests: symbol-backed function exact ranges, stripped binary heuristic ranges, import thunk classification.
- Regression tests: strings and imports should attach only to functions whose ranges contain the xref/callsite according to the indexed model.
- Negative tests: unknown boundaries should remain low-confidence instead of being silently promoted.

## Scoring Explainability

### Risks

- A score without structured reasons is hard to test and hard to defend in exported findings.
- If scoring uses unordered maps or non-stable tie-breaking, Function Radar will reorder rows between runs.
- User tags are in F-003 scoring scope, so analysis memory changes can affect score. That coupling must be explicit.

### Architecture and Implementation Findings

- Make score breakdown a first-class model, not a formatted string: signal key, weight, matched evidence object refs, contribution, and display label.
- Deterministic ordering should be part of the contract: `score desc`, then stable tie-breakers such as normalized address and object key.
- Score reasons should link to the evidence object that caused the reason where possible: sensitive string, dangerous import, xref, entrypoint proximity, user tag.
- UX acceptance should require every non-zero score to show at least one reason, and every reason to be inspectable in the right pane.

### Test Requirements

- Unit tests for each scoring signal.
- Fixture-level golden tests for final score, reason labels, contribution values, and sorted order.
- Tie-breaker tests for equal scores.
- Explainability invariant: no visible score row can have an empty reason set unless score is zero and explicitly labelled as no signals.

## Migration Safety

### Risks

- F-001 creates the durable project foundation; F-005/F-006 later depend on preserving notes, tags, renames, findings, and evidence links.
- SQLite migrations can preserve tables but break object references if object keys change.
- Automatic migration on project open can destroy analyst work without a backup or dry-run path.

### Architecture and Implementation Findings

- Add a `schema_migrations` table from the first database version. Migrations should be forward-only and idempotence-tested.
- Define object reference storage early, even if some object types are sparse in v0.1. Findings, notes, tags, and reports should point at stable object refs rather than view-local IDs.
- Project open should detect schema version and expose clear migration errors. For v0.1, a backup-before-migrate behavior is safer than silent in-place mutation.
- Migration tests should use real SQLite fixture DBs, not just in-memory schema creation.

### Test Requirements

- Old-project fixture with artifact, functions, strings, imports, notes, tags, renames, and findings.
- Migration test: run migrator, reopen project, assert all annotation/evidence object refs resolve.
- Failure test: migration error leaves original DB intact and produces a structured error.

## TUI State Tests

### Risks

- Full terminal rendering tests are expensive and brittle, but RevDeck still needs deterministic confidence in the three-pane workspace.
- Navigation can regress even when database tests pass: selection, inspector context, focus, back/forward stack, and command results are state behavior.

### Architecture and Implementation Findings

- Split TUI into state/reducer/view layers. Test the reducer with synthetic events before relying on terminal snapshots.
- State tests should model the product loop: open project, load overview counts, select Function Radar row, update inspector, jump to strings/imports/xrefs, tag object, create finding, export report.
- Keep layout rendering snapshot tests minimal and viewport-stable. State-level assertions should carry most coverage.

### Test Requirements

- Reducer tests for focus movement, selection movement, inspector update, back/forward navigation, command result routing, modal/edit state, and error display.
- TUI integration smoke test using a test backend for the main workspace at fixed terminal sizes.
- Reopen-state test: persistent annotations resolve after app restart; ephemeral UI focus may reset but object refs must not.

## Command Parser Tests

### Risks

- RevDeck's command bar is a core TUI affordance in `RevDeck.txt`; ambiguous or partially parsed commands can mutate the wrong object.
- Quoted strings, object names, addresses, severities, tags, and search queries create parsing edge cases.
- Parser tests become hard if parse, target resolution, and execution are coupled.

### Architecture and Implementation Findings

- Separate command parser, resolver, and executor. Parser returns an AST; resolver maps AST targets to object refs or ambiguity diagnostics; executor mutates state only after successful resolution.
- Cover MVP commands only: search/find, xrefs, tag, rename, finding create/edit/link, report/export, navigation open/jump. Do not implement the broader v1 query language yet.
- Error messages should be structured enough for tests: invalid syntax, unknown command, missing argument, ambiguous target, unresolved target, unsupported-in-v0.1.

### Test Requirements

- Table-driven parser tests for valid MVP commands.
- Invalid command tests for missing arguments, malformed quotes, unsupported commands, and ambiguous target syntax.
- Resolver tests using fixture project data where `system`, a string, and a function name can collide.
- Executor tests proving invalid or ambiguous commands do not mutate notes/tags/findings.

## Report Round Trips

### Risks

- Findings are the deliverable layer; if export omits severity/status/evidence/object links, RevDeck fails the v0.1 loop.
- Markdown can be readable but lossy. JSON can round-trip key fields but still break if ordering or object refs are unstable.
- Missing evidence should be visible before export, not silently omitted.

### Architecture and Implementation Findings

- Treat JSON export as canonical and Markdown as a presentation format generated from the same finding model.
- Use stable ordering in exports: findings by severity/order/ID, evidence by object type and object key, tags alphabetically.
- Add an export validation step that marks findings with missing or unresolved evidence before writing the report.
- Store enough object context in JSON to round-trip key fields without requiring the exact same SQLite row IDs.

### Test Requirements

- JSON round-trip tests for finding severity, status, summary, tags, evidence refs, and annotation context.
- Markdown golden tests for a small fixture project. Keep snapshots stable by deterministic ordering and fixed timestamps or timestamp injection.
- Missing-evidence tests: export warns or marks unresolved evidence.
- Reopen-export-reimport smoke: create finding, export JSON, parse it back, compare canonical model.

## Feature-Level Planning Implications

1. F-001 should include fixture infrastructure, stable object keys, analysis run records, structured import errors, and first migration table.
2. F-003 should include score breakdown schema and deterministic sort tests, not just UI rows.
3. F-004/F-005 planning should require a shared `ObjectRef` model before navigation, notes, tags, and findings diverge.
4. F-002 should include TUI state/reducer tests as a first deliverable, with rendering snapshots only as smoke coverage.
5. F-006 should define canonical JSON before Markdown formatting and include unresolved-evidence validation.
6. Command parser work should be a separate implementation task because it gates navigation, tagging, findings, and export commands.

## Recommended Verification Gates

- `cargo test` unit suite for parsers, scoring, object refs, migrations, and export model.
- Fixture integration tests that import known binaries into temporary project DBs and assert deterministic persisted outputs.
- TUI reducer tests with synthetic events and fixed fixture state.
- Report golden tests with normalized timestamps and stable ordering.
- Migration tests using checked-in old-version SQLite DB fixtures.

## Discoverable Knowledge

The reusable rule for the plan is: RevDeck v0.1 must treat determinism as a product invariant. Fixture binaries, stable object refs, structured score reasons, migrations, command execution, and report exports should all be tested through the same deterministic project workspace lens.
