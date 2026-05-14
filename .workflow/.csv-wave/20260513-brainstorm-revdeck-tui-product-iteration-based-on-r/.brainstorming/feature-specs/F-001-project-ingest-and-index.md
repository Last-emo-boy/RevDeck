# F-001 Project Ingest And Index

## Intent
Create the durable foundation for RevDeck projects. A user MUST be able to create/open a project, import a binary artifact, run indexing, and reopen the same project with stable objects.

## Scope
- Project directory and SQLite database.
- Artifact registration with path, hash, type, and metadata.
- Binary structure indexing: sections, symbols, strings, imports, functions, and xrefs where available.
- Analysis run records for deterministic re-indexing.

## Acceptance Signals
- Indexed object counts are visible in Overview.
- Objects have stable IDs.
- Import failures are stored as structured errors.
- Fixture binaries produce deterministic results.

## Dependencies
None.
