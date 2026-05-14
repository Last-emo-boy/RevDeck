# Test Strategist Analysis

## Quality Strategy
RevDeck should be tested as a deterministic project workspace. The most important properties are stable indexing, explainable scoring, durable annotations, reversible navigation, and reportable evidence.

## Fixture Set
Create small fixtures:
- Minimal ELF with known sections/imports/strings.
- Stripped ELF fixture.
- Binary containing sensitive strings and dangerous imports.
- Fake external adapter JSON output.
- Corrupt or unsupported artifact.
- Project with notes/tags/findings for migration and export tests.

## Test Areas
- Import/index: object counts, metadata, error states, stable IDs.
- Scoring: reason generation and deterministic ordering.
- Navigation: string -> xref -> function -> import -> note -> finding.
- Command parser: exact syntax, invalid commands, ambiguous targets.
- Persistence: reopen project, annotations and navigation targets still resolve.
- Export: Markdown/JSON include finding evidence, severity, status, and object links.
- Migration: schema version upgrades do not drop annotations.

## Mocking
External dependencies should be mocked at adapter boundaries. Tests should not require Ghidra, radare2, Frida, Volatility, or tshark unless explicitly marked integration.

## Regression Risks
- Non-deterministic scoring will make snapshots noisy.
- Address-based IDs alone may break across diff/import scenarios; stable object identity needs design attention.
- TUI tests need state-level assertions even before full terminal rendering automation exists.
