# F-007 First Party Adapter Proof Pack

Priority: P1

## Summary

Ship real adapter examples so the SDK is not theoretical. The adapters should normalize external evidence into RevDeck ObjectBatch fixtures.

## Candidate Adapters

- Ghidra or rizin JSON export adapter.
- Trace JSONL importer.
- ASAN/UBSAN/panic crash log importer.
- binwalk-style firmware tree importer.

## Must Have

- Fixture-based replay for each adapter.
- Manifest and permission examples.
- Clear provenance linking imported facts to source files and plugin run.

## Acceptance

- At least one adapter can import external evidence into a project and expose it in TUI views.
