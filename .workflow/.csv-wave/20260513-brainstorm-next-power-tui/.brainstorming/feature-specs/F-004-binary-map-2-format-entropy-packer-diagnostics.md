# F-004 Binary Map 2 Format Entropy Packer Diagnostics

Priority: P1

## Summary

Expand Binary Map into the first stop for file identity and parse health: format details, sections, import grouping, entropy hints, resources, and clear explanations for unknown or packed input.

## Must Have

- PE/ELF format summary and architecture metadata when parser provides it.
- Section table with address, size, flags, and entropy bucket.
- Parse diagnostics panel with next actions.
- Packed/obfuscated suspicion hints based on entropy/import/string scarcity.

## Acceptance

- Unknown file magic tells the user what happened and what to try next.
- Packed-like fixtures show a clear diagnostic without pretending to fully unpack.
