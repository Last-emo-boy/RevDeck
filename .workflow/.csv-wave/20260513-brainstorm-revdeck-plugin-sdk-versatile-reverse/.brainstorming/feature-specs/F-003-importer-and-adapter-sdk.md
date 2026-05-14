# F-003 Importer And Adapter SDK

## Purpose

Make RevDeck versatile by importing outputs from specialized tools into the unified object graph before attempting to reimplement those tools.

## User Value

Analysts can bring Ghidra/rizin exports, traces, crash logs, firmware trees, pcap summaries, and memory-forensics output into the same TUI workflow: triage, jump, tag, note, link evidence, and report.

## Requirements

- Importers/adapters MUST run through the plugin host with declared permissions.
- Adapters SHOULD emit ObjectBatch outputs plus diagnostics.
- Each source file or stream SHOULD become an Artifact with content hash and provenance.
- Address-space normalization MUST distinguish static VA, file offset, firmware path offset, runtime PC, crash frame PC, protocol byte range, and memory VA.
- Adapters MUST report reconciliation failures for missing symbols, rebasing ambiguity, unsupported tool versions, malformed records, and duplicate events.

## Initial Adapter Set

- Ghidra or rizin/radare2 export adapter: functions, symbols, strings, imports, xrefs, call graph.
- Trace JSONL importer: Frida, syscall, QEMU, generic call/return events.
- Crash importer: ASAN, UBSAN, Rust/Go/Python panic logs, stack clustering.
- Firmware tree adapter: binwalk-like directories, file inventory, embedded binary linkage.
- Later: tshark/pcap adapter and Volatility JSON adapter.

## TUI/CLI Affordances

- `revdeck import --plugin <id> <path>`
- Empty lab states tell the user which importer can populate the view.
- Command Deck exposes adapter commands with examples and permission summaries.
- Cockpit shows running/import failed/import degraded status chips.

## Test Strategy

- Fixture-driven adapter tests with golden object counts, edge counts, diagnostics, redaction flags, and deterministic digest.
- Malformed input fixtures.
- Rebased address fixtures.
- Duplicate event fixtures.

## Rollout Notes

Ship first-party proof plugins with the SDK preview. They are more valuable than an early public marketplace.
