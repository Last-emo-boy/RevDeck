# Subject Matter Expert Analysis

## Summary

RevDeck should specialize by making reverse-engineering evidence navigable across artifacts, not by competing with mature disassemblers, debuggers, fuzzers, firmware unpackers, packet analyzers, or memory-forensics suites. The domain value is a durable workspace where an analyst can connect a binary function, a firmware file, a trace event, a crash frame, a protocol message, a memory object, a diff, notes, and findings without losing provenance.

The SDK should therefore be adapter-first and evidence-first. First-party examples should prove that common real-world outputs can be imported cleanly: Ghidra/radare2/rizin exports, Frida/QEMU/syscall traces, ASAN/UBSAN/panic logs, binwalk extraction trees, tshark/pcap summaries, Volatility JSON, and generic JSONL evidence.

## Feature Notes

F-001 `plugin-manifest-and-capability-model`: Domain plugins need more than generic capability names. The manifest should declare artifact families (`binary`, `firmware_tree`, `trace`, `crash_log`, `pcap`, `memory_forensics`, `external_export`), supported formats, architecture assumptions, address-space model, symbol requirements, redaction behavior, and whether outputs are facts, heuristics, or suggestions. A Frida trace importer and an ASAN crash parser should not receive the same default permissions.

F-002 `stable-schema-and-object-graph-sdk`: The minimum useful domain object set should include Binary, Function, BasicBlock, InstructionRef, String, Import, File, FirmwareComponent, TraceRun, TraceEvent, SyscallEvent, MemoryAccess, CrashGroup, CrashInstance, StackFrame, InputSample, ProtocolMessage, ProtocolField, MemoryProcess, Module, Region, Handle, Socket, DiffItem, ScoreReason, and FindingEvidence. Every object should support confidence, source run, normalized address/range, and raw-source pointer.

F-003 `importer-and-adapter-sdk`: This is the most important SME feature. RevDeck should normalize external outputs before adding new native analyzers. Priority adapters: Ghidra function/string/import/callgraph export, radare2/rizin JSON, Frida call trace JSONL, QEMU/syscall trace, ASAN/UBSAN parser, Rust/Go/Python panic parser, binwalk directory manifest, tshark JSON, Volatility process/module/network output. Adapters should emit diagnostics when addresses, symbols, timestamps, or artifact hashes cannot be reconciled.

F-004 `specialized-lab-extension-points`: Labs should be thin domain lenses over the shared graph. Graph Lab should favor local neighborhoods and path queries, not whole-program graph rendering. Trace Lab needs timeline, call search, argument search, first-seen value, who-wrote address, and run diff. Diff Lab needs file, import, string, function, CFG-shape, and behavior deltas. Firmware Lab needs filesystem layout, init/web route mapping, component inventory, key/token candidates, and batch binary linkage. Crash Lab needs stack signature clustering, duplicate handling, input sample linkage, fixed/new/regressed states, and relation to functions/traces/diffs. Protocol Lab needs message lists, hex/field annotations, opcode clustering, length/checksum candidates, request-response pairing, and exporter drafts. Memory Lab should initially import Volatility-style process trees, modules, regions, handles, sockets, suspicious injections, and dumped binaries.

F-005 `scoring-rule-and-triage-pack-sdk`: Reverse-engineering scores must be explainable. Useful rule packs include dangerous imports, network-input-to-command sinks, auth/config strings, crypto/key material, parser complexity, crash top-frame frequency, newly introduced risky imports, protocol opcode hotspots, suspicious memory regions, and firmware web routes reaching binaries. Scores should expose evidence refs and confidence, not just labels like "high risk".

F-006 `plugin-execution-safety-and-permissions`: Responsible-use boundaries matter. Plugins should default to local-only, no network, no credential access, no unrestricted sample export, and bounded process execution. RevDeck should record when a plugin could expose secrets, run external tools, inspect memory dumps, or parse malware samples. The UI and reports should avoid framing output as exploit generation or bypass automation.

F-007 `developer-tooling-and-test-harness`: The SDK needs domain fixtures, not only schema unit tests. Include tiny ELF/PE/Mach-O samples, stripped binaries, trace JSONL, malformed traces, ASAN logs, panic logs, binwalk-like trees, small pcap/tshark JSON, Volatility JSON, and golden graph deltas. Test harnesses should validate deterministic object IDs, address normalization, deduplication, diagnostics, and no direct DB writes.

F-008 `plugin-driven-finding-and-report-workflow`: Plugins may propose draft findings such as "crash group reaches parser function" or "new firmware endpoint calls system-like import", but analyst confirmation must remain explicit. Findings should preserve the evidence chain across object types: firmware file -> string -> function -> trace event -> crash frame -> diff item -> analyst note.

## Highest-Value Initial Plugin Set

1. Ghidra export adapter for functions, symbols, strings, imports, xrefs, and call graph.
2. Frida/QEMU trace importer using RevDeck JSONL trace schema.
3. ASAN/UBSAN/panic crash importer with stack clustering.
4. binwalk firmware-tree adapter plus batch ELF linkage.
5. tshark/pcap protocol-message adapter.
6. Volatility JSON memory-forensics adapter.

These prove the SDK across static, dynamic, firmware, crash, protocol, and memory evidence while keeping RevDeck centered on navigation, triage, notes, findings, and reports.
