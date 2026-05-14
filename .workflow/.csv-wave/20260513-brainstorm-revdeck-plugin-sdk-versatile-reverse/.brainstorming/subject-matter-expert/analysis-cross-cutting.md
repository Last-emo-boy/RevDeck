# Subject Matter Expert Cross-Cutting Analysis

## Domain Decisions

Adapter-first should be the main SME decision. Reverse engineers already use specialized tools because each artifact family has deep edge cases. RevDeck should not reimplement Ghidra, Frida, binwalk, tshark, Volatility, or fuzzing infrastructure in the SDK cycle. It should provide stable ingestion contracts, evidence normalization, graph linkage, triage, and reportable provenance.

The common workflow should be:

1. Import or adapt an artifact.
2. Normalize objects and edges under one `analysis_run`.
3. Reconcile addresses, timestamps, hashes, symbols, and file paths.
4. Surface high-value queues and local graph neighborhoods.
5. Let the analyst add notes, tags, status, and confirmations.
6. Export findings with evidence chains and plugin provenance.

## Evidence Normalization Rules

All domain modules should keep raw-source pointers. For a pcap message this may be packet number, stream ID, timestamp, and byte range. For a crash it may be log path, line range, stack frame index, input sample hash, and sanitizer category. For memory it may be plugin name, Volatility table, PID, virtual address range, and dump hash. For firmware it may be extraction path, offset, filesystem path, archive layer, and file hash.

Address identity must be explicit. Static binary addresses, runtime module-relative addresses, firmware file offsets, crash frame PCs, trace PCs, memory virtual addresses, and protocol byte offsets are not interchangeable. Plugins should declare the address space they emit and provide rebasing metadata when possible.

Confidence should be first-class. Function boundaries from symbols, debug info, heuristics, external disassembly, and trace-only call targets should carry different confidence. Protocol fields inferred from statistics should not look the same as analyst-confirmed field annotations. Memory-injection labels from heuristics should remain suggestions until reviewed.

## Cross-Lab Workflows

Graph + Trace: A local call graph should be filterable to "observed in trace" and "not observed in trace". A source-to-sink path is more credible when there is a trace event sequence linking input, parser, and sink.

Trace + Crash: A crash instance should link to the last N trace events, syscall context, memory writes, and top-frame function. The lab should answer whether the crash happens before or after a sensitive branch, and whether it is reproducible across runs.

Firmware + Diff + Binary: Firmware analysis should connect changed files to changed binaries, changed functions, new imports, new web routes, and new strings. The useful question is not "what changed?" but "what changed near exposed input or sensitive behavior?"

Protocol + Trace + Binary: Protocol messages should link to `recv`, parser functions, opcode handlers, and response generation. Inferred fields should be usable as search filters for traces and crash inputs.

Memory + Binary + Findings: Memory artifacts should connect dumped modules to Binary Map, suspicious strings to Strings, sockets to Protocol Lab, process tree nodes to findings, and injected regions to score reasons.

Crash + Diff: Crash groups need state across versions: new, known, fixed, regressed, flaky, duplicate. A new crash in a changed parser function should rank above a repeated null dereference in an unrelated path.

## Edge Cases To Design For

Stripped binaries, packed sections, PIE/ASLR rebasing, missing symbols, overlapping functions, multiple architectures in one firmware, endian differences, thunk/import stubs, statically linked libraries, C++ mangling, tail calls, and external tool disagreement should all produce diagnostics instead of silent precision.

Trace imports may be partial, sampled, out of order, multi-threaded, clock-skewed, or missing return events. The Trace Lab should support "best effort timeline" and visibly mark incomplete call stacks.

Crash logs may have missing frames, optimized-out functions, inlined frames, sanitizer-specific wording, platform-specific paths, duplicate reports with slightly different stack depth, and input samples that cannot be stored for policy reasons.

Protocol samples may be encrypted, compressed, length-prefixed with endian ambiguity, multiplexed, fragmented, or stateful. RevDeck should help annotate hypotheses; it should not claim protocol truth from weak statistics.

Memory-forensics outputs are tool-version-sensitive and may include stale handles, terminated processes, incomplete regions, poisoned strings, or private data. Redaction and least privilege should be visible from the start.

Firmware trees may include symlinks, nested archives, duplicate files, generated files, proprietary formats, corrupted filesystems, vendor SDK blobs, and license-sensitive content. Hashing and path normalization are required before graph linkage.

## Responsible-Use Boundaries

RevDeck can support authorized vulnerability research, malware triage, firmware audit, crash analysis, and forensics. It should avoid product language and plugin examples that automate exploitation, credential theft, stealth, persistence, bypasses, or sample exfiltration. Adapters may import exploit-relevant evidence such as command sinks or memory corruption crashes, but the workflow should frame this as analysis, reproduction context, risk explanation, and remediation support.

Plugins should distinguish "secret candidate found" from "secret extracted". Reports should default to redacted values for credentials, private keys, tokens, packet payloads, and memory strings. Unredacted export should require analyst choice and be audited.

Network access, external process execution, and remote symbol/download services should be denied by default. When granted, the run record should state what was allowed, what files/artifacts were accessible, and whether any output was produced outside the project directory.

## Product And Engineering Implications

The first SDK release should make domain fixtures and golden graph deltas part of the public contract. A plugin author should be able to prove that a trace importer, crash parser, or firmware adapter emits stable objects, explainable diagnostics, and no unsupported writes without opening the TUI.

Specialized Labs should share command idioms: `find`, `open`, `xrefs`, `tag`, `note`, `status`, `finding link`, and local filters. Domain-specific commands should be additive: `trace first-seen`, `trace who-wrote`, `crash group`, `protocol field`, `firmware route`, `memory process`, and `diff changed-near`.

Custom plugin object types are tempting for domain speed, but RevDeck should start with core-owned object families plus typed metadata extensions. Recurring plugin shapes can graduate into stable schema migrations after they prove value across multiple adapters.

The strongest release narrative is: "Bring your existing reverse-engineering tools; RevDeck turns their output into a persistent evidence graph." That keeps the scope realistic and makes the SDK valuable before custom lenses or marketplaces exist.
