# Synthesis Specification

RevDeck should evolve into an extensible reverse-engineering workspace by making plugins first-class, audited producers of normalized evidence. The SDK should focus on local, deterministic, host-mediated plugins before marketplace distribution or broad custom UI surfaces.

The recommended sequence is:

1. Define `revdeck-plugin.toml`, capability taxonomy, permission scopes, and manifest validation.
2. Publish stable schemas and an ObjectBatch contract for graph deltas, typed attributes, datasets, diagnostics, score reasons, and draft findings.
3. Implement a process-based plugin host that gives plugins approved inputs and commits only validated outputs.
4. Ship `revdeck plugin test` with fixture replay, deterministic digest checks, sandbox denial tests, and manifest/schema validation.
5. Prove the SDK with adapter plugins for static exports, trace JSONL, crash logs, firmware trees, and eventually protocol/memory outputs.
6. Add specialized lab lenses as declarative views over the shared graph, not isolated mini-apps.

This path keeps the current Binary Triage loop intact while opening a controlled route to Graph Lab, Trace Lab, Diff Lab, Firmware Lab, Crash Lab, Protocol Lab, Memory Lab, scoring packs, and report extensions.
