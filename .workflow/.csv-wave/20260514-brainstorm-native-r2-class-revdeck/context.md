# Native-Only RevDeck Brainstorm

Date: 2026-05-14
Mode: maestro-managed continuation

## Decision

RevDeck will benchmark against r2-class workflows, but it will not depend on external reverse-engineering tools or compatibility adapters as the product foundation.

The product direction is now native analyzer first:

- Native binary parsing and project model stay in RevDeck.
- Instruction, basic block, CFG, callgraph and xref recovery become first-class RevDeck facts.
- Plugin SDK remains a RevDeck extension surface, but the core analyzer must not require external CLIs.
- External compatibility packs are out of scope for the current roadmap.

## Current baseline

Current code already has:

- Native ELF/PE import through the Rust `object` crate.
- Artifact, section, symbol, import, string, function and xref persistence.
- Function Radar scoring.
- Three-pane TUI, Graph Lab, Command Deck and findings/report workflow.
- Plugin SDK preview and host-mediated ObjectBatch commit.

Current native analyzer gaps:

- No durable instruction model.
- No durable basic block model.
- No CFG edge schema.
- Function discovery is still symbol/entrypoint/heuristic oriented.
- Xrefs are mostly signal heuristics, not instruction-driven.
- Graph Lab cannot switch between CFG/callgraph/xref modes yet.

## Product thesis

RevDeck should become a complete terminal-native reverse-engineering product by owning the full evidence pipeline:

binary bytes -> native decode -> instructions -> blocks -> CFG/callgraph/xrefs -> triage -> notes/findings -> report.

The first mature-product milestone is not a full decompiler. The first high-leverage milestone is a durable native CFG foundation that all later analyzer features can build on.

