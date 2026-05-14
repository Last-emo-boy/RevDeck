# Plan Report -- M2A TUI Power Navigation And M2B Adapter Commit Pipeline

Status: planned

## Summary

This plan advances both M2A and M2B without over-scoping into full Labs, marketplace, or arbitrary process sandboxing.

M2A implements a visible TUI power slice:

- Graph Lab as a first-class workspace lens.
- Minimal Command Deck overlay.
- Breadcrumb/status-chip polish in the command/status area.

M2B implements a useful plugin SDK slice:

- Host-mediated ObjectBatch commit for objects and edges.
- Plugin run audit plus contribution counts.
- CLI `plugin commit` and deterministic `plugin run --commit` fixture replay.

## Task Count

6 tasks across 3 waves. See `.workflow/scratch/20260513-plan-m2a-m2b-power-navigation-adapter-commit/plan.json`.
