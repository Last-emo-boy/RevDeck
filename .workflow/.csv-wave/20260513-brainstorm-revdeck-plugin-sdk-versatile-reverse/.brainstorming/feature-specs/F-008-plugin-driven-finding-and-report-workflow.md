# F-008 Plugin Driven Finding And Report Workflow

## Purpose

Allow plugins to propose findings, evidence chains, report fragments, and exports while preserving analyst authority over final conclusions.

## User Value

Analysts get faster report drafting from imported evidence, but final deliverables remain explicit, reviewable, and credible.

## Requirements

- Plugins MAY create suggestions or draft findings.
- Plugins MUST NOT silently create analyst-confirmed findings.
- Finding suggestions MUST include provider, confidence, evidence chain, source run, redaction flags, and review status.
- Reports MUST distinguish plugin-generated, edited, and analyst-confirmed sections.
- Exports SHOULD preserve provenance enough to reproduce or challenge each claim.

## SDK/Data Contracts

Suggested fields:

- `finding_origin`: `analyst`, `plugin_suggestion`, `imported`
- `suggestion_status`: `open`, `accepted`, `rejected`, `superseded`
- `evidence_chain`: ordered `EvidenceLink` list
- `report_fragment`: schema ID, provider, body, redaction flags, source run

## TUI/CLI Affordances

- Findings view separates suggestions, drafts, and confirmed findings.
- Inspector shows review actions for plugin suggestions.
- Command Deck exposes accept/reject/link/export workflows.
- Reports show provenance and redaction status.

## Test Strategy

- Plugin suggestions cannot appear as confirmed findings without explicit action.
- Evidence-chain order and provenance survive export.
- Redaction defaults are enforced.
- Rejected/superseded suggestions do not reappear after rerun unless materially changed.

## Rollout Notes

Defer until F-002, F-006, and F-007 are stable. It is high value but depends on trust and provenance.
