# F-006 Findings And Report Export

## Intent
Turn analysis into deliverable conclusions. Findings SHOULD include severity, status, summary, tags, and linked evidence.

## Scope
- Create/edit finding records.
- Link evidence objects.
- Export Markdown and JSON.
- Include object references and annotation context in reports.

## Acceptance Signals
- A finding can link to a function, string, import, note, or xref.
- Exported Markdown is readable.
- Exported JSON round-trips key fields.
- Missing evidence is visible before export.

## Dependencies
F-004, F-005.
