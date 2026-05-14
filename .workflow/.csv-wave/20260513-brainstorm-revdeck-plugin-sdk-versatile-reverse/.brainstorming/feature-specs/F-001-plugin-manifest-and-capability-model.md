# F-001 Plugin Manifest And Capability Model

## Purpose

Define the stable entry point for every RevDeck plugin. The manifest is the trust contract, compatibility boundary, capability declaration, permission request, UI registration source, and test target.

## User Value

Analysts can inspect what a plugin does before it runs: what it reads, what it writes, which commands it adds, which object types it supports, and whether it is stable or experimental.

## Requirements

- RevDeck MUST validate `revdeck-plugin.toml` before install and before every run.
- The manifest MUST include `id`, `name`, `version`, `sdk_version`, `revdeck_compat`, `capabilities`, `permissions`, `inputs`, `outputs`, `config_schema`, and `provenance`.
- Capabilities SHOULD start with `importer`, `adapter`, `analyzer`, `scorer`, `exporter`, `rule_pack`, `lens`, and `action`.
- `lens` and `action` SHOULD be experimental until host-owned UI slots are stable.
- Plugins MUST NOT request direct SQLite access as a supported capability.

## SDK/Data Contracts

Example manifest sections:

```toml
[plugin]
id = "com.revdeck.examples.ghidra-export"
version = "0.1.0"
sdk_version = "0.1"
revdeck_compat = ">=0.1,<0.3"

[[capabilities]]
kind = "adapter"
inputs = ["ghidra-json"]
outputs = ["object_batch"]

[permissions]
artifact_read = ["binary", "external_export"]
project_write = ["objects", "edges", "attributes", "diagnostics"]
network = false
process_spawn = false

[ui]
commands = ["ghidra.import"]
inspector_cards = ["ghidra.provenance"]
```

## TUI/CLI Affordances

- `revdeck plugin validate <path>` validates manifests.
- `revdeck plugin inspect <path>` prints capabilities, permissions, compatibility, commands, and provenance behavior.
- Command Deck shows plugin commands, examples, required permissions, and blocked states.
- Cockpit can show plugin state chips such as `RUN`, `WARN`, `BLOCK`, or `EXP`.

## Test Strategy

- Golden valid manifests for each capability.
- Negative fixtures for bad semver, unknown permissions, duplicate IDs, unsupported SDK ranges, missing provenance, and invalid config schema.
- Install-time and run-time validation must produce the same normalized manifest digest.

## Rollout Notes

Implement this before plugin execution. Treat manifest validation as the first public SDK contract.
