# 20260514 execute native lea destination registers

## Intent

Continue the native analyzer path by making RIP-relative data-reference instructions write the actual decoded destination register.

## Scope

- RIP-relative `lea` and `mov` now decode the ModRM `reg` field for destination registers.
- REX.R destination extension is supported for 64-bit RIP-relative forms, e.g. `lea r9,[rip+disp32]`.
- 32-bit RIP-relative forms use 32-bit destination register names, e.g. `mov edx,[rip+disp32]`.
- Existing data targets and string xrefs are preserved.
- Register access summaries now receive precise writes such as `rcx`, `r9`, and `edx` instead of a placeholder register.

## Constraints

- This slice covers RIP-relative `mod=00 rm=101` forms only.
- It does not add new non-RIP ModRM addressing modes; those are already handled by the generic ModRM/SIB decoder path.
- No external reverse engineering tools or compatibility adapters are used.

## Evidence

- Focused tests passed:
  - `cargo test -p revdeck-index native_decoder_tracks_rip_relative_destination_registers`
  - `cargo test -p revdeck-index native_cfg_collection_creates_rip_relative_string_xrefs`

## Files

- `crates/revdeck-index/src/native_decode.rs`
- `crates/revdeck-index/src/lib.rs`
