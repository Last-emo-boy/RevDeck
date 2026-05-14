# Slice: native lea r64 memory operands

## Goal

Decode general `lea r64, m` forms and represent frame-relative address taking distinctly from stack slot reads.

## Changes

- Added native decode support for `REX.W + 8D /r` `lea r64, m`.
- Added ModRM/SIB memory operand support for address calculations such as:
  - `lea rax,[rbp-0x10]`
  - `lea r9,[rsp+r10*4+0x20]`
- `lea` memory-style operands use `DataReference` role so address registers are read and the destination register is written.
- Stack slot metadata now labels `DataReference` operands as `address_reference` instead of `data_reference`.
- Added synthetic PE coverage so frame-relative `lea` records an address reference, not a stack slot read.

## Verification

- `cargo test -p revdeck-index native_decoder_decodes_lea_r64_memory_operands -- --nocapture`
- `cargo test -p revdeck-index synthetic_pe_function_metadata_marks_lea_stack_slots_as_address_references -- --nocapture`
- `cargo test -p revdeck-index native_indexer_tracks_lea_data_target_constants -- --nocapture`
- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- Native-only audit passed with no matches for external compatibility patterns.

## Result

`revdeck-index` now has 82 tests. The native analyzer distinguishes stack address-taking from stack memory reads while preserving `lea` constant propagation.
