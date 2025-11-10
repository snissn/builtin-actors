**Implement RIP-7212 (P256VERIFY) Precompile**

- Scope: Entire repository
- Goal: Add a new EVM precompile at address `0x0000000000000000000000000000000000000100` that verifies secp256r1 (P‑256) ECDSA signatures per RIP‑7212. Follow code structure and testing rigor similar to commit 747a3ede8198a22545127a64d8ced4898b81c712 in filecoin-project/builtin-actors (large precompile feature diff with modular code + unit and integration tests).

**Spec Highlights (RIP‑7212)**
- Address: `0x0100` (20‑byte address with the last two bytes `0x01 0x00`).
- Input (exactly 160 bytes, big‑endian):
  - 32 bytes: `hash` (message digest)
  - 32 bytes: `r` (signature component)
  - 32 bytes: `s` (signature component)
  - 32 bytes: `x` (pubkey X coordinate)
  - 32 bytes: `y` (pubkey Y coordinate)
- Output:
  - On success: 32‑byte word encoding integer `1`.
  - On failure: empty output.
- Required checks:
  - `r` and `s` in `(0, n)` where `n` is P‑256 subgroup order.
  - `x` and `y` in `[0, p)` where `p` is field modulus; `(0,0)` MUST be rejected; public key MUST be on the curve.
- Gas: Fixed 3450 (document; interpreter here does not meter per‑precompile currently).

**Design Overview**
- Add a new precompile implementation for RIP‑7212 in `actors/evm` mirroring the organization of other precompiles (see BLS12‑381 modules added in the model diff):
  - Add a `p256` module under `actors/evm/src/interpreter/precompiles/` with a single entrypoint function `p256_verify<RT: Runtime>(..., input, ...) -> PrecompileResult`.
  - Update precompile dispatch to route `0x…0100` to `p256_verify`.
  - Keep the implementation pure (no syscalls, no side effects) and allow STATICCALL.

**Addressing Model and Routing**
- Current dispatch only indexes by the last byte for EVM precompiles and rejects `index == 0`, which would exclude `0x…0100`.
- Update both of the following to support RIP precompile addresses ≥ 0x0100 without breaking existing 0x01…0x11 mapping:
  - `actors/evm/src/interpreter/precompiles/mod.rs`:
    - Extend `lookup_precompile(...)` to special‑case `0x…0100` and call `p256_verify`.
    - Do not disturb the existing `EVM_PRECOMPILES` table for 0x01…0x11.
  - `actors/evm/shared/src/address.rs` and `actors/evm/src/interpreter/precompiles/mod.rs`:
    - Update `is_reserved_precompile_address` to also return true when the prefix is `0x00`, bytes 1..18 are 0, and the last two bytes form a big‑endian index ≥ `0x0001` (so `0x…0100` is recognized). Preserve compatibility with existing 1‑byte index behavior.
    - Add unit tests covering `0x…0100` recognition without breaking existing addresses.

**Implementation Steps**
1) Add dependencies (pure Rust; no extra toolchain needed):
   - `actors/evm/Cargo.toml`:
     - Add `p256 = { version = "0.13", default-features = false }`
     - Add `ecdsa = { version = "0.16", default-features = false }`
     - If needed for integer parsing: `subtle = "2"` (prefer avoiding unless strictly necessary).

2) Implement precompile logic:
   - File: `actors/evm/src/interpreter/precompiles/p256.rs`
   - Public function: `pub fn p256_verify<RT: Runtime>(_: &mut System<RT>, input: &[u8], _: PrecompileContext) -> PrecompileResult`.
   - Behavior:
     - Require `input.len() == 160`, else `Err(PrecompileError::IncorrectInputSize)`.
     - Split input into `hash`, `r`, `s`, `x`, `y` (all big‑endian 32‑byte slices).
     - Construct verifying key from `(x,y)` with `p256::AffinePoint::from_xy(FieldElement::from_bytes(x), FieldElement::from_bytes(y))` and reject if not on curve or if `(x,y) == (0,0)`.
     - Parse `r` and `s` as nonzero scalars strictly in `(0, n)`. Return `InvalidInput` if out of range.
     - Construct an `ecdsa::Signature` from `(r,s)`; verify `verify_prehash` over `hash` using the verifying key.
     - On success, return 32‑byte big‑endian `1`. On failure, return `Ok(vec![])`.
   - No malleability check beyond NIST spec (as per RIP‑7212). Wrapper libraries can add it.

3) Register the precompile:
   - File: `actors/evm/src/interpreter/precompiles/mod.rs`:
     - Add `mod p256;` at the top alongside other modules.
     - `use p256::p256_verify;`.
     - In `lookup_precompile(addr)`, before the legacy table dispatch, detect `addr == 0x…0100` and return `Some(p256_verify::<RT>)`.
     - Keep `EVM_PRECOMPILES` array unchanged for backward compatibility.

4) Recognize the `0x…0100` address as reserved:
   - File: `actors/evm/src/interpreter/precompiles/mod.rs`:
     - Update `is_reserved_precompile_address` to treat both 1‑byte `(last != 0)` and 2‑byte `(last == 0 && second_last != 0)` EVM indices as reserved when prefix is `0x00` and middle bytes are zero.
   - File: `actors/evm/shared/src/address.rs`:
     - If this helper is relied upon elsewhere, mirror the same behavior in `EthAddress::is_precompile()`; otherwise, leave it and rely on the interpreter’s `is_reserved_precompile_address`.
   - Add tests proving `0x…0100` is reserved and routed, without changing existing 0x01..0x11 behavior.

5) Unit tests (module‑local):
   - File: `actors/evm/src/interpreter/precompiles/p256.rs`
   - Add tests with `MockRuntime` similar in structure to the BLS12 tests in the model diff:
     - `test_p256_verify_valid_signature_returns_one` — valid (hash, r, s, x, y) should return `0x…0001`.
     - `test_p256_verify_wrong_hash_returns_empty`.
     - `test_p256_verify_invalid_r_or_s_range_returns_invalid_input` (r=0, s=0, r>=n, s>=n).
     - `test_p256_verify_invalid_pubkey_point` ((0,0), off‑curve points, x>=p, y>=p).
     - `test_p256_verify_input_length_variants` (short/long inputs) → `IncorrectInputSize`.
     - `test_is_reserved_precompile_address_0x0100` (using interpreter helper) returns true.

6) EVM‑level tests (assembly harness), following the model diff style:
   - File: `actors/evm/tests/precompile.rs` (or a new `p256_precompile.rs` next to it)
   - Reuse the existing test runner harness to:
     - CALL/STATICCALL `0x…0100` with a valid 160‑byte payload → success, 32‑byte `1` output; check no reverts.
     - Invalid payloads → success with empty output (interpreter encodes precompile failure as status=0 revert; assert via harness expected behavior, mirroring other precompile tests).
     - Try CALL with value and confirm value transfer happens post‑success per `call_precompile` semantics (value transfer happens after a successful precompile execution).

7) Integration tests (optional but recommended when feasible):
   - Add a small scenario to `test_vm/tests/suite/evm_test.rs` to deploy a contract that calls `0x…0100` and observes outputs for valid/invalid cases.

8) Docs and activation:
   - No NV/bundle gating for this repo; always enable `0x…0100` dispatch (mirrors how EIP‑7702 was de‑gated in this codebase).
   - Keep `rip-7212.md` as the authoritative spec reference; no need to edit it.

9) CI & formatting:
   - Run `cargo fmt --all` and fix clippy warnings if any.
   - No extra toolchain steps are needed (unlike BLS `blst` in the model diff), since `p256` is pure Rust.

**Testing Matrix**
- Unit tests (module):
  - Valid vector → returns 32‑byte `1`.
  - Wrong hash → empty output.
  - r/s out of range → `InvalidInput`.
  - Off‑curve pubkey or (0,0) → `InvalidInput`.
  - x or y ≥ p → `InvalidInput`.
  - Input size != 160 → `IncorrectInputSize`.
  - Recognize address `0x…0100` as reserved.

- EVM tests:
  - CALL and STATICCALL with valid input → success and 32‑byte `1` return.
  - CALL with value on success → value transfer occurs (post‑success semantics).
  - Invalid input (wrong length, malformed coordinates) → reverted/empty per precompile failure path.
  - Ensure `Precompiles::<MockRuntime>::is_precompile` returns true for `0x…0100` and false for `0x…0000`.

- Integration (optional):
  - End‑to‑end through TestVM contract calling `0x…0100` with both valid and invalid vectors.

**Code References to Modify or Add**
- Add new precompile module:
  - `actors/evm/src/interpreter/precompiles/p256.rs`

- Register and route precompile:
  - `actors/evm/src/interpreter/precompiles/mod.rs:1` (add `mod p256;`)
  - `actors/evm/src/interpreter/precompiles/mod.rs` (extend `lookup_precompile` to recognize `0x…0100`)
  - `actors/evm/src/interpreter/precompiles/mod.rs` (broaden `is_reserved_precompile_address` to include 2‑byte index form)

- Address helper (optional, keep consistent):
  - `actors/evm/shared/src/address.rs:94` (consider aligning `EthAddress::is_precompile` with 2‑byte index support; otherwise rely on interpreter’s function during dispatch)

- Tests:
  - `actors/evm/src/interpreter/precompiles/p256.rs` (unit tests with `MockRuntime`)
  - `actors/evm/tests/precompile.rs` or `actors/evm/tests/p256_precompile.rs` (EVM‑level harness tests)
  - `test_vm/tests/suite/evm_test.rs` (optional integration scenario)

**Style and Structure (mirror model diff)**
- Keep precompile code self‑contained with clear doc comments at top describing the spec linkage (RIP‑7212), inputs/outputs, and safety notes.
- Avoid unwraps on external input; map parse/curve errors to `PrecompileError::{InvalidInput, EcErr, IncorrectInputSize}` appropriately.
- Favor small helpers for parsing, range checks, and encoding the 32‑byte `1`.
- Module‑local tests with explicit vectors; prefer deterministic vectors over random.

**How to Run**
- Build: `cargo build --workspace`
- Unit tests: `cargo test -p fil_actor_evm -- --nocapture`
- Full suite: `cargo test --workspace -- --nocapture`

**Notes on Gas**
- RIP‑7212 specifies 3450 gas. The current interpreter passes gas into precompiles via `PrecompileContext` but does not charge per‑precompile in this layer. Document 3450 in comments and ensure tests do not assert gas metering. If a gas‑metering layer is added elsewhere in the future, map `0x…0100` → 3450.

**Non‑Goals**
- Do not add malleability checks beyond NIST spec (apps can add in wrappers).
- Do not change or remove existing precompiles or their addresses.
- Do not introduce C dependencies or toolchain changes (keep `p256` pure Rust).

