# Phase 2 Spec Review: Private Balance Proofs

**Reviewer:** Claude Opus 4.6 (automated spec review)
**Date:** 2026-02-06
**Status:** BLOCKING -- findings must be resolved before Phase 2 implementation begins
**Files reviewed:**
- `SPEC.md` (full, focusing on Phase 2 sections and data structures)
- `REQUIREMENTS.md`
- `PLAN.md`
- `host/src/merkle.rs` (existing commitment implementation)
- `host/src/lib.rs` (tests)
- `host/src/main.rs` (Phase 1 host program)
- `methods/guest/src/membership.rs` (Phase 1 circuit)
- `contracts/src/MembershipVerifier.sol` (Phase 1 contract)

---

## Executive Summary

The Phase 2 spec for private balance proofs is structurally sound. The commitment scheme `SHA256(pubkey || balance || salt)` is appropriate for a PoC: it is computationally binding under SHA-256 collision resistance, computationally hiding due to the 256-bit salt, and the fixed-field-length encoding eliminates preimage ambiguity. The range proof approach (simple comparison inside the zkVM rather than a dedicated range proof circuit) is correct for RISC Zero and avoids unnecessary complexity.

However, the review identified **3 high-priority issues**, **5 medium-priority gaps**, and **4 low-priority observations** that should be addressed before implementation. The most critical finding is the absence of a Phase 2 contract specification in `SPEC.md` -- the balance proof verification contract is entirely missing between Phase 1's `MembershipVerifier` and Phase 3's `TransferVerifier`.

---

## 1. Commitment Scheme Analysis: SHA256(pubkey || balance || salt)

### 1.1 Binding Property

**Verdict: SOUND**

The commitment is computationally binding under standard SHA-256 collision resistance assumptions. Finding two distinct tuples `(pubkey_1, balance_1, salt_1)` and `(pubkey_2, balance_2, salt_2)` that hash to the same 32-byte commitment would require finding a SHA-256 collision, which is computationally infeasible (O(2^128) work for a birthday attack on 256-bit output).

No issues here for a PoC. In a production system, this would still be adequate -- SHA-256's collision resistance is well-established and not under credible threat.

### 1.2 Hiding Property

**Verdict: SOUND with one observation**

The 256-bit random salt ensures computational hiding. Even if an attacker knows the pubkey and can guess possible balance values (the u64 space is only 2^64, and real balances are much smaller), they cannot verify their guess without knowing the salt. The salt provides 2^256 possible preimages for any given (pubkey, balance) pair, making brute-force infeasible.

**Observation:** The hiding is computational, not information-theoretic. This is inherent to hash-based commitments and is acceptable. Pedersen commitments would provide information-theoretic hiding, but they are not necessary for this PoC and would add significant complexity (elliptic curve operations inside RISC Zero, which lacks hardware acceleration for those).

### 1.3 Fixed-Field-Length Encoding (72-byte preimage)

**Verdict: SOUND**

The preimage structure is:
```
[pubkey: 32 bytes] [balance: 8 bytes LE] [salt: 32 bytes]
= 72 bytes total, fixed-length
```

This is safe against length-extension and reinterpretation attacks because:

1. **No length ambiguity.** All three fields have fixed, known sizes. There is no way to shift byte boundaries to reinterpret `(pubkey_A, balance_A, salt_A)` as `(pubkey_B, balance_B, salt_B)` while preserving the 72-byte total. The pubkey is always bytes 0-31, balance is always bytes 32-39, and salt is always bytes 40-71.

2. **No variable-length encoding.** Unlike schemes that use variable-length fields or length prefixes, there is no ambiguity about where one field ends and another begins.

3. **Consistent endianness.** The spec explicitly states little-endian for the u64 balance, and the implementation in `merkle.rs` uses `balance.to_le_bytes()`, which matches. The spec and implementation are consistent.

**One subtlety worth documenting:** SHA-256 itself uses Merkle-Damgard construction and is theoretically vulnerable to length-extension attacks. However, this is irrelevant here because the commitment is not used as a MAC -- the attacker gains nothing from being able to compute `SHA256(pubkey || balance || salt || attacker_suffix)` since that is not a valid 72-byte commitment input. The fixed input length neutralizes length-extension concerns.

### 1.4 Comparison to Alternatives

| Scheme | Binding | Hiding | RISC Zero Performance | Complexity | Verdict for PoC |
|--------|---------|--------|----------------------|------------|-----------------|
| SHA-256 (current) | Computational | Computational (with salt) | Excellent (HW accel) | Low | Best choice |
| Pedersen commitment | Computational (DL) | Information-theoretic | Poor (EC ops in zkVM) | High | Overkill for PoC |
| Poseidon hash | Computational | Computational (with salt) | Good (ZK-friendly) | Medium | Better for SNARK systems, not needed for RISC Zero |
| MiMC | Computational | Computational (with salt) | Good | Medium | Same as Poseidon |

**Recommendation:** Keep SHA-256. It is the correct choice for RISC Zero due to hardware acceleration, and provides adequate security properties for this PoC.

---

## 2. Range Proof Approach

### 2.1 Circuit Design

**Verdict: SOUND**

The spec's approach is not a traditional "range proof" in the Bulletproofs/Sigma-protocol sense. Instead, it leverages RISC Zero's general-purpose zkVM to perform a simple comparison:

```rust
assert!(balance >= required_amount);
```

This is correct and arguably the main advantage of using a zkVM like RISC Zero over circuit-specific proving systems. The entire balance proof circuit (SPEC.md lines 245-267) does three things:

1. Recomputes the leaf commitment from `(pubkey, balance, salt)`.
2. Verifies Merkle membership of that commitment.
3. Asserts `balance >= required_amount`.

This is sound because the zkVM executes arbitrary Rust, and the assertion is enforced as a constraint -- if the assertion fails, no valid proof can be generated.

### 2.2 Balance Representation and Overflow

**Verdict: REQUIRES CLARIFICATION (Medium priority)**

The balance is represented as `u64`. Several edge cases need to be documented or handled:

- **Zero balance:** A balance of 0 is a valid state. The circuit correctly handles `0 >= 0` (trivially true) and `0 >= 1` (assertion fails, no proof generated). However, the spec does not discuss whether zero-balance accounts should remain in the Merkle tree or be pruned. This matters for tree management in the operator database.

- **Maximum balance (u64::MAX = 18,446,744,073,709,551,615):** The spec does not define an upper bound. In Phase 3 (transfers), `recipient_balance + amount` could overflow u64. The Phase 3 circuit pseudocode on SPEC.md line 355 performs:
  ```rust
  let new_recipient_balance = recipient_balance + amount;
  ```
  In Rust, this will **panic in debug mode** and **wrap in release mode**. The circuit MUST use checked arithmetic or the spec must mandate that the guest is compiled in debug mode. This is a latent bug that will manifest in Phase 3 but should be caught now.

- **required_amount = 0:** The circuit will always succeed for any account in the tree. The spec should clarify whether this is an allowed query or if `required_amount > 0` should be enforced.

### 2.3 What the Proof Actually Proves

The Phase 2 proof establishes:

> "There exists an account in the committed state (identified by merkle_root) whose balance is at least required_amount."

It does NOT prove:
- Who owns that account (pubkey is private).
- What the actual balance is (only that it meets the threshold).
- That the prover is the account owner (no secret key is involved in Phase 2).

**Gap (High priority):** Phase 2 has no authentication. Anyone who obtains the Merkle proof data (pubkey, balance, salt, path) can generate a valid balance proof for that account. The spec should explicitly document this limitation. In Phase 3, authentication is provided via the secret key / nullifier scheme, but Phase 2 lacks this entirely.

This matters because if the operator shares Merkle proof data with a user (as shown in the Phase 1 flow diagram, step 4), that user could generate proofs on behalf of the account owner. The spec should clarify the trust model for Phase 2: either (a) the operator only shares proof data with the authenticated account owner, or (b) Phase 2 proofs are not attributable to a specific user by design.

---

## 3. Spec Gaps

### 3.1 Missing Phase 2 Contract (HIGH PRIORITY)

The spec defines contracts for Phase 1 (`MembershipVerifier`, lines 199-221), Phase 3 (`TransferVerifier`, lines 385-417), and Phase 4 (`ValidiumBridge`, lines 469-509). **There is no contract for Phase 2.**

The Phase 2 section (lines 225-273) has a circuit definition but no corresponding Solidity contract. The spec needs a `BalanceVerifier` contract that:
- Stores the accounts root (or reuses the allowlist root, which needs to be clarified).
- Accepts a seal, journal root, and required_amount.
- Verifies the proof via the RISC Zero verifier.
- Emits an event on successful verification.

This is the most critical gap for Phase 2 implementation.

### 3.2 Missing Operator Database Schema (MEDIUM PRIORITY)

FR2.1 requires "Operator can maintain account balances off-chain (SQLite)." The `Cargo.toml` includes `rusqlite` as a dependency. `PLAN.md` shows a sketch of the SQLite integration pattern. But neither the spec nor the plan defines the actual schema.

Phase 2 implementation needs at minimum:
```sql
CREATE TABLE accounts (
    id INTEGER PRIMARY KEY,
    pubkey BLOB NOT NULL,        -- 32 bytes
    balance INTEGER NOT NULL,    -- u64
    salt BLOB NOT NULL,          -- 32 bytes
    leaf_index INTEGER NOT NULL, -- position in Merkle tree
    UNIQUE(pubkey)
);
```

The spec should define:
- Table structure and column types.
- Whether `leaf_index` is stable or reassigned on updates.
- How the operator handles account creation vs. updates.
- Whether historical state is preserved or overwritten.

### 3.3 State Root Transition: Phase 1 to Phase 2 (MEDIUM PRIORITY)

Phase 1 uses an "allowlist root" where leaves are arbitrary 32-byte values (in the current implementation, `SHA256(pubkey)` per PLAN.md line 72, though SPEC.md is ambiguous -- the Phase 1 circuit takes a generic `leaf: [u8; 32]`).

Phase 2 uses an "accounts root" where leaves are `SHA256(pubkey || balance || salt)`.

The spec does not address:
- Are these the same tree or different trees?
- Is there a migration path from Phase 1's allowlist root to Phase 2's accounts root?
- Does the on-chain contract need to store both roots?
- Can Phase 1 membership proofs coexist with Phase 2 balance proofs?

**Recommendation:** The spec should explicitly state that Phase 2 introduces a new tree with a different leaf structure. Phase 1's `MembershipVerifier` contract would be deployed separately from Phase 2's contract, or the spec should describe how the contract evolves.

### 3.4 Nullifier Scope in Phase 2 (MEDIUM PRIORITY)

Phase 1's `MembershipVerifier.sol` includes a `usedNullifiers` mapping (line 20 of the contract), but the Phase 1 circuit does not produce a nullifier and FR1.5 marks it as optional. Phase 2's circuit also does not produce a nullifier.

The spec should clarify: can a Phase 2 balance proof be replayed? If the state root does not change between proofs, the same proof remains valid. This may be intentional (a balance proof is a read-only attestation, not a state-changing action), but it should be explicitly documented.

### 3.5 Salt Rotation Policy (MEDIUM PRIORITY)

The spec does not define when or how salts are rotated. The salt serves two purposes:
1. Hiding the balance in the commitment.
2. In Phase 3, ensuring new commitments differ from old ones (SPEC.md lines 323-324 show `new_sender_salt` and `new_recipient_salt` as separate private inputs).

For Phase 2, if the same salt is reused across multiple tree states, an observer could detect that a specific leaf has not changed (same commitment = same account with same balance). The spec should document whether salt rotation is:
- Required on every state update.
- Recommended but not enforced.
- Irrelevant for Phase 2 (since balance proofs are read-only).

### 3.6 Journal Encoding Mismatch Risk (LOW PRIORITY)

The Phase 1 guest uses `risc0_zkvm::guest::env::commit(&expected_root)` which serializes via serde/bincode. The Solidity contract uses `abi.encodePacked(journalRoot)` and then `sha256(journal)`. These two encoding schemes must produce identical byte sequences.

For a `[u8; 32]`, bincode serialization produces the raw 32 bytes (no length prefix), and `abi.encodePacked(bytes32)` also produces raw 32 bytes. So they happen to match for Phase 1.

For Phase 2, the journal would contain `(merkle_root: [u8; 32], required_amount: u64)`. The encoding must be carefully matched:
- Rust side: `env::commit(&root); env::commit(&required_amount);` -- bincode encodes u64 as 8 bytes little-endian.
- Solidity side: `abi.encodePacked(root, required_amount)` -- encodes uint64 as 8 bytes big-endian (per ABI spec, `encodePacked` for uint types uses big-endian).

**This will cause a mismatch.** The Phase 2 contract must account for the endianness difference, either by:
- Using `abi.encodePacked(root, swapEndian(required_amount))` on the Solidity side.
- Having the guest commit bytes explicitly in big-endian order.
- Using a different serialization approach (e.g., committing raw bytes).

This is a known class of bugs in RISC Zero + Solidity integrations and should be explicitly addressed in the spec.

---

## 4. Cross-Phase Consistency

### 4.1 Phase 1 to Phase 2 Circuit Evolution

**Verdict: CLEAN extension, no breaking changes**

Phase 2's balance proof circuit (SPEC.md lines 245-267) is a strict superset of Phase 1's membership circuit:
1. It reconstructs the leaf from `(pubkey, balance, salt)` -- new in Phase 2.
2. It calls `verify_membership(leaf, path, indices, expected_root)` -- reuses Phase 1 logic.
3. It asserts `balance >= required_amount` -- new in Phase 2.

The existing `verify_membership` function in `host/src/merkle.rs` (lines 125-145) and the guest circuit logic in `methods/guest/src/membership.rs` can be reused directly. No breaking changes to Phase 1 structures.

### 4.2 Phase 2 to Phase 3 Forward Compatibility

The Phase 2 commitment structure `SHA256(pubkey || balance || salt)` is exactly what Phase 3 uses for leaf computation (SPEC.md lines 333-336, 357-361). The 72-byte preimage format is consistent across phases. No forward compatibility issues.

### 4.3 Key Derivation Consistency

Phase 2 does not involve secret keys -- the pubkey is a direct private input. Phase 3 introduces `sender_sk` and derives pubkey via `derive_pubkey(sender_sk)`, which SPEC.md's Security Model (line 545) defines as `pubkey = sha256(secret_key)`.

This is consistent. Phase 2 accounts created with a given pubkey will be usable in Phase 3 as long as the user retains the corresponding secret key. The spec should note this forward dependency: Phase 2 accounts MUST be created with pubkeys that have a known corresponding secret key, even though Phase 2 itself does not use secret keys.

### 4.4 Merkle Tree Implementation

The existing `MerkleTree` in `host/src/merkle.rs` uses:
- Fixed depth (configurable, default 20).
- SHA-256 for internal nodes: `hash_pair(left, right)`.
- Zero-padding for empty leaves: `[0u8; 32]`.

This is fully compatible with Phase 2. The `account_commitment` function (lines 149-155) already implements the Phase 2 commitment scheme correctly. The implementation matches the spec.

---

## 5. Recommendations

### High Priority (must fix before Phase 2 implementation)

| # | Finding | Recommendation |
|---|---------|---------------|
| H1 | No Phase 2 contract in SPEC.md | Add a `BalanceVerifier` contract section with Solidity pseudocode. Should verify seal against IMAGE_ID, check journal contains expected root and required_amount, and emit a `BalanceProofVerified(bytes32 root, uint64 amount)` event. |
| H2 | Phase 2 balance proof has no authentication | Document explicitly that Phase 2 proofs are unauthenticated attestations. Anyone with the account data can prove balance sufficiency. Add a note that authentication is deferred to Phase 3 (secret key + nullifier). If authentication is needed in Phase 2, add a `secret_key` private input and pubkey commitment to the circuit. |
| H3 | Journal encoding endianness mismatch (Rust LE vs Solidity BE) | Add a spec section on journal encoding conventions. Either standardize on big-endian for all journal values, or document the byte-swapping required on the Solidity side. Include a worked example showing the exact byte layout. |

### Medium Priority (should fix before Phase 2 implementation)

| # | Finding | Recommendation |
|---|---------|---------------|
| M1 | No operator database schema defined | Add a database schema section to SPEC.md covering the `accounts` table, column types, constraints, and basic CRUD operations for the operator. |
| M2 | Phase 1 to Phase 2 tree transition undefined | Clarify whether Phase 2 uses a new tree or extends Phase 1's tree. Define the leaf format for each phase and whether contracts are separate or unified. |
| M3 | u64 overflow risk in Phase 3 `recipient_balance + amount` | Add a spec requirement that all arithmetic in circuits MUST use checked operations. Document the valid balance range. This is a Phase 3 concern but the data types are established in Phase 2. |
| M4 | Salt rotation policy undefined | Document whether salts must change on state updates and when salt rotation is required vs. optional. |
| M5 | Zero-balance and max-balance edge cases undocumented | Specify behavior for `balance = 0` (should the account remain in the tree?), `required_amount = 0` (always-true proof, is this allowed?), and `balance = u64::MAX` (overflow guard). |

### Low Priority (nice to have, can be addressed during implementation)

| # | Finding | Recommendation |
|---|---------|---------------|
| L1 | Nullifier design uses static domain separator | The nullifier `SHA256(sk || "nullifier_domain")` is the same for all transfers from the same account. Consider making the domain separator include the phase or operation type for future extensibility. This is primarily a Phase 3 concern. |
| L2 | Empty leaf `[0u8; 32]` is a valid SHA-256 preimage | An attacker could construct a commitment `SHA256(zero_pubkey || zero_balance || zero_salt)` that matches an empty leaf. This is extremely unlikely (SHA-256 collision) but worth noting. In practice, this is not exploitable because the empty leaf hash is `SHA256([0;32] || [0;8] || [0;32])` which is NOT `[0;32]` -- the padding leaves are `[0;32]` directly, not hashed commitments. So there is no actual issue, but documenting this explicitly would prevent future confusion. |
| L3 | Phase 1 test uses `keccak256` for root generation | `MembershipVerifier.t.sol` line 17 uses `keccak256("test-allowlist-root")` to generate a test root. This is fine for testing (the root value is arbitrary), but noting it here in case anyone confuses the test hash with the protocol hash (SHA-256). |
| L4 | `IMAGE_ID` is `bytes32(0)` placeholder | The Phase 1 contract has `IMAGE_ID = bytes32(0)`. The Phase 2 contract will need its own IMAGE_ID. The spec should note that each phase's circuit has a distinct IMAGE_ID and that placeholder values must be replaced before deployment. |

---

## 6. Implementation Readiness Checklist

Before Phase 2 implementation can begin, the following spec updates are needed:

- [ ] **H1:** Add `BalanceVerifier` contract specification to SPEC.md
- [ ] **H2:** Document authentication model for Phase 2 balance proofs
- [ ] **H3:** Define journal encoding convention (endianness)
- [ ] **M1:** Define operator database schema
- [ ] **M2:** Clarify Phase 1 to Phase 2 tree relationship

Once these are resolved, the existing codebase provides a solid foundation:
- `host/src/merkle.rs` -- `account_commitment()` already implements the Phase 2 commitment correctly.
- `host/src/merkle.rs` -- `MerkleTree` and `MerkleProof` are reusable without modification.
- `methods/guest/src/membership.rs` -- Phase 1 circuit logic can be extended for Phase 2.
- `contracts/src/MembershipVerifier.sol` -- Provides the template for the Phase 2 contract.

The Rust implementation quality is high. The Merkle tree code is clean, well-tested (11 tests covering construction, proofs, verification, and edge cases), and faithfully implements the spec.
