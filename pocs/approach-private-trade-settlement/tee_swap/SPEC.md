---
title: "Cross-Chain Private Atomic Swap"
status: Draft
version: 0.1.0
authors: []
created: 2025-02-12
iptf_use_case: "https://github.com/ethereum/iptf-map/blob/master/use-cases/private-trade-settlement.md"
iptf_approach: "https://github.com/ethereum/iptf-map/blob/master/approaches/approach-private-trade-settlement.md"
---

# TEE-Coordinated Private Atomic Swap Protocol

## Overview

A protocol for atomic cross-chain swaps of private UTXO notes using stealth addresses and time-locked dual spending conditions. Designed for Delivery-vs-Payment settlement between institutional counterparties.

**Trust model**: Users MUST NOT share spending keys. TEE coordinates but cannot steal funds. Hardware manufacturer trust is required.

---

## Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

---

## Hash Domain Separation

All hashes MUST use an explicit domain tag as the first argument to prevent cross-purpose collisions in a cross-chain context:

| Domain     | Tag                     | Purpose                        |
| ---------- | ----------------------- | ------------------------------ |
| Commitment | `"tee_swap.commitment"` | Note commitment derivation     |
| Nullifier  | `"tee_swap.nullifier"`  | Nullifier derivation           |
| Stealth    | `"tee_swap.stealth"`    | Stealth address key derivation |
| Salt       | `"tee_swap.salt_enc"`   | Salt encryption key derivation |

Convention: `H(domain, ...)` denotes `Hash(domain_tag ‖ ...)` where `‖` is concatenation.

> **Why domain separation?** Without it, a hash computed for one purpose (e.g., a commitment) could collide with a hash computed for another purpose (e.g., a nullifier or stealth key). In a cross-chain protocol, this risk is amplified. Domain tags ensure each hash is unambiguously scoped to its intended use.

---

## Data Types

### Time-Locked Note

```
Note {
    chainId: uint256,         // Network identifier (binds note to a specific chain)
    value: uint64,            // Amount
    assetId: bytes32,         // Asset identifier (USD, BOND, etc.)
    owner: bytes32,           // Primary owner (stealth address)
    fallbackOwner: bytes32,   // Original owner (refund path)
    timeout: uint256,         // Timestamp when fallback becomes valid
    salt: bytes32             // Blinding factor
}
```

**Derived values:**

- `commitment = H("tee_swap.commitment", chainId, value, assetId, owner, fallbackOwner, timeout, salt)`
- `nullifier = H("tee_swap.nullifier", commitment, salt)`

**Spending conditions (enforced by circuit):**

The circuit proves ALL of the following:

```
1. Commitment preimage: commitment == H("tee_swap.commitment", chainId, value, assetId, owner, fallbackOwner, timeout, salt)
2. Merkle inclusion: commitment exists in the commitment tree at the given root
3. Nullifier correctness: nullifier == H("tee_swap.nullifier", commitment, salt)
4. Ownership: EITHER
   a. Know sk_owner where sk_owner·G == owner       (claim path)
   b. Know sk_fallback where sk_fallback·G == fallbackOwner
      AND current_timestamp > timeout                (refund path)
      where current_timestamp is a PUBLIC INPUT
```

**Circuit timeout validation:** The circuit cannot read `block.timestamp` directly. Instead, `current_timestamp` is passed as a **public input** to the proof. The circuit checks `current_timestamp > timeout` internally. The on-chain verifier contract enforces that the public input matches `block.timestamp` at verification time. This splits the check: the circuit proves the timeout relationship, the contract guarantees the timestamp is real.

> **Why `H("tee_swap.nullifier", commitment, salt)` and not `Hash(commitment, spendingKey)`?** The nullifier MUST be unique per note AND independent of which spending path is used. If the nullifier varied by spending key, the owner path and fallback path would produce different nullifiers for the same note, enabling a double-spend where Party B claims and Party A refunds the same note. With `H("tee_swap.nullifier", commitment, salt)`, the nullifier is canonical: whichever path is used first, the second attempt is rejected by the nullifier set.

---

### Stealth Address Components

```
MetaAddress {
    sk_meta: bytes32,         // Meta private key (never shared)
    pk_meta: Point            // Meta public key (published)
}

EphemeralKey {
    r: bytes32,               // Ephemeral private key
    R: Point                  // R = r·G (ephemeral public key)
}

StealthAddress {
    pk_stealth: Point         // One-time address
    sk_stealth: bytes32       // Derived by recipient only
}
```

**Derivation:**

```
Sender (knows pk_meta_recipient, generates r):
  shared_secret = ECDH(r, pk_meta_recipient) = r·pk_meta
  pk_stealth = pk_meta + H("tee_swap.stealth", shared_secret)·G

Recipient (knows sk_meta, receives R):
  shared_secret = ECDH(sk_meta, R) = sk_meta·R
  sk_stealth = sk_meta + H("tee_swap.stealth", shared_secret)
```

---

### On-Chain State (per network)

Each network maintains:

```
CommitmentTree {
    tree: MerkleTree,          // Append-only Merkle tree of all note commitments
    roots: bytes32[]           // History of recent roots (for proof flexibility)
}

NullifierSet {
    nullifiers: Set<bytes32>   // All nullifiers ever submitted (spent notes)
}
```

**Invariant:** Each commitment in the tree maps to exactly one nullifier (`H("tee_swap.nullifier", commitment, salt)`). Once that nullifier appears in the set, the note MUST NOT be spent again via any path.

**Transaction flow:**

1. **Create note:** insert `commitment` into `CommitmentTree`
2. **Spend note:** verify ZK proof, check `nullifier ∉ NullifierSet`, add `nullifier` to `NullifierSet`

---

### Swap State

```
SwapIntent {
    swapId: bytes32,                    // Unique swap identifier
    partyA_commitment: bytes32,         // A's locked note commitment
    partyB_commitment: bytes32,         // B's locked note commitment
    partyA_ephemeralKey: Point,         // R_A (for B to derive sk_stealth)
    partyB_ephemeralKey: Point,         // R_B (for A to derive sk_stealth)
    encrypted_salt_A: bytes32,          // salt_A encrypted for Party B via ECDH(r_A, pk_meta_B)
    encrypted_salt_B: bytes32,          // salt_B encrypted for Party A via ECDH(r_B, pk_meta_A)
    timeout: uint256,                   // Swap expiry
    revealed: bool                      // TEE has revealed ephemeral keys
}
```

---

## Atomic Swap Protocol

### Phase 1: Lock Notes to Stealth Addresses

Each party creates a time-locked note for the counterparty and generates a deposit proof. The proof extends the standard note-creation circuit with stealth address derivation and three binding commitments. These commitments enable the TEE to verify correctness in Phase 2 without accessing any private key or computing any elliptic curve operation.

**Deposit circuit:**

```
Public inputs:
  commitment            // New note commitment (inserted into CommitmentTree)
  pk_stealth            // Stealth address (note owner). Safe to publish: unlinkable without R
  h_R                   // H(R): binds the proof to a specific ephemeral public key
  h_meta                // H(pk_meta_counterparty, salt): binds to the intended counterparty
  h_enc                 // H(encrypted_salt): binds to a correctly encrypted salt

Private inputs:
  r                     // Ephemeral private key (never leaves the prover)
  pk_meta_counterparty  // Counterparty's meta public key
  chainId, value, assetId, fallbackOwner, timeout, salt   // Note fields
  encrypted_salt        // Pre-computed by prover

Circuit constraints:
  1. commitment == H("tee_swap.commitment", chainId, value, assetId, pk_stealth, fallbackOwner, timeout, salt)
  2. pk_stealth == pk_meta_counterparty + H("tee_swap.stealth", r · pk_meta_counterparty)·G
  3. h_R == H(r·G)
  4. h_meta == H(pk_meta_counterparty, salt)
  5. h_enc == H(encrypted_salt)
     where encrypted_salt == salt XOR H("tee_swap.salt_enc", r · pk_meta_counterparty)
```

Constraint 2 guarantees the stealth address is correctly derived. Constraints 3-5 produce binding commitments that the TEE can open and verify in Phase 2. The ECDH shared secret (`r · pk_meta_counterparty`) is computed once inside the circuit and reused for both stealth derivation (constraint 2) and salt encryption (constraint 5).

If the note is funded by spending an existing note, the circuit MUST also prove standard spend operations (Merkle inclusion, nullifier correctness, ownership of the spent note).

**Party A (swapping USD for BOND):**

```
1. Generate ephemeral key pair (r_A, R_A = r_A·G) and random salt_A
2. Compute:
   - shared_secret_AB = r_A · pk_meta_B
   - pk_stealth_B = pk_meta_B + H("tee_swap.stealth", shared_secret_AB)·G
   - encrypted_salt_A = salt_A XOR H("tee_swap.salt_enc", shared_secret_AB)
3. Create time-locked note:
   - chainId = Network 1 chain ID
   - owner = pk_stealth_B (B can claim with stealth key)
   - fallbackOwner = pk_A (A can refund after timeout)
   - timeout = now + 48h
   - salt = salt_A
4. Generate deposit proof (see circuit above):
   - Public inputs: commitment_A, pk_stealth_B, H(R_A), H(pk_meta_B, salt_A), H(encrypted_salt_A)
   - Nullifies old note (old nullifier added to NullifierSet)
   - Inserts new commitment into CommitmentTree
5. Submit proof on Network 1 (USD chain)
6. Send to TEE (via attested channel): (swapId, R_A, encrypted_salt_A, noteDetails_A)
```

**Party B (swapping BOND for USD):**

```
1. Generate ephemeral key pair (r_B, R_B = r_B·G) and random salt_B
2. Compute:
   - shared_secret_BA = r_B · pk_meta_A
   - pk_stealth_A = pk_meta_A + H("tee_swap.stealth", shared_secret_BA)·G
   - encrypted_salt_B = salt_B XOR H("tee_swap.salt_enc", shared_secret_BA)
3. Create time-locked note:
   - chainId = Network 2 chain ID
   - owner = pk_stealth_A
   - fallbackOwner = pk_B
   - timeout = now + 48h
   - salt = salt_B
4. Generate deposit proof (see circuit above):
   - Public inputs: commitment_B, pk_stealth_A, H(R_B), H(pk_meta_A, salt_B), H(encrypted_salt_B)
   - Nullifies old note (old nullifier added to NullifierSet)
   - Inserts new commitment into CommitmentTree
5. Submit proof on Network 2 (BOND chain)
6. Send to TEE (via attested channel): (swapId, R_B, encrypted_salt_B, noteDetails_B)
```

> **Why R MUST remain secret until Phase 3.** The ephemeral public key R is the stealth address "unlock": given R, the counterparty can derive sk_stealth and claim the note. If R were a public output of the deposit proof, the counterparty could claim immediately after deposit, before locking their own note. Publishing only `H(R)` at deposit time preserves atomicity. R is revealed later in the TEE's atomic announcement (Phase 3).

---

### Phase 2: TEE Verification

The TEE combines on-chain proof data with off-chain submissions to verify swap correctness. The deposit proofs have already been verified on-chain by the ZK verifier contract, which guarantees the mathematical correctness of stealth address derivation and salt encryption (Phase 1 circuit constraints 1-5). The TEE's role is to verify that the off-chain data matches the on-chain binding commitments, and that the swap terms are compatible.

```
TEE receives via attested channel:
  - From Party A: (swapId, R_A, encrypted_salt_A, noteDetails_A)
  - From Party B: (swapId, R_B, encrypted_salt_B, noteDetails_B)

TEE reads from on-chain (public inputs of verified deposit proofs):
  - From Network 1: commitment_A, pk_stealth_B, h_R_A, h_meta_A, h_enc_A
  - From Network 2: commitment_B, pk_stealth_A, h_R_B, h_meta_B, h_enc_B

TEE MUST verify:

  1. Deposit proofs exist and are verified on their respective chains

  2. Commitment correctness (noteDetails match on-chain commitments):
     - H("tee_swap.commitment", noteDetails_A) == commitment_A
     - H("tee_swap.commitment", noteDetails_B) == commitment_B

  3. Binding commitment openings (off-chain data matches on-chain commitments):
     - H(R_A) == h_R_A
     - H(pk_meta_B, noteDetails_A.salt) == h_meta_A
     - H(encrypted_salt_A) == h_enc_A
     (same three checks for Party B's data against h_R_B, h_meta_B, h_enc_B)

  4. Swap terms match (amounts, assets, chain IDs)
  5. Both notes have matching timeout
  6. Timeout has not expired
```

**Why binding commitments are trustworthy.** The TEE performs only hash comparisons, no elliptic curve operations. The security argument:

- The on-chain ZK verifier has already verified the deposit proof. Circuit constraint 2 guarantees `pk_stealth` is correctly derived from the prover's ephemeral key `r` and `pk_meta_counterparty`. Constraints 3-5 guarantee `h_R`, `h_meta`, and `h_enc` are consistent with the same `r` and `pk_meta_counterparty`.
- When the TEE opens `h_meta_A` and finds it matches `H(pk_meta_B, salt_A)`, it confirms the note targets Party B specifically (not some other pk_meta). A malicious Party A cannot produce a valid proof for a different pk_meta that opens to `H(pk_meta_B, salt_A)`, because the circuit enforces the binding internally.
- When the TEE opens `h_R_A` and finds it matches `H(R_A)`, it confirms the `R_A` received off-chain is the same ephemeral key used in the proof. Party A cannot later provide a different R without failing this check.
- When the TEE opens `h_enc_A` and finds it matches `H(encrypted_salt_A)`, it confirms the encrypted salt is correctly derived (the circuit proved this in constraint 5). Party A cannot substitute a garbage encrypted salt.

If all checks pass, the TEE proceeds to Phase 3.

> **RPC trust assumption:** Step 1 relies on an external RPC endpoint (e.g., Infura, Alchemy) to read on-chain state. The TEE trusts the RPC provider to return correct commitment data. A compromised or malicious RPC could feed false state, causing the TEE to approve a swap against a non-existent commitment. To tighten this, a light client such as [Helios](https://github.com/a16z/helios) could run inside the TEE, verifying state proofs against the consensus and eliminating RPC trust entirely.

---

### Phase 3: Atomic Revelation

**The TEE MUST atomically publish both ephemeral keys and encrypted salts:**

```solidity
function announceSwap(
    bytes32 swapId,
    bytes32 ephemeralKey_A,       // R_A (Party B uses to derive sk_stealth)
    bytes32 ephemeralKey_B,       // R_B (Party A uses to derive sk_stealth)
    bytes32 encrypted_salt_A,     // salt_A encrypted for Party B
    bytes32 encrypted_salt_B      // salt_B encrypted for Party A
) external onlyTEE {
    announcements[swapId] = SwapAnnouncement({
        ephemKey_A: ephemeralKey_A,
        ephemKey_B: ephemeralKey_B,
        encSalt_A: encrypted_salt_A,
        encSalt_B: encrypted_salt_B,
        timestamp: block.timestamp
    });
    emit SwapRevealed(swapId);
}
```

**Both parties MUST monitor the agreed-upon announcement location (contract on either network, or off-chain service).**

**What each party receives from the announcement:**

- Party A: `R_B` (to derive sk_stealth_A) + `encrypted_salt_B` (to decrypt salt_B and compute nullifier)
- Party B: `R_A` (to derive sk_stealth_B) + `encrypted_salt_A` (to decrypt salt_A and compute nullifier)

**On-chain footprint:** The announcement contains only ephemeral public keys (random curve points) and encrypted salts (random-looking 32-byte values). No amounts, asset types, or party identities are revealed. A post-quantum adversary who breaks the ECDH underlying the salt encryption recovers only the salt, a random blinding factor with no semantic meaning without the full note details.

**Atomicity:** TEE reveals both keys and encrypted salts in a single operation, or neither. This guarantees both parties can claim their notes, or both can refund. Works identically for same-network and cross-chain swaps.

---

### Phase 4: Claim or Refund

> **Privacy note:** Parties SHOULD stagger their claim transactions with a random delay after the announcement (see T7). Claiming simultaneously creates a timing correlation that links both legs of the swap.

**Party B claims USD (normal path):**

```
1. Read R_A and encrypted_salt_A from announcement contract
2. Compute shared secret:
   - shared_secret_AB = sk_meta_B · R_A
3. Decrypt salt:
   - salt_A = encrypted_salt_A XOR H("tee_swap.salt_enc", shared_secret_AB)
4. Derive stealth key:
   - sk_stealth_B = sk_meta_B + H("tee_swap.stealth", shared_secret_AB)
5. Reconstruct note details from swap terms + decrypted salt:
   - chainId = Network 1 chain ID (known from swap terms)
   - value = agreed USD amount (known from swap terms)
   - assetId = USD identifier (known from swap terms)
   - owner = pk_stealth_B = pk_meta_B + H("tee_swap.stealth", shared_secret_AB)·G
   - fallbackOwner = pk_A (known from swap terms)
   - timeout = agreed timeout (known from swap terms)
   - salt = salt_A (decrypted above)
6. Compute:
   - commitment_A = H("tee_swap.commitment", chainId, value, assetId, owner, fallbackOwner, timeout, salt_A)
   - nullifier = H("tee_swap.nullifier", commitment_A, salt_A)
7. Generate ZK proof:
   - Proves knowledge of commitment preimage (with domain tag)
   - Proves Merkle inclusion of commitment_A in Network 1's CommitmentTree
   - Proves nullifier == H("tee_swap.nullifier", commitment_A, salt_A)
   - Proves knowledge of sk_stealth_B where sk_stealth_B·G == owner
8. Submit proof to Network 1. Nullifier is added to NullifierSet. Party B receives USD
```

**Party A claims BOND (normal path):**

```
1. Read R_B and encrypted_salt_B from announcement contract
2. Compute: shared_secret_BA = sk_meta_A · R_B
3. Decrypt: salt_B = encrypted_salt_B XOR H("tee_swap.salt_enc", shared_secret_BA)
4. Derive: sk_stealth_A = sk_meta_A + H("tee_swap.stealth", shared_secret_BA)
5. Reconstruct note details (same process as Party B, using Network 2 parameters)
6. Compute commitment_B, nullifier
7. Generate ZK proof (same structure as above, proving sk_stealth_A)
8. Submit proof to Network 2. Nullifier is added to NullifierSet. Party A receives BOND
```

**Refund scenario (TEE failed to reveal before timeout):**

```
Party A refunds USD:
  1. Wait until block.timestamp > timeout
  2. Party A already knows salt_A and all note details (they created the note)
  3. Compute: nullifier = H("tee_swap.nullifier", commitment_A, salt_A)
  4. Generate ZK proof:
     - Proves knowledge of commitment preimage (with domain tag)
     - Proves Merkle inclusion in CommitmentTree
     - Proves nullifier == H("tee_swap.nullifier", commitment_A, salt_A)
     - Proves knowledge of sk_A where sk_A·G == fallbackOwner
     - Proves current_timestamp > timeout (current_timestamp is a public input; verifier contract checks it matches block.timestamp)
  5. Submit proof. Nullifier is added to NullifierSet. Party A reclaims USD

Party B refunds BOND (same process, using salt_B and note details which they created)
```

> **Note:** If Party B already claimed (nullifier in set), Party A's refund attempt is rejected because the nullifier is the same regardless of spending path. This is the core double-spend protection.

---

## Security Properties

**Guaranteed (cryptographic):**

- Users cannot lose funds to TEE
- Users can always recover via timeout refund
- Double-spend prevention: canonical nullifier per note (`H("tee_swap.nullifier", commitment, salt)`) ensures a note spent via one path cannot be spent again via the other
- Front-running impossible (stealth address protection)
- Large anonymity set (all notes indistinguishable)
- Atomic swaps: both parties can claim or both refund (no partial execution)

**Atomicity source:**

- **TEE's atomic revelation of both ephemeral keys** - not blockchain consensus
- Works identically for same-network and cross-chain swaps
- Independent of which network(s) hold the notes

**Trusted:**

- TEE hardware manufacturer (can see plaintext, cannot steal)
- TEE operator (can censor by not revealing, cannot steal)
- Both parties monitor agreed announcement location

For detailed threat analysis and mitigation status of each vector, see [Annex A: Threat Model](#annex-a-threat-model).

---

## TEE Key Management

The TEE must submit transactions on-chain (swap announcements in Phase 3). This raises practical questions: how does the TEE pay for gas, how does it authenticate to the contract, and how are enclave keys rotated?

### Problem

A naive approach (funding an EOA inside the TEE) has drawbacks:

- The TEE needs ETH for gas, requiring external top-ups
- The EOA's secp256k1 key may not match the enclave's native key type (e.g., P-256 for SGX, RSA for some attestation flows)
- All swap announcements are linked to a single `msg.sender`, creating a correlation point
- Key rotation requires redeploying or updating every contract that references the TEE address

### Solution: Account Abstraction (EIP-4337)

The TEE operates through a smart account, using its enclave-derived key pair as the signing authority.

**Architecture:**

```
1. TEE signs UserOp with enclave key
2. Bundler submits UserOp to EntryPoint
3. EntryPoint calls SmartAccount.validateUserOp()   // verifies TEE signature
4. EntryPoint calls SmartAccount.execute()
5.   SmartAccount calls AnnouncementContract.announceSwap()
```

In `announceSwap`, `msg.sender` is the smart account address. The announcement contract authenticates via:

```solidity
modifier onlyTEE() {
    require(msg.sender == teeSmartAccount);
    _;
}
```

The smart account handles TEE signature verification internally. The announcement contract is decoupled from the TEE's key type or rotation schedule.

**Benefits:**

- **Gas abstraction:** A paymaster sponsors UserOps. The TEE never holds ETH.
- **Flexible signature schemes:** `validateUserOp` can verify P-256, RSA, or any scheme the enclave uses, and is not limited to secp256k1.
- **Stable identity:** The smart account address is permanent. Contracts reference this address regardless of the underlying TEE key.

### Key Rotation

TEE enclaves rotate keys on redeployment, attestation refresh, or hardware migration. The smart account supports this natively:

1. TEE generates a new key pair inside the enclave
2. TEE signs a UserOp **with the current (old) key** calling `smartAccount.rotateSigner(newPubKey)`
3. Smart account updates its authorized signer
4. Subsequent UserOps must be signed with the new key

The smart account address does not change. No update is required in the announcement contract or any other contract referencing `teeSmartAccount`.

### Trust Implications

The smart account introduces no additional trust assumptions beyond the TEE itself:

- Only the enclave can produce valid signatures for UserOps
- The bundler is untrusted: it relays but cannot forge UserOps
- The paymaster is untrusted: it sponsors gas but cannot influence execution
- The `onlyTEE` check in the announcement contract remains equivalent to verifying the TEE's authority, mediated through the smart account

---

## Annex A: Threat Model

### T1: TEE Steals User Funds

**Attack:** TEE attempts to spend users' notes.

**Mitigation:** Mitigated.

- Users never share spending keys (sk_meta, r) with the TEE
- TEE receives: ephemeral public keys (R), encrypted salts, and plaintext note details (which contain no private keys)
- TEE cannot derive stealth private keys: sk_stealth = sk_meta + H("tee_swap.stealth", shared_secret) requires sk_meta, which the TEE does not possess
- Deposit proof correctness (stealth address derivation, salt encryption) is verified on-chain by the ZK verifier, not by the TEE. The TEE only opens binding commitments via hash comparisons
- Worst case: TEE refuses to reveal keys. Users refund after timeout

**Impact if TEE compromised:** Censorship only, not theft.

---

### T2: Hardware Manufacturer Compromise

**Attack:** Intel/AMD/AWS extracts plaintext from TEE during execution.

**Mitigation:** Partially mitigated.

- No cryptographic defense against manufacturer
- Institutional users may accept this risk (already trust HSMs from same vendors)
- Multi-TEE approach: require M-of-N TEEs from different manufacturers

**Impact:** Manufacturer sees swap amounts and parties (privacy loss), but cannot steal (no spending keys).

---

### T3: Partial Revelation Attack

**Attack:** TEE reveals R_A (Party B claims USD) but crashes before revealing R_B (Party A can't claim BOND).

**Mitigation:** Mitigated.

- TEE reveals both R_A and R_B in a single atomic operation (both or neither)
- Atomicity enforced by TEE, not by blockchain. Works cross-chain
- If TEE fails before revelation, timeout refunds activate for both parties
- Announcement can be on-chain (either network) or off-chain service

**Impact:** No vulnerability. Atomicity guaranteed by TEE's single revelation operation, independent of whether notes are on same network or different networks.

---

### T4: Front-Running Announcement

**Attack:** MEV bot sees announcement transaction in mempool, tries to claim notes before legitimate parties.

**Mitigation:** Mitigated.

- Only recipient with sk_meta can derive sk_stealth from revealed R
- Attacker seeing R_A cannot derive sk_stealth_B without sk_meta_B
- Announcement reveals public key R, not private key

**Impact:** No vulnerability. Stealth address crypto prevents front-running.

---

### T5: TEE Censorship / Selective Reveal

**Attack:** TEE reveals keys for one party but refuses to reveal for the other.

**Mitigation:** Partially mitigated.

- Announcement contract enforces atomic revelation (both keys or neither)
- Timeout refunds provide escape hatch if TEE goes offline
- TEE can censor by never revealing at all. Users wait until timeout

**Impact:** Temporary denial of service. Users always recover funds via timeout.

---

### T6: Timeout Too Short

**Attack:** Malicious party sets timeout = now + 1 minute, immediately refunds after locking.

**Mitigation:** Mitigated.

- TEE MUST verify timeout is reasonable (e.g., minimum 24-48h)
- TEE MUST reject swaps with insufficient timeout window
- Both parties' notes MUST have matching timeout

**Impact:** Prevented by TEE validation.

---

### T7: Anonymity Set Attacks

**Attack:** Observer links locked notes to claims via timing/amount analysis.

**Mitigation:** Partially mitigated.

- All notes look identical on-chain (same commitment structure)
- Time-locked notes indistinguishable from normal notes
- Spending with stealth key vs refund path produces identical on-chain footprint
- Large anonymity set: swap notes mix with all system notes
- Claim transactions SHOULD be staggered. If both parties claim shortly after the TEE announcement, an observer can correlate the two spend transactions by timing, linking the USD and BOND legs of the same swap. Parties SHOULD introduce a random delay (e.g., minutes to hours) between the announcement and their claim submission. The timeout window (48h) provides ample room for this.

**Impact:** Minimal metadata leakage with proper claim staggering. Without staggering, timing correlation can link swap legs across chains.

---

### T8: Announcement Location Disagreement

**Attack:** Parties monitor different announcement locations, miss the revelation.

**Mitigation:** Mitigated.

- Announcement location agreed upon during swap negotiation
- Can be on-chain contract (either network) or off-chain service
- Both parties MUST monitor the same location
- If party misses announcement, timeout refund available

**Impact:** Coordination issue, not security issue. Parties can always refund if they miss announcement.
