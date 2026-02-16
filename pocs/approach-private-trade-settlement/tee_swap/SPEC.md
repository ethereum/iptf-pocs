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
    encryptedNoteA_forB: bytes,         // Note_A details (incl. salt_A), encrypted to pk_meta_B
    encryptedNoteB_forA: bytes,         // Note_B details (incl. salt_B), encrypted to pk_meta_A
    timeout: uint256,                   // Swap expiry
    revealed: bool                      // TEE has revealed ephemeral keys
}
```

---

## Atomic Swap Protocol

### Phase 1: Lock Notes to Stealth Addresses

**Party A (swapping USD for BOND):**

```
1. Generate ephemeral key: r_A, random salt_A
2. Compute:
   - shared_secret_AB = ECDH(r_A, pk_meta_B)
   - pk_stealth_B = pk_meta_B + H("tee_swap.stealth", shared_secret_AB)·G
3. Create time-locked note:
   - chainId = Network 1 chain ID
   - owner = pk_stealth_B (B can claim with stealth key)
   - fallbackOwner = pk_A (A can refund after timeout)
   - timeout = now + 48h
   - salt = salt_A
4. Generate ZK proof: spend existing USD note, producing a new time-locked note
   - Nullifies old note (old nullifier added to NullifierSet)
   - Inserts new commitment into CommitmentTree
5. Submit proof on Network 1 (USD chain)
6. Send to TEE (encrypted): (swapId, R_A, Note_A details including salt_A)
```

**Party B (swapping BOND for USD):**

```
1. Generate ephemeral key: r_B, random salt_B
2. Compute:
   - shared_secret_BA = ECDH(r_B, pk_meta_A)
   - pk_stealth_A = pk_meta_A + H("tee_swap.stealth", shared_secret_BA)·G
3. Create time-locked note:
   - chainId = Network 2 chain ID
   - owner = pk_stealth_A
   - fallbackOwner = pk_B
   - timeout = now + 48h
   - salt = salt_B
4. Generate ZK proof: spend existing BOND note, producing a new time-locked note
   - Nullifies old note (old nullifier added to NullifierSet)
   - Inserts new commitment into CommitmentTree
5. Submit proof on Network 2 (BOND chain)
6. Send to TEE (encrypted): (swapId, R_B, Note_B details including salt_B)
```

> **Salt communication:** Each party needs the counterparty's note details (including salt) to eventually claim. The TEE relays these during Phase 3 alongside the ephemeral keys, encrypted so only the intended recipient can read them. Party B receives Note_A details (including salt_A), Party A receives Note_B details (including salt_B).

---

### Phase 2: TEE Verification

```
TEE receives from both parties:
  - (swapId, R_A, noteDetails_A) from A
  - (swapId, R_B, noteDetails_B) from B

TEE MUST verify:
  1. Both commitments exist on their respective chains
  2. Commitments match provided note details
  3. Stealth addresses are correctly derived:
     - pk_stealth_B = pk_meta_B + H("tee_swap.stealth", ECDH(R_A, pk_meta_B))·G
     - pk_stealth_A = pk_meta_A + H("tee_swap.stealth", ECDH(R_B, pk_meta_A))·G
  4. Swap terms match (amounts, assets)
  5. Both notes have same timeout
  6. Timeout hasn't expired

If all checks pass, TEE prepares encrypted payloads for the announcement:
  7. encryptedNoteA_forB = ECIES.Encrypt(pk_meta_B, noteDetails_A)
  8. encryptedNoteB_forA = ECIES.Encrypt(pk_meta_A, noteDetails_B)
     where noteDetails = (chainId, value, assetId, owner, fallbackOwner, timeout, salt)
```

> **RPC trust assumption:** Step 1 relies on an external RPC endpoint (e.g., Infura, Alchemy) to read on-chain state. The TEE trusts the RPC provider to return correct commitment data. A compromised or malicious RPC could feed false state, causing the TEE to approve a swap against a non-existent commitment. To tighten this, a light client such as [Helios](https://github.com/a16z/helios) could run inside the TEE, verifying state proofs against the consensus and eliminating RPC trust entirely.

---

### Phase 3: Atomic Revelation

**The TEE MUST atomically publish both ephemeral keys and encrypted note details:**

```solidity
function announceSwap(
    bytes32 swapId,
    bytes32 ephemeralKey_A,       // R_A (Party B uses to derive sk_stealth)
    bytes32 ephemeralKey_B,       // R_B (Party A uses to derive sk_stealth)
    bytes encryptedNoteA_forB,    // Note_A details (incl. salt_A), encrypted to pk_meta_B
    bytes encryptedNoteB_forA     // Note_B details (incl. salt_B), encrypted to pk_meta_A
) external onlyTEE {
    announcements[swapId] = SwapAnnouncement({
        ephemKey_A: ephemeralKey_A,
        ephemKey_B: ephemeralKey_B,
        encNoteA: encryptedNoteA_forB,
        encNoteB: encryptedNoteB_forA,
        timestamp: block.timestamp
    });
    emit SwapRevealed(swapId);
}
```

**Both parties MUST monitor the agreed-upon announcement location (contract on either network, or off-chain service).**

**What each party receives from the announcement:**

- Party A: `R_B` (to derive sk_stealth_A) + encrypted Note_B details including `salt_B` (to compute nullifier)
- Party B: `R_A` (to derive sk_stealth_B) + encrypted Note_A details including `salt_A` (to compute nullifier)

**Atomicity:** TEE reveals both keys in a single operation, or neither. This guarantees both parties can claim their notes, or both can refund. Works identically for same-network and cross-chain swaps.

---

### Phase 4: Claim or Refund

> **Privacy note:** Parties SHOULD stagger their claim transactions with a random delay after the announcement (see T7). Claiming simultaneously creates a timing correlation that links both legs of the swap.

**Party B claims USD (normal path):**

```
1. Reads R_A and encrypted Note_A details from announcement contract
2. Decrypts Note_A details with sk_meta_B, obtaining (value, assetId, salt_A, owner, fallbackOwner, timeout)
3. Derives: sk_stealth_B = sk_meta_B + H("tee_swap.stealth", ECDH(sk_meta_B, R_A))
4. Computes: commitment_A = H("tee_swap.commitment", chainId, value, assetId, owner, fallbackOwner, timeout, salt_A)
5. Computes: nullifier = H("tee_swap.nullifier", commitment_A, salt_A)
6. Generates ZK proof:
   - Proves knowledge of commitment preimage (with domain tag)
   - Proves Merkle inclusion of commitment_A in Network 1's CommitmentTree
   - Proves nullifier == H("tee_swap.nullifier", commitment_A, salt_A)
   - Proves knowledge of sk_stealth_B where sk_stealth_B·G == owner
7. Submits proof to Network 1. Nullifier is added to NullifierSet. Party B receives USD
```

**Party A claims BOND (normal path):**

```
1. Reads R_B and encrypted Note_B details from announcement contract
2. Decrypts Note_B details with sk_meta_A, obtaining (value, assetId, salt_B, owner, fallbackOwner, timeout)
3. Derives: sk_stealth_A = sk_meta_A + H("tee_swap.stealth", ECDH(sk_meta_A, R_B))
4. Computes: commitment_B, nullifier (same derivation as above)
5. Generates ZK proof (same structure as above, proving sk_stealth_A)
6. Submits proof to Network 2. Nullifier is added to NullifierSet. Party A receives BOND
```

**Refund scenario (TEE failed to reveal before timeout):**

```
Party A refunds USD:
  1. Wait until block.timestamp > timeout
  2. Party A already knows salt_A (they created the note)
  3. Compute: nullifier = H("tee_swap.nullifier", commitment_A, salt_A)
  4. Generate ZK proof:
     - Proves knowledge of commitment preimage (with domain tag)
     - Proves Merkle inclusion in CommitmentTree
     - Proves nullifier == H("tee_swap.nullifier", commitment_A, salt_A)
     - Proves knowledge of sk_A where sk_A·G == fallbackOwner
     - Proves current_timestamp > timeout (current_timestamp is a public input; verifier contract checks it matches block.timestamp)
  5. Submit proof. Nullifier is added to NullifierSet. Party A reclaims USD

Party B refunds BOND (same process, using salt_B which they created)
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

- Users never share spending keys with TEE
- TEE only receives ephemeral public keys (R), not private keys (r)
- TEE cannot derive stealth private keys without user's meta private key
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
