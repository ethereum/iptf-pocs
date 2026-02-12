---
title: "TEE Swap"
status: Draft
version: 0.1.0
authors: []
created: 2025-02-12
iptf_use_case: "https://github.com/ethereum/iptf-map/blob/master/use-cases/private-trade-settlement.md"
iptf_approach: "https://github.com/ethereum/iptf-map/blob/master/approaches/approach-private-trade-settlement.md"
---

# TEE-Coordinated Atomic Swap Protocol - Specification

## Overview

A protocol for atomic cross-chain swaps of private UTXO notes using stealth addresses and time-locked dual spending conditions. Designed for Delivery-vs-Payment settlement between institutional counterparties.

**Trust model**: Users never share spending keys. TEE coordinates but cannot steal funds. Hardware manufacturer trust is required.

---

## Data Types

### Time-Locked Note

```
Note {
    value: uint64,            // Amount
    assetId: bytes32,         // Asset identifier (USD, BOND, etc.)
    owner: bytes32,           // Primary owner (stealth address)
    fallbackOwner: bytes32,   // Original owner (refund path)
    timeout: uint256,         // Timestamp when fallback becomes valid
    salt: bytes32             // Blinding factor
}
```

**Spending conditions (enforced by circuit):**
```
Can spend if EITHER:
  1. Know sk_owner (stealth key) — normal claim path
  2. Know sk_fallback AND block.timestamp > timeout — refund path
```

**Derived values:**
- `commitment = Hash(value, assetId, owner, fallbackOwner, timeout, salt)`
- `nullifier = Hash(commitment, spendingKey)` where spendingKey is either sk_owner or sk_fallback

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
  pk_stealth = pk_meta + Hash(shared_secret)·G

Recipient (knows sk_meta, receives R):
  shared_secret = ECDH(sk_meta, R) = sk_meta·R
  sk_stealth = sk_meta + Hash(shared_secret)
```

---

### Swap State

```
SwapIntent {
    swapId: bytes32,                    // Unique swap identifier
    partyA_commitment: bytes32,         // A's locked note commitment
    partyB_commitment: bytes32,         // B's locked note commitment
    partyA_ephemeralKey: Point,         // R_A (for B to derive sk_stealth)
    partyB_ephemeralKey: Point,         // R_B (for A to derive sk_stealth)
    timeout: uint256,                   // Swap expiry
    revealed: bool                      // TEE has revealed ephemeral keys
}
```

---

## Atomic Swap Protocol

### Phase 1: Lock Notes to Stealth Addresses

**Party A (swapping USD for BOND):**
```
1. Generate ephemeral key: r_A
2. Compute:
   - shared_secret_AB = ECDH(r_A, pk_meta_B)
   - pk_stealth_B = pk_meta_B + Hash(shared_secret_AB)·G
3. Create time-locked note:
   - owner = pk_stealth_B (B can claim with ephemeral key)
   - fallbackOwner = pk_A (A can refund after timeout)
   - timeout = now + 48h
4. Generate ZK proof: spend USD note → create time-locked note
5. Submit proof on Network 1 (USD chain)
6. Send to TEE (encrypted): (swapId, r_A·G, Note details)
```

**Party B (swapping BOND for USD):**
```
1. Generate ephemeral key: r_B
2. Compute:
   - shared_secret_BA = ECDH(r_B, pk_meta_A)
   - pk_stealth_A = pk_meta_A + Hash(shared_secret_BA)·G
3. Create time-locked note:
   - owner = pk_stealth_A
   - fallbackOwner = pk_B
   - timeout = now + 48h
4. Generate ZK proof: spend BOND note → create time-locked note
5. Submit proof on Network 2 (BOND chain)
6. Send to TEE (encrypted): (swapId, r_B·G, Note details)
```

---

### Phase 2: TEE Verification

```
TEE receives from both parties:
  - (swapId, R_A, noteDetails_A) from A
  - (swapId, R_B, noteDetails_B) from B

TEE verifies:
  1. Both commitments exist on their respective chains ✓
  2. Commitments match provided note details ✓
  3. Stealth addresses correctly derived:
     - pk_stealth_B = pk_meta_B + Hash(ECDH(R_A, pk_meta_B))·G ✓
     - pk_stealth_A = pk_meta_A + Hash(ECDH(R_B, pk_meta_A))·G ✓
  4. Swap terms match (amounts, assets) ✓
  5. Both notes have same timeout ✓
  6. Timeout hasn't expired ✓
```

---

### Phase 3: Atomic Revelation

**TEE atomically publishes both ephemeral keys:**

```solidity
function announceSwap(
    bytes32 swapId,
    bytes32 ephemeralKey_A,  // R_A for Party B
    bytes32 ephemeralKey_B   // R_B for Party A
) external onlyTEE {
    announcements[swapId] = SwapAnnouncement({
        ephemKey_A: ephemeralKey_A,
        ephemKey_B: ephemeralKey_B,
        timestamp: block.timestamp
    });
    emit SwapRevealed(swapId);
}
```

**Both parties monitor announcement location (contract on either network, or off-chain service).**

**Atomicity:** TEE reveals both keys in a single operation, or neither. This guarantees both parties can claim their notes, or both can refund. Works identically for same-network and cross-chain swaps.

---

### Phase 4: Claim or Refund

**Party B claims USD (normal path):**
```
1. Reads R_A from announcement contract
2. Derives: sk_stealth_B = sk_meta_B + Hash(ECDH(sk_meta_B, R_A))
3. Generates ZK proof: spend note with sk_stealth_B
4. Submits to Network 1 → receives USD
```

**Party A claims BOND (normal path):**
```
1. Reads R_B from announcement contract
2. Derives: sk_stealth_A = sk_meta_A + Hash(ECDH(sk_meta_A, R_B))
3. Generates ZK proof: spend note with sk_stealth_A
4. Submits to Network 2 → receives BOND
```

**Refund scenario (TEE failed to reveal before timeout):**
```
Party A refunds USD:
  1. Wait until block.timestamp > timeout
  2. Generate ZK proof: spend note with sk_fallback_A (original key)
  3. Circuit validates: timeout expired ✓
  4. Reclaim USD note

Party B refunds BOND (same process)
```

---

## Threat Models & Mitigations

### T1: TEE Steals User Funds

**Attack:** TEE attempts to spend users' notes.

**Mitigation:**
- ✅ Users never share spending keys with TEE
- ✅ TEE only receives ephemeral public keys (R), not private keys (r)
- ✅ TEE cannot derive stealth private keys without user's meta private key
- ✅ Worst case: TEE refuses to reveal keys → users refund after timeout

**Impact if TEE compromised:** Censorship only, not theft.

---

### T2: Hardware Manufacturer Compromise

**Attack:** Intel/AMD/AWS extracts plaintext from TEE during execution.

**Mitigation:**
- ❌ No cryptographic defense against manufacturer
- ⚠️ Institutional users may accept this risk (already trust HSMs from same vendors)
- ⚠️ Multi-TEE approach: require M-of-N TEEs from different manufacturers

**Impact:** Manufacturer sees swap amounts and parties (privacy loss), but cannot steal (no spending keys).

---

### T3: Partial Revelation Attack

**Attack:** TEE reveals R_A (Party B claims USD) but crashes before revealing R_B (Party A can't claim BOND).

**Mitigation:**
- ✅ TEE reveals both R_A and R_B in a single atomic operation (both or neither)
- ✅ Atomicity enforced by TEE, not by blockchain - works cross-chain
- ✅ If TEE fails before revelation → timeout refunds activate for both parties
- ✅ Announcement can be on-chain (either network) or off-chain service

**Impact:** No vulnerability. Atomicity guaranteed by TEE's single revelation operation, independent of whether notes are on same network or different networks.

---

### T4: Front-Running Announcement

**Attack:** MEV bot sees announcement transaction in mempool, tries to claim notes before legitimate parties.

**Mitigation:**
- ✅ Only recipient with sk_meta can derive sk_stealth from revealed R
- ✅ Attacker seeing R_A cannot derive sk_stealth_B without sk_meta_B
- ✅ Announcement reveals public key R, not private key

**Impact:** No vulnerability. Stealth address crypto prevents front-running.

---

### T5: TEE Censorship / Selective Reveal

**Attack:** TEE reveals keys for one party but refuses to reveal for the other.

**Mitigation:**
- ✅ Announcement contract enforces atomic revelation (both keys or neither)
- ✅ Timeout refunds provide escape hatch if TEE goes offline
- ⚠️ TEE can censor by never revealing at all → users wait until timeout

**Impact:** Temporary denial of service. Users always recover funds via timeout.

---

### T6: Timeout Too Short

**Attack:** Malicious party sets timeout = now + 1 minute, immediately refunds after locking.

**Mitigation:**
- ✅ TEE verifies timeout is reasonable (e.g., minimum 24-48h)
- ✅ TEE rejects swaps with insufficient timeout window
- ✅ Both parties' notes must have matching timeout

**Impact:** Prevented by TEE validation.

---

### T7: Anonymity Set Attacks

**Attack:** Observer links locked notes to claims via timing/amount analysis.

**Mitigation:**
- ✅ All notes look identical on-chain (same commitment structure)
- ✅ Time-locked notes indistinguishable from normal notes
- ✅ Spending with stealth key vs refund path produces identical on-chain footprint
- ✅ Large anonymity set: swap notes mix with all system notes

**Impact:** Minimal metadata leakage. Privacy comparable to client-side ZK systems.

---

### T8: Announcement Location Disagreement

**Attack:** Parties monitor different announcement locations, miss the revelation.

**Mitigation:**
- ✅ Announcement location agreed upon during swap negotiation
- ✅ Can be on-chain contract (either network) or off-chain service
- ✅ Both parties must monitor the same location
- ✅ If party misses announcement, timeout refund available

**Impact:** Coordination issue, not security issue. Parties can always refund if they miss announcement.

---

## Security Properties

**Guaranteed (cryptographic):**
- Users cannot lose funds to TEE
- Users can always recover via timeout refund
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

---

## Comparison to Alternatives

| Property | This Protocol | Client-Side ZK (Railgun) | Traditional TEE DvP |
|----------|---------------|--------------------------|---------------------|
| User keeps spending keys | ✅ Yes | ✅ Yes | ❌ No (TEE has keys) |
| TEE can steal funds | ❌ No | N/A | ⚠️ Yes |
| Timeout recovery | ✅ Yes | N/A | ❌ No |
| Anonymity set | All notes | All notes | Only swaps |
| Atomic swaps | ✅ Yes (TEE revelation) | N/A | ✅ Yes (but risky) |
| Works cross-chain | ✅ Yes | N/A | ❌ No |
| Proof generation | Client-side | Client-side | TEE-side |
| Trust requirement | HW manufacturer | None | TEE operator + HW |

**Key innovation:** Atomicity via TEE's revelation mechanism (not blockchain consensus) enables cross-chain swaps while users retain custody of spending keys. Privacy maintained through stealth addresses and large anonymity sets.
