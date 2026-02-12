---
title: "DIY Validium"
status: Draft
version: 0.2.0
authors: []
created: 2026-01-29
iptf_use_case: "Private institutional payments"
iptf_approach: "Validium with ZK proofs"
---

# DIY Validium: Protocol Specification

## Executive Summary

Institutions want blockchain guarantees — immutability, settlement finality, auditability — without blockchain transparency. This protocol keeps account data in the operator's database and posts only Merkle roots and ZK validity proofs on-chain.

Three operations cover the institutional lifecycle:

| Operation | What It Does | Business Use |
|-----------|-------------|-------------|
| **Transfer** | Private payment between accounts | Institutional settlements, private stablecoin transfers |
| **Bridge** | Deposit ERC20 (gated) + withdrawal (proven exit) | On/off ramp between public and private systems |
| **Disclosure** | Prove compliance without revealing data | Regulatory attestations, capital adequacy proofs |

The disclosure circuit is the key differentiator: compliance rules written as readable Rust functions, auditable by non-cryptographers.

## Problem Statement

| Use Case | What's Private | What's On-Chain |
|----------|---------------|-----------------|
| **Private Stablecoins** | Holder balances, transfer amounts | Total supply, validity proofs |
| **Tokenized Securities** | Positions, trade details | Settlement finality, compliance attestations |
| **Cross-Institution Settlement** | Bilateral positions, netting details | Net settlement amounts, proof of correct computation |

### Constraints

- **Privacy**: Balances and transfer amounts must remain confidential
- **Regulatory**: System must support selective disclosure to auditors
- **Operational**: Must integrate with existing Ethereum tooling
- **Trust**: Minimize trust assumptions while acknowledging PoC limitations

## Approach

Build a Validium-style system where:
- Full account state lives off-chain (operator database)
- Merkle roots of state are committed on-chain
- Zero-knowledge proofs validate state transitions
- RISC Zero provides the proving system (Rust circuits, no trusted setup)

| Alternative | Why Not |
|-------------|---------|
| On-chain encrypted state | Gas costs prohibitive, limited computation |
| Full zkRollup | Data availability overhead unnecessary for PoC |
| Trusted execution (SGX) | Different trust model, hardware dependency |
| ZKSync Prividium / full L2 | Privacy exists but no custom compliance rules — institutions can't write their own verification logic |

### What's Different from Prividium

Prividium (ZKSync) is a full L2 platform — you get privacy, but compliance logic is baked into the platform. You can't customize it.

**DIY Validium shows custom ZK compliance proofs as Rust functions.** Institutions write their own rules:

```rust
// In the disclosure circuit — readable by any Rust engineer:
assert!(balance >= threshold, "Balance below threshold");
let disclosure_key_hash =
    sha256(&[&pubkey[..], &auditor_pubkey[..], b"disclosure_v1"].concat());
```

Purpose-built circuits are easier to audit than a full zkEVM. An auditor reviewing a 40-line Rust function is a fundamentally different (and better) experience than auditing a zkEVM opcode table.

## Protocol Design

### Participants

| Role | Description |
|------|-------------|
| **Operator** | Maintains off-chain state, generates proofs, submits to chain |
| **User** | Owns accounts, initiates transfers, generates proofs locally |
| **Verifier Contract** | On-chain contract that verifies proofs and tracks state |
| **Auditor** | Receives disclosure proofs, verifies compliance |

### Data Structures

**Account (Off-chain):**
```
Account { pubkey: [u8; 32], balance: u64, salt: [u8; 32] }
```

**Account Commitment (Merkle Leaf):**
```
commitment = SHA256(pubkey || balance_le || salt)   // 72 bytes input
```

**Merkle Tree:** Binary, SHA-256, depth 20 (~1M accounts).
```
internal_node = SHA256(left_child || right_child)
```

**Nullifier (double-spend prevention):**
```
nullifier = SHA256(secret_key || old_root || domain_tag)
```
Domain tags: `"transfer_v1"`, `"withdrawal_v1"`. State-bound — each state transition generates a unique nullifier per account.

### On-Chain State

```solidity
// TransferVerifier
bytes32 public stateRoot;
mapping(bytes32 => bool) public nullifiers;

// ValidiumBridge (extends with ERC20)
IERC20 public token;
bytes32 public allowlistRoot;
```

---

## Operation 1: Transfer

Private payment between two accounts. Both sender and recipient balances change; the old Merkle root transitions to a new root via dual-leaf update.

### Flow

```
Sender         Operator              RISC Zero          Contract
  │               │                      │                  │
  │ request ─────▶│                      │                  │
  │               │ provide state ──────▶│                  │
  │               │                      │ prove ──────────▶│
  │               │                      │                  │ verify + update root
  │               │ update off-chain DB  │                  │
```

### Circuit: Transfer Proof

**Public Inputs (Journal):** `old_root` (32) + `new_root` (32) + `nullifier` (32) = 96 bytes

**Private Inputs:** sender_sk, sender_balance, sender_salt, sender_path, sender_indices, amount, recipient_pubkey, recipient_balance, recipient_salt, recipient_path, recipient_indices, new_sender_salt, new_recipient_salt

**Circuit Logic:**
```rust
// Derive sender identity
let sender_pubkey = sha256(&sender_sk);

// Business logic
assert_ne!(sender_pubkey, recipient_pubkey, "Self-transfer not allowed");
assert!(amount > 0, "Transfer amount must be positive");
assert!(sender_balance >= amount, "Insufficient balance");
assert!(recipient_balance <= u64::MAX - amount, "Recipient overflow");

// Verify both accounts exist in old tree
let sender_old_leaf = account_commitment(&sender_pubkey, sender_balance, &sender_salt);
let old_root = compute_root(sender_old_leaf, &sender_path, &sender_indices);
verify_membership(recipient_old_leaf, &recipient_path, &recipient_indices, old_root);

// State transition: compute new root with updated balances
let nullifier = sha256(&[&sender_sk, &old_root, b"transfer_v1"].concat());
let new_root = compute_new_root(sender_new_leaf, recipient_new_leaf, ...);

commit(old_root, new_root, nullifier);
```

**Dual-Leaf Root Recomputation:** When two leaves change simultaneously, the algorithm finds the divergence depth (shallowest level where sender/recipient indices differ), recomputes each branch independently below it, joins them at divergence, and hashes upward using shared siblings.

### Contract: TransferVerifier

```solidity
function executeTransfer(bytes seal, bytes32 oldRoot, bytes32 newRoot, bytes32 nullifier) {
    require(oldRoot == stateRoot, "Stale state");
    require(!nullifiers[nullifier], "Double spend");
    verifier.verify(seal, IMAGE_ID, sha256(abi.encodePacked(oldRoot, newRoot, nullifier)));
    stateRoot = newRoot;
    nullifiers[nullifier] = true;
}
```

---

## Operation 2: Bridge (Deposit + Withdrawal)

### Deposit Flow

Deposits are gated by an allowlist membership proof: only pubkeys in the allowlist Merkle tree can deposit ERC20 tokens into the private system.

```
User                    Contract                 Operator
  │ approve(amount) ───▶│                        │
  │ deposit(amt, pk,    │                        │
  │   membershipSeal) ─▶│ verify membership      │
  │                     │ transferFrom ──▶       │
  │                     │ emit Deposit ─────────▶│
  │                     │                        │ credit off-chain balance
```

### Withdrawal Circuit

Single-leaf state transition: balance decreases, funds exit to L1.

**Public Inputs (Journal):** `old_root` (32) + `new_root` (32) + `nullifier` (32) + `amount_be` (8) + `recipient` (20) = 124 bytes

**Circuit Logic:**
```rust
let pubkey = sha256(&secret_key);
let old_leaf = account_commitment(&pubkey, balance, &salt);
let old_root = compute_root(old_leaf, &path, &indices);

// Business logic
assert!(amount > 0, "Withdrawal amount must be positive");
assert!(balance >= amount, "Insufficient balance");

let nullifier = sha256(&[&secret_key, &old_root, b"withdrawal_v1"].concat());
let new_leaf = account_commitment(&pubkey, balance - amount, &new_salt);
let new_root = compute_root(new_leaf, &path, &indices);

commit(old_root, new_root, nullifier, amount, recipient);
```

### Contract: ValidiumBridge

```solidity
function deposit(uint256 amount, bytes32 pubkey, bytes calldata membershipSeal) external {
    require(amount > 0);
    verifier.verify(membershipSeal, MEMBERSHIP_IMAGE_ID, sha256(abi.encodePacked(allowlistRoot)));
    token.transferFrom(msg.sender, address(this), amount);
    emit Deposit(msg.sender, pubkey, amount);
}

function withdraw(bytes seal, bytes32 oldRoot, bytes32 newRoot,
                  bytes32 nullifier, uint64 amount, address recipient) external {
    require(oldRoot == stateRoot && !nullifiers[nullifier] && amount > 0);
    verifier.verify(seal, WITHDRAWAL_IMAGE_ID, sha256(journal));
    stateRoot = newRoot;
    nullifiers[nullifier] = true;
    token.transfer(recipient, amount);  // CEI: state updates before external call
}
```

---

## Operation 3: Disclosure — The Differentiator

The disclosure circuit proves that an account satisfies a compliance predicate (balance >= threshold) without revealing the actual balance, identity, or tree position. The proof is bound to a specific auditor via a disclosure key.

This is what makes DIY Validium distinct from platform-level privacy solutions: **institutions write compliance rules as readable Rust functions**, not as opaque zkEVM bytecode.

### Flow

```
User                    Auditor                  Contract (optional)
  │◀─── request ────────│                        │
  │ generate proof      │                        │
  │──── proof ─────────▶│                        │
  │                     │ verify (off-chain) ───▶│
  │                     │◀── verified ───────────│
```

### Circuit: Disclosure Proof

**Public Inputs (Journal):** `merkle_root` (32) + `threshold_be` (8) + `disclosure_key_hash` (32) = 72 bytes

**Circuit Logic:**
```rust
// Derive identity and verify account exists
let pubkey = sha256(&secret_key);
let leaf = account_commitment(&pubkey, balance, &salt);
let merkle_root = compute_root(leaf, &path, &indices);

// === Business logic (readable by any Rust engineer) ===
assert!(balance >= threshold, "Balance below threshold");
let disclosure_key_hash =
    sha256(&[&pubkey[..], &auditor_pubkey[..], b"disclosure_v1"].concat());

commit(merkle_root, threshold, disclosure_key_hash);
```

**Disclosure Key Derivation:** `SHA256(pubkey || auditor_pubkey || "disclosure_v1")`

Three properties:
1. **Auditor binding** — proof is only meaningful to the intended auditor
2. **Account binding** — different accounts produce different keys
3. **Domain separation** — `"disclosure_v1"` prevents collisions with other protocol hashes

**Institutional applications:**
- Capital adequacy: "Prove reserves >= $50M" without revealing $53.7M
- Counterparty solvency: "Prove you can cover this $10M trade"
- AML threshold: "Prove no single balance exceeds $10K"

### Contract: DisclosureVerifier

```solidity
function verifyDisclosure(bytes seal, bytes32 root, uint64 threshold,
                          bytes32 disclosureKeyHash) external {
    require(root == stateRoot);
    verifier.verify(seal, IMAGE_ID, sha256(abi.encodePacked(root, threshold, disclosureKeyHash)));
    emit DisclosureVerified(root, threshold, disclosureKeyHash);
}
```

> Read-only contract: no nullifiers, no root updates. Disclosure proofs are attestations, not state transitions.

---

## Why Rust for ZK Circuits

The same disclosure logic in three ZK systems:

### RISC Zero (Rust) — 5 lines of business logic

```rust
let pubkey = sha256(&secret_key);
let leaf = account_commitment(&pubkey, balance, &salt);
let root = compute_root(leaf, &path, &indices);
assert!(balance >= threshold);
let dk = sha256(&[&pubkey[..], &auditor_pk[..], b"disclosure_v1"].concat());
```

### Circom — ~80 lines, manual constraint wiring

```
template Disclosure(DEPTH) {
    signal input secret_key[256];    // Must decompose to bits
    signal input balance;
    signal input threshold;

    // SHA-256 = 30K constraints per call. 5 calls = 150K constraints.
    component pk = Sha256(256);      // Manual bit wiring
    pk.in <== secret_key;

    // Merkle proof: DEPTH Sha256 components + multiplexers
    component merkle[DEPTH];
    component mux[DEPTH];
    for (var i = 0; i < DEPTH; i++) {
        merkle[i] = Sha256(512);
        mux[i] = Mux1();
        // ... 10+ lines of manual signal routing per level
    }

    // Balance check: LessThan(64) range proof
    component lt = LessThan(64);
    lt.in[0] <== threshold;
    lt.in[1] <== balance + 1;
    lt.out === 1;

    // Disclosure key: Sha256(256+256+104) with manual concat
    component dk = Sha256(616);
    // ... 30+ lines of bit-by-bit signal assignment
}
```

### Noir — Similar to Rust, but less mature

```
fn main(secret_key: [u8; 32], ...) -> pub ([u8; 32], u64, [u8; 32]) {
    let pubkey = std::hash::sha256(secret_key);
    // Similar to Rust, but array operations less ergonomic
    // No standard concat — manual byte-by-byte packing
    let mut input: [u8; 68] = [0; 68];
    for i in 0..32 { input[i] = pubkey[i]; }
    for i in 0..32 { input[32 + i] = auditor_pubkey[i]; }
    // ...
}
```

**Key insight:** The Rust version reads like a verification procedure. The Circom version reads like circuit plumbing. For institutional auditors reviewing compliance logic, this matters.

---

## Privacy Guarantees

| Operation | What's Public | What's Private | Who Learns What |
|-----------|--------------|----------------|-----------------|
| **Deposit** | Amount, depositor address | Account position in tree | Public observers see deposit |
| **Transfer** | Nullifiers, Merkle roots | Amount, sender, recipient, balances | Only operator sees details |
| **Disclosure** | Threshold, disclosure_key_hash | Actual balance, pubkey, tree position | Auditor learns: balance >= threshold. Nothing more. |
| **Withdrawal** | Amount, recipient address | Prior balance, account history | Public observers see withdrawal |

**Critical caveats:**
- Deposits and withdrawals are public — privacy exists only between them
- Operator sees everything — primary privacy concern in production
- No DA fallback — if operator disappears, funds are locked
- Timing analysis can link deposits to withdrawals with few participants

## Operator Trust Model

**Trusted (not enforced):**
- Credits private balances correctly on deposit
- Maintains Merkle tree accurately
- Maps pubkeys to real identities
- Controls data availability

**Enforced by ZK + on-chain verification:**
- Cannot forge a transfer or withdrawal without the sender's secret key
- Cannot double-spend (nullifiers recorded on-chain)
- Cannot steal funds via withdrawal (proofs verified on-chain)
- Cannot update state root without a valid proof
- Cannot fake a disclosure proof (bound to real account state + specific auditor)

## Limitations & Shortcuts (PoC Scope)

- **Centralized operator** — Production: DA committee or on-chain calldata
- **Hash-based disclosure keys** — Production: threshold decryption or verifiable encryption (Penumbra, Aztec)
- **Simple key derivation** (`pubkey = SHA256(sk)`) — Production: EC key derivation (ed25519)
- **In-memory storage** — Production: persistent database
- **IMAGE_ID placeholders** (`bytes32(0)`) — Must be set to real guest image IDs
- **No batching** — One proof per operation; production would batch
- **Single ERC20** — Production: add `asset_id` to commitment scheme
- **Dev mode for tests** — Rust tests use `RISC0_DEV_MODE` (fake proofs)

## Future Work

- **Viewing keys with real crypto** — Replace hash-based disclosure keys with threshold decryption (Penumbra) or verifiable encryption (Aztec)
- **Data availability** — DA committee or on-chain calldata fallback (escape hatch)
- **Multi-asset** — Add `asset_id` to commitment: `SHA256(pubkey || asset_id || balance_le || salt)`
- **Transaction batching** — N transfers per proof
- **Range proofs** — Prove "amount in [min, max]" for AML compliance
- **ERC-3643 compliance hooks** — ZK proofs of claim validity (KYC status without revealing claims)

## Terminology

- **Commitment** — Hash that hides a value but can be verified later
- **Merkle Root** — Single hash representing entire tree state
- **Nullifier** — Unique identifier that prevents double-use of a commitment
- **Journal** — Public outputs from a RISC Zero proof
- **Seal** — The proof bytes that can be verified on-chain
- **Validium** — L2 where data is off-chain but validity is proven
- **Disclosure Key** — Hash binding an account to a specific auditor
- **Prividium Pattern** — Privacy by default, transparency by choice

## References

- [RISC Zero Documentation](https://dev.risczero.com/)
- [Tornado Cash — Nullifier Design](https://tornado.cash/)
- [Zcash Protocol Specification](https://zips.z.cash/protocol/protocol.pdf)
- [Validium on ethereum.org](https://ethereum.org/en/developers/docs/scaling/validium/)
- [Penumbra — Viewing Keys](https://protocol.penumbra.zone/)
- [Aztec — Note Discovery](https://docs.aztec.network/)
