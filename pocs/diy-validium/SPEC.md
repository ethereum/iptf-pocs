---
title: "DIY Validium"
status: Draft
version: 0.1.0
authors: []
created: 2026-01-29
iptf_use_case: "Private institutional payments"
iptf_approach: "Validium with ZK proofs"
---

# DIY Validium: Protocol Specification

## Problem Statement

Institutions want blockchain guarantees—immutability, settlement finality, auditability—without blockchain transparency. Competitors shouldn't see your volumes, positions, or counterparties.

The pattern: **Keep data in your database, post only roots + ZK proofs on-chain.**

This gives you Ethereum's security guarantees while keeping sensitive data private.

### Use Cases

| Use Case | What's Private | What's On-Chain |
|----------|---------------|-----------------|
| **Private Stablecoins** | Holder balances, transfer amounts | Total supply, validity proofs |
| **Tokenized Securities** | Positions, trade details | Settlement finality, compliance attestations |
| **Cross-Institution Settlement** | Bilateral positions, netting details | Net settlement amounts, proof of correct computation |

### Constraints

- **Privacy**: Balances and transfer amounts must remain confidential from public observers
- **Regulatory**: System must be auditable (future: viewing keys for selective disclosure)
- **Operational**: Must integrate with existing Ethereum tooling
- **Trust**: Minimize trust assumptions while acknowledging PoC limitations

## Approach

### Strategy

Build a Validium-style system where:
- Full account state lives off-chain (operator database)
- Merkle roots of state are committed on-chain
- Zero-knowledge proofs validate state transitions
- RISC Zero provides the proving system

### Why This Approach

| Alternative | Why Not |
|-------------|---------|
| On-chain encrypted state | Gas costs prohibitive, limited computation |
| Full zkRollup | Data availability overhead unnecessary for PoC |
| Trusted execution (SGX) | Different trust model, hardware dependency |
| MPC-based | Complexity, coordination overhead |

Validium with ZK proofs provides:
- Strong privacy (ZK reveals nothing beyond validity)
- Low on-chain cost (only roots and proofs)
- Flexibility to evolve trust model later

### Tools & Primitives

- **RISC Zero zkVM**: Write circuits in Rust, STARK-based proofs, no trusted setup
- **SHA-256**: Hash function with hardware acceleration in RISC Zero
- **Binary Merkle Trees**: Simple, well-understood commitment structure
- **Nullifiers**: Prevent double-spending without revealing account identity

## Protocol Design

### Participants & Roles

| Role | Description |
|------|-------------|
| **Operator** | Maintains off-chain state, generates proofs, submits to chain |
| **User** | Owns accounts, initiates transfers, generates proofs locally |
| **Verifier Contract** | On-chain contract that verifies proofs and tracks state |

### Data Structures

#### Account (Off-chain)

```
Account {
    pubkey: [u8; 32],      // Public key (derived from secret key)
    balance: u64,          // Account balance
    salt: [u8; 32],        // Random salt for hiding
}
```

#### Account Commitment (Leaf)

```
commitment = SHA256(pubkey || balance || salt)
```

Where `||` denotes concatenation:
- `pubkey`: 32 bytes
- `balance`: 8 bytes (little-endian u64)
- `salt`: 32 bytes
- Total: 72 bytes input to SHA256

#### Merkle Tree

Binary Merkle tree with SHA256:
```
internal_node = SHA256(left_child || right_child)
```

Tree depth: 20 (supports ~1M accounts)

#### Nullifier

```
nullifier = SHA256(secret_key || old_root || "transfer_v1")
```

- `secret_key`: 32 bytes
- `old_root`: 32 bytes (the pre-transition Merkle root)
- `"transfer_v1"`: ASCII domain separator (operation-specific)

Nullifiers are **state-bound**: each state transition generates a unique nullifier
derived from the sender's secret key and the pre-transition root. This allows
accounts to perform multiple transfers while preventing double-spends (same
old_root can only be used once per account). Different operation types use
different domain separators to ensure disjoint nullifier spaces.

### On-Chain State

```solidity
contract ValidiumVerifier {
    bytes32 public stateRoot;
    mapping(bytes32 => bool) public nullifiers;
    address public operator;

    // Phase 4: ERC20 bridge
    IERC20 public token;
    uint256 public totalDeposited;
}
```

---

## Phase 1: Allowlist Membership

### Flow

```
┌──────────┐     ┌──────────┐     ┌──────────┐     ┌──────────┐
│ Operator │     │   User   │     │ RISC Zero│     │ Contract │
└────┬─────┘     └────┬─────┘     └────┬─────┘     └────┬─────┘
     │                │                │                │
     │ 1. Create allowlist             │                │
     │ 2. Compute root                 │                │
     │ 3. Deploy contract ─────────────────────────────▶│
     │                │                │                │
     │ 4. Share leaf + proof           │                │
     │───────────────▶│                │                │
     │                │                │                │
     │                │ 5. Generate ZK proof            │
     │                │───────────────▶│                │
     │                │                │                │
     │                │◀───────────────│                │
     │                │   receipt      │                │
     │                │                │                │
     │                │ 6. Submit proof ───────────────▶│
     │                │                │                │
     │                │◀─────────────── 7. Verify ──────│
```

### Circuit: Membership Proof

**Public Inputs:**
- `merkle_root: [u8; 32]`

**Private Inputs:**
- `leaf: [u8; 32]` (the user's entry)
- `path: Vec<[u8; 32]>` (sibling hashes)
- `path_indices: Vec<bool>` (left/right at each level)

**Circuit Logic:**
```rust
fn verify_membership(
    leaf: [u8; 32],
    path: &[[u8; 32]],
    indices: &[bool],
    expected_root: [u8; 32]
) {
    let mut current = leaf;

    for (i, sibling) in path.iter().enumerate() {
        current = if indices[i] {
            // current is right child
            sha256(&[sibling, &current].concat())
        } else {
            // current is left child
            sha256(&[&current, sibling].concat())
        };
    }

    assert_eq!(current, expected_root);
}
```

**Committed Outputs (Journal):**
- `merkle_root: [u8; 32]`

### Contract: MembershipVerifier

```solidity
contract MembershipVerifier {
    bytes32 public allowlistRoot;
    IRiscZeroVerifier public verifier;
    bytes32 public constant IMAGE_ID = /* guest program hash */;

    mapping(bytes32 => bool) public usedNullifiers;

    function verifyMembership(
        bytes calldata seal,
        bytes32 journalRoot
    ) external returns (bool) {
        require(journalRoot == allowlistRoot, "Root mismatch");

        bytes memory journal = abi.encodePacked(journalRoot);
        verifier.verify(seal, IMAGE_ID, sha256(journal));

        return true;
    }
}
```

---

## Phase 2: Private Balance Proofs

### Flow

Same as Phase 1, but circuit proves balance property.

### Circuit: Balance Proof

**Public Inputs:**
- `merkle_root: [u8; 32]`
- `required_amount: u64`

**Private Inputs:**
- `pubkey: [u8; 32]`
- `balance: u64`
- `salt: [u8; 32]`
- `path: Vec<[u8; 32]>`
- `path_indices: Vec<bool>`

**Circuit Logic:**
```rust
fn verify_balance(
    pubkey: [u8; 32],
    balance: u64,
    salt: [u8; 32],
    path: &[[u8; 32]],
    indices: &[bool],
    expected_root: [u8; 32],
    required_amount: u64
) {
    // 1. Compute leaf commitment
    let leaf = sha256(&[
        &pubkey[..],
        &balance.to_le_bytes()[..],
        &salt[..]
    ].concat());

    // 2. Verify membership
    verify_membership(leaf, path, indices, expected_root);

    // 3. Check balance requirement
    assert!(balance >= required_amount);
}
```

**Committed Outputs (Journal):**
- `merkle_root: [u8; 32]`
- `required_amount: u64`

> **Authentication Note:** Phase 2 balance proofs are unauthenticated — the circuit
> does not require a secret key. Anyone with the account data (pubkey, balance, salt,
> Merkle path) can generate a valid balance proof. This is acceptable because balance
> proofs are read-only attestations ("some account has balance >= X"), not state-changing
> operations. Authentication via secret keys is introduced in Phase 3 (transfers).
> The operator is responsible for sharing account data only with the account owner.

### Contract: BalanceVerifier

```solidity
contract BalanceVerifier {
    bytes32 public accountsRoot;
    IRiscZeroVerifier public verifier;
    bytes32 public constant IMAGE_ID = /* balance proof circuit hash */;

    event BalanceProofVerified(bytes32 indexed root, uint64 requiredAmount);

    function verifyBalance(
        bytes calldata seal,
        bytes32 journalRoot,
        uint64 requiredAmount
    ) external view returns (bool) {
        require(journalRoot == accountsRoot, "Root mismatch");

        bytes memory journal = abi.encodePacked(journalRoot, requiredAmount);
        verifier.verify(seal, IMAGE_ID, sha256(journal));

        return true;
    }
}
```

> **Note on `abi.encodePacked` and endianness:** The journal committed by the RISC Zero
> guest uses serde/bincode encoding (little-endian for integers). The Solidity
> `abi.encodePacked` uses big-endian for `uint` types. For `bytes32` values this is
> not an issue (raw bytes, no endianness). For `required_amount: u64`, the guest must
> commit the value as big-endian bytes to match Solidity's encoding:
>
> ```rust
> // In guest circuit:
> env::commit_slice(&root);                          // 32 bytes, no endianness issue
> env::commit_slice(&required_amount.to_be_bytes()); // 8 bytes, big-endian for Solidity
> ```
>
> Alternatively, the Solidity contract can reverse the byte order. The chosen approach
> should be consistent across all phases. This PoC uses **big-endian guest commits**
> to match Solidity's `abi.encodePacked` convention.

---

## Phase 3: Private Transfers

### Flow

```
┌──────────┐     ┌──────────┐     ┌──────────┐     ┌──────────┐
│ Operator │     │  Sender  │     │ RISC Zero│     │ Contract │
└────┬─────┘     └────┬─────┘     └────┬─────┘     └────┬─────┘
     │                │                │                │
     │ 1. Provide current state        │                │
     │───────────────▶│                │                │
     │                │                │                │
     │                │ 2. Compute transfer proof       │
     │                │───────────────▶│                │
     │                │                │                │
     │                │◀─── receipt ───│                │
     │                │                │                │
     │ 3. Submit proof + new root      │                │
     │◀───────────────│                │                │
     │                │                │                │
     │ 4. Update state──────────────────────────────────▶│
     │                │                │                │
     │                │◀─────────────── 5. Verify ──────│
     │                │                │                │
     │ 6. Update off-chain DB          │                │
     │                │                │                │
```

### Circuit: Transfer Proof

**Public Inputs:**
- `old_root: [u8; 32]`
- `new_root: [u8; 32]`
- `nullifier: [u8; 32]`

**Private Inputs:**
- `sender_sk: [u8; 32]` (secret key)
- `sender_balance: u64`
- `sender_salt: [u8; 32]`
- `sender_path: Vec<[u8; 32]>` (length == TREE_DEPTH)
- `sender_indices: Vec<bool>` (length == TREE_DEPTH)
- `amount: u64`
- `recipient_pubkey: [u8; 32]`
- `recipient_balance: u64` (current)
- `recipient_salt: [u8; 32]`
- `recipient_path: Vec<[u8; 32]>` (length == TREE_DEPTH)
- `recipient_indices: Vec<bool>` (length == TREE_DEPTH)
- `new_sender_salt: [u8; 32]`
- `new_recipient_salt: [u8; 32]`

**Input Validation:**
```rust
assert_eq!(sender_path.len(), TREE_DEPTH);
assert_eq!(sender_indices.len(), TREE_DEPTH);
assert_eq!(recipient_path.len(), TREE_DEPTH);
assert_eq!(recipient_indices.len(), TREE_DEPTH);
assert!(amount > 0, "Transfer amount must be positive");
```

**Circuit Logic:**
```rust
fn verify_transfer(/* inputs */) {
    // 1. Derive sender pubkey; prohibit self-transfers
    let sender_pubkey = sha256(&sender_sk);  // pubkey = SHA256(secret_key)
    assert_ne!(sender_pubkey, recipient_pubkey, "Self-transfer not allowed");

    // 2. Compute sender's old commitment
    let sender_old_leaf = sha256(&[
        &sender_pubkey[..],
        &sender_balance.to_le_bytes()[..],
        &sender_salt[..]
    ].concat());

    // 3. Verify sender in old tree
    verify_membership(sender_old_leaf, &sender_path, &sender_indices, old_root);

    // 4. Compute recipient's old commitment and verify in old tree
    let recipient_old_leaf = sha256(&[
        &recipient_pubkey[..],
        &recipient_balance.to_le_bytes()[..],
        &recipient_salt[..]
    ].concat());
    verify_membership(recipient_old_leaf, &recipient_path, &recipient_indices, old_root);

    // 5. Check sufficient balance (underflow protection)
    assert!(sender_balance >= amount, "Insufficient balance");

    // 6. Check recipient overflow protection
    assert!(recipient_balance <= u64::MAX - amount, "Recipient balance overflow");

    // 7. Compute state-bound nullifier
    let computed_nullifier = sha256(&[
        &sender_sk[..],
        &old_root[..],
        b"transfer_v1"
    ].concat());
    assert_eq!(computed_nullifier, nullifier);

    // 8. Compute new balances (safe after checks in steps 5-6)
    let new_sender_balance = sender_balance - amount;
    let new_recipient_balance = recipient_balance + amount;

    // 9. Compute new commitments
    let sender_new_leaf = sha256(&[
        &sender_pubkey[..],
        &new_sender_balance.to_le_bytes()[..],
        &new_sender_salt[..]
    ].concat());

    let recipient_new_leaf = sha256(&[
        &recipient_pubkey[..],
        &new_recipient_balance.to_le_bytes()[..],
        &new_recipient_salt[..]
    ].concat());

    // 10. Recompute new root with both leaves updated
    let computed_new_root = compute_new_root(
        sender_new_leaf, &sender_indices,
        recipient_new_leaf, &recipient_indices,
        &sender_path, &recipient_path,
    );
    assert_eq!(computed_new_root, new_root);
}
```

**Dual-Leaf Root Recomputation (`compute_new_root`):**

When two leaves change simultaneously, the tree update must account for
whether the sender and recipient share subtree ancestors. The algorithm:

1. Find the divergence depth: the shallowest level where `sender_indices`
   and `recipient_indices` differ.
2. Below divergence: recompute each branch independently using its own
   sibling path from the old tree.
3. At divergence: the two recomputed branches become siblings of each other.
4. Above divergence: continue hashing upward using shared sibling hashes
   (which are the same in both paths above the divergence point).

```rust
fn compute_new_root(
    sender_leaf: [u8; 32],
    sender_indices: &[bool],
    recipient_leaf: [u8; 32],
    recipient_indices: &[bool],
    sender_path: &[[u8; 32]],
    recipient_path: &[[u8; 32]],
) -> [u8; 32] {
    let depth = sender_indices.len();

    // Find divergence depth.
    // The indices array is indexed leaf-to-root: indices[0] is the leaf level,
    // indices[depth-1] is the root-adjacent level. We scan from root
    // (highest index) downward to find the shallowest level where the
    // sender and recipient paths first differ.
    let divergence = (0..depth)
        .rev()
        .find(|&i| sender_indices[i] != recipient_indices[i])
        .expect("Sender and recipient must differ (no self-transfers)");

    // Recompute sender's branch from leaf (index 0) up to (but not
    // including) the divergence level.
    let mut sender_hash = sender_leaf;
    for i in 0..divergence {
        sender_hash = if sender_indices[i] {
            sha256(&[&sender_path[i][..], &sender_hash[..]].concat())
        } else {
            sha256(&[&sender_hash[..], &sender_path[i][..]].concat())
        };
    }

    // Recompute recipient's branch from leaf up to (but not including)
    // the divergence level.
    let mut recipient_hash = recipient_leaf;
    for i in 0..divergence {
        recipient_hash = if recipient_indices[i] {
            sha256(&[&recipient_path[i][..], &recipient_hash[..]].concat())
        } else {
            sha256(&[&recipient_hash[..], &recipient_path[i][..]].concat())
        };
    }

    // At divergence level, the two branches are siblings.
    let mut current = if sender_indices[divergence] {
        // Sender is right child, recipient is left child
        sha256(&[&recipient_hash[..], &sender_hash[..]].concat())
    } else {
        // Sender is left child, recipient is right child
        sha256(&[&sender_hash[..], &recipient_hash[..]].concat())
    };

    // Continue hashing above divergence toward root using shared path
    // siblings (same in both paths above the divergence point).
    for i in (divergence + 1)..depth {
        current = if sender_indices[i] {
            sha256(&[&sender_path[i][..], &current[..]].concat())
        } else {
            sha256(&[&current[..], &sender_path[i][..]].concat())
        };
    }

    current
}
```

**Invariant:** Accounts maintain fixed positions in the Merkle tree. The
sender's position (encoded by `sender_indices`) and recipient's position
(encoded by `recipient_indices`) do not change between old and new state.
Tree compaction is not supported in this PoC.

**Committed Outputs (Journal):**
- `old_root: [u8; 32]`
- `new_root: [u8; 32]`
- `nullifier: [u8; 32]`

All committed as big-endian bytes for Solidity compatibility (see Phase 2 endianness note).

### Contract: TransferVerifier

```solidity
contract TransferVerifier {
    bytes32 public stateRoot;
    mapping(bytes32 => bool) public nullifiers;
    IRiscZeroVerifier public verifier;
    address public operator;
    bytes32 public constant IMAGE_ID = /* transfer circuit hash */;

    error StaleState(bytes32 expected, bytes32 provided);
    error NullifierAlreadyUsed(bytes32 nullifier);

    event Transfer(
        bytes32 indexed oldRoot,
        bytes32 indexed newRoot,
        bytes32 indexed nullifier
    );

    function executeTransfer(
        bytes calldata seal,
        bytes32 oldRoot,
        bytes32 newRoot,
        bytes32 nullifier
    ) external {
        // 1. Check old root matches current state (cheap check first)
        if (oldRoot != stateRoot) revert StaleState(stateRoot, oldRoot);

        // 2. Check nullifier not used (cheap check)
        if (nullifiers[nullifier]) revert NullifierAlreadyUsed(nullifier);

        // 3. Verify proof (expensive — after cheap checks)
        bytes memory journal = abi.encodePacked(oldRoot, newRoot, nullifier);
        verifier.verify(seal, IMAGE_ID, sha256(journal));

        // 4. Atomic state update (no external calls between these)
        stateRoot = newRoot;
        nullifiers[nullifier] = true;

        emit Transfer(oldRoot, newRoot, nullifier);
    }
}
```

> **Access Control:** In this PoC, `executeTransfer` is callable by any address.
> In production, restrict to the operator or authorized submitters to limit
> gas griefing from invalid proof submissions.

### Off-Chain State Consistency

The operator maintains an off-chain mirror of the account state. To prevent
divergence between off-chain and on-chain state:

1. **Sequential processing:** The operator generates at most one proof per
   state root. No concurrent proof generation from the same root.
2. **Pending transaction tracking:** While a transfer transaction is pending
   in the mempool, the operator rejects new proof generation requests.
3. **Confirmation:** After on-chain confirmation, the operator applies the
   state transition to the off-chain database and opens the next proof slot.
4. **Revert handling:** If a transaction reverts (stale state, gas issues),
   the operator discards the pending state diff and resumes from the
   confirmed on-chain root.

```
Operator State Machine:
  IDLE ──[generate proof]──▶ PENDING ──[tx confirmed]──▶ IDLE (new root)
                                │
                                └──[tx reverted]──▶ IDLE (same root)
```

> **PoC Shortcut:** This PoC uses single-threaded proof generation, which
> naturally serializes state transitions. Production systems would need
> explicit locking or an optimistic concurrency mechanism.

### Phase Independence

Phase 2 and Phase 3 deploy separate contracts with independent state roots.
Phase 2's `BalanceVerifier` operates on a static snapshot of account state.
Phase 3's `TransferVerifier` manages a dynamic state root that evolves with
each transfer. In a production system, these would be unified into a single
contract.

---

## Phase 4: Institutional Lifecycle (Bridge + Compliance Disclosure)

Phase 4 demonstrates the full institutional lifecycle: deposit ERC20 tokens
into the private system (gated by allowlist membership), execute private
transfers (Phase 3), prove compliance to regulators via selective disclosure,
and withdraw back to ERC20. This is the "Prividium pattern" — privacy by
default, transparency by choice.

### Overview

```
Institution A           Operator                  On-chain

DEPOSIT (permissioned):
  membership proof ──────────────────────────────→ verify allowlist membership
  approve + deposit ─────────────────────────────→ transferFrom(A, bridge, amt)
                        credit off-chain balance    emit Deposit(pubkey, amt)
                        update Merkle root ──────→ updateRoot(newRoot, proof)

TRANSFER (private):
  [Phase 3 — hidden from everyone, only nullifiers on-chain]

COMPLIANCE DISCLOSURE:
  regulator requests audit
  A generates disclosure ────────────────────────→ verify disclosure proof
    proof: "account with                           (optional: on-chain or off-chain)
    disclosure_key K has
    balance >= threshold"
  Regulator learns: A is solvent
  Regulator does NOT learn: exact balance, pubkey, tree position

WITHDRAW (proven):
  generate withdrawal proof
  withdraw(seal, ...) ──────────────────────────→ verify proof
                                                   check stateRoot, nullifier
                                                   transfer(recipient, amount)
                                                   emit Withdrawal(...)
```

### Deposit Flow

```
User                    Contract                 Operator
  │                         │                        │
  │ 1. approve(amount)      │                        │
  │────────────────────────▶│                        │
  │                         │                        │
  │ 2. deposit(amount, pk,  │                        │
  │    membershipSeal)      │                        │
  │────────────────────────▶│                        │
  │                         │ 3. Verify membership   │
  │                         │    proof (allowlist)    │
  │                         │ 4. transferFrom        │
  │                         │─────────▶              │
  │                         │                        │
  │                         │ 5. emit Deposit event  │
  │                         │───────────────────────▶│
  │                         │                        │
  │                         │ 6. Credit off-chain    │
  │                         │                        │
  │                         │ 7. Update root + proof │
  │                         │◀───────────────────────│
```

Deposits are gated by an allowlist membership proof: only addresses whose
pubkey is in the allowlist Merkle tree can deposit. The bridge contract
verifies the membership proof on-chain before accepting the ERC20 transfer.

> **PoC Shortcut:** In this PoC, the membership proof verification in the
> bridge is simplified — it checks that a valid seal is provided but the
> IMAGE_ID is a placeholder `bytes32(0)`. Production would use the real
> compiled guest image ID.

### Withdraw Flow

```
User                    Contract                 Operator
  │                         │                        │
  │ 1. Get merkle proof     │                        │
  │────────────────────────────────────────────────▶│
  │◀────────────────────────────────────────────────│
  │                         │                        │
  │ 2. Generate ZK proof    │                        │
  │         locally         │                        │
  │                         │                        │
  │ 3. withdraw(proof, amt) │                        │
  │────────────────────────▶│                        │
  │                         │ 4. Verify proof        │
  │                         │ 5. Check nullifier     │
  │                         │ 6. Update root         │
  │                         │ 7. Transfer tokens     │
  │◀────────────────────────│                        │
  │                         │                        │
  │                         │ 8. Notify withdrawal   │
  │                         │───────────────────────▶│
```

### Circuit: Withdrawal Proof

The withdrawal circuit is structurally similar to a transfer (Phase 3)
but updates only a single leaf: the sender's balance decreases by the
withdrawal amount. No recipient leaf is involved — the funds exit the
private system entirely.

**Public Inputs (Journal):**
- `old_root: [u8; 32]` — pre-withdrawal Merkle root
- `new_root: [u8; 32]` — post-withdrawal Merkle root
- `nullifier: [u8; 32]` — withdrawal nullifier
- `amount: u64` — withdrawal amount (big-endian, 8 bytes)
- `recipient: [u8; 20]` — Ethereum address to receive funds

**Private Inputs:**
- `secret_key: [u8; 32]` — account owner's secret key
- `balance: u64` — current balance
- `salt: [u8; 32]` — current salt
- `path: Vec<[u8; 32]>` — Merkle proof path (length == TREE_DEPTH)
- `indices: Vec<bool>` — Merkle proof direction flags (length == TREE_DEPTH)
- `new_salt: [u8; 32]` — new salt for the post-withdrawal commitment

**Circuit Logic:**
```rust
fn verify_withdrawal(/* inputs */) {
    // 1. Derive pubkey from secret key
    let pubkey = sha256(&secret_key);

    // 2. Compute old leaf commitment
    let old_leaf = sha256(&[&pubkey[..], &balance.to_le_bytes()[..], &salt[..]].concat());

    // 3. Verify account exists in current tree (recompute root from leaf)
    let old_root = recompute_root(old_leaf, &path, &indices);

    // 4. Validate withdrawal amount
    assert!(amount > 0, "Withdrawal amount must be positive");
    assert!(balance >= amount, "Insufficient balance");

    // 5. Compute nullifier (domain-separated from transfers)
    let nullifier = sha256(&[&secret_key[..], &old_root[..], b"withdrawal_v1"].concat());

    // 6. Compute new leaf with reduced balance
    let new_balance = balance - amount;
    let new_leaf = sha256(&[&pubkey[..], &new_balance.to_le_bytes()[..], &new_salt[..]].concat());

    // 7. Single-leaf root update: replace old_leaf with new_leaf in tree
    let new_root = compute_single_leaf_root(new_leaf, &path, &indices);

    // 8. Commit public outputs (big-endian for Solidity compatibility)
    commit(old_root);                          // 32 bytes
    commit(new_root);                          // 32 bytes
    commit(nullifier);                         // 32 bytes
    commit(amount.to_be_bytes());              // 8 bytes, big-endian
    commit(recipient);                         // 20 bytes
}
```

**Single-Leaf Root Update (`compute_single_leaf_root`):**

Unlike the dual-leaf update in Phase 3, a withdrawal only modifies one leaf.
The new root is computed by hashing the new leaf upward through the same
Merkle path, using the original siblings:

```rust
fn compute_single_leaf_root(
    new_leaf: [u8; 32],
    path: &[[u8; 32]],
    indices: &[bool],
) -> [u8; 32] {
    let mut current = new_leaf;
    for (sibling, &is_right) in path.iter().zip(indices.iter()) {
        current = if is_right {
            sha256(&[sibling, &current].concat())
        } else {
            sha256(&[&current, sibling].concat())
        };
    }
    current
}
```

**Nullifier Domain Separation:** Withdrawal nullifiers use the domain tag
`"withdrawal_v1"` instead of `"transfer_v1"`. This ensures that a transfer
nullifier and a withdrawal nullifier from the same account and state are
always different, preventing cross-operation collisions.

**Committed Outputs (Journal):**
Total: 124 bytes = old_root (32) + new_root (32) + nullifier (32) +
amount_be (8) + recipient (20).

All committed as raw bytes via `env::commit_slice`. The `amount` field is
committed as big-endian u64 (8 bytes) to match Solidity's `abi.encodePacked`
encoding for `uint64`.

### Contract: ValidiumBridge

```solidity
contract ValidiumBridge {
    IERC20 public immutable token;
    IRiscZeroVerifier public immutable verifier;
    bytes32 public stateRoot;
    mapping(bytes32 => bool) public nullifiers;
    address public operator;

    bytes32 public allowlistRoot;
    bytes32 public constant MEMBERSHIP_IMAGE_ID = bytes32(0);
    bytes32 public constant WITHDRAWAL_IMAGE_ID = bytes32(0);

    error StaleState(bytes32 expected, bytes32 provided);
    error NullifierAlreadyUsed(bytes32 nullifier);
    error InvalidAmount();

    event Deposit(address indexed depositor, bytes32 pubkey, uint256 amount);
    event Withdrawal(
        bytes32 indexed nullifier,
        address indexed recipient,
        uint256 amount
    );

    constructor(
        IERC20 _token,
        IRiscZeroVerifier _verifier,
        bytes32 _initialRoot,
        bytes32 _allowlistRoot
    ) {
        token = _token;
        verifier = _verifier;
        stateRoot = _initialRoot;
        allowlistRoot = _allowlistRoot;
        operator = msg.sender;
    }

    function deposit(
        uint256 amount,
        bytes32 pubkey,
        bytes calldata membershipSeal
    ) external {
        if (amount == 0) revert InvalidAmount();

        // Verify membership proof: pubkey must be in allowlist
        bytes memory membershipJournal = abi.encodePacked(allowlistRoot);
        verifier.verify(
            membershipSeal, MEMBERSHIP_IMAGE_ID, sha256(membershipJournal)
        );

        token.transferFrom(msg.sender, address(this), amount);
        emit Deposit(msg.sender, pubkey, amount);
    }

    function withdraw(
        bytes calldata seal,
        bytes32 oldRoot,
        bytes32 newRoot,
        bytes32 nullifier,
        uint64 amount,
        address recipient
    ) external {
        if (oldRoot != stateRoot) revert StaleState(stateRoot, oldRoot);
        if (nullifiers[nullifier]) revert NullifierAlreadyUsed(nullifier);
        if (amount == 0) revert InvalidAmount();

        // Journal: oldRoot(32) + newRoot(32) + nullifier(32) +
        //          amount_be(8) + recipient(20) = 124 bytes
        bytes memory journal = abi.encodePacked(
            oldRoot, newRoot, nullifier, amount, recipient
        );
        verifier.verify(seal, WITHDRAWAL_IMAGE_ID, sha256(journal));

        // CEI: state updates before external call
        stateRoot = newRoot;
        nullifiers[nullifier] = true;

        token.transfer(recipient, amount);

        emit Withdrawal(nullifier, recipient, amount);
    }
}
```

> **CEI Pattern:** The `withdraw` function follows Checks-Effects-Interactions:
> state updates (`stateRoot`, `nullifiers`) happen before the external
> `token.transfer` call to prevent reentrancy.

### Compliance Disclosure Flow

```
User                    Auditor                  Contract (optional)
  │                         │                        │
  │ 1. Auditor requests     │                        │
  │    compliance check     │                        │
  │◀────────────────────────│                        │
  │                         │                        │
  │ 2. Generate disclosure  │                        │
  │    proof locally        │                        │
  │                         │                        │
  │ 3. Submit proof to      │                        │
  │    auditor (off-chain)  │                        │
  │────────────────────────▶│                        │
  │                         │                        │
  │                         │ 4. Verify proof        │
  │                         │ (off-chain or on-chain)│
  │                         │───────────────────────▶│
  │                         │                        │
  │                         │◀───────────────────────│
  │                         │    verified            │
```

### Circuit: Disclosure Proof

The disclosure circuit is the Prividium differentiator. It proves that an
account satisfies a compliance predicate (balance >= threshold) without
revealing the actual balance, the account's pubkey, or its position in the
tree. The proof is bound to a specific auditor via a disclosure key.

**Public Inputs (Journal):**
- `merkle_root: [u8; 32]` — current state root
- `threshold: u64` — minimum balance being proven (big-endian, 8 bytes)
- `disclosure_key_hash: [u8; 32]` — `SHA256(SHA256(sk) || auditor_pubkey || "disclosure_v1")`

**Private Inputs:**
- `secret_key: [u8; 32]` — account owner's secret key
- `balance: u64` — account balance
- `salt: [u8; 32]` — account salt
- `path: Vec<[u8; 32]>` — Merkle proof path
- `indices: Vec<bool>` — Merkle proof direction flags
- `auditor_pubkey: [u8; 32]` — the auditor's public key

**Circuit Logic:**
```rust
fn verify_disclosure(/* inputs */) {
    // 1. Derive pubkey from secret key
    let pubkey = sha256(&secret_key);

    // 2. Compute leaf commitment
    let leaf = sha256(&[&pubkey[..], &balance.to_le_bytes()[..], &salt[..]].concat());

    // 3. Verify account exists in current tree (recompute root from leaf)
    let merkle_root = recompute_root(leaf, &path, &indices);

    // 4. Prove balance satisfies threshold
    assert!(balance >= threshold, "Balance below threshold");

    // 5. Compute disclosure key (binds proof to specific auditor)
    let disclosure_key_hash = sha256(
        &[&pubkey[..], &auditor_pubkey[..], b"disclosure_v1"].concat()
    );

    // 6. Commit public outputs (big-endian for Solidity compatibility)
    commit(merkle_root);                       // 32 bytes
    commit(threshold.to_be_bytes());           // 8 bytes, big-endian
    commit(disclosure_key_hash);               // 32 bytes
}
```

**Disclosure Key Derivation:**

The disclosure key hash serves three purposes:
1. **Auditor binding:** Includes `auditor_pubkey`, so the proof is only
   meaningful to the intended auditor. A different auditor produces a
   different `disclosure_key_hash`.
2. **Account binding:** Includes the prover's `pubkey` (derived from `sk`),
   so different accounts produce different keys.
3. **Domain separation:** The `"disclosure_v1"` tag prevents collisions
   with other hash-based constructs in the protocol.

The auditor registers or agrees upon their `auditor_pubkey` off-chain.
When the prover submits a disclosure proof, the auditor checks that
`disclosure_key_hash` matches the expected value for the account
relationship.

**Why this works:**
- Auditor Bob knows his own pubkey and Alice's expected `disclosure_key_hash`
  (established during account onboarding or out-of-band).
- Alice proves: "the account bound to this disclosure_key_hash has
  balance >= threshold."
- Bob verifies the proof. He learns Alice satisfies the threshold.
  He does **not** learn her exact balance, her pubkey directly, or
  her position in the tree.
- The proof is auditor-specific — Alice cannot reuse a proof meant
  for a different auditor, because `disclosure_key_hash` would differ.

**Institutional applications:**
- Capital adequacy: "Prove reserves >= $50M" without revealing $53.7M
- Counterparty solvency: "Prove you can cover this $10M trade"
- AML threshold: "Prove no single balance exceeds $10K"

**Committed Outputs (Journal):**
Total: 72 bytes = merkle_root (32) + threshold_be (8) +
disclosure_key_hash (32).

### Contract: DisclosureVerifier

```solidity
contract DisclosureVerifier {
    IRiscZeroVerifier public immutable verifier;
    bytes32 public stateRoot;
    bytes32 public constant IMAGE_ID = bytes32(0);

    event DisclosureVerified(
        bytes32 indexed root,
        uint64 threshold,
        bytes32 indexed disclosureKeyHash
    );

    constructor(IRiscZeroVerifier _verifier, bytes32 _stateRoot) {
        verifier = _verifier;
        stateRoot = _stateRoot;
    }

    function verifyDisclosure(
        bytes calldata seal,
        bytes32 root,
        uint64 threshold,
        bytes32 disclosureKeyHash
    ) external {
        require(root == stateRoot, "Root mismatch");

        // Journal: root(32) + threshold_be(8) + disclosureKeyHash(32) = 72 bytes
        bytes memory journal = abi.encodePacked(
            root, threshold, disclosureKeyHash
        );
        verifier.verify(seal, IMAGE_ID, sha256(journal));

        emit DisclosureVerified(root, threshold, disclosureKeyHash);
    }
}
```

> **Read-only contract:** The DisclosureVerifier does not modify state
> (no nullifiers, no root updates). Disclosure proofs are attestations,
> not state transitions. The `stateRoot` is set at construction and can
> be updated by the operator to track the current bridge state.

### Privacy Guarantees

| Operation | What's Public | What's Private | Who Learns What |
|-----------|--------------|----------------|-----------------|
| **Deposit** | Amount, depositor address, pubkey | Account position in tree | Public chain observers see deposit |
| **Transfer** | Nullifiers, Merkle roots | Amount, sender, recipient, balances | Only operator sees details |
| **Disclosure** | Threshold, disclosure_key_hash | Actual balance, pubkey, tree position | Auditor learns: balance >= threshold. Nothing more. |
| **Withdraw** | Amount, recipient address | Prior balance, account history, tree position | Public chain observers see withdrawal |

**Critical caveats:**
- Deposits and withdrawals are public — privacy exists only between them
- Operator sees everything — primary privacy concern in production
- No DA fallback — if operator disappears, funds are locked
- Timing analysis can link deposits to withdrawals with few participants
- Disclosure proofs reveal a lower bound on balance, not the exact value

### Operator Trust Model

**Trusted (not enforced by ZK or on-chain logic):**
- Credits private balances correctly on deposit (could credit wrong amount)
- Maintains Merkle tree accurately (could serve stale or incorrect proofs)
- Maps pubkeys to real identities (sees all account data)
- Controls data availability (sole holder of off-chain state)

**Enforced by ZK proofs + on-chain verification:**
- Cannot forge a transfer or withdrawal proof without the sender's secret key
- Cannot double-spend (nullifiers are recorded on-chain, one per state root per account)
- Cannot steal funds via withdrawal (withdrawal proofs are verified on-chain)
- Cannot update state root without a valid proof
- Cannot fake a disclosure proof (bound to real account state and specific auditor)

---

## Security Model

### Threat Model

| Adversary | Capability |
|-----------|------------|
| Public observer | Sees all on-chain data (deposits, withdrawals, roots, nullifiers) |
| Malicious user | Tries to forge proofs, double-spend, or create fake disclosures |
| Network attacker | Can delay/reorder transactions |
| Curious auditor | Receives disclosure proofs; tries to learn more than threshold |

**NOT considered:**
- Malicious operator (trusted in this PoC)
- Side-channel attacks on proof generation
- Cross-chain bridge attacks (no L1/L2 bridge)

### Guarantees

| Property | Mechanism |
|----------|-----------|
| Balance privacy | ZK proofs reveal nothing beyond validity |
| No double-spend | Nullifiers are recorded on-chain |
| No forgery | Requires knowledge of secret key |
| State integrity | Root transitions validated by proofs |
| Selective disclosure | Disclosure proofs bound to specific auditor and threshold |
| Deposit gating | Membership proof required for bridge deposit |
| Withdrawal integrity | Bridge verifies proof before releasing ERC20 tokens |

### Limitations & Shortcuts (PoC Scope)

- **Centralized operator**: Data availability depends on single operator
  - Production: DA committee or on-chain calldata

- **No real viewing keys**: Disclosure uses hash-based key derivation, not
  encryption-based viewing keys
  - Production: Threshold decryption, verifiable encryption (see Penumbra, Aztec)

- **Simple key derivation**: `pubkey = sha256(secret_key)`
  - Production: Use proper EC key derivation (e.g., ed25519)

- **Fixed tree depth**: 20 levels hardcoded
  - Production: Make configurable

- **In-memory account storage**: PoC uses in-memory data structures
  - Production: Use a persistent database (SQLite, Postgres, etc.)

- **IMAGE_ID placeholders**: On-chain contracts use `bytes32(0)` as the
  guest image ID. Must be updated with real compiled image IDs before
  testnet deployment.

- **No transaction batching**: Each operation requires a separate proof.
  Production would batch multiple transfers per proof.

- **Single ERC20**: Bridge supports one token. Production would add
  `asset_id` to the commitment scheme.

---

## Future Work

The following extensions are documented for completeness. None are
implemented in this PoC.

- **Viewing keys with real crypto**: Replace hash-based disclosure keys
  with threshold decryption or verifiable encryption. See Penumbra's
  viewing key model and Aztec's note discovery mechanism.

- **Role-based access control**: Operator/trader/auditor roles with
  permissioned contract access. The bridge should restrict `withdraw`
  to the operator or authorized submitters.

- **Data availability**: DA committee or on-chain calldata fallback
  so users can reconstruct state if the operator disappears (escape hatch).

- **Multi-asset**: Add `asset_id` to the commitment scheme:
  `SHA256(pubkey || asset_id || balance_le || salt)`. Each deposit
  specifies which token is being deposited.

- **Transaction batching**: N transfers per proof for cost efficiency.
  The circuit would verify N sender-recipient pairs in a single execution.

- **Range proofs**: Prove "amount ∈ [min, max]" without revealing the
  exact value. Useful for AML compliance ("no transaction > $10K").

- **ERC-3643 compliance hooks**: ZK proofs of claim validity — prove
  KYC status without revealing the underlying claim data.

---

## Terminology

- **Commitment**: Hash that hides a value but can be verified later
- **Merkle Root**: Single hash representing entire tree state
- **Nullifier**: Unique identifier that prevents double-use of a commitment
- **Journal**: Public outputs from a RISC Zero proof
- **Seal**: The proof bytes that can be verified on-chain
- **Validium**: L2 where data is off-chain but validity is proven
- **Disclosure Key**: Hash binding an account to a specific auditor, enabling selective compliance proofs
- **Prividium Pattern**: Privacy by default, transparency by choice — private state transitions with selective disclosure for compliance

## References

- [RISC Zero Documentation](https://dev.risczero.com/)
- [Tornado Cash (nullifier design)](https://tornado.cash/)
- [Zcash Protocol Specification](https://zips.z.cash/protocol/protocol.pdf)
- [Validium on ethereum.org](https://ethereum.org/en/developers/docs/scaling/validium/)
- [Penumbra — Viewing Keys](https://protocol.penumbra.zone/)
- [Aztec — Note Discovery](https://docs.aztec.network/)
