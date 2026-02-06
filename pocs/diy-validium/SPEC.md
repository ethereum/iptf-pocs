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

## Phase 4: ERC20 Bridge

### Deposit Flow

```
User                    Contract                 Operator
  │                         │                        │
  │ 1. approve(amount)      │                        │
  │────────────────────────▶│                        │
  │                         │                        │
  │ 2. deposit(amount, pk)  │                        │
  │────────────────────────▶│                        │
  │                         │ 3. transferFrom        │
  │                         │─────────▶              │
  │                         │                        │
  │                         │ 4. emit Deposit event  │
  │                         │───────────────────────▶│
  │                         │                        │
  │                         │ 5. Credit off-chain    │
  │                         │                        │
  │                         │ 6. Update root + proof │
  │                         │◀───────────────────────│
```

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

### Contract: Bridge

```solidity
contract ValidiumBridge {
    IERC20 public token;
    bytes32 public stateRoot;
    mapping(bytes32 => bool) public nullifiers;
    IRiscZeroVerifier public verifier;

    event Deposit(address indexed depositor, bytes32 pubkey, uint256 amount);
    event Withdrawal(bytes32 nullifier, address recipient, uint256 amount);

    function deposit(uint256 amount, bytes32 pubkey) external {
        token.transferFrom(msg.sender, address(this), amount);
        emit Deposit(msg.sender, pubkey, amount);
        // Operator watches events, credits off-chain balance
    }

    function withdraw(
        bytes calldata seal,
        bytes32 oldRoot,
        bytes32 newRoot,
        bytes32 nullifier,
        uint256 amount,
        address recipient
    ) external {
        require(oldRoot == stateRoot, "Stale state");
        require(!nullifiers[nullifier], "Already withdrawn");

        bytes memory journal = abi.encodePacked(
            oldRoot, newRoot, nullifier, amount, recipient
        );
        verifier.verify(seal, WITHDRAW_IMAGE_ID, sha256(journal));

        stateRoot = newRoot;
        nullifiers[nullifier] = true;
        token.transfer(recipient, amount);

        emit Withdrawal(nullifier, recipient, amount);
    }
}
```

---

## Security Model

### Threat Model

| Adversary | Capability |
|-----------|------------|
| Public observer | Sees all on-chain data |
| Malicious user | Tries to forge proofs, double-spend |
| Network attacker | Can delay/reorder transactions |

**NOT considered:**
- Malicious operator (trusted in this PoC)
- Side-channel attacks on proof generation

### Guarantees

| Property | Mechanism |
|----------|-----------|
| Balance privacy | ZK proofs reveal nothing beyond validity |
| No double-spend | Nullifiers are recorded on-chain |
| No forgery | Requires knowledge of secret key |
| State integrity | Root transitions validated by proofs |

### Limitations & Shortcuts (PoC Scope)

- **Centralized operator**: Data availability depends on single operator
  - Production: DA committee or on-chain calldata

- **No viewing keys**: Cannot selectively reveal to regulators
  - Production: Add optional disclosure mechanism

- **Simple key derivation**: `pubkey = sha256(secret_key)`
  - Production: Use proper EC key derivation

- **Fixed tree depth**: 20 levels hardcoded
  - Production: Make configurable

- **In-memory account storage**: PoC uses in-memory data structures
  - Production: Use a persistent database (SQLite, Postgres, etc.)

---

## Terminology

- **Commitment**: Hash that hides a value but can be verified later
- **Merkle Root**: Single hash representing entire tree state
- **Nullifier**: Unique identifier that prevents double-use of a commitment
- **Journal**: Public outputs from a RISC Zero proof
- **Seal**: The proof bytes that can be verified on-chain
- **Validium**: L2 where data is off-chain but validity is proven

## References

- [RISC Zero Documentation](https://dev.risczero.com/)
- [Tornado Cash (nullifier design)](https://tornado.cash/)
- [Zcash Protocol Specification](https://zips.z.cash/protocol/protocol.pdf)
- [Validium on ethereum.org](https://ethereum.org/en/developers/docs/scaling/validium/)
