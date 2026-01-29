---
title: "DIY Prividium"
status: Draft
version: 0.1.0
authors: []
created: 2026-01-29
iptf_use_case: "Private institutional payments"
iptf_approach: "Validium with ZK proofs"
---

# DIY Prividium: Protocol Specification

## Problem Statement

Financial institutions need to transact on Ethereum while maintaining confidentiality of balances and transaction details. Public blockchains expose all state to observers, making them unsuitable for sensitive financial operations without a privacy layer.

### Constraints

- **Privacy**: Balances and transfer amounts must remain confidential
- **Regulatory**: System must be auditable (future: viewing keys)
- **Operational**: Must integrate with existing Ethereum tooling
- **Trust**: Minimize trust assumptions while acknowledging PoC limitations

## Approach

### Strategy

Build a Validium-style system where:
- Full account state lives off-chain (SQLite database)
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
nullifier = SHA256(secret_key || "nullifier_domain")
```

- `secret_key`: 32 bytes
- `"nullifier_domain"`: ASCII string, padded/hashed

### On-Chain State

```solidity
contract PrividiumVerifier {
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
- `sender_path: Vec<[u8; 32]>`
- `sender_indices: Vec<bool>`
- `amount: u64`
- `recipient_pubkey: [u8; 32]`
- `recipient_balance: u64` (current)
- `recipient_salt: [u8; 32]`
- `recipient_path: Vec<[u8; 32]>`
- `recipient_indices: Vec<bool>`
- `new_sender_salt: [u8; 32]`
- `new_recipient_salt: [u8; 32]`

**Circuit Logic:**
```rust
fn verify_transfer(/* inputs */) {
    // 1. Derive sender pubkey from secret key
    let sender_pubkey = derive_pubkey(sender_sk);

    // 2. Compute sender's old commitment
    let sender_old_leaf = sha256(&[
        &sender_pubkey[..],
        &sender_balance.to_le_bytes()[..],
        &sender_salt[..]
    ].concat());

    // 3. Verify sender in old tree
    verify_membership(sender_old_leaf, &sender_path, &sender_indices, old_root);

    // 4. Check sufficient balance
    assert!(sender_balance >= amount);

    // 5. Compute nullifier
    let computed_nullifier = sha256(&[
        &sender_sk[..],
        b"nullifier_domain"
    ].concat());
    assert_eq!(computed_nullifier, nullifier);

    // 6. Compute new balances
    let new_sender_balance = sender_balance - amount;
    let new_recipient_balance = recipient_balance + amount;

    // 7. Compute new commitments
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

    // 8. Verify new tree structure
    // (simplified: in practice, need to update both leaves and recompute root)
    let computed_new_root = compute_new_root(
        sender_new_leaf, sender_indices,
        recipient_new_leaf, recipient_indices,
        old_root
    );
    assert_eq!(computed_new_root, new_root);
}
```

**Committed Outputs (Journal):**
- `old_root: [u8; 32]`
- `new_root: [u8; 32]`
- `nullifier: [u8; 32]`

### Contract: TransferVerifier

```solidity
contract TransferVerifier {
    bytes32 public stateRoot;
    mapping(bytes32 => bool) public nullifiers;
    IRiscZeroVerifier public verifier;
    bytes32 public constant IMAGE_ID = /* transfer circuit hash */;

    function executeTransfer(
        bytes calldata seal,
        bytes32 oldRoot,
        bytes32 newRoot,
        bytes32 nullifier
    ) external {
        // 1. Check old root matches current state
        require(oldRoot == stateRoot, "Stale state");

        // 2. Check nullifier not used
        require(!nullifiers[nullifier], "Double spend");

        // 3. Verify proof
        bytes memory journal = abi.encodePacked(oldRoot, newRoot, nullifier);
        verifier.verify(seal, IMAGE_ID, sha256(journal));

        // 4. Update state
        stateRoot = newRoot;
        nullifiers[nullifier] = true;

        emit Transfer(oldRoot, newRoot, nullifier);
    }
}
```

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
contract PrividiumBridge {
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
