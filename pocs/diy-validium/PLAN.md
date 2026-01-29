# DIY Validium PoC - Implementation Plan

Location: `iptf-pocs/pocs/diy-validium/`

## Vision

Build toward **private payments** in phases, starting simple and adding complexity. This is a Validium-style architecture: data lives off-chain (SQLite), proofs live on-chain.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                     Off-Chain (Operator)                     │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────┐  │
│  │   SQLite    │───▶│ Merkle Tree │───▶│   RISC Zero     │  │
│  │  Database   │    │  (in Rust)  │    │  Proof Gen      │  │
│  └─────────────┘    └─────────────┘    └────────┬────────┘  │
└─────────────────────────────────────────────────┼───────────┘
                                                  │
                                                  ▼
┌─────────────────────────────────────────────────────────────┐
│                      On-Chain (Sepolia)                      │
│  ┌─────────────────────────────────────────────────────┐    │
│  │  Smart Contract                                      │    │
│  │  - bytes32 stateRoot                                 │    │
│  │  - mapping(bytes32 => bool) nullifiers               │    │
│  │  - RISC Zero verifier                                │    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

---

## Tech Stack Decisions

| Component | Choice | Rationale |
|-----------|--------|-----------|
| ZK Framework | RISC Zero | Write circuits in Rust, good tooling |
| Hash Function | **SHA-256** | RISC Zero has hardware acceleration for SHA-256 |
| Off-chain Storage | SQLite | Simple, portable, sufficient for PoC |
| On-chain | Solidity/Sepolia | Standard EVM, testnet for iteration |
| Tree Structure | Binary Merkle Tree | Simple, well-understood |

**Critical Choice: SHA-256 over Keccak**
- RISC Zero's zkVM has accelerated SHA-256 proving
- Keccak would work but proofs are significantly slower
- For on-chain verification, we commit SHA-256 roots (not Keccak)

---

## Phase 1: Allowlist Membership

### What You Build
Prove "I'm on the approved list" without revealing which entry.

### Components
```
SQLite: allowlist.db (identity entries)
       ↓
Merkle Tree (computed in Rust)
       ↓
Root committed on-chain
       ↓
ZK proof: "I know a leaf in this tree"
```

### Spec
| Element | Detail |
|---------|--------|
| Leaf | `SHA256(pubkey)` |
| Private input | `pubkey`, `merkle_path`, `path_indices` |
| Public input | `merkle_root` |
| Circuit | Recompute root from leaf+path, assert matches |
| On-chain | `bytes32 root` + optional `mapping nullifiers` |

### What You Learn
- RISC Zero basics
- Merkle proofs in circuits
- On-chain verification

---

## Phase 2: Private Balance State

### What You Add
Instead of just proving membership, prove **properties** of your entry.

### Components
```
SQLite: accounts.db (pubkey, balance, salt)
       ↓
Merkle Tree of account commitments
       ↓
Root on-chain
       ↓
ZK proof: "I have an account with balance >= X"
```

### Spec
| Element | Detail |
|---------|--------|
| Leaf (commitment) | `SHA256(pubkey \|\| balance \|\| salt)` |
| Private input | `pubkey`, `balance`, `salt`, `merkle_path` |
| Public input | `merkle_root`, `required_amount` |
| Circuit | Prove membership AND `balance >= required_amount` |
| On-chain | `bytes32 accountsRoot` |

**Commitment Scheme Rationale:**
- `pubkey`: identifies the account owner
- `balance`: the value being hidden
- `salt`: prevents rainbow table attacks on balance

### What You Learn
- Combining membership + range proofs
- Commitment schemes (hiding account details)

---

## Phase 3: Private Transfers

### What You Add
State transitions: "I'm spending from my balance, creating new state"

### Components
```
SQLite: accounts.db (pubkey, balance, salt)
       ↓
Old root → ZK proof → New root
       ↓
Nullifier (prevents double-spend)
       ↓
On-chain: update root, record nullifier
```

### Spec
| Element | Detail |
|---------|--------|
| Nullifier | `SHA256(sender.secret_key \|\| "nullifier_domain")` |
| Private input | `sender_sk`, `sender_balance`, `sender_salt`, `amount`, `recipient_pubkey`, `merkle_paths` |
| Public input | `old_root`, `new_root`, `nullifier` |
| Circuit | 1) Derive sender_pubkey from sender_sk; 2) Prove sender in old tree with balance >= amount; 3) Compute nullifier; 4) Compute new state; 5) Assert new root matches |
| On-chain | `bytes32 stateRoot` + `mapping(bytes32 => bool) nullifiers` |

**Nullifier Design:**
- Derived from secret key + domain separator
- Same account always produces same nullifier → prevents double-spend
- Different domain separator could enable multiple "spending types"

### What You Learn
- Nullifier schemes
- State transition proofs
- Account model with privacy

---

## Phase 4: Tokenization (ERC20 Bridge)

### What You Add
Connect the private system to real on-chain assets via deposit/withdraw.

### Components
```
ERC20 Token (on-chain)
       ↓ deposit
Private Balance System
       ↓ withdraw
ERC20 Token (on-chain)
```

### Spec
| Element | Detail |
|---------|--------|
| Deposit | User locks ERC20, operator credits private balance, updates root |
| Withdraw | User proves private balance ownership, burns private balance, unlocks ERC20 |
| Private input (withdraw) | `pubkey`, `balance`, `salt`, `withdraw_amount`, `merkle_path`, `secret_key` |
| Public input (withdraw) | `old_root`, `new_root`, `nullifier`, `withdraw_amount`, `recipient_address` |
| On-chain | ERC20 escrow + state root + nullifiers |

### What You Learn
- Bridging private ↔ public state
- Atomic deposit/withdraw flows
- Trust assumptions in operator model

---

## How the Phases Connect

```
Phase 1          Phase 2              Phase 3              Phase 4
┌─────────┐      ┌─────────────┐      ┌────────────────┐   ┌─────────────┐
│ Merkle  │  →   │ Merkle +    │  →   │ State          │ → │ ERC20       │
│ Member- │      │ Property    │      │ Transitions    │   │ Bridge      │
│ ship    │      │ Proofs      │      │ + Nullifiers   │   │             │
└─────────┘      └─────────────┘      └────────────────┘   └─────────────┘
    ↓                  ↓                     ↓                    ↓
"I'm on list"    "I have >= X"      "I sent X to Bob"    "Deposit/Withdraw"
```

---

## SQLite Integration

All phases use the same pattern:

```rust
// Host program (not in ZK, manages data)
let db = Connection::open("accounts.db")?;

// Query data
let accounts: Vec<Account> = db.query_map(
    "SELECT pubkey, balance, salt FROM accounts",
    |row| Account {
        pubkey: row.get(0),
        balance: row.get(1),
        salt: row.get(2)
    }
)?;

// Build Merkle tree with SHA-256
let leaves: Vec<[u8; 32]> = accounts.iter()
    .map(|a| sha256(&[&a.pubkey[..], &a.balance.to_le_bytes(), &a.salt[..]].concat()))
    .collect();
let tree = MerkleTree::new(leaves);

// Generate proof for specific account
let proof = tree.get_proof(index);

// Feed to RISC Zero guest
let receipt = prover.prove(guest_code, (account, proof, required_amount))?;
```

---

## File Structure

```
iptf-pocs/pocs/diy-validium/
├── README.md               # Overview and instructions
├── REQUIREMENTS.md         # Formal requirements
├── SPEC.md                 # Protocol specification
├── PLAN.md                 # This file
├── CHANGELOG.md            # Change history
├── Cargo.toml              # Rust workspace
├── contracts/
│   ├── foundry.toml
│   └── src/
│       ├── Verifier.sol         # Phase 1: membership
│       ├── BalanceVerifier.sol  # Phase 2: balance proofs
│       ├── TransferVerifier.sol # Phase 3: transfers
│       └── Bridge.sol           # Phase 4: ERC20 bridge
├── methods/
│   ├── guest/
│   │   └── src/
│   │       ├── membership.rs    # Phase 1 circuit
│   │       ├── balance.rs       # Phase 2 circuit
│   │       └── transfer.rs      # Phase 3 circuit
│   └── build.rs
├── host/
│   └── src/
│       ├── main.rs              # CLI entrypoint
│       ├── merkle.rs            # Merkle tree implementation
│       └── db.rs                # SQLite interface
├── data/
│   └── sample.db                # Sample SQLite data
└── scripts/
    ├── setup.sh
    └── demo.sh
```

---

## Verification (How to Test)

1. **Local proof generation**
   ```bash
   cd iptf-pocs/pocs/diy-validium
   cargo run --release -- prove-membership
   ```

2. **Sepolia deployment**
   ```bash
   cd contracts
   forge script script/Deploy.s.sol --rpc-url sepolia --broadcast
   ```

3. **End-to-end demo**
   ```bash
   ./scripts/demo.sh
   # Should output:
   # - Merkle root: 0x...
   # - Proof generated (seal + journal)
   # - Tx submitted: https://sepolia.etherscan.io/tx/...
   # - Verification: SUCCESS
   ```

---

## Sanity Check Answers

**Q1: Is Merkle membership the right starting point?**
Yes. It establishes the full pipeline (data → tree → proof → verify) with minimal circuit complexity.

**Q2: RISC Zero circuit for Merkle proof - any gotchas?**
- Use SHA-256 (hardware accelerated in RISC Zero), not Keccak
- Tree depth of 20-32 is reasonable (1M-4B leaves)
- Path encoding: use `Vec<bool>` for left/right direction

**Q3: How much harder is Phase 3 vs Phase 1?**
Significantly harder:
- Phase 1: ~50 lines of circuit logic
- Phase 3: ~200+ lines (state transitions, nullifiers, multiple tree operations)
- But each phase builds on the previous, so the learning curve is manageable

**Q4: SQLite → Merkle tree → ZK proof - is this pattern sound?**
Yes, this is the Validium model:
- Data availability: operator holds full state (trust assumption)
- Validity: proofs guarantee correctness
- For production: consider data availability committee or on-chain calldata

**Q5: What's missing to call this "private payments"?**
- Transaction graph privacy (batch multiple transfers)
- Decentralized sequencing (currently single operator)
- Regulatory compliance hooks (viewing keys, audit trails)
- Key management (recovery, rotation)
