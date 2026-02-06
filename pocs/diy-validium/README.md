# DIY Validium

A proof of concept for private institutional payments on Ethereum using a validium architecture with zero-knowledge proofs.

## What This Demonstrates

Institutions need blockchain guarantees -- immutability, settlement finality, auditability -- without exposing balances, transfer amounts, or counterparties to public observers. This PoC demonstrates a validium pattern: account state lives off-chain in the operator's database, while only Merkle roots and ZK validity proofs are posted on-chain. The result is Ethereum's security model with database-level privacy.

See [SPEC.md](SPEC.md) for the full protocol specification.

## Architecture Overview

```
Off-chain (Operator)          ZK Layer (RISC Zero)         On-chain (Ethereum)
+-----------------------+     +---------------------+     +---------------------+
| Account database      | --> | Prove state valid   | --> | Verify proof        |
| - pubkeys, balances   |     | - Membership        |     | - Store Merkle root |
| - salts, Merkle tree  |     | - Balance >= X      |     | - Record nullifiers |
|                       |     | - Transfer correct   |     | - Emit events       |
+-----------------------+     +---------------------+     +---------------------+
```

Data stays private. Only roots and proofs touch the chain.

## Phases

| Phase | Description | Status |
|-------|-------------|--------|
| **1. Allowlist Membership** | Prove you belong to an approved set without revealing your identity | Implemented |
| **2. Private Balance Proofs** | Prove balance >= X without revealing actual balance | Implemented |
| **3. Private Transfers** | Transfer value between accounts with ZK-proven state transitions | Implemented |
| **4. ERC20 Bridge** | Deposit/withdraw between on-chain ERC20 and private balances | Spec only |

## Prerequisites

- **Rust** 1.75+ with the `nightly` toolchain
- **RISC Zero toolchain** -- install via [rzup](https://dev.risczero.com/api/zkvm/install):
  ```
  curl -L https://risczero.com/install | bash
  rzup install
  ```
- **Foundry** (`forge`, `cast`) -- install via [foundryup](https://book.getfoundry.sh/getting-started/installation)

No Node.js required.

## Build and Run

### Build

```bash
cd pocs/diy-validium

# Dev build (skips guest ELF compilation for faster iteration)
RISC0_SKIP_BUILD=1 cargo build

# Full build (compiles guest programs -- slow, requires RISC Zero toolchain)
cargo build
```

### Run Tests

```bash
# Rust tests (Merkle tree, account store, circuit tests via dev mode)
RISC0_SKIP_BUILD=1 cargo test -p diy-validium-host

# Solidity tests (MembershipVerifier, BalanceVerifier)
cd contracts && forge test --offline
```

### Run the E2E Demo

```bash
# Dev mode: uses fake proofs for fast iteration (~seconds)
RISC0_DEV_MODE=1 cargo run

# Real proving: generates actual STARK proofs (~minutes)
cargo run
```

The demo creates sample accounts, builds a Merkle tree, then runs Phase 1 (membership proof), Phase 2 (balance proof), and Phase 3 (transfer proof with dual-leaf state transition) end-to-end.

### Deploy Contracts

```bash
cd contracts

# Local deployment with mock verifier
forge script script/Deploy.s.sol --broadcast

# Testnet deployment (set RPC_URL and provide a real verifier)
VERIFIER_ADDRESS=0x... ALLOWLIST_ROOT=0x... ACCOUNTS_ROOT=0x... \
  forge script script/Deploy.s.sol --rpc-url $RPC_URL --broadcast
```

If `VERIFIER_ADDRESS` is not set, the script deploys a `MockRiscZeroVerifier` that accepts all proofs (suitable for testing only).

## Project Structure

```
diy-validium/
├── SPEC.md                          # Protocol specification (main deliverable)
├── REQUIREMENTS.md                  # Formal requirements from use case
├── Cargo.toml                       # Rust workspace root
├── host/
│   ├── src/
│   │   ├── main.rs                  # E2E demo (Phase 1 + Phase 2 + Phase 3)
│   │   ├── merkle.rs                # Merkle tree + proof generation
│   │   └── accounts.rs              # Account model + store
│   └── tests/                       # Integration tests
├── methods/
│   ├── guest/src/
│   │   ├── membership.rs            # Phase 1 ZK circuit
│   │   ├── balance.rs               # Phase 2 ZK circuit
│   │   └── transfer.rs              # Phase 3 ZK circuit
│   └── src/lib.rs                   # ELF + image ID exports
└── contracts/
    ├── src/
    │   ├── MembershipVerifier.sol    # Phase 1 on-chain verifier
    │   ├── BalanceVerifier.sol       # Phase 2 on-chain verifier
    │   └── TransferVerifier.sol      # Phase 3 on-chain verifier
    ├── test/                         # Foundry tests
    └── script/Deploy.s.sol           # Deployment script
```

## Cryptographic Assumptions and Threat Model

**Primitives:**
- SHA-256 for commitments and Merkle tree hashing (hardware-accelerated in RISC Zero)
- RISC Zero STARK-based proof system (no trusted setup)
- Binary Merkle trees (depth 20 in spec, depth 4 in demo for speed)

**What is protected:**
- Individual account balances are hidden from public observers
- Transfer amounts and sender/recipient links are not revealed on-chain
- Allowlist membership can be proven without disclosing identity

**What is NOT protected:**
- Malicious operator -- the operator is trusted to maintain correct off-chain state and data availability
- Traffic analysis and timing correlation
- Side-channel attacks on proof generation
- Regulatory visibility -- no viewing keys or selective disclosure in this PoC

## Known Limitations

- **Centralized operator**: Single operator holds all account data. Production would use a DA committee or post calldata on-chain.
- **No viewing keys**: No mechanism for selective disclosure to regulators or auditors.
- **Simple key derivation**: `pubkey = SHA256(secret_key)`. Production would use proper elliptic curve key derivation.
- **In-memory storage**: Account state is held in memory. Production would use a persistent database.
- **IMAGE_ID placeholders**: On-chain contracts use `bytes32(0)` as the guest image ID. Must be updated with real compiled image IDs before testnet deployment.
- **No transaction batching**: Each operation requires a separate proof. Production would batch multiple transfers.
- **Dev mode for tests**: Rust integration tests use `RISC0_DEV_MODE` (fake proofs) for speed.

## Security Disclaimer

**This is a proof of concept for research and evaluation purposes only.** Do not use in production without thorough security audits. The implementation may contain bugs, incomplete features, or cryptographic weaknesses. No guarantees of correctness, security, or fitness for any purpose.

## References

- [RISC Zero Documentation](https://dev.risczero.com/)
- [Tornado Cash -- Nullifier Design](https://tornado.cash/)
- [Zcash Protocol Specification](https://zips.z.cash/protocol/protocol.pdf)
- [Validium on ethereum.org](https://ethereum.org/en/developers/docs/scaling/validium/)
