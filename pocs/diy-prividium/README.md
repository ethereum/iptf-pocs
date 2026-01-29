# DIY Prividium

> **Status:** Draft
> **Privacy Primitive:** Private balances and transfers with ZK proofs

## Overview

DIY Prividium demonstrates a privacy-preserving payment system built in phases:

1. **Allowlist Membership** - Prove you're on an approved list without revealing your identity
2. **Private Balances** - Prove you have sufficient balance without revealing the amount
3. **Private Transfers** - Transfer value privately between accounts
4. **Tokenization** - Bridge between private balances and on-chain ERC20 tokens

This is a Validium-style architecture: account data lives off-chain (SQLite), validity proofs live on-chain (Ethereum/Sepolia).

## Cryptographic Assumptions

- **Primitives used:** SHA-256 Merkle trees, RISC Zero zkVM proofs
- **Security assumptions:** Collision resistance of SHA-256, soundness of RISC Zero's STARK-based proof system
- **Trusted setup:** No trusted setup required (RISC Zero uses STARKs)

## Threat Model

What this protects against:
- Public observers cannot learn individual account balances
- Public observers cannot link transfers to specific accounts
- Validators cannot learn private data beyond what's explicitly revealed

What this does NOT protect against:
- Malicious operator (centralized data availability)
- Traffic analysis / timing correlation
- Side-channel attacks on proof generation
- Regulatory/compliance scenarios (no viewing keys in MVP)

## Tech Stack

| Component | Choice |
|-----------|--------|
| ZK Framework | RISC Zero |
| Hash Function | SHA-256 (accelerated in RISC Zero) |
| Off-chain Storage | SQLite |
| On-chain | Solidity on Sepolia |

## Building

Prerequisites:
- Rust 1.75+
- RISC Zero toolchain (`cargo install cargo-risczero`)
- Foundry (`forge`, `cast`)

```bash
# Install RISC Zero toolchain
cargo risczero install

# Build Rust components
cargo build --release

# Build Solidity contracts
cd contracts && forge build
```

## Running

```bash
# Phase 1: Generate membership proof
cargo run --release -- prove-membership --db data/sample.db --index 0

# Deploy verifier contract
cd contracts
forge script script/Deploy.s.sol --rpc-url sepolia --broadcast

# Run end-to-end demo
./scripts/demo.sh
```

## Tests

```bash
# Run Rust tests
cargo test

# Run Solidity tests
cd contracts && forge test
```

## Known Limitations

- **Centralized operator**: Single operator holds all account data (data availability risk)
- **No viewing keys**: No mechanism for selective disclosure to regulators
- **Single-threaded**: Proof generation is not parallelized
- **No batching**: Each transfer requires a separate proof (no transaction batching)
- **PoC security**: Not audited, not production-ready

## Project Structure

```
diy-prividium/
├── README.md           # This file
├── REQUIREMENTS.md     # Formal requirements
├── SPEC.md             # Protocol specification
├── PLAN.md             # Implementation roadmap
├── contracts/          # Solidity verifiers
├── methods/guest/      # RISC Zero circuits
├── host/               # Proof generation CLI
├── data/               # Sample SQLite databases
└── scripts/            # Demo and setup scripts
```

## References

- [RISC Zero Documentation](https://dev.risczero.com/)
- [Validium Architecture](https://ethereum.org/en/developers/docs/scaling/validium/)
- [IPTF Map: Private Payments](https://github.com/ethereum/iptf-map)
