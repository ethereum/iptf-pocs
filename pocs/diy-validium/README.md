# DIY Validium

A proof of concept for private institutional payments on Ethereum using a validium architecture with zero-knowledge proofs.

## What This Demonstrates

Institutions need blockchain guarantees -- immutability, settlement finality, auditability -- without exposing balances, transfer amounts, or counterparties. This PoC demonstrates a validium pattern: account state lives off-chain, while only Merkle roots and ZK validity proofs are posted on-chain.

Four operations cover the institutional lifecycle:

| Operation | What It Does | Business Use |
|-----------|-------------|-------------|
| **Transfer** | Private payment between accounts | Institutional settlements, stablecoin transfers |
| **Bridge** | ERC20 deposit (gated) + withdrawal (proven exit) | On/off ramp between public and private systems |
| **Disclosure** | Prove compliance without revealing data | Regulatory attestations, capital adequacy proofs |
| **Escape Hatch** | Emergency fund recovery when operator disappears or censors | Business continuity, regulatory fund access |

### Relationship to Prividium

DIY Validium and Prividium (ZKSync) are the same architecture: account-based validiums with off-chain state, on-chain roots, and ZK validity proofs. This PoC demonstrates how to build the pattern from scratch using RISC Zero, with compliance rules expressed as Rust guest programs. The disclosure proof is 40 lines of readable Rust that any engineer can audit:

```rust
// The full business logic of a disclosure proof:
let pubkey = sha256(&secret_key);
let leaf = account_commitment(&pubkey, balance, &salt);
let merkle_root = compute_root(leaf, &path, &indices);

assert!(balance >= threshold, "Balance below threshold");
let disclosure_key_hash =
    sha256(&[&pubkey[..], &auditor_pubkey[..], b"disclosure_v1"].concat());
```

Compare this to ~80 lines of Circom constraint wiring or a full zkEVM opcode table. For institutional auditors reviewing compliance logic, readability matters.

See [SPEC.md](SPEC.md) for the full protocol specification, including a comparison of the disclosure proof in Rust vs Circom and Noir.

### How Does This Compare to Aztec?

Aztec is the most prominent privacy-native L2, using Noir as its ZK language. Different architecture, different tradeoffs:

| Dimension | DIY Validium (RISC Zero) | Aztec (Noir) |
|-----------|--------------------------|--------------|
| **Architecture** | Validium: off-chain data, on-chain proofs on L1 | Privacy-native L2 rollup with its own sequencer and DA |
| **ZK Language** | Rust via RISC Zero zkVM (general-purpose, large ecosystem) | Noir (ZK-specific DSL, growing ecosystem) |
| **Compliance Logic** | Custom Rust functions -- institutions write their own rules | Platform-level privacy; custom compliance requires Noir expertise |
| **Deployment Target** | Ethereum L1 directly (Solidity verifier contracts) | Aztec L2 (separate network, bridges to Ethereum) |
| **Gas Cost** | High per-proof (~200K--300K gas for Groth16 verification on L1; STARKs are compressed to Groth16 before posting) | Amortized across L2 block; users pay L2 fees |
| **Bridging** | Native -- ERC20 deposits/withdrawals directly on L1 | Requires L1-L2 bridge with messaging delay |
| **Privacy Model** | Selective: operator sees everything, users prove to auditors | Default encrypted notes; viewing keys for selective disclosure |
| **Data Availability** | Operator-held (trust assumption) | L2 DA layer with encrypted note storage |
| **Auditability** | Rust guest programs readable by any engineer | Noir readable but requires ZK-DSL familiarity |

**DIY Validium wins on:** direct L1 settlement (no bridge delay), custom compliance in a mainstream language, simpler trust model to reason about, standard Solidity/Foundry tooling.

**Aztec wins on:** default privacy at scale, lower per-transaction cost (L2 amortization), mature privacy primitives (note discovery, encrypted memos), decentralized sequencing roadmap.

**The core tradeoff:** DIY Validium trades platform maturity and cost efficiency for direct L1 deployment and custom compliance logic in Rust. For institutions evaluating privacy, this PoC demonstrates the building blocks work -- the question is whether to build bespoke or adopt a platform.

## Architecture

```
Off-chain (Operator)          ZK Layer (RISC Zero)         On-chain (Ethereum)
+-----------------------+     +---------------------+     +---------------------+
| Account database      | --> | Prove state valid   | --> | Verify proof        |
| - pubkeys, balances   |     | - Transfer correct   |     | - Store Merkle root |
| - salts, Merkle tree  |     | - Withdrawal valid   |     | - Track state root  |
|                       |     | - Disclosure valid   |     | - Bridge ERC20      |
+-----------------------+     +---------------------+     +---------------------+
```

Data stays private. Only roots and proofs touch the chain.

## Prerequisites

- **Rust** 1.75+ with the `nightly` toolchain
- **RISC Zero toolchain** -- install via [rzup](https://dev.risczero.com/api/zkvm/install):
  ```
  curl -L https://risczero.com/install | bash
  rzup install
  ```
- **Foundry** (`forge`, `cast`) -- install via [foundryup](https://book.getfoundry.sh/getting-started/installation)

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
# Rust tests (Merkle tree, account store, guest program tests via dev mode)
RISC0_SKIP_BUILD=1 cargo test -p diy-validium-host

# Solidity tests (transfer verifier, bridge, disclosure verifier)
# Note: first run needs `forge test` (without --offline) to cache the solc binary
cd contracts && forge test --offline
```

### Run the E2E Demo

```bash
# Dev mode: uses fake proofs for fast iteration (~seconds)
RISC0_DEV_MODE=1 cargo run

# Real proving: generates STARK proofs locally (~minutes, not compressed to Groth16)
cargo run
```

The demo creates sample accounts, builds a Merkle tree, then runs three operations end-to-end: transfer, withdrawal, and disclosure. The escape hatch (Operation 4) is tested via Solidity tests only.

### Deploy Contracts

```bash
cd contracts

# Local deployment with mock verifier
forge script script/Deploy.s.sol --broadcast

# Testnet deployment (set RPC_URL and provide a real verifier + token)
VERIFIER_ADDRESS=0x... TOKEN_ADDRESS=0x... ALLOWLIST_ROOT=0x... ACCOUNTS_ROOT=0x... \
  forge script script/Deploy.s.sol --rpc-url $RPC_URL --broadcast
```

## Project Structure

```
diy-validium/
├── SPEC.md                          # Protocol specification (main deliverable)
├── REQUIREMENTS.md                  # Formal requirements from use case
├── Cargo.toml                       # Rust workspace root
├── host/
│   ├── src/
│   │   ├── main.rs                  # E2E demo (Transfer + Withdrawal + Disclosure)
│   │   ├── merkle.rs                # Merkle tree + proof generation
│   │   └── accounts.rs              # Account model + store
│   └── tests/                       # Integration tests
│       ├── transfer_circuit.rs      # Transfer proof tests
│       ├── withdrawal_circuit.rs    # Withdrawal proof tests
│       ├── disclosure_circuit.rs    # Disclosure proof tests
│       └── account_store.rs         # Account store tests
├── methods/
│   ├── guest/
│   │   ├── crypto/                  # Shared crypto primitives (sha256, Merkle ops)
│   │   └── src/
│   │       ├── membership.rs        # Membership guest program (used by bridge deposit)
│   │       ├── transfer.rs          # Transfer guest program
│   │       ├── withdrawal.rs        # Withdrawal guest program
│   │       └── disclosure.rs        # Disclosure guest program
│   └── src/lib.rs                   # ELF + image ID exports
└── contracts/
    ├── src/
    │   ├── TransferVerifier.sol     # Transfer on-chain verifier
    │   ├── ValidiumBridge.sol       # ERC20 bridge (deposit + withdrawal)
    │   └── DisclosureVerifier.sol   # Disclosure on-chain verifier
    ├── test/                        # Foundry tests
    └── script/Deploy.s.sol          # Deployment script
```

## Cryptographic Assumptions and Threat Model

**Primitives:**
- SHA-256 for commitments and Merkle tree hashing (hardware-accelerated in RISC Zero)
- RISC Zero STARK-based proof system (STARKs require no trusted setup; on-chain L1 verification uses Groth16 compression, which relies on RISC Zero's universal trusted setup)
- Binary Merkle trees (depth 20 in spec, depth 4 in demo for speed)

**What is protected:**
- Individual account balances are hidden from public observers
- Transfer amounts and sender/recipient links are not revealed on-chain
- Compliance can be proven without revealing exact balances (disclosure proofs)

**What is NOT protected:**
- Malicious operator -- trusted to maintain correct off-chain state and data availability
- Traffic analysis and timing correlation
- Deposits and withdrawals are public -- privacy exists only between them
- Escape withdrawals reveal full account details on-chain (privacy sacrificed for fund recovery)

## Known Limitations

- **Centralized operator**: Single operator holds all account data. Escape hatch (Operation 4) allows fund recovery after 7-day timeout, and forced withdrawals provide anti-censorship protection (operator must process or system freezes within 1 day). Users must save their account data after every transaction. Production would add DA layers (blob checkpoints) to reduce this burden.
- **Hash-based disclosure keys**: Uses `SHA256(pubkey || auditor_pubkey || "disclosure_v1")`, not encryption-based viewing keys. Production would use threshold decryption or verifiable encryption.
- **Simple key derivation**: `pubkey = SHA256(secret_key)`. Production would use proper elliptic curve key derivation.
- **In-memory storage**: Account state is held in memory. Production would use a persistent database.
- **IMAGE_IDs**: Contracts accept IMAGE_IDs as constructor params. The E2E test passes real IMAGE_IDs when guest ELFs are compiled; the deploy script defaults to `bytes32(0)` for local/testnet use.
- **No transaction batching**: Each operation requires a separate proof.
- **Single ERC20**: Bridge supports one token.
- **Dev mode for tests**: Rust integration tests use `RISC0_DEV_MODE` (fake proofs) for speed.
- **Escape hatch privacy trade-off**: Emergency withdrawal reveals `pubkey`, `balance`, and `salt` on-chain. Acceptable when the operator is gone and the alternative is losing funds.

## Security Disclaimer

**This is a proof of concept for research and evaluation purposes only.** Do not use in production without thorough security audits. The implementation may contain bugs, incomplete features, or cryptographic weaknesses. No guarantees of correctness, security, or fitness for any purpose.

## References

- [RISC Zero Documentation](https://dev.risczero.com/)
- [Zcash Protocol Specification](https://zips.z.cash/protocol/protocol.pdf)
- [Validium on ethereum.org](https://ethereum.org/en/developers/docs/scaling/validium/)
- [Penumbra -- Viewing Keys](https://protocol.penumbra.zone/)
- [Aztec -- Note Discovery](https://docs.aztec.network/)
