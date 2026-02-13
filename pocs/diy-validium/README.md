# DIY Validium

A proof of concept for private institutional payments on Ethereum using a validium architecture with zero-knowledge proofs.

## What This Demonstrates

Institutions need blockchain guarantees -- immutability, settlement finality, auditability -- without exposing balances, transfer amounts, or counterparties. This PoC demonstrates a validium pattern: account state lives off-chain, while only Merkle roots and ZK validity proofs are posted on-chain.

Three operations cover the institutional lifecycle:

| Operation | What It Does | Business Use |
|-----------|-------------|-------------|
| **Transfer** | Private payment between accounts | Institutional settlements, stablecoin transfers |
| **Bridge** | ERC20 deposit (gated) + withdrawal (proven exit) | On/off ramp between public and private systems |
| **Disclosure** | Prove compliance without revealing data | Regulatory attestations, capital adequacy proofs |

### Why Not Just Use Prividium?

Prividium (ZKSync) is a full L2 -- you get privacy, but compliance logic is baked into the platform. **DIY Validium shows custom ZK compliance proofs as Rust functions.** The disclosure circuit is 40 lines of readable Rust that any engineer can audit:

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

See [SPEC.md](SPEC.md) for the full protocol specification, including a side-by-side comparison of the disclosure circuit in Rust, Circom, and Noir.

### How Does This Compare to Aztec?

Aztec is the most prominent privacy-native L2, using Noir as its circuit language. Different architecture, different tradeoffs:

| Dimension | DIY Validium (RISC Zero) | Aztec (Noir) |
|-----------|--------------------------|--------------|
| **Architecture** | Validium: off-chain data, on-chain proofs on L1 | Privacy-native L2 rollup with its own sequencer and DA |
| **Circuit Language** | Rust (general-purpose, large ecosystem) | Noir (ZK-specific DSL, growing ecosystem) |
| **Compliance Logic** | Custom Rust functions -- institutions write their own rules | Platform-level privacy; custom compliance requires Noir expertise |
| **Deployment Target** | Ethereum L1 directly (Solidity verifier contracts) | Aztec L2 (separate network, bridges to Ethereum) |
| **Gas Cost** | High per-proof (~200K--400K gas for STARK verification on L1) | Amortized across L2 block; users pay L2 fees |
| **Bridging** | Native -- ERC20 deposits/withdrawals directly on L1 | Requires L1-L2 bridge with messaging delay |
| **Privacy Model** | Selective: operator sees everything, users prove to auditors | Default encrypted notes; viewing keys for selective disclosure |
| **Data Availability** | Operator-held (trust assumption) | L2 DA layer with encrypted note storage |
| **Auditability** | Rust circuits readable by any engineer | Noir readable but requires ZK-DSL familiarity |

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
# Rust tests (Merkle tree, account store, circuit tests via dev mode)
RISC0_SKIP_BUILD=1 cargo test -p diy-validium-host

# Solidity tests (transfer verifier, bridge, disclosure verifier)
cd contracts && forge test --offline
```

### Run the E2E Demo

```bash
# Dev mode: uses fake proofs for fast iteration (~seconds)
RISC0_DEV_MODE=1 cargo run

# Real proving: generates actual STARK proofs (~minutes)
cargo run
```

The demo creates sample accounts, builds a Merkle tree, then runs all three operations end-to-end: transfer, withdrawal, and disclosure.

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
│       ├── transfer_circuit.rs      # Transfer circuit tests
│       ├── withdrawal_circuit.rs    # Withdrawal circuit tests
│       ├── disclosure_circuit.rs    # Disclosure circuit tests
│       └── account_store.rs         # Account store tests
├── methods/
│   ├── guest/
│   │   ├── crypto/                  # Shared crypto primitives (sha256, Merkle ops)
│   │   └── src/
│   │       ├── membership.rs        # Membership circuit (used by bridge deposit)
│   │       ├── transfer.rs          # Transfer circuit
│   │       ├── withdrawal.rs        # Withdrawal circuit
│   │       └── disclosure.rs        # Disclosure circuit (THE differentiator)
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
- RISC Zero STARK-based proof system (no trusted setup)
- Binary Merkle trees (depth 20 in spec, depth 4 in demo for speed)

**What is protected:**
- Individual account balances are hidden from public observers
- Transfer amounts and sender/recipient links are not revealed on-chain
- Compliance can be proven without revealing exact balances (disclosure proofs)

**What is NOT protected:**
- Malicious operator -- trusted to maintain correct off-chain state and data availability
- Traffic analysis and timing correlation
- Deposits and withdrawals are public -- privacy exists only between them

## Known Limitations

- **Centralized operator**: Single operator holds all account data. Production would use a DA committee or post calldata on-chain.
- **Hash-based disclosure keys**: Uses `SHA256(pubkey || auditor_pubkey || "disclosure_v1")`, not encryption-based viewing keys. Production would use threshold decryption or verifiable encryption.
- **Simple key derivation**: `pubkey = SHA256(secret_key)`. Production would use proper elliptic curve key derivation.
- **In-memory storage**: Account state is held in memory. Production would use a persistent database.
- **IMAGE_ID placeholders**: On-chain contracts use `bytes32(0)` as the guest image ID.
- **No transaction batching**: Each operation requires a separate proof.
- **Single ERC20**: Bridge supports one token.
- **Dev mode for tests**: Rust integration tests use `RISC0_DEV_MODE` (fake proofs) for speed.

## Security Disclaimer

**This is a proof of concept for research and evaluation purposes only.** Do not use in production without thorough security audits. The implementation may contain bugs, incomplete features, or cryptographic weaknesses. No guarantees of correctness, security, or fitness for any purpose.

## References

- [RISC Zero Documentation](https://dev.risczero.com/)
- [Zcash Protocol Specification](https://zips.z.cash/protocol/protocol.pdf)
- [Validium on ethereum.org](https://ethereum.org/en/developers/docs/scaling/validium/)
- [Penumbra -- Viewing Keys](https://protocol.penumbra.zone/)
- [Aztec -- Note Discovery](https://docs.aztec.network/)
