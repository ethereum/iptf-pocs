# Shielded Pool Extension: PIR + Epoch Nullifiers

Extension of the [shielded-pool](../shielded-pool/) private-payments construction with:

- PIR over the wallet's pre-spend tree reads, closing the state-read privacy leak at the indexer/RPC layer.
- Epoch-based nullifiers with a per-note recursive chain proof (IVC), bounding the on-chain nullifier set without imposing linear per-spend work as notes age.

The note format, deposit, and attestation flows of the parent are preserved. The commitment is extended to bind `epoch_created` so the on-chain verifier can enforce that a spend's chain proof covers the note's full lifetime.

## Status

Implementation in progress. The protocol is proof-system agnostic; see [SPEC.md](./SPEC.md) for the abstract requirements an implementation must meet. This folder is a self-contained PoC (no cross-PoC imports from `../shielded-pool/`); any source mirrored from the parent is duplicated locally per the repo's PoC-independence rule.

## Layout

```
shielded-pool-extension/
├── SPEC.md                 protocol specification (primary deliverable)
├── README.md               this file
├── Cargo.toml              wallet / off-chain Rust workspace
├── Nargo.toml              Noir circuit workspace
├── foundry.toml            Solidity build config
├── circuits/
│   ├── deposit/            extended deposit circuit
│   ├── transfer/           extended spend circuit (recursive chain-proof verify)
│   ├── withdraw/           extended spend circuit (recursive chain-proof verify)
│   └── chain_update/       new IVC chain-update circuit
├── contracts/
│   ├── src/                ShieldedPoolExt, interfaces, verifiers
│   ├── script/             deploy scripts
│   └── test/               forge tests
├── scripts/
│   └── generate-verifiers.sh
└── src/lib/                Rust wallet, PIR client, prover/channel adapters
```

## Prerequisites

- [Foundry](https://getfoundry.sh/introduction/installation)
- [Nargo](https://noir-lang.org/docs/getting_started/noir_installation)
- [Barretenberg](https://barretenberg.aztec.network/docs/getting_started)
- Rust toolchain (pinned via `rust-toolchain.toml`)

## Installation

```bash
cd pocs/private-payment/shielded-pool-extension
forge soldeer install
cp .env.example .env
```

## Build & Test

```bash
# Contracts
forge build
forge test

# Circuits
nargo compile --workspace
nargo test --workspace

# Wallet
cargo test --lib

# Regenerate Solidity verifiers after circuit changes
chmod +x scripts/generate-verifiers.sh
./scripts/generate-verifiers.sh
```

## Documents

- [SPEC.md](./SPEC.md) — protocol specification
- Parent SPEC: [`../shielded-pool/SPEC.md`](../shielded-pool/SPEC.md)
- Parent REQUIREMENTS: [`../REQUIREMENTS.md`](../REQUIREMENTS.md)

## Security disclaimer

Research prototype, not production-ready. Cryptographic assumptions and known shortcuts are documented in [SPEC.md](./SPEC.md).
