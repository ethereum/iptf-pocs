# Private Institutional Bond on Aztec L2

> **Status:** Complete
> **Privacy Primitive:** Confidential transfers via Aztec native notes

A zero-coupon bond protocol deployed on Aztec Network for native privacy. Transaction amounts stay private while maintaining regulatory compliance via on-chain whitelist.

## Overview

This is a proof-of-concept implementation of a privacy-preserving bond protocol on Aztec L2. Bondholders can trade and redeem bonds without revealing transaction amounts to the blockchain—amounts are encrypted in private notes.

### Key Features

- Zero-coupon bonds with maturity enforcement
- Native Aztec privacy (notes, nullifiers, encrypted state)
- Private peer-to-peer trading with atomic DvP support
- Redemption at maturity
- All amounts private; whitelist entries visible for KYC/AML compliance

## Repository Structure

#### `/contracts`

Aztec smart contract implementing the bond protocol.

- `src/main.nr` — Main contract (Noir)

#### `/SPEC.md`

Full specification covering identity model, storage structure, protocol flow, security assumptions, and privacy analysis. Includes appendix on Authentication Witness (authwit) pattern.

#### `/test.sh`

End-to-end demo script demonstrating the complete bond lifecycle.

## How It Works: Aztec Privacy Model

Aztec provides native privacy primitives that handle the complexity we built manually in the custom-utxo approach:

- **Notes**: Encrypted state owned by users
- **Nullifiers**: Prevent double-spending without revealing which note was spent
- **Private execution**: Proofs generated client-side, verified on-chain

### Privacy Guarantees

| Data                     | Visibility                           |
| ------------------------ | ------------------------------------ |
| Whitelist (who can hold) | Public                               |
| Individual balances      | Private                              |
| Transfer amounts         | Private                              |
| Total supply             | Public (but fixed at initialization) |

The fixed supply model prevents observers from deducing transaction amounts by watching supply changes.

## Cryptographic Assumptions

- **Aztec Protocol**: ZK-SNARK proofs, note encryption, nullifier uniqueness
- **Grumpkin Curve**: Aztec's native curve for note encryption and nullifiers
- **ECDH**: Secure key exchange for note encryption

## Threat Model

- **Decentralized Sequencer**: No single trusted relayer (unlike custom-utxo approach)
- **Encrypted Mempool**: Frontrunning mitigation built into Aztec
- **Issuer Trust**: Issuer controls whitelist (acceptable for regulated context)
- **Public Identities**: Participants linkable via whitelist (regulatory requirement)

## Getting Started

### Prerequisites

- [Docker](https://docs.docker.com/get-docker/)
- [Aztec Sandbox](https://docs.aztec.network/guides/developer_guides/getting_started)

### Build Everything

```bash
# 1. Start Aztec sandbox
aztec start --sandbox

# 2. Import test accounts (in a new terminal)
aztec-wallet import-test-accounts

# 3. Compile contract
cd contracts
aztec compile
```

## Demo: Full Bond Lifecycle

This walkthrough demonstrates the complete flow: issuance → whitelist → distribution → P2P trade → redemption.

### Terminal 1: Start Aztec Sandbox

```bash
aztec start --sandbox
```

Wait for "Aztec Sandbox is now ready". The sandbox provides pre-funded test accounts.

### Terminal 2: Run Demo Script

```bash
./test.sh
```

### Step 1: Issuer Deploys Bond Contract

```bash
aztec-wallet deploy private_bonds-PrivateBonds.json \
  --from accounts:test0 \
  --init initialize \
  --args 1000000 0
```

This will:

- Deploy the PrivateBonds contract
- Mint entire supply (1M) to issuer's private balance
- Set maturity date (0 for immediate in demo)

### Step 2: KYC & Whitelist Investors

```bash
# Add Investor A to whitelist
aztec-wallet send add_to_whitelist \
  --from accounts:test0 \
  --contract-address contracts:privatebonds \
  --args accounts:test1

# Add Investor B to whitelist
aztec-wallet send add_to_whitelist \
  --from accounts:test0 \
  --contract-address contracts:privatebonds \
  --args accounts:test2
```

Whitelist is public (regulatory requirement). Only whitelisted addresses can hold bonds.

### Step 3: Primary Market Distribution

```bash
# Issuer distributes 500k to Investor A (amount hidden)
aztec-wallet send distribute_private \
  --from accounts:test0 \
  --contract-address contracts:privatebonds \
  --args accounts:test1 500000

# Issuer distributes 300k to Investor B (amount hidden)
aztec-wallet send distribute_private \
  --from accounts:test0 \
  --contract-address contracts:privatebonds \
  --args accounts:test2 300000
```

Observers see whitelist checks but NOT the amounts. Total supply unchanged.

### Step 4: Secondary Market Trading

```bash
# Investor A sells 100k to Investor B (amount hidden)
aztec-wallet send transfer_private \
  --from accounts:test1 \
  --contract-address contracts:privatebonds \
  --args accounts:test2 100000
```

This is the most private operation:

- Sender: Hidden (note consumption reveals nothing)
- Recipient: Revealed via whitelist check
- Amount: Hidden

### Step 5: Redemption at Maturity

```bash
# Investor A redeems their bonds
aztec-wallet send redeem \
  --from accounts:test1 \
  --contract-address contracts:privatebonds \
  --args 400000

# Investor B redeems their bonds
aztec-wallet send redeem \
  --from accounts:test2 \
  --contract-address contracts:privatebonds \
  --args 400000
```

Bonds are burned. In production, a DvP contract would atomically exchange bonds for stablecoins.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      Aztec Wallet CLI                       │
│  ┌──────────┐  ┌────────────┐  ┌──────────┐  ┌──────────┐  │
│  │ Deploy   │  │ Distribute │  │ Transfer │  │  Redeem  │  │
│  └────┬─────┘  └─────┬──────┘  └────┬─────┘  └────┬─────┘  │
│       │              │              │              │        │
│       ▼              ▼              ▼              ▼        │
│  ┌──────────────────────────────────────────────────────┐  │
│  │            PXE (Private Execution Environment)       │  │
│  │         ZK Proof Generation + Note Management        │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                  Aztec L2 (ZK Rollup to Ethereum)           │
│  ┌─────────────────────────────────────────────────────┐   │
│  │              PrivateBonds Contract (Noir)            │   │
│  │                                                      │   │
│  │  Public State:                                       │   │
│  │    owner, whitelist, total_supply, maturity_date     │   │
│  │                                                      │   │
│  │  Private State:                                      │   │
│  │    private_balances (encrypted notes)                │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

## Test Accounts

The sandbox provides pre-funded test accounts:

| Account | Role       | Description                 |
| ------- | ---------- | --------------------------- |
| `test0` | Issuer     | Bond issuer / administrator |
| `test1` | Investor A | Institutional investor      |
| `test2` | Investor B | Institutional investor      |

## PoC Implementation Notes

This repository is a proof-of-concept. The following simplifications were made:

| Spec Feature                          | PoC Implementation                      | Rationale                                |
| ------------------------------------- | --------------------------------------- | ---------------------------------------- |
| Atomic DvP with stablecoin            | Simple `transfer_private` + off-chain   | No stablecoin contract on Aztec testnet  |
| Atomic redemption (bond ↔ stablecoin) | Simple `redeem` burn + off-chain fiat   | No stablecoin contract on Aztec testnet  |
| Bond attributes (ISIN/Asset ID)       | Single asset type assumed               | Simplifies contract for PoC              |
| Key rotation support                  | Not implemented                         | Aztec account abstraction handles keys   |
| Per-note selective disclosure         | Per-contract viewing keys (app-siloed)  | Native Aztec granularity; per-note needs custom ECDH |
| Merkle whitelist for privacy          | Public `Map<address, bool>`             | Simpler, acceptable for regulated context|

### Known Limitations

- **No stablecoin integration**: Redemption burns bonds; fiat settlement happens off-chain
- **Public whitelist**: Participants are linkable via whitelist reads (acceptable for KYC compliance)
- **Single bond type**: No multi-tranche or multi-maturity support
- **Viewing key scope**: App-siloed (per-contract) granularity; per-note disclosure requires custom implementation
- **Testnet only**: Not audited for production use

### What Aztec Provides (vs Custom UTXO)

This approach significantly reduces implementation complexity compared to the custom-utxo PoC:

| Component               | Custom UTXO           | Aztec L2              |
| ----------------------- | --------------------- | --------------------- |
| Note encryption         | Manual implementation | Protocol-native       |
| Nullifier management    | Manual implementation | Protocol-native       |
| Merkle tree             | Manual implementation | Protocol-native       |
| ZK circuit              | Manual Noir circuit   | Built into BalanceSet |
| Proof generation        | Manual bb CLI         | PXE handles it        |
| Double-spend prevention | Contract logic        | Protocol-native       |

## License

MIT
