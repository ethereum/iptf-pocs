---
title: "DIY Prividium Requirements"
use_case: "Private institutional payments"
approach: "Validium with ZK proofs"
---

# DIY Prividium Requirements

## 1. Core Problem

Financial institutions need to transact on Ethereum while keeping balances and transaction details confidential from public observers, competitors, and unauthorized parties.

> Goal: Demonstrate a minimal private payment system using ZK proofs, progressing from simple membership proofs to full private transfers.

## 2. Functional Requirements (MUST)

### Phase 1: Allowlist Membership

- **FR1.1**: Operator can create and maintain an allowlist of authorized participants
- **FR1.2**: Operator can compute and publish the Merkle root of the allowlist on-chain
- **FR1.3**: User can generate a ZK proof of allowlist membership without revealing their identity
- **FR1.4**: Smart contract can verify membership proofs against the published root
- **FR1.5**: (Optional) Contract can record nullifiers to prevent proof reuse

### Phase 2: Private Balance State

- **FR2.1**: Operator can maintain account balances off-chain (SQLite)
- **FR2.2**: Account state is committed as: `SHA256(pubkey || balance || salt)`
- **FR2.3**: User can prove they have balance >= X without revealing actual balance
- **FR2.4**: Operator can update the state root when balances change
- **FR2.5**: Contract stores and validates the current accounts root

### Phase 3: Private Transfers

- **FR3.1**: User can transfer value to another user privately
- **FR3.2**: Transfer proof demonstrates:
  - Sender owns an account in the current state
  - Sender has sufficient balance
  - State transition is computed correctly
  - Nullifier prevents double-spend
- **FR3.3**: Contract updates state root and records nullifier atomically
- **FR3.4**: Recipient's balance is updated off-chain by operator

### Phase 4: Tokenization (ERC20 Bridge)

- **FR4.1**: User can deposit ERC20 tokens to receive private balance
- **FR4.2**: User can withdraw private balance to receive ERC20 tokens
- **FR4.3**: Deposit: tokens locked in escrow, operator credits private balance
- **FR4.4**: Withdraw: user proves ownership, tokens released from escrow
- **FR4.5**: Total private supply equals total escrowed tokens (conservation)

### Access Control

- **AC1**: Only operator can update state roots
- **AC2**: Anyone can submit valid proofs for verification
- **AC3**: Nullifier registry prevents double-spending

## 3. Privacy Requirements (MUST)

### Confidential Data (hidden from public)

- Individual account balances
- Account ownership (which pubkey has what balance)
- Transfer amounts
- Sender/recipient relationship in transfers

### Public Data (visible on-chain)

- Merkle roots (allowlist root, accounts root)
- Nullifiers (opaque 32-byte values)
- Proof validity (pass/fail)
- Total deposited/withdrawn amounts (Phase 4)
- Contract events and timestamps

### Regulatory Oversight

Out of scope for MVP. Future considerations:
- Viewing keys for selective disclosure
- Audit trail generation
- Compliance hooks

## 4. Security Requirements (MUST)

- **SR1: No Double-Spend**: Nullifier scheme prevents spending the same balance twice
- **SR2: No Forgery**: Cannot create valid proofs for accounts you don't own (requires secret key)
- **SR3: No Replay**: Proofs are bound to specific state roots
- **SR4: Balance Conservation**: Transfers cannot create or destroy value
- **SR5: Root Integrity**: Only valid state transitions can update the root

## 5. Operational Requirements (MUST)

- **Finality**: Proof verification is immediate (single transaction)
- **Cost**: Verification gas cost should be reasonable (<500k gas target)
- **Operator Model**: Centralized operator for MVP (trust assumption documented)
- **Key Management**: Users manage their own secret keys (no recovery mechanism in MVP)

## 6. Out of Scope (PoC)

The following are explicitly NOT addressed in this PoC:

- **Decentralized sequencing**: Single operator model only
- **Data availability guarantees**: No DA committee or on-chain calldata
- **Viewing keys / regulatory disclosure**: No selective reveal mechanism
- **Key recovery**: No social recovery or backup schemes
- **Transaction batching**: Single proof per operation
- **Cross-chain**: Sepolia testnet only
- **Production security audit**: This is a PoC, not production-ready code
- **MEV protection**: No private mempool or commit-reveal
- **Multi-asset**: Single token type only (Phase 4)
