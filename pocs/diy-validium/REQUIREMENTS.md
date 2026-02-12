---
title: "DIY Validium Requirements"
use_case: "Private institutional payments"
approach: "Validium with ZK proofs"
---

# DIY Validium Requirements

## 1. Core Problem

Financial institutions need to transact on Ethereum while keeping balances and transaction details confidential from public observers, competitors, and unauthorized parties. They also need to prove compliance to regulators without revealing sensitive data.

> Goal: Demonstrate a minimal private payment system with three core operations: transfer, bridge, and disclosure.

## 2. Functional Requirements (MUST)

### Transfer (Private Payment)

- **FR1.1**: User can transfer value to another user privately
- **FR1.2**: Transfer proof demonstrates: sender owns an account in the current state, sender has sufficient balance, state transition is correct, nullifier prevents double-spend
- **FR1.3**: Contract updates state root and records nullifier atomically
- **FR1.4**: Recipient's balance is updated off-chain by operator

### Bridge (Deposit + Withdrawal)

- **FR2.1**: User can deposit ERC20 tokens to receive private balance
- **FR2.2**: Deposits are gated by allowlist membership proof
- **FR2.3**: User can withdraw private balance to receive ERC20 tokens
- **FR2.4**: Withdrawal proof demonstrates: account ownership, sufficient balance, state transition, nullifier
- **FR2.5**: Total private supply equals total escrowed tokens (conservation)

### Disclosure (Compliance)

- **FR3.1**: User can prove balance >= threshold to a specific auditor
- **FR3.2**: Disclosure proof is bound to a specific auditor via disclosure key
- **FR3.3**: Disclosure is read-only (no state mutation, no nullifier)
- **FR3.4**: Auditor learns only that balance satisfies the threshold

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
- Total deposited/withdrawn amounts
- Contract events and timestamps

### Regulatory Oversight

- Disclosure proofs allow selective attestation to auditors
- Auditor learns balance >= threshold, nothing more

## 4. Security Requirements (MUST)

- **SR1: No Double-Spend**: Nullifier scheme prevents spending the same balance twice
- **SR2: No Forgery**: Cannot create valid proofs for accounts you don't own (requires secret key)
- **SR3: No Replay**: Proofs are bound to specific state roots
- **SR4: Balance Conservation**: Transfers cannot create or destroy value
- **SR5: Root Integrity**: Only valid state transitions can update the root

## 5. Operational Requirements (MUST)

- **Finality**: Proof verification is immediate (single transaction)
- **Cost**: Verification gas cost should be reasonable (<500k gas target)
- **Operator Model**: Centralized operator for PoC (trust assumption documented)
- **Key Management**: Users manage their own secret keys (no recovery mechanism)

## 6. Out of Scope (PoC)

- Decentralized sequencing (single operator only)
- Data availability guarantees (no DA committee or on-chain calldata)
- Key recovery or social recovery
- Transaction batching
- Multi-asset support
- Production security audit
- MEV protection
