---
title: "Private Payment Requirements"
use_case: "https://github.com/ethereum/iptf-map/blob/master/use-cases/private-payments.md"
approach: "https://github.com/ethereum/iptf-map/blob/master/approaches/approach-private-payments.md"
---

# Confidential Payment Protocol Requirements

## 1. Core Problem
Institutional payment flows on public blockchains expose treasury operations, supplier relationships, and settlement patterns—revealing competitive intelligence to observers. The system must enable confidential stablecoin transfers while maintaining regulatory compliance and supporting high-frequency institutional operations.

## 2. Functional Requirements (MUST)
- **Shielding (Deposit)**:
  - Convert public ERC-20 stablecoins (USDC, EURC) into private notes.
  - Lock tokens in a shielding contract; mint corresponding private commitment.

- **Private Transfer**:
  - Peer-to-peer transfers between shielded balances.
  - Sender proves ownership and valid balance without revealing amount or recipient.

- **Unshielding (Withdraw)**:
  - Convert private notes back to public ERC-20 tokens.
  - Burn private commitment; release tokens from shielding contract.

- **Whitelist**:
  - Only KYC-verified addresses can shield, transfer, or unshield.
  - Registry must validate eligibility before any operation.

## 3. Privacy Requirements (MUST)
- **Confidential Data**: Payment amounts, counterparty identities, transaction patterns, and payment timing.
- **Public Data**:
  - Transaction existence (tx hash).
  - Anonymity set (aggregate only).
- **Regulatory Oversight**:
  - Viewing Keys: Capability to grant regulators read-only access to specific transaction details.
  - Audit Trail: System must maintain encrypted records for AML/CFT monitoring, tax reporting, and sanctions screening.

## 4. Security & Standards (MUST)
- **Double-spend Protection**: Cryptographic enforcement preventing reuse of spent funds.
- **Stablecoin Compatibility**: Must work with standard ERC-20 tokens without requiring issuer modifications.
- **Access Control**: Strict separation—only whitelisted participants can interact with the system.

## 5. Performance & Ops (MUST)
- **Finality**: Near real-time settlement (minutes, not hours).
- **Cost Efficiency**: Transaction costs must support high-frequency institutional operations (daily treasury flows).
- **Key Management**: Support for key rotation to align with institutional security policies.

## 6. Out of Scope
- Traditional payment rail integration (SWIFT, ISO 20022, ACH, SEPA).
- Consumer (B2C) payment flows.
- Cross-chain bridging.
- Fiat on/off ramps.
