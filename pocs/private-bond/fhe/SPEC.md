---
title: "Private Bond (Zama fhEVM)"
status: Draft
version: 0.1.0
authors: ["Yanis"]
created: 2026-01-28
iptf_use_case: "https://github.com/ethereum/iptf-map/blob/master/use-cases/use-case-private-bonds.md"
iptf_approach: "https://github.com/ethereum/iptf-map/blob/master/approaches/approach-private-bonds.md"
---

# Private Institutional Bond on Zama fhEVM

## Overview

This protocol implements confidential institutional bonds using Zama's fhEVM - a framework that enables Fully Homomorphic Encryption (FHE) on EVM-compatible chains. Unlike private UTXO approaches where users generate ZK proofs locally, FHE allows **computations on encrypted data** with computation delegated to off-chain coprocessors while encrypted state remains on-chain.

Key characteristics:

- **Account-based model**: Familiar ERC20-like interface with encrypted balances
- **On-chain encrypted computation**: Arithmetic and comparisons on ciphertexts
- **Threshold decryption**: Distributed key management (no single decryption authority)
- **ACL-based access**: Fine-grained control over who can decrypt what
- **EVM compatibility**: Standard Solidity with `@fhevm/solidity` library (FHE.sol)

The contract implements: bond lifecycle (issuance, transfer, redemption), whitelist enforcement, issuer admin controls, and regulatory viewing key support via ACLs.

## FHE vs ZK: Architectural Comparison

| Aspect | Private UTXO with ZK | FHE (Zama fhEVM) |
|--------|----------------------|------------------|
| State model | UTXO (notes, nullifiers) | Account-based (balances) |
| Privacy mechanism | Prove without revealing | Compute on encrypted data |
| Where computation happens | Off-chain (prover) | Off-chain (coprocessor) with on-chain encrypted state |
| Double-spend prevention | Nullifiers | Encrypted balance checks |
| Developer experience | New paradigm with DSLs (circuits, notes) | Familiar (ERC20-like)* |
| Client requirements | Local proving (compute-heavy) | Standard wallet + network decryption† |
| Trust model | Cryptographic only | Threshold network operators |

*Solidity with FHE library, but debugging encrypted state is non-trivial.

†**Vendor dependency consideration**: Decryption requires Zama's threshold network. Institutions face a choice: (a) rely on Zama's hosted infrastructure (potential vendor lock-in), or (b) operate their own threshold network nodes (significant operational cost, unclear feasibility for single institutions). This differs from ZK approaches where users hold their own decryption keys.

## Identity & Access Model

**Ethereum Address**: Standard EOA or contract address. Used for:

- Whitelist registry entries
- Balance ownership
- Transaction authorization
- ACL permissions (who can decrypt)

**Whitelist**: Public mapping of KYC-approved addresses maintained by issuer.

```solidity
mapping(address => bool) public whitelist;
```

**Enforcement**: All transfer functions verify both sender and recipient are whitelisted before executing encrypted operations.

**Privacy Model**: Participant addresses are visible on-chain (public whitelist). Balances and transfer amounts are encrypted. This aligns with institutional requirements: identities public, positions confidential.

**Issuer Role**: Privileged address stored in contract. Can:

- Mint bonds to investors (primary market)
- Manage whitelist (add/remove addresses)
- Transfer ownership
- Grant regulatory access via ACL

## Storage Structure

**Public State:**

```solidity
address public owner;                           // Issuer address
mapping(address => bool) public whitelist;      // KYC registry
uint64 public totalSupply;                      // Total bonds issued (public)
uint64 public maturityDate;                     // Unix timestamp
```

**Encrypted State:**

```solidity
mapping(address => euint64) internal _balances;
mapping(address => mapping(address => euint64)) internal _allowances;
```

- `euint64`: Encrypted 64-bit unsigned integer (Zama FHE library type)
- Balances and allowances remain encrypted at rest and during computation
- Only authorized addresses (via ACL) can request decryption

**Total Supply Visibility**: Unlike the other approaches, total supply is public. This is a design choice - making it encrypted would prevent observers from knowing the bond issuance size, but for institutional bonds this is typically public information. The confidential aspect is *who holds how much*, not the total outstanding.

> **Alternative Design**: Total supply could be encrypted (`euint64`) if the issuance size itself needs to be confidential. This would require the issuer to decrypt it when needed for reporting.

## Access Control List (ACL)

FHE ciphertexts are useless without decryption rights. Zama's ACL system controls who can decrypt what:

```solidity
// Grant address permission to decrypt a ciphertext
FHE.allow(ciphertext, address);

// Grant this contract permission (for internal operations)
FHE.allowThis(ciphertext);
```

**Automatic Grants**: When balances change, the contract grants decryption rights:

```solidity
function _transfer(address from, address to, euint64 amount) internal {
    // ... transfer logic ...

    // Grant decryption rights
    FHE.allow(_balances[from], from);  // Sender can see new balance
    FHE.allow(_balances[to], to);      // Recipient can see new balance
    FHE.allowThis(_balances[from]);    // Contract can verify in future
    FHE.allowThis(_balances[to]);
}
```

**Regulatory Access**: Issuer can grant regulators decryption rights to specific balances:

```solidity
function grantAuditAccess(address account, address auditor) external onlyOwner {
    FHE.allow(_balances[account], auditor);
}
```

## Primary Market: Issuance

The issuer deploys the contract with bond parameters, then mints to investors after off-chain payment confirmation.

**Initialization:**

```solidity
constructor(uint64 _totalSupply, uint64 _maturityDate) {
    owner = msg.sender;
    totalSupply = _totalSupply;
    maturityDate = _maturityDate;
    whitelist[msg.sender] = true;

    // Issuer starts with full supply (encrypted)
    _balances[msg.sender] = FHE.asEuint64(_totalSupply);
    FHE.allow(_balances[msg.sender], msg.sender);
    FHE.allowThis(_balances[msg.sender]);
}
```

**Distribution Flow:**

1. Investor completes KYC off-chain
2. Issuer adds investor to whitelist: `addToWhitelist(investor)`
3. Investor sends fiat payment via traditional rails
4. Issuer confirms payment receipt
5. Issuer transfers bonds: `transfer(investor, encryptedAmount)`
   - Amount is encrypted - observer sees transfer occurred but not size
   - Both issuer and investor can decrypt their resulting balances

**Minting (Alternative)**: For bonds issued over time, a `mint()` function could add to supply:

```solidity
function mint(address to, externalEuint64 encryptedAmount, bytes calldata inputProof)
    external onlyOwner
{
    require(whitelist[to], "Not whitelisted");
    euint64 amount = FHE.fromExternal(encryptedAmount, inputProof);
    _balances[to] = FHE.add(_balances[to], amount);
    // Update ACLs...
}
```

> **PoC Simplification**: For the PoC, we use fixed supply at deployment with transfers from issuer, matching the other approaches.

## Secondary Market: Trading

Peer-to-peer trading uses the encrypted approve/transferFrom pattern, similar to ERC20 but with encrypted amounts.

### Simple Transfer

```solidity
function transfer(address to, externalEuint64 encryptedAmount, bytes calldata inputProof)
    external
    returns (bool)
{
    require(whitelist[msg.sender] && whitelist[to], "Not whitelisted");

    euint64 amount = FHE.fromExternal(encryptedAmount, inputProof);
    _transfer(msg.sender, to, amount);
    return true;
}
```

The `externalEuint64` type represents an encrypted value produced off-chain and sent to the contract. The `inputProof` contains zero-knowledge proofs validating the ciphertext is well-formed.

### Encrypted Transfer Logic

```solidity
function _transfer(address from, address to, euint64 amount) internal {
    // Check sufficient balance (encrypted comparison)
    ebool hasEnough = FHE.le(amount, _balances[from]);

    // Conditional transfer: only executes if hasEnough is true
    // If false, transfer amount becomes 0 (no revert, preserves privacy)
    euint64 transferAmount = FHE.select(hasEnough, amount, FHE.asEuint64(0));

    // Update balances (encrypted arithmetic)
    _balances[from] = FHE.sub(_balances[from], transferAmount);
    _balances[to] = FHE.add(_balances[to], transferAmount);

    // Update ACLs
    FHE.allow(_balances[from], from);
    FHE.allow(_balances[to], to);
    FHE.allowThis(_balances[from]);
    FHE.allowThis(_balances[to]);

    emit Transfer(from, to);  // No amount in event (confidential)
}
```

**Privacy Note**: The `FHE.select()` pattern avoids reverts on insufficient balance, which would leak information. Instead, the transfer silently becomes zero. Applications should verify success by checking balance changes.

> **API Note**: As of fhEVM v0.7+, the library was renamed from `TFHE` to `FHE` and the package from `fhevm` to `@fhevm/solidity`. External encrypted inputs use `externalEuintXX` types with `FHE.fromExternal()` for validation.

### Approve and TransferFrom

For atomic DvP, the approval pattern enables third-party transfers:

```solidity
function approve(address spender, externalEuint64 encryptedAmount, bytes calldata inputProof)
    external
    returns (bool)
{
    euint64 amount = FHE.fromExternal(encryptedAmount, inputProof);
    _allowances[msg.sender][spender] = amount;

    FHE.allow(_allowances[msg.sender][spender], msg.sender);
    FHE.allow(_allowances[msg.sender][spender], spender);
    FHE.allowThis(_allowances[msg.sender][spender]);

    emit Approval(msg.sender, spender);
    return true;
}

function transferFrom(address from, address to, externalEuint64 encryptedAmount, bytes calldata inputProof)
    external
    returns (bool)
{
    require(whitelist[from] && whitelist[to], "Not whitelisted");

    euint64 amount = FHE.fromExternal(encryptedAmount, inputProof);
    _spendAllowance(from, msg.sender, amount);
    _transfer(from, to, amount);
    return true;
}
```

### Atomic DvP

For true atomic bond-for-stablecoin swaps, a DvP contract coordinates:

```solidity
contract ConfidentialDvP {
    function executeSwap(
        address bondContract,
        address stablecoinContract,
        address seller,      // Has bonds, wants stables
        address buyer,       // Has stables, wants bonds
        externalEuint64 bondAmount,
        externalEuint64 stableAmount,
        bytes calldata bondProof,
        bytes calldata stableProof
    ) external {
        // Both transfers in single transaction
        // If either fails (insufficient balance/allowance), both fail
        IConfidentialBond(bondContract).transferFrom(
            seller, buyer, bondAmount, bondProof
        );
        IConfidentialStable(stablecoinContract).transferFrom(
            buyer, seller, stableAmount, stableProof
        );
    }
}
```

**RFQ Flow:**

1. Buyer broadcasts Request for Quote off-chain
2. Seller responds with price
3. Both parties approve DvP contract for their respective tokens
4. Either party calls `executeSwap()` with agreed amounts
5. Atomic execution: both legs succeed or both fail

> **PoC Limitation**: Full atomic DvP requires a confidential stablecoin contract. For PoC, we demonstrate the bond contract only, with off-chain fiat settlement.

## Redemption & Maturity

At maturity, bondholders redeem their bonds for par value. The bond contract burns the investor's balance; settlement happens off-chain or via atomic swap with stablecoins.

### Maturity Enforcement

```solidity
modifier afterMaturity() {
    require(block.timestamp >= maturityDate, "Bond not mature");
    _;
}
```

### Redemption Flow

**Simple Burn (PoC approach):**

```solidity
function redeem(externalEuint64 encryptedAmount, bytes calldata inputProof)
    external
    afterMaturity
{
    require(whitelist[msg.sender], "Not whitelisted");

    euint64 amount = FHE.fromExternal(encryptedAmount, inputProof);

    // Verify sufficient balance
    ebool hasEnough = FHE.le(amount, _balances[msg.sender]);
    euint64 redeemAmount = FHE.select(hasEnough, amount, FHE.asEuint64(0));

    // Burn (subtract from balance, don't add anywhere)
    _balances[msg.sender] = FHE.sub(_balances[msg.sender], redeemAmount);

    // Update ACL
    FHE.allow(_balances[msg.sender], msg.sender);
    FHE.allowThis(_balances[msg.sender]);

    emit Redemption(msg.sender);  // Amount confidential
}
```

**Full Atomic Redemption (production):**

Similar to secondary market DvP - investor's bonds are burned while issuer's stablecoins transfer to investor, atomically.

### Privacy Properties

- Redemption amounts confidential (encrypted, only parties + auditors can decrypt)
- Redemption *occurrence* visible (event emitted, on-chain transaction)
- Total supply could optionally decrease (if tracked encrypted) or remain static (burn = transfer to zero address equivalent)

## Regulatory Viewing Keys

Regulators need read-only access to positions and transactions. FHE's ACL system provides granular control.

### Granting Access

The issuer can grant auditors decryption rights at various granularities:

**Per-account access:**

```solidity
function grantAuditAccess(address account, address auditor) external onlyOwner {
    FHE.allow(_balances[account], auditor);
}
```

**Bulk access (all current holders):**

```solidity
function grantBulkAuditAccess(address auditor, address[] calldata accounts)
    external onlyOwner
{
    for (uint i = 0; i < accounts.length; i++) {
        FHE.allow(_balances[accounts[i]], auditor);
    }
}
```

### Decryption Process

1. Regulator requests decryption via Zama Gateway
2. Gateway verifies ACL permissions
3. Threshold MPC network performs decryption (2/3 of 13 nodes required)
4. Plaintext returned to regulator

**Important**: Decryption is *requested*, not automatic. The regulator must actively query each balance they have access to.

### Access Scope Comparison

| Scope | FHE (Zama) | ZK (Aztec) |
|-------|------------|------------|
| Per-balance | Supported (native) | Not supported |
| Per-account | Supported | Supported (app-siloed IVK) |
| Historical transactions | Requires stored ciphertexts | Via viewing keys |
| Revocation | Not supported (once granted) | Not supported |

**Limitation**: Once ACL access is granted, it cannot be revoked. The regulator retains ability to decrypt that ciphertext. For time-limited access, the application would need to re-encrypt balances periodically (expensive).

### Audit Trail

The contract can maintain an encrypted audit log:

```solidity
struct AuditEntry {
    uint256 timestamp;
    address from;
    address to;
    euint64 amount;  // Encrypted
}

AuditEntry[] public auditLog;

function _logTransfer(address from, address to, euint64 amount) internal {
    auditLog.push(AuditEntry(block.timestamp, from, to, amount));
    // Grant auditor access to the amount
    FHE.allow(amount, auditorAddress);
}
```

> **PoC Simplification**: The PoC implements basic ACL grants without a full audit log structure.

## Security Model

### Trust Assumptions

| Component | Trust Requirement |
|-----------|-------------------|
| FHE cryptography | TFHE security (lattice-based) |
| Threshold network | 2/3 honest operators (9 of 13) |
| Coprocessor nodes | Majority honest for computation |
| AWS Nitro Enclaves | Hardware attestation integrity |
| Issuer | Honest for whitelist management |

### What Zama Protocol Provides

| Security Property | Mechanism |
|-------------------|-----------|
| Balance confidentiality | FHE encryption (TFHE) |
| Computation integrity | Publicly verifiable FHE ops |
| Decryption security | Threshold MPC (no single decryptor) |
| Access control | On-chain ACL, verified by KMS |

### What the Application Must Handle

| Concern | Mitigation |
|---------|------------|
| Whitelist censorship | Acceptable for regulated context |
| ACL management | Issuer grants appropriate access |
| Input validation | Proof verification on encrypted inputs |
| Front-running | Encrypted amounts reduce MEV, but tx ordering visible |

### Comparison with ZK Approaches

| Aspect | Custom UTXO | Aztec L2 | FHE (Zama) |
|--------|-------------|----------|------------|
| Single point of failure | Trusted relayer | Sequencer (decentralized) | Threshold network |
| Cryptographic assumptions | Poseidon, BN254 | Noir circuits | TFHE (lattice) |
| Hardware trust | None | None | AWS Nitro Enclaves |
| Decryption model | User keys only | User keys only | Threshold network |

### Known Limitations

**Threshold Network Dependency**: Unlike ZK approaches where users hold their own decryption keys, FHE requires the threshold network for any decryption. If the network is unavailable or compromised (>1/3 malicious), users cannot access their balances.

**Hardware Trust**: Current implementation relies on AWS Nitro Enclave attestation. The roadmap targets "ZK-MPC" to remove this dependency.

**No Revocation**: ACL permissions are permanent. Once granted, a regulator (or any address) retains decryption rights for that ciphertext.

**Gas Costs**: FHE operations are computationally expensive. While Zama optimizes via coprocessors, costs may exceed ZK approaches for complex operations.

## Contract Interface

```solidity
interface IConfidentialBond {
    // View functions
    function owner() external view returns (address);
    function totalSupply() external view returns (uint64);
    function maturityDate() external view returns (uint64);
    function whitelist(address account) external view returns (bool);

    // Encrypted balance (returns ciphertext, only authorized can decrypt)
    function balanceOf(address account) external view returns (euint64);

    // Admin functions
    function addToWhitelist(address account) external;
    function removeFromWhitelist(address account) external;
    function grantAuditAccess(address account, address auditor) external;
    function transferOwnership(address newOwner) external;

    // Token functions (encrypted amounts)
    function transfer(address to, externalEuint64 amount, bytes calldata proof) external returns (bool);
    function approve(address spender, externalEuint64 amount, bytes calldata proof) external returns (bool);
    function transferFrom(address from, address to, externalEuint64 amount, bytes calldata proof) external returns (bool);

    // Redemption
    function redeem(externalEuint64 amount, bytes calldata proof) external;

    // Events (amounts omitted for confidentiality)
    event Transfer(address indexed from, address indexed to);
    event Approval(address indexed owner, address indexed spender);
    event Redemption(address indexed holder);
    event WhitelistUpdated(address indexed account, bool status);
}
```

## Terminology

| Term | Definition |
|------|------------|
| euint64 | Encrypted 64-bit unsigned integer (internal contract type) |
| ebool | Encrypted boolean |
| externalEuint64 | Encrypted value produced off-chain, requires proof validation |
| FHE.fromExternal() | Validates and converts external encrypted input to internal type |
| ACL | Access Control List - determines who can decrypt ciphertexts |
| Threshold decryption | Decryption requiring cooperation of multiple parties (2/3) |
| Coprocessor | Off-chain node that executes FHE operations |
| KMS | Key Management Service - threshold MPC for decryption |
| Gateway | Zama component that coordinates decryption requests |
| TFHE | Fully Homomorphic Encryption over the Torus (underlying cryptography) |

---

## Appendix A: Encrypted Input Handling

Users submit encrypted values with zero-knowledge proofs to prevent malicious ciphertexts:

```solidity
import { FHE, euint64, externalEuint64 } from "@fhevm/solidity/lib/FHE.sol";
import { ZamaEthereumConfig } from "@fhevm/solidity/config/ZamaConfig.sol";

contract ConfidentialBond is ZamaEthereumConfig {
    function transfer(address to, externalEuint64 encryptedAmount, bytes calldata inputProof) external {
        // Validate proof and convert external input to internal encrypted type
        euint64 amount = FHE.fromExternal(encryptedAmount, inputProof);
        // ... rest of transfer logic
    }
}
```

**Key concepts:**

- `externalEuint64`: Represents an encrypted value produced off-chain by the user's wallet
- `inputProof`: Zero-knowledge proof of knowledge (ZKPoK) validating the ciphertext
- `FHE.fromExternal()`: Validates the proof and converts to internal `euint64` type
- Contract must inherit from `ZamaEthereumConfig` for fhEVM functionality

The proof ensures:
- Ciphertext is well-formed
- Encrypted under the correct network key
- Within valid range for the type

This prevents attacks where malicious ciphertexts could cause unexpected behavior during homomorphic operations.

---

## Appendix B: Requirements Coverage

| Requirement | Status | Notes |
|-------------|--------|-------|
| Off-chain settlement (primary market) | Supported | Fiat rails for initial subscription |
| Issuer minting | Supported | Fixed supply at init or incremental mint |
| Bond attributes (maturity) | Supported | Public maturity date, enforced on redeem |
| Bond attributes (ISIN/Asset ID) | PoC Gap | Single asset type assumed |
| Bond attributes (Coupon) | N/A | Zero-coupon bonds only |
| Atomic DvP (secondary market) | Supported | Via approve/transferFrom + DvP contract |
| RFQ matching flow | Supported | Off-chain negotiation, on-chain settlement |
| Redemption at maturity | Supported | Maturity check + burn |
| Burn mechanism | Supported | Balance subtraction (encrypted) |
| Whitelist (KYC addresses) | Supported | Public mapping |
| Whitelist validation | Supported | Checked on all transfers |
| Confidential amounts/balances | Supported | FHE encryption |
| Public participant identities | Supported | Addresses visible |
| Public timestamps | Supported | Block timestamps visible |
| Viewing keys for regulators | Supported | ACL-based decryption grants |
| Audit trail | Partial | Via ACL grants; structured log optional |
| Double-spend protection | Supported | Encrypted balance checks |
| Access control | Supported | Issuer/Investor separation |
| Finality | Supported | Host chain finality |
| Cost efficiency | TBD | FHE ops expensive; coprocessor mitigates |
| Key rotation | PoC Gap | Would require re-encryption |

---

## References

- [Zama fhEVM GitHub](https://github.com/zama-ai/fhevm)
- [Zama Protocol Litepaper](https://docs.zama.org/protocol/zama-protocol-litepaper)
- [fhEVM Quick Start Tutorial](https://docs.zama.org/protocol/solidity-guides/getting-started/quick-start-tutorial/turn_it_into_fhevm)
- [Encrypted Operations](https://docs.zama.org/protocol/solidity-guides/smart-contract/operations)
- [Encrypted Inputs](https://docs.zama.org/protocol/solidity-guides/smart-contract/inputs)
- [FHE Library Overview](https://docs.zama.org/protocol/protocol/overview/library)
- [Confidential ERC20 Reference](https://github.com/zama-ai/fhevm-contracts/blob/main/contracts/token/ERC20/ConfidentialERC20.sol)
