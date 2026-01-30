# Private Bond (FHE Approach)

> **Status:** In Progress
> **Privacy Primitive:** Confidential bond transfers using Fully Homomorphic Encryption

## Overview

This implementation demonstrates a privacy-preserving zero-coupon bond using [Zama's fhEVM](https://docs.zama.org/fhevm) - a framework enabling Fully Homomorphic Encryption (FHE) on EVM-compatible chains.

Unlike ZK-based approaches where computations happen off-chain and are verified on-chain, FHE allows **computations directly on encrypted data on-chain**.

### Key Characteristics

| Aspect | Description |
|--------|-------------|
| State model | Account-based (ERC20-like interface) |
| Privacy mechanism | Homomorphic encryption (TFHE) |
| Balance storage | Encrypted (`euint64`) |
| Transfer amounts | Encrypted with ZK proof validation |
| Developer experience | Familiar Solidity with `@fhevm/solidity` |
| Trust model | Threshold network (2/3 of operators) |

## Prerequisites

- Node.js >= 20 (even-numbered LTS version)
- npm >= 7.0.0

## Quick Start

```bash
# Install dependencies
npm install

# Compile contracts
npm run compile

# Run tests (mock FHE - fast)
npm run test

# Run tests on Sepolia (real FHE - requires setup)
npm run test:sepolia
```

## Project Structure

```
fhe/
├── contracts/
│   └── ConfidentialBond.sol    # Main contract
├── test/
│   └── ConfidentialBond.test.ts  # Comprehensive test suite
├── hardhat.config.ts           # Hardhat + fhEVM configuration
├── package.json
├── tsconfig.json
├── SPEC.md                     # Protocol specification
└── README.md
```

## Contract Interface

```solidity
interface IConfidentialBond {
    // View functions
    function owner() external view returns (address);
    function totalSupply() external view returns (uint64);
    function maturityDate() external view returns (uint64);
    function whitelist(address account) external view returns (bool);
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
}
```

## Privacy Model

| Data | Visibility |
|------|------------|
| Participant addresses | Public (whitelist is visible) |
| Balances | Encrypted (only holder + authorized auditors can decrypt) |
| Transfer amounts | Encrypted |
| Total supply | Public (institutional transparency) |
| Maturity date | Public |

## Testing Modes

The fhEVM Hardhat plugin supports multiple runtime environments:

| Mode | Command | Encryption | Speed | Use Case |
|------|---------|------------|-------|----------|
| Mock (Hardhat) | `npm test` | Simulated | Fast (seconds) | Development, CI |
| Sepolia | `npm run test:sepolia` | Real FHE | Slow (minutes) | Production validation |

### Running Tests

```bash
# Mock mode (default) - fast, simulated encryption
npm run test

# Sepolia mode - real FHE (see below for setup)
npm run test:sepolia
```

## Testing on Sepolia (Real FHE)

Running tests on Sepolia executes real FHE operations using [Zama's coprocessor](https://www.zama.org/post/fhevm-coprocessor). This validates that the protocol works with actual homomorphic encryption, not just simulated operations.

### Prerequisites

1. **Sepolia ETH**: Get testnet ETH from a faucet:
   - [Alchemy Sepolia Faucet](https://sepoliafaucet.com)
   - [Infura Sepolia Faucet](https://www.infura.io/faucet/sepolia)

2. **Infura Account**: Create a free account at [infura.io](https://infura.io) and get an API key.

### Setup

Set your credentials using Hardhat's secure variable storage:

```bash
# Set your wallet private key (never commit this!)
npx hardhat vars set PRIVATE_KEY

# Set your Infura API key
npx hardhat vars set INFURA_API_KEY
```

Verify configuration:

```bash
npx hardhat vars list
```

### Running Sepolia Tests

```bash
# Run all tests (takes 5-10 minutes)
npm run test:sepolia

# Run a single test (recommended for development)
npx hardhat test --network sepolia --grep "should set the correct owner"
```

### Important Notes

| Consideration | Details |
|---------------|---------|
| **Gas Costs** | FHE operations are expensive. Ensure wallet has at least 0.5 Sepolia ETH |
| **Time** | Full test suite takes 5-10 minutes due to real encryption operations |
| **Confirmations** | Tests wait for transaction confirmations on Sepolia |
| **Time Manipulation** | Some redemption tests are skipped on Sepolia (can't fast-forward time on live network) |

### Troubleshooting

| Issue | Solution |
|-------|----------|
| "insufficient funds" | Get more Sepolia ETH from faucet |
| "timeout exceeded" | Tests have 10-minute timeout; retry or run single tests |
| "nonce too low" | Wait for pending transactions to confirm |
| "gas estimation failed" | Increase gas limit in hardhat.config.ts |

## Test Coverage

The test suite covers:

- **Deployment**: Constructor initialization, owner setup, encrypted supply allocation
- **Whitelist Management**: Add/remove addresses, access control
- **Transfers**: Encrypted transfers, insufficient balance handling (FHE.select pattern)
- **Approve/TransferFrom**: Allowances for atomic DvP
- **Redemption**: Maturity enforcement, token burning
- **Regulatory Access**: ACL-based audit access grants
- **Edge Cases**: Zero amounts, self-transfers, full balance operations

## Known Limitations

1. **Threshold Network Dependency**: Unlike ZK approaches where users hold decryption keys, FHE requires the threshold network for any decryption.

2. **No ACL Revocation**: Once audit access is granted, it cannot be revoked (per-ciphertext limitation).

3. **Gas Costs**: FHE operations are computationally expensive, though coprocessors mitigate this.

4. **Silent Failures**: The `FHE.select` pattern means insufficient balance transfers "succeed" with zero effect (for privacy). Applications should verify balance changes.

5. **Time-Dependent Tests**: Redemption tests that require time manipulation (fast-forwarding to maturity) only run in mock mode since live networks can't manipulate time.

## Security Disclaimer

**This is a proof of concept for research and evaluation purposes only.**

- Do NOT use in production without thorough security audits
- Implementation may contain bugs or incomplete features
- No guarantees of correctness or fitness for any purpose

## References

- [SPEC.md](./SPEC.md) - Full protocol specification
- [Zama fhEVM Documentation](https://docs.zama.org/fhevm)
- [Zama Protocol Litepaper](https://docs.zama.org/protocol/zama-protocol-litepaper)
- [fhEVM Hardhat Template](https://github.com/zama-ai/fhevm-hardhat-template)
