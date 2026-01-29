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

| Mode | Encryption | Speed | Use Case |
|------|------------|-------|----------|
| `hardhat` | Mock | Fast | Unit tests, CI, rapid iteration |
| `hardhat node` | Mock | Fast | Integration testing with persistence |
| `sepolia` | Real | Slow | Production-like validation |

### Running Tests

```bash
# Mock mode (default) - fast, no real encryption
npm run test

# Sepolia mode - real FHE, requires configuration
npx hardhat vars set MNEMONIC
npx hardhat vars set INFURA_API_KEY
npm run test:sepolia
```

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

5. **Mock Mode Limitations**: The fhEVM mock framework has issues with Hardhat's `loadFixture` when tests perform complex state reverts. Some edge case tests may fail in mock mode but pass on Sepolia with real encryption.

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
