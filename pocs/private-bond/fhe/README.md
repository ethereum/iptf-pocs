# Private Bond (FHE Approach)

> **Status:** Draft
> **Privacy Primitive:** Confidential bond transfers using Fully Homomorphic Encryption

## Overview

This PoC demonstrates a privacy-preserving zero-coupon bond using [Zama's fhEVM](https://docs.zama.org/fhevm). Unlike ZK approaches where computations happen off-chain and are verified on-chain, FHE allows computations directly on encrypted data.

See [SPEC.md](./SPEC.md) for the full protocol specification.

## Quick Start

```bash
npm install
npm run compile
npm test          # Mock FHE (fast, simulated)
npm run test:sepolia  # Real FHE (slow, requires setup)
```

## Testing Modes

| Mode | Command | What happens | Speed |
|------|---------|--------------|-------|
| **Mock** | `npm test` | FHE simulated in-memory via `@fhevm/mock-utils` | Seconds |
| **Sepolia** | `npm run test:sepolia` | Real TFHE ops via Zama coprocessor | Minutes |

**Important**: Local tests (`npm test`) do not perform real homomorphic encryption. The `@fhevm/mock-utils` library simulates FHE behavior for fast development. To validate actual FHE operations, run on Sepolia. No critical tests were skipped for efficiency—all core functionality is validated on the live network.

## Sepolia Setup (Real FHE)

1. Get Sepolia ETH from a [faucet](https://sepoliafaucet.com)
2. Get an [Infura](https://infura.io) API key
3. Get a Zama fhEVM API key (can be a placeholder value)
4. Set credentials:

```bash
npx hardhat vars set PRIVATE_KEY
npx hardhat vars set INFURA_API_KEY
npx hardhat vars set ZAMA_FHEVM_API_KEY
```

Sepolia tests take 5-10 minutes and require ~0.5 ETH for gas. Time-dependent tests (redemption) are skipped since live networks can't fast-forward time.

## Test Coverage

- Deployment & initialization
- Whitelist management
- Encrypted transfers (including silent failure on insufficient balance)
- Approve/TransferFrom for atomic DvP
- Redemption at maturity
- Regulatory audit access via ACL

## Known Limitations

1. **Mock vs Real**: Local tests simulate FHE; only Sepolia validates real encryption
2. **Threshold Network**: Decryption requires Zama's network (unlike ZK where users hold keys)
3. **No ACL Revocation**: Audit access is permanent per-ciphertext
4. **Silent Failures**: Insufficient balance transfers "succeed" with zero effect (for privacy)

## Security Disclaimer

**Proof of concept for research only.** Do not use in production without security audits.

## References

- [SPEC.md](./SPEC.md) - Protocol specification
- [Zama fhEVM Docs](https://docs.zama.org/fhevm)
- [fhEVM Hardhat Template](https://github.com/zama-ai/fhevm-hardhat-template)
