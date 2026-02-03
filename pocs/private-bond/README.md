# Private Bond

> **Status:** In Progress
> **Privacy Primitive:** Confidential bond transfers with regulatory compliance

## Overview

This PoC demonstrates a privacy-preserving zero-coupon bond protocol. Bondholders can trade and redeem bonds without revealing transaction amounts, while maintaining full auditability for regulators.

Three implementation approaches are provided:

| Approach        | Description                       | Location                       |
| --------------- | --------------------------------- | ------------------------------ |
| **Custom UTXO** | Privacy built from scratch on EVM | [custom-utxo/](./custom-utxo/) |
| **Privacy L2**  | Native privacy on Aztec network   | [privacy-l2/](./privacy-l2/)   |
| **FHE**         | Fully Homomorphic Encryption      | [fhe/](./fhe/)                 |

## Requirements

See [REQUIREMENTS.md](./REQUIREMENTS.md) for the shared requirements all approaches implement.

## Specifications

- [custom-utxo/SPEC.md](./custom-utxo/SPEC.md) — Custom UTXO protocol design
- [privacy-l2/SPEC.md](./privacy-l2/SPEC.md) — Aztec L2 protocol design
- [fhe/SPEC.md](./fhe/SPEC.md) — Zama fhEVM protocol design

## Comparison

| Aspect              | Custom UTXO                      | Privacy L2                    | FHE (Zama)                      |
| ------------------- | -------------------------------- | ----------------------------- | ------------------------------- |
| Deployment          | Ethereum mainnet                 | Aztec L2                      | Zama-enabled chain              |
| State model         | UTXO (notes, nullifiers)         | UTXO (notes, nullifiers)      | Account-based (ERC20-like)      |
| Privacy mechanism   | ZK proofs                        | ZK proofs                     | Homomorphic encryption          |
| Code complexity     | ~1000+ lines across 3 components | ~200 lines single contract    | ~300 lines single contract      |
| Trusted relayer     | Required (issuer)                | Not required                  | Not required                    |
| Trust assumptions   | Cryptographic only               | Cryptographic only            | Threshold network (2/3 honest)  |
| Composability       | Isolated system                  | Native cross-contract         | Native cross-contract           |
| Client requirements | Light (relayer handles proofs)   | Heavy (PXE for local proving) | Light (standard wallet)         |
| Regulatory access   | Per-note viewing keys            | App-siloed viewing keys       | ACL-based decryption grants     |
| Throughput          | High (relayer batching)          | Bound by sequencer            | Bound by coprocessor capacity   |

## Quick Start

### Custom UTXO Approach

```bash
cd custom-utxo

# Build circuits
cd circuits && nargo build && cd ..

# Build and test contracts
cd contracts && forge build && forge test && cd ..

# Build wallet
cd wallet && cargo build --release && cd ..
```

### Privacy L2 Approach

```bash
cd privacy-l2

# Start Aztec sandbox
aztec start --sandbox

# Run demo (in another terminal)
./test.sh
```

### FHE Approach

```bash
cd fhe

# Install dependencies
npm install

# Compile contracts
npx hardhat compile

# Run tests (requires fhEVM devnet)
npx hardhat test
```

## Known Limitations

See each approach's README for specific limitations:

- [custom-utxo/README.md](./custom-utxo/README.md)
- [privacy-l2/README.md](./privacy-l2/README.md)
- [fhe/README.md](./fhe/README.md)

## References

- [Blog Post Part 1: Building Private Bonds on Ethereum](https://blog.example.com/private-bonds-part-1)
- [Blog Post Part 2: Private Bonds on Aztec L2](https://blog.example.com/private-bonds-part-2)
- [Zama fhEVM Documentation](https://docs.zama.org/fhevm)
- [Zama Protocol Litepaper](https://docs.zama.org/protocol/zama-protocol-litepaper)
