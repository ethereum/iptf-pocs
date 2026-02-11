# Private Bond Benchmarks

Comparison of three implementation approaches.

> Note: this are not precise benchmarks and should not be seen as a point of reference. These are estimates gathered from documentation and code available, that we could have run.

## Gas Costs

### Custom UTXO

**PoC not directly measurable** - Our PoC uses UltraPlonk and a trivial Merkle tree implementation that's too costly for production. However, we can use [Railgun](https://docs.railgun.org/) gas costs as a production reference for a mature custom UTXO system with optimized Groth16 proofs.

**Railgun Production Reference** (from [Railgun-Privacy/contract](https://github.com/Railgun-Privacy/contract)):

| Operation           | Min Gas | Max Gas   | Avg Gas    | Notes                          |
| ------------------- | ------- | --------- | ---------- | ------------------------------ |
| Shield (deposit)    | 52,598  | 2,209,668 | **~1.19M** | Move tokens into privacy pool  |
| Transact (transfer) | 32,118  | 1,183,520 | **~1.07M** | Private transfer between users |

See also [Paladin](https://www.paladinprivacy.org/) for enterprise-focused custom UTXO patterns.

### Aztec L2

**Not measurable**: Aztec execution layer is scheduled for later in 2026, only at that moment we will be able to test the fee structure of the network.

### Zama FHE

```bash
cd pocs/private-bond/fhe && REPORT_GAS=true npm run test:sepolia
```

**Measured on Sepolia**:

| Operation           | FHE Ops | Actual Gas |
| ------------------- | ------- | ---------- |
| Deployment          | N/A     | ~1.66M     |
| Transfer            | 4       | ~330K      |
| addToWhitelist      | 0       | ~47K       |
| removeFromWhitelist | 0       | ~26K       |
| transferOwnership   | 0       | ~34K       |

**Not yet measured**: TransferFrom, Approve, Redeem (tests pending).

Gas is on-chain only; FHE computation is off-chain (see Latency).

---

## Computation Latency

### Custom UTXO

**Not directly measurable** - As stated above.
Proxy: [Semaphore V4 - Benchmarks](https://docs.semaphore.pse.dev/benchmarks) with similar circuit complexity (Merkle Tree inclusion proof + nullifier) with a Groth16 prover.

| Environment | Est. Proving Time |
| ----------- | ----------------- |
| Browser     | 5-30s             |
| Node.js     | 2-10s             |
| Server      | <1-3s             |

### Aztec L2

**Measured on Local Aztec Sandbox**:

Average proving time: **~9.8 seconds** per transaction

| Operation            | Witness Gen (ms) | IVC Proof (ms) | Total (ms)    |
| -------------------- | ---------------- | -------------- | ------------- |
| Deployment           | 1,500            | 8,502          | 10,002        |
| Whitelist Add        | 857-1,488        | 7,222-7,470    | 8,327-8,709   |
| Private Distribution | 1,231-1,240      | 8,999-9,145    | 10,231-10,385 |
| Private Transfer     | 1,357            | 9,836          | 11,194        |
| Redeem               | 1,327-1,347      | 8,268-8,377    | 9,615-9,704   |

Machine: MacBook Pro M1 Pro - 16GB
Source: [privacy-l2/test.sh](./privacy-l2/test.sh) using `aztec-wallet profile`

### Zama FHE

**Estimated** from operation counts (~10-20ms per FHE op):

| Operation    | FHE Ops | Latency (CPU) | Latency (GPU, 2026) |
| ------------ | ------- | ------------- | ------------------- |
| Transfer     | 4       | ~40-80ms      | ~1.6-3.2ms          |
| TransferFrom | 7       | ~70-140ms     | ~2.8-5.6ms          |
| Redeem       | 3       | ~30-60ms      | ~1.2-2.4ms          |

Source: [Zama fhEVM paper](https://github.com/zama-ai/fhevm/blob/main/fhevm-whitepaper.pdf)

---

## Throughput (TPS)

| Approach    | Current (PoC) | Production Potential | Bottleneck                    |
| ----------- | ------------- | -------------------- | ----------------------------- |
| Custom UTXO | N/A           | L1: ~15-30 TPS       | PoC: Centralized issuer relay |
|             |               | L2: ~2,000+ TPS      | Prod: Network + gas costs     |
| Aztec L2    | N/A           | unknown              | Sequencer + L1 batching       |
| Zama FHE    | N/A           | unknown              | Coprocessor network           |

_Note on Zama: TPS announces a network-wide TPS of 500-1000 (shared across all fhEVM apps)._

---

## Privacy Comparison

| Approach    | Hidden                        | Public                                          |
| ----------- | ----------------------------- | ----------------------------------------------- |
| Custom UTXO | Amounts, balances, tx linkage | Merkle root updates, nullifiers, tx count       |
| Aztec L2    | Amounts, balances             | Addresses (via whitelist), L1 state commitments |
| Zama FHE    | Amounts, balances             | Addresses, tx existence                         |

---

## Trade-offs

| Approach    | Strengths                                          | Weaknesses                                                                                    |
| ----------- | -------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| Custom UTXO | Full unlinkability, proven model, full audit trail | Centralized issuer, custom implementation                                                     |
| Aztec L2    | Native privacy L2, composable, scalable            | Not live, unknown costs and TPS                                                               |
| Zama FHE    | EVM-compatible, devx                               | Shared network TPS (500-1000 across all apps), addresses public, threshold network dependency |

---

## Sources

- [Railgun Documentation](https://docs.railgun.org/)
- [Railgun Gas Report](./railgun-gas-report.txt) - Hardhat gas benchmarks for production Railgun contracts
- [Semaphore V4 Benchmarks](https://docs.semaphore.pse.dev/benchmarks)
- [Aztec Documentation](https://docs.aztec.network/)
- [Zama fhEVM Documentation](https://docs.zama.ai/fhevm)
- [Zama Protocol Litepaper](https://www.zama.ai/)
