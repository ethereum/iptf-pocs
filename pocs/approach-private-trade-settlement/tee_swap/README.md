# TEE Swap

> **Status:** Draft
> **Privacy Primitive:** Atomic cross-chain swaps of private UTXO notes via TEE-coordinated stealth address revelation

## Overview

This approach uses a Trusted Execution Environment (TEE) to coordinate atomic delivery-versus-payment (DvP) settlement of private UTXO notes across chains. Users lock notes to stealth addresses with time-locked dual spending conditions, and the TEE atomically reveals ephemeral keys that allow both parties to claim. Users never share spending keys — the TEE can censor but never steal.

See [SPEC.md](./SPEC.md) for the full protocol specification.

## Cryptographic Assumptions

- **Primitives used:** Stealth addresses (ECDH + elliptic curve arithmetic), Pedersen commitments, ZK proofs (Noir circuits), time-locked spending conditions
- **Security assumptions:** Discrete log hardness (Grumpkin curve), TEE enclave integrity, hash function collision resistance
- **Trusted setup:** No cryptographic trusted setup; trust is placed in TEE hardware and attestation infrastructure

## Threat Model

What does this protect against:
- [x] Public observers cannot learn trade amounts, prices, or counterparty identities
- [x] Miners/validators cannot front-run trades (stealth address protection)
- [x] TEE compromise leads to censorship only, not fund theft
- [x] Users can always recover funds via timeout refund path

What this does NOT protect against:
- TEE hardware manufacturer can see plaintext inside enclave (privacy loss, not theft)
- TEE operator can censor by refusing to reveal (denial of service, not theft)
- Network-level traffic analysis (timing, message sizes)

## Prerequisites

- [Rust](https://www.rust-lang.org/tools/install)
- [Foundry](https://getfoundry.sh/introduction/installation)
- [Nargo](https://noir-lang.org/docs/getting_started/installation/) (Noir toolchain)

## Installation

```bash
cd pocs/approach-private-trade-settlement/tee_swap
# Install Solidity dependencies
forge soldeer install
```

## Building

```bash
# Build Solidity contracts
forge build

# Check Rust TEE code
cargo check

# Build Noir circuits
cd circuits/deposit && nargo check && cd ../..
cd circuits/spend && nargo check && cd ../..
```

## Running

### Mock mode

```bash
cargo run --bin demo
```

### Full e2e demo with real proof generation + onchain verification + tee swap coordination

```bash
cargo run --bin e2e
```

> **note**: you may use `--release` to make the demos execute faster

## Tests

```bash
forge test
cargo test --lib
```

## Known Limitations

- TEE enclave is simulated in software; no real hardware attestation
- Single TEE operator (no M-of-N redundancy)
- No actual encrypted channel between counterparties and enclave
- Static KYC whitelist (no identity provider integration)
- Simplified on-chain attestation verification (ECDSA signature check only)

## References

- [SPEC.md](./SPEC.md) — Full protocol specification
- [Intel SGX Explained (Costan & Devadas, 2016)](https://eprint.iacr.org/2016/086)
- [AWS Nitro Enclaves Documentation](https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave.html)
- [Atomic DvP on Distributed Ledgers (BIS, 2020)](https://www.bis.org/publ/othp31.htm)
