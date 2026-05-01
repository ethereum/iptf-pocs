# Resilient Disbursement Rails

> **Status:** Draft | In Progress | Complete
> **Privacy Primitive:** [e.g., confidential transfers, private voting, anonymous credentials]

## Overview

Brief description of what this PoC demonstrates.

## Cryptographic Assumptions

- **Primitives used:** [e.g., Pedersen commitments, zk-SNARKs, ring signatures]
- **Security assumptions:** [e.g., discrete log hardness in the chosen group]
- **Trusted setup:** [Yes/No, and details if yes]

## Threat Model

What does this protect against:
- [ ] Public observers cannot learn X
- [ ] Validators cannot learn Y

What this does NOT protect against:
- Collusion between A and B
- Side-channel attacks
- etc.

## Prerequisites

- [Rust](https://www.rust-lang.org/tools/install)
- [Foundry](https://getfoundry.sh/introduction/installation)
- [Nargo](https://noir-lang.org/docs/getting_started/noir_installation)
- [Barretenberg](https://barretenberg.aztec.network/docs/getting_started)

## Installation

```bash
cd pocs/private-payment/resilient-disbursement-rails
# Install Solidity dependencies
forge soldeer install
```

## Building

```bash
nargo compile --workspace
forge build
cargo check
```

## Running

```bash
# How to run the PoC
```

## Tests

```bash
nargo test --workspace
forge test
cargo test --lib
```

## Known Limitations

- Limitation 1
- Limitation 2

## References

- Link to paper/spec this implements
- Related work
