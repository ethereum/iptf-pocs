# Shielded Pool Extension: PIR + Epoch Nullifiers

A spec-only PoC that extends the [shielded-pool](../shielded-pool/) private-payments construction with two additions:

- PIR over the wallet's pre-spend tree reads, closing the state-read privacy leak at the indexer/RPC layer.
- Epoch-based nullifiers with a per-note recursive chain proof (IVC), bounding the on-chain nullifier set without imposing linear per-spend work as notes age.

The note format, deposit, and attestation flows of the parent are preserved. The commitment is extended to bind `epoch_created` so the on-chain verifier can enforce that a spend's chain proof covers the note's full lifetime.

## Status

Specification only. No implementation in this folder. The protocol is proof-system agnostic; see [SPEC.md](./SPEC.md) for the abstract requirements an implementation must meet.

## Documents

- [SPEC.md](./SPEC.md): protocol specification
- Parent SPEC: [`../shielded-pool/SPEC.md`](../shielded-pool/SPEC.md)
- Parent REQUIREMENTS: [`../REQUIREMENTS.md`](../REQUIREMENTS.md)

## Security disclaimer

Research prototype, not production-ready. Cryptographic assumptions and known shortcuts are documented in the SPEC.
