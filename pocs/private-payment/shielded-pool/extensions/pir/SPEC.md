---
title: "Shielded Pool: PIR + Epoch Nullifiers Extension"
status: Draft
version: 0.1.0
authors: []
created: 2026-05-19
iptf_use_case: "https://github.com/ethereum/iptf-map/blob/master/use-cases/private-stablecoins.md"
iptf_approach: "https://github.com/ethereum/iptf-map/blob/master/approaches/approach-private-payments.md"
---

# Shielded Pool: PIR + Epoch Nullifiers Extension

## Overview

The parent shielded-pool design leaves two concerns unaddressed.

**End-user state-read privacy.** Before spending, the wallet fetches the Merkle path of the input note's commitment from the on-chain state. In practice that read goes to an RPC node. The read reveals the queried leaf index, which under KYC links to a real identity. The parent `REQUIREMENTS.md` privacy section ("Transaction patterns and timing correlation") implies this should not be observable, but the parent SPEC does not specify how the wallet performs the read.

**Nullifier-set bloat.** The on-chain nullifier set grows linearly with transaction history and is never pruned. As the system scales, the set of entities able to host that state shrinks to a few large providers, which become a centralization and liveness risk. The parent does not enumerate this at PoC scope.

This extension addresses both. PIR over the wallet's pre-spend tree reads closes the state-read leak. Epoch-based nullifiers bound the active on-chain set: past epochs are anchored on-chain by a single Merkle root each, and the corresponding tree content is hosted by the same off-chain state-replica server that answers PIR queries. The note format, deposit flow, and attestation flow are unchanged.

---

## Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

---

## Diff vs Parent

| Parent primitive | Status |
|---|---|
| `Note` data structure | Unchanged |
| `Commitment` derivation | Unchanged |
| `Nullifier` derivation | Extended: `η_e = poseidon(commitment, spending_key, epoch_id)` |
| Attestation registry and flows | Unchanged |
| `Deposit` flow | Unchanged |
| `Private Transfer` flow | Extended: commitment-tree path read via PIR; non-membership against each frozen epoch's nullifier tree, also read via PIR |
| `Withdraw` flow | Extended: same path-via-PIR and frozen-epoch non-membership inputs as `Transfer` |
| Commitment tree retrieval | Alternate fetch path (PIR-served raw nodes) |
| Historical root retrieval | Light-client-verified (replaces implicit trusted RPC) |
| `ShieldedPool` on-chain state | Extended: `currentEpoch`, `frozenNullifierRoots`, `rolloverEpoch()` |

---

## Approach

| Gap | Primitive |
|---|---|
| State-read privacy | **InsPIRe** ([eprint 2025/1352](https://eprint.iacr.org/2025/1352)). Single-server PIR with silent preprocessing (no client-side hint download). |
| Database layout for tree state | **Raw flattened Merkle node arrays**, per [`tree-pir`](https://github.com/brech1/tree-pir). Per spend, the wallet retrieves `log(N)` sibling nodes via a batched PIR query, not a precomputed path. |
| Root authenticity | **Light client** (e.g. Helios) verifies the contract storage slot holding `commitment_root` and `frozenNullifierRoots[e]` against Ethereum consensus. The PIR-served path is reconstructed against light-client-verified roots inside the wallet and inside the spend circuit. |
| Nullifier bloat | **Epoch-based nullifiers** with coarse epochs and linear non-membership composition. No recursion at PoC scope. |

PIR-internal cryptographic parameters are inherited from InsPIRe and are not pinned in this spec.

---

## Data Types

### Nullifier (extended)

```
nullifier_e = poseidon(commitment, spending_key, epoch_id)
```

`epoch_id` is a `u64` advanced by `ShieldedPool.rolloverEpoch()`. Distinct values produce unlinkable nullifiers for the same note.

---

## On-Chain State

`ShieldedPool` MUST add:

```solidity
uint64  public currentEpoch;
mapping(uint64 => bytes32) public frozenNullifierRoots;

/// PoC: owner-only. Production: decentralized trigger.
function rolloverEpoch() external onlyOwner;
```

On `rolloverEpoch()`, the contract:

1. Computes the Merkle root of the active `nullifiers` set and stores it in `frozenNullifierRoots[currentEpoch]`.
2. Resets the active `nullifiers` mapping.
3. Increments `currentEpoch`.
4. Emits `EpochRollover(uint64 epoch, bytes32 root)`.

All other on-chain state from the parent SPEC is unchanged.

---

## Off-Chain State-Replica Server

A single server replicates public on-chain state and exposes one PIR endpoint.

**Hosted data (single logical database, raw flattened Merkle nodes):**

| Tree | Source | Used for |
|---|---|---|
| Commitment tree | `Deposit`, `Transfer` events | Sibling nodes for membership witness of input notes |
| Frozen nullifier tree (one per past epoch `e`) | `Transfer`, `Withdraw`, `EpochRollover` events | Sibling nodes for non-membership witness against `frozenNullifierRoots[e]` |

Each tree is stored as its flattened node array, as in [`tree-pir`](https://github.com/brech1/tree-pir). The server indexes tree-id and node offset; the wallet addresses queries against `(tree_id, node_offset)`.

The frozen nullifier trees are hosted off-chain (rather than re-derived per spend by each wallet) because the contract retains only their roots: the underlying leaves and intermediate nodes are reconstructible from `Transfer`/`Withdraw` event logs, but the per-spend cost of every wallet rebuilding every frozen tree is prohibitive. The state-replica server performs this reconstruction once and offers it as a shared service.

The server is untrusted for correctness. Returned nodes are consumed only as part of a witness assembled and re-checked client-side. The wallet reconstructs a root from each witness and compares against the corresponding light-client-verified on-chain root. The spend circuit re-checks the same reconstruction.

---

## Flows

### Private Transfer (extended)

```
┌─────────┐    ┌────────────┐    ┌─────────────┐    ┌──────────────┐
│ Wallet  │    │ Light      │    │ State-      │    │ ShieldedPool │
│         │    │ Client     │    │ Replica/PIR │    │              │
└────┬────┘    └─────┬──────┘    └──────┬──────┘    └──────┬───────┘
     │ 1. Verify     │                  │                  │
     │   roots       │                  │                  │
     │──────────────►│                  │                  │
     │◄──────────────│                  │                  │
     │ 2. Batched    │                  │                  │
     │   PIR query   │                  │                  │
     │   for log(N)  │                  │                  │
     │   sibling     │                  │                  │
     │   nodes on    │                  │                  │
     │   commitment  │                  │                  │
     │   tree path   │                  │                  │
     │─────────────────────────────────►│                  │
     │◄─────────────────────────────────│                  │
     │ 3. For each   │                  │                  │
     │   frozen      │                  │                  │
     │   epoch e_j:  │                  │                  │
     │   batched PIR │                  │                  │
     │   query for   │                  │                  │
     │   low-leaf +  │                  │                  │
     │   sibling     │                  │                  │
     │   nodes in    │                  │                  │
     │   frozen tree │                  │                  │
     │─────────────────────────────────►│                  │
     │◄─────────────────────────────────│                  │
     │ 4. Assemble witnesses; prove and submit via relayer │
     │─────────────────────────────────────────────────────►
```

**Steps:**

1. Wallet fetches `commitment_root` and `frozenNullifierRoots[e_j]` for every `e_j` the note has lived through. These MUST be verified against Ethereum consensus via a light client. The PIR server MUST NOT be trusted for any of these values.
2. Wallet issues a batched InsPIRe query against the commitment-tree node array for the `log(N)` sibling nodes on the path from the input leaf to the root. PIR returns the requested nodes only: it does not perform the membership check. The wallet reconstructs the root from the returned nodes and asserts equality with the light-client-verified `commitment_root`. The same nodes are passed into the spend circuit as the membership witness.
3. For each frozen epoch `e_j`, the wallet computes `η_{e_j} = poseidon(commitment, spending_key, e_j)`, locates the low-leaf index in that frozen tree (the leaf whose `value < η_{e_j} < next_value`), and issues a batched PIR query for the low-leaf record and the `log(N)` sibling nodes on its path to the root. PIR returns nodes; the non-membership check itself is performed inside the spend circuit. The wallet reconstructs the root from the returned nodes and asserts equality with `frozenNullifierRoots[e_j]`.
4. Wallet assembles the witnesses, runs the extended `transfer` circuit (see below), and submits via the existing relayer path. All on-chain checks (active-epoch nullifier uniqueness, proof verification, commitment insertion) proceed as in the parent SPEC.

### Withdraw (extended)

Same diff as `Transfer`, applied to a single spent note. The path read against the commitment tree and the non-membership reads against each frozen nullifier tree MUST go through PIR; roots MUST be light-client-verified.

### Epoch Rollover

```
┌──────────┐   ┌──────────────┐   ┌──────────────┐
│ Operator │   │ ShieldedPool │   │ State-       │
│          │   │              │   │ Replica/PIR  │
└────┬─────┘   └──────┬───────┘   └──────┬───────┘
     │ rollover()    │                   │
     │──────────────►│                   │
     │               │ freeze active     │
     │               │ tree, commit      │
     │               │ root, emit event  │
     │               │──────────────────►│
     │               │                   │ append frozen
     │               │                   │ tree nodes to
     │               │                   │ hosted data
```

---

## Circuit Constraints (diff)

### Transfer Circuit

**Additional public inputs:**

- `current_epoch`: `u64`
- `frozen_epoch_roots[k]`: `bytes32[k]`, where `k` is the number of frozen epochs the input notes have lived through

**Additional private inputs (per input note, per frozen epoch `e_j`):**

- `non_membership_low_leaf_j`, `non_membership_path_j`, `non_membership_indices_j`: witness reconstructing to `frozen_epoch_roots[j]` and proving `η_{e_j}` is absent from the frozen tree

**Additional constraints:**

For each input note and each frozen epoch `e_j`:

1. `η_{e_j} = poseidon(commitment_in, spending_key, e_j)`
2. The supplied non-membership witness for `η_{e_j}` reconstructs to `frozen_epoch_roots[j]` under the standard sorted-low-leaf non-membership pattern.

For the active-epoch nullifier (replaces the parent's `poseidon2(commitment, spending_key)`):

3. `nullifier = poseidon(commitment_in, spending_key, current_epoch)`

Value preservation, commitment formation, and membership checks from the parent circuit are unchanged.

### Withdraw Circuit

Same diff as `Transfer`, applied to the single spent note.

---

## Security Model

### Threat Model (additions to parent)

| Adversary | Capabilities | Mitigations |
|---|---|---|
| **Malicious PIR / state-replica server** | Sees PIR query traffic; knows public state; MAY serve incorrect nodes | Query privacy: InsPIRe (single-server, malicious-server model). Correctness: every returned node is consumed only as part of a root reconstruction checked against a light-client-verified on-chain root and re-checked inside the spend circuit. |
| **Untrusted RPC for root reads** | MAY misreport `commitment_root` or `frozenNullifierRoots[e]` | Roots MUST be read through a light client that verifies storage proofs against Ethereum consensus. |
| **Network observer** | Sees IP, timing, size of PIR sessions; MAY correlate sequential queries from the same wallet | Out of scope for PoC. Production deployment SHOULD use Tor or batched query windows. |

The parent threat model (public observer, malicious relayer, compromised viewing key, malicious compliance authority) is unchanged.

### Guarantees (additions to parent)

| Property | Description |
|---|---|
| **Query privacy** | The state-replica server learns nothing about which tree index the wallet queried, beyond what is publicly inferable from query timing. |
| **Witness correctness** | A malicious server cannot cause the wallet to produce a valid spend against an incorrect Merkle path or non-membership witness: every reconstruction is re-checked inside the circuit against light-client-verified roots. |
| **Bounded active state** | Validators retain only the active-epoch nullifier set. Past epochs are anchored on-chain by one `bytes32` each. |

### Limitations & Shortcuts (PoC Scope)

| Limitation | Impact | Production Mitigation |
|---|---|---|
| No correlated-query defense | Sequential PIR sessions from the same wallet/IP still link via network metadata | Mixnet, Tor, or per-block batching |
| Linear `k` non-membership growth | Spend proof grows linearly in the number of frozen epochs the note has lived through | Coarse epochs bound `k` at PoC scope. Tachyon-style recursive aggregation collapses this to constant. |
| Centralized epoch rollover | Owner-only `rolloverEpoch()` is a single point of liveness | Decentralized trigger (per-block, per-time, or validator-voted) |
| Single state-replica server | One operator hosts the entire PIR-served database | Multiple independent replicas; wallet load-balances |
| No PIR over the encrypted note log | Note discovery still requires trial decryption or operator-side filtering | FMD / OMR (future extension) |
| No post-quantum primitives | Encryption around notes uses ECDH/AEAD as in parent | Lattice KEM and signatures (future extension) |

---

## Terminology

| Term | Definition |
|---|---|
| **PIR** | Private Information Retrieval. Protocol allowing a client to fetch row `i` from a database held by a server without revealing `i` to the server. |
| **Silent preprocessing** | A PIR preprocessing model in which all setup is server-side, with no offline hint downloaded by the client. |
| **Frozen epoch** | A past epoch whose active nullifier set has been committed to a single root on-chain. Its full tree content is hosted off-chain by the state-replica server. |
| **Non-membership witness** | A Merkle witness in sorted-low-leaf form proving that a queried value is absent from an indexed Merkle tree. |
| **State-replica server** | Off-chain service that ingests on-chain events, hosts the flattened Merkle node arrays of the commitment tree and all frozen nullifier trees, and answers PIR queries against them. |
| **Light client** | Client that verifies Ethereum chain headers and storage proofs against consensus, enabling trustless reads of `commitment_root` and `frozenNullifierRoots[e]`. |

---

## References

- InsPIRe: Mahdavi, Patel, Seo, Yeo, *Communication-Efficient PIR with Server-side Preprocessing*. IACR ePrint 2025/1352. <https://eprint.iacr.org/2025/1352>
- Bowe, Miers, *A Note on Notes: Towards Scalable Anonymous Payments via Evolving Nullifiers and Oblivious Synchronization*. IACR ePrint 2025/2031. <https://eprint.iacr.org/2025/2031>
- tree-pir: <https://github.com/brech1/tree-pir>
- Helios light client: <https://github.com/a16z/helios>
- Polygon Miden, *Epoch-based nullifier database*: <https://github.com/0xMiden/miden-vm/discussions/356>
- Aztec, *Global State Epochs*: <https://forum.aztec.network/t/global-state-epochs/2704>
- A. Tomescu, *Notes on scaling nullifier sets*: <https://alinush.github.io/nullifiers>
- Parent: [`../../SPEC.md`](../../SPEC.md)
- Parent: [`../../../REQUIREMENTS.md`](../../../REQUIREMENTS.md)
