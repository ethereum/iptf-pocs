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

State-read privacy. Before spending, the wallet fetches the input note's Merkle path from on-chain state. That RPC read reveals the queried leaf index, which under KYC links to a real identity. The parent `REQUIREMENTS.md` flags this; the parent SPEC does not specify how the wallet performs the read.

Nullifier-set bloat. The on-chain nullifier set grows linearly with history and is never pruned, shrinking the set of entities able to host it.

This extension addresses both. PIR over the pre-spend tree reads closes the state-read leak. Epoch-based nullifiers bound the active on-chain set: past epochs are anchored by one Merkle root each, with tree content hosted by the same off-chain state-replica server that answers PIR queries.

A per-note recursive chain proof (IVC) keeps per-spend work bounded: the wallet extends it one step per rollover, and the spend circuit recursively verifies one chain proof instead of inlining `k` non-membership checks. The commitment binds `epoch_created` so the verifier can enforce that the chain covers the note's full lifetime. Deposit and attestation flows are otherwise unchanged.

---

## Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

---

## Proof System Requirements

This extension is proof-system agnostic. Required capabilities: an EVM-verifiable outer artifact (spend proofs verified on-chain in O(1) gas), in-circuit recursive verification of the system's own proofs, the ability to bind a verifying key as a circuit value, zero-knowledge for spend proofs (chain-update proofs need not be zk), and support for branching the recursive verify on a base case (either via circuit-level conditionals or via a sentinel proof).

Notation: `assert verify(vk, proof, public_inputs)` denotes the in-circuit recursive-verify primitive. `FixedVK` is the chain-update circuit's verifying key, fixed at deployment.

Reference instantiation (non-normative): Noir (`std::verify_proof`) with the Aztec `bb_proof_verification` library on UltraHonk, using `noir-recursive-no-zk` for chain-update artifacts and `evm` for the outer spend artifact. Halo2, Plonky2/3, Nova-family folding, Risc0, and SP1 are also candidates.

---

## Diff vs Parent

| Parent primitive | Status |
|---|---|
| `Note` data structure | Extended: includes `epoch_created` |
| `Commitment` derivation | Extended: `c = poseidon(token, amount, owner_pubkey, salt, epoch_created)` |
| `Nullifier` derivation | Extended: `η_e = poseidon(commitment, spending_key, epoch_id)` |
| Attestation registry and flows | Unchanged |
| `Deposit` flow | Extended: circuit enforces `epoch_created == currentEpoch` on the new commitment |
| `Private Transfer` flow | Extended: commitment-tree path read via PIR; spend circuit recursively verifies one per-input-note chain proof (no `k`-fold non-membership inside the spend circuit) |
| `Withdraw` flow | Extended: same PIR path read and recursive chain-proof verification as `Transfer` |
| Commitment tree retrieval | Alternate fetch path (PIR-served raw nodes) |
| Historical root retrieval | Light-client-verified (replaces implicit trusted RPC) |
| `ShieldedPool` on-chain state | Extended: `currentEpoch`, `frozenNullifierRoots`, `rolloverEpoch()`; spend tx supplies per-input-note `epoch_created` so the contract recomputes the expected chain accumulator from stored frozen roots |
| Per-note chain proof | New: maintained off-chain by the wallet; extended one step per epoch rollover (or `k` steps at wake-up after offline periods) |

---

## Approach

| Gap | Primitive |
|---|---|
| State-read privacy | InsPIRe ([eprint 2025/1352](https://eprint.iacr.org/2025/1352)): single-server PIR with silent preprocessing |
| Database layout | Raw flattened Merkle node arrays per [`tree-pir`](https://github.com/brech1/tree-pir); wallet fetches `log(N)` sibling nodes per spend via batched PIR query |
| Root authenticity | Light client (e.g. Helios) verifies `commitment_root` and `frozenNullifierRoots[e]` against consensus; paths are reconstructed against these roots in wallet and circuit |
| Nullifier bloat | Coarse epoch-based nullifiers; cross-epoch non-membership folded into a per-note recursive chain proof (IVC), verified once by the spend circuit regardless of note age |
| Spend-time per-note coverage | Commitment binds `epoch_created`, letting the verifier enforce chain coverage over the note's full lifetime |

Artifact roles: inner (chain-update, consumed recursively) and outer (spend, verified on-chain). PIR parameters are inherited from InsPIRe.

---

## Data Types

### Note (extended)

```
Note {
    token:         address    // ERC-20 token contract
    amount:        u128
    owner_pubkey:  Point      // spending public key of owner
    salt:          Field      // random salt
    epoch_created: u64        // value of currentEpoch at the moment this note was committed
}
```

### Commitment (extended)

```
commitment = poseidon(token, amount, owner_pubkey, salt, epoch_created)
```

### Nullifier (extended)

```
η_e = poseidon(commitment, spending_key, epoch_id)
```

`epoch_id` is advanced by `rolloverEpoch()`; distinct values yield distinct nullifiers for the same note across epochs.

### Chain proof (new)

A `ChainProof` attests that a note is non-spent through some past epoch. Produced by the chain-update circuit, maintained off-chain by the wallet.

Public inputs:

```
ChainProof.public_inputs {
    commitment:              Field   // the note this chain attests about
    epoch_created:           u64     // bound into commitment
    epoch_validated_through: u64     // next epoch needing non-membership; equals currentEpoch when fully caught up (epoch_created ≤ epoch_validated_through ≤ currentEpoch)
    accumulator:             Field   // running Poseidon hash over frozen roots used to build this chain
}
```

Epochs in `[epoch_created, epoch_validated_through - 1]` have been folded into `accumulator` and checked for non-membership.

- Genesis: `epoch_validated_through == epoch_created`, `accumulator == 0`.
- Step:

```
accumulator_new = poseidon2(accumulator_prev, frozenNullifierRoots[epoch_validated_through_prev])
epoch_validated_through_new = epoch_validated_through_prev + 1
```

At spend time the contract recomputes the expected accumulator from `frozenNullifierRoots[epoch_created .. currentEpoch - 1]` and reverts on mismatch.

---

## On-Chain State

`ShieldedPool` MUST add:

```solidity
uint64  public currentEpoch;
mapping(uint64 => bytes32) public frozenNullifierRoots;
// Active-epoch nullifier set is epoch-namespaced so "reset" on rollover is a no-op:
mapping(uint64 => mapping(bytes32 => bool)) public activeNullifiers;

/// PoC: owner-only. Production: decentralized trigger.
function rolloverEpoch() external onlyOwner;

/// View helper: recomputes the chain accumulator the spend circuit must match.
function expectedChainAccumulator(uint64 epochCreated) external view returns (bytes32);
```

The active-epoch nullifier set is tracked by both a LeanIMT (for its root, frozen on rollover) and `activeNullifiers` (for O(1) uniqueness checks). The tree is updated incrementally per `Transfer`/`Withdraw` so rollover is O(1) gas.

On `rolloverEpoch()`: read the active-tree root, write to `frozenNullifierRoots[currentEpoch]`, reset the active tree, increment `currentEpoch`, emit `EpochRollover(uint64 epoch, bytes32 root)`.

On every `transfer` / `withdraw`: read each input note's `epoch_created` from public inputs, revert if `accumulator != expectedChainAccumulator(epoch_created)`, insert `η_{currentEpoch}` into the active-epoch tree and `activeNullifiers[currentEpoch]`.

```solidity
function expectedChainAccumulator(uint64 epochCreated) public view returns (bytes32) {
    bytes32 acc = bytes32(0);
    for (uint64 e = epochCreated; e < currentEpoch; e++) {
        acc = poseidon2(acc, frozenNullifierRoots[e]);
    }
    return acc;
}
```

Active-epoch spends are caught by the uniqueness check, not the chain. Gas cost: `O(currentEpoch - epochCreated)` per spend, bounded by coarse epochs (monthly target).

---

## Off-Chain State-Replica Server

One server replicates public on-chain state and exposes a PIR endpoint. Hosted data (raw flattened Merkle nodes per [`tree-pir`](https://github.com/brech1/tree-pir), addressed as `(tree_id, node_offset)`):

| Tree | Source | Used for |
|---|---|---|
| Commitment tree | `Deposit`, `Transfer` events | Membership witness of input notes |
| Frozen nullifier tree (per past epoch `e`) | `Transfer`, `Withdraw`, `EpochRollover` events | Non-membership witness for the chain-update circuit |

The contract retains only frozen-tree roots, so the server reconstructs each frozen tree once from event logs and offers it as a shared service.

The server is untrusted for correctness. Returned nodes are reassembled client-side into a root and compared against the light-client-verified on-chain root; both circuits re-check the same reconstructions.

Frozen trees are append-only-then-static, so PIR preprocessing is paid once per epoch. The commitment tree grows continuously; preprocessing amortization is out of scope.

---

## Flows

The wallet maintains one `ChainProof` per owned note, updated either eagerly on each observed `EpochRollover` (one proof per rollover per held note) or lazily before spend (one proof per missed epoch, sequential). By spend time, `epoch_validated_through == currentEpoch`.

### Chain Maintenance (wallet-local; new)

1. Wallet observes `EpochRollover(e_frozen, root)` and verifies the root via the light client.
2. For each owned note with `ChainProof.epoch_validated_through == e_frozen`, the wallet computes `η_{e_frozen} = poseidon(commitment, spending_key, e_frozen)` and PIR-fetches the non-membership witness against the just-frozen tree.
3. Wallet runs the chain-update circuit, which recursively verifies the prior chain proof, reconstructs `frozenNullifierRoots[e_frozen]` from PIR-served siblings, checks `η_{e_frozen}` absent under the sorted-low-leaf pattern, folds it into the accumulator, and emits a new `ChainProof` with `epoch_validated_through = e_frozen + 1`.
4. Wallet stores the new chain proof and discards the previous one.

Catch-up: an offline wallet runs steps 2-3 sequentially per missed epoch. Work is bounded-memory and resumable.

### Note Genesis (sentinel chain proof)

On note creation (via `Deposit` or as a `Transfer` output), the owner generates an initial `ChainProof` with `epoch_validated_through = epoch_created`, `accumulator = 0`. The chain-update circuit handles this via its base-case branch (`epoch_validated_through == epoch_created`), which skips prior-proof verification.

### Private Transfer (extended)

1. Catch up each input note's `ChainProof` to `epoch_validated_through == currentEpoch`. Notes created in the current epoch already satisfy this via their genesis proof.
2. PIR-fetch `log(N)` sibling nodes per input commitment, reconstruct the root, and assert equality with the light-client-verified `commitment_root`.
3. Run the spend circuit with per-input chain proofs, membership witnesses, spending key, and output note data (`epoch_created = currentEpoch`).
4. Submit via relayer with the proof and public inputs (per-input `(commitment, epoch_created, accumulator)` triples).
5. Contract verifies the proof, checks `accumulator == expectedChainAccumulator(epoch_created)` per input, checks `η_{currentEpoch} ∉ activeNullifiers[currentEpoch]`, inserts nullifiers and commitments, emits `Transfer`.

The PIR server is consulted only for tree node retrievals in steps 1-2, never trusted for roots.

### Withdraw (extended)

Same diff as `Transfer` applied to a single input note.

### Epoch Rollover

The operator (PoC: contract owner) calls `rolloverEpoch()`. The contract reads the active-tree root, writes it to `frozenNullifierRoots[currentEpoch]`, increments `currentEpoch`, and emits `EpochRollover`. The state-replica server ingests the event and appends the frozen tree's nodes to its hosted data. Wallets run Chain Maintenance for their notes.

---

## Circuit Constraints (diff)

One new circuit (chain-update) plus diffs to the parent Deposit / Transfer / Withdraw circuits.

### Deposit Circuit (diff)

- New public input: `current_epoch_at_deposit: u64`. The contract enforces `current_epoch_at_deposit == currentEpoch`.
- New constraint: `commitment == poseidon(token, amount, owner_pubkey, salt, epoch_created)` with `epoch_created == current_epoch_at_deposit`.

After deposit, the wallet generates the genesis chain proof via the chain-update circuit's base-case branch.

### Chain-Update Circuit (new)

Inner artifact, consumed recursively by other chain-update proofs and by the spend circuit. Used for both extension and genesis.

Public inputs (the `ChainProof`):

- `commitment: Field`
- `epoch_created: u64`
- `epoch_validated_through: u64`
- `accumulator: Field`

Private inputs:

- `is_base_case: bool`. True only when `epoch_validated_through == epoch_created`.
- `prior_chain.{vk, proof, public_inputs}`: recursive witness; ignored when `is_base_case == true`.
- `frozen_root_next: Field`: equal to `frozenNullifierRoots[prior_chain.public_inputs.epoch_validated_through]`.
- `spending_key: Field`
- `non_membership.{low_leaf, low_leaf_next_value, path, indices, leaf_index}`: sorted-low-leaf witness against `frozen_root_next`.

Constraints:

Let `e_prev = prior_chain.public_inputs.epoch_validated_through`.

1. Base-case branch (`is_base_case == true`):
   - `epoch_validated_through == epoch_created`
   - `accumulator == 0`
   - No recursive verify, no non-membership check.

2. Inductive branch (`is_base_case == false`):
   - `assert verify(prior_chain.vk, prior_chain.proof, prior_chain.public_inputs)`
   - `prior_chain.vk == FixedVK` (the chain-update circuit's own VK)
   - `prior_chain.public_inputs.commitment == commitment`
   - `prior_chain.public_inputs.epoch_created == epoch_created`
   - `epoch_validated_through == e_prev + 1`
   - `accumulator == poseidon2(prior_chain.public_inputs.accumulator, frozen_root_next)`
   - `η = poseidon(commitment, spending_key, e_prev)`
   - Sorted-low-leaf check: `low_leaf < η < low_leaf_next_value`, and the supplied Merkle path with `low_leaf` at `leaf_index` reconstructs to `frozen_root_next`.

Branch soundness: `is_base_case` is private but constraint set #1 forces `epoch_validated_through == epoch_created` and `accumulator == 0`. A spender cannot fake the base case for a note with `epoch_created < currentEpoch` because the spend circuit enforces `chain.epoch_validated_through == currentEpoch` and the on-chain accumulator check binds to real frozen roots.

### Spend Circuit (Transfer / Withdraw, diff)

Outer artifact, verified on-chain. MUST be zero-knowledge.

New public inputs:

- Per input note: `commitment_in: Field`, `epoch_created_in: u64`, `chain_accumulator_in: Field`.
- Global: `current_epoch: u64`.

New private inputs (per input note): `chain_proof.{vk, proof, public_inputs}`.

New constraints (per input note):

1. `assert verify(chain_proof.vk, chain_proof.proof, chain_proof.public_inputs)`
2. `chain_proof.vk == FixedVK`
3. `chain_proof.public_inputs.commitment == commitment_in`
4. `chain_proof.public_inputs.epoch_created == epoch_created_in`
5. `chain_proof.public_inputs.accumulator == chain_accumulator_in`
6. `chain_proof.public_inputs.epoch_validated_through == current_epoch` (for a fresh note this holds via the base case).
7. `nullifier_active = poseidon(commitment_in, spending_key, current_epoch)` (replaces parent's `poseidon2(commitment, spending_key)`).
8. `commitment_out_i == poseidon(token_out_i, amount_out_i, owner_out_i, salt_out_i, current_epoch)` (outputs minted with `epoch_created == current_epoch`).

Value preservation, token consistency, and commitment-tree membership are unchanged from the parent SPEC.

Contract-side public-input checks: `chain_accumulator_in == expectedChainAccumulator(epoch_created_in)` per input, `current_epoch == self.currentEpoch`, `nullifier_active ∉ activeNullifiers[currentEpoch]`.

---

## Security Model

### Threat Model (additions to parent)

| Adversary | Capabilities | Mitigations |
|---|---|---|
| Malicious PIR / state-replica server | Sees query traffic; MAY serve incorrect nodes | InsPIRe single-server malicious-server model for privacy; every returned node is re-checked against a light-client-verified root inside a circuit |
| Untrusted RPC for root reads | MAY misreport `commitment_root` or `frozenNullifierRoots[e]` | Roots MUST be read through a light client verifying storage proofs against consensus |
| Malicious wallet attempting cross-epoch double-spend | Holds spending key; MAY spend the same note in two epochs or forge a chain against fabricated roots | `epoch_created` bound into commitment; spend circuit enforces `chain.epoch_validated_through == current_epoch`; contract enforces `accumulator == expectedChainAccumulator(epoch_created)`; chain VK constrained to `FixedVK` |
| Network observer | Sees IP, timing, size of PIR sessions | Out of scope; production SHOULD use Tor or batched windows |

The parent threat model (public observer, malicious relayer, compromised viewing key, malicious compliance authority) is unchanged.

### Guarantees (additions to parent)

| Property | Description |
|---|---|
| Query privacy | The state-replica server learns nothing about the queried tree index beyond what query timing publicly reveals. |
| Witness correctness | A malicious server cannot induce a valid spend against an incorrect path, non-membership witness, or chain proof: reconstructions are re-checked in-circuit against light-client roots, and accumulators are re-checked on-chain. |
| Cross-epoch double-spend safety | A note can be spent in at most one epoch. Range `[epoch_created, current_epoch - 1]` is bound by the commitment and on-chain accumulator check; the active-set uniqueness check covers the final epoch. |
| Bounded active state | Validators retain only the active-epoch nullifier set; past epochs are anchored by one `bytes32` each. |
| Constant-cost spend (when chain is current) | Spend-circuit recursion cost is independent of note age once `epoch_validated_through == currentEpoch`. |

### Limitations & Shortcuts (PoC Scope)

| Limitation | Impact | Production Mitigation |
|---|---|---|
| No correlated-query defense | Sequential PIR sessions from the same wallet/IP link via network metadata | Mixnet, Tor, or per-block batching |
| Chain catch-up cost on offline wallets | A wallet offline for `k` epochs pays `O(k)` sequential chain-update proofs and `O(k)` PIR queries before spending | Tachyon-style shared accumulator |
| Per-spend `O(k)` on-chain accumulator hashing | `expectedChainAccumulator` costs `O(currentEpoch - epoch_created)` SLOADs and Poseidon hashes | On-chain Merkle of frozen roots, or shared accumulator |
| Wallet maintains a chain proof per held note | Per-note state plus incremental proofs at every rollover | Shared accumulator removes per-note state |
| Centralized epoch rollover | Owner-only `rolloverEpoch()` is a liveness single point | Decentralized trigger |
| Single state-replica server | Spend liveness depends on one replica; logs allow reconstruction so funds are safe | Multiple independent replicas |
| Recursive prover maturity | Required capabilities are not uniformly stable across systems | Pin a version; track upstream releases |
| No PIR over the encrypted note log | Note discovery requires trial decryption or operator-side filtering | FMD / OMR (future extension) |
| No post-quantum primitives | Note encryption uses ECDH/AEAD as in parent | Lattice KEM and signatures |

---

## Terminology

| Term | Definition |
|---|---|
| PIR | Private Information Retrieval. Client fetches row `i` from a server-held database without revealing `i`. |
| Silent preprocessing | PIR preprocessing model with all setup server-side; no client hint download. |
| Frozen epoch | Past epoch whose nullifier set has been committed to a single root on-chain; tree content hosted off-chain. |
| Non-membership witness | Sorted-low-leaf Merkle witness proving absence from an indexed Merkle tree. |
| State-replica server | Off-chain service hosting flattened node arrays of the commitment tree and frozen nullifier trees; answers PIR queries. |
| Light client | Verifies Ethereum headers and storage proofs against consensus. |
| Chain proof | Per-note off-chain proof of non-spend from `epoch_created` through `epoch_validated_through - 1`. |
| IVC | Incrementally Verifiable Computation. Each invocation recursively verifies its predecessor; permits bounded-memory step-wise extension. |
| Base-case sentinel | Genesis chain proof with `epoch_validated_through == epoch_created` and `accumulator == 0`. |
| Chain accumulator | Running Poseidon hash binding a chain proof to the sequence of frozen roots; recomputable on-chain. |

---

## References

Normative and background:

- InsPIRe: Mahdavi, Patel, Seo, Yeo, "Communication-Efficient PIR with Server-side Preprocessing". IACR ePrint 2025/1352. <https://eprint.iacr.org/2025/1352>
- Bowe, Miers, "A Note on Notes: Towards Scalable Anonymous Payments via Evolving Nullifiers and Oblivious Synchronization". IACR ePrint 2025/2031. <https://eprint.iacr.org/2025/2031>
- tree-pir: <https://github.com/brech1/tree-pir>
- Helios light client: <https://github.com/a16z/helios>
- Polygon Miden, "Epoch-based nullifier database": <https://github.com/0xMiden/miden-vm/discussions/356>
- Aztec, "Global State Epochs": <https://forum.aztec.network/t/global-state-epochs/2704>
- A. Tomescu, "Notes on scaling nullifier sets": <https://alinush.github.io/nullifiers>
- Parent: [`../../SPEC.md`](../../SPEC.md)
- Parent: [`../../../REQUIREMENTS.md`](../../../REQUIREMENTS.md)

Reference instantiation (non-normative):

- Noir standard library, "Recursion": <https://noir-lang.org/docs/noir/standard_library/recursion>
- Aztec `bb_proof_verification`: <https://github.com/AztecProtocol/aztec-packages/tree/master/barretenberg/noir/bb_proof_verification>
- noir-examples, "Recursion": <https://github.com/noir-lang/noir-examples/tree/master/recursion>
