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

Nullifier-set bloat. The on-chain nullifier set grows linearly with history and is never pruned. At Visa-scale throughput (~150 M tx/day, 32 B per nullifier) this is ~5 GB/day in raw nullifier bytes alone, before tree overhead. Beyond the multi-terabyte range the set of entities able to host it shrinks to a few well-resourced providers; see Bowe and Miers (ePrint 2025/2031) for fuller analysis.

This extension addresses both. PIR over the pre-spend tree reads hides which leaf the wallet queried from the serving node, breaking the leaf-index-to-identity link. Epoch-based nullifiers bound the active on-chain set: past epochs are anchored by one Merkle root each, with tree content hosted by the same off-chain state-replica server that answers PIR queries.

A per-note recursive chain proof (IVC) keeps per-spend work bounded: the wallet extends it one step per rollover, and the spend circuit recursively verifies one chain proof instead of inlining `k` non-membership checks. The commitment binds `epoch_created` so the verifier can enforce that the chain covers the note's full lifetime. Deposit and attestation flows are otherwise unchanged.

Non-membership witnesses for unspent (phantom) epochs carry no on-chain footprint, so they are served in clear; PIR is reserved for the commitment-path read and the single current-epoch nullifier lookup. This relaxes full oblivious synchronization in exchange for far fewer private queries per spend (see Off-Chain State-Replica Server and Limitations).

---

## Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

---

## Proof System Requirements

This extension is proof-system agnostic. Required capabilities: an EVM-verifiable outer artifact with a succinct on-chain verifier (cost depends only on public-input length, not on circuit size), in-circuit recursive verification of the system's own proofs, the ability to bind a verifying key as a circuit value, zero-knowledge for spend proofs (chain-update proofs need not be zk), and support for branching the recursive verify on a base case (via circuit-level conditionals or a sentinel proof).

Notation: `assert recursive_verify(inner_vk, inner_statement, inner_proof)` denotes the in-circuit primitive asserting that `inner_proof` is a valid proof of `inner_statement` under `inner_vk`. All three are witnesses to the outer circuit; the outer circuit MAY re-expose any of them as its own public inputs depending on what the consuming verifier (on-chain contract or outer recursion layer) must bind to. `FixedVK` is the chain-update circuit's verifying key, fixed at deployment.

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
| `ShieldedPool` on-chain state | Extended: `currentEpoch`, `frozenNullifierRoots`, `activeNullifierRoot`, `rolloverEpoch()`; spend tx supplies per-input-note `epoch_created` (so the contract recomputes the expected chain accumulator) and `(pre_active_root, post_active_root)` (so the contract advances the active-tree root) |
| Per-note chain proof | New: maintained off-chain by the wallet; extended one step per epoch rollover (or `k` steps at wake-up after offline periods) |

---

## Approach

| Gap | Primitive |
|---|---|
| State-read privacy | InsPIRe ([eprint 2025/1352](https://eprint.iacr.org/2025/1352)): single-server PIR with silent preprocessing |
| Database layout | Raw flattened Merkle node arrays per [`tree-pir`](https://github.com/brech1/tree-pir); wallet fetches `log(N)` sibling nodes per spend via batched PIR query. Commitment tree is a LeanIMT (append-only, membership only); active and frozen nullifier trees are indexed Merkle trees (sorted leaves with `next_value`/`next_index` pointers, supporting sorted-low-leaf non-membership and insertion) |
| Root authenticity | Light client (e.g. Helios) verifies `commitment_root` and `frozenNullifierRoots[e]` against consensus; paths are reconstructed against these roots in wallet and circuit |
| Nullifier bloat | Coarse epoch-based nullifiers; cross-epoch non-membership folded into a per-note recursive chain proof (IVC), verified once by the spend circuit regardless of note age |
| Spend-time per-note coverage | Commitment binds `epoch_created`, letting the verifier enforce chain coverage over the note's full lifetime |
| Phantom-epoch query privacy | Nullifiers for unspent (phantom) epochs never touch the chain, so their non-membership witnesses are served in clear; PIR is reserved for the commitment read and the single current-epoch low-leaf lookup (whose nullifier becomes the on-chain spend artifact) |

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
// Active-epoch nullifier set is an indexed Merkle tree; the contract holds
// only the current root and a leaf counter, advanced by each spend and reset on rollover.
bytes32 public activeNullifierRoot;
uint64  public activeLeafCount;   // next free slot = canonical append index
bytes32 public constant EMPTY_IMT_ROOT = /* root of an empty indexed Merkle tree, fixed at deployment */;

/// PoC: owner-only. Production: decentralized trigger.
function rolloverEpoch() external onlyOwner;

/// View helper: recomputes the chain accumulator the spend circuit must match.
function expectedChainAccumulator(uint64 epochCreated) external view returns (bytes32);
```

The active-epoch nullifier set is an indexed Merkle tree: leaves are sorted by value and each leaf carries a `(next_value, next_index)` pointer to the next-larger leaf. Absence of η is proven with a `low_leaf` where `low_leaf.value < η < low_leaf.next_value`. Inserting η mutates two leaves: the predecessor (its `next_value`/`next_index` repoint to η) and a freshly written leaf at the next free slot. The spend circuit performs the insertion in-circuit (see Spend Circuit diff), so the contract sees only `(pre_active_root, post_active_root)` plus the leaf count and accepts the transition by verifying the spend proof. A valid sorted-low-leaf insertion is itself a non-membership proof of η in the prior tree, so no separate `activeNullifiers` mapping or uniqueness check is needed. On-chain active-tree state is one `bytes32` and one counter; per-leaf state is held off-chain and reconstructible from event logs.

Canonical append. New leaves are placed at sequential indices starting from `activeLeafCount`, so the post-root is a deterministic function of the inserted-nullifier sequence. A replica replaying the emitted nullifiers in block-then-input order reproduces the identical tree and root. The circuit enforces both the sequential index and that the target slot was empty, so a spend cannot overwrite an existing nullifier leaf.

On `rolloverEpoch()`: `frozenNullifierRoots[currentEpoch] = activeNullifierRoot`, then `activeNullifierRoot = EMPTY_IMT_ROOT`, `activeLeafCount = 0`, `currentEpoch += 1`, emit `EpochRollover(uint64 epoch, bytes32 root)`.

Epoch cadence. The protocol does not impose an epoch duration; one epoch is whatever period elapses between two `rolloverEpoch()` calls. The PoC targets one rollover per month. Production deployments SHOULD pin a fixed cadence (e.g. one rollover every `N` blocks, or one per calendar period) so wallets and replicas can plan capacity. Coarse cadence directly bounds `k`, which sets both the per-spend on-chain accumulator hashing cost and the maximum chain-update work a wallet pays after an offline period.

On every `transfer` / `withdraw`: read each input note's `epoch_created` from public inputs, revert if `accumulator != expectedChainAccumulator(epoch_created)`, revert if `pre_active_root != activeNullifierRoot` or `pre_leaf_count != activeLeafCount`, then set `activeNullifierRoot = post_active_root` and `activeLeafCount += k`. The spend proof internally chains `k` sorted-low-leaf insertions (one per input nullifier) from `pre_active_root` to `post_active_root`, appending at indices `pre_leaf_count .. pre_leaf_count + k - 1`; a repeated η across two inputs of the same tx fails the second insertion because the low-leaf check would no longer be strict.

```solidity
function expectedChainAccumulator(uint64 epochCreated) public view returns (bytes32) {
    bytes32 acc = bytes32(0);
    for (uint64 e = epochCreated; e < currentEpoch; e++) {
        acc = poseidon2(acc, frozenNullifierRoots[e]);
    }
    return acc;
}
```

Active-epoch spends are caught by the in-circuit indexed-tree insertion: any prior occurrence of η in the active tree makes the sorted-low-leaf proof unsatisfiable, so no separate uniqueness check is needed. On-chain gas per spend: `O(currentEpoch - epochCreated)` SLOADs and Poseidon hashes in `expectedChainAccumulator`, plus a constant-size pre/post-root comparison and root write; bounded by coarse epochs (monthly target).

---

## Off-Chain State-Replica Server

One server replicates public on-chain state and exposes a PIR endpoint. Hosted data (raw flattened Merkle nodes per [`tree-pir`](https://github.com/brech1/tree-pir), addressed as `(tree_id, node_offset)`):

| Tree | Construction | Source | Used for |
|---|---|---|---|
| Commitment tree | LeanIMT | `Deposit`, `Transfer` events | Membership witness of input notes (leaf-index known to wallet from its own minting event) |
| Active nullifier tree (current epoch) | Indexed Merkle tree | `Transfer`, `Withdraw` events since the last `EpochRollover` | Sorted-low-leaf insertion witness for the spend circuit's in-circuit active-tree update; PIR-served (current-epoch nullifier becomes the on-chain spend artifact) |
| Frozen nullifier tree (per past epoch `e`) | Indexed Merkle tree | `Transfer`, `Withdraw`, `EpochRollover` events | Sorted-low-leaf non-membership witness for the chain-update circuit; served in clear (phantom nullifiers have no on-chain footprint) |

The contract retains only roots (one live `activeNullifierRoot` plus one `frozenNullifierRoots[e]` per past epoch), so the server reconstructs every tree from event logs and offers them as a shared service.

Query model, phantom vs current epoch. A note's per-epoch nullifiers `η_e = poseidon(commitment, spending_key, e)` for `e` in `[epoch_created, currentEpoch - 1]` are phantoms: the note was not spent in those epochs, so these values never appear on-chain. With no on-chain footprint to correlate against, the wallet sends a phantom to the server in clear and receives the sorted-low-leaf non-membership witness; correctness is re-checked in-circuit against the light-client root, so a malicious witness cannot produce a valid spend. No PIR and no local index are needed for phantom epochs.

The current-epoch nullifier `η_{currentEpoch}` is the exception: it becomes the on-chain spend artifact, so revealing it or its low-leaf neighbourhood before the transaction lands would let the server link the querying client to the spend. So the current-epoch low-leaf lookup stays private. The wallet keeps a local sorted `(value, leaf_index)` index of the current epoch's active tree (rebuilt from events since the last rollover), finds the predecessor leaf-index locally, then issues one index-addressed PIR query for that leaf and its sibling path. The commitment-membership read is PIR'd the same way, with the leaf-index known from the note's minting event. PIR is therefore consulted in exactly two places per spend; the `k - 1` phantom witnesses are served in clear.

The server is untrusted for correctness. Returned nodes are reassembled client-side into a root and compared against the light-client-verified on-chain root; both circuits re-check the same reconstructions.

Root-fetch scheduling. Wallets MUST issue `eth_getProof` for `commitment_root` and any newly-emitted `frozenNullifierRoots[e]` on a fixed schedule, independent of intent to spend: poll `commitment_root` every `T` blocks and pull `frozenNullifierRoots[e]` immediately on observing each `EpochRollover(e)` event. The RPC therefore sees a uniform stream of queries shared by every active wallet, and cannot link a fetch to an imminent spend. Privacy reduces to k-anonymity over the active user base; the only metadata that remains is "this client is a ShieldedPool user," which is already public for anyone who has ever deposited or withdrawn.

Light-client check (pseudocode). Reconciliation walks the two-level MPT from the consensus-verified header down to the contract's storage slot:

```
// Inputs: contract address C, storage slot s, expected value v.
header                       = LightClient.latest_finalized_header()  // verified vs consensus
{ accountProof, storageProof,
  storageHash, value }       = rpc.eth_getProof(C, [s], header.block_number)

// Level 1: header.state_root commits to all accounts.
//   Verify C's account leaf and extract its storageHash.
assert verify_mpt(
    root  = header.state_root,
    key   = keccak256(C),
    leaf  = rlp({nonce, balance, storageHash, codeHash}),
    proof = accountProof,
)

// Level 2: storageHash commits to all storage slots of C.
//   For mapping slot: slot = keccak256(abi.encode(mappingKey, baseSlot)).
assert verify_mpt(
    root  = storageHash,
    key   = keccak256(s),
    leaf  = rlp(value),
    proof = storageProof,
)

assert value == v
```

Run once per `commitment_root` consumed at spend time, and once per `frozenNullifierRoots[e]` consumed during chain extension.

Frozen nullifier trees are served in clear (no PIR), so no PIR preprocessing applies to them. The active nullifier tree and the commitment tree are PIR-served and mutate continuously; preprocessing amortization across those mutations is out of scope.

---

## Flows

The wallet maintains one `ChainProof` per owned note, updated either eagerly on each observed `EpochRollover` (one proof per rollover per held note) or lazily before spend (one proof per missed epoch, sequential). By spend time, `epoch_validated_through == currentEpoch`.

### Chain Maintenance (wallet-local; new)

1. Wallet observes `EpochRollover(e_frozen, root)` and verifies the root via the light client.
2. For each owned note with `ChainProof.epoch_validated_through == e_frozen`, the wallet computes the phantom `η_{e_frozen} = poseidon(commitment, spending_key, e_frozen)` and sends it to the server in clear; the server returns the sorted-low-leaf non-membership witness against the just-frozen tree (see Off-Chain State-Replica Server, query model).
3. Wallet runs the chain-update circuit, which recursively verifies the prior chain proof, reconstructs `frozenNullifierRoots[e_frozen]` from the server-returned siblings, checks `η_{e_frozen}` absent under the sorted-low-leaf pattern, folds it into the accumulator, and emits a new `ChainProof` with `epoch_validated_through = e_frozen + 1`.
4. Wallet stores the new chain proof and discards the previous one.

Catch-up: an offline wallet runs steps 2-3 sequentially per missed epoch. Work is bounded-memory and resumable.

### Note Genesis (sentinel chain proof)

On note creation (via `Deposit` or as a `Transfer` output), the owner generates an initial `ChainProof` with `epoch_validated_through = epoch_created`, `accumulator = 0`. The chain-update circuit handles this via its base-case branch (`epoch_validated_through == epoch_created`), which skips prior-proof verification.

### Private Transfer (extended)

1. Catch up each input note's `ChainProof` to `epoch_validated_through == currentEpoch` via Chain Maintenance (phantom-epoch witnesses fetched in clear). Notes created in the current epoch already satisfy this via their genesis proof.
2. PIR-fetch `log(N)` sibling nodes per input commitment, reconstruct the root, and assert equality with the light-client-verified `commitment_root`.
3. For each input note's `η_{currentEpoch}`, locate the predecessor leaf-index in the wallet's local sorted index of the current epoch's active tree and PIR-fetch the predecessor leaf and its sibling path. This is the only private nullifier query, since `η_{currentEpoch}` becomes the on-chain spend artifact. The wallet then composes `k` sorted-low-leaf insertion witnesses into a chain advancing from `pre_active_root` (the on-chain current root) to `post_active_root`.
4. Run the spend circuit with per-input chain proofs, commitment-tree membership witnesses, the chained active-tree insertion witnesses, spending key, and output note data (`epoch_created = currentEpoch`).
5. Submit via relayer with the proof and public inputs: per-input `(nullifier_active, epoch_created, accumulator)` triples plus the global `(pre_active_root, post_active_root, pre_leaf_count, current_epoch)`. Input commitments stay private.
6. Contract verifies the proof, checks `accumulator == expectedChainAccumulator(epoch_created)` per input and `pre_active_root == activeNullifierRoot`, sets `activeNullifierRoot = post_active_root`, inserts output commitments, emits `Transfer` carrying the per-input `nullifier_active` values so replicas can rebuild the active indexed tree.

PIR is used only for the commitment read (step 2) and the current-epoch low-leaf lookup (step 3); phantom-epoch witnesses (step 1) are served in clear. The server is never trusted for roots: every returned node is re-checked in-circuit against the light-client root.

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

Kept separate from the spend circuit because (a) chain-update proofs are consumed only recursively and need not be zero-knowledge or EVM-verifiable, while spend proofs are both; (b) the two have different public-input shapes; (c) keeping the recursion-frequent artifact small reduces wallet proving time across the typical update sequence. An implementation MAY merge them into one circuit with a mode flag, at the cost of paying ZK and EVM-target overhead on every chain update.

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
- `token, amount, salt: Field`: the input note's remaining commitment preimage (`commitment` and `epoch_created` are already public inputs).
- `non_membership.{low_leaf, low_leaf_next_value, path, indices, leaf_index}`: sorted-low-leaf witness against `frozen_root_next`.

Constraints:

Let `e_prev = prior_chain.public_inputs.epoch_validated_through`.

1. Base-case branch (`is_base_case == true`):
   - `epoch_validated_through == epoch_created`
   - `accumulator == 0`
   - No recursive verify, no non-membership check.

2. Inductive branch (`is_base_case == false`):
   - `assert recursive_verify(prior_chain.vk, prior_chain.public_inputs, prior_chain.proof)`
   - `prior_chain.vk == FixedVK` (the chain-update circuit's own VK)
   - `prior_chain.public_inputs.commitment == commitment`
   - `prior_chain.public_inputs.epoch_created == epoch_created`
   - `epoch_validated_through == e_prev + 1` (advances by one rollover; see "Epoch Cadence" below for what one rollover represents)
   - `accumulator == poseidon2(prior_chain.public_inputs.accumulator, frozen_root_next)`
   - Key binding: `owner_pubkey == poseidon(spending_key)` and `commitment == poseidon(token, amount, owner_pubkey, salt, epoch_created)`. The public `commitment` thus pins `spending_key` to the note's real owner key, so the nullifier below is the one that would actually have been published if the note were spent in `e_prev`. Without this, a prover could supply a fabricated `spending_key`, derive a phantom η that is trivially absent, and pass non-membership while the real nullifier sits in the frozen tree.
   - `η = poseidon(commitment, spending_key, e_prev)`
   - Sorted-low-leaf check: `low_leaf < η < low_leaf_next_value`, and the supplied Merkle path with `low_leaf` at `leaf_index` reconstructs to `frozen_root_next`.

Branch soundness: `is_base_case` is private but constraint set #1 forces `epoch_validated_through == epoch_created` and `accumulator == 0`. A spender cannot fake the base case for a note with `epoch_created < currentEpoch` because the spend circuit enforces `chain.epoch_validated_through == currentEpoch` and the on-chain accumulator check binds to real frozen roots.

### Spend Circuit (Transfer / Withdraw, diff)

Outer artifact, verified on-chain. MUST be zero-knowledge.

New public inputs:

- Per input note `i`: `nullifier_active_i: Field`, `epoch_created_in_i: u64`, `chain_accumulator_in_i: Field`.
- Global: `current_epoch: u64`, `pre_active_root: Field`, `post_active_root: Field`, `pre_leaf_count: u64` (in addition to the parent's output commitments and `commitment_root`).

`nullifier_active_i` is public and emitted in the `Transfer` / `Withdraw` event so replicas can rebuild the active indexed tree from the event log. `commitment_in_i` is kept private (below) for unlinkability, matching the parent: only the nullifier becomes the public spend artifact, never the input commitment.

New private inputs:

- Per input note `i`: `commitment_in_i: Field`, proven a member of the commitment tree against `commitment_root`.
- Per input note `i`: `chain_proof_i.{vk, proof, public_inputs}`.
- Per input note `i`: `active_insertion_i.{low_leaf, low_leaf_index, low_leaf_path, new_leaf_path}`, the indexed-tree insertion witness. `low_leaf_path` authenticates the predecessor at `low_leaf_index`; `new_leaf_path` authenticates the (empty) append slot. The append index is not a free input: it is fixed to `pre_leaf_count + (i - 1)` by the constraints below.

New constraints (per input note `i`):

1. `assert recursive_verify(chain_proof_i.vk, chain_proof_i.public_inputs, chain_proof_i.proof)`
2. `chain_proof_i.vk == FixedVK`
3. `chain_proof_i.public_inputs.commitment == commitment_in_i`
4. `chain_proof_i.public_inputs.epoch_created == epoch_created_in_i`
5. `chain_proof_i.public_inputs.accumulator == chain_accumulator_in_i`
6. `chain_proof_i.public_inputs.epoch_validated_through == current_epoch` (for a fresh note this holds via the base case).
7. `nullifier_active_i == poseidon(commitment_in_i, spending_key, current_epoch)` (replaces parent's `poseidon2(commitment, spending_key)`); the result is the public input of the same name and is emitted in the event.

New constraint (per output note `j`):

8. `commitment_out_j == poseidon(token_out_j, amount_out_j, owner_out_j, salt_out_j, current_epoch)` (outputs minted with `epoch_created == current_epoch`).

Active-tree insertion chain (single pass threading the root through all `k` input nullifiers). Let `r_0 = pre_active_root`. For each input `i = 1..k`, with canonical append index `new_leaf_index = pre_leaf_count + (i - 1)`:

1. Predecessor membership and non-membership: `low_leaf` at `low_leaf_index` with `low_leaf_path` reconstructs to `r_{i-1}`, and `low_leaf.value < nullifier_active_i < low_leaf.next_value`.
2. Mutate predecessor: `low_leaf_updated = (value = low_leaf.value, next_value = nullifier_active_i, next_index = new_leaf_index)`. Recompute the intermediate root `r'` from `r_{i-1}` along `low_leaf_path`.
3. Empty-slot check: `new_leaf_path` proves the slot at `new_leaf_index` holds the empty leaf in `r'`. This prevents overwriting an existing nullifier leaf.
4. Write new leaf: `new_leaf = (value = nullifier_active_i, next_value = low_leaf.next_value, next_index = low_leaf.next_index)` at `new_leaf_index`. Recompute `r_i` from `r'` along `new_leaf_path`.

Final constraints: `r_k == post_active_root` and the append range is exactly `[pre_leaf_count, pre_leaf_count + k - 1]` (the contract sets `activeLeafCount += k`).

Two leaves change per insertion (predecessor and new slot), so each step carries two paths and is applied in sequence: the predecessor mutation produces `r'`, and the new-leaf write is proven against `r'`, since the two positions may share internal nodes. Double-spend prevention follows from step 1: any prior occurrence of `nullifier_active_i` in the active tree (from a past spend, or an earlier input in the same tx) breaks the strict `low_leaf.value < nullifier_active_i < low_leaf.next_value` inequality and makes the proof unsatisfiable.

Input commitment reconstruction (changed from parent): each input note's commitment is reconstructed inside the circuit as `commitment_in_i == poseidon(token_in_i, amount_in_i, owner_in_i, salt_in_i, epoch_created_in_i)`, gaining `epoch_created_in_i` over the parent's four-field preimage, and the commitment-tree membership witness is verified against this reconstructed value. The membership-proof shape (Merkle path against `commitment_root`) is unchanged; only the leaf preimage differs. Value preservation and token consistency are unchanged from the parent SPEC.

Contract-side public-input checks: `chain_accumulator_in_i == expectedChainAccumulator(epoch_created_in_i)` per input, `current_epoch == self.currentEpoch`, `pre_active_root == self.activeNullifierRoot`, `pre_leaf_count == self.activeLeafCount`. On success: `self.activeNullifierRoot = post_active_root` and `self.activeLeafCount += k`.

---

## Security Model

### Threat Model (additions to parent)

| Adversary | Capabilities | Mitigations |
|---|---|---|
| Malicious PIR / state-replica server | Sees query traffic; MAY serve incorrect nodes | InsPIRe single-server malicious-server model for privacy; every returned node is re-checked against a light-client-verified root inside a circuit |
| Oblivious-sync server profiling a wallet | Receives phantom nullifiers `η_e` in clear; MAY profile a wallet's note ages and portfolio size, and across colluding servers link the same note across providers | Phantoms have no on-chain footprint, so the public spend stays unlinkable to these queries; the leak is per-wallet metadata to the serving party only. PoC accepts this; production SHOULD use oblivious nullifier derivation and synchronization (Bowe and Miers 2025/2031) so the service stays oblivious. See Limitations. |
| Untrusted RPC for root reads | MAY misreport `commitment_root` or `frozenNullifierRoots[e]` | Roots MUST be read through a light client verifying storage proofs against consensus |
| Malicious wallet attempting cross-epoch double-spend | Holds spending key; MAY spend the same note in two epochs, forge a chain against fabricated roots, or build the chain under a fabricated spending key | `epoch_created` bound into commitment; spend circuit enforces `chain.epoch_validated_through == current_epoch`; contract enforces `accumulator == expectedChainAccumulator(epoch_created)`; chain VK constrained to `FixedVK`; chain-update circuit binds `spending_key` to the public `commitment` via `owner_pubkey == poseidon(spending_key)`, so phantom non-membership cannot be proven under a fake key |
| Network observer | Sees IP, timing, size of PIR sessions | Out of scope; production SHOULD use Tor or batched windows |

The parent threat model (public observer, malicious relayer, compromised viewing key, malicious compliance authority) is unchanged.

### Guarantees (additions to parent)

| Property | Description |
|---|---|
| Query privacy (PIR'd reads) | For the two PIR'd reads, commitment membership and the current-epoch low-leaf lookup, the server learns nothing about the queried index beyond timing. Phantom-epoch non-membership is intentionally served in clear, so the server does learn those phantom nullifiers (see Threat Model, Limitations); this never links to the on-chain spend. |
| Witness correctness | A malicious server cannot induce a valid spend against an incorrect path, non-membership witness, or chain proof: reconstructions are re-checked in-circuit against light-client roots, and accumulators are re-checked on-chain. |
| Cross-epoch double-spend safety | A note can be spent in at most one epoch. Range `[epoch_created, current_epoch - 1]` is bound by the commitment and on-chain accumulator check; the current epoch is covered by the in-circuit sorted-low-leaf insertion against `activeNullifierRoot`, which fails if η already appears in the active tree. |
| Bounded active state | On-chain state per epoch is one `bytes32` (`activeNullifierRoot`, overwritten on each spend, reset on rollover) plus one `bytes32` per past epoch (`frozenNullifierRoots[e]`). Per-leaf state of the active and frozen trees lives off-chain and is reconstructible from event logs, so on-chain storage does not grow per nullifier. |
| Constant-cost spend circuit (when chain is current) | Spend-circuit verification cost is independent of note age once `epoch_validated_through == currentEpoch`: one recursive chain-proof verify regardless of how many epochs the note has lived. |
| Linear contract-side accumulator check | The on-chain check is not constant: `expectedChainAccumulator(epoch_created)` costs `O(currentEpoch - epoch_created)` SLOADs and Poseidon hashes, linear in the number of frozen epochs the note spans. Bounded in practice by coarse epochs (monthly target); see Limitations for the production mitigation (on-chain Merkle of frozen roots, or shared accumulator). |

### Limitations & Shortcuts (PoC Scope)

| Limitation | Impact | Production Mitigation |
|---|---|---|
| Chain catch-up cost on offline wallets | A wallet offline for `k` epochs pays `O(k)` sequential chain-update proofs and `O(k)` in-clear non-membership queries before spending | Tachyon-style shared accumulator |
| Per-spend `O(k)` on-chain accumulator hashing | `expectedChainAccumulator` costs `O(currentEpoch - epoch_created)` SLOADs and Poseidon hashes | On-chain Merkle of frozen roots, or shared accumulator |
| Wallet maintains a chain proof per held note | Per-note state plus incremental proofs at every rollover | Shared accumulator removes per-note state |
| Centralized epoch rollover | Owner-only `rolloverEpoch()` is a liveness single point | Decentralized trigger |
| Single state-replica server | Spend liveness depends on one replica; logs allow reconstruction so funds are safe | Multiple independent replicas |
| Active-root write contention | The active tree is advanced through a single `activeNullifierRoot`. A spend built against a `pre_active_root` that another spend has already superseded reverts, and its insertion witness (including the low-leaf predecessor) must be rebuilt against the new root. Concurrent spends therefore serialize. | Relayer/sequencer that orders spends and rebuilds witnesses, or batched multi-spend active-tree updates |
| Server-side metadata leak (in-clear phantom serving) | The state-replica server learns a wallet's phantom nullifiers, hence note ages and portfolio metadata (not its on-chain spends); colluding servers can link the same note across providers | Oblivious nullifier derivation and synchronization (Bowe and Miers 2025/2031, Project Tachyon), keeping the syncing service oblivious |
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
| Indexed Merkle tree | Merkle tree whose leaves are sorted by value and carry `(next_value, next_index)` pointers to the next-larger leaf; supports both sorted-low-leaf non-membership and ordered insertion proofs. The active and frozen nullifier trees use this construction. |
| LeanIMT | Lean Incremental Merkle Tree (Semaphore); an append-only Merkle tree variant. The commitment tree uses this construction (membership only, no ordering needed). |
| Non-membership witness | Sorted-low-leaf Merkle witness proving absence from an indexed Merkle tree. |
| State-replica server | Off-chain service hosting flattened node arrays of the commitment tree and the active/frozen nullifier trees. Answers PIR queries for the commitment-path read and the current-epoch low-leaf lookup, and serves phantom (frozen-epoch) non-membership witnesses in clear. |
| Phantom nullifier | A note's per-epoch nullifier `η_e` for an epoch in which the note was not spent; never emitted on-chain, so it can be revealed to the state-replica server without linking to any on-chain transaction. |
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
- Parent SPEC: [`../shielded-pool/SPEC.md`](../shielded-pool/SPEC.md)
- Parent REQUIREMENTS: [`../REQUIREMENTS.md`](../REQUIREMENTS.md)

Reference instantiation (non-normative):

- Noir standard library, "Recursion": <https://noir-lang.org/docs/noir/standard_library/recursion>
- Aztec `bb_proof_verification`: <https://github.com/AztecProtocol/aztec-packages/tree/master/barretenberg/noir/bb_proof_verification>
- noir-examples, "Recursion": <https://github.com/noir-lang/noir-examples/tree/master/recursion>
