use bb_proof_verification::{UltraHonkVerificationKey, UltraHonkZKProof, verify_honk_proof};
use poseidon::poseidon::bn254::{hash_1, hash_2, hash_3, hash_5};

// Transfer spend circuit (extended, 2-in-2-out). See ../../SPEC.md "Spend
// Circuit (Transfer / Withdraw, diff)".
//
// Per input: reconstruct the commitment binding `epoch_created` (parent key
// binding owner_pubkey = poseidon(spending_key), now poseidon5), verify
// commitment-tree membership, recursively verify the note's ChainProof, and emit
// the per-epoch active nullifier `poseidon3(commitment, sk, current_epoch)`.
// Outputs are minted at `current_epoch`. Performs NO active-tree work (that is
// the relayer's insertion circuit). Value preservation + token consistency are
// inherited from the parent.

global MAX_COMMITMENT_TREE_DEPTH: u32 = 32;
global CHAIN_PROOF_PUB_LEN: u32 = 5;

fn poseidon1(a: Field) -> Field {
    hash_1([a])
}
fn poseidon2(a: Field, b: Field) -> Field {
    hash_2([a, b])
}
fn poseidon3(a: Field, b: Field, c: Field) -> Field {
    hash_3([a, b, c])
}
fn poseidon5(a: Field, b: Field, c: Field, d: Field, e: Field) -> Field {
    hash_5([a, b, c, d, e])
}

// LeanIMT commitment-tree membership (dynamic depth). Mirrors the off-chain
// `CommitmentMerkleProof::reconstruct_root`: fold the leaf up `proof_length`
// levels with poseidon2; `indices[i] == 0` => current node is the left child.
fn verify_membership(
    leaf: Field,
    root: Field,
    proof_length: u32,
    indices: [bool; MAX_COMMITMENT_TREE_DEPTH],
    path: [Field; MAX_COMMITMENT_TREE_DEPTH],
) {
    let mut node = leaf;
    for i in 0..MAX_COMMITMENT_TREE_DEPTH {
        if i < proof_length {
            if indices[i] {
                node = poseidon2(path[i], node);
            } else {
                node = poseidon2(node, path[i]);
            }
        }
    }
    assert(node == root, "membership: root mismatch");
}

// Recursively verify one input note's ChainProof and bind its public inputs to
// the spend's per-input values. The chain proof must be fully caught up
// (`epoch_validated_through == current_epoch`).
fn verify_input_chain(
    chain_vk: UltraHonkVerificationKey,
    chain_proof: UltraHonkZKProof,
    chain_pub: [Field; CHAIN_PROOF_PUB_LEN],
    chain_vk_hash: Field,
    commitment_in: Field,
    epoch_created_in: Field,
    current_epoch: Field,
    chain_accumulator_in: Field,
) {
    verify_honk_proof(chain_vk, chain_proof, chain_pub, chain_vk_hash);
    assert(chain_pub[0] == commitment_in, "chain: commitment mismatch");
    assert(chain_pub[1] == epoch_created_in, "chain: epoch_created mismatch");
    assert(chain_pub[2] == current_epoch, "chain: not caught up to current_epoch");
    assert(chain_pub[3] == chain_accumulator_in, "chain: accumulator mismatch");
    assert(chain_pub[4] == chain_vk_hash, "chain: vk_hash mismatch");
}

fn main(
    // Public inputs. Epochs are field-encoded integers.
    nullifier_active_0: pub Field,
    nullifier_active_1: pub Field,
    commitment_out_0: pub Field,
    commitment_out_1: pub Field,
    commitment_root: pub Field,
    current_epoch: pub Field,
    // Chain-update circuit's VK hash; the contract pins it to its deploy-time value.
    chain_vk_hash: pub Field,
    epoch_created_in_0: pub Field,
    epoch_created_in_1: pub Field,
    chain_accumulator_in_0: pub Field,
    chain_accumulator_in_1: pub Field,
    // Private inputs.
    spending_key: Field,
    token_in_0: Field,
    amount_in_0: u64,
    salt_in_0: Field,
    token_in_1: Field,
    amount_in_1: u64,
    salt_in_1: Field,
    token_out_0: Field,
    amount_out_0: u64,
    owner_out_0: Field,
    salt_out_0: Field,
    token_out_1: Field,
    amount_out_1: u64,
    owner_out_1: Field,
    salt_out_1: Field,
    proof_length: u32,
    path_0: [Field; MAX_COMMITMENT_TREE_DEPTH],
    indices_0: [bool; MAX_COMMITMENT_TREE_DEPTH],
    path_1: [Field; MAX_COMMITMENT_TREE_DEPTH],
    indices_1: [bool; MAX_COMMITMENT_TREE_DEPTH],
    // One shared chain-update VK; one ChainProof per input note.
    chain_vk: UltraHonkVerificationKey,
    chain_proof_0: UltraHonkZKProof,
    chain_pub_0: [Field; CHAIN_PROOF_PUB_LEN],
    chain_proof_1: UltraHonkZKProof,
    chain_pub_1: [Field; CHAIN_PROOF_PUB_LEN],
) {
    // Parent constraint 1: owner_pubkey is derived from the spending key, so a
    // valid spend proves ownership of the input notes.
    let owner_pubkey = poseidon1(spending_key);

    // --- Input 0 (always a real note) ---
    let commitment_in_0 =
        poseidon5(token_in_0, amount_in_0 as Field, owner_pubkey, salt_in_0, epoch_created_in_0);
    verify_membership(commitment_in_0, commitment_root, proof_length, indices_0, path_0);
    assert(
        nullifier_active_0 == poseidon3(commitment_in_0, spending_key, current_epoch),
        "nullifier_0 mismatch",
    );
    verify_input_chain(
        chain_vk,
        chain_proof_0,
        chain_pub_0,
        chain_vk_hash,
        commitment_in_0,
        epoch_created_in_0,
        current_epoch,
        chain_accumulator_in_0,
    );

    // --- Input 1 (may be a zero/padding note: amount 0, not in the tree) ---
    let commitment_in_1 =
        poseidon5(token_in_1, amount_in_1 as Field, owner_pubkey, salt_in_1, epoch_created_in_1);
    let is_zero_note = amount_in_1 == 0;
    if !is_zero_note {
        verify_membership(commitment_in_1, commitment_root, proof_length, indices_1, path_1);
        verify_input_chain(
            chain_vk,
            chain_proof_1,
            chain_pub_1,
            chain_vk_hash,
            commitment_in_1,
            epoch_created_in_1,
            current_epoch,
            chain_accumulator_in_1,
        );
    }
    // The nullifier is constrained even for a zero note (cannot be forged).
    assert(
        nullifier_active_1 == poseidon3(commitment_in_1, spending_key, current_epoch),
        "nullifier_1 mismatch",
    );

    // --- Outputs (minted with epoch_created == current_epoch) ---
    assert(
        commitment_out_0
            == poseidon5(token_out_0, amount_out_0 as Field, owner_out_0, salt_out_0, current_epoch),
        "commitment_out_0 mismatch",
    );
    assert(
        commitment_out_1
            == poseidon5(token_out_1, amount_out_1 as Field, owner_out_1, salt_out_1, current_epoch),
        "commitment_out_1 mismatch",
    );

    // --- Value preservation + token consistency (parent) ---
    assert(amount_in_0 + amount_in_1 == amount_out_0 + amount_out_1, "value not conserved");
    assert(token_in_0 == token_in_1, "input token mismatch");
    assert(token_in_0 == token_out_0, "output_0 token mismatch");
    assert(token_in_0 == token_out_1, "output_1 token mismatch");
}

// Recursive (full-spend) cases need real bb chain proofs and are exercised by
// the bb-prover harness / e2e. This unit test covers the non-recursive
// commitment-tree membership helper.
#[test]
fn test_membership_roundtrip() {
    let leaf = 0x1111;
    let sibling = 0x2222;
    let mut path: [Field; MAX_COMMITMENT_TREE_DEPTH] = [0; MAX_COMMITMENT_TREE_DEPTH];
    let indices: [bool; MAX_COMMITMENT_TREE_DEPTH] = [false; MAX_COMMITMENT_TREE_DEPTH];
    path[0] = sibling;
    let root = poseidon2(leaf, sibling); // leaf at index 0, depth 1
    verify_membership(leaf, root, 1, indices, path);
}

#[test(should_fail_with = "membership: root mismatch")]
fn test_membership_wrong_root() {
    let leaf = 0x1111;
    let mut path: [Field; MAX_COMMITMENT_TREE_DEPTH] = [0; MAX_COMMITMENT_TREE_DEPTH];
    let indices: [bool; MAX_COMMITMENT_TREE_DEPTH] = [false; MAX_COMMITMENT_TREE_DEPTH];
    path[0] = 0x2222;
    verify_membership(leaf, 0x9999, 1, indices, path);
}
