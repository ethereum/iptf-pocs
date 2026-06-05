use bb_proof_verification::{UltraHonkVerificationKey, UltraHonkZKProof, verify_honk_proof};
use poseidon::poseidon::bn254::{hash_1, hash_2, hash_3, hash_5};

// Withdraw spend circuit (extended). Same per-input diff as `transfer`, applied
// to a single input note (full withdrawal, no change output): reconstruct the
// commitment binding `epoch_created`, verify commitment-tree membership,
// recursively verify the note's ChainProof, and emit the per-epoch active
// nullifier. The note's full `amount` exits the pool to `recipient`. See
// ../../SPEC.md "Withdraw (extended)".

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

// LeanIMT commitment-tree membership (dynamic depth); mirrors the off-chain
// `CommitmentMerkleProof::reconstruct_root`.
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

// Recursively verify the input note's ChainProof, fully caught up to the
// current epoch, and bind its public inputs.
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
    nullifier_active: pub Field,
    token: pub Field,
    amount: pub Field,
    recipient: pub Field,
    commitment_root: pub Field,
    current_epoch: pub Field,
    chain_vk_hash: pub Field,
    epoch_created_in: pub Field,
    chain_accumulator_in: pub Field,
    // Private inputs.
    spending_key: Field,
    salt: Field,
    proof_length: u32,
    path: [Field; MAX_COMMITMENT_TREE_DEPTH],
    indices: [bool; MAX_COMMITMENT_TREE_DEPTH],
    chain_vk: UltraHonkVerificationKey,
    chain_proof: UltraHonkZKProof,
    chain_pub: [Field; CHAIN_PROOF_PUB_LEN],
) {
    // Parent constraint 1: owner_pubkey derived from the spending key.
    let owner_pubkey = poseidon1(spending_key);

    // Reconstruct the note commitment binding epoch_created (the claimed
    // token/amount must match the committed note).
    let commitment_in = poseidon5(token, amount, owner_pubkey, salt, epoch_created_in);

    verify_membership(commitment_in, commitment_root, proof_length, indices, path);

    assert(
        nullifier_active == poseidon3(commitment_in, spending_key, current_epoch),
        "nullifier mismatch",
    );

    verify_input_chain(
        chain_vk,
        chain_proof,
        chain_pub,
        chain_vk_hash,
        commitment_in,
        epoch_created_in,
        current_epoch,
        chain_accumulator_in,
    );

    // `recipient` is bound to the proof via the public inputs; the contract
    // sends the withdrawn funds there. No further in-circuit constraint.
    let _ = recipient;
}

// The full recursive `main` is exercised by the bb-prover harness / e2e. This
// unit test covers the non-recursive membership helper.
#[test]
fn test_membership_roundtrip() {
    let leaf = 0x3333;
    let sibling = 0x4444;
    let mut path: [Field; MAX_COMMITMENT_TREE_DEPTH] = [0; MAX_COMMITMENT_TREE_DEPTH];
    let indices: [bool; MAX_COMMITMENT_TREE_DEPTH] = [false; MAX_COMMITMENT_TREE_DEPTH];
    path[0] = sibling;
    let root = poseidon2(leaf, sibling);
    verify_membership(leaf, root, 1, indices, path);
}

#[test(should_fail_with = "membership: root mismatch")]
fn test_membership_wrong_root() {
    let leaf = 0x3333;
    let mut path: [Field; MAX_COMMITMENT_TREE_DEPTH] = [0; MAX_COMMITMENT_TREE_DEPTH];
    let indices: [bool; MAX_COMMITMENT_TREE_DEPTH] = [false; MAX_COMMITMENT_TREE_DEPTH];
    path[0] = 0x4444;
    verify_membership(leaf, 0x9999, 1, indices, path);
}
