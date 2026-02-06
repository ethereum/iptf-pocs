//! Integration tests for the membership circuit logic (Phase 1).
//!
//! These tests validate the circuit logic as a pure Rust function on the host
//! side, without requiring the RISC Zero zkVM. The circuit logic from SPEC.md
//! (lines 172-193) takes a leaf, path, indices, and expected root, then
//! recomputes the root via SHA-256 and asserts equality.
//!
//! Once the guest program is implemented, separate zkVM integration tests
//! should exercise the full proving flow.

use diy_validium_host::merkle::{account_commitment, verify_membership, MerkleTree};
use sha2::{Digest, Sha256};

/// Helper: compute SHA-256 of input bytes.
fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

// -------------------------------------------------------------------
// Circuit logic tests (mirrors SPEC.md verify_membership)
// -------------------------------------------------------------------

#[test]
fn test_circuit_accepts_valid_membership_proof() {
    let leaves: Vec<[u8; 32]> = (0..4)
        .map(|i| sha256(format!("member_{i}").as_bytes()))
        .collect();
    let tree = MerkleTree::from_leaves(&leaves, 20);
    let root = tree.root();
    let proof = tree.prove(0);

    // This should succeed — valid leaf + valid proof + correct root
    verify_membership(leaves[0], &proof.path, &proof.indices, root);
}

#[test]
#[should_panic]
fn test_circuit_rejects_invalid_leaf() {
    let leaves: Vec<[u8; 32]> = (0..4)
        .map(|i| sha256(format!("member_{i}").as_bytes()))
        .collect();
    let tree = MerkleTree::from_leaves(&leaves, 20);
    let root = tree.root();
    let proof = tree.prove(0);

    let fake_leaf = sha256(b"not_a_member");
    // This should panic — wrong leaf with valid proof
    verify_membership(fake_leaf, &proof.path, &proof.indices, root);
}

#[test]
#[should_panic]
fn test_circuit_rejects_wrong_root() {
    let leaves: Vec<[u8; 32]> = (0..4)
        .map(|i| sha256(format!("member_{i}").as_bytes()))
        .collect();
    let tree = MerkleTree::from_leaves(&leaves, 20);
    let proof = tree.prove(0);

    let wrong_root = sha256(b"wrong_root");
    // This should panic — correct leaf but wrong expected root
    verify_membership(leaves[0], &proof.path, &proof.indices, wrong_root);
}

#[test]
#[should_panic]
fn test_circuit_rejects_tampered_path() {
    let leaves: Vec<[u8; 32]> = (0..4)
        .map(|i| sha256(format!("member_{i}").as_bytes()))
        .collect();
    let tree = MerkleTree::from_leaves(&leaves, 20);
    let root = tree.root();
    let mut proof = tree.prove(0);

    // Tamper with first sibling in the path
    proof.path[0] = sha256(b"tampered_sibling");

    // This should panic — tampered proof path
    verify_membership(leaves[0], &proof.path, &proof.indices, root);
}

#[test]
#[should_panic]
fn test_circuit_rejects_flipped_indices() {
    let leaves: Vec<[u8; 32]> = (0..4)
        .map(|i| sha256(format!("member_{i}").as_bytes()))
        .collect();
    let tree = MerkleTree::from_leaves(&leaves, 20);
    let root = tree.root();
    let mut proof = tree.prove(0);

    // Flip all indices (left <-> right)
    for idx in proof.indices.iter_mut() {
        *idx = !*idx;
    }

    // This should panic — wrong path direction
    verify_membership(leaves[0], &proof.path, &proof.indices, root);
}

// -------------------------------------------------------------------
// Account commitment + membership (end-to-end Phase 1 flow)
// -------------------------------------------------------------------

#[test]
fn test_end_to_end_account_membership_proof() {
    // 1. Create accounts with commitments per SPEC.md
    let pubkey_0 = sha256(b"secret_key_0"); // simplified key derivation
    let balance_0: u64 = 1000;
    let salt_0 = sha256(b"salt_0");
    let commitment_0 = account_commitment(&pubkey_0, balance_0, &salt_0);

    let pubkey_1 = sha256(b"secret_key_1");
    let balance_1: u64 = 2000;
    let salt_1 = sha256(b"salt_1");
    let commitment_1 = account_commitment(&pubkey_1, balance_1, &salt_1);

    // 2. Build the allowlist tree
    let tree = MerkleTree::from_leaves(&[commitment_0, commitment_1], 20);
    let root = tree.root();

    // 3. Generate and verify a membership proof for account 0
    let proof = tree.prove(0);
    verify_membership(commitment_0, &proof.path, &proof.indices, root);
}

#[test]
#[should_panic]
fn test_wrong_balance_commitment_fails_membership() {
    let pubkey = sha256(b"secret_key_0");
    let balance: u64 = 1000;
    let salt = sha256(b"salt_0");
    let correct_commitment = account_commitment(&pubkey, balance, &salt);

    // Build tree with correct commitment
    let tree = MerkleTree::from_leaves(&[correct_commitment], 20);
    let root = tree.root();
    let proof = tree.prove(0);

    // Try to prove membership with wrong balance (attacker claims 9999)
    let wrong_commitment = account_commitment(&pubkey, 9999, &salt);

    // This should panic — the wrong commitment is not in the tree
    verify_membership(wrong_commitment, &proof.path, &proof.indices, root);
}
