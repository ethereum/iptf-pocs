//! Integration tests for the balance proof circuit logic (Phase 2).
//!
//! These tests validate the balance proof circuit logic as a pure Rust function
//! on the host side, without requiring the RISC Zero zkVM. The circuit logic
//! from SPEC.md (lines 244-267) takes a pubkey, balance, salt, Merkle path,
//! indices, expected root, and required amount, then:
//!   1. Recomputes the leaf commitment: SHA256(pubkey || balance_le || salt)
//!   2. Verifies Merkle membership of that leaf
//!   3. Asserts balance >= required_amount
//!
//! These are TDD "red phase" tests — they define the API for `verify_balance`
//! which does not exist yet. The tests should fail to compile until the
//! function is implemented.
//!
//! Once the guest program is implemented, separate zkVM integration tests
//! should exercise the full proving flow.

use diy_validium_host::merkle::{account_commitment, verify_balance, MerkleTree};
use sha2::{Digest, Sha256};

/// Helper: compute SHA-256 of input bytes.
fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

// -------------------------------------------------------------------
// Balance proof circuit tests (mirrors SPEC.md verify_balance)
// -------------------------------------------------------------------

#[test]
fn test_valid_balance_proof_succeeds() {
    // Create two accounts with known balances
    let pubkey_0 = sha256(b"secret_key_0");
    let balance_0: u64 = 5000;
    let salt_0 = sha256(b"salt_0");
    let commitment_0 = account_commitment(&pubkey_0, balance_0, &salt_0);

    let pubkey_1 = sha256(b"secret_key_1");
    let balance_1: u64 = 3000;
    let salt_1 = sha256(b"salt_1");
    let commitment_1 = account_commitment(&pubkey_1, balance_1, &salt_1);

    // Build the accounts tree
    let tree = MerkleTree::from_leaves(&[commitment_0, commitment_1], 20);
    let root = tree.root();
    let proof = tree.prove(0);

    // Verify that account 0 has balance >= 1000 (it has 5000)
    verify_balance(
        pubkey_0,
        balance_0,
        salt_0,
        &proof.path,
        &proof.indices,
        root,
        1000, // required_amount
    );
}

#[test]
#[should_panic]
fn test_balance_below_threshold_panics() {
    let pubkey = sha256(b"secret_key_0");
    let balance: u64 = 500;
    let salt = sha256(b"salt_0");
    let commitment = account_commitment(&pubkey, balance, &salt);

    let tree = MerkleTree::from_leaves(&[commitment], 20);
    let root = tree.root();
    let proof = tree.prove(0);

    // Balance is 500 but we require 1000 — should panic
    verify_balance(
        pubkey,
        balance,
        salt,
        &proof.path,
        &proof.indices,
        root,
        1000, // required_amount exceeds actual balance
    );
}

#[test]
#[should_panic]
fn test_wrong_pubkey_fails() {
    let pubkey = sha256(b"secret_key_0");
    let balance: u64 = 5000;
    let salt = sha256(b"salt_0");
    let commitment = account_commitment(&pubkey, balance, &salt);

    let tree = MerkleTree::from_leaves(&[commitment], 20);
    let root = tree.root();
    let proof = tree.prove(0);

    // Use wrong pubkey — recomputed leaf won't match, Merkle check fails
    let wrong_pubkey = sha256(b"wrong_key");
    verify_balance(
        wrong_pubkey,
        balance,
        salt,
        &proof.path,
        &proof.indices,
        root,
        1000,
    );
}

#[test]
#[should_panic]
fn test_wrong_salt_fails() {
    let pubkey = sha256(b"secret_key_0");
    let balance: u64 = 5000;
    let salt = sha256(b"salt_0");
    let commitment = account_commitment(&pubkey, balance, &salt);

    let tree = MerkleTree::from_leaves(&[commitment], 20);
    let root = tree.root();
    let proof = tree.prove(0);

    // Use wrong salt — recomputed leaf won't match, Merkle check fails
    let wrong_salt = sha256(b"wrong_salt");
    verify_balance(
        pubkey,
        balance,
        wrong_salt,
        &proof.path,
        &proof.indices,
        root,
        1000,
    );
}

#[test]
#[should_panic]
fn test_wrong_root_fails() {
    let pubkey = sha256(b"secret_key_0");
    let balance: u64 = 5000;
    let salt = sha256(b"salt_0");
    let commitment = account_commitment(&pubkey, balance, &salt);

    let tree = MerkleTree::from_leaves(&[commitment], 20);
    let proof = tree.prove(0);

    // Valid proof but checked against a wrong root — should panic
    let wrong_root = sha256(b"wrong_root");
    verify_balance(
        pubkey,
        balance,
        salt,
        &proof.path,
        &proof.indices,
        wrong_root,
        1000,
    );
}

#[test]
fn test_zero_required_amount_always_succeeds() {
    // Any account with balance >= 0 should pass when required_amount is 0
    let pubkey = sha256(b"secret_key_0");
    let balance: u64 = 0; // even zero balance
    let salt = sha256(b"salt_0");
    let commitment = account_commitment(&pubkey, balance, &salt);

    let tree = MerkleTree::from_leaves(&[commitment], 20);
    let root = tree.root();
    let proof = tree.prove(0);

    // required_amount = 0, so balance (0) >= 0 is true
    verify_balance(
        pubkey,
        balance,
        salt,
        &proof.path,
        &proof.indices,
        root,
        0, // required_amount
    );
}

#[test]
fn test_exact_balance_equals_threshold() {
    let pubkey = sha256(b"secret_key_0");
    let balance: u64 = 2500;
    let salt = sha256(b"salt_0");
    let commitment = account_commitment(&pubkey, balance, &salt);

    let tree = MerkleTree::from_leaves(&[commitment], 20);
    let root = tree.root();
    let proof = tree.prove(0);

    // balance == required_amount (2500 >= 2500) — should pass
    verify_balance(
        pubkey,
        balance,
        salt,
        &proof.path,
        &proof.indices,
        root,
        2500, // exact threshold
    );
}

// -------------------------------------------------------------------
// End-to-end balance attestation (full Phase 2 flow)
// -------------------------------------------------------------------

#[test]
fn test_end_to_end_balance_attestation() {
    // 1. Operator creates multiple accounts with real commitments
    let pubkey_a = sha256(b"institution_a_key");
    let balance_a: u64 = 10_000;
    let salt_a = sha256(b"salt_inst_a");
    let commitment_a = account_commitment(&pubkey_a, balance_a, &salt_a);

    let pubkey_b = sha256(b"institution_b_key");
    let balance_b: u64 = 50_000;
    let salt_b = sha256(b"salt_inst_b");
    let commitment_b = account_commitment(&pubkey_b, balance_b, &salt_b);

    let pubkey_c = sha256(b"institution_c_key");
    let balance_c: u64 = 750;
    let salt_c = sha256(b"salt_inst_c");
    let commitment_c = account_commitment(&pubkey_c, balance_c, &salt_c);

    // 2. Build the accounts tree from all commitments
    let tree = MerkleTree::from_leaves(&[commitment_a, commitment_b, commitment_c], 20);
    let root = tree.root();

    // 3. Institution A proves balance >= 5000 (has 10,000)
    let proof_a = tree.prove(0);
    verify_balance(
        pubkey_a,
        balance_a,
        salt_a,
        &proof_a.path,
        &proof_a.indices,
        root,
        5_000,
    );

    // 4. Institution B proves balance >= 25000 (has 50,000)
    let proof_b = tree.prove(1);
    verify_balance(
        pubkey_b,
        balance_b,
        salt_b,
        &proof_b.path,
        &proof_b.indices,
        root,
        25_000,
    );

    // 5. Institution C proves balance >= 500 (has 750)
    let proof_c = tree.prove(2);
    verify_balance(
        pubkey_c,
        balance_c,
        salt_c,
        &proof_c.path,
        &proof_c.indices,
        root,
        500,
    );
}
