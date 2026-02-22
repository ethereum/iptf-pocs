//! Integration tests for the disclosure proof guest program logic.
//!
//! These tests validate the disclosure proof logic as a pure Rust
//! function on the host side, without requiring the RISC Zero zkVM. The
//! guest program from SPEC.md ("Guest Program: Disclosure Proof") takes
//! an account owner's secret key, account data, Merkle proof, a threshold,
//! and an auditor pubkey, then:
//!   1. Derives pubkey from secret key: SHA256(sk)
//!   2. Computes leaf commitment: SHA256(pubkey || balance_le || salt)
//!   3. Verifies Merkle membership against expected root
//!   4. Asserts balance >= threshold
//!   5. Computes disclosure_key_hash: SHA256(pubkey || auditor_pubkey || "disclosure_v1")
//!
//! This is a read-only attestation — no state mutation, no nullifier.
//!
//! These are TDD "red phase" tests — they define the API for `verify_disclosure`
//! and `compute_disclosure_key_hash` which do not exist yet. The tests should
//! fail to compile until the functions are implemented.
//!
//! Once the guest program is implemented, separate zkVM integration tests
//! should exercise the full proving flow.

use diy_validium_host::accounts::{Account, AccountStore};
use diy_validium_host::merkle::{compute_disclosure_key_hash, verify_disclosure, MerkleTree};
use sha2::{Digest, Sha256};

/// Helper: compute SHA-256 of input bytes.
fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Tree depth used across all tests in this file.
/// Depth 4 gives 16 leaf slots — enough for tests, fast to compute.
const TREE_DEPTH: usize = 4;

/// Helper: build a single-account tree and return everything needed for a
/// disclosure test.
///
/// Returns (store, tree, root, secret_key, account_index, auditor_pubkey).
fn setup_disclosure_tree(
    balance: u64,
) -> (
    AccountStore,
    MerkleTree,
    [u8; 32],
    [u8; 32],
    usize,
    [u8; 32],
) {
    let sk = sha256(b"disclosure_sk_0");
    let pubkey = sha256(&sk);
    let salt = sha256(b"disclosure_salt_0");

    let mut store = AccountStore::new();
    let idx = store.add_account(Account {
        pubkey,
        balance,
        salt,
    });

    let tree = store.build_tree(TREE_DEPTH);
    let root = tree.root();

    let auditor_pubkey = sha256(b"auditor_pubkey_0");

    (store, tree, root, sk, idx, auditor_pubkey)
}

// -------------------------------------------------------------------
// verify_disclosure tests (mirrors SPEC.md guest program logic)
// -------------------------------------------------------------------

#[test]
fn test_valid_disclosure_succeeds() {
    let (store, tree, root, sk, idx, auditor_pubkey) = setup_disclosure_tree(10_000);

    let account = store.get_account(idx);
    let proof = tree.prove(idx);

    let threshold: u64 = 5_000;

    // Compute expected disclosure_key_hash per SPEC.md:
    // SHA256(pubkey || auditor_pubkey || "disclosure_v1")
    let pubkey = sha256(&sk);
    let expected_dkh = compute_disclosure_key_hash(&pubkey, &auditor_pubkey);

    // This should succeed without panic: balance (10_000) >= threshold (5_000)
    verify_disclosure(
        sk,
        account.balance,
        account.salt,
        &proof.path,
        &proof.indices,
        threshold,
        auditor_pubkey,
        root,
        expected_dkh,
    );
}

#[test]
#[should_panic(expected = "below threshold")]
fn test_balance_below_threshold_panics() {
    let (store, tree, root, sk, idx, auditor_pubkey) = setup_disclosure_tree(1_000);

    let account = store.get_account(idx);
    let proof = tree.prove(idx);

    // Threshold (5_000) exceeds balance (1_000) — should panic
    let threshold: u64 = 5_000;

    let pubkey = sha256(&sk);
    let expected_dkh = compute_disclosure_key_hash(&pubkey, &auditor_pubkey);

    verify_disclosure(
        sk,
        account.balance,
        account.salt,
        &proof.path,
        &proof.indices,
        threshold,
        auditor_pubkey,
        root,
        expected_dkh,
    );
}

#[test]
#[should_panic]
fn test_wrong_sk_panics() {
    let (store, tree, root, _sk, idx, auditor_pubkey) = setup_disclosure_tree(10_000);

    let account = store.get_account(idx);
    let proof = tree.prove(idx);

    let threshold: u64 = 5_000;

    // Use a wrong secret key — derived pubkey won't match the tree leaf,
    // so Merkle membership verification will fail
    let wrong_sk = sha256(b"wrong_secret_key");
    let wrong_pubkey = sha256(&wrong_sk);
    let expected_dkh = compute_disclosure_key_hash(&wrong_pubkey, &auditor_pubkey);

    verify_disclosure(
        wrong_sk,
        account.balance,
        account.salt,
        &proof.path,
        &proof.indices,
        threshold,
        auditor_pubkey,
        root,
        expected_dkh,
    );
}

#[test]
#[should_panic]
fn test_wrong_root_panics() {
    let (store, tree, _root, sk, idx, auditor_pubkey) = setup_disclosure_tree(10_000);

    let account = store.get_account(idx);
    let proof = tree.prove(idx);

    let threshold: u64 = 5_000;

    // Use a fabricated root — Merkle membership check will fail
    let wrong_root = sha256(b"wrong_root");

    let pubkey = sha256(&sk);
    let expected_dkh = compute_disclosure_key_hash(&pubkey, &auditor_pubkey);

    verify_disclosure(
        sk,
        account.balance,
        account.salt,
        &proof.path,
        &proof.indices,
        threshold,
        auditor_pubkey,
        wrong_root,
        expected_dkh,
    );
}

#[test]
fn test_disclosure_key_is_auditor_specific() {
    // Different auditor_pubkey must produce different disclosure_key_hash.
    // This verifies the auditor-binding property from SPEC.md.
    let sk = sha256(b"disclosure_sk_0");
    let pubkey = sha256(&sk);

    let auditor_a = sha256(b"auditor_pubkey_a");
    let auditor_b = sha256(b"auditor_pubkey_b");

    let dkh_a = compute_disclosure_key_hash(&pubkey, &auditor_a);
    let dkh_b = compute_disclosure_key_hash(&pubkey, &auditor_b);

    assert_ne!(
        dkh_a, dkh_b,
        "Disclosure key hash must differ for different auditors (auditor-binding)"
    );

    // Verify the formula matches SPEC.md:
    // disclosure_key_hash = SHA256(pubkey || auditor_pubkey || "disclosure_v1")
    let expected_a = sha256(&[&pubkey[..], &auditor_a[..], b"disclosure_v1"].concat());
    assert_eq!(
        dkh_a, expected_a,
        "Disclosure key hash must equal SHA256(pubkey || auditor_pubkey || 'disclosure_v1')"
    );
}

#[test]
fn test_disclosure_key_is_account_specific() {
    // Different accounts (different SK) must produce different disclosure_key_hash
    // even with the same auditor. This verifies the account-binding property.
    let sk_alice = sha256(b"alice_sk");
    let pubkey_alice = sha256(&sk_alice);

    let sk_bob = sha256(b"bob_sk");
    let pubkey_bob = sha256(&sk_bob);

    let auditor = sha256(b"shared_auditor_pubkey");

    let dkh_alice = compute_disclosure_key_hash(&pubkey_alice, &auditor);
    let dkh_bob = compute_disclosure_key_hash(&pubkey_bob, &auditor);

    assert_ne!(
        dkh_alice, dkh_bob,
        "Disclosure key hash must differ for different accounts (account-binding)"
    );
}

#[test]
fn test_balance_exactly_at_threshold() {
    // Edge case: balance == threshold should succeed (>= check, not >)
    let (store, tree, root, sk, idx, auditor_pubkey) = setup_disclosure_tree(5_000);

    let account = store.get_account(idx);
    let proof = tree.prove(idx);

    // Threshold exactly equals balance
    let threshold: u64 = 5_000;

    let pubkey = sha256(&sk);
    let expected_dkh = compute_disclosure_key_hash(&pubkey, &auditor_pubkey);

    // This should succeed without panic: balance (5_000) >= threshold (5_000)
    verify_disclosure(
        sk,
        account.balance,
        account.salt,
        &proof.path,
        &proof.indices,
        threshold,
        auditor_pubkey,
        root,
        expected_dkh,
    );
}

#[test]
fn test_zero_threshold_succeeds() {
    // Edge case: threshold=0 should always succeed (any balance >= 0 for u64)
    let (store, tree, root, sk, idx, auditor_pubkey) = setup_disclosure_tree(0);

    let account = store.get_account(idx);
    let proof = tree.prove(idx);

    let threshold: u64 = 0;

    let pubkey = sha256(&sk);
    let expected_dkh = compute_disclosure_key_hash(&pubkey, &auditor_pubkey);

    // This should succeed: balance (0) >= threshold (0)
    verify_disclosure(
        sk,
        account.balance,
        account.salt,
        &proof.path,
        &proof.indices,
        threshold,
        auditor_pubkey,
        root,
        expected_dkh,
    );
}
