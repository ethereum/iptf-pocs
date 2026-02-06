//! Integration tests for the withdrawal proof circuit logic (Phase 4).
//!
//! These tests validate the withdrawal proof circuit logic as a pure Rust function
//! on the host side, without requiring the RISC Zero zkVM. The circuit logic
//! from SPEC.md (lines 728-807) takes account data, a Merkle path, amount,
//! new salt, and recipient address, then:
//!   1. Derives pubkey from secret key: SHA256(sk)
//!   2. Verifies account membership in old tree
//!   3. Checks balance >= amount > 0
//!   4. Computes state-bound nullifier: SHA256(sk || old_root || "withdrawal_v1")
//!   5. Computes new commitment with reduced balance and fresh salt
//!   6. Recomputes new root via single-leaf update (compute_single_leaf_root)
//!
//! These are TDD "red phase" tests — they define the API for `verify_withdrawal`
//! and `compute_single_leaf_root` which do not exist yet. The tests should fail
//! to compile until the functions are implemented.
//!
//! Once the guest program is implemented, separate zkVM integration tests
//! should exercise the full proving flow.

use diy_validium_host::accounts::{Account, AccountStore};
use diy_validium_host::merkle::{
    account_commitment, compute_single_leaf_root, verify_withdrawal, MerkleTree,
};
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

/// Helper: build a single-account tree and return everything needed for a withdrawal test.
///
/// Returns (store, tree, old_root, secret_key, account_idx, new_salt, recipient).
fn setup_single_account_tree(
    balance: u64,
) -> (
    AccountStore,
    MerkleTree,
    [u8; 32],
    [u8; 32],
    usize,
    [u8; 32],
    [u8; 20],
) {
    let sk = sha256(b"withdrawal_sk_0");
    let pubkey = sha256(&sk);
    let salt = sha256(b"withdrawal_salt_0");

    let mut store = AccountStore::new();
    let idx = store.add_account(Account {
        pubkey,
        balance,
        salt,
    });

    let tree = store.build_tree(TREE_DEPTH);
    let old_root = tree.root();

    let new_salt = sha256(b"new_withdrawal_salt_0");

    // Ethereum address (20 bytes) for the withdrawal recipient
    let recipient: [u8; 20] = [0xAB; 20];

    (store, tree, old_root, sk, idx, new_salt, recipient)
}

/// Helper: compute the withdrawal nullifier as specified in SPEC.md:
/// `SHA256(secret_key || old_root || "withdrawal_v1")`
fn compute_withdrawal_nullifier(secret_key: &[u8; 32], old_root: &[u8; 32]) -> [u8; 32] {
    sha256(&[&secret_key[..], &old_root[..], b"withdrawal_v1"].concat())
}

/// Helper: compute the expected new root after a withdrawal by rebuilding the
/// full tree from updated account commitments.
fn rebuild_tree_after_withdrawal(
    store: &AccountStore,
    account_idx: usize,
    pubkey: [u8; 32],
    new_balance: u64,
    new_salt: [u8; 32],
) -> [u8; 32] {
    let mut commitments = store.commitments();
    commitments[account_idx] = account_commitment(&pubkey, new_balance, &new_salt);
    let new_tree = MerkleTree::from_leaves(&commitments, TREE_DEPTH);
    new_tree.root()
}

// -------------------------------------------------------------------
// verify_withdrawal tests (mirrors SPEC.md Phase 4 circuit logic)
// -------------------------------------------------------------------

#[test]
fn test_valid_withdrawal_succeeds() {
    let (store, tree, old_root, sk, idx, new_salt, recipient) = setup_single_account_tree(5000);

    let account = store.get_account(idx);
    let proof = tree.prove(idx);

    let amount: u64 = 1000;

    // Compute expected new root by full tree rebuild
    let pubkey = sha256(&sk);
    let new_root =
        rebuild_tree_after_withdrawal(&store, idx, pubkey, account.balance - amount, new_salt);

    let nullifier = compute_withdrawal_nullifier(&sk, &old_root);

    // This should succeed without panic
    verify_withdrawal(
        sk,
        account.balance,
        account.salt,
        &proof.path,
        &proof.indices,
        amount,
        new_salt,
        recipient,
        old_root,
        new_root,
        nullifier,
    );
}

#[test]
#[should_panic(expected = "Insufficient balance")]
fn test_insufficient_balance_panics() {
    let (store, tree, old_root, sk, idx, new_salt, recipient) = setup_single_account_tree(500);

    let account = store.get_account(idx);
    let proof = tree.prove(idx);

    // Amount exceeds balance (500 < 1000)
    let amount: u64 = 1000;

    // new_root doesn't matter — should panic before reaching it
    let nullifier = compute_withdrawal_nullifier(&sk, &old_root);
    let fake_new_root = [0u8; 32];

    verify_withdrawal(
        sk,
        account.balance,
        account.salt,
        &proof.path,
        &proof.indices,
        amount,
        new_salt,
        recipient,
        old_root,
        fake_new_root,
        nullifier,
    );
}

#[test]
#[should_panic(expected = "must be positive")]
fn test_zero_amount_panics() {
    let (store, tree, old_root, sk, idx, new_salt, recipient) = setup_single_account_tree(5000);

    let account = store.get_account(idx);
    let proof = tree.prove(idx);

    // Zero amount should be rejected
    let amount: u64 = 0;

    let nullifier = compute_withdrawal_nullifier(&sk, &old_root);
    let fake_new_root = [0u8; 32];

    verify_withdrawal(
        sk,
        account.balance,
        account.salt,
        &proof.path,
        &proof.indices,
        amount,
        new_salt,
        recipient,
        old_root,
        fake_new_root,
        nullifier,
    );
}

#[test]
#[should_panic]
fn test_wrong_sk_panics() {
    let (store, tree, old_root, _sk, idx, new_salt, recipient) = setup_single_account_tree(5000);

    let account = store.get_account(idx);
    let proof = tree.prove(idx);

    let amount: u64 = 1000;

    // Use a wrong secret key — derived pubkey won't match the tree leaf
    let wrong_sk = sha256(b"wrong_secret_key");
    let nullifier = compute_withdrawal_nullifier(&wrong_sk, &old_root);
    let fake_new_root = [0u8; 32];

    verify_withdrawal(
        wrong_sk,
        account.balance,
        account.salt,
        &proof.path,
        &proof.indices,
        amount,
        new_salt,
        recipient,
        old_root,
        fake_new_root,
        nullifier,
    );
}

#[test]
#[should_panic]
fn test_wrong_root_panics() {
    let (store, tree, _old_root, sk, idx, new_salt, recipient) = setup_single_account_tree(5000);

    let account = store.get_account(idx);
    let proof = tree.prove(idx);

    let amount: u64 = 1000;

    // Use a fabricated old_root — Merkle membership check will fail
    let wrong_old_root = sha256(b"wrong_root");
    let nullifier = compute_withdrawal_nullifier(&sk, &wrong_old_root);
    let fake_new_root = [0u8; 32];

    verify_withdrawal(
        sk,
        account.balance,
        account.salt,
        &proof.path,
        &proof.indices,
        amount,
        new_salt,
        recipient,
        wrong_old_root,
        fake_new_root,
        nullifier,
    );
}

#[test]
fn test_nullifier_domain_separation() {
    // Withdrawal nullifiers use "withdrawal_v1" domain tag, while transfer
    // nullifiers use "transfer_v1". Given the same secret key and old_root,
    // the two nullifiers must be different.
    let sk = sha256(b"withdrawal_sk_0");
    let root = sha256(b"some_state_root");

    let withdrawal_nullifier = sha256(&[&sk[..], &root[..], b"withdrawal_v1"].concat());
    let transfer_nullifier = sha256(&[&sk[..], &root[..], b"transfer_v1"].concat());

    assert_ne!(
        withdrawal_nullifier, transfer_nullifier,
        "Withdrawal and transfer nullifiers must differ due to domain separation"
    );

    // Also verify the withdrawal nullifier matches the spec formula directly
    let expected = compute_withdrawal_nullifier(&sk, &root);
    assert_eq!(
        withdrawal_nullifier, expected,
        "Withdrawal nullifier must equal SHA256(sk || old_root || 'withdrawal_v1')"
    );
}

// -------------------------------------------------------------------
// compute_single_leaf_root tests (single-leaf root recomputation)
// -------------------------------------------------------------------

#[test]
fn test_compute_single_leaf_root_matches_rebuild() {
    // Update one leaf via compute_single_leaf_root, then rebuild the tree
    // from scratch with the same updated leaf. Both roots must match.
    let (store, tree, _old_root, sk, idx, new_salt, _recipient) = setup_single_account_tree(5000);

    let account = store.get_account(idx);
    let proof = tree.prove(idx);

    let amount: u64 = 1000;
    let pubkey = sha256(&sk);

    // Compute the new leaf commitment with reduced balance
    let new_leaf = account_commitment(&pubkey, account.balance - amount, &new_salt);

    // Compute new root via single-leaf update
    let new_root = compute_single_leaf_root(new_leaf, &proof.path, &proof.indices);

    // Compute expected root by full tree rebuild
    let expected_root =
        rebuild_tree_after_withdrawal(&store, idx, pubkey, account.balance - amount, new_salt);

    assert_eq!(
        new_root, expected_root,
        "compute_single_leaf_root must match a full tree rebuild"
    );
}

#[test]
fn test_withdrawal_full_balance() {
    // Withdrawing the entire balance (balance - amount = 0) should succeed.
    let balance: u64 = 5000;
    let (store, tree, old_root, sk, idx, new_salt, recipient) = setup_single_account_tree(balance);

    let account = store.get_account(idx);
    let proof = tree.prove(idx);

    // Withdraw everything
    let amount: u64 = balance;

    let pubkey = sha256(&sk);
    let new_root = rebuild_tree_after_withdrawal(
        &store, idx, pubkey, 0, // balance after full withdrawal
        new_salt,
    );

    let nullifier = compute_withdrawal_nullifier(&sk, &old_root);

    // This should succeed — zero remaining balance is valid
    verify_withdrawal(
        sk,
        account.balance,
        account.salt,
        &proof.path,
        &proof.indices,
        amount,
        new_salt,
        recipient,
        old_root,
        new_root,
        nullifier,
    );
}
