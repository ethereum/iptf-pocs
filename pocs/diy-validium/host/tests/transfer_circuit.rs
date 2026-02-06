//! Integration tests for the transfer proof circuit logic (Phase 3).
//!
//! These tests validate the transfer proof circuit logic as a pure Rust function
//! on the host side, without requiring the RISC Zero zkVM. The circuit logic
//! from SPEC.md (lines 359-453) takes sender/recipient account data, Merkle
//! paths, amount, and new salts, then:
//!   1. Derives sender pubkey from secret key: SHA256(sender_sk)
//!   2. Prohibits self-transfers (sender_pubkey == recipient_pubkey)
//!   3. Verifies both sender and recipient membership in old tree
//!   4. Checks sufficient sender balance and recipient overflow protection
//!   5. Computes state-bound nullifier: SHA256(sender_sk || old_root || "transfer_v1")
//!   6. Computes new commitments with updated balances and fresh salts
//!   7. Recomputes new root via dual-leaf update (compute_new_root)
//!
//! These are TDD "red phase" tests — they define the API for `verify_transfer`
//! and `compute_new_root` which do not exist yet. The tests should fail to
//! compile until the functions are implemented.
//!
//! Once the guest program is implemented, separate zkVM integration tests
//! should exercise the full proving flow.

use diy_validium_host::accounts::{Account, AccountStore};
use diy_validium_host::merkle::{
    account_commitment, compute_new_root, verify_transfer, MerkleTree,
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

/// Helper: build a two-account tree and return everything needed for a transfer test.
///
/// Returns (store, tree, old_root, sender_sk, sender_idx, recipient_idx,
///          new_sender_salt, new_recipient_salt).
fn setup_two_account_tree(
    sender_balance: u64,
    recipient_balance: u64,
) -> (
    AccountStore,
    MerkleTree,
    [u8; 32],
    [u8; 32],
    usize,
    usize,
    [u8; 32],
    [u8; 32],
) {
    let sender_sk = sha256(b"sender_sk_0");
    let sender_pubkey = sha256(&sender_sk);
    let sender_salt = sha256(b"sender_salt_0");

    let recipient_sk = sha256(b"recipient_sk_0");
    let recipient_pubkey = sha256(&recipient_sk);
    let recipient_salt = sha256(b"recipient_salt_0");

    let mut store = AccountStore::new();
    let sender_idx = store.add_account(Account {
        pubkey: sender_pubkey,
        balance: sender_balance,
        salt: sender_salt,
    });
    let recipient_idx = store.add_account(Account {
        pubkey: recipient_pubkey,
        balance: recipient_balance,
        salt: recipient_salt,
    });

    let tree = store.build_tree(TREE_DEPTH);
    let old_root = tree.root();

    let new_sender_salt = sha256(b"new_sender_salt_0");
    let new_recipient_salt = sha256(b"new_recipient_salt_0");

    (
        store,
        tree,
        old_root,
        sender_sk,
        sender_idx,
        recipient_idx,
        new_sender_salt,
        new_recipient_salt,
    )
}

/// Helper: compute the nullifier as specified in SPEC.md:
/// `SHA256(sender_sk || old_root || "transfer_v1")`
fn compute_nullifier(sender_sk: &[u8; 32], old_root: &[u8; 32]) -> [u8; 32] {
    sha256(&[&sender_sk[..], &old_root[..], b"transfer_v1"].concat())
}

/// Helper: compute the expected new root after a transfer by rebuilding the
/// full tree from updated account commitments.
fn rebuild_tree_after_transfer(
    store: &AccountStore,
    sender_idx: usize,
    sender_pubkey: [u8; 32],
    new_sender_balance: u64,
    new_sender_salt: [u8; 32],
    recipient_idx: usize,
    recipient_pubkey: [u8; 32],
    new_recipient_balance: u64,
    new_recipient_salt: [u8; 32],
) -> [u8; 32] {
    let mut commitments = store.commitments();
    commitments[sender_idx] =
        account_commitment(&sender_pubkey, new_sender_balance, &new_sender_salt);
    commitments[recipient_idx] = account_commitment(
        &recipient_pubkey,
        new_recipient_balance,
        &new_recipient_salt,
    );
    let new_tree = MerkleTree::from_leaves(&commitments, TREE_DEPTH);
    new_tree.root()
}

// -------------------------------------------------------------------
// verify_transfer tests (mirrors SPEC.md Phase 3 circuit logic)
// -------------------------------------------------------------------

#[test]
fn test_valid_transfer_succeeds() {
    let (
        store,
        tree,
        old_root,
        sender_sk,
        sender_idx,
        recipient_idx,
        new_sender_salt,
        new_recipient_salt,
    ) = setup_two_account_tree(5000, 3000);

    let sender = store.get_account(sender_idx);
    let recipient = store.get_account(recipient_idx);

    let sender_proof = tree.prove(sender_idx);
    let recipient_proof = tree.prove(recipient_idx);

    let amount: u64 = 1000;

    // Compute expected new root by full tree rebuild
    let sender_pubkey = sha256(&sender_sk);
    let new_root = rebuild_tree_after_transfer(
        &store,
        sender_idx,
        sender_pubkey,
        sender.balance - amount,
        new_sender_salt,
        recipient_idx,
        recipient.pubkey,
        recipient.balance + amount,
        new_recipient_salt,
    );

    let nullifier = compute_nullifier(&sender_sk, &old_root);

    // This should succeed without panic
    verify_transfer(
        sender_sk,
        sender.balance,
        sender.salt,
        &sender_proof.path,
        &sender_proof.indices,
        amount,
        recipient.pubkey,
        recipient.balance,
        recipient.salt,
        &recipient_proof.path,
        &recipient_proof.indices,
        new_sender_salt,
        new_recipient_salt,
        old_root,
        new_root,
        nullifier,
    );
}

#[test]
#[should_panic(expected = "Insufficient balance")]
fn test_insufficient_balance_panics() {
    let (
        store,
        tree,
        old_root,
        sender_sk,
        sender_idx,
        recipient_idx,
        new_sender_salt,
        new_recipient_salt,
    ) = setup_two_account_tree(500, 3000);

    let sender = store.get_account(sender_idx);
    let recipient = store.get_account(recipient_idx);

    let sender_proof = tree.prove(sender_idx);
    let recipient_proof = tree.prove(recipient_idx);

    // Amount exceeds sender balance (500 < 1000)
    let amount: u64 = 1000;

    // new_root and nullifier don't matter — should panic before reaching them
    let nullifier = compute_nullifier(&sender_sk, &old_root);
    let fake_new_root = [0u8; 32];

    verify_transfer(
        sender_sk,
        sender.balance,
        sender.salt,
        &sender_proof.path,
        &sender_proof.indices,
        amount,
        recipient.pubkey,
        recipient.balance,
        recipient.salt,
        &recipient_proof.path,
        &recipient_proof.indices,
        new_sender_salt,
        new_recipient_salt,
        old_root,
        fake_new_root,
        nullifier,
    );
}

#[test]
#[should_panic]
fn test_wrong_sender_sk_panics() {
    let (
        store,
        tree,
        old_root,
        _sender_sk,
        sender_idx,
        recipient_idx,
        new_sender_salt,
        new_recipient_salt,
    ) = setup_two_account_tree(5000, 3000);

    let sender = store.get_account(sender_idx);
    let recipient = store.get_account(recipient_idx);

    let sender_proof = tree.prove(sender_idx);
    let recipient_proof = tree.prove(recipient_idx);

    let amount: u64 = 1000;

    // Use a wrong secret key — derived pubkey won't match the tree leaf
    let wrong_sk = sha256(b"wrong_secret_key");
    let nullifier = compute_nullifier(&wrong_sk, &old_root);
    let fake_new_root = [0u8; 32];

    verify_transfer(
        wrong_sk,
        sender.balance,
        sender.salt,
        &sender_proof.path,
        &sender_proof.indices,
        amount,
        recipient.pubkey,
        recipient.balance,
        recipient.salt,
        &recipient_proof.path,
        &recipient_proof.indices,
        new_sender_salt,
        new_recipient_salt,
        old_root,
        fake_new_root,
        nullifier,
    );
}

#[test]
#[should_panic]
fn test_wrong_recipient_balance_panics() {
    let (
        store,
        tree,
        old_root,
        sender_sk,
        sender_idx,
        recipient_idx,
        new_sender_salt,
        new_recipient_salt,
    ) = setup_two_account_tree(5000, 3000);

    let sender = store.get_account(sender_idx);
    let recipient = store.get_account(recipient_idx);

    let sender_proof = tree.prove(sender_idx);
    let recipient_proof = tree.prove(recipient_idx);

    let amount: u64 = 1000;

    // Use a fake recipient balance (9999 instead of 3000) — the recomputed
    // recipient leaf won't match the old tree, so membership verification fails.
    let fake_recipient_balance: u64 = 9999;

    let nullifier = compute_nullifier(&sender_sk, &old_root);
    let fake_new_root = [0u8; 32];

    verify_transfer(
        sender_sk,
        sender.balance,
        sender.salt,
        &sender_proof.path,
        &sender_proof.indices,
        amount,
        recipient.pubkey,
        fake_recipient_balance,
        recipient.salt,
        &recipient_proof.path,
        &recipient_proof.indices,
        new_sender_salt,
        new_recipient_salt,
        old_root,
        fake_new_root,
        nullifier,
    );
}

#[test]
#[should_panic]
fn test_wrong_root_panics() {
    let (
        store,
        tree,
        _old_root,
        sender_sk,
        sender_idx,
        recipient_idx,
        new_sender_salt,
        new_recipient_salt,
    ) = setup_two_account_tree(5000, 3000);

    let sender = store.get_account(sender_idx);
    let recipient = store.get_account(recipient_idx);

    let sender_proof = tree.prove(sender_idx);
    let recipient_proof = tree.prove(recipient_idx);

    let amount: u64 = 1000;

    // Use a fabricated old_root — Merkle membership checks will fail
    let wrong_old_root = sha256(b"wrong_root");
    let nullifier = compute_nullifier(&sender_sk, &wrong_old_root);
    let fake_new_root = [0u8; 32];

    verify_transfer(
        sender_sk,
        sender.balance,
        sender.salt,
        &sender_proof.path,
        &sender_proof.indices,
        amount,
        recipient.pubkey,
        recipient.balance,
        recipient.salt,
        &recipient_proof.path,
        &recipient_proof.indices,
        wrong_old_root,
        fake_new_root,
        nullifier,
    );
}

#[test]
#[should_panic(expected = "Self-transfer not allowed")]
fn test_self_transfer_panics() {
    // Build a tree where sender and recipient are the same account
    let sk = sha256(b"sender_sk_0");
    let pubkey = sha256(&sk);
    let salt = sha256(b"salt_self");

    let mut store = AccountStore::new();
    let idx = store.add_account(Account {
        pubkey,
        balance: 5000,
        salt,
    });

    let tree = store.build_tree(TREE_DEPTH);
    let old_root = tree.root();
    let proof = tree.prove(idx);

    let amount: u64 = 1000;
    let new_sender_salt = sha256(b"new_salt_s");
    let new_recipient_salt = sha256(b"new_salt_r");
    let nullifier = compute_nullifier(&sk, &old_root);
    let fake_new_root = [0u8; 32];

    // sender_pubkey == recipient_pubkey — should panic
    verify_transfer(
        sk,
        5000,
        salt,
        &proof.path,
        &proof.indices,
        amount,
        pubkey, // recipient_pubkey == sender_pubkey
        5000,
        salt,
        &proof.path,
        &proof.indices,
        new_sender_salt,
        new_recipient_salt,
        old_root,
        fake_new_root,
        nullifier,
    );
}

#[test]
#[should_panic(expected = "overflow")]
fn test_overflow_panics() {
    // Recipient balance near u64::MAX so that adding amount overflows
    let sender_sk = sha256(b"sender_sk_0");
    let sender_pubkey = sha256(&sender_sk);
    let sender_salt = sha256(b"sender_salt_0");

    let recipient_sk = sha256(b"recipient_sk_0");
    let recipient_pubkey = sha256(&recipient_sk);
    let recipient_salt = sha256(b"recipient_salt_0");

    let mut store = AccountStore::new();
    store.add_account(Account {
        pubkey: sender_pubkey,
        balance: 1000,
        salt: sender_salt,
    });
    store.add_account(Account {
        pubkey: recipient_pubkey,
        balance: u64::MAX - 500, // near max
        salt: recipient_salt,
    });

    let tree = store.build_tree(TREE_DEPTH);
    let old_root = tree.root();

    let sender_proof = tree.prove(0);
    let recipient_proof = tree.prove(1);

    // amount = 1000, recipient_balance = u64::MAX - 500
    // recipient_balance + amount = u64::MAX + 500 — overflows
    let amount: u64 = 1000;
    let new_sender_salt = sha256(b"new_sender_salt_0");
    let new_recipient_salt = sha256(b"new_recipient_salt_0");
    let nullifier = compute_nullifier(&sender_sk, &old_root);
    let fake_new_root = [0u8; 32];

    verify_transfer(
        sender_sk,
        1000,
        sender_salt,
        &sender_proof.path,
        &sender_proof.indices,
        amount,
        recipient_pubkey,
        u64::MAX - 500,
        recipient_salt,
        &recipient_proof.path,
        &recipient_proof.indices,
        new_sender_salt,
        new_recipient_salt,
        old_root,
        fake_new_root,
        nullifier,
    );
}

#[test]
fn test_nullifier_is_state_bound() {
    // The same sender_sk with different old_roots should produce different nullifiers.
    // This verifies the state-binding property from SPEC.md (lines 112-124).
    let sender_sk = sha256(b"sender_sk_0");

    let root_a = sha256(b"state_root_a");
    let root_b = sha256(b"state_root_b");

    let nullifier_a = compute_nullifier(&sender_sk, &root_a);
    let nullifier_b = compute_nullifier(&sender_sk, &root_b);

    assert_ne!(
        nullifier_a, nullifier_b,
        "Nullifier must change when old_root changes (state-bound property)"
    );

    // Also verify the nullifier matches the spec formula directly
    let expected = sha256(&[&sender_sk[..], &root_a[..], b"transfer_v1"].concat());
    assert_eq!(
        nullifier_a, expected,
        "Nullifier must equal SHA256(sender_sk || old_root || 'transfer_v1')"
    );
}

// -------------------------------------------------------------------
// compute_new_root tests (dual-leaf root recomputation)
// -------------------------------------------------------------------

#[test]
fn test_compute_new_root_matches_full_rebuild() {
    // Update two leaves via compute_new_root, then rebuild the tree from
    // scratch with the same updated leaves. Both roots must match.
    let (
        store,
        tree,
        _old_root,
        sender_sk,
        sender_idx,
        recipient_idx,
        new_sender_salt,
        new_recipient_salt,
    ) = setup_two_account_tree(5000, 3000);

    let sender = store.get_account(sender_idx);
    let recipient = store.get_account(recipient_idx);

    let sender_proof = tree.prove(sender_idx);
    let recipient_proof = tree.prove(recipient_idx);

    let amount: u64 = 1000;
    let sender_pubkey = sha256(&sender_sk);

    // Compute new leaf commitments
    let sender_new_leaf =
        account_commitment(&sender_pubkey, sender.balance - amount, &new_sender_salt);
    let recipient_new_leaf = account_commitment(
        &recipient.pubkey,
        recipient.balance + amount,
        &new_recipient_salt,
    );

    // Compute new root via dual-leaf update
    let new_root = compute_new_root(
        sender_new_leaf,
        &sender_proof.indices,
        recipient_new_leaf,
        &recipient_proof.indices,
        &sender_proof.path,
        &recipient_proof.path,
    );

    // Compute expected root by full tree rebuild
    let expected_root = rebuild_tree_after_transfer(
        &store,
        sender_idx,
        sender_pubkey,
        sender.balance - amount,
        new_sender_salt,
        recipient_idx,
        recipient.pubkey,
        recipient.balance + amount,
        new_recipient_salt,
    );

    assert_eq!(
        new_root, expected_root,
        "compute_new_root must match a full tree rebuild"
    );
}

#[test]
fn test_compute_new_root_different_subtrees() {
    // Place sender and recipient in opposite halves of the tree so the
    // divergence point is at the root level (depth index 0).
    let sender_sk = sha256(b"sender_sk_1");
    let sender_pubkey = sha256(&sender_sk);
    let sender_salt = sha256(b"sender_salt_1");

    let recipient_sk = sha256(b"recipient_sk_1");
    let recipient_pubkey = sha256(&recipient_sk);
    let recipient_salt = sha256(b"recipient_salt_1");

    let mut store = AccountStore::new();

    // Sender at index 0 (left half), fill indices 1..7 with padding accounts,
    // recipient at index 8 (right half of a depth-4 tree with 16 leaves).
    store.add_account(Account {
        pubkey: sender_pubkey,
        balance: 10_000,
        salt: sender_salt,
    });
    // Fill indices 1 through 7 with dummy accounts
    for i in 1u8..8 {
        let pk = sha256(&[b"padding_pk_".as_slice(), &[i]].concat());
        let sl = sha256(&[b"padding_salt_".as_slice(), &[i]].concat());
        store.add_account(Account {
            pubkey: pk,
            balance: 100,
            salt: sl,
        });
    }
    // Recipient at index 8 (opposite half)
    store.add_account(Account {
        pubkey: recipient_pubkey,
        balance: 2_000,
        salt: recipient_salt,
    });

    let sender_idx = 0;
    let recipient_idx = 8;

    let tree = store.build_tree(TREE_DEPTH);

    let sender_proof = tree.prove(sender_idx);
    let recipient_proof = tree.prove(recipient_idx);

    let amount: u64 = 3000;
    let new_sender_salt = sha256(b"new_sender_salt_1");
    let new_recipient_salt = sha256(b"new_recipient_salt_1");

    let sender_new_leaf = account_commitment(&sender_pubkey, 10_000 - amount, &new_sender_salt);
    let recipient_new_leaf =
        account_commitment(&recipient_pubkey, 2_000 + amount, &new_recipient_salt);

    let new_root = compute_new_root(
        sender_new_leaf,
        &sender_proof.indices,
        recipient_new_leaf,
        &recipient_proof.indices,
        &sender_proof.path,
        &recipient_proof.path,
    );

    // Full rebuild for comparison
    let expected_root = rebuild_tree_after_transfer(
        &store,
        sender_idx,
        sender_pubkey,
        10_000 - amount,
        new_sender_salt,
        recipient_idx,
        recipient_pubkey,
        2_000 + amount,
        new_recipient_salt,
    );

    assert_eq!(
        new_root, expected_root,
        "compute_new_root must handle sender and recipient in opposite halves"
    );
}

#[test]
fn test_compute_new_root_adjacent_leaves() {
    // Sender at index 0, recipient at index 1 — indices differ only in the
    // last bit (deepest level), so divergence is at depth - 1.
    let sender_sk = sha256(b"sender_sk_adj");
    let sender_pubkey = sha256(&sender_sk);
    let sender_salt = sha256(b"sender_salt_adj");

    let recipient_sk = sha256(b"recipient_sk_adj");
    let recipient_pubkey = sha256(&recipient_sk);
    let recipient_salt = sha256(b"recipient_salt_adj");

    let mut store = AccountStore::new();
    store.add_account(Account {
        pubkey: sender_pubkey,
        balance: 8000,
        salt: sender_salt,
    });
    store.add_account(Account {
        pubkey: recipient_pubkey,
        balance: 1000,
        salt: recipient_salt,
    });

    let sender_idx = 0;
    let recipient_idx = 1;

    let tree = store.build_tree(TREE_DEPTH);

    let sender_proof = tree.prove(sender_idx);
    let recipient_proof = tree.prove(recipient_idx);

    let amount: u64 = 2000;
    let new_sender_salt = sha256(b"new_sender_salt_adj");
    let new_recipient_salt = sha256(b"new_recipient_salt_adj");

    let sender_new_leaf = account_commitment(&sender_pubkey, 8000 - amount, &new_sender_salt);
    let recipient_new_leaf =
        account_commitment(&recipient_pubkey, 1000 + amount, &new_recipient_salt);

    let new_root = compute_new_root(
        sender_new_leaf,
        &sender_proof.indices,
        recipient_new_leaf,
        &recipient_proof.indices,
        &sender_proof.path,
        &recipient_proof.path,
    );

    // Full rebuild for comparison
    let expected_root = rebuild_tree_after_transfer(
        &store,
        sender_idx,
        sender_pubkey,
        8000 - amount,
        new_sender_salt,
        recipient_idx,
        recipient_pubkey,
        1000 + amount,
        new_recipient_salt,
    );

    assert_eq!(
        new_root, expected_root,
        "compute_new_root must handle adjacent leaves (divergence at deepest level)"
    );
}
