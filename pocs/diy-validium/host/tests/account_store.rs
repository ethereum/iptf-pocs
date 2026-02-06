//! TDD test scaffolds for the Phase 2 in-memory AccountStore.
//!
//! These tests define the expected API for `AccountStore` (to live in
//! `host/src/accounts.rs`). They are written in the red phase -- they
//! reference types and functions that do not exist yet and therefore
//! should NOT compile until the `accounts` module is implemented.
//!
//! The AccountStore is a thin Vec<Account> wrapper that provides
//! convenience methods for managing off-chain account state and
//! building Merkle trees from account commitments.
//!
//! See SPEC.md lines 79-99 for the Account data structure and
//! commitment scheme: `SHA256(pubkey || balance_le || salt)` = 72 bytes.
//!
//! See PHASE2-SPEC-REVIEW.md finding M1 for context on why this store
//! is needed (operator database schema). This in-memory implementation
//! serves as the foundation before any optional SQLite layer.

use diy_validium_host::accounts::{Account, AccountStore};
use diy_validium_host::merkle::{account_commitment, MerkleTree};

/// Helper: create a deterministic test account with a given index.
/// Uses simple SHA-256 derivations for pubkey and salt so tests are
/// reproducible without randomness.
fn make_test_account(index: u8, balance: u64) -> Account {
    use sha2::{Digest, Sha256};
    let pubkey: [u8; 32] = Sha256::digest([b"pubkey_", &[index]].concat()).into();
    let salt: [u8; 32] = Sha256::digest([b"salt_", &[index]].concat()).into();
    Account {
        pubkey,
        balance,
        salt,
    }
}

// -------------------------------------------------------------------
// Basic store operations
// -------------------------------------------------------------------

#[test]
fn test_new_store_is_empty() {
    let store = AccountStore::new();
    assert_eq!(store.len(), 0, "A new AccountStore should have length 0");
}

#[test]
fn test_add_account_returns_index() {
    let mut store = AccountStore::new();

    let idx0 = store.add_account(make_test_account(0, 1000));
    let idx1 = store.add_account(make_test_account(1, 2000));
    let idx2 = store.add_account(make_test_account(2, 3000));

    assert_eq!(idx0, 0, "First account should get index 0");
    assert_eq!(idx1, 1, "Second account should get index 1");
    assert_eq!(idx2, 2, "Third account should get index 2");
}

#[test]
fn test_get_account_returns_correct_data() {
    let mut store = AccountStore::new();

    let account = make_test_account(42, 5000);
    let expected_pubkey = account.pubkey;
    let expected_balance = account.balance;
    let expected_salt = account.salt;

    let idx = store.add_account(account);
    let retrieved = store.get_account(idx);

    assert_eq!(retrieved.pubkey, expected_pubkey, "pubkey should match");
    assert_eq!(retrieved.balance, expected_balance, "balance should match");
    assert_eq!(retrieved.salt, expected_salt, "salt should match");
}

// -------------------------------------------------------------------
// Balance updates
// -------------------------------------------------------------------

#[test]
fn test_update_balance_changes_commitment() {
    let mut store = AccountStore::new();

    let account = make_test_account(0, 1000);
    let idx = store.add_account(account);

    // Compute commitment before update.
    let commitment_before = {
        let acct = store.get_account(idx);
        account_commitment(&acct.pubkey, acct.balance, &acct.salt)
    };

    // Update balance with a new salt (as recommended by PHASE2-SPEC-REVIEW.md
    // finding on salt rotation -- new balance should use a fresh salt).
    use sha2::{Digest, Sha256};
    let new_salt: [u8; 32] = Sha256::digest(b"new_salt_after_update").into();
    store.update_balance(idx, 2000, new_salt);

    // Compute commitment after update.
    let commitment_after = {
        let acct = store.get_account(idx);
        account_commitment(&acct.pubkey, acct.balance, &acct.salt)
    };

    assert_ne!(
        commitment_before, commitment_after,
        "Updating balance (and salt) must change the account commitment"
    );

    // Verify the stored values actually changed.
    let updated = store.get_account(idx);
    assert_eq!(updated.balance, 2000, "Balance should be updated to 2000");
    assert_eq!(updated.salt, new_salt, "Salt should be updated");
}

// -------------------------------------------------------------------
// Merkle tree integration
// -------------------------------------------------------------------

#[test]
fn test_build_tree_produces_valid_root() {
    let mut store = AccountStore::new();
    store.add_account(make_test_account(0, 1000));
    store.add_account(make_test_account(1, 2000));

    let depth = 4; // small tree for tests
    let tree = store.build_tree(depth);

    // Manually compute the expected root from the same commitments.
    let commitments = store.commitments();
    let expected_tree = MerkleTree::from_leaves(&commitments, depth);

    assert_eq!(
        tree.root(),
        expected_tree.root(),
        "build_tree root should match a manually constructed MerkleTree"
    );
}

#[test]
fn test_build_tree_proofs_verify() {
    let mut store = AccountStore::new();
    store.add_account(make_test_account(0, 1000));
    store.add_account(make_test_account(1, 2000));
    store.add_account(make_test_account(2, 3000));

    let depth = 4;
    let tree = store.build_tree(depth);
    let root = tree.root();
    let commitments = store.commitments();

    // Every account's commitment should have a valid Merkle proof.
    for (i, commitment) in commitments.iter().enumerate() {
        let proof = tree.prove(i);
        assert!(
            proof.verify(*commitment, root),
            "Proof for account at index {i} should verify against the tree root"
        );
    }
}

// -------------------------------------------------------------------
// Commitment consistency
// -------------------------------------------------------------------

#[test]
fn test_commitments_match_manual_computation() {
    let mut store = AccountStore::new();

    let acct0 = make_test_account(0, 1000);
    let acct1 = make_test_account(1, 2000);

    // Compute expected commitments before adding (since add_account moves ownership).
    let expected_0 = account_commitment(&acct0.pubkey, acct0.balance, &acct0.salt);
    let expected_1 = account_commitment(&acct1.pubkey, acct1.balance, &acct1.salt);

    store.add_account(acct0);
    store.add_account(acct1);

    let commitments = store.commitments();

    assert_eq!(commitments.len(), 2, "Should have 2 commitments");
    assert_eq!(
        commitments[0], expected_0,
        "Commitment 0 should match account_commitment(pubkey, balance, salt)"
    );
    assert_eq!(
        commitments[1], expected_1,
        "Commitment 1 should match account_commitment(pubkey, balance, salt)"
    );
}

// -------------------------------------------------------------------
// Multi-account end-to-end
// -------------------------------------------------------------------

#[test]
fn test_store_with_multiple_accounts() {
    let mut store = AccountStore::new();

    let num_accounts = 8;
    for i in 0..num_accounts {
        let idx = store.add_account(make_test_account(i, (i as u64 + 1) * 1000));
        assert_eq!(idx, i as usize);
    }

    assert_eq!(store.len(), num_accounts as usize);

    // Build a tree and verify every account has a valid proof.
    let depth = 4; // 2^4 = 16 leaves, enough for 8 accounts
    let tree = store.build_tree(depth);
    let root = tree.root();
    let commitments = store.commitments();

    assert_eq!(commitments.len(), num_accounts as usize);

    for i in 0..num_accounts as usize {
        let acct = store.get_account(i);
        let expected_commitment = account_commitment(&acct.pubkey, acct.balance, &acct.salt);

        // Commitment from store matches manual computation.
        assert_eq!(
            commitments[i], expected_commitment,
            "Commitment at index {i} should match manual computation"
        );

        // Merkle proof verifies.
        let proof = tree.prove(i);
        assert!(
            proof.verify(commitments[i], root),
            "Merkle proof for account {i} should verify"
        );
    }
}
