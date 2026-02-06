//! Transfer proof circuit (Phase 3)
//!
//! Proves a valid private transfer between two accounts in the Merkle tree.
//! The circuit verifies both accounts exist in the old tree, checks balance
//! constraints, computes a state-bound nullifier, updates both leaves with
//! new balances and salts, and recomputes the new Merkle root via dual-leaf
//! update (SPEC.md Phase 3).
//!
//! Public inputs (committed to journal):
//! - old_root: [u8; 32] - the pre-transition Merkle root (big-endian)
//! - new_root: [u8; 32] - the post-transition Merkle root (big-endian)
//! - nullifier: [u8; 32] - state-bound nullifier for double-spend prevention (big-endian)
//!
//! Private inputs (witness, not revealed):
//! - sender_sk: [u8; 32] - sender's secret key
//! - sender_balance: u64 - sender's current balance
//! - sender_salt: [u8; 32] - sender's current salt
//! - sender_path: Vec<[u8; 32]> - sender's Merkle proof path
//! - sender_indices: Vec<bool> - sender's Merkle proof direction flags
//! - amount: u64 - transfer amount
//! - recipient_pubkey: [u8; 32] - recipient's public key
//! - recipient_balance: u64 - recipient's current balance
//! - recipient_salt: [u8; 32] - recipient's current salt
//! - recipient_path: Vec<[u8; 32]> - recipient's Merkle proof path
//! - recipient_indices: Vec<bool> - recipient's Merkle proof direction flags
//! - new_sender_salt: [u8; 32] - sender's new salt after transfer
//! - new_recipient_salt: [u8; 32] - recipient's new salt after transfer

#![no_main]

use sha2::{Digest, Sha256};

risc0_zkvm::guest::entry!(main);

/// SHA-256 of arbitrary bytes.
fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// SHA-256(left || right) for Merkle tree internal nodes.
fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// Account commitment: SHA256(pubkey || balance_le || salt).
fn account_commitment(pubkey: &[u8; 32], balance: u64, salt: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(pubkey);
    hasher.update(balance.to_le_bytes());
    hasher.update(salt);
    hasher.finalize().into()
}

/// Verify Merkle membership by recomputing root from leaf and proof path.
fn verify_membership(
    leaf: [u8; 32],
    path: &[[u8; 32]],
    indices: &[bool],
    expected_root: [u8; 32],
) {
    let mut current = leaf;
    for (sibling, &is_right) in path.iter().zip(indices.iter()) {
        current = if is_right {
            hash_pair(sibling, &current)
        } else {
            hash_pair(&current, sibling)
        };
    }
    assert_eq!(
        current, expected_root,
        "Merkle root mismatch: membership verification failed"
    );
}

/// Dual-leaf root recomputation after updating sender and recipient leaves.
///
/// Proof arrays are leaf-to-root: path[0] is the leaf-level sibling,
/// path[depth-1] is the root-adjacent sibling.
fn compute_new_root(
    sender_leaf: [u8; 32],
    sender_indices: &[bool],
    recipient_leaf: [u8; 32],
    recipient_indices: &[bool],
    sender_path: &[[u8; 32]],
    recipient_path: &[[u8; 32]],
) -> [u8; 32] {
    let depth = sender_indices.len();

    // Find divergence: the shallowest level (closest to root) where
    // sender and recipient indices differ. In leaf-to-root indexing
    // this is the highest array index where they differ.
    let divergence = (0..depth)
        .rev()
        .find(|&i| sender_indices[i] != recipient_indices[i])
        .expect("Sender and recipient must differ (no self-transfers)");

    // Recompute sender's branch from leaf (level 0) up to but not
    // including the divergence level.
    let mut sender_hash = sender_leaf;
    for i in 0..divergence {
        sender_hash = if sender_indices[i] {
            hash_pair(&sender_path[i], &sender_hash)
        } else {
            hash_pair(&sender_hash, &sender_path[i])
        };
    }

    // Recompute recipient's branch from leaf up to but not including
    // the divergence level.
    let mut recipient_hash = recipient_leaf;
    for i in 0..divergence {
        recipient_hash = if recipient_indices[i] {
            hash_pair(&recipient_path[i], &recipient_hash)
        } else {
            hash_pair(&recipient_hash, &recipient_path[i])
        };
    }

    // At the divergence level the two recomputed branches are siblings.
    let mut current = if sender_indices[divergence] {
        // Sender is right child, recipient is left child
        hash_pair(&recipient_hash, &sender_hash)
    } else {
        // Sender is left child, recipient is right child
        hash_pair(&sender_hash, &recipient_hash)
    };

    // Above divergence: continue hashing toward the root using the
    // shared siblings (same in both paths above the divergence point).
    for i in (divergence + 1)..depth {
        current = if sender_indices[i] {
            hash_pair(&sender_path[i], &current)
        } else {
            hash_pair(&current, &sender_path[i])
        };
    }

    current
}

fn main() {
    // 1. Read all private inputs
    let sender_sk: [u8; 32] = risc0_zkvm::guest::env::read();
    let sender_balance: u64 = risc0_zkvm::guest::env::read();
    let sender_salt: [u8; 32] = risc0_zkvm::guest::env::read();
    let sender_path: Vec<[u8; 32]> = risc0_zkvm::guest::env::read();
    let sender_indices: Vec<bool> = risc0_zkvm::guest::env::read();
    let amount: u64 = risc0_zkvm::guest::env::read();
    let recipient_pubkey: [u8; 32] = risc0_zkvm::guest::env::read();
    let recipient_balance: u64 = risc0_zkvm::guest::env::read();
    let recipient_salt: [u8; 32] = risc0_zkvm::guest::env::read();
    let recipient_path: Vec<[u8; 32]> = risc0_zkvm::guest::env::read();
    let recipient_indices: Vec<bool> = risc0_zkvm::guest::env::read();
    let new_sender_salt: [u8; 32] = risc0_zkvm::guest::env::read();
    let new_recipient_salt: [u8; 32] = risc0_zkvm::guest::env::read();

    // 2. Derive sender pubkey from secret key
    let sender_pubkey = sha256(&sender_sk);

    // 3. Prohibit self-transfers
    assert_ne!(sender_pubkey, recipient_pubkey, "Self-transfer not allowed");

    // 4. Compute sender's old leaf commitment and verify in old tree
    let sender_old_leaf = account_commitment(&sender_pubkey, sender_balance, &sender_salt);
    let old_root: [u8; 32] = {
        let mut current = sender_old_leaf;
        for (sibling, &is_right) in sender_path.iter().zip(sender_indices.iter()) {
            current = if is_right {
                hash_pair(sibling, &current)
            } else {
                hash_pair(&current, sibling)
            };
        }
        current
    };

    // 5. Compute recipient's old leaf commitment and verify in old tree
    let recipient_old_leaf =
        account_commitment(&recipient_pubkey, recipient_balance, &recipient_salt);
    verify_membership(recipient_old_leaf, &recipient_path, &recipient_indices, old_root);

    // 6. Check positive transfer amount
    assert!(amount > 0, "Transfer amount must be positive");

    // 7. Check sufficient sender balance (underflow protection)
    assert!(sender_balance >= amount, "Insufficient balance");

    // 8. Check recipient overflow protection
    assert!(
        recipient_balance <= u64::MAX - amount,
        "Recipient balance overflow"
    );

    // 9. Compute state-bound nullifier
    let nullifier = sha256(&[&sender_sk[..], &old_root[..], b"transfer_v1"].concat());

    // 10. Compute new balances (safe after checks in steps 6-8)
    let new_sender_balance = sender_balance - amount;
    let new_recipient_balance = recipient_balance + amount;

    // 11. Compute new leaf commitments
    let sender_new_leaf = account_commitment(&sender_pubkey, new_sender_balance, &new_sender_salt);
    let recipient_new_leaf =
        account_commitment(&recipient_pubkey, new_recipient_balance, &new_recipient_salt);

    // 12. Recompute new root with both leaves updated
    let new_root = compute_new_root(
        sender_new_leaf,
        &sender_indices,
        recipient_new_leaf,
        &recipient_indices,
        &sender_path,
        &recipient_path,
    );

    // 13. Commit public outputs to journal (big-endian for Solidity compatibility)
    risc0_zkvm::guest::env::commit_slice(&old_root);
    risc0_zkvm::guest::env::commit_slice(&new_root);
    risc0_zkvm::guest::env::commit_slice(&nullifier);
}
