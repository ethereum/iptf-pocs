//! Transfer proof circuit
//!
//! Proves a valid private transfer between two accounts in the Merkle tree.
//! Dual-leaf state transition: sender balance decreases, recipient increases.
//!
//! Public inputs (journal): old_root, new_root, nullifier
//! Private inputs: sender_sk, sender_balance, sender_salt, sender_path,
//!   sender_indices, amount, recipient_pubkey, recipient_balance, recipient_salt,
//!   recipient_path, recipient_indices, new_sender_salt, new_recipient_salt

#![no_main]

use guest_crypto::{account_commitment, compute_root, hash_pair, sha256, verify_membership};

risc0_zkvm::guest::entry!(main);

/// Dual-leaf root recomputation after updating sender and recipient leaves.
fn compute_new_root(
    sender_leaf: [u8; 32],
    sender_indices: &[bool],
    recipient_leaf: [u8; 32],
    recipient_indices: &[bool],
    sender_path: &[[u8; 32]],
    recipient_path: &[[u8; 32]],
) -> [u8; 32] {
    let depth = sender_indices.len();

    let divergence = (0..depth)
        .rev()
        .find(|&i| sender_indices[i] != recipient_indices[i])
        .expect("Sender and recipient must differ (no self-transfers)");

    let mut sender_hash = sender_leaf;
    for i in 0..divergence {
        sender_hash = if sender_indices[i] {
            hash_pair(&sender_path[i], &sender_hash)
        } else {
            hash_pair(&sender_hash, &sender_path[i])
        };
    }

    let mut recipient_hash = recipient_leaf;
    for i in 0..divergence {
        recipient_hash = if recipient_indices[i] {
            hash_pair(&recipient_path[i], &recipient_hash)
        } else {
            hash_pair(&recipient_hash, &recipient_path[i])
        };
    }

    let mut current = if sender_indices[divergence] {
        hash_pair(&recipient_hash, &sender_hash)
    } else {
        hash_pair(&sender_hash, &recipient_hash)
    };

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
    // Read private inputs
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

    // Derive sender identity
    let sender_pubkey = sha256(&sender_sk);

    // === Business logic ===
    assert_ne!(sender_pubkey, recipient_pubkey, "Self-transfer not allowed");
    assert!(amount > 0, "Transfer amount must be positive");
    assert!(sender_balance >= amount, "Insufficient balance");
    assert!(recipient_balance <= u64::MAX - amount, "Recipient balance overflow");

    // Verify both accounts exist in old tree
    let sender_old_leaf = account_commitment(&sender_pubkey, sender_balance, &sender_salt);
    let old_root = compute_root(sender_old_leaf, &sender_path, &sender_indices);

    let recipient_old_leaf =
        account_commitment(&recipient_pubkey, recipient_balance, &recipient_salt);
    verify_membership(recipient_old_leaf, &recipient_path, &recipient_indices, old_root);

    // State transition
    let nullifier = sha256(&[&sender_sk[..], &old_root[..], b"transfer_v1"].concat());

    let new_sender_balance = sender_balance - amount;
    let new_recipient_balance = recipient_balance + amount;

    let sender_new_leaf = account_commitment(&sender_pubkey, new_sender_balance, &new_sender_salt);
    let recipient_new_leaf =
        account_commitment(&recipient_pubkey, new_recipient_balance, &new_recipient_salt);

    let new_root = compute_new_root(
        sender_new_leaf,
        &sender_indices,
        recipient_new_leaf,
        &recipient_indices,
        &sender_path,
        &recipient_path,
    );

    // Commit public outputs
    risc0_zkvm::guest::env::commit_slice(&old_root);
    risc0_zkvm::guest::env::commit_slice(&new_root);
    risc0_zkvm::guest::env::commit_slice(&nullifier);
}
