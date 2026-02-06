//! Withdrawal proof circuit (Phase 4)
//!
//! Proves a valid withdrawal from an account in the Merkle tree.
//! The circuit verifies the account exists in the old tree, checks balance
//! constraints, computes a state-bound nullifier, updates the leaf with
//! reduced balance and fresh salt, and recomputes the new Merkle root via
//! single-leaf update (SPEC.md Phase 4).
//!
//! Public inputs (committed to journal):
//! - old_root: [u8; 32] - the pre-transition Merkle root
//! - new_root: [u8; 32] - the post-transition Merkle root
//! - nullifier: [u8; 32] - state-bound nullifier for double-spend prevention
//! - amount: u64 - withdrawal amount (8 bytes, big-endian)
//! - recipient: [u8; 20] - Ethereum address receiving the withdrawal
//!
//! Private inputs (witness, not revealed):
//! - secret_key: [u8; 32] - account holder's secret key
//! - balance: u64 - current balance
//! - salt: [u8; 32] - current salt
//! - path: Vec<[u8; 32]> - Merkle proof path
//! - indices: Vec<bool> - Merkle proof direction flags
//! - amount: u64 - withdrawal amount
//! - new_salt: [u8; 32] - fresh salt for updated commitment
//! - recipient: [u8; 20] - Ethereum address for on-chain withdrawal

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

/// Compute the Merkle root by hashing a leaf upward through the proof path.
///
/// Used for both membership verification (old root) and single-leaf root
/// update (new root) — the logic is identical.
fn compute_root(leaf: [u8; 32], path: &[[u8; 32]], indices: &[bool]) -> [u8; 32] {
    let mut current = leaf;
    for (sibling, &is_right) in path.iter().zip(indices.iter()) {
        current = if is_right {
            hash_pair(sibling, &current)
        } else {
            hash_pair(&current, sibling)
        };
    }
    current
}

fn main() {
    // 1. Read all private inputs (order must match host env::write order)
    let secret_key: [u8; 32] = risc0_zkvm::guest::env::read();
    let balance: u64 = risc0_zkvm::guest::env::read();
    let salt: [u8; 32] = risc0_zkvm::guest::env::read();
    let path: Vec<[u8; 32]> = risc0_zkvm::guest::env::read();
    let indices: Vec<bool> = risc0_zkvm::guest::env::read();
    let amount: u64 = risc0_zkvm::guest::env::read();
    let new_salt: [u8; 32] = risc0_zkvm::guest::env::read();
    let recipient: [u8; 20] = risc0_zkvm::guest::env::read();

    // 2. Derive pubkey from secret key
    let pubkey = sha256(&secret_key);

    // 3. Compute old leaf commitment and verify membership (recompute root)
    let old_leaf = account_commitment(&pubkey, balance, &salt);
    let old_root = compute_root(old_leaf, &path, &indices);

    // 4. Validate withdrawal
    assert!(amount > 0, "Withdrawal amount must be positive");
    assert!(balance >= amount, "Insufficient balance");

    // 5. Compute nullifier (domain: "withdrawal_v1")
    let nullifier = sha256(&[&secret_key[..], &old_root[..], b"withdrawal_v1"].concat());

    // 6. Compute new leaf with reduced balance
    let new_balance = balance - amount;
    let new_leaf = account_commitment(&pubkey, new_balance, &new_salt);

    // 7. Single-leaf root update
    let new_root = compute_root(new_leaf, &path, &indices);

    // 8. Commit public outputs to journal
    risc0_zkvm::guest::env::commit_slice(&old_root); // 32 bytes
    risc0_zkvm::guest::env::commit_slice(&new_root); // 32 bytes
    risc0_zkvm::guest::env::commit_slice(&nullifier); // 32 bytes
    risc0_zkvm::guest::env::commit_slice(&amount.to_be_bytes()); // 8 bytes, big-endian
    risc0_zkvm::guest::env::commit_slice(&recipient); // 20 bytes
}
