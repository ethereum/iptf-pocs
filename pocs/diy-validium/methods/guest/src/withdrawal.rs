//! Withdrawal proof circuit
//!
//! Proves a valid withdrawal from an account in the Merkle tree.
//! Single-leaf state transition: balance decreases, funds exit to L1.
//!
//! Public inputs (journal): old_root, new_root, nullifier, amount, recipient
//! Private inputs: secret_key, balance, salt, path, indices, amount, new_salt, recipient

#![no_main]

use guest_crypto::{account_commitment, compute_root, sha256};

risc0_zkvm::guest::entry!(main);

fn main() {
    // Read private inputs
    let secret_key: [u8; 32] = risc0_zkvm::guest::env::read();
    let balance: u64 = risc0_zkvm::guest::env::read();
    let salt: [u8; 32] = risc0_zkvm::guest::env::read();
    let path: Vec<[u8; 32]> = risc0_zkvm::guest::env::read();
    let indices: Vec<bool> = risc0_zkvm::guest::env::read();
    let amount: u64 = risc0_zkvm::guest::env::read();
    let new_salt: [u8; 32] = risc0_zkvm::guest::env::read();
    let recipient: [u8; 20] = risc0_zkvm::guest::env::read();

    // Derive identity and verify account exists
    let pubkey = sha256(&secret_key);
    let old_leaf = account_commitment(&pubkey, balance, &salt);
    let old_root = compute_root(old_leaf, &path, &indices);

    // === Business logic ===
    assert!(amount > 0, "Withdrawal amount must be positive");
    assert!(balance >= amount, "Insufficient balance");

    let nullifier = sha256(&[&secret_key[..], &old_leaf[..], b"withdrawal_v1"].concat());

    let new_balance = balance - amount;
    let new_leaf = account_commitment(&pubkey, new_balance, &new_salt);
    let new_root = compute_root(new_leaf, &path, &indices);

    // Commit public outputs
    risc0_zkvm::guest::env::commit_slice(&old_root);
    risc0_zkvm::guest::env::commit_slice(&new_root);
    risc0_zkvm::guest::env::commit_slice(&nullifier);
    risc0_zkvm::guest::env::commit_slice(&amount.to_be_bytes());
    risc0_zkvm::guest::env::commit_slice(&recipient);
}
