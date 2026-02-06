//! Balance proof circuit (Phase 2)
//!
//! Proves that an account in the Merkle tree holds at least `required_amount`
//! without revealing the actual balance, pubkey, or leaf position.
//! The circuit recomputes the leaf commitment and Merkle root using SHA-256,
//! asserts the root matches the expected value, and checks that balance >=
//! required_amount (SPEC.md lines 244-267).
//!
//! Public inputs (committed to journal):
//! - merkle_root: [u8; 32] - the root of the accounts Merkle tree (big-endian)
//! - required_amount: u64 - the minimum balance threshold (big-endian)
//!
//! Private inputs (witness, not revealed):
//! - pubkey: [u8; 32] - the account public key
//! - balance: u64 - the account balance
//! - salt: [u8; 32] - the blinding salt
//! - path: Vec<[u8; 32]> - sibling hashes along the Merkle path
//! - indices: Vec<bool> - left/right flags (true = current node is right child)
//! - expected_root: [u8; 32] - the expected Merkle root

#![no_main]

use sha2::{Digest, Sha256};

risc0_zkvm::guest::entry!(main);

fn main() {
    // 1. Read private inputs
    let pubkey: [u8; 32] = risc0_zkvm::guest::env::read();
    let balance: u64 = risc0_zkvm::guest::env::read();
    let salt: [u8; 32] = risc0_zkvm::guest::env::read();
    let path: Vec<[u8; 32]> = risc0_zkvm::guest::env::read();
    let indices: Vec<bool> = risc0_zkvm::guest::env::read();
    let expected_root: [u8; 32] = risc0_zkvm::guest::env::read();
    let required_amount: u64 = risc0_zkvm::guest::env::read();

    // 2. Recompute leaf commitment: SHA256(pubkey || balance_le || salt)
    let leaf: [u8; 32] = {
        let mut hasher = Sha256::new();
        hasher.update(pubkey);
        hasher.update(balance.to_le_bytes());
        hasher.update(salt);
        hasher.finalize().into()
    };

    // 3. Recompute Merkle root from leaf and proof path
    let mut current = leaf;
    for (sibling, &is_right) in path.iter().zip(indices.iter()) {
        let mut hasher = Sha256::new();
        if is_right {
            // Current node is right child: hash(sibling || current)
            hasher.update(sibling);
            hasher.update(current);
        } else {
            // Current node is left child: hash(current || sibling)
            hasher.update(current);
            hasher.update(sibling);
        }
        current = hasher.finalize().into();
    }

    // 4. Assert computed root matches expected root
    assert_eq!(
        current, expected_root,
        "Merkle root mismatch: membership verification failed"
    );

    // 5. Assert balance >= required_amount
    assert!(
        balance >= required_amount,
        "Balance check failed: insufficient balance"
    );

    // 6. Commit public inputs to journal (big-endian for Solidity compatibility)
    risc0_zkvm::guest::env::commit(&expected_root);
    risc0_zkvm::guest::env::commit(&required_amount.to_be_bytes());
}
