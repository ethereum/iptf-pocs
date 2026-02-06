//! Disclosure proof circuit (Phase 4)
//!
//! Proves that an account holder's balance meets a threshold, bound to a
//! specific auditor, without revealing the actual balance or account identity.
//! This is a read-only attestation — no state mutation, no nullifier.
//!
//! Public inputs (committed to journal):
//! - merkle_root: [u8; 32] - the Merkle root the account is proven against
//! - threshold: u64 - the minimum balance threshold (8 bytes, big-endian)
//! - disclosure_key_hash: [u8; 32] - SHA256(pubkey || auditor_pubkey || "disclosure_v1")
//!
//! Private inputs (witness, not revealed):
//! - secret_key: [u8; 32] - account owner's secret key
//! - balance: u64 - account balance
//! - salt: [u8; 32] - account salt
//! - path: Vec<[u8; 32]> - Merkle proof path
//! - indices: Vec<bool> - Merkle proof direction flags
//! - threshold: u64 - minimum balance threshold
//! - auditor_pubkey: [u8; 32] - auditor's public key

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
    let threshold: u64 = risc0_zkvm::guest::env::read();
    let auditor_pubkey: [u8; 32] = risc0_zkvm::guest::env::read();

    // 2. Derive pubkey from secret key
    let pubkey = sha256(&secret_key);

    // 3. Compute leaf commitment and verify membership (recompute root)
    let leaf = account_commitment(&pubkey, balance, &salt);
    let merkle_root = compute_root(leaf, &path, &indices);

    // 4. Prove balance satisfies threshold
    assert!(balance >= threshold, "Balance below threshold");

    // 5. Compute disclosure key hash
    let disclosure_key_hash =
        sha256(&[&pubkey[..], &auditor_pubkey[..], b"disclosure_v1"].concat());

    // 6. Commit public outputs to journal
    risc0_zkvm::guest::env::commit_slice(&merkle_root); // 32 bytes
    risc0_zkvm::guest::env::commit_slice(&threshold.to_be_bytes()); // 8 bytes, big-endian
    risc0_zkvm::guest::env::commit_slice(&disclosure_key_hash); // 32 bytes
}
