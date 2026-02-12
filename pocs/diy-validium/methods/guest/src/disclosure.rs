//! Disclosure proof circuit — THE differentiator
//!
//! Proves that an account holder's balance meets a compliance threshold,
//! bound to a specific auditor, without revealing balance or identity.
//! This is a read-only attestation — no state mutation, no nullifier.
//!
//! Public inputs (journal): merkle_root, threshold, disclosure_key_hash
//! Private inputs: secret_key, balance, salt, path, indices, threshold, auditor_pubkey

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
    let threshold: u64 = risc0_zkvm::guest::env::read();
    let auditor_pubkey: [u8; 32] = risc0_zkvm::guest::env::read();

    // Derive identity and verify account exists
    let pubkey = sha256(&secret_key);
    let leaf = account_commitment(&pubkey, balance, &salt);
    let merkle_root = compute_root(leaf, &path, &indices);

    // === Business logic (readable by any Rust engineer) ===
    assert!(balance >= threshold, "Balance below threshold");
    let disclosure_key_hash =
        sha256(&[&pubkey[..], &auditor_pubkey[..], b"disclosure_v1"].concat());

    // Commit public outputs
    risc0_zkvm::guest::env::commit_slice(&merkle_root);
    risc0_zkvm::guest::env::commit_slice(&threshold.to_be_bytes());
    risc0_zkvm::guest::env::commit_slice(&disclosure_key_hash);
}
