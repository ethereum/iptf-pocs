//! Membership proof guest program
//!
//! Proves that a leaf exists in a Merkle tree without revealing which leaf.
//! Used by ValidiumBridge.deposit() to gate entry to the private system.
//!
//! Public inputs (journal): merkle_root (32) + pubkey (32) = 64 bytes
//! Private inputs: leaf, path, indices, expected_root, pubkey

#![no_main]

use guest_crypto::compute_root;

risc0_zkvm::guest::entry!(main);

fn main() {
    let leaf: [u8; 32] = risc0_zkvm::guest::env::read();
    let path: Vec<[u8; 32]> = risc0_zkvm::guest::env::read();
    let indices: Vec<bool> = risc0_zkvm::guest::env::read();
    let expected_root: [u8; 32] = risc0_zkvm::guest::env::read();
    let pubkey: [u8; 32] = risc0_zkvm::guest::env::read();

    // Bind proof to the depositor's pubkey: the leaf in the allowlist tree IS the pubkey
    assert_eq!(leaf, pubkey, "Leaf does not match pubkey");

    let computed_root = compute_root(leaf, &path, &indices);
    assert_eq!(computed_root, expected_root, "Merkle root mismatch");

    risc0_zkvm::guest::env::commit(&expected_root);
    risc0_zkvm::guest::env::commit(&pubkey);
}
