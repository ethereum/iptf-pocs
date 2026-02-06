//! Membership proof circuit (Phase 1)
//!
//! Proves that a leaf exists in a Merkle tree without revealing which leaf.
//! The circuit recomputes the Merkle root from a leaf and proof path using
//! SHA-256, then asserts it matches the expected root (SPEC.md lines 162-197).
//!
//! Public inputs (committed to journal):
//! - merkle_root: [u8; 32] - the root of the allowlist Merkle tree
//!
//! Private inputs (witness, not revealed):
//! - leaf: [u8; 32] - the account commitment
//! - path: Vec<[u8; 32]> - sibling hashes along the Merkle path
//! - indices: Vec<bool> - left/right flags (true = current node is right child)

#![no_main]

use sha2::{Digest, Sha256};

risc0_zkvm::guest::entry!(main);

fn main() {
    // 1. Read private inputs (leaf, merkle proof)
    let leaf: [u8; 32] = risc0_zkvm::guest::env::read();
    let path: Vec<[u8; 32]> = risc0_zkvm::guest::env::read();
    let indices: Vec<bool> = risc0_zkvm::guest::env::read();

    // 2. Read the expected root
    let expected_root: [u8; 32] = risc0_zkvm::guest::env::read();

    // 3. Recompute root from leaf and proof path
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

    // 5. Commit the public inputs (root) to the journal
    risc0_zkvm::guest::env::commit(&expected_root);
}
