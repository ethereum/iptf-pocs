//! Membership proof circuit (Phase 1)
//!
//! Proves that a leaf exists in a Merkle tree without revealing which leaf.
//!
//! Public inputs:
//! - merkle_root: [u8; 32] - the root of the allowlist Merkle tree
//!
//! Private inputs:
//! - leaf: [u8; 32] - the leaf value (e.g., hash of address)
//! - proof: Vec<([u8; 32], bool)> - sibling hashes and left/right flags

#![no_main]

risc0_zkvm::guest::entry!(main);

fn main() {
    // TODO: Implement in Phase 1
    // 1. Read private inputs (leaf, merkle proof)
    // 2. Read public input (expected root)
    // 3. Recompute root from leaf and proof path
    // 4. Assert computed root matches expected root
    // 5. Commit the public inputs (root) to the journal
}
