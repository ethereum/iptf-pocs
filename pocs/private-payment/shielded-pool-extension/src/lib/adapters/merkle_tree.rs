//! LeanIMT commitment-tree mirror.
//!
//! Wraps the `lean-imt` crate to provide the Poseidon-based append-only
//! commitment tree, matching the on-chain LeanIMT and the Noir circuit's
//! `binary_merkle_root`. Ported from the parent shielded-pool (PoC independence);
//! the only change is that the node hasher delegates to
//! [`crate::crypto::poseidon::poseidon2`] so every Merkle node uses the same
//! Poseidon instance as the rest of the crate (and the circuits).

use alloy::primitives::B256;
use lean_imt::hashed_tree::{
    HashedLeanIMT,
    LeanIMTHasher,
};

use crate::{
    crypto::poseidon::poseidon2,
    domain::merkle::CommitmentMerkleProof,
};

/// Poseidon (arity-2) hasher for the LeanIMT, delegating to the crate's
/// `poseidon2` so node hashes match the commitment/circuit Poseidon exactly.
#[derive(Debug, Default, Clone)]
pub struct PoseidonHash;

impl LeanIMTHasher<32> for PoseidonHash {
    fn hash(input: &[u8]) -> [u8; 32] {
        // LeanIMT calls this with two concatenated 32-byte children.
        let left = B256::from_slice(&input[..32]);
        let right = B256::from_slice(&input[32..]);
        poseidon2(left, right).0
    }
}

/// Commitment tree using LeanIMT with Poseidon hashing.
pub struct CommitmentTree(HashedLeanIMT<32, PoseidonHash>);

fn decode_path(index: usize, path_len: usize) -> Vec<u8> {
    let mut path = Vec::with_capacity(path_len);
    for i in 0..path_len {
        path.push(((index >> i) & 1) as u8); // LSB first
    }
    path
}

impl CommitmentTree {
    /// Create a new empty commitment tree.
    pub fn new() -> Self {
        Self(HashedLeanIMT::new(&[], PoseidonHash).expect("empty LeanIMT init"))
    }

    /// Insert a leaf (commitment hash) into the tree.
    pub fn insert(&mut self, leaf: &[u8; 32]) {
        self.0.insert(leaf);
    }

    /// Number of leaves in the tree.
    pub fn len(&self) -> usize {
        self.0.size()
    }

    /// Whether the tree is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Current root, or `None` if empty.
    pub fn root(&self) -> Option<[u8; 32]> {
        self.0.root()
    }

    /// Generate a membership proof for the leaf at `leaf_index`.
    pub fn generate_commitment_proof(&self, leaf_index: u64) -> Option<CommitmentMerkleProof> {
        let proof = self.0.generate_proof(leaf_index as usize).ok()?;
        let path: Vec<B256> = proof.siblings.iter().map(|s| B256::from_slice(s)).collect();
        let indices = decode_path(proof.index, proof.siblings.len());
        Some(CommitmentMerkleProof::new(path, indices, leaf_index))
    }
}

impl Default for CommitmentTree {
    fn default() -> Self {
        Self::new()
    }
}

/// Raw bytes of a `B256` for tree insertion.
pub fn b256_to_bytes(value: &B256) -> [u8; 32] {
    value.0
}

/// A `B256` from tree bytes.
pub fn bytes_to_b256(bytes: &[u8; 32]) -> B256 {
    B256::from_slice(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_commitment_tree_basic() {
        let mut tree = CommitmentTree::new();
        assert!(tree.is_empty());
        tree.insert(&[1u8; 32]);
        assert_eq!(tree.len(), 1);
        assert!(tree.root().is_some());
    }

    #[test]
    fn test_commitment_tree_proof_generation() {
        let mut tree = CommitmentTree::new();
        tree.insert(&[1u8; 32]);
        tree.insert(&[2u8; 32]);

        let proof = tree.generate_commitment_proof(0).unwrap();
        assert_eq!(proof.leaf_index, 0);
        assert_eq!(proof.proof_length, proof.path.len());
        assert!(!proof.path.is_empty());
    }

    #[test]
    fn test_b256_conversion() {
        let original = B256::repeat_byte(42);
        assert_eq!(bytes_to_b256(&b256_to_bytes(&original)), original);
    }
}
