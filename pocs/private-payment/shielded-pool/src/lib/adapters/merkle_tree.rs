//! Merkle tree adapter using LeanIMT from zk-kit.rust
//!
//! This module wraps the `lean-imt` crate to provide Poseidon-based Merkle trees
//! that match the on-chain LeanIMT implementation and the Noir circuit's
//! `binary_merkle_root` function.

use ark_bn254::{
    Fq,
    Fr,
};
use ark_ff::{
    BigInteger,
    PrimeField,
};
use lean_imt::hashed_tree::{
    HashedLeanIMT,
    LeanIMTHasher,
};
use light_poseidon::{
    Poseidon,
    PoseidonHasher,
};

use crate::domain::merkle::{
    AttestationMerkleProof,
    CommitmentMerkleProof,
};

/// Poseidon hasher for LeanIMT.
///
/// Uses light-poseidon with the Circom-compatible configuration (matching Solidity's PoseidonT3).
#[derive(Debug, Default, Clone)]
pub struct PoseidonHash;

impl LeanIMTHasher<32> for PoseidonHash {
    fn hash(input: &[u8]) -> [u8; 32] {
        let hash = Poseidon::<Fq>::new_circom(2)
            .expect("Failed to initialize Poseidon")
            .hash(&[
                Fr::from_be_bytes_mod_order(&input[..32]),
                Fr::from_be_bytes_mod_order(&input[32..]),
            ])
            .expect("Poseidon hash failed");

        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(&hash.into_bigint().to_bytes_be());

        hash_bytes
    }
}

/// Commitment tree using LeanIMT with Poseidon hashing.
pub struct CommitmentTree(HashedLeanIMT<32, PoseidonHash>);

/// Attestation tree using LeanIMT with Poseidon hashing.
pub struct AttestationTree(HashedLeanIMT<32, PoseidonHash>);

fn decode_path(index: usize, path_len: usize) -> Vec<u8> {
    let mut path = Vec::with_capacity(path_len);

    for i in 0..path_len {
        // extract bits from LSB to MSB
        let bit = ((index >> i) & 1) as u8;
        path.push(bit);
    }

    path
}

impl CommitmentTree {
    /// Create a new empty commitment tree.
    pub fn new() -> Self {
        Self(HashedLeanIMT::new(&[], PoseidonHash).unwrap())
    }

    /// Insert a leaf into the tree.
    pub fn insert(&mut self, leaf: &[u8; 32]) {
        self.0.insert(leaf);
    }

    /// Get the number of leaves in the tree.
    pub fn len(&self) -> usize {
        self.0.size()
    }

    /// Check if the tree is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Get the current root of the tree, or None if empty.
    pub fn root(&self) -> Option<[u8; 32]> {
        self.0.root()
    }

    /// Generate a merkle proof for the leaf at the given index.
    pub fn generate_commitment_proof(
        &self,
        leaf_index: u64,
    ) -> Option<CommitmentMerkleProof> {
        let proof = self.0.generate_proof(leaf_index as usize).ok()?;

        let path: Vec<alloy::primitives::B256> = proof
            .siblings
            .iter()
            .map(|s| alloy::primitives::B256::from_slice(s))
            .collect();

        let indices: Vec<u8> = decode_path(proof.index, proof.siblings.len());

        let proof_length = path.len();

        Some(CommitmentMerkleProof {
            path,
            indices,
            leaf_index,
            proof_length,
        })
    }
}

impl Default for CommitmentTree {
    fn default() -> Self {
        Self::new()
    }
}

impl AttestationTree {
    /// Create a new empty attestation tree.
    pub fn new() -> Self {
        Self(HashedLeanIMT::new(&[], PoseidonHash).unwrap())
    }

    /// Insert a leaf into the tree.
    pub fn insert(&mut self, leaf: &[u8; 32]) {
        self.0.insert(leaf);
    }

    /// Get the number of leaves in the tree.
    pub fn len(&self) -> usize {
        self.0.size()
    }

    /// Check if the tree is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Get the current root of the tree, or None if empty.
    pub fn root(&self) -> Option<[u8; 32]> {
        self.0.root()
    }

    /// Generate a merkle proof for the leaf at the given index.
    pub fn generate_attestation_proof(
        &self,
        leaf_index: u64,
    ) -> Option<AttestationMerkleProof> {
        let proof = self.0.generate_proof(leaf_index as usize).ok()?;

        let path: Vec<alloy::primitives::B256> = proof
            .siblings
            .iter()
            .map(|s| alloy::primitives::B256::from_slice(s))
            .collect();

        let indices: Vec<u8> = decode_path(proof.index, proof.siblings.len());

        let proof_length = path.len();

        Some(AttestationMerkleProof {
            path,
            indices,
            leaf_index,
            proof_length,
        })
    }
}

impl Default for AttestationTree {
    fn default() -> Self {
        Self::new()
    }
}

/// Convert a B256 value to bytes for insertion into the tree.
pub fn b256_to_bytes(value: &alloy::primitives::B256) -> [u8; 32] {
    value.0
}

/// Convert bytes from the tree to a B256 value.
pub fn bytes_to_b256(bytes: &[u8; 32]) -> alloy::primitives::B256 {
    alloy::primitives::B256::from_slice(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::B256;

    #[test]
    fn test_commitment_tree_basic() {
        let mut tree = CommitmentTree::new();

        // Insert a leaf
        let leaf1 = [1u8; 32];
        tree.insert(&leaf1);

        assert_eq!(tree.len(), 1);
        assert!(tree.root().is_some());
    }

    #[test]
    fn test_commitment_tree_proof_generation() {
        let mut tree = CommitmentTree::new();

        // Insert two leaves
        let leaf1 = [1u8; 32];
        let leaf2 = [2u8; 32];
        tree.insert(&leaf1);
        tree.insert(&leaf2);

        // Generate proof for first leaf
        let proof = tree.generate_commitment_proof(0).unwrap();

        assert_eq!(proof.leaf_index, 0);
        assert_eq!(proof.proof_length, proof.path.len());
        assert!(!proof.path.is_empty());
    }

    #[test]
    fn test_attestation_tree_proof_generation() {
        let mut tree = AttestationTree::new();

        // Insert leaves
        let leaf1 = [1u8; 32];
        let leaf2 = [2u8; 32];
        let leaf3 = [3u8; 32];
        tree.insert(&leaf1);
        tree.insert(&leaf2);
        tree.insert(&leaf3);

        // Generate proof for second leaf
        let proof = tree.generate_attestation_proof(1).unwrap();

        assert_eq!(proof.leaf_index, 1);
        assert_eq!(proof.proof_length, proof.path.len());
    }

    #[test]
    fn test_b256_conversion() {
        let original = B256::from_slice(&[42u8; 32]);
        let bytes = b256_to_bytes(&original);
        let converted = bytes_to_b256(&bytes);
        assert_eq!(original, converted);
    }
}
