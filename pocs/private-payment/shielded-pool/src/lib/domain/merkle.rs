use alloy::primitives::{
    B256,
    U256,
};
use serde::{
    Deserialize,
    Serialize,
};

/// Maximum depth of the commitment Merkle tree (supports up to 2^32 commitments).
/// LeanIMT uses dynamic depth, but arrays are sized to this maximum.
pub const MAX_COMMITMENT_TREE_DEPTH: usize = 32;

/// Maximum depth of the attestation Merkle tree (supports up to 2^20 attestations).
/// LeanIMT uses dynamic depth, but arrays are sized to this maximum.
pub const MAX_ATTESTATION_TREE_DEPTH: usize = 20;

/// Merkle proof for a commitment in the commitment tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitmentMerkleProof {
    /// Sibling hashes along the path from leaf to root.
    pub path: Vec<B256>,
    /// Index bits indicating left (0) or right (1) at each level.
    pub indices: Vec<u8>,
    /// The leaf index in the tree.
    pub leaf_index: u64,
    /// The actual proof length (tree depth at time of proof generation).
    /// This is used for dynamic-depth merkle proof verification in circuits.
    pub proof_length: usize,
}

impl CommitmentMerkleProof {
    /// Create a new commitment Merkle proof.
    pub fn new(path: Vec<B256>, indices: Vec<u8>, leaf_index: u64) -> Self {
        let proof_length = path.len();
        Self {
            path,
            indices,
            leaf_index,
            proof_length,
        }
    }

    /// Create a new commitment Merkle proof with explicit proof length.
    pub fn with_proof_length(
        path: Vec<B256>,
        indices: Vec<u8>,
        leaf_index: u64,
        proof_length: usize,
    ) -> Self {
        Self {
            path,
            indices,
            leaf_index,
            proof_length,
        }
    }
}

/// Merkle proof for an attestation in the attestation tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationMerkleProof {
    /// Sibling hashes along the path from leaf to root.
    pub path: Vec<B256>,
    /// Index bits indicating left (0) or right (1) at each level.
    pub indices: Vec<u8>,
    /// The leaf index in the tree.
    pub leaf_index: u64,
    /// The actual proof length (tree depth at time of proof generation).
    /// This is used for dynamic-depth merkle proof verification in circuits.
    pub proof_length: usize,
}

impl AttestationMerkleProof {
    /// Create a new attestation Merkle proof.
    pub fn new(path: Vec<B256>, indices: Vec<u8>, leaf_index: u64) -> Self {
        let proof_length = path.len();
        Self {
            path,
            indices,
            leaf_index,
            proof_length,
        }
    }

    /// Create a new attestation Merkle proof with explicit proof length.
    pub fn with_proof_length(
        path: Vec<B256>,
        indices: Vec<u8>,
        leaf_index: u64,
        proof_length: usize,
    ) -> Self {
        Self {
            path,
            indices,
            leaf_index,
            proof_length,
        }
    }

    /// Create from contract proof elements (deprecated - clients now maintain local trees).
    /// Kept for backwards compatibility.
    pub fn from_contract_elements(elements: Vec<U256>, leaf_index: u64) -> Self {
        let path: Vec<B256> = elements.into_iter().map(|e| e.into()).collect();

        // Compute indices from leaf_index
        let mut indices = Vec::with_capacity(path.len());
        let mut idx = leaf_index;
        for _ in 0..path.len() {
            indices.push((idx & 1) as u8);
            idx >>= 1;
        }

        let proof_length = path.len();

        Self {
            path,
            indices,
            leaf_index,
            proof_length,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attestation_proof_from_elements() {
        let elements = vec![U256::from(10u64), U256::from(20u64)];
        let leaf_index = 2u64; // binary: 10

        let proof = AttestationMerkleProof::from_contract_elements(elements, leaf_index);

        assert_eq!(proof.path.len(), 2);
        assert_eq!(proof.indices, vec![0, 1]); // LSB first
        assert_eq!(proof.leaf_index, 2);
    }
}
