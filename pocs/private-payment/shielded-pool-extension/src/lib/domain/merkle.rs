use alloy::primitives::B256;
use serde::{
    Deserialize,
    Serialize,
};

use crate::crypto::poseidon::poseidon2;

/// Maximum depth of the commitment Merkle tree (supports up to 2^32 commitments).
/// LeanIMT uses dynamic depth, but arrays are sized to this maximum.
pub const MAX_COMMITMENT_TREE_DEPTH: usize = 32;

/// Merkle proof for a commitment in the commitment tree.
///
/// Ported from the parent shielded-pool (LeanIMT membership). Unchanged by this
/// extension: the commitment tree stores commitment hashes opaquely, so binding
/// `epoch_created` into the commitment does not affect the tree structure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitmentMerkleProof {
    /// Sibling hashes along the path from leaf to root.
    pub path: Vec<B256>,
    /// Index bits indicating left (0) or right (1) at each level.
    pub indices: Vec<u8>,
    /// The leaf index in the tree.
    pub leaf_index: u64,
    /// Actual proof length (dynamic tree depth at proof-generation time).
    pub proof_length: usize,
}

impl CommitmentMerkleProof {
    /// Create a new commitment Merkle proof (proof length inferred from `path`).
    pub fn new(path: Vec<B256>, indices: Vec<u8>, leaf_index: u64) -> Self {
        let proof_length = path.len();
        Self {
            path,
            indices,
            leaf_index,
            proof_length,
        }
    }

    /// Reconstruct the tree root from `leaf` and this proof's siblings/indices
    /// (`indices[i] == 0` means the running node is the left child at level `i`).
    /// Mirrors the circuit's `binary_merkle_root` check.
    pub fn reconstruct_root(&self, leaf: B256) -> B256 {
        let mut node = leaf;
        for (sibling, &bit) in self.path.iter().zip(self.indices.iter()) {
            node = if bit == 0 {
                poseidon2(node, *sibling)
            } else {
                poseidon2(*sibling, node)
            };
        }
        node
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proof_length_inferred() {
        let proof = CommitmentMerkleProof::new(
            vec![B256::repeat_byte(1), B256::repeat_byte(2)],
            vec![0, 1],
            2,
        );
        assert_eq!(proof.proof_length, 2);
        assert_eq!(proof.leaf_index, 2);
    }
}
