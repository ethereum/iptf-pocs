//! DIY Validium host library
//!
//! Provides Merkle tree operations and circuit input preparation
//! for the diy-validium protocol.

pub mod accounts;
pub mod merkle;

#[cfg(test)]
mod tests {
    use super::merkle::MerkleTree;
    use sha2::{Digest, Sha256};

    /// Helper: compute SHA-256 of input bytes.
    fn sha256(data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().into()
    }

    // ---------------------------------------------------------------
    // Tree construction tests
    // ---------------------------------------------------------------

    #[test]
    fn test_build_tree_from_single_leaf() {
        let leaf = sha256(b"account_0");
        let tree = MerkleTree::from_leaves(&[leaf], 20);
        // Root of a tree with one real leaf and padding should be deterministic
        let root = tree.root();
        assert_eq!(root.len(), 32);
    }

    #[test]
    fn test_build_tree_from_multiple_leaves() {
        let leaves: Vec<[u8; 32]> = (0..8)
            .map(|i| sha256(format!("account_{i}").as_bytes()))
            .collect();
        let tree = MerkleTree::from_leaves(&leaves, 20);
        let root = tree.root();
        assert_eq!(root.len(), 32);
    }

    #[test]
    fn test_tree_root_is_deterministic() {
        let leaves: Vec<[u8; 32]> = (0..4)
            .map(|i| sha256(format!("leaf_{i}").as_bytes()))
            .collect();
        let tree1 = MerkleTree::from_leaves(&leaves, 20);
        let tree2 = MerkleTree::from_leaves(&leaves, 20);
        assert_eq!(tree1.root(), tree2.root());
    }

    #[test]
    fn test_different_leaves_produce_different_roots() {
        let leaves_a: Vec<[u8; 32]> = (0..4)
            .map(|i| sha256(format!("set_a_{i}").as_bytes()))
            .collect();
        let leaves_b: Vec<[u8; 32]> = (0..4)
            .map(|i| sha256(format!("set_b_{i}").as_bytes()))
            .collect();
        let tree_a = MerkleTree::from_leaves(&leaves_a, 20);
        let tree_b = MerkleTree::from_leaves(&leaves_b, 20);
        assert_ne!(tree_a.root(), tree_b.root());
    }

    #[test]
    fn test_tree_depth_is_configurable() {
        let leaf = sha256(b"single");
        let tree_small = MerkleTree::from_leaves(&[leaf], 4);
        let tree_large = MerkleTree::from_leaves(&[leaf], 8);
        // Different depths should generally produce different roots
        // because padding/empty leaves are hashed to different depths
        assert_ne!(tree_small.root(), tree_large.root());
    }

    #[test]
    fn test_default_depth_is_20() {
        let leaf = sha256(b"default_depth");
        let tree = MerkleTree::new(&[leaf]);
        assert_eq!(tree.depth(), 20);
    }

    // ---------------------------------------------------------------
    // Proof generation tests
    // ---------------------------------------------------------------

    #[test]
    fn test_generate_proof_returns_correct_length() {
        let leaves: Vec<[u8; 32]> = (0..4)
            .map(|i| sha256(format!("account_{i}").as_bytes()))
            .collect();
        let tree = MerkleTree::from_leaves(&leaves, 20);
        let proof = tree.prove(0);
        // Path length should equal tree depth
        assert_eq!(proof.path.len(), 20);
        assert_eq!(proof.indices.len(), 20);
    }

    #[test]
    fn test_generate_proof_for_each_leaf() {
        let leaves: Vec<[u8; 32]> = (0..8)
            .map(|i| sha256(format!("account_{i}").as_bytes()))
            .collect();
        let tree = MerkleTree::from_leaves(&leaves, 5);
        for i in 0..8 {
            let proof = tree.prove(i);
            assert_eq!(proof.path.len(), 5);
            assert_eq!(proof.indices.len(), 5);
        }
    }

    // ---------------------------------------------------------------
    // Proof verification tests
    // ---------------------------------------------------------------

    #[test]
    fn test_valid_proof_recomputes_root() {
        let leaves: Vec<[u8; 32]> = (0..4)
            .map(|i| sha256(format!("account_{i}").as_bytes()))
            .collect();
        let tree = MerkleTree::from_leaves(&leaves, 20);
        let root = tree.root();

        for (i, leaf) in leaves.iter().enumerate() {
            let proof = tree.prove(i);
            assert!(
                proof.verify(*leaf, root),
                "Valid proof for leaf {i} should verify against root"
            );
        }
    }

    #[test]
    fn test_invalid_leaf_fails_verification() {
        let leaves: Vec<[u8; 32]> = (0..4)
            .map(|i| sha256(format!("account_{i}").as_bytes()))
            .collect();
        let tree = MerkleTree::from_leaves(&leaves, 20);
        let root = tree.root();
        let proof = tree.prove(0);

        let wrong_leaf = sha256(b"not_in_tree");
        assert!(
            !proof.verify(wrong_leaf, root),
            "Proof with wrong leaf should fail"
        );
    }

    #[test]
    fn test_proof_against_wrong_root_fails() {
        let leaves: Vec<[u8; 32]> = (0..4)
            .map(|i| sha256(format!("account_{i}").as_bytes()))
            .collect();
        let tree = MerkleTree::from_leaves(&leaves, 20);
        let proof = tree.prove(0);

        let wrong_root = sha256(b"wrong_root");
        assert!(
            !proof.verify(leaves[0], wrong_root),
            "Proof against wrong root should fail"
        );
    }

    #[test]
    fn test_swapped_sibling_fails_verification() {
        let leaves: Vec<[u8; 32]> = (0..4)
            .map(|i| sha256(format!("account_{i}").as_bytes()))
            .collect();
        let tree = MerkleTree::from_leaves(&leaves, 20);
        let root = tree.root();

        // Get proof for leaf 0 but try to use it with leaf 1
        let proof_for_0 = tree.prove(0);
        assert!(
            !proof_for_0.verify(leaves[1], root),
            "Proof for leaf 0 should not verify leaf 1"
        );
    }

    // ---------------------------------------------------------------
    // Edge cases
    // ---------------------------------------------------------------

    #[test]
    fn test_tree_with_power_of_two_leaves() {
        let leaves: Vec<[u8; 32]> = (0..16)
            .map(|i| sha256(format!("leaf_{i}").as_bytes()))
            .collect();
        let tree = MerkleTree::from_leaves(&leaves, 4);
        let root = tree.root();

        for (i, leaf) in leaves.iter().enumerate() {
            let proof = tree.prove(i);
            assert!(proof.verify(*leaf, root));
        }
    }

    #[test]
    fn test_tree_with_non_power_of_two_leaves() {
        // 5 leaves — not a power of two, needs padding
        let leaves: Vec<[u8; 32]> = (0..5)
            .map(|i| sha256(format!("leaf_{i}").as_bytes()))
            .collect();
        let tree = MerkleTree::from_leaves(&leaves, 4);
        let root = tree.root();

        for (i, leaf) in leaves.iter().enumerate() {
            let proof = tree.prove(i);
            assert!(proof.verify(*leaf, root));
        }
    }

    // ---------------------------------------------------------------
    // Account commitment tests (from SPEC.md)
    // ---------------------------------------------------------------

    #[test]
    fn test_account_commitment_matches_spec() {
        // commitment = SHA256(pubkey || balance || salt)
        // pubkey: 32 bytes, balance: 8 bytes LE u64, salt: 32 bytes = 72 bytes
        use super::merkle::account_commitment;

        let pubkey = [0xAA_u8; 32];
        let balance: u64 = 1000;
        let salt = [0xBB_u8; 32];

        let commitment = account_commitment(&pubkey, balance, &salt);
        assert_eq!(commitment.len(), 32);

        // Same inputs should produce same commitment
        let commitment2 = account_commitment(&pubkey, balance, &salt);
        assert_eq!(commitment, commitment2);

        // Different balance should produce different commitment
        let commitment3 = account_commitment(&pubkey, 999, &salt);
        assert_ne!(commitment, commitment3);
    }
}
