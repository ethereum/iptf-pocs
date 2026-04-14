use ark_bn254::Fr;

use crate::{
    poseidon::hash_merkle_node,
    types::MerklePath,
};

/// Verify that a leaf at the given index produces the expected root.
pub fn verify(leaf: Fr, path: &MerklePath, expected_root: Fr) -> bool {
    if path.siblings.is_empty() {
        return leaf == expected_root;
    }

    let mut current = leaf;
    for (sibling, &index) in path.siblings.iter().zip(path.indices.iter()) {
        current = if index == 0 {
            hash_merkle_node(current, *sibling)
        } else {
            hash_merkle_node(*sibling, current)
        };
    }
    current == expected_root
}
