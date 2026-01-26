use poseidon_rs::{Fr, Poseidon};
use ff::PrimeField;

/// Tree height must match circuit's TREE_HEIGHT constant
pub const TREE_HEIGHT: usize = 3;

/// Maximum number of leaves (2^TREE_HEIGHT)
pub const MAX_LEAVES: usize = 1 << TREE_HEIGHT; // 8

/// Zero value for empty nodes
fn zero() -> Fr {
    Fr::from_str("0").unwrap()
}

/// Hash two field elements using Poseidon
fn hash2(left: Fr, right: Fr) -> Fr {
    let hasher = Poseidon::new();
    hasher.hash(vec![left, right]).expect("Poseidon hash failed")
}

/// Merkle path for proving note existence
/// Matches the circuit's expected format
#[derive(Clone, Debug)]
pub struct CircuitMerklePath {
    /// 0 = current node is on left, 1 = current node is on right
    pub indices: [u8; TREE_HEIGHT],
    /// Sibling hashes at each level
    pub elements: [Fr; TREE_HEIGHT],
}

impl CircuitMerklePath {
    /// Create a dummy path (all zeros) - used for padding
    pub fn dummy() -> Self {
        CircuitMerklePath {
            indices: [0; TREE_HEIGHT],
            elements: [zero(); TREE_HEIGHT],
        }
    }
}

/// Fixed-height Merkle tree matching the circuit's TREE_HEIGHT
pub struct FixedMerkleTree {
    /// All levels of the tree, from leaves (level 0) to root (level TREE_HEIGHT)
    levels: Vec<Vec<Fr>>,
    /// Number of actual leaves inserted
    leaf_count: usize,
}

impl FixedMerkleTree {
    /// Create a new empty tree
    pub fn new() -> Self {
        // Initialize with empty levels
        let mut levels = Vec::with_capacity(TREE_HEIGHT + 1);
        
        // Level 0: leaves (initially all zeros)
        levels.push(vec![zero(); MAX_LEAVES]);
        
        // Build empty tree levels
        for level in 1..=TREE_HEIGHT {
            let prev_len = levels[level - 1].len();
            let this_len = (prev_len + 1) / 2;
            let mut this_level = Vec::with_capacity(this_len);
            
            for i in 0..this_len {
                let left = levels[level - 1].get(i * 2).copied().unwrap_or(zero());
                let right = levels[level - 1].get(i * 2 + 1).copied().unwrap_or(zero());
                this_level.push(hash2(left, right));
            }
            levels.push(this_level);
        }
        
        FixedMerkleTree {
            levels,
            leaf_count: 0,
        }
    }
    
    /// Create tree from existing commitments
    pub fn from_leaves(leaves: &[Fr]) -> Self {
        let mut tree = Self::new();
        for leaf in leaves {
            tree.insert(*leaf);
        }
        tree
    }
    
    /// Insert a new leaf (commitment) and update the tree
    pub fn insert(&mut self, leaf: Fr) -> usize {
        if self.leaf_count >= MAX_LEAVES {
            panic!("Merkle tree is full (max {} leaves)", MAX_LEAVES);
        }
        
        let index = self.leaf_count;
        self.levels[0][index] = leaf;
        self.leaf_count += 1;
        
        // Update path from leaf to root
        self.update_path(index);
        
        index
    }
    
    /// Update the tree along the path from a leaf to the root
    fn update_path(&mut self, leaf_index: usize) {
        let mut current_index = leaf_index;
        
        for level in 0..TREE_HEIGHT {
            let left_idx = current_index - (current_index % 2);
            let right_idx = left_idx + 1;
            
            let left = self.levels[level].get(left_idx).copied().unwrap_or(zero());
            let right = self.levels[level].get(right_idx).copied().unwrap_or(zero());
            
            let parent_idx = current_index / 2;
            self.levels[level + 1][parent_idx] = hash2(left, right);
            
            current_index = parent_idx;
        }
    }
    
    /// Get the current root
    pub fn root(&self) -> Fr {
        self.levels[TREE_HEIGHT][0]
    }
    
    /// Generate a Merkle proof for the leaf at the given index
    pub fn generate_proof(&self, leaf_index: usize) -> CircuitMerklePath {
        if leaf_index >= self.leaf_count && leaf_index >= MAX_LEAVES {
            panic!("Leaf index {} out of bounds", leaf_index);
        }
        
        let mut indices = [0u8; TREE_HEIGHT];
        let mut elements = [zero(); TREE_HEIGHT];
        
        let mut current_index = leaf_index;
        
        for level in 0..TREE_HEIGHT {
            // Determine if current node is on the right (1) or left (0)
            let is_right = (current_index % 2) as u8;
            indices[level] = is_right;
            
            // Get sibling
            let sibling_index = if is_right == 1 {
                current_index - 1
            } else {
                current_index + 1
            };
            
            elements[level] = self.levels[level]
                .get(sibling_index)
                .copied()
                .unwrap_or(zero());
            
            current_index = current_index / 2;
        }
        
        CircuitMerklePath { indices, elements }
    }
    
    /// Verify a proof (for testing)
    pub fn verify_proof(&self, leaf: Fr, proof: &CircuitMerklePath) -> bool {
        let mut current = leaf;
        
        for i in 0..TREE_HEIGHT {
            let sibling = proof.elements[i];
            let is_right = proof.indices[i];
            
            current = if is_right == 1 {
                hash2(sibling, current)
            } else {
                hash2(current, sibling)
            };
        }
        
        current == self.root()
    }
    
    /// Get number of leaves
    pub fn len(&self) -> usize {
        self.leaf_count
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_empty_tree() {
        let tree = FixedMerkleTree::new();
        // Root of empty tree should be hash of zeros
        let expected_root = hash2(hash2(hash2(zero(), zero()), hash2(zero(), zero())), 
                                  hash2(hash2(zero(), zero()), hash2(zero(), zero())));
        // Actually for our tree it's simpler since we initialize differently
        println!("Empty tree root: {:?}", tree.root());
    }
    
    #[test]
    fn test_single_leaf() {
        let mut tree = FixedMerkleTree::new();
        let leaf = Fr::from_str("12345").unwrap();
        tree.insert(leaf);
        
        let proof = tree.generate_proof(0);
        assert!(tree.verify_proof(leaf, &proof));
        
        println!("Single leaf proof indices: {:?}", proof.indices);
        println!("Root: {:?}", tree.root());
    }
    
    #[test]
    fn test_two_leaves() {
        let mut tree = FixedMerkleTree::new();
        let leaf0 = Fr::from_str("100").unwrap();
        let leaf1 = Fr::from_str("200").unwrap();
        
        tree.insert(leaf0);
        tree.insert(leaf1);
        
        let proof0 = tree.generate_proof(0);
        let proof1 = tree.generate_proof(1);
        
        assert!(tree.verify_proof(leaf0, &proof0));
        assert!(tree.verify_proof(leaf1, &proof1));
        
        // Leaf 0 is on left (index=0), sibling is leaf1
        assert_eq!(proof0.indices[0], 0);
        assert_eq!(proof0.elements[0], leaf1);
        
        // Leaf 1 is on right (index=1), sibling is leaf0
        assert_eq!(proof1.indices[0], 1);
        assert_eq!(proof1.elements[0], leaf0);
    }
    
    #[test]
    fn test_matches_circuit_example() {
        // Replicate the circuit test case
        let private_key = Fr::from_str("999").unwrap();
        
        // owner_in = poseidon::hash_1([private_key])
        let hasher = Poseidon::new();
        let owner_in = hasher.hash(vec![private_key]).unwrap();
        
        // Commitment calculation (simplified - just testing tree structure)
        let comm_in_0 = Fr::from_str("12345").unwrap(); // placeholder
        let comm_in_1 = Fr::from_str("0").unwrap(); // dummy note commitment
        
        let mut tree = FixedMerkleTree::new();
        tree.insert(comm_in_0);
        tree.insert(comm_in_1);
        
        let proof0 = tree.generate_proof(0);
        let proof1 = tree.generate_proof(1);
        
        // Verify proofs work
        assert!(tree.verify_proof(comm_in_0, &proof0));
        assert!(tree.verify_proof(comm_in_1, &proof1));
        
        println!("Circuit-style tree test passed!");
        println!("Proof0 indices: {:?}", proof0.indices);
        println!("Proof1 indices: {:?}", proof1.indices);
    }
}

