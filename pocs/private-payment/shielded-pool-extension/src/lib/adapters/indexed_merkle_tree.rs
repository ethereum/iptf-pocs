//! Off-chain indexed Merkle tree mirror.
//!
//! Maintains the leaves of an active or frozen nullifier tree, computes its
//! root, and generates the witnesses the circuits consume:
//! [`NonMembershipWitness`] (chain-update, over frozen trees) and
//! [`InsertionWitness`] (insertion circuit, over the active tree). The hashing
//! and witness shapes live in [`crate::domain::indexed_merkle`]; this is the
//! stateful container that produces them.
//!
//! Convention: index 0 is the genesis leaf `(0, 0, 0)`, which doubles as the
//! empty-slot value and the bootstrap low-leaf covering `[0, +inf)`. Real
//! nullifiers append at indices 1, 2, ..., so [`leaf_count`] starts at 1 and an
//! empty tree's root equals [`empty_root`].
//!
//! PoC note: `root()` and `merkle_path()` recompute the occupied levels on each
//! call (O(occupied) hashing); fine at PoC scale, not optimized for Visa-scale
//! epochs.
//!
//! [`leaf_count`]: IndexedMerkleTree::leaf_count
//! [`empty_root`]: IndexedMerkleTree::empty_root
//! [`NonMembershipWitness`]: crate::domain::indexed_merkle::NonMembershipWitness
//! [`InsertionWitness`]: crate::domain::indexed_merkle::InsertionWitness

use alloy::primitives::B256;

use crate::{
    crypto::poseidon::poseidon2,
    domain::indexed_merkle::{
        IndexedLeaf,
        InsertionWitness,
        NonMembershipWitness,
        NULLIFIER_TREE_DEPTH,
        covers,
        empty_leaf_hash,
    },
};

/// Errors from inserting into the off-chain tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum IndexedTreeError {
    #[error("value 0 is reserved for the empty/genesis leaf")]
    ReservedZeroValue,
    #[error("value already present in the tree")]
    DuplicateValue,
}

/// An off-chain indexed Merkle tree of fixed depth [`NULLIFIER_TREE_DEPTH`].
pub struct IndexedMerkleTree {
    /// Occupied leaves in index order (index 0 = genesis leaf).
    leaves: Vec<IndexedLeaf>,
    /// Zero-subtree hash per level: `zero_hashes[0]` = empty-leaf hash, and
    /// `zero_hashes[l+1] = poseidon2(zero_hashes[l], zero_hashes[l])`.
    zero_hashes: Vec<B256>,
}

impl Default for IndexedMerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

impl IndexedMerkleTree {
    /// A fresh tree holding only the genesis leaf at index 0.
    pub fn new() -> Self {
        let mut zero_hashes = Vec::with_capacity(NULLIFIER_TREE_DEPTH + 1);
        zero_hashes.push(empty_leaf_hash());
        for level in 0..NULLIFIER_TREE_DEPTH {
            let prev = zero_hashes[level];
            zero_hashes.push(poseidon2(prev, prev));
        }
        Self {
            leaves: vec![IndexedLeaf::EMPTY],
            zero_hashes,
        }
    }

    /// Number of occupied leaves (genesis + appended); also the next free index.
    pub fn leaf_count(&self) -> u64 {
        self.leaves.len() as u64
    }

    /// Root of a fully-empty tree (the on-chain `EMPTY_IMT_ROOT` constant).
    pub fn empty_root(&self) -> B256 {
        self.zero_hashes[NULLIFIER_TREE_DEPTH]
    }

    /// Current root.
    pub fn root(&self) -> B256 {
        self.levels().pop().expect("levels has DEPTH+1 entries")[0]
    }

    /// True if `value` is already present as a leaf.
    pub fn contains(&self, value: B256) -> bool {
        self.leaves.iter().any(|leaf| leaf.value == value)
    }

    /// Index of the low-leaf whose range strictly covers `value`, or `None` if
    /// `value` is already present (no leaf covers an existing value).
    pub fn low_leaf_index(&self, value: B256) -> Option<u64> {
        self.leaves
            .iter()
            .position(|leaf| covers(leaf, value))
            .map(|i| i as u64)
    }

    /// Sorted-low-leaf non-membership witness for `value` against the current
    /// root, or `None` if `value` is present.
    pub fn non_membership_witness(&self, value: B256) -> Option<NonMembershipWitness> {
        let low_leaf_index = self.low_leaf_index(value)?;
        Some(NonMembershipWitness {
            low_leaf: self.leaves[low_leaf_index as usize],
            low_leaf_index,
            siblings: self.merkle_path(low_leaf_index),
        })
    }

    /// Insert `value`, mutating the predecessor and appending the new leaf.
    /// Returns the [`InsertionWitness`] advancing the pre-root to the new root.
    pub fn insert(&mut self, value: B256) -> Result<InsertionWitness, IndexedTreeError> {
        if value == B256::ZERO {
            return Err(IndexedTreeError::ReservedZeroValue);
        }
        let low_leaf_index = self
            .low_leaf_index(value)
            .ok_or(IndexedTreeError::DuplicateValue)?;

        let low_leaf = self.leaves[low_leaf_index as usize];
        let new_leaf_index = self.leaves.len() as u64;

        // Predecessor path against the pre-state root.
        let low_leaf_siblings = self.merkle_path(low_leaf_index);

        // Mutate the predecessor to point at the new leaf (tree now at r').
        self.leaves[low_leaf_index as usize].next_value = value;
        self.leaves[low_leaf_index as usize].next_index = new_leaf_index;

        // Empty-slot path for the append index against r'.
        let new_leaf_siblings = self.merkle_path(new_leaf_index);

        // Write the new leaf, inheriting the predecessor's old forward pointer.
        self.leaves.push(IndexedLeaf {
            value,
            next_value: low_leaf.next_value,
            next_index: low_leaf.next_index,
        });

        Ok(InsertionWitness {
            low_leaf,
            low_leaf_index,
            low_leaf_siblings,
            new_leaf_index,
            new_leaf_siblings,
        })
    }

    /// Compute the occupied-prefix node hashes per level. `levels[0]` is the leaf
    /// hashes; `levels[NULLIFIER_TREE_DEPTH][0]` is the root.
    fn levels(&self) -> Vec<Vec<B256>> {
        let mut levels: Vec<Vec<B256>> = Vec::with_capacity(NULLIFIER_TREE_DEPTH + 1);
        levels.push(self.leaves.iter().map(IndexedLeaf::hash).collect());
        for level in 0..NULLIFIER_TREE_DEPTH {
            let current = &levels[level];
            let mut next = Vec::with_capacity(current.len().div_ceil(2));
            let mut i = 0;
            while i < current.len() {
                let left = current[i];
                let right = if i + 1 < current.len() {
                    current[i + 1]
                } else {
                    self.zero_hashes[level]
                };
                next.push(poseidon2(left, right));
                i += 2;
            }
            levels.push(next);
        }
        levels
    }

    /// Sibling path for `index` (length [`NULLIFIER_TREE_DEPTH`]). Siblings in the
    /// empty region of the tree come from `zero_hashes`.
    fn merkle_path(&self, index: u64) -> Vec<B256> {
        let levels = self.levels();
        let mut path = Vec::with_capacity(NULLIFIER_TREE_DEPTH);
        let mut idx = index as usize;
        for (level, nodes) in levels.iter().take(NULLIFIER_TREE_DEPTH).enumerate() {
            let sibling_idx = idx ^ 1;
            let sibling = nodes
                .get(sibling_idx)
                .copied()
                .unwrap_or(self.zero_hashes[level]);
            path.push(sibling);
            idx >>= 1;
        }
        path
    }
}

#[cfg(test)]
mod tests {
    use alloy::primitives::U256;

    use super::*;

    fn v(n: u64) -> B256 {
        B256::from(U256::from(n))
    }

    #[test]
    fn empty_tree_root_matches_empty_root() {
        let tree = IndexedMerkleTree::new();
        assert_eq!(tree.leaf_count(), 1, "genesis leaf occupies index 0");
        assert_eq!(tree.root(), tree.empty_root());
    }

    #[test]
    fn insertion_witness_reconstructs_new_root() {
        let mut tree = IndexedMerkleTree::new();
        // Insert out of order to exercise predecessor lookup.
        for value in [v(50), v(10), v(90), v(30)] {
            let pre_root = tree.root();
            let witness = tree.insert(value).unwrap();
            let post_root = tree.root();
            assert_eq!(
                witness.verify_and_apply(pre_root, value),
                Some(post_root),
                "insertion witness must advance pre_root to the tree's new root"
            );
        }
    }

    #[test]
    fn non_membership_witness_verifies_for_absent_values() {
        let mut tree = IndexedMerkleTree::new();
        for value in [v(10), v(20), v(30)] {
            tree.insert(value).unwrap();
        }
        let root = tree.root();

        // Absent value between existing leaves.
        let absent = v(25);
        let witness = tree.non_membership_witness(absent).unwrap();
        assert!(witness.verify(root, absent));

        // A present value has no non-membership witness.
        assert!(tree.non_membership_witness(v(20)).is_none());
        assert!(tree.contains(v(20)));
    }

    #[test]
    fn linked_list_stays_sorted() {
        let mut tree = IndexedMerkleTree::new();
        let inserted = [v(50), v(10), v(90), v(30), v(70)];
        for value in inserted {
            tree.insert(value).unwrap();
        }

        // Walk the linked list from the genesis leaf following next_index.
        let mut walk = Vec::new();
        let mut leaf = tree.leaves[0];
        while leaf.next_value != B256::ZERO {
            walk.push(leaf.next_value);
            leaf = tree.leaves[leaf.next_index as usize];
        }
        let mut expected: Vec<B256> = inserted.to_vec();
        expected.sort_by_key(|b| U256::from_be_bytes(b.0));
        assert_eq!(walk, expected, "values must be linked in ascending order");
    }

    #[test]
    fn deterministic_root_across_identical_sequences() {
        let mut a = IndexedMerkleTree::new();
        let mut b = IndexedMerkleTree::new();
        for value in [v(7), v(3), v(11)] {
            a.insert(value).unwrap();
            b.insert(value).unwrap();
        }
        assert_eq!(a.root(), b.root());
    }

    #[test]
    fn rejects_duplicate_and_zero() {
        let mut tree = IndexedMerkleTree::new();
        tree.insert(v(42)).unwrap();
        assert_eq!(tree.insert(v(42)), Err(IndexedTreeError::DuplicateValue));
        assert_eq!(
            tree.insert(B256::ZERO),
            Err(IndexedTreeError::ReservedZeroValue)
        );
    }
}
