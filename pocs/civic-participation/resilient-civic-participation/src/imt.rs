//! Depth-D sorted-linked-list IMT engine, parameterized by `IMT_DEPTH`.

use ark_bn254::Fr;

use crate::{
    IMT_DEPTH,
    error::ImtError,
    ports::imt::{
        ImtInsertWitness,
        ImtLeaf,
        ImtMembership,
        ImtNonMembership,
        ImtPath,
        ImtStore,
    },
    poseidon::{
        fr_from_be_bytes,
        fr_to_be_bytes,
        hash_merkle_node,
        poseidon4,
    },
    types::Bytes32,
};

/// Internal leaf as `Fr`; converted to `Bytes32` at the port boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct InternalLeaf {
    value: Fr,
    next_index: u32,
    next_value: Fr,
}

impl InternalLeaf {
    fn empty() -> Self {
        Self {
            value: Fr::from(0u64),
            next_index: 0,
            next_value: Fr::from(0u64),
        }
    }
    fn hash(&self) -> Fr {
        // Matches Noir `hash_imt_leaf`: width-5 over `(value, next_index, next_value, 0)`.
        poseidon4(
            self.value,
            Fr::from(self.next_index as u64),
            self.next_value,
            Fr::from(0u64),
        )
    }
    fn to_wire(self) -> ImtLeaf {
        ImtLeaf {
            value: fr_to_be_bytes(&self.value),
            next_index: self.next_index,
            next_value: fr_to_be_bytes(&self.next_value),
        }
    }
}

/// Depth-`IMT_DEPTH` IMT with a sparse `HashMap<u64, Fr>` per level.
#[derive(Clone)]
pub struct IndexedMerkleTree {
    leaves: Vec<InternalLeaf>,
    /// `tree[0]` is leaf hashes by index; `tree[D]` is the root.
    tree: Vec<std::collections::HashMap<u64, Fr>>,
    empty_subtree: [Fr; IMT_DEPTH + 1],
}

impl IndexedMerkleTree {
    /// Fresh tree with the empty low leaf `(0, 0, 0)` at index `0`.
    pub fn new() -> Self {
        let empty_subtree = compute_empty_subtree();
        let tree: Vec<std::collections::HashMap<u64, Fr>> = (0..=IMT_DEPTH)
            .map(|_| std::collections::HashMap::new())
            .collect();
        let mut t = Self {
            leaves: vec![InternalLeaf::empty()],
            tree,
            empty_subtree,
        };
        t.set_leaf_hash(0, InternalLeaf::empty().hash());
        t
    }

    fn set_leaf_hash(&mut self, i: u32, h: Fr) {
        self.tree[0].insert(i as u64, h);
        let mut idx: u64 = i as u64;
        for level in 0..IMT_DEPTH {
            let me = self.tree[level]
                .get(&idx)
                .copied()
                .unwrap_or(self.empty_subtree[level]);
            let sib = self.tree[level]
                .get(&(idx ^ 1))
                .copied()
                .unwrap_or(self.empty_subtree[level]);
            let (left, right) = if idx.is_multiple_of(2) {
                (me, sib)
            } else {
                (sib, me)
            };
            let parent_idx = idx / 2;
            let parent = hash_merkle_node(left, right);
            self.tree[level + 1].insert(parent_idx, parent);
            idx = parent_idx;
        }
    }

    pub fn root_fr(&self) -> Fr {
        self.tree[IMT_DEPTH]
            .get(&0)
            .copied()
            .unwrap_or(self.empty_subtree[IMT_DEPTH])
    }

    /// Merkle path for leaf index `i`.
    fn path_for(&self, i: u32) -> ImtPath {
        let mut siblings = Vec::with_capacity(IMT_DEPTH);
        let mut indices = Vec::with_capacity(IMT_DEPTH);
        let mut idx: u64 = i as u64;
        for level in 0..IMT_DEPTH {
            let sibling_idx = idx ^ 1;
            let sibling = self.tree[level]
                .get(&sibling_idx)
                .copied()
                .unwrap_or(self.empty_subtree[level]);
            siblings.push(fr_to_be_bytes(&sibling));
            indices.push((idx % 2) as u8);
            idx /= 2;
        }
        ImtPath { siblings, indices }
    }

    fn find_low_leaf_index(&self, target: Fr) -> Result<u32, ImtError> {
        // Linear scan; PoC scale only.
        let mut low_idx: Option<usize> = None;
        for (i, leaf) in self.leaves.iter().enumerate() {
            if leaf.value == target {
                return Err(ImtError::DuplicateInsertion);
            }
            let is_low = leaf.value < target
                && (leaf.next_value > target || leaf.next_value == Fr::from(0u64));
            if is_low {
                low_idx = Some(i);
            }
        }
        low_idx
            .map(|i| i as u32)
            .ok_or_else(|| ImtError::LowLeafInvariant("no low leaf found".into()))
    }
}

impl Default for IndexedMerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

impl ImtStore for IndexedMerkleTree {
    fn root(&self) -> Bytes32 {
        fr_to_be_bytes(&self.root_fr())
    }

    fn size(&self) -> usize {
        self.leaves.len()
    }

    fn membership(&self, value: &Bytes32) -> Option<ImtMembership> {
        let v = fr_from_be_bytes(value);
        for (i, leaf) in self.leaves.iter().enumerate() {
            if leaf.value == v {
                return Some(ImtMembership {
                    leaf: leaf.to_wire(),
                    leaf_index: i as u32,
                    path: self.path_for(i as u32),
                });
            }
        }
        None
    }

    fn non_membership(&self, value: &Bytes32) -> Option<ImtNonMembership> {
        let v = fr_from_be_bytes(value);
        let mut low: Option<(usize, InternalLeaf)> = None;
        for (i, leaf) in self.leaves.iter().enumerate() {
            if leaf.value == v {
                return None;
            }
            let is_low = leaf.value < v
                && (leaf.next_value > v || leaf.next_value == Fr::from(0u64));
            if is_low {
                low = Some((i, *leaf));
            }
        }
        low.map(|(i, leaf)| ImtNonMembership {
            low_leaf: leaf.to_wire(),
            low_leaf_index: i as u32,
            low_leaf_path: self.path_for(i as u32),
        })
    }

    fn insert(&mut self, value: &Bytes32) -> Result<ImtInsertWitness, ImtError> {
        let v = fr_from_be_bytes(value);

        let cap = 1usize << IMT_DEPTH;
        if self.leaves.len() >= cap {
            return Err(ImtError::CapacityExhausted(IMT_DEPTH));
        }

        let low_idx = self.find_low_leaf_index(v)?;
        let low_leaf_before = self.leaves[low_idx as usize];
        let new_index = self.leaves.len() as u32;

        let low_leaf_path_before = self.path_for(low_idx);

        let low_leaf_after = InternalLeaf {
            value: low_leaf_before.value,
            next_index: new_index,
            next_value: v,
        };
        let new_leaf = InternalLeaf {
            value: v,
            next_index: low_leaf_before.next_index,
            next_value: low_leaf_before.next_value,
        };

        self.leaves[low_idx as usize] = low_leaf_after;
        self.set_leaf_hash(low_idx, low_leaf_after.hash());
        self.leaves.push(new_leaf);
        self.set_leaf_hash(new_index, new_leaf.hash());

        let new_leaf_path = self.path_for(new_index);
        let new_root = self.root_fr();

        Ok(ImtInsertWitness {
            low_leaf_before: low_leaf_before.to_wire(),
            low_leaf_after: low_leaf_after.to_wire(),
            low_leaf_index: low_idx,
            low_leaf_path: low_leaf_path_before,
            new_leaf: new_leaf.to_wire(),
            new_leaf_index: new_index,
            new_leaf_path,
            new_root: fr_to_be_bytes(&new_root),
        })
    }
}

/// Precomputed `empty_subtree[i] = hash_subtree_of_height_i_of_zeros`.
fn compute_empty_subtree() -> [Fr; IMT_DEPTH + 1] {
    let mut levels = [Fr::from(0u64); IMT_DEPTH + 1];
    // Level 0 = `hash_4(0, 0, 0, 0)`, matching Noir `hash_imt_leaf`.
    levels[0] = poseidon4(
        Fr::from(0u64),
        Fr::from(0u64),
        Fr::from(0u64),
        Fr::from(0u64),
    );
    for i in 1..=IMT_DEPTH {
        levels[i] = hash_merkle_node(levels[i - 1], levels[i - 1]);
    }
    levels
}

#[cfg(test)]
mod tests {
    use super::*;

    fn be(n: u64) -> Bytes32 {
        let mut b = [0u8; 32];
        b[24..].copy_from_slice(&n.to_be_bytes());
        b
    }

    fn verify_path(leaf_hash: Fr, path: &ImtPath, expected_root: Fr) -> bool {
        let mut current = leaf_hash;
        for (sibling, &index) in path.siblings.iter().zip(path.indices.iter()) {
            let s = fr_from_be_bytes(sibling);
            current = if index == 0 {
                hash_merkle_node(current, s)
            } else {
                hash_merkle_node(s, current)
            };
        }
        current == expected_root
    }

    #[test]
    fn test_fresh_tree_has_root_with_empty_low_leaf() {
        let t = IndexedMerkleTree::new();
        let r1 = t.root_fr();
        let t2 = IndexedMerkleTree::new();
        let r2 = t2.root_fr();
        assert_eq!(r1, r2);
    }

    #[test]
    fn test_insert_advances_root_and_size() {
        let mut t = IndexedMerkleTree::new();
        let r0 = t.root_fr();
        let _ = t.insert(&be(100)).unwrap();
        assert_ne!(t.root_fr(), r0);
        assert_eq!(t.size(), 2); // empty + 100
    }

    #[test]
    fn test_insert_witness_root_matches_tree_root() {
        let mut t = IndexedMerkleTree::new();
        let w = t.insert(&be(42)).unwrap();
        assert_eq!(w.new_root, fr_to_be_bytes(&t.root_fr()));
    }

    #[test]
    fn test_duplicate_insertion_rejected() {
        let mut t = IndexedMerkleTree::new();
        let _ = t.insert(&be(10)).unwrap();
        let err = t.insert(&be(10));
        assert!(matches!(err, Err(ImtError::DuplicateInsertion)));
    }

    #[test]
    fn test_membership_returns_path_that_verifies() {
        let mut t = IndexedMerkleTree::new();
        let _ = t.insert(&be(7)).unwrap();
        let _ = t.insert(&be(3)).unwrap();
        let _ = t.insert(&be(11)).unwrap();
        let root = t.root_fr();
        let m = t.membership(&be(7)).unwrap();
        let leaf_fr = poseidon4(
            fr_from_be_bytes(&m.leaf.value),
            Fr::from(m.leaf.next_index as u64),
            fr_from_be_bytes(&m.leaf.next_value),
            Fr::from(0u64),
        );
        assert!(verify_path(leaf_fr, &m.path, root));
    }

    #[test]
    fn test_non_membership_returns_low_leaf_that_brackets() {
        let mut t = IndexedMerkleTree::new();
        let _ = t.insert(&be(10)).unwrap();
        let _ = t.insert(&be(30)).unwrap();
        let _ = t.insert(&be(50)).unwrap();
        let nm = t.non_membership(&be(20)).unwrap();
        assert_eq!(nm.low_leaf.value, be(10));
        assert_eq!(nm.low_leaf.next_value, be(30));
    }

    #[test]
    fn test_non_membership_returns_none_when_value_present() {
        let mut t = IndexedMerkleTree::new();
        let _ = t.insert(&be(10)).unwrap();
        assert!(t.non_membership(&be(10)).is_none());
    }

    #[test]
    fn test_membership_returns_none_when_absent() {
        let t = IndexedMerkleTree::new();
        assert!(t.membership(&be(99)).is_none());
    }

    #[test]
    fn test_in_order_inserts_keep_sorted_linked_list() {
        let mut t = IndexedMerkleTree::new();
        for v in [10u64, 20, 30, 40] {
            let _ = t.insert(&be(v)).unwrap();
        }
        let mut idx = 0u32;
        let mut last_value = Fr::from(0u64);
        let mut count = 0;
        loop {
            let leaf = t.leaves[idx as usize];
            if count > 0 {
                assert!(leaf.value > last_value);
                last_value = leaf.value;
            }
            if leaf.next_value == Fr::from(0u64) {
                break;
            }
            idx = leaf.next_index;
            count += 1;
            if count > 100 {
                panic!("linked list cycle");
            }
        }
    }

    #[test]
    fn test_out_of_order_inserts_still_sorted_via_low_leaf_updates() {
        let mut t = IndexedMerkleTree::new();
        for v in [30u64, 10, 50, 20, 40] {
            let _ = t.insert(&be(v)).unwrap();
        }
        let mut idx = 0u32;
        let mut last = Fr::from(0u64);
        let mut visited = 0;
        loop {
            let leaf = t.leaves[idx as usize];
            if visited > 0 {
                assert!(leaf.value > last, "values not ascending");
                last = leaf.value;
            }
            if leaf.next_value == Fr::from(0u64) {
                break;
            }
            idx = leaf.next_index;
            visited += 1;
            if visited > 100 {
                panic!("linked list cycle");
            }
        }
    }

    #[test]
    fn test_root_changes_with_each_insert() {
        let mut t = IndexedMerkleTree::new();
        let mut last = t.root_fr();
        for v in [10u64, 20, 30] {
            let _ = t.insert(&be(v)).unwrap();
            let r = t.root_fr();
            assert_ne!(r, last);
            last = r;
        }
    }

    #[test]
    fn test_insert_witness_satisfies_noir_constraints() {
        // Confirm the Rust witness fields satisfy the new Noir IMT constraints:
        // - low_leaf_index decomposes to low_leaf_path.indices (24 LSB bits)
        // - new_leaf_index decomposes to new_leaf_path.indices (24 LSB bits)
        // - low_leaf_after.next_index == new_leaf_index
        // - low_leaf_index != new_leaf_index (no collision)
        // - new_leaf_index == prior_leaf_count + 1 (sentinel at index 0)
        let mut t = IndexedMerkleTree::new();
        let prior_size = t.size();
        let w = t.insert(&be(100)).unwrap();

        // Aztec sentinel + 1 real insert = new_leaf_index = 1.
        assert_eq!(w.new_leaf_index, prior_size as u32);
        assert_eq!(w.low_leaf_after.next_index, w.new_leaf_index);
        assert_ne!(w.low_leaf_index, w.new_leaf_index);

        // Bit decomposition of low_leaf_index == low_leaf_path.indices
        let mut x = w.low_leaf_index as u64;
        for k in 0..IMT_DEPTH {
            assert_eq!(w.low_leaf_path.indices[k] as u64, x & 1, "low bit {k}");
            x >>= 1;
        }
        // Bit decomposition of new_leaf_index == new_leaf_path.indices
        let mut x = w.new_leaf_index as u64;
        for k in 0..IMT_DEPTH {
            assert_eq!(w.new_leaf_path.indices[k] as u64, x & 1, "new bit {k}");
            x >>= 1;
        }
    }

    #[test]
    fn test_imt_size_includes_sentinel() {
        // The sentinel empty leaf at index 0 counts in size(); the Noir
        // verify_insert uses absolute index = prior_leaf_count + 1 to
        // account for this.
        let t = IndexedMerkleTree::new();
        assert_eq!(t.size(), 1);
    }
}
