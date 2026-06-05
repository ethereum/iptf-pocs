//! Indexed Merkle tree primitives (sorted-low-leaf pattern).
//!
//! Used for the active and frozen nullifier trees. Leaves are sorted by value
//! and each carries a `(next_value, next_index)` pointer to the next-larger
//! leaf, forming a linked list in value order. This supports two operations:
//!
//! - **Sorted-low-leaf non-membership**: a value `η` is absent iff there is a
//!   `low_leaf` with `low_leaf.value < η < low_leaf.next_value`. Used by the
//!   chain-update circuit over frozen trees.
//! - **Insertion**: inserting `η` mutates the predecessor (its pointers repoint
//!   to `η`) and writes a new leaf at the next free slot. A valid sorted-low-leaf
//!   insertion is itself a non-membership proof of `η` in the prior tree. Used by
//!   the insertion circuit over the active tree.
//!
//! This module holds the pure types, hashing, and the witness-verification logic
//! that the circuits mirror; [`crate::adapters::indexed_merkle_tree`] holds the
//! stateful tree that generates the witnesses. The `next_value == 0` sentinel
//! denotes "+infinity" (the current largest leaf); real nullifiers are Poseidon
//! outputs and are never 0.

use alloy::primitives::{
    B256,
    U256,
};
use serde::{
    Deserialize,
    Serialize,
};

use crate::crypto::poseidon::{
    poseidon2,
    poseidon3,
};

/// Tree depth (PoC parameter; capacity `2^DEPTH` leaves per tree). Path length
/// in the circuits equals this, so it MUST match the in-circuit constant.
pub const NULLIFIER_TREE_DEPTH: usize = 32;

/// A leaf of the indexed Merkle tree.
///
/// `leaf_hash = poseidon3(value, next_value, next_index)`. The all-zero leaf
/// `(0, 0, 0)` is both the empty-slot value and the genesis low-leaf covering
/// the range `[0, +inf)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexedLeaf {
    pub value: B256,
    pub next_value: B256,
    pub next_index: u64,
}

impl IndexedLeaf {
    /// The empty / genesis leaf `(0, 0, 0)`.
    pub const EMPTY: IndexedLeaf = IndexedLeaf {
        value: B256::ZERO,
        next_value: B256::ZERO,
        next_index: 0,
    };

    /// `poseidon3(value, next_value, next_index)`.
    pub fn hash(&self) -> B256 {
        poseidon3(self.value, self.next_value, index_to_field(self.next_index))
    }
}

/// Hash of the empty leaf; also the hash stored in every unwritten slot.
pub fn empty_leaf_hash() -> B256 {
    IndexedLeaf::EMPTY.hash()
}

/// Encode a leaf index as a field element (matches the Noir `index as Field`).
pub fn index_to_field(index: u64) -> B256 {
    B256::from(U256::from(index))
}

fn as_uint(value: B256) -> U256 {
    U256::from_be_bytes(value.0)
}

/// True if `query` falls strictly inside the range covered by `low`:
/// `low.value < query < low.next_value`, with `next_value == 0` meaning +inf.
pub fn covers(low: &IndexedLeaf, query: B256) -> bool {
    let lo = as_uint(low.value);
    let q = as_uint(query);
    let hi = as_uint(low.next_value);
    lo < q && (low.next_value == B256::ZERO || q < hi)
}

/// Recompute the root implied by a leaf at `index` with the given sibling path.
/// `siblings[level]` is the sibling hash at that level; the path bit is the
/// `level`-th bit of `index` (0 = current node is the left child).
pub fn root_from_path(leaf_hash: B256, index: u64, siblings: &[B256]) -> B256 {
    let mut node = leaf_hash;
    let mut idx = index;
    for sibling in siblings {
        node = if idx & 1 == 0 {
            poseidon2(node, *sibling)
        } else {
            poseidon2(*sibling, node)
        };
        idx >>= 1;
    }
    node
}

/// Verify that `leaf_hash` sits at `index` under `root` via `siblings`.
pub fn verify_inclusion(root: B256, leaf_hash: B256, index: u64, siblings: &[B256]) -> bool {
    root_from_path(leaf_hash, index, siblings) == root
}

/// Sorted-low-leaf non-membership witness for the chain-update circuit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NonMembershipWitness {
    pub low_leaf: IndexedLeaf,
    pub low_leaf_index: u64,
    /// Sibling path of `low_leaf` (length `NULLIFIER_TREE_DEPTH`).
    pub siblings: Vec<B256>,
}

impl NonMembershipWitness {
    /// Verify `query` is absent under `root`: the low-leaf is included and its
    /// range strictly covers `query`.
    pub fn verify(&self, root: B256, query: B256) -> bool {
        verify_inclusion(root, self.low_leaf.hash(), self.low_leaf_index, &self.siblings)
            && covers(&self.low_leaf, query)
    }
}

/// Insertion witness for the insertion circuit: one sorted-low-leaf insertion of
/// `value` advancing the root from a pre-state to a post-state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InsertionWitness {
    /// Predecessor leaf as it stands in the pre-state tree.
    pub low_leaf: IndexedLeaf,
    pub low_leaf_index: u64,
    /// Sibling path of `low_leaf` against the pre-state root.
    pub low_leaf_siblings: Vec<B256>,
    /// Canonical append index for the new leaf (`pre_leaf_count + i - 1`).
    pub new_leaf_index: u64,
    /// Sibling path of the (empty) append slot against the intermediate root
    /// `r'` produced after the predecessor mutation.
    pub new_leaf_siblings: Vec<B256>,
}

impl InsertionWitness {
    /// Replay the insertion of `value` from `pre_root`, returning the post-root,
    /// or `None` if any check fails. Mirrors the insertion circuit exactly:
    ///
    /// 1. predecessor membership + `low_leaf.value < value < low_leaf.next_value`
    /// 2. mutate predecessor `(value, value→next_value, next_index→new_index)` → `r'`
    /// 3. the append slot holds the empty leaf in `r'`
    /// 4. write the new leaf `(value, low.next_value, low.next_index)` → post-root
    pub fn verify_and_apply(&self, pre_root: B256, value: B256) -> Option<B256> {
        // 1. Predecessor membership and non-membership of `value`.
        if !verify_inclusion(
            pre_root,
            self.low_leaf.hash(),
            self.low_leaf_index,
            &self.low_leaf_siblings,
        ) {
            return None;
        }
        if !covers(&self.low_leaf, value) {
            return None;
        }

        // 2. Mutate predecessor to point at the new leaf; recompute r'.
        let updated_low = IndexedLeaf {
            value: self.low_leaf.value,
            next_value: value,
            next_index: self.new_leaf_index,
        };
        let r_prime = root_from_path(
            updated_low.hash(),
            self.low_leaf_index,
            &self.low_leaf_siblings,
        );

        // 3. The append slot must be empty in r'.
        if !verify_inclusion(
            r_prime,
            empty_leaf_hash(),
            self.new_leaf_index,
            &self.new_leaf_siblings,
        ) {
            return None;
        }

        // 4. Write the new leaf, inheriting the predecessor's old forward pointer.
        let new_leaf = IndexedLeaf {
            value,
            next_value: self.low_leaf.next_value,
            next_index: self.low_leaf.next_index,
        };
        Some(root_from_path(
            new_leaf.hash(),
            self.new_leaf_index,
            &self.new_leaf_siblings,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_leaf_is_zero_triple() {
        assert_eq!(IndexedLeaf::EMPTY.value, B256::ZERO);
        assert_eq!(IndexedLeaf::EMPTY.next_value, B256::ZERO);
        assert_eq!(IndexedLeaf::EMPTY.next_index, 0);
    }

    #[test]
    fn covers_uses_infinity_sentinel() {
        let genesis = IndexedLeaf::EMPTY; // (0, 0=inf, 0)
        let v = B256::from(U256::from(42u64));
        assert!(covers(&genesis, v)); // 0 < 42 < inf
        assert!(!covers(&genesis, B256::ZERO)); // 0 < 0 is false

        let mid = IndexedLeaf {
            value: B256::from(U256::from(10u64)),
            next_value: B256::from(U256::from(20u64)),
            next_index: 5,
        };
        assert!(covers(&mid, B256::from(U256::from(15u64))));
        assert!(!covers(&mid, B256::from(U256::from(20u64)))); // not strict at upper
        assert!(!covers(&mid, B256::from(U256::from(10u64)))); // not strict at lower
        assert!(!covers(&mid, B256::from(U256::from(25u64)))); // above range
    }

    #[test]
    fn inclusion_roundtrips() {
        let leaf = IndexedLeaf {
            value: B256::from(U256::from(7u64)),
            next_value: B256::ZERO,
            next_index: 0,
        };
        let siblings = vec![B256::ZERO; NULLIFIER_TREE_DEPTH];
        let root = root_from_path(leaf.hash(), 3, &siblings);
        assert!(verify_inclusion(root, leaf.hash(), 3, &siblings));
        assert!(!verify_inclusion(root, leaf.hash(), 2, &siblings));
    }
}
