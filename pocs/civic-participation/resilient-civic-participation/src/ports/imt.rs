//! Indexed Merkle Tree port (Aztec-style, depth 24).

use serde::{
    Deserialize,
    Serialize,
};

use crate::{
    error::ImtError,
    types::Bytes32,
};

/// Sorted-linked-list IMT entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImtLeaf {
    pub value: Bytes32,
    pub next_index: u32,
    pub next_value: Bytes32,
}

impl ImtLeaf {
    pub const ZERO: Self = Self {
        value: [0u8; 32],
        next_index: 0,
        next_value: [0u8; 32],
    };
    pub fn is_zero(&self) -> bool {
        *self == Self::ZERO
    }
}

/// Merkle path (siblings + indices) for an IMT leaf hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImtPath {
    pub siblings: Vec<Bytes32>,
    pub indices: Vec<u8>,
}

/// Membership witness for a leaf.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImtMembership {
    pub leaf: ImtLeaf,
    pub leaf_index: u32,
    pub path: ImtPath,
}

/// Non-membership witness via the bracketing low leaf.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImtNonMembership {
    pub low_leaf: ImtLeaf,
    pub low_leaf_index: u32,
    pub low_leaf_path: ImtPath,
}

/// IMT insertion witness consumed by batch SNARK constraint 6.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImtInsertWitness {
    pub low_leaf_before: ImtLeaf,
    pub low_leaf_after: ImtLeaf,
    pub low_leaf_index: u32,
    pub low_leaf_path: ImtPath,
    pub new_leaf: ImtLeaf,
    pub new_leaf_index: u32,
    pub new_leaf_path: ImtPath,
    /// Root after inserting `new_leaf` and rewriting the low leaf.
    pub new_root: Bytes32,
}

pub trait ImtStore: Send + Sync {
    /// Current root (BE 32 bytes); `[0u8; 32]` means uninitialized.
    fn root(&self) -> Bytes32;

    /// Inserted-value count (low-leaf + appended leaves).
    fn size(&self) -> usize;

    /// Membership witness if `value` is present.
    fn membership(&self, value: &Bytes32) -> Option<ImtMembership>;

    /// Non-membership witness for `value`; `None` if present.
    fn non_membership(&self, value: &Bytes32) -> Option<ImtNonMembership>;

    /// Insert `value`; errors on duplicates and capacity exhaustion.
    fn insert(&mut self, value: &Bytes32) -> Result<ImtInsertWitness, ImtError>;
}
