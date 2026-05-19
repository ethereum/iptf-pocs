//! Resolver types.

use serde::{
    Deserialize,
    Serialize,
};

use crate::types::{
    Bytes32,
    ClassTag,
    PetitionId,
};

/// Registry handle used by the resolver to reconstruct the leaf set.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolverView {
    pub petition_id: PetitionId,
    pub r_root: Bytes32,
    pub predicate_hash: Bytes32,
    pub running_root: Bytes32,
    pub leaf_count: u64,
    pub class_set: Vec<ClassTag>,
    pub class_thresholds: Vec<u64>,
    pub class_index: u8,
    /// `batch_versioned_hash` per active batch, in batch_index order.
    pub active_batch_versioned_hashes: Vec<Bytes32>,
}
