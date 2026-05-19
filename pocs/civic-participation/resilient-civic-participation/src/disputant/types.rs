//! Disputant types.

use serde::{
    Deserialize,
    Serialize,
};

use crate::types::{
    Bytes32,
    PetitionId,
};

/// Context gathered before building a dispute.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisputeContext {
    pub petition_id: PetitionId,
    pub batch_versioned_hash: Bytes32,
    pub batch_index: u32,
    pub class_set: Vec<u16>,
}
