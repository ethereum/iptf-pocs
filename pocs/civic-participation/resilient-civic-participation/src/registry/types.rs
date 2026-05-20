//! Registry types.

use serde::{
    Deserialize,
    Serialize,
};

use crate::types::{
    Address,
    Bytes32,
    ClassTag,
    PetitionId,
};

/// Tombstone written into `running_root` when the petition becomes `Unresolved`.
pub const TOMBSTONE_MARKER: Bytes32 = {
    let mut b = [0u8; 32];
    b[31] = 1;
    b
};

/// Result of `Registry::register`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisteredPetition {
    pub petition_id: PetitionId,
    pub slot: u32,
    pub predicate_hash: Bytes32,
    pub registered_at_block: u64,
}

/// Event emitted by `register`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PetitionRegisteredEvent {
    pub petition_id: PetitionId,
    pub slot: u32,
    pub r_root: Bytes32,
    pub predicate_hash: Bytes32,
    pub class_set: Vec<ClassTag>,
    pub class_thresholds: Vec<u64>,
    pub class_index: u8,
    pub close_at_block: u64,
    pub bounty: u128,
}

/// Emitted by `publish_batch`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchPublishedEvent {
    pub petition_id: PetitionId,
    pub batch_index: u32,
    pub batch_versioned_hash: Bytes32,
    pub new_running_root: Bytes32,
    pub new_identity_tag_set_root: Bytes32,
    pub new_leaf_count: u64,
}

/// Emitted by `dispute`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchRepudiatedEvent {
    pub petition_id: PetitionId,
    pub batch_index: u32,
    pub new_running_root: Bytes32,
    pub new_identity_tag_set_root: Bytes32,
    pub new_leaf_count: u64,
}

/// Emitted by `resolve`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PetitionResolvedEvent {
    pub petition_id: PetitionId,
    pub b: bool,
    pub b_per_class: Vec<bool>,
}

/// Emitted by `mark_unresolved`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PetitionUnresolvedEvent {
    pub petition_id: PetitionId,
}

/// `BountyPaid` event paid to the winning resolver.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BountyPaidEvent {
    pub petition_id: PetitionId,
    pub recipient: Address,
    pub amount: u128,
}

/// `BountyRefunded` event for organizer refund and caller gas rebate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BountyRefundedEvent {
    pub petition_id: PetitionId,
    pub recipient: Address,
    pub amount: u128,
}

/// `AlphaUpdated` event emitted by `update_alpha`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlphaUpdatedEvent {
    pub old_alpha: u64,
    pub new_alpha: u64,
}

/// Petition state snapshot for Relayer, Resolver, and Disputant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PetitionStateView {
    pub petition_id: PetitionId,
    pub r_root: Bytes32,
    pub predicate_hash: Bytes32,
    pub class_set: Vec<ClassTag>,
    pub class_thresholds: Vec<u64>,
    pub class_index: u8,
    pub slot: u32,
    pub running_root: Bytes32,
    pub identity_tag_set_root: Bytes32,
    pub leaf_count: u64,
    pub next_batch_index: u32,
}
