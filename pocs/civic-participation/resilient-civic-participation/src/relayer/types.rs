//! Relayer types.

use serde::{
    Deserialize,
    Serialize,
};

use crate::{
    ports::imt::ImtInsertWitness,
    types::{
        Bytes32,
        ClassTag,
        PetitionId,
        SignerSubmission,
    },
};

/// Registry-supplied petition coordinates used to build a batch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PetitionView {
    pub petition_id: PetitionId,
    pub r_root: Bytes32,
    pub predicate_hash: Bytes32,
    pub class_index: u8,
    pub class_set: Vec<ClassTag>,
    pub slot: u32,
    pub running_root: Bytes32,
    pub identity_tag_set_root: Bytes32,
    pub leaf_count: u64,
    /// Deploy-pinned signer VK hash; the batch SNARK must commit to
    /// this value as a public input.
    pub signer_vk_hash: Bytes32,
}

/// Per-position state the batch witness consumes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchPosition {
    pub submission: SignerSubmission,
    pub leaf_insert: ImtInsertWitness,
    pub identity_tag_insert: ImtInsertWitness,
}
