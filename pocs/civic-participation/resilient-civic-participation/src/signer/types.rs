//! Signer-specific types: enrollment artifact and per-petition view.

use serde::{
    Deserialize,
    Serialize,
};

use crate::types::{
    Bytes32,
    ClassTag,
    PetitionId,
};

/// Enrollment artifact handed to the RI credential layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollmentArtifact {
    pub attr_hash: Bytes32,
    pub chain_root: Bytes32,
    pub attr_version: u32,
}

/// Per-petition view the signer consumes.
#[derive(Debug, Clone)]
pub struct PetitionMeta {
    pub petition_id: PetitionId,
    pub r_root: Bytes32,
    pub predicate_hash: Bytes32,
    pub slot: u32,
    pub class_index: u8,
    pub class_tag: ClassTag,
    pub predicate_def: crate::predicate::PredicateDef,
    pub salt: Bytes32,
    pub ri_leaf_index: u32,
}
