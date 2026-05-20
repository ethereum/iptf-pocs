//! Organizer-side types.

use serde::{
    Deserialize,
    Serialize,
};

use crate::{
    predicate::PredicateDef,
    types::{
        Address,
        Bytes32,
        ClassTag,
        U256Be,
    },
};

/// SPEC Petition Registration `register(petition_data, B)` args.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PetitionDraft {
    pub organizer: Address,
    pub r_root: Bytes32,
    pub predicate_def: PredicateDef,
    pub salt: Bytes32,
    pub class_set: Vec<ClassTag>,
    pub class_thresholds: Vec<u64>,
    pub class_index: u8,
    pub close_at_block: u64,
    pub bounty: U256Be,
}
