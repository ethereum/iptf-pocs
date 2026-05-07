//! Registry-side types.

use serde::{
    Deserialize,
    Serialize,
};

use crate::types::{
    Bytes32,
    SecpPubkey,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CardStatus {
    Active,
    Revoked,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CardRecord {
    pub card_id: Bytes32,
    pub m: SecpPubkey,
    pub status: CardStatus,
    pub cohort_position: u64,
}

/// Operator-printed bundle handed to recipients at personalization. The
/// companion device persists `cohort_position` per active enrollment so it
/// can index the cohort tree at claim time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalizationPacket {
    pub card_id: Bytes32,
    pub m: SecpPubkey,
    pub cohort_position: u64,
    pub cohort_version: u64,
}
