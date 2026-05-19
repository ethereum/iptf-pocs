use thiserror::Error;

use crate::error::ProofError;

#[derive(Debug, Error)]
pub enum SignerError {
    #[error("FSRT slot {slot} below current ratchet head {head}")]
    SlotInPast { slot: u32, head: u32 },
    #[error("FSRT slot {slot} exceeds chain length {chain_len}")]
    SlotOutOfRange { slot: u32, chain_len: u32 },
    #[error("RI lookup failed: {0}")]
    RiLookup(String),
    #[error("predicate failure: {0}")]
    Predicate(#[from] crate::error::PredicateError),
    #[error("proof: {0}")]
    Proof(#[from] ProofError),
    #[error("merkle: {0}")]
    Merkle(#[from] crate::error::MerkleError),
    #[error("invariant violated: {0}")]
    Invariant(String),
}
