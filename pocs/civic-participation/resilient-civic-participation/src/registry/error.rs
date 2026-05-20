use thiserror::Error;

use crate::error::{
    BlobError,
    ImtError,
    PredicateError,
    ProofError,
};

/// Boxed payload for [`RegistryError::BatchPriorMismatch`]; keeps the enum small.
#[derive(Debug)]
pub struct BatchPriorMismatch {
    pub expected_rr: [u8; 32],
    pub expected_idt: [u8; 32],
    pub expected_lc: u64,
    pub got_rr: [u8; 32],
    pub got_idt: [u8; 32],
    pub got_lc: u64,
}

impl std::fmt::Display for BatchPriorMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "expected running_root={:?}, identity_tag_set_root={:?}, leaf_count={}; got running_root={:?}, identity_tag_set_root={:?}, leaf_count={}",
            self.expected_rr,
            self.expected_idt,
            self.expected_lc,
            self.got_rr,
            self.got_idt,
            self.got_lc,
        )
    }
}

#[derive(Debug, Error)]
pub enum RegistryError {
    #[error("petition with the same petition_id already registered")]
    DuplicatePetition,
    #[error("petition not found")]
    UnknownPetition,
    #[error("petition state {0:?} disallows operation `{1}`")]
    BadState(crate::types::PetitionState, &'static str),
    #[error("R has not been published on RI for the SPEC-required minimum age")]
    RRootTooYoung,
    #[error("alpha {alpha} outside governance bounds [{min}, {max}]")]
    AlphaOutOfBounds { alpha: u64, min: u64, max: u64 },
    #[error("bounty {bounty} below required minimum {min}")]
    BountyBelowMinimum { bounty: u128, min: u128 },
    #[error("petition runs out of FSRT slots: S = {0}")]
    SlotCounterExhausted(u32),
    #[error("predicate: {0}")]
    Predicate(#[from] PredicateError),
    #[error("batch SNARK verification failed: {0}")]
    BadBatchProof(ProofError),
    #[error("batch prior-state mismatch: {0}")]
    BatchPriorMismatch(Box<BatchPriorMismatch>),
    #[error("batch size {0} outside [1, BATCH_SIZE_MAX]")]
    BatchSizeOutOfRange(usize),
    #[error("resolution SNARK verification failed: {0}")]
    BadResolutionProof(ProofError),
    #[error("resolution public inputs disagree with registry state")]
    ResolutionStateMismatch,
    #[error("dispute opening invalid: {0}")]
    BadDisputeOpening(BlobError),
    #[error("dispute violation predicate did not hold against the supplied evidence")]
    DisputePredicateNotMet,
    #[error("dispute references unknown batch_index {0}")]
    DisputeUnknownBatch(u32),
    #[error("dispute references already-repudiated batch_index {0}")]
    DisputeBatchAlreadyRepudiated(u32),
    #[error("imt error: {0}")]
    Imt(#[from] ImtError),
    #[error("blob error: {0}")]
    Blob(#[from] BlobError),
}
