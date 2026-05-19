use thiserror::Error;

use crate::error::{
    BlobError,
    ImtError,
    ProofError,
};

#[derive(Debug, Error)]
pub enum RelayerError {
    #[error("batch is empty")]
    EmptyBatch,
    #[error("batch size {0} exceeds BATCH_SIZE_MAX {1}")]
    BatchSizeExceeded(usize, usize),
    #[error("intra-batch duplicate nullifier at positions {0} and {1}")]
    DuplicateNullifier(usize, usize),
    #[error("intra-batch duplicate identity_tag at positions {0} and {1}")]
    DuplicateIdentityTag(usize, usize),
    #[error("signer SNARK verification failed at position {0}: {1}")]
    SignerProofInvalid(usize, ProofError),
    #[error("class_tag {0} at position {1} is not in petition's class_set")]
    ClassTagOutOfSet(u16, usize),
    #[error("petition_id mismatch at position {0}")]
    PetitionIdMismatch(usize),
    #[error("relayer local state diverges from petition view")]
    StateDiverged,
    #[error("leaf_count overflow")]
    LeafCountOverflow,
    #[error("blob: {0}")]
    Blob(#[from] BlobError),
    #[error("imt: {0}")]
    Imt(#[from] ImtError),
    #[error("proof: {0}")]
    Proof(#[from] ProofError),
}
