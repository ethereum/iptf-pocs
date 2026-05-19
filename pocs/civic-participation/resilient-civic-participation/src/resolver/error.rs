use thiserror::Error;

use crate::error::{
    BlobError,
    ImtError,
    ProofError,
};

#[derive(Debug, Error)]
pub enum ResolverError {
    #[error("petition state does not allow resolution")]
    BadState,
    #[error("no active batches recorded; nothing to reconstruct")]
    NoBatches,
    #[error("reconstructed leaf count {0} disagrees with on-chain leaf_count {1}")]
    LeafCountMismatch(u64, u64),
    #[error("reconstructed running_root disagrees with on-chain running_root")]
    RootMismatch,
    #[error("reconstructed leaves are not strictly sorted at position {0}")]
    LeafOrderingFailure(usize),
    #[error("blob: {0}")]
    Blob(#[from] BlobError),
    #[error("imt: {0}")]
    Imt(#[from] ImtError),
    #[error("proof: {0}")]
    Proof(#[from] ProofError),
}
