use thiserror::Error;

use crate::{
    crypto::aead::AeadError,
    error::{
        PoolError,
        ProofError,
    },
};

#[derive(Debug, Error)]
pub enum RelayError {
    #[error("AEAD failure: {0}")]
    AeadFailure(#[from] AeadError),
    #[error("malformed voucher: {0}")]
    BadVoucherFormat(String),
    #[error("proof generation: {0}")]
    ProofGeneration(#[from] ProofError),
    #[error("pool failure: {0}")]
    Pool(#[from] PoolError),
    #[error("commitment not found in pool sub-tree")]
    CommitmentNotFound,
}
