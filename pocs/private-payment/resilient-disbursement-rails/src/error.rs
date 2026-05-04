//! Shared error types. Per-actor errors live in their own modules and may
//! wrap these.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProofError {
    #[error("proof generation failed: {0}")]
    Generation(String),
    #[error("witness serialization failed: {0}")]
    WitnessSerialization(String),
}

#[derive(Debug, Error)]
pub enum PoolError {
    #[error("pool RPC failure: {0}")]
    Rpc(String),
}

#[derive(Debug, Error)]
pub enum MerkleError {
    #[error("leaf index {0} out of range (size {1})")]
    OutOfRange(usize, usize),
    #[error("empty tree has no proof")]
    EmptyTree,
    #[error("merkle proof construction failed: {0}")]
    ProofFailure(String),
}

#[derive(Debug, Error)]
pub enum CardError {
    #[error("auth token mismatch")]
    AuthTokenMismatch,
    #[error("malformed APDU")]
    BadApdu,
    #[error("pre-hashed H_msg refused; card constructs the preimage internally")]
    PreHashedHMsgRefused,
    #[error("master key not yet generated; send GENERATE_KEY first")]
    KeyNotGenerated,
    #[error("voucher context fields disagree with the bound round header")]
    CtxHeaderMismatch,
    #[error("signature failed: {0}")]
    SignFailure(String),
}
