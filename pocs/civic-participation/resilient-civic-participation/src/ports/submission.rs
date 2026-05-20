//! Signer-to-relayer submission seam (in-process adapter ships with the PoC).

use thiserror::Error;

use crate::types::SignerSubmission;

#[derive(Debug, Error)]
pub enum SubmissionError {
    #[error("relay not in roster")]
    UnknownRelay,
    #[error("relay rejected submission: {0}")]
    Rejected(String),
}

pub trait RelaySubmission: Send + Sync {
    /// Push a submission addressed to `relay_id`.
    fn submit(
        &self,
        relay_id: &[u8; 32],
        submission: SignerSubmission,
    ) -> Result<(), SubmissionError>;
}
