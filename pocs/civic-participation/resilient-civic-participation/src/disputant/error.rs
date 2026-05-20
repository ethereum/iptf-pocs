use thiserror::Error;

use crate::error::BlobError;

#[derive(Debug, Error)]
pub enum DisputantError {
    #[error("violation predicate did not hold against the supplied records")]
    PredicateNotViolated,
    #[error("blob: {0}")]
    Blob(#[from] BlobError),
}
