use thiserror::Error;

use crate::error::PredicateError;

#[derive(Debug, Error)]
pub enum OrganizerError {
    #[error("class_set has {0} entries; bound is 1..={1}")]
    ClassSetSize(usize, usize),
    #[error("class_thresholds.len() ({thresholds}) != class_set.len() ({class_set})")]
    ThresholdLenMismatch { thresholds: usize, class_set: usize },
    #[error("class_index {0} not in class_set")]
    ClassIndexOutOfRange(u8),
    #[error("class_set must be strictly increasing")]
    ClassSetNotSorted,
    #[error("predicate: {0}")]
    Predicate(#[from] PredicateError),
    #[error("close_at_block is in the past relative to registration_block")]
    CloseInPast,
    #[error("signing window exceeds the SPEC limit of 11.5 days")]
    SigningWindowTooLong,
}
