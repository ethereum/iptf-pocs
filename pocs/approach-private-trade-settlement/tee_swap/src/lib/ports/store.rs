use alloy::primitives::B256;
use std::future::Future;

use crate::domain::swap::PartySubmission;

/// Port for buffering the first party submission while awaiting the counterparty.
///
/// The store only holds **pending** submissions (one side arrived, waiting for the other).
/// Once both submissions are present, the caller retrieves and removes the entry.
/// Replay protection for completed swaps is handled on-chain (`require(!revealed)`),
/// not by the store.
///
/// Implementations:
/// - `InMemorySwapStore` (for PoC/testing)
pub trait SwapStore: Send + Sync {
    /// Buffer a submission. Returns the pending counterparty submission if one
    /// was already waiting for this `swap_id`, consuming both from the store.
    /// Returns `None` if this is the first submission for this swap.
    fn submit(
        &self,
        submission: PartySubmission,
    ) -> impl Future<Output = Result<Option<PartySubmission>, StoreError>> + Send;

    /// Remove a pending submission (e.g., on timeout or cancellation).
    fn remove(
        &self,
        swap_id: B256,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Check whether a pending submission exists for this swap_id.
    fn has_pending(
        &self,
        swap_id: B256,
    ) -> impl Future<Output = Result<bool, StoreError>> + Send;
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("swap already has both submissions")]
    DuplicateSubmission,

    #[error("no pending submission for swap: {0}")]
    SwapNotFound(B256),

    #[error("internal store error: {0}")]
    Internal(String),
}
