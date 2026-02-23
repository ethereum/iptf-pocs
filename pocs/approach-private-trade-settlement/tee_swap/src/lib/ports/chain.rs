use alloy::primitives::B256;
use std::future::Future;

use super::{SwapLockData, TransferPublicInputs, TxReceipt};
use crate::domain::swap::SwapAnnouncement;

/// Port for interacting with a blockchain (one instance per chain).
///
/// Implementations:
/// - `EthereumChainClient` (alloy, future)
/// - Mock implementation for testing
pub trait ChainPort: Send + Sync {
    /// Read on-chain lock data for a commitment (from `SwapNoteLocked` event).
    fn get_swap_lock_data(
        &self,
        commitment: B256,
    ) -> impl Future<Output = Result<SwapLockData, ChainError>> + Send;

    /// Insert a commitment without proof (PoC funding only).
    fn fund(
        &self,
        commitment: B256,
    ) -> impl Future<Output = Result<TxReceipt, ChainError>> + Send;

    /// Submit a transfer proof on-chain (lock, claim, refund, or standard transfer).
    fn transfer(
        &self,
        proof: &[u8],
        public_inputs: &TransferPublicInputs,
    ) -> impl Future<Output = Result<TxReceipt, ChainError>> + Send;

    /// Announce a swap via the TeeLock contract (TEE only).
    fn announce_swap(
        &self,
        announcement: &SwapAnnouncement,
    ) -> impl Future<Output = Result<TxReceipt, ChainError>> + Send;

    /// Read a swap announcement from the TeeLock contract.
    fn get_announcement(
        &self,
        swap_id: B256,
    ) -> impl Future<Output = Result<SwapAnnouncement, ChainError>> + Send;

    /// Get the current Merkle root of the commitment tree.
    fn get_commitment_root(
        &self,
    ) -> impl Future<Output = Result<B256, ChainError>> + Send;

    /// Check if a nullifier has been spent.
    fn is_nullifier_spent(
        &self,
        nullifier: B256,
    ) -> impl Future<Output = Result<bool, ChainError>> + Send;
}

#[derive(Debug, thiserror::Error)]
pub enum ChainError {
    #[error("commitment not found: {0}")]
    CommitmentNotFound(B256),

    #[error("announcement not found for swap_id: {0}")]
    AnnouncementNotFound(B256),

    #[error("transaction failed: {0}")]
    TransactionFailed(String),

    #[error("RPC error: {0}")]
    Rpc(String),
}
