use alloy::primitives::B256;
use std::collections::HashMap;
use tokio::sync::Mutex;

use crate::domain::swap::SwapAnnouncement;
use crate::ports::chain::{ChainError, ChainPort};
use crate::ports::{SwapLockData, TransferPublicInputs, TxReceipt};

/// Minimal mock of `ChainPort` for coordinator testing and demo.
///
/// Only implements `get_swap_lock_data` and `announce_swap` — the two methods
/// the coordinator uses. Issue #34 builds the real Ethereum adapter.
pub struct MockChainPort {
    lock_data: Mutex<HashMap<B256, SwapLockData>>,
    announcements: Mutex<HashMap<B256, SwapAnnouncement>>,
}

impl MockChainPort {
    pub fn new() -> Self {
        Self {
            lock_data: Mutex::new(HashMap::new()),
            announcements: Mutex::new(HashMap::new()),
        }
    }

    /// Populate lock data (simulates `SwapNoteLocked` event stored on-chain).
    pub async fn insert_lock_data(&self, commitment: B256, data: SwapLockData) {
        self.lock_data.lock().await.insert(commitment, data);
    }

    /// Read a stored announcement (for test assertions).
    pub async fn get_stored_announcement(&self, swap_id: B256) -> Option<SwapAnnouncement> {
        self.announcements.lock().await.get(&swap_id).cloned()
    }
}

impl Default for MockChainPort {
    fn default() -> Self {
        Self::new()
    }
}

impl ChainPort for MockChainPort {
    async fn get_swap_lock_data(&self, commitment: B256) -> Result<SwapLockData, ChainError> {
        self.lock_data
            .lock()
            .await
            .get(&commitment)
            .cloned()
            .ok_or(ChainError::CommitmentNotFound(commitment))
    }

    async fn announce_swap(
        &self,
        announcement: &SwapAnnouncement,
    ) -> Result<TxReceipt, ChainError> {
        self.announcements
            .lock()
            .await
            .insert(announcement.swap_id, announcement.clone());
        Ok(TxReceipt {
            tx_hash: announcement.swap_id,
            success: true,
        })
    }

    async fn fund(&self, _commitment: B256) -> Result<TxReceipt, ChainError> {
        unimplemented!("MockChainPort: fund not needed by coordinator")
    }

    async fn transfer(
        &self,
        _proof: &[u8],
        _public_inputs: &TransferPublicInputs,
    ) -> Result<TxReceipt, ChainError> {
        unimplemented!("MockChainPort: transfer not needed by coordinator")
    }

    async fn get_announcement(&self, swap_id: B256) -> Result<SwapAnnouncement, ChainError> {
        self.announcements
            .lock()
            .await
            .get(&swap_id)
            .cloned()
            .ok_or(ChainError::AnnouncementNotFound(swap_id))
    }

    async fn get_commitment_root(&self) -> Result<B256, ChainError> {
        unimplemented!("MockChainPort: get_commitment_root not needed by coordinator")
    }

    async fn is_nullifier_spent(&self, _nullifier: B256) -> Result<bool, ChainError> {
        unimplemented!("MockChainPort: is_nullifier_spent not needed by coordinator")
    }
}
