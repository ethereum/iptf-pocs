use alloy_primitives::B256;
use std::collections::HashMap;
use tokio::sync::Mutex;

use crate::domain::swap::PartySubmission;
use crate::ports::store::{StoreError, SwapStore};

/// In-memory implementation of `SwapStore` for PoC and testing.
///
/// Holds only pending first submissions (waiting for the counterparty).
/// Once both sides submit, the entry is consumed and removed.
/// Replay protection for completed swaps is delegated to the on-chain
/// `require(!revealed)` guard in the announcement contract.
pub struct InMemorySwapStore {
    pending: Mutex<HashMap<B256, PartySubmission>>,
}

impl InMemorySwapStore {
    pub fn new() -> Self {
        Self {
            pending: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for InMemorySwapStore {
    fn default() -> Self {
        Self::new()
    }
}

impl SwapStore for InMemorySwapStore {
    async fn submit(
        &self,
        submission: PartySubmission,
    ) -> Result<Option<PartySubmission>, StoreError> {
        let mut pending = self.pending.lock().await;
        let swap_id = submission.swap_id;

        match pending.remove(&swap_id) {
            // First submission for this swap — buffer it.
            None => {
                pending.insert(swap_id, submission);
                Ok(None)
            }
            // Second submission — return the first, consuming the entry.
            Some(first) => Ok(Some(first)),
        }
    }

    async fn remove(&self, swap_id: B256) -> Result<(), StoreError> {
        let mut pending = self.pending.lock().await;
        pending
            .remove(&swap_id)
            .ok_or(StoreError::SwapNotFound(swap_id))?;
        Ok(())
    }

    async fn has_pending(&self, swap_id: B256) -> Result<bool, StoreError> {
        let pending = self.pending.lock().await;
        Ok(pending.contains_key(&swap_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::note::Note;

    fn test_submission(swap_id: B256, salt: u8) -> PartySubmission {
        PartySubmission {
            swap_id,
            nonce: B256::repeat_byte(0xFF),
            ephemeral_pubkey: B256::repeat_byte(salt),
            encrypted_salt: B256::repeat_byte(salt + 1),
            note_details: Note::with_salt(
                B256::left_padding_from(&[1]),
                1000,
                B256::repeat_byte(0x01),
                B256::repeat_byte(0xBB),
                B256::repeat_byte(0xCC),
                B256::left_padding_from(&[0x01, 0x00]),
                B256::repeat_byte(salt),
            ),
        }
    }

    #[tokio::test]
    async fn first_submission_returns_none() {
        let store = InMemorySwapStore::new();
        let swap_id = B256::repeat_byte(0x10);

        let result = store.submit(test_submission(swap_id, 0x01)).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn second_submission_returns_first() {
        let store = InMemorySwapStore::new();
        let swap_id = B256::repeat_byte(0x10);

        store.submit(test_submission(swap_id, 0x01)).await.unwrap();
        let first = store.submit(test_submission(swap_id, 0x02)).await.unwrap();

        assert!(first.is_some());
        // Returned submission is the first one (salt byte 0x01)
        assert_eq!(first.unwrap().ephemeral_pubkey, B256::repeat_byte(0x01));
    }

    #[tokio::test]
    async fn entry_consumed_after_match() {
        let store = InMemorySwapStore::new();
        let swap_id = B256::repeat_byte(0x10);

        store.submit(test_submission(swap_id, 0x01)).await.unwrap();
        store.submit(test_submission(swap_id, 0x02)).await.unwrap();

        // Entry was consumed — no pending submission remains
        assert!(!store.has_pending(swap_id).await.unwrap());
    }

    #[tokio::test]
    async fn has_pending_true_after_first() {
        let store = InMemorySwapStore::new();
        let swap_id = B256::repeat_byte(0x10);

        store.submit(test_submission(swap_id, 0x01)).await.unwrap();
        assert!(store.has_pending(swap_id).await.unwrap());
    }

    #[tokio::test]
    async fn has_pending_false_for_unknown() {
        let store = InMemorySwapStore::new();
        assert!(!store.has_pending(B256::repeat_byte(0x99)).await.unwrap());
    }

    #[tokio::test]
    async fn remove_pending_submission() {
        let store = InMemorySwapStore::new();
        let swap_id = B256::repeat_byte(0x10);

        store.submit(test_submission(swap_id, 0x01)).await.unwrap();
        store.remove(swap_id).await.unwrap();

        assert!(!store.has_pending(swap_id).await.unwrap());
    }

    #[tokio::test]
    async fn remove_unknown_swap_fails() {
        let store = InMemorySwapStore::new();
        let result = store.remove(B256::repeat_byte(0x99)).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn resubmit_after_consumption_buffers_again() {
        let store = InMemorySwapStore::new();
        let swap_id = B256::repeat_byte(0x10);

        // First round: both submit, entry consumed
        store.submit(test_submission(swap_id, 0x01)).await.unwrap();
        store.submit(test_submission(swap_id, 0x02)).await.unwrap();

        // Second round: new submission buffers as pending again
        let result = store.submit(test_submission(swap_id, 0x03)).await.unwrap();
        assert!(result.is_none());
        assert!(store.has_pending(swap_id).await.unwrap());
    }
}
