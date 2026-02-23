use std::collections::HashMap;

use alloy::primitives::B256;
use tokio::sync::Mutex;

use crate::crypto::poseidon::{bind_enc, bind_meta, bind_r, bind_swap, commitment_hash, swap_id_hash};
use crate::domain::swap::{PartySubmission, SwapAnnouncement};
use crate::ports::chain::{ChainError, ChainPort};
use crate::ports::store::{StoreError, SwapStore};
use crate::ports::{SwapLockData, TxReceipt};

/// Error type for coordinator verification failures.
#[derive(Debug, thiserror::Error)]
pub enum CoordinatorError {
    #[error("swap_id mismatch: submissions reference different swaps")]
    SwapIdMismatch,

    #[error("nonce mismatch between submissions")]
    NonceMismatch,

    #[error("commitment mismatch for {party}: recomputed {recomputed}, on-chain {on_chain}")]
    CommitmentMismatch {
        party: &'static str,
        recomputed: B256,
        on_chain: B256,
    },

    #[error("binding commitment mismatch for {party}: {binding} check failed")]
    BindingMismatch {
        party: &'static str,
        binding: &'static str,
    },

    #[error("swap_id does not match recomputed value from note details")]
    SwapIdRecomputationFailed,

    #[error("timeout mismatch between notes: a={timeout_a}, b={timeout_b}")]
    TimeoutMismatch { timeout_a: B256, timeout_b: B256 },

    #[error("timeout mismatch: note timeout {note} does not match on-chain lock {on_chain}")]
    TimeoutLockMismatch { note: B256, on_chain: B256 },

    #[error("missing lock data for pending submission")]
    MissingLockData,

    #[error("unknown chain_id: {0}")]
    UnknownChain(B256),

    #[error("chain error: {0}")]
    Chain(#[from] ChainError),

    #[error("store error: {0}")]
    Store(#[from] StoreError),
}

/// Result of handling a party submission.
#[derive(Debug)]
pub enum SubmissionResult {
    /// First submission buffered, waiting for counterparty.
    Pending,
    /// Both submissions verified. Announcement posted on-chain.
    Verified {
        announcement: SwapAnnouncement,
        tx_receipt: TxReceipt,
    },
}

/// TEE swap coordinator — performs hash-only verification (SPEC §Phase 2)
/// and posts swap announcements on-chain (Phase 3).
///
/// Generic over `ChainPort` (blockchain interaction) and `SwapStore`
/// (submission buffering). Chains are registered at instantiation;
/// the announcement chain (TeeLock) is fixed.
pub struct SwapCoordinator<C: ChainPort, S: SwapStore> {
    store: S,
    /// chain_id → chain port (one per chain involved in the swap)
    chains: HashMap<B256, C>,
    /// Which chain hosts the TeeLock contract (fixed at TEE instantiation)
    announcement_chain_id: B256,
    pending_lock_data: Mutex<HashMap<B256, SwapLockData>>,
}

impl<C: ChainPort, S: SwapStore> SwapCoordinator<C, S> {
    pub fn new(store: S, chains: HashMap<B256, C>, announcement_chain_id: B256) -> Self {
        Self {
            store,
            chains,
            announcement_chain_id,
            pending_lock_data: Mutex::new(HashMap::new()),
        }
    }

    /// Handle a party submission.
    ///
    /// Reads lock data from the submission's chain, buffers or verifies,
    /// and posts the announcement on-chain when both parties have submitted.
    ///
    /// - First submission for a swap_id: reads lock data, buffers in store. Returns `Pending`.
    /// - Second submission: reads lock data, retrieves the first, runs hash-only
    ///   verification, posts announcement on TeeLock chain, returns `Verified`.
    pub async fn handle_submission(
        &self,
        submission: PartySubmission,
    ) -> Result<SubmissionResult, CoordinatorError> {
        let swap_id = submission.swap_id;

        // Resolve chain from submission's note chain_id
        let chain = self
            .chains
            .get(&submission.note_details.chain_id)
            .ok_or(CoordinatorError::UnknownChain(submission.note_details.chain_id))?;

        // Compute commitment and read lock data from chain
        let commitment = commitment_hash(&submission.note_details);
        let lock_data = chain.get_swap_lock_data(commitment).await?;

        match self.store.submit(submission.clone()).await? {
            // First submission — buffer lock data and wait.
            None => {
                let mut pending = self.pending_lock_data.lock().await;
                pending.insert(swap_id, lock_data);
                Ok(SubmissionResult::Pending)
            }
            // Second submission — retrieve first's lock data, verify, announce.
            Some(first_submission) => {
                let first_lock_data = {
                    let mut pending = self.pending_lock_data.lock().await;
                    pending
                        .remove(&swap_id)
                        .ok_or(CoordinatorError::MissingLockData)?
                };

                let announcement = verify_swap(
                    &first_submission,
                    &submission,
                    &first_lock_data,
                    &lock_data,
                )?;

                // Post announcement on the TeeLock chain
                let announcement_chain = self
                    .chains
                    .get(&self.announcement_chain_id)
                    .ok_or(CoordinatorError::UnknownChain(self.announcement_chain_id))?;
                let tx_receipt = announcement_chain.announce_swap(&announcement).await?;

                Ok(SubmissionResult::Verified {
                    announcement,
                    tx_receipt,
                })
            }
        }
    }

    /// Check if a pending (first-party) submission exists for this swap.
    pub async fn has_pending(&self, swap_id: B256) -> Result<bool, CoordinatorError> {
        Ok(self.store.has_pending(swap_id).await?)
    }

    /// Retrieve a swap announcement from the announcement chain.
    pub async fn get_announcement(
        &self,
        swap_id: B256,
    ) -> Result<SwapAnnouncement, CoordinatorError> {
        let chain = self
            .chains
            .get(&self.announcement_chain_id)
            .ok_or(CoordinatorError::UnknownChain(self.announcement_chain_id))?;
        Ok(chain.get_announcement(swap_id).await?)
    }
}

/// Pure hash-only verification of two swap submissions against on-chain lock data.
///
/// Implements SPEC §Phase 2 — the TEE's verification logic. No elliptic curve
/// operations; only Poseidon hash comparisons.
///
/// The two submissions may arrive in either order (A first or B first).
/// Role determination is performed internally by trying both orderings
/// when recomputing the swap_id.
pub fn verify_swap(
    sub_1: &PartySubmission,
    sub_2: &PartySubmission,
    lock_1: &SwapLockData,
    lock_2: &SwapLockData,
) -> Result<SwapAnnouncement, CoordinatorError> {
    // ── Step 1: Swap ID and nonce agreement ──
    if sub_1.swap_id != sub_2.swap_id {
        return Err(CoordinatorError::SwapIdMismatch);
    }
    if sub_1.nonce != sub_2.nonce {
        return Err(CoordinatorError::NonceMismatch);
    }

    let swap_id = sub_1.swap_id;
    let nonce = sub_1.nonce;

    // ── Step 2: Determine roles (A vs B) via swap_id recomputation ──
    // The swap_id_hash is order-dependent. Try (sub_1=A, sub_2=B) first.
    // pk_meta is derived from fallback_owner (each party sets fallback_owner = own_pk_meta.x).
    let timeout = sub_1.note_details.timeout;

    let (sub_a, sub_b, lock_a, lock_b) = determine_roles(
        sub_1, sub_2, lock_1, lock_2, timeout, nonce, swap_id,
    )?;

    // ── Step 3: Commitment correctness ──
    verify_commitment(sub_a, lock_a, "A")?;
    verify_commitment(sub_b, lock_b, "B")?;

    // ── Step 4: Binding commitment openings (4 checks per party) ──
    let pk_meta_a = sub_a.note_details.fallback_owner;
    let pk_meta_b = sub_b.note_details.fallback_owner;

    verify_bindings(sub_a, lock_a, swap_id, pk_meta_b, "A")?;
    verify_bindings(sub_b, lock_b, swap_id, pk_meta_a, "B")?;

    // ── Step 5: Timeout consistency ──
    if sub_a.note_details.timeout != sub_b.note_details.timeout {
        return Err(CoordinatorError::TimeoutMismatch {
            timeout_a: sub_a.note_details.timeout,
            timeout_b: sub_b.note_details.timeout,
        });
    }
    if lock_a.timeout != sub_a.note_details.timeout {
        return Err(CoordinatorError::TimeoutLockMismatch {
            note: sub_a.note_details.timeout,
            on_chain: lock_a.timeout,
        });
    }
    if lock_b.timeout != sub_b.note_details.timeout {
        return Err(CoordinatorError::TimeoutLockMismatch {
            note: sub_b.note_details.timeout,
            on_chain: lock_b.timeout,
        });
    }

    // ── Step 6: Construct announcement ──
    Ok(SwapAnnouncement {
        swap_id,
        ephemeral_key_a: sub_a.ephemeral_pubkey,
        ephemeral_key_b: sub_b.ephemeral_pubkey,
        encrypted_salt_a: sub_a.encrypted_salt,
        encrypted_salt_b: sub_b.encrypted_salt,
    })
}

/// Determine which submission is Party A and which is Party B by recomputing
/// the swap_id from note details in both orderings.
fn determine_roles<'a>(
    sub_1: &'a PartySubmission,
    sub_2: &'a PartySubmission,
    lock_1: &'a SwapLockData,
    lock_2: &'a SwapLockData,
    timeout: B256,
    nonce: B256,
    expected_swap_id: B256,
) -> Result<
    (
        &'a PartySubmission,
        &'a PartySubmission,
        &'a SwapLockData,
        &'a SwapLockData,
    ),
    CoordinatorError,
> {
    // Try ordering: sub_1 = A, sub_2 = B
    let try_1_as_a = swap_id_hash(
        sub_1.note_details.value,
        sub_1.note_details.asset_id,
        sub_1.note_details.chain_id,
        sub_2.note_details.value,
        sub_2.note_details.asset_id,
        sub_2.note_details.chain_id,
        timeout,
        sub_1.note_details.fallback_owner,
        sub_2.note_details.fallback_owner,
        nonce,
    );

    if try_1_as_a == expected_swap_id {
        return Ok((sub_1, sub_2, lock_1, lock_2));
    }

    // Try ordering: sub_2 = A, sub_1 = B
    let try_2_as_a = swap_id_hash(
        sub_2.note_details.value,
        sub_2.note_details.asset_id,
        sub_2.note_details.chain_id,
        sub_1.note_details.value,
        sub_1.note_details.asset_id,
        sub_1.note_details.chain_id,
        timeout,
        sub_2.note_details.fallback_owner,
        sub_1.note_details.fallback_owner,
        nonce,
    );

    if try_2_as_a == expected_swap_id {
        return Ok((sub_2, sub_1, lock_2, lock_1));
    }

    Err(CoordinatorError::SwapIdRecomputationFailed)
}

/// Verify that recomputed commitment from note details matches on-chain lock data.
fn verify_commitment(
    sub: &PartySubmission,
    lock: &SwapLockData,
    party: &'static str,
) -> Result<(), CoordinatorError> {
    let recomputed = commitment_hash(&sub.note_details);
    if recomputed != lock.commitment {
        return Err(CoordinatorError::CommitmentMismatch {
            party,
            recomputed,
            on_chain: lock.commitment,
        });
    }
    Ok(())
}

/// Verify the 4 binding commitments for a party's submission against on-chain lock data.
///
/// - h_swap: binds deposit to this specific swap
/// - h_r: binds to the ephemeral public key R
/// - h_meta: binds to the counterparty's meta public key
/// - h_enc: binds to the encrypted salt
fn verify_bindings(
    sub: &PartySubmission,
    lock: &SwapLockData,
    swap_id: B256,
    counterparty_pk_meta: B256,
    party: &'static str,
) -> Result<(), CoordinatorError> {
    if bind_swap(swap_id, sub.note_details.salt) != lock.h_swap {
        return Err(CoordinatorError::BindingMismatch {
            party,
            binding: "h_swap",
        });
    }

    if bind_r(sub.ephemeral_pubkey) != lock.h_r {
        return Err(CoordinatorError::BindingMismatch {
            party,
            binding: "h_r",
        });
    }

    if bind_meta(counterparty_pk_meta, sub.note_details.salt) != lock.h_meta {
        return Err(CoordinatorError::BindingMismatch {
            party,
            binding: "h_meta",
        });
    }

    if bind_enc(sub.encrypted_salt) != lock.h_enc {
        return Err(CoordinatorError::BindingMismatch {
            party,
            binding: "h_enc",
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::merkle_tree::LocalMerkleTree;
    use crate::adapters::memory_store::InMemorySwapStore;
    use crate::adapters::mock_chain::MockChainPort;
    use crate::domain::note::Note;
    use crate::domain::stealth::MetaKeyPair;
    use crate::domain::swap::SwapTerms;
    use crate::party::prepare_lock;

    /// Test fixture providing two parties, swap terms, locked notes, submissions,
    /// and lock data for coordinator testing.
    struct TestFixture {
        sub_a: PartySubmission,
        sub_b: PartySubmission,
        lock_data_a: SwapLockData,
        lock_data_b: SwapLockData,
        swap_id: B256,
    }

    impl TestFixture {
        fn new() -> Self {
            let mut rng = ark_std::test_rng();
            let meta_a = MetaKeyPair::generate(&mut rng);
            let meta_b = MetaKeyPair::generate(&mut rng);

            let terms = SwapTerms::new(
                B256::left_padding_from(&[1]),    // chain_id_a
                B256::left_padding_from(&[2]),    // chain_id_b
                1000,                              // value_a (USD)
                50,                                // value_b (BOND)
                B256::repeat_byte(0x01),           // asset_id_a
                B256::repeat_byte(0x02),           // asset_id_b
                B256::left_padding_from(&[0x00, 0x01, 0x51, 0x80]), // timeout ~24h
                meta_a.pk_x(),
                meta_b.pk_x(),
                B256::repeat_byte(0xFF),           // nonce
            );

            // Fund and lock Party A
            let mut tree_a = LocalMerkleTree::new();
            let note_a = Note::new(
                terms.chain_id_a, terms.value_a, terms.asset_id_a,
                meta_a.pk_x(), B256::ZERO, B256::ZERO,
            );
            let leaf_idx_a = tree_a.len() as u64;
            tree_a.insert_commitment(&note_a.commitment());
            let proof_a = tree_a.generate_proof(leaf_idx_a).unwrap();
            let root_a = tree_a.current_root().unwrap();

            let lock_a = prepare_lock(
                &terms, &meta_a, &meta_b.pk.into(),
                &note_a, &proof_a, root_a,
            );

            // Fund and lock Party B
            let mut tree_b = LocalMerkleTree::new();
            let note_b = Note::new(
                terms.chain_id_b, terms.value_b, terms.asset_id_b,
                meta_b.pk_x(), B256::ZERO, B256::ZERO,
            );
            let leaf_idx_b = tree_b.len() as u64;
            tree_b.insert_commitment(&note_b.commitment());
            let proof_b = tree_b.generate_proof(leaf_idx_b).unwrap();
            let root_b = tree_b.current_root().unwrap();

            let lock_b = prepare_lock(
                &terms, &meta_b, &meta_a.pk.into(),
                &note_b, &proof_b, root_b,
            );

            // Build lock data from witness (simulating on-chain SwapNoteLocked events)
            let lock_data_a = SwapLockData {
                commitment: lock_a.locked_note.commitment().0,
                timeout: lock_a.witness.timeout,
                pk_stealth: lock_a.witness.pk_stealth,
                h_swap: lock_a.witness.h_swap,
                h_r: lock_a.witness.h_r,
                h_meta: lock_a.witness.h_meta,
                h_enc: lock_a.witness.h_enc,
            };

            let lock_data_b = SwapLockData {
                commitment: lock_b.locked_note.commitment().0,
                timeout: lock_b.witness.timeout,
                pk_stealth: lock_b.witness.pk_stealth,
                h_swap: lock_b.witness.h_swap,
                h_r: lock_b.witness.h_r,
                h_meta: lock_b.witness.h_meta,
                h_enc: lock_b.witness.h_enc,
            };

            Self {
                sub_a: lock_a.submission,
                sub_b: lock_b.submission,
                lock_data_a,
                lock_data_b,
                swap_id: terms.swap_id,
            }
        }
    }

    // ── verify_swap tests ──

    #[test]
    fn test_verify_swap_happy_path() {
        let f = TestFixture::new();
        let result = verify_swap(&f.sub_a, &f.sub_b, &f.lock_data_a, &f.lock_data_b);
        assert!(result.is_ok());
    }

    #[test]
    fn test_announcement_fields_correct() {
        let f = TestFixture::new();
        let announcement = verify_swap(&f.sub_a, &f.sub_b, &f.lock_data_a, &f.lock_data_b).unwrap();

        assert_eq!(announcement.swap_id, f.swap_id);
        assert_eq!(announcement.ephemeral_key_a, f.sub_a.ephemeral_pubkey);
        assert_eq!(announcement.ephemeral_key_b, f.sub_b.ephemeral_pubkey);
        assert_eq!(announcement.encrypted_salt_a, f.sub_a.encrypted_salt);
        assert_eq!(announcement.encrypted_salt_b, f.sub_b.encrypted_salt);
    }

    #[test]
    fn test_role_determination_order_independent() {
        let f = TestFixture::new();

        // Submit B first, then A (reversed order)
        let result = verify_swap(&f.sub_b, &f.sub_a, &f.lock_data_b, &f.lock_data_a);
        assert!(result.is_ok());

        let announcement = result.unwrap();
        // Announcement should still have A's key as ephemeral_key_a
        assert_eq!(announcement.ephemeral_key_a, f.sub_a.ephemeral_pubkey);
        assert_eq!(announcement.ephemeral_key_b, f.sub_b.ephemeral_pubkey);
    }

    #[test]
    fn test_swap_id_mismatch_rejected() {
        let f = TestFixture::new();
        let mut sub_b_bad = f.sub_b.clone();
        sub_b_bad.swap_id = B256::repeat_byte(0xDE);

        let result = verify_swap(&f.sub_a, &sub_b_bad, &f.lock_data_a, &f.lock_data_b);
        assert!(matches!(result, Err(CoordinatorError::SwapIdMismatch)));
    }

    #[test]
    fn test_nonce_mismatch_rejected() {
        let f = TestFixture::new();
        let mut sub_b_bad = f.sub_b.clone();
        sub_b_bad.nonce = B256::repeat_byte(0xDE);

        let result = verify_swap(&f.sub_a, &sub_b_bad, &f.lock_data_a, &f.lock_data_b);
        assert!(matches!(result, Err(CoordinatorError::NonceMismatch)));
    }

    #[test]
    fn test_commitment_mismatch_rejected() {
        let f = TestFixture::new();
        let mut sub_a_bad = f.sub_a.clone();
        sub_a_bad.note_details.value = 9999; // tamper with value

        let result = verify_swap(&sub_a_bad, &f.sub_b, &f.lock_data_a, &f.lock_data_b);
        // Role determination will fail because tampered value changes the swap_id recomputation
        assert!(result.is_err());
    }

    #[test]
    fn test_binding_h_swap_mismatch() {
        let f = TestFixture::new();
        let mut lock_a_bad = f.lock_data_a.clone();
        lock_a_bad.h_swap = B256::repeat_byte(0xDE);

        let result = verify_swap(&f.sub_a, &f.sub_b, &lock_a_bad, &f.lock_data_b);
        assert!(matches!(
            result,
            Err(CoordinatorError::BindingMismatch { party: "A", binding: "h_swap" })
        ));
    }

    #[test]
    fn test_binding_h_r_mismatch() {
        let f = TestFixture::new();
        let mut lock_a_bad = f.lock_data_a.clone();
        lock_a_bad.h_r = B256::repeat_byte(0xDE);

        let result = verify_swap(&f.sub_a, &f.sub_b, &lock_a_bad, &f.lock_data_b);
        assert!(matches!(
            result,
            Err(CoordinatorError::BindingMismatch { party: "A", binding: "h_r" })
        ));
    }

    #[test]
    fn test_binding_h_meta_mismatch() {
        let f = TestFixture::new();
        let mut lock_b_bad = f.lock_data_b.clone();
        lock_b_bad.h_meta = B256::repeat_byte(0xDE);

        let result = verify_swap(&f.sub_a, &f.sub_b, &f.lock_data_a, &lock_b_bad);
        assert!(matches!(
            result,
            Err(CoordinatorError::BindingMismatch { party: "B", binding: "h_meta" })
        ));
    }

    #[test]
    fn test_binding_h_enc_mismatch() {
        let f = TestFixture::new();
        let mut lock_a_bad = f.lock_data_a.clone();
        lock_a_bad.h_enc = B256::repeat_byte(0xDE);

        let result = verify_swap(&f.sub_a, &f.sub_b, &lock_a_bad, &f.lock_data_b);
        assert!(matches!(
            result,
            Err(CoordinatorError::BindingMismatch { party: "A", binding: "h_enc" })
        ));
    }

    #[test]
    fn test_swap_id_recomputation_mismatch() {
        let f = TestFixture::new();
        // Tamper with note value but fix commitment to match (so commitment check passes
        // but swap_id recomputation fails). Easiest: tamper lock_data commitment to match
        // the tampered note, so commitment check passes but swap_id recomputation fails.
        let mut sub_a_bad = f.sub_a.clone();
        sub_a_bad.note_details.value = 9999;
        let tampered_commitment = commitment_hash(&sub_a_bad.note_details);
        let mut lock_a_fixed = f.lock_data_a.clone();
        lock_a_fixed.commitment = tampered_commitment;

        let result = verify_swap(&sub_a_bad, &f.sub_b, &lock_a_fixed, &f.lock_data_b);
        assert!(matches!(
            result,
            Err(CoordinatorError::SwapIdRecomputationFailed)
        ));
    }

    #[test]
    fn test_timeout_mismatch_rejected() {
        let f = TestFixture::new();
        let mut lock_a_bad = f.lock_data_a.clone();
        lock_a_bad.timeout = B256::repeat_byte(0xDE);

        let result = verify_swap(&f.sub_a, &f.sub_b, &lock_a_bad, &f.lock_data_b);
        assert!(matches!(
            result,
            Err(CoordinatorError::TimeoutLockMismatch { .. })
        ));
    }

    // ── handle_submission tests (with MockChainPort) ──

    /// Create a coordinator pre-populated with on-chain lock data from the fixture.
    async fn create_test_coordinator(
        f: &TestFixture,
    ) -> SwapCoordinator<MockChainPort, InMemorySwapStore> {
        let chain_a = MockChainPort::new();
        chain_a
            .insert_lock_data(f.lock_data_a.commitment, f.lock_data_a.clone())
            .await;

        let chain_b = MockChainPort::new();
        chain_b
            .insert_lock_data(f.lock_data_b.commitment, f.lock_data_b.clone())
            .await;

        let chain_id_a = f.sub_a.note_details.chain_id;
        let chain_id_b = f.sub_b.note_details.chain_id;

        let mut chains = HashMap::new();
        chains.insert(chain_id_a, chain_a);
        chains.insert(chain_id_b, chain_b);

        SwapCoordinator::new(InMemorySwapStore::new(), chains, chain_id_a)
    }

    #[tokio::test]
    async fn test_first_submission_returns_pending() {
        let f = TestFixture::new();
        let coordinator = create_test_coordinator(&f).await;

        let result = coordinator
            .handle_submission(f.sub_a)
            .await
            .unwrap();

        assert!(matches!(result, SubmissionResult::Pending));
    }

    #[tokio::test]
    async fn test_second_submission_returns_verified() {
        let f = TestFixture::new();
        let coordinator = create_test_coordinator(&f).await;

        coordinator
            .handle_submission(f.sub_a.clone())
            .await
            .unwrap();

        let result = coordinator
            .handle_submission(f.sub_b.clone())
            .await
            .unwrap();

        match result {
            SubmissionResult::Verified { announcement, tx_receipt } => {
                assert_eq!(announcement.swap_id, f.swap_id);
                assert!(tx_receipt.success);
            }
            SubmissionResult::Pending => panic!("Expected Verified, got Pending"),
        }
    }

    #[tokio::test]
    async fn test_handle_submission_order_independent() {
        let f = TestFixture::new();
        let coordinator = create_test_coordinator(&f).await;

        // Submit B first, then A
        coordinator
            .handle_submission(f.sub_b.clone())
            .await
            .unwrap();

        let result = coordinator
            .handle_submission(f.sub_a.clone())
            .await
            .unwrap();

        match result {
            SubmissionResult::Verified { announcement, .. } => {
                assert_eq!(announcement.swap_id, f.swap_id);
                assert_eq!(announcement.ephemeral_key_a, f.sub_a.ephemeral_pubkey);
                assert_eq!(announcement.ephemeral_key_b, f.sub_b.ephemeral_pubkey);
            }
            SubmissionResult::Pending => panic!("Expected Verified, got Pending"),
        }
    }

    #[tokio::test]
    async fn test_chain_read_failure() {
        let f = TestFixture::new();

        // Create coordinator with empty chains (no lock data inserted)
        let chain_a = MockChainPort::new();
        let chain_b = MockChainPort::new();

        let chain_id_a = f.sub_a.note_details.chain_id;
        let chain_id_b = f.sub_b.note_details.chain_id;

        let mut chains = HashMap::new();
        chains.insert(chain_id_a, chain_a);
        chains.insert(chain_id_b, chain_b);

        let coordinator = SwapCoordinator::new(InMemorySwapStore::new(), chains, chain_id_a);

        let result = coordinator.handle_submission(f.sub_a).await;
        assert!(matches!(result, Err(CoordinatorError::Chain(_))));
    }

    #[tokio::test]
    async fn test_unknown_chain_rejected() {
        let f = TestFixture::new();

        // Create coordinator with only chain_a, no chain_b
        let chain_a = MockChainPort::new();
        chain_a
            .insert_lock_data(f.lock_data_a.commitment, f.lock_data_a.clone())
            .await;

        let chain_id_a = f.sub_a.note_details.chain_id;

        let mut chains = HashMap::new();
        chains.insert(chain_id_a, chain_a);

        let coordinator = SwapCoordinator::new(InMemorySwapStore::new(), chains, chain_id_a);

        // Party B's submission references chain_b which is not registered
        let result = coordinator.handle_submission(f.sub_b).await;
        assert!(matches!(result, Err(CoordinatorError::UnknownChain(_))));
    }
}
