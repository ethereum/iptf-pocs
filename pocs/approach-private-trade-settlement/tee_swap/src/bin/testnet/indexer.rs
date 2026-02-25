use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use alloy::primitives::{Address, B256};
use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use alloy::rpc::types::Filter;
use alloy::sol_types::SolEvent;
use tokio::sync::{Mutex, Notify};

use tee_swap::adapters::abi::{IPrivateUTXO, ITeeLock};
use tee_swap::adapters::merkle_tree::LocalMerkleTree;
use tee_swap::domain::merkle::CommitmentMerkleProof;

/// Maximum block range per log query (avoids RPC limits).
const BATCH_SIZE: u64 = 500;

/// Internal mutable state managed by the indexer.
struct IndexerState {
    tree: LocalMerkleTree,
    /// commitment -> leaf index
    commitment_indices: HashMap<B256, u64>,
    /// swap_ids that have been revealed on-chain
    revealed_swaps: HashSet<B256>,
    /// nullifiers that have been spent
    spent_nullifiers: HashSet<B256>,
    /// last processed block
    last_block: u64,
}

/// Indexes on-chain events for a single chain, rebuilding a local Merkle tree
/// from `NoteCreated` events and tracking `SwapRevealed` and `NoteSpent`.
pub struct ChainIndexer {
    provider: DynProvider,
    private_utxo: Address,
    tee_lock: Option<Address>,
    state: Arc<Mutex<IndexerState>>,
    caught_up: Arc<Notify>,
    caught_up_flag: Arc<AtomicBool>,
}

impl ChainIndexer {
    /// Create a new indexer. `tee_lock` is `Some` only on the announcement chain (Sepolia).
    pub fn new(
        rpc_url: &str,
        private_utxo: Address,
        tee_lock: Option<Address>,
        deployment_block: u64,
    ) -> Result<Self, String> {
        let provider = DynProvider::new(
            ProviderBuilder::new().connect_http(
                rpc_url
                    .parse()
                    .map_err(|e| format!("Invalid RPC URL: {e}"))?,
            ),
        );

        Ok(Self {
            provider,
            private_utxo,
            tee_lock,
            state: Arc::new(Mutex::new(IndexerState {
                tree: LocalMerkleTree::new(),
                commitment_indices: HashMap::new(),
                revealed_swaps: HashSet::new(),
                spent_nullifiers: HashSet::new(),
                last_block: deployment_block.saturating_sub(1),
            })),
            caught_up: Arc::new(Notify::new()),
            caught_up_flag: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Start the polling loop in a background task.
    pub fn start(self: &Arc<Self>) {
        let this = Arc::clone(self);
        tokio::spawn(async move {
            this.poll_loop().await;
        });
    }

    async fn poll_loop(&self) {
        // Backfill to head
        loop {
            let head = match self.provider.get_block_number().await {
                Ok(n) => n,
                Err(e) => {
                    tracing::warn!("indexer: failed to get block number: {e}");
                    tokio::time::sleep(std::time::Duration::from_secs(4)).await;
                    continue;
                }
            };

            let last = {
                let state = self.state.lock().await;
                state.last_block
            };

            if last >= head {
                // Caught up
                if !self.caught_up_flag.load(Ordering::Relaxed) {
                    self.caught_up_flag.store(true, Ordering::Release);
                    self.caught_up.notify_waiters();
                }
                tokio::time::sleep(std::time::Duration::from_secs(4)).await;
                continue;
            }

            // Process in batches
            let from = last + 1;
            let to = head.min(from + BATCH_SIZE - 1);

            if let Err(e) = self.process_range(from, to).await {
                tracing::warn!("indexer: error processing blocks {from}..{to}: {e}");
                tokio::time::sleep(std::time::Duration::from_secs(4)).await;
                continue;
            }

            // Update last_block
            {
                let mut state = self.state.lock().await;
                state.last_block = to;
            }

            // Notify waiters after each batch
            self.caught_up.notify_waiters();
        }
    }

    async fn process_range(&self, from: u64, to: u64) -> Result<(), String> {
        // Fetch all log types from the RPC (no lock held during I/O)
        let note_filter = Filter::new()
            .address(self.private_utxo)
            .event_signature(IPrivateUTXO::NoteCreated::SIGNATURE_HASH)
            .from_block(from)
            .to_block(to);

        let spent_filter = Filter::new()
            .address(self.private_utxo)
            .event_signature(IPrivateUTXO::NoteSpent::SIGNATURE_HASH)
            .from_block(from)
            .to_block(to);

        let (note_logs, spent_logs) = tokio::try_join!(
            async { self.provider.get_logs(&note_filter).await.map_err(|e| format!("NoteCreated query: {e}")) },
            async { self.provider.get_logs(&spent_filter).await.map_err(|e| format!("NoteSpent query: {e}")) },
        )?;

        let reveal_logs = if let Some(tee_lock) = self.tee_lock {
            let reveal_filter = Filter::new()
                .address(tee_lock)
                .event_signature(ITeeLock::SwapRevealed::SIGNATURE_HASH)
                .from_block(from)
                .to_block(to);
            self.provider
                .get_logs(&reveal_filter)
                .await
                .map_err(|e| format!("SwapRevealed query: {e}"))?
        } else {
            vec![]
        };

        // Sort NoteCreated by (block_number, log_index) for deterministic ordering
        let mut note_logs = note_logs;
        note_logs.sort_by_key(|l| (l.block_number, l.log_index));

        // Single lock acquisition for all state mutations
        let mut state = self.state.lock().await;

        for log in &note_logs {
            match log.log_decode::<IPrivateUTXO::NoteCreated>() {
                Ok(event) => {
                    let commitment = event.inner.commitment;
                    // Guard against duplicate insertion on retry
                    if !state.commitment_indices.contains_key(&commitment) {
                        let idx = state.tree.len() as u64;
                        state
                            .tree
                            .insert_commitment(&tee_swap::domain::commitment::Commitment(commitment));
                        state.commitment_indices.insert(commitment, idx);
                    }
                }
                Err(e) => tracing::warn!("indexer: NoteCreated decode error: {e}"),
            }
        }

        for log in &spent_logs {
            match log.log_decode::<IPrivateUTXO::NoteSpent>() {
                Ok(event) => { state.spent_nullifiers.insert(event.inner.nullifier); }
                Err(e) => tracing::warn!("indexer: NoteSpent decode error: {e}"),
            }
        }

        for log in &reveal_logs {
            match log.log_decode::<ITeeLock::SwapRevealed>() {
                Ok(event) => { state.revealed_swaps.insert(event.inner.swapId); }
                Err(e) => tracing::warn!("indexer: SwapRevealed decode error: {e}"),
            }
        }

        Ok(())
    }

    // ── Consumer API ──

    /// Block until the indexer has caught up with the chain head at least once.
    pub async fn wait_until_caught_up(&self) {
        if self.caught_up_flag.load(Ordering::Acquire) {
            return;
        }
        self.caught_up.notified().await;
    }

    /// Wait for a commitment to appear in the indexed tree. Returns the leaf index.
    pub async fn wait_for_commitment(&self, commitment: B256) -> u64 {
        loop {
            {
                let state = self.state.lock().await;
                if let Some(&idx) = state.commitment_indices.get(&commitment) {
                    return idx;
                }
            }
            // Wait for next indexer batch
            self.caught_up.notified().await;
        }
    }

    /// Wait for a swap to be revealed on-chain (SwapRevealed event).
    pub async fn wait_for_swap_revealed(&self, swap_id: B256) {
        loop {
            {
                let state = self.state.lock().await;
                if state.revealed_swaps.contains(&swap_id) {
                    return;
                }
            }
            self.caught_up.notified().await;
        }
    }

    /// Generate a Merkle proof for a given leaf index (snapshot of current tree).
    pub async fn generate_proof(&self, leaf_index: u64) -> Option<CommitmentMerkleProof> {
        let state = self.state.lock().await;
        state.tree.generate_proof(leaf_index)
    }

    /// Get the current root of the indexed Merkle tree.
    pub async fn current_root(&self) -> Option<B256> {
        let state = self.state.lock().await;
        state.tree.current_root()
    }
}
