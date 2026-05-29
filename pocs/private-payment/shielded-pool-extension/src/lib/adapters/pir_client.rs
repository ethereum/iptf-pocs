//! Cleartext PIR client (Slice 1 stand-in for the PIR'd commitment-path read).
//!
//! Fetches the membership path from the shared in-process state replica in clear
//! — the server learns the leaf index. Slice 2 replaces this with a real PIR
//! backend behind the same [`PirClient`] trait; callers do not change.

use std::sync::{
    Arc,
    RwLock,
};

use crate::{
    adapters::state_replica::StateReplica,
    domain::merkle::CommitmentMerkleProof,
    ports::pir::{
        PirClient,
        PirError,
    },
};

/// Cleartext PIR client over a shared in-process [`StateReplica`].
pub struct CleartextPirClient {
    replica: Arc<RwLock<StateReplica>>,
}

impl CleartextPirClient {
    pub fn new(replica: Arc<RwLock<StateReplica>>) -> Self {
        Self { replica }
    }
}

impl PirClient for CleartextPirClient {
    fn fetch_membership_path(&self, leaf_index: u64) -> Result<CommitmentMerkleProof, PirError> {
        let replica = self.replica.read().expect("replica lock poisoned");
        if replica.commitment_count() == 0 {
            return Err(PirError::EmptyTree);
        }
        replica
            .commitment_proof(leaf_index)
            .ok_or(PirError::LeafOutOfRange(leaf_index))
    }
}
