//! In-memory state-replica core.
//!
//! Replays `ShieldedPoolExt` events to rebuild the public off-chain state the
//! wallet and relayer query: the commitment LeanIMT, the current epoch's active
//! nullifier tree, and one frozen nullifier tree per past epoch. Untrusted for
//! correctness — served witnesses are re-checked in-circuit against
//! light-client-verified roots.
//!
//! Driven by a synthetic event stream in unit tests and by the live RPC event
//! source in the on-chain e2e. The wallet and relayer share one in-process
//! instance (the e2e is in-process; there is no separate HTTP server).

use std::collections::HashMap;

use alloy::primitives::B256;

use crate::{
    adapters::{
        indexed_merkle_tree::{
            IndexedMerkleTree,
            IndexedTreeError,
        },
        merkle_tree::CommitmentTree,
    },
    domain::{
        indexed_merkle::{
            InsertionWitness,
            NonMembershipWitness,
        },
        merkle::CommitmentMerkleProof,
    },
    ports::state_replica::{
        Event,
        StateReplicaQuery,
    },
};

/// Relayer inputs for the insertion proof: advancing the active tree from
/// `pre_root` to `post_root` by inserting `nullifiers` at canonical indices
/// starting at `pre_leaf_count`. Built against a snapshot of the active tree —
/// the canonical tree advances via the Transfer/Withdraw event ingest when the
/// spend's tx lands, so the relayer can build the proof before the tx confirms.
#[derive(Debug, Clone)]
pub struct InsertionInput {
    pub pre_root: B256,
    pub post_root: B256,
    pub pre_leaf_count: u64,
    pub nullifiers: Vec<B256>,
    pub witnesses: Vec<InsertionWitness>,
}

/// In-memory replica of public `ShieldedPoolExt` state, rebuilt from events.
pub struct StateReplica {
    commitment_tree: CommitmentTree,
    active_tree: IndexedMerkleTree,
    frozen_trees: HashMap<u64, IndexedMerkleTree>,
    current_epoch: u64,
}

impl Default for StateReplica {
    fn default() -> Self {
        Self::new()
    }
}

impl StateReplica {
    pub fn new() -> Self {
        Self {
            commitment_tree: CommitmentTree::new(),
            active_tree: IndexedMerkleTree::new(),
            frozen_trees: HashMap::new(),
            current_epoch: 0,
        }
    }

    /// Apply one event. Events MUST be replayed in block-then-input order so the
    /// reconstructed trees match the canonical on-chain ones.
    pub fn ingest(&mut self, event: Event) {
        match event {
            Event::Deposit { commitment } => {
                self.commitment_tree.insert(&commitment.0);
            }
            Event::Transfer {
                nullifiers,
                output_commitments,
            } => {
                for commitment in output_commitments {
                    self.commitment_tree.insert(&commitment.0);
                }
                for nullifier in nullifiers {
                    // A well-formed stream never replays a duplicate; ignore the
                    // Result (a duplicate would indicate an invalid on-chain spend
                    // that could not have landed).
                    let _ = self.active_tree.insert(nullifier);
                }
            }
            Event::Withdraw { nullifiers } => {
                for nullifier in nullifiers {
                    let _ = self.active_tree.insert(nullifier);
                }
            }
            Event::EpochRollover { epoch } => {
                let frozen =
                    std::mem::replace(&mut self.active_tree, IndexedMerkleTree::new());
                self.frozen_trees.insert(epoch, frozen);
                self.current_epoch = epoch + 1;
            }
        }
    }

    /// Current epoch (number of rollovers ingested).
    pub fn current_epoch(&self) -> u64 {
        self.current_epoch
    }

    /// Number of commitments in the commitment tree.
    pub fn commitment_count(&self) -> usize {
        self.commitment_tree.len()
    }

    /// Current commitment-tree root, or `None` if no commitments yet.
    pub fn commitment_root(&self) -> Option<B256> {
        self.commitment_tree.root().map(B256::from)
    }

    /// Current active nullifier-tree root.
    pub fn active_nullifier_root(&self) -> B256 {
        self.active_tree.root()
    }

    /// Membership path for an owned commitment leaf (served cleartext by the
    /// `CleartextPirClient` dev stub; obliviously by the real `SimplePirClient`).
    pub fn commitment_proof(&self, leaf_index: u64) -> Option<CommitmentMerkleProof> {
        self.commitment_tree.generate_commitment_proof(leaf_index)
    }

    /// Relayer: build the insertion-proof inputs for a spend's `nullifiers`,
    /// against a snapshot of the current active tree. Does NOT mutate the
    /// canonical tree — that advances via the Transfer/Withdraw event ingest when
    /// the spend lands — so the relayer can build the proof before the tx confirms.
    pub fn build_insertion(
        &self,
        nullifiers: &[B256],
    ) -> Result<InsertionInput, IndexedTreeError> {
        let mut tree = self.active_tree.clone();
        let pre_root = tree.root();
        let pre_leaf_count = tree.leaf_count();
        let mut witnesses = Vec::with_capacity(nullifiers.len());
        for &nullifier in nullifiers {
            witnesses.push(tree.insert(nullifier)?);
        }
        Ok(InsertionInput {
            pre_root,
            post_root: tree.root(),
            pre_leaf_count,
            nullifiers: nullifiers.to_vec(),
            witnesses,
        })
    }
}

impl StateReplicaQuery for StateReplica {
    fn phantom_witness(&self, epoch: u64, nullifier: B256) -> Option<NonMembershipWitness> {
        self.frozen_trees.get(&epoch)?.non_membership_witness(nullifier)
    }

    fn frozen_nullifier_root(&self, epoch: u64) -> Option<B256> {
        self.frozen_trees.get(&epoch).map(IndexedMerkleTree::root)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        RwLock,
    };

    use alloy::primitives::{
        B256,
        U256,
    };

    use super::*;
    use crate::{
        adapters::pir_client::CleartextPirClient,
        ports::pir::PirClient,
    };

    fn b(n: u64) -> B256 {
        B256::from(U256::from(n))
    }

    #[test]
    fn relayer_insertion_witnesses_chain_to_post_root() {
        let replica = StateReplica::new();
        let nullifiers = [b(50), b(90)];

        let input = replica.build_insertion(&nullifiers).unwrap();

        // build_insertion uses a snapshot: the canonical active tree is untouched.
        assert_eq!(replica.active_nullifier_root(), input.pre_root);
        assert_eq!(input.pre_leaf_count, 1, "genesis leaf occupies index 0");

        // Each witness advances the root (the same chain the insertion circuit
        // verifies), reaching post_root.
        let mut root = input.pre_root;
        for (i, witness) in input.witnesses.iter().enumerate() {
            root = witness
                .verify_and_apply(root, input.nullifiers[i])
                .expect("valid insertion");
        }
        assert_eq!(root, input.post_root);
    }

    #[test]
    fn replays_stream_and_serves_consistent_witnesses() {
        let replica = Arc::new(RwLock::new(StateReplica::new()));

        let (c0, c1, c2) = (b(111), b(222), b(333));
        let n1 = b(40); // nullifier spent in epoch 0

        {
            let mut r = replica.write().unwrap();
            r.ingest(Event::Deposit { commitment: c0 });
            r.ingest(Event::Transfer {
                nullifiers: vec![n1],
                output_commitments: vec![c1, c2],
            });
            r.ingest(Event::EpochRollover { epoch: 0 });
        }

        // Commitment tree holds c0, c1, c2; the PIR'd path for leaf 0 reconstructs
        // the live commitment root.
        let pir = CleartextPirClient::new(replica.clone());
        let proof = pir.fetch_membership_path(0).unwrap();

        let r = replica.read().unwrap();
        assert_eq!(r.commitment_count(), 3);
        assert_eq!(r.current_epoch(), 1);
        assert_eq!(
            proof.reconstruct_root(c0),
            r.commitment_root().unwrap(),
            "PIR'd path must rebuild the commitment root"
        );

        // Phantom non-membership for an absent nullifier in frozen epoch 0 verifies
        // against that epoch's frozen root.
        let absent = b(99);
        let witness = r.phantom_witness(0, absent).unwrap();
        assert!(witness.verify(r.frozen_nullifier_root(0).unwrap(), absent));

        // n1 was spent in epoch 0, so it is present — no phantom witness.
        assert!(r.phantom_witness(0, n1).is_none());

        // Active tree was reset on rollover.
        let fresh = IndexedMerkleTree::new();
        assert_eq!(r.active_nullifier_root(), fresh.root());
    }

    #[test]
    fn pir_fetch_on_empty_tree_errors() {
        let replica = Arc::new(RwLock::new(StateReplica::new()));
        let pir = CleartextPirClient::new(replica.clone());
        assert!(pir.fetch_membership_path(0).is_err());
    }
}
