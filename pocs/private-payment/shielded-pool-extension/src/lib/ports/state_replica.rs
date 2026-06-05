//! State-replica port: the events the replica ingests and the cleartext queries
//! the wallet makes against it.
//!
//! The commitment membership path (the PIR'd read) is fetched separately via
//! [`crate::ports::pir::PirClient`]. The replica is untrusted for correctness:
//! served witnesses are re-checked in-circuit against light-client-verified
//! roots. See SPEC.md "Off-Chain State-Replica Server".

use alloy::primitives::B256;

use crate::domain::indexed_merkle::NonMembershipWitness;

/// On-chain events the replica ingests to rebuild public state. Mirrors the
/// `ShieldedPoolExt` events; produced live by the RPC adapter (later slice) or
/// fed synthetically in tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// A deposit appended `commitment` to the commitment tree.
    Deposit { commitment: B256 },
    /// A transfer appended `output_commitments` and spent the public
    /// `nullifiers` (the η_active list) into the active nullifier tree.
    Transfer {
        nullifiers: Vec<B256>,
        output_commitments: Vec<B256>,
    },
    /// A withdraw spent `nullifiers` into the active nullifier tree.
    Withdraw { nullifiers: Vec<B256> },
    /// Epoch `epoch` rolled over: its active tree is frozen and the active tree
    /// resets for `epoch + 1`.
    EpochRollover { epoch: u64 },
}

/// Cleartext queries the wallet makes to the state-replica server.
pub trait StateReplicaQuery {
    /// Sorted-low-leaf non-membership witness for `nullifier` against the frozen
    /// tree of `epoch`. `None` if the epoch is not frozen or `nullifier` is present.
    fn phantom_witness(&self, epoch: u64, nullifier: B256) -> Option<NonMembershipWitness>;

    /// Root of a frozen epoch's nullifier tree. Untrusted (light-client-verified
    /// in a later slice); served so the wallet/circuit knows what root to
    /// reconstruct a phantom witness against.
    fn frozen_nullifier_root(&self, epoch: u64) -> Option<B256>;
}
