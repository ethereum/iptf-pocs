//! PIR client port: the single PIR'd read, the commitment-tree membership path.

use crate::domain::merkle::CommitmentMerkleProof;

/// Errors from a PIR membership-path fetch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PirError {
    #[error("leaf index {0} is out of range")]
    LeafOutOfRange(u64),
    #[error("commitment tree is empty")]
    EmptyTree,
}

/// The single PIR'd read: the commitment-tree membership path for a leaf the
/// wallet owns (its index is known from its own minting event).
///
/// Two adapters implement this trait. The `CleartextPirClient` dev stub sends the
/// leaf index to the server (which learns it) — convenient for tests, not private.
/// The real `SimplePirClient` computes the sibling-node offsets locally and
/// fetches each node obliviously over the `tree-pir` flattened array, so the leaf
/// index never leaves the wallet. Phantom-epoch lookups and the active tree are
/// NOT PIR'd (see `StateReplicaQuery` and SPEC.md "Off-Chain State-Replica Server").
pub trait PirClient {
    /// Fetch the membership path for the commitment at `leaf_index`.
    fn fetch_membership_path(&self, leaf_index: u64) -> Result<CommitmentMerkleProof, PirError>;
}
