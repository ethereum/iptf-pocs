//! Cleartext PIR client: a dev stand-in for the PIR'd commitment-path read.
//!
//! Fetches the membership path from the shared in-process state replica in clear
//! — the server learns the leaf index. The real [`SimplePirClient`] (below)
//! implements the same [`PirClient`] trait without revealing the index; callers
//! do not change.

use std::sync::{
    Arc,
    RwLock,
};

use lean_imt::stateless::stateless_path;

use crate::{
    adapters::{
        commitment_pir::{
            build_commitment_pir_db,
            level_sizes,
            limbs_to_node,
            record_index,
            LIMBS_PER_NODE,
        },
        merkle_tree::CommitmentTree,
        pir::PirDatabase,
        state_replica::StateReplica,
    },
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

/// Real SimplePIR commitment-path client. Holds a snapshot PIR database
/// of the commitment tree (the server side) plus the public leaf count. A fetch
/// derives the sibling positions from the leaf index via `stateless_path` — no
/// tree access — then PIR-fetches each sibling's limbs and reassembles the proof,
/// so the server only ever sees encrypted queries and never the leaf index.
///
/// Drop-in for [`CleartextPirClient`]: same [`PirClient`] trait, same
/// `CommitmentMerkleProof` output (verified against the cleartext path in tests).
pub struct SimplePirClient {
    /// `None` for an empty tree (nothing to read).
    db: Option<PirDatabase>,
    leaf_count: usize,
}

impl SimplePirClient {
    /// Snapshot the commitment tree into a SimplePIR database (runs the expensive
    /// offline `setup`).
    pub fn from_tree(tree: &CommitmentTree) -> Self {
        let leaf_count = tree.len();
        let db = (leaf_count > 0).then(|| build_commitment_pir_db(tree));
        Self { db, leaf_count }
    }
}

impl PirClient for SimplePirClient {
    fn fetch_membership_path(&self, leaf_index: u64) -> Result<CommitmentMerkleProof, PirError> {
        let db = self.db.as_ref().ok_or(PirError::EmptyTree)?;
        // Sibling positions from the leaf index alone (no tree access).
        let elements = stateless_path(leaf_index as usize, self.leaf_count)
            .map_err(|_| PirError::LeafOutOfRange(leaf_index))?;
        let sizes = level_sizes(self.leaf_count);

        let mut path = Vec::with_capacity(elements.len());
        let mut indices = Vec::with_capacity(elements.len());
        for element in &elements {
            let mut limbs = [0u64; LIMBS_PER_NODE];
            for (limb, slot) in limbs.iter_mut().enumerate() {
                *slot = db.fetch(record_index(&sizes, element.level(), element.sibling_index(), limb));
            }
            path.push(limbs_to_node(&limbs));
            // `is_right` == the proven node was a right child => sibling on the
            // left => index bit 1 (matches `CommitmentMerkleProof::reconstruct_root`).
            indices.push(u8::from(element.is_right()));
        }
        Ok(CommitmentMerkleProof::new(path, indices, leaf_index))
    }
}

#[cfg(test)]
mod tests {
    use alloy::primitives::B256;

    use super::*;

    fn tree_with(n: u8) -> (CommitmentTree, Vec<[u8; 32]>) {
        let mut tree = CommitmentTree::new();
        let leaves: Vec<[u8; 32]> = (1..=n).map(|i| [i; 32]).collect();
        for leaf in &leaves {
            tree.insert(leaf);
        }
        (tree, leaves)
    }

    /// The oblivious PIR path equals the cleartext tree proof and reconstructs the
    /// root, for every leaf of a tree with odd-promoted levels (5 leaves).
    #[test]
    fn pir_path_matches_cleartext_and_reconstructs_root() {
        let (tree, leaves) = tree_with(5);
        let root = B256::from_slice(&tree.root().unwrap());
        let client = SimplePirClient::from_tree(&tree);

        for i in 0..leaves.len() as u64 {
            let pir = client.fetch_membership_path(i).expect("pir path");
            let reference = tree.generate_commitment_proof(i).expect("cleartext path");
            assert_eq!(pir.path, reference.path, "siblings must match cleartext (leaf {i})");
            assert_eq!(pir.indices, reference.indices, "index bits must match cleartext (leaf {i})");
            assert_eq!(
                pir.reconstruct_root(B256::from_slice(&leaves[i as usize])),
                root,
                "reconstructed root must match (leaf {i})",
            );
        }
    }

    #[test]
    fn single_leaf_has_empty_path() {
        let (tree, leaves) = tree_with(1);
        let client = SimplePirClient::from_tree(&tree);
        let proof = client.fetch_membership_path(0).expect("path");
        assert_eq!(proof.proof_length, 0);
        assert_eq!(proof.reconstruct_root(B256::from_slice(&leaves[0])), B256::from_slice(&tree.root().unwrap()));
    }

    #[test]
    fn empty_tree_and_out_of_range_error() {
        let empty = SimplePirClient::from_tree(&CommitmentTree::new());
        assert_eq!(empty.fetch_membership_path(0), Err(PirError::EmptyTree));

        let (tree, _) = tree_with(3);
        let client = SimplePirClient::from_tree(&tree);
        assert_eq!(client.fetch_membership_path(3), Err(PirError::LeafOutOfRange(3)));
    }
}
