//! SHA-256 binary Merkle tree for the diy-validium protocol.
//!
//! Provides tree construction, proof generation, proof verification,
//! and account commitment computation as specified in SPEC.md.

use sha2::{Digest, Sha256};

/// A fixed-depth binary Merkle tree using SHA-256 internal nodes.
///
/// Leaves are stored at the bottom layer and padded with `[0u8; 32]`
/// up to `2^depth` entries.
pub struct MerkleTree {
    /// All nodes stored in a flat array. Index 1 is the root.
    /// For a tree of depth `d`, there are `2^(d+1)` slots (index 0 unused).
    nodes: Vec<[u8; 32]>,
    depth: usize,
}

/// A Merkle inclusion proof — the sibling path from leaf to root.
pub struct MerkleProof {
    /// Sibling hashes from leaf level (index 0) up to the root's child level.
    pub path: Vec<[u8; 32]>,
    /// Direction flags: `true` means the current node is the **right** child
    /// at that level (so the sibling is on the left).
    pub indices: Vec<bool>,
}

/// Hash two 32-byte children into a parent: `SHA256(left || right)`.
fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

impl MerkleTree {
    /// Build a Merkle tree with the default depth of 20.
    pub fn new(leaves: &[[u8; 32]]) -> Self {
        Self::from_leaves(leaves, 20)
    }

    /// Build a Merkle tree of the given `depth` from `leaves`.
    ///
    /// The tree has `2^depth` leaf slots. Provided leaves fill the first
    /// positions; remaining slots are padded with `[0u8; 32]`.
    pub fn from_leaves(leaves: &[[u8; 32]], depth: usize) -> Self {
        let num_leaves = 1 << depth; // 2^depth
        let total_nodes = 2 * num_leaves; // indices 0..2*num_leaves-1, index 0 unused

        let mut nodes = vec![[0u8; 32]; total_nodes];

        // Fill leaf layer (starts at index num_leaves).
        for (i, leaf) in leaves.iter().enumerate() {
            nodes[num_leaves + i] = *leaf;
        }
        // Remaining leaf slots are already [0u8; 32] (empty leaf).

        // Build tree bottom-up.
        for i in (1..num_leaves).rev() {
            nodes[i] = hash_pair(&nodes[2 * i], &nodes[2 * i + 1]);
        }

        Self { nodes, depth }
    }

    /// The Merkle root hash.
    pub fn root(&self) -> [u8; 32] {
        self.nodes[1]
    }

    /// The depth (number of levels from leaf to root) of this tree.
    pub fn depth(&self) -> usize {
        self.depth
    }

    /// Generate an inclusion proof for the leaf at `index`.
    pub fn prove(&self, index: usize) -> MerkleProof {
        let num_leaves = 1 << self.depth;
        let mut node_idx = num_leaves + index;

        let mut path = Vec::with_capacity(self.depth);
        let mut indices = Vec::with_capacity(self.depth);

        for _ in 0..self.depth {
            // Determine if current node is a right child (odd index).
            let is_right = node_idx & 1 == 1;
            indices.push(is_right);

            // Sibling is the other child of the same parent.
            let sibling_idx = if is_right { node_idx - 1 } else { node_idx + 1 };
            path.push(self.nodes[sibling_idx]);

            // Move up to parent.
            node_idx /= 2;
        }

        MerkleProof { path, indices }
    }
}

impl MerkleProof {
    /// Verify that `leaf` is included in a tree with the given `root`.
    pub fn verify(&self, leaf: [u8; 32], root: [u8; 32]) -> bool {
        let mut current = leaf;

        for (sibling, &is_right) in self.path.iter().zip(self.indices.iter()) {
            current = if is_right {
                // Current node is the right child; sibling is on the left.
                hash_pair(sibling, &current)
            } else {
                // Current node is the left child; sibling is on the right.
                hash_pair(&current, sibling)
            };
        }

        current == root
    }
}

/// Verify membership by recomputing the Merkle root from a leaf and proof,
/// then asserting it matches `expected_root`.
///
/// This mirrors the circuit logic from SPEC.md (lines 172-193): the circuit
/// performs the same recomputation inside the zkVM and panics on mismatch.
pub fn verify_membership(
    leaf: [u8; 32],
    path: &[[u8; 32]],
    indices: &[bool],
    expected_root: [u8; 32],
) {
    let mut current = leaf;

    for (sibling, &is_right) in path.iter().zip(indices.iter()) {
        current = if is_right {
            hash_pair(sibling, &current)
        } else {
            hash_pair(&current, sibling)
        };
    }

    assert_eq!(
        current, expected_root,
        "Merkle root mismatch: membership verification failed"
    );
}

/// Verify a balance proof as specified in SPEC.md (lines 244-267).
///
/// This mirrors the balance circuit logic: recompute the leaf commitment
/// from `pubkey`, `balance`, and `salt`, verify Merkle membership against
/// `expected_root`, and assert `balance >= required_amount`.
///
/// Panics on any verification failure (invalid membership or insufficient balance).
pub fn verify_balance(
    pubkey: [u8; 32],
    balance: u64,
    salt: [u8; 32],
    path: &[[u8; 32]],
    indices: &[bool],
    expected_root: [u8; 32],
    required_amount: u64,
) {
    // 1. Recompute the leaf commitment
    let leaf = account_commitment(&pubkey, balance, &salt);

    // 2. Verify Merkle membership (panics on mismatch)
    verify_membership(leaf, path, indices, expected_root);

    // 3. Assert balance >= required_amount
    assert!(
        balance >= required_amount,
        "Balance check failed: balance {balance} < required {required_amount}"
    );
}

/// Compute an account commitment as specified in SPEC.md:
/// `SHA256(pubkey || balance_le_bytes || salt)` — 72 bytes input.
pub fn account_commitment(pubkey: &[u8; 32], balance: u64, salt: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(pubkey);
    hasher.update(balance.to_le_bytes());
    hasher.update(salt);
    hasher.finalize().into()
}
