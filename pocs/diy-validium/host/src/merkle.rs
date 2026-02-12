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

/// Verify Merkle membership by recomputing root from leaf and proof path.
fn verify_membership(leaf: [u8; 32], path: &[[u8; 32]], indices: &[bool], expected_root: [u8; 32]) {
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

/// Compute an account commitment as specified in SPEC.md:
/// `SHA256(pubkey || balance_le_bytes || salt)` — 72 bytes input.
pub fn account_commitment(pubkey: &[u8; 32], balance: u64, salt: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(pubkey);
    hasher.update(balance.to_le_bytes());
    hasher.update(salt);
    hasher.finalize().into()
}

/// Recompute a Merkle root after updating two leaves simultaneously.
///
/// When a transfer changes both the sender and recipient leaves, the
/// algorithm finds the shallowest level where the two paths diverge,
/// recomputes each sub-branch independently below that level, joins
/// them as siblings at the divergence point, and continues hashing
/// upward using the shared siblings above divergence.
///
/// See SPEC.md Phase 3, "Dual-Leaf Root Recomputation".
pub fn compute_new_root(
    sender_leaf: [u8; 32],
    sender_indices: &[bool],
    recipient_leaf: [u8; 32],
    recipient_indices: &[bool],
    sender_path: &[[u8; 32]],
    recipient_path: &[[u8; 32]],
) -> [u8; 32] {
    let depth = sender_indices.len();

    // Proof arrays are leaf-to-root: path[0] is the leaf-level sibling,
    // path[depth-1] is the root-adjacent sibling.
    //
    // Find divergence: the shallowest level (closest to root) where
    // sender_indices and recipient_indices differ. In our leaf-to-root
    // indexing this is the highest array index where they differ.
    let divergence = (0..depth)
        .rev()
        .find(|&i| sender_indices[i] != recipient_indices[i])
        .expect("Sender and recipient must differ (no self-transfers)");

    // Recompute sender's branch from leaf (level 0) up to but not
    // including the divergence level.
    let mut sender_hash = sender_leaf;
    for i in 0..divergence {
        sender_hash = if sender_indices[i] {
            hash_pair(&sender_path[i], &sender_hash)
        } else {
            hash_pair(&sender_hash, &sender_path[i])
        };
    }

    // Recompute recipient's branch from leaf up to but not including
    // the divergence level.
    let mut recipient_hash = recipient_leaf;
    for i in 0..divergence {
        recipient_hash = if recipient_indices[i] {
            hash_pair(&recipient_path[i], &recipient_hash)
        } else {
            hash_pair(&recipient_hash, &recipient_path[i])
        };
    }

    // At the divergence level the two recomputed branches are siblings.
    let mut current = if sender_indices[divergence] {
        // Sender is right child, recipient is left child
        hash_pair(&recipient_hash, &sender_hash)
    } else {
        // Sender is left child, recipient is right child
        hash_pair(&sender_hash, &recipient_hash)
    };

    // Above divergence: continue hashing toward the root using the
    // shared siblings (same in both paths above the divergence point).
    for i in (divergence + 1)..depth {
        current = if sender_indices[i] {
            hash_pair(&sender_path[i], &current)
        } else {
            hash_pair(&current, &sender_path[i])
        };
    }

    current
}

/// Verify a transfer proof as specified in SPEC.md Phase 3 circuit logic.
///
/// This mirrors the transfer circuit: derives the sender pubkey from the
/// secret key, verifies both accounts in the old tree, checks balance
/// constraints, verifies the nullifier, computes new commitments, and
/// asserts the new root matches.
///
/// Panics on any verification failure.
#[allow(clippy::too_many_arguments)]
pub fn verify_transfer(
    sender_sk: [u8; 32],
    sender_balance: u64,
    sender_salt: [u8; 32],
    sender_path: &[[u8; 32]],
    sender_indices: &[bool],
    amount: u64,
    recipient_pubkey: [u8; 32],
    recipient_balance: u64,
    recipient_salt: [u8; 32],
    recipient_path: &[[u8; 32]],
    recipient_indices: &[bool],
    new_sender_salt: [u8; 32],
    new_recipient_salt: [u8; 32],
    old_root: [u8; 32],
    new_root: [u8; 32],
    nullifier: [u8; 32],
) {
    // 1. Derive sender pubkey from secret key
    let sender_pubkey = sha256_hash(&sender_sk);

    // 2. Prohibit self-transfers
    assert_ne!(sender_pubkey, recipient_pubkey, "Self-transfer not allowed");

    // 3. Compute sender's old leaf commitment and verify in old tree
    let sender_old_leaf = account_commitment(&sender_pubkey, sender_balance, &sender_salt);
    verify_membership(sender_old_leaf, sender_path, sender_indices, old_root);

    // 4. Compute recipient's old leaf commitment and verify in old tree
    let recipient_old_leaf =
        account_commitment(&recipient_pubkey, recipient_balance, &recipient_salt);
    verify_membership(
        recipient_old_leaf,
        recipient_path,
        recipient_indices,
        old_root,
    );

    // 5. Check positive transfer amount
    assert!(amount > 0, "Transfer amount must be positive");

    // 6. Check sufficient sender balance (underflow protection)
    assert!(sender_balance >= amount, "Insufficient balance");

    // 7. Check recipient overflow protection
    assert!(
        recipient_balance <= u64::MAX - amount,
        "Recipient balance overflow"
    );

    // 8. Compute and verify state-bound nullifier
    let computed_nullifier = sha256_hash(&[&sender_sk[..], &old_root[..], b"transfer_v1"].concat());
    assert_eq!(computed_nullifier, nullifier, "Nullifier mismatch");

    // 9. Compute new balances (safe after checks in steps 5-7)
    let new_sender_balance = sender_balance - amount;
    let new_recipient_balance = recipient_balance + amount;

    // 10. Compute new leaf commitments
    let sender_new_leaf = account_commitment(&sender_pubkey, new_sender_balance, &new_sender_salt);
    let recipient_new_leaf = account_commitment(
        &recipient_pubkey,
        new_recipient_balance,
        &new_recipient_salt,
    );

    // 11. Recompute new root with both leaves updated
    let computed_new_root = compute_new_root(
        sender_new_leaf,
        sender_indices,
        recipient_new_leaf,
        recipient_indices,
        sender_path,
        recipient_path,
    );
    assert_eq!(
        computed_new_root, new_root,
        "New root mismatch: state transition verification failed"
    );
}

/// Compute the Merkle root after replacing a leaf with `new_leaf`.
///
/// This is a single-leaf root update: hash the new leaf upward through
/// the same Merkle path, reusing the original siblings. Equivalent to
/// Merkle membership verification but returns the computed root instead
/// of asserting equality.
///
/// See SPEC.md Phase 4, "Single-Leaf Root Update".
pub fn compute_single_leaf_root(
    new_leaf: [u8; 32],
    path: &[[u8; 32]],
    indices: &[bool],
) -> [u8; 32] {
    let mut current = new_leaf;
    for (sibling, &is_right) in path.iter().zip(indices.iter()) {
        current = if is_right {
            hash_pair(sibling, &current)
        } else {
            hash_pair(&current, sibling)
        };
    }
    current
}

/// Verify a withdrawal proof as specified in SPEC.md Phase 4 circuit logic.
///
/// This mirrors the withdrawal circuit: derives the pubkey from the secret
/// key, verifies account membership in the old tree, checks balance
/// constraints, verifies the nullifier, computes the new commitment with
/// reduced balance, and asserts the new root matches via single-leaf update.
///
/// The `recipient` parameter is committed to the journal in the guest for
/// on-chain use but does not affect the circuit's state transition logic.
///
/// Panics on any verification failure.
#[allow(clippy::too_many_arguments)]
pub fn verify_withdrawal(
    secret_key: [u8; 32],
    balance: u64,
    salt: [u8; 32],
    path: &[[u8; 32]],
    indices: &[bool],
    amount: u64,
    new_salt: [u8; 32],
    _recipient: [u8; 20],
    old_root: [u8; 32],
    new_root: [u8; 32],
    nullifier: [u8; 32],
) {
    // 1. Derive pubkey from secret key
    let pubkey = sha256_hash(&secret_key);

    // 2. Compute old leaf commitment
    let old_leaf = account_commitment(&pubkey, balance, &salt);

    // 3. Verify membership in old tree
    verify_membership(old_leaf, path, indices, old_root);

    // 4. Check amount > 0
    assert!(amount > 0, "Withdrawal amount must be positive");

    // 5. Check balance >= amount
    assert!(balance >= amount, "Insufficient balance");

    // 6. Compute and verify state-bound nullifier
    let computed_nullifier =
        sha256_hash(&[&secret_key[..], &old_root[..], b"withdrawal_v1"].concat());
    assert_eq!(computed_nullifier, nullifier, "Nullifier mismatch");

    // 7. Compute new balance
    let new_balance = balance - amount;

    // 8. Compute new leaf commitment with reduced balance and fresh salt
    let new_leaf = account_commitment(&pubkey, new_balance, &new_salt);

    // 9. Compute new root via single-leaf update
    let computed_new_root = compute_single_leaf_root(new_leaf, path, indices);
    assert_eq!(
        computed_new_root, new_root,
        "New root mismatch: state transition verification failed"
    );
}

/// Compute the disclosure key hash as specified in SPEC.md Phase 4:
/// `SHA256(pubkey || auditor_pubkey || "disclosure_v1")`
///
/// The disclosure key binds the proof to a specific account (via pubkey)
/// and a specific auditor (via auditor_pubkey), with domain separation.
pub fn compute_disclosure_key_hash(pubkey: &[u8; 32], auditor_pubkey: &[u8; 32]) -> [u8; 32] {
    sha256_hash(&[&pubkey[..], &auditor_pubkey[..], b"disclosure_v1"].concat())
}

/// Verify a disclosure proof as specified in SPEC.md Phase 4 circuit logic.
///
/// This mirrors the disclosure circuit: derives the pubkey from the secret
/// key, verifies the account exists in the tree, checks balance >= threshold,
/// and verifies the disclosure key hash binds to the correct account and auditor.
///
/// This is a read-only attestation — no nullifier, no state mutation.
///
/// Panics on any verification failure.
#[allow(clippy::too_many_arguments)]
pub fn verify_disclosure(
    secret_key: [u8; 32],
    balance: u64,
    salt: [u8; 32],
    path: &[[u8; 32]],
    indices: &[bool],
    threshold: u64,
    auditor_pubkey: [u8; 32],
    expected_root: [u8; 32],
    expected_disclosure_key_hash: [u8; 32],
) {
    // 1. Derive pubkey from secret key
    let pubkey = sha256_hash(&secret_key);

    // 2. Compute leaf commitment
    let leaf = account_commitment(&pubkey, balance, &salt);

    // 3. Verify Merkle membership (panics on mismatch)
    verify_membership(leaf, path, indices, expected_root);

    // 4. Assert balance >= threshold
    assert!(
        balance >= threshold,
        "Balance below threshold: balance {balance} < threshold {threshold}"
    );

    // 5. Compute and verify disclosure key hash
    let computed_dkh = compute_disclosure_key_hash(&pubkey, &auditor_pubkey);
    assert_eq!(
        computed_dkh, expected_disclosure_key_hash,
        "Disclosure key hash mismatch"
    );
}

/// Helper: compute SHA-256 of input bytes.
fn sha256_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}
