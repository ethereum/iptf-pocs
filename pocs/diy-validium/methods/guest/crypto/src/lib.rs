//! Shared cryptographic primitives for diy-validium guest circuits.
//!
//! Extracts the repetitive crypto boilerplate (SHA-256, Merkle operations,
//! account commitments) so that guest circuits can focus on business logic.

use sha2::{Digest, Sha256};

/// SHA-256 of arbitrary bytes.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// SHA-256(left || right) for Merkle tree internal nodes.
pub fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// Account commitment: SHA256(pubkey || balance_le || salt).
pub fn account_commitment(pubkey: &[u8; 32], balance: u64, salt: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(pubkey);
    hasher.update(balance.to_le_bytes());
    hasher.update(salt);
    hasher.finalize().into()
}

/// Compute the Merkle root by hashing a leaf upward through the proof path.
///
/// Used for membership verification (recompute old root) and single-leaf
/// root update (compute new root) — the logic is identical.
pub fn compute_root(leaf: [u8; 32], path: &[[u8; 32]], indices: &[bool]) -> [u8; 32] {
    let mut current = leaf;
    for (sibling, &is_right) in path.iter().zip(indices.iter()) {
        current = if is_right {
            hash_pair(sibling, &current)
        } else {
            hash_pair(&current, sibling)
        };
    }
    current
}

/// Verify Merkle membership by recomputing root and asserting it matches.
pub fn verify_membership(
    leaf: [u8; 32],
    path: &[[u8; 32]],
    indices: &[bool],
    expected_root: [u8; 32],
) {
    let computed = compute_root(leaf, path, indices);
    assert_eq!(
        computed, expected_root,
        "Merkle root mismatch: membership verification failed"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_deterministic() {
        let a = sha256(b"hello");
        let b = sha256(b"hello");
        assert_eq!(a, b);
    }

    #[test]
    fn test_sha256_different_inputs() {
        let a = sha256(b"hello");
        let b = sha256(b"world");
        assert_ne!(a, b);
    }

    #[test]
    fn test_hash_pair_deterministic() {
        let left = sha256(b"left");
        let right = sha256(b"right");
        let a = hash_pair(&left, &right);
        let b = hash_pair(&left, &right);
        assert_eq!(a, b);
    }

    #[test]
    fn test_hash_pair_order_matters() {
        let left = sha256(b"left");
        let right = sha256(b"right");
        assert_ne!(hash_pair(&left, &right), hash_pair(&right, &left));
    }

    #[test]
    fn test_account_commitment_deterministic() {
        let pubkey = [0xAA; 32];
        let salt = [0xBB; 32];
        let a = account_commitment(&pubkey, 1000, &salt);
        let b = account_commitment(&pubkey, 1000, &salt);
        assert_eq!(a, b);
    }

    #[test]
    fn test_account_commitment_different_balance() {
        let pubkey = [0xAA; 32];
        let salt = [0xBB; 32];
        let a = account_commitment(&pubkey, 1000, &salt);
        let b = account_commitment(&pubkey, 999, &salt);
        assert_ne!(a, b);
    }

    #[test]
    fn test_compute_root_single_level() {
        let leaf = sha256(b"leaf");
        let sibling = sha256(b"sibling");
        // leaf is left child (index false)
        let root = compute_root(leaf, &[sibling], &[false]);
        assert_eq!(root, hash_pair(&leaf, &sibling));
    }

    #[test]
    fn test_compute_root_right_child() {
        let leaf = sha256(b"leaf");
        let sibling = sha256(b"sibling");
        // leaf is right child (index true)
        let root = compute_root(leaf, &[sibling], &[true]);
        assert_eq!(root, hash_pair(&sibling, &leaf));
    }

    #[test]
    fn test_verify_membership_succeeds() {
        let leaf = sha256(b"leaf");
        let sibling = sha256(b"sibling");
        let expected = hash_pair(&leaf, &sibling);
        verify_membership(leaf, &[sibling], &[false], expected);
    }

    #[test]
    #[should_panic(expected = "Merkle root mismatch")]
    fn test_verify_membership_fails_wrong_root() {
        let leaf = sha256(b"leaf");
        let sibling = sha256(b"sibling");
        let wrong = sha256(b"wrong");
        verify_membership(leaf, &[sibling], &[false], wrong);
    }
}
