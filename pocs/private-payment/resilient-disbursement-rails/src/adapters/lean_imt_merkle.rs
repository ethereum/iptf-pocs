//! `LeanImtMerkleStore`: variable-depth LeanIMT adapter shared by the
//! cohort tree (max depth 20) and the pool sub-tree (max depth 32). Depth
//! is enforced by the consumer; the lean-imt crate itself is variable-depth.
//!
//! Mirrors the reference identity PoC's adapter.

use ark_bn254::Fr;
use ark_ff::{
    BigInteger,
    PrimeField,
};
use lean_imt::hashed_tree::{
    HashedLeanIMT,
    LeanIMTHasher,
};

use crate::{
    error::MerkleError,
    ports::merkle::{
        MerklePath,
        MerkleStore,
    },
    poseidon::hash_merkle_node,
};

/// Lean-imt hasher adapter: lean-imt concatenates two 32-byte big-endian
/// inputs into a 64-byte buffer; we split, convert to Fr, run our Poseidon
/// `hash_merkle_node`, and convert back.
pub struct PoseidonHasher;

impl LeanIMTHasher<32> for PoseidonHasher {
    fn hash(input: &[u8]) -> [u8; 32] {
        let left = fr_from_be_bytes(&input[..32]);
        let right = fr_from_be_bytes(&input[32..]);
        let result = hash_merkle_node(left, right);
        fr_to_be_bytes(&result)
    }
}

fn fr_from_be_bytes(bytes: &[u8]) -> Fr {
    let mut le = [0u8; 32];
    for i in 0..32 {
        le[i] = bytes[31 - i];
    }
    Fr::from_le_bytes_mod_order(&le)
}

fn fr_to_be_bytes(fr: &Fr) -> [u8; 32] {
    let bigint = fr.into_bigint();
    let le = bigint.to_bytes_le();
    let mut be = [0u8; 32];
    for i in 0..32 {
        be[i] = le[31 - i];
    }
    be
}

pub fn fr_to_hash(fr: &Fr) -> [u8; 32] {
    fr_to_be_bytes(fr)
}

pub fn hash_to_fr(hash: &[u8; 32]) -> Fr {
    fr_from_be_bytes(hash)
}

/// Backed by `zk-kit-lean-imt`. Used for both cohort and pool sub-trees.
pub struct LeanImtMerkleStore {
    tree: HashedLeanIMT<32, PoseidonHasher>,
}

impl LeanImtMerkleStore {
    pub fn new() -> Self {
        Self {
            tree: HashedLeanIMT::<32, PoseidonHasher>::new(&[], PoseidonHasher).unwrap(),
        }
    }
}

impl Default for LeanImtMerkleStore {
    fn default() -> Self {
        Self::new()
    }
}

impl MerkleStore for LeanImtMerkleStore {
    fn root(&self) -> Option<Fr> {
        self.tree.root().map(|h| hash_to_fr(&h))
    }

    fn size(&self) -> usize {
        self.tree.size()
    }

    fn get_proof(&self, index: usize) -> Result<MerklePath, MerkleError> {
        if self.tree.size() == 0 {
            return Err(MerkleError::EmptyTree);
        }
        if index >= self.tree.size() {
            return Err(MerkleError::OutOfRange(index, self.tree.size()));
        }
        let proof = self
            .tree
            .generate_proof(index)
            .map_err(|e| MerkleError::ProofFailure(format!("{e:?}")))?;
        let siblings: Vec<Fr> = proof.siblings.iter().map(|s| hash_to_fr(s)).collect();
        let indices: Vec<u8> = (0..proof.siblings.len())
            .map(|i| ((proof.index >> i) & 1) as u8)
            .collect();
        Ok(MerklePath { siblings, indices })
    }

    fn insert(&mut self, leaf: Fr) -> usize {
        let idx = self.tree.size();
        let hash = fr_to_hash(&leaf);
        self.tree.insert(&hash);
        idx
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verify(leaf: Fr, path: &MerklePath, expected_root: Fr) -> bool {
        if path.siblings.is_empty() {
            return leaf == expected_root;
        }
        let mut current = leaf;
        for (sibling, &index) in path.siblings.iter().zip(path.indices.iter()) {
            current = if index == 0 {
                hash_merkle_node(current, *sibling)
            } else {
                hash_merkle_node(*sibling, current)
            };
        }
        current == expected_root
    }

    #[test]
    fn test_single_leaf() {
        let mut store = LeanImtMerkleStore::new();
        let leaf = Fr::from(42u64);
        store.insert(leaf);
        assert_eq!(store.root(), Some(leaf));
    }

    #[test]
    fn test_two_leaves_proof() {
        let mut store = LeanImtMerkleStore::new();
        let a = Fr::from(10u64);
        let b = Fr::from(20u64);
        store.insert(a);
        store.insert(b);
        let root = store.root().unwrap();
        let path_a = store.get_proof(0).unwrap();
        assert!(verify(a, &path_a, root));
        let path_b = store.get_proof(1).unwrap();
        assert!(verify(b, &path_b, root));
    }

    #[test]
    fn test_five_leaves_proof() {
        let mut store = LeanImtMerkleStore::new();
        let leaves: Vec<Fr> = (1..=5).map(|i| Fr::from(i as u64 * 10)).collect();
        for &leaf in &leaves {
            store.insert(leaf);
        }
        let root = store.root().unwrap();
        for (i, &leaf) in leaves.iter().enumerate() {
            let path = store.get_proof(i).unwrap();
            assert!(verify(leaf, &path, root), "proof failed for leaf {i}");
        }
    }

    #[test]
    fn test_get_proof_out_of_range() {
        let mut store = LeanImtMerkleStore::new();
        store.insert(Fr::from(1u64));
        assert!(matches!(
            store.get_proof(5),
            Err(MerkleError::OutOfRange(5, 1))
        ));
    }

    #[test]
    fn test_get_proof_empty_tree() {
        let store = LeanImtMerkleStore::new();
        assert!(matches!(store.get_proof(0), Err(MerkleError::EmptyTree)));
    }

    #[test]
    fn test_wrong_leaf_fails_verification() {
        let mut store = LeanImtMerkleStore::new();
        store.insert(Fr::from(1u64));
        store.insert(Fr::from(2u64));
        let root = store.root().unwrap();
        let path = store.get_proof(0).unwrap();
        assert!(!verify(Fr::from(999u64), &path, root));
    }
}
