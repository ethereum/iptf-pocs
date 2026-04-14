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
    ports::merkle::MerkleStore,
    poseidon::hash_merkle_node,
    types::MerklePath,
};

/// Poseidon hasher adapter for lean-imt's `LeanIMTHasher` trait.
///
/// The lean-imt crate concatenates left(32) || right(32) and passes
/// the 64 bytes to this hash function for binary tree nodes.
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

/// Convert an Fr element to its 32-byte big-endian hash representation.
pub fn fr_to_hash(fr: &Fr) -> [u8; 32] {
    fr_to_be_bytes(fr)
}

/// Convert a 32-byte big-endian hash back to an Fr element.
pub fn hash_to_fr(hash: &[u8; 32]) -> Fr {
    fr_from_be_bytes(hash)
}

/// Merkle store backed by `zk-kit-lean-imt`.
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

impl MerkleStore for LeanImtMerkleStore {
    fn root(&self) -> Option<Fr> {
        self.tree.root().map(|h| hash_to_fr(&h))
    }

    fn size(&self) -> usize {
        self.tree.size()
    }

    fn get_proof(&self, index: usize) -> MerklePath {
        let proof = self.tree.generate_proof(index).unwrap();

        // lean-imt's MerkleProof stores:
        //   - siblings: Vec<[u8; 32]>   -- sibling at each proof level
        //   - index: usize              -- bit-packed path (bit i: 0=left, 1=right)
        //
        // Our MerklePath wants:
        //   - siblings: Vec<Fr>
        //   - indices: Vec<u8>          -- per-level direction (0=left, 1=right)
        //
        // The lean-imt proof may have fewer siblings than tree depth when a
        // level has an odd count (no sibling exists for the last node). The
        // bit at position i in proof.index tells us the direction at level i.

        let siblings: Vec<Fr> = proof.siblings.iter().map(|s| hash_to_fr(s)).collect();

        let indices: Vec<u8> = (0..proof.siblings.len())
            .map(|i| ((proof.index >> i) & 1) as u8)
            .collect();

        MerklePath { siblings, indices }
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
    use crate::domain::merkle::verify;

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

        let path_a = store.get_proof(0);
        assert!(verify(a, &path_a, root));

        let path_b = store.get_proof(1);
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
            let path = store.get_proof(i);
            assert!(verify(leaf, &path, root), "proof failed for leaf {i}");
        }
    }

    #[test]
    fn test_incremental_root_changes() {
        let mut store = LeanImtMerkleStore::new();
        store.insert(Fr::from(1u64));
        let r1 = store.root();
        store.insert(Fr::from(2u64));
        let r2 = store.root();
        assert_ne!(r1, r2);
    }

    #[test]
    fn test_wrong_leaf_fails_verification() {
        let mut store = LeanImtMerkleStore::new();
        store.insert(Fr::from(1u64));
        store.insert(Fr::from(2u64));
        let root = store.root().unwrap();
        let path = store.get_proof(0);
        assert!(!verify(Fr::from(999u64), &path, root));
    }
}
