//! In-process ResilientIdentity stand-in backed by `zk-kit-lean-imt`.

use std::collections::HashMap;

use lean_imt::hashed_tree::{
    HashedLeanIMT,
    LeanIMTHasher,
};

use crate::{
    error::MerkleError,
    ports::ri::{
        RiCredentialLayer,
        RiPath,
    },
    poseidon::{
        fr_from_be_bytes,
        fr_to_be_bytes,
        hash_merkle_node,
    },
    types::Bytes32,
};

/// `LeanIMTHasher` adapter using Poseidon1 `hash_merkle_node`.
pub struct PoseidonHasher;

impl LeanIMTHasher<32> for PoseidonHasher {
    fn hash(input: &[u8]) -> [u8; 32] {
        let left: &[u8; 32] = input[..32]
            .try_into()
            .expect("LeanIMTHasher contract: 64-byte input");
        let right: &[u8; 32] = input[32..]
            .try_into()
            .expect("LeanIMTHasher contract: 64-byte input");
        let result = hash_merkle_node(fr_from_be_bytes(left), fr_from_be_bytes(right));
        fr_to_be_bytes(&result)
    }
}

pub struct InMemoryRi {
    tree: HashedLeanIMT<32, PoseidonHasher>,
    root_first_seen: HashMap<Bytes32, u64>,
}

impl InMemoryRi {
    pub fn new() -> Self {
        let tree = HashedLeanIMT::<32, PoseidonHasher>::new(&[], PoseidonHasher)
            .expect("HashedLeanIMT::new");
        let mut s = Self {
            tree,
            root_first_seen: HashMap::new(),
        };
        let r = s.root();
        s.root_first_seen.entry(r).or_insert(0);
        s
    }
}

impl Default for InMemoryRi {
    fn default() -> Self {
        Self::new()
    }
}

impl RiCredentialLayer for InMemoryRi {
    fn append_leaf(&mut self, attr_hash: Bytes32, posted_at_block: u64) -> u32 {
        let idx = self.tree.size();
        self.tree.insert(&attr_hash);
        let r = self.root();
        self.root_first_seen.entry(r).or_insert(posted_at_block);
        idx as u32
    }

    fn root(&self) -> Bytes32 {
        self.tree.root().unwrap_or([0u8; 32])
    }

    fn merkle_path(&self, leaf_index: u32) -> Result<RiPath, MerkleError> {
        if self.tree.size() == 0 {
            return Err(MerkleError::EmptyTree);
        }
        if (leaf_index as usize) >= self.tree.size() {
            return Err(MerkleError::OutOfRange(
                leaf_index as usize,
                self.tree.size(),
            ));
        }
        let proof = self
            .tree
            .generate_proof(leaf_index as usize)
            .map_err(|e| MerkleError::ProofFailure(format!("{e:?}")))?;
        let siblings: Vec<Bytes32> = proof.siblings.clone();
        // lean-imt encodes path direction in `proof.index`: bit i = 0 means left child.
        let indices: Vec<u8> = (0..proof.siblings.len())
            .map(|i| ((proof.index >> i) & 1) as u8)
            .collect();
        Ok(RiPath { siblings, indices })
    }

    fn root_first_seen(&self, root: &Bytes32) -> Option<u64> {
        self.root_first_seen.get(root).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fr_be(v: u64) -> Bytes32 {
        let mut b = [0u8; 32];
        b[24..].copy_from_slice(&v.to_be_bytes());
        b
    }

    #[test]
    fn test_empty_tree_root_recorded() {
        let ri = InMemoryRi::new();
        let r = ri.root();
        assert_eq!(ri.root_first_seen(&r), Some(0));
    }

    #[test]
    fn test_append_records_block() {
        let mut ri = InMemoryRi::new();
        ri.append_leaf(fr_be(7), 100);
        let r = ri.root();
        assert_eq!(ri.root_first_seen(&r), Some(100));
    }

    #[test]
    fn test_path_verifies_against_root() {
        let mut ri = InMemoryRi::new();
        ri.append_leaf(fr_be(1), 0);
        ri.append_leaf(fr_be(2), 0);
        ri.append_leaf(fr_be(3), 0);
        let root_be = ri.root();
        let path = ri.merkle_path(1).unwrap();
        let mut current = fr_from_be_bytes(&fr_be(2));
        for (s, &dir) in path.siblings.iter().zip(path.indices.iter()) {
            let s_fr = fr_from_be_bytes(s);
            current = if dir == 0 {
                hash_merkle_node(current, s_fr)
            } else {
                hash_merkle_node(s_fr, current)
            };
        }
        assert_eq!(fr_to_be_bytes(&current), root_be);
    }

    #[test]
    fn test_path_out_of_range() {
        let mut ri = InMemoryRi::new();
        ri.append_leaf(fr_be(1), 0);
        let err = ri.merkle_path(5);
        assert!(matches!(err, Err(MerkleError::OutOfRange(5, 1))));
    }
}
