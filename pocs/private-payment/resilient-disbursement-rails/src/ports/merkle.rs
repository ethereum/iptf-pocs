//! Merkle-store port. Identical shape to the reference identity PoC's
//! `MerkleStore`; `MerklePath` is a generic `(siblings, indices)` shape that
//! works for both the cohort tree (depth 20) and the pool sub-tree (depth
//! 32) via the lean-imt variable-depth API.

use ark_bn254::Fr;

use crate::error::MerkleError;

#[derive(Debug, Clone)]
pub struct MerklePath {
    pub siblings: Vec<Fr>,
    pub indices: Vec<u8>,
}

pub trait MerkleStore: Send + Sync {
    fn root(&self) -> Option<Fr>;
    fn size(&self) -> usize;
    fn get_proof(&self, index: usize) -> Result<MerklePath, MerkleError>;
    fn insert(&mut self, leaf: Fr) -> usize;
}
