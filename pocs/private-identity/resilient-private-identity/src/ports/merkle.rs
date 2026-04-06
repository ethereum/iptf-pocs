use ark_bn254::Fr;

use crate::types::MerklePath;

pub trait MerkleStore: Send + Sync {
    fn root(&self) -> Option<Fr>;
    fn size(&self) -> usize;
    fn get_proof(&self, index: usize) -> MerklePath;
    fn insert(&mut self, leaf: Fr) -> usize;
}
