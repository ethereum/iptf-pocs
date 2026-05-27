//! ResilientIdentity credential-layer port.

use serde::{
    Deserialize,
    Serialize,
};

use crate::{
    error::MerkleError,
    types::Bytes32,
};

/// RI Merkle path; siblings are `Bytes32` big-endian.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiPath {
    pub siblings: Vec<Bytes32>,
    pub indices: Vec<u8>,
}

pub trait RiCredentialLayer: Send + Sync {
    /// Append `attr_hash` as the next RI leaf; returns the leaf index.
    fn append_leaf(&mut self, attr_hash: Bytes32, posted_at_block: u64) -> u32;

    fn root(&self) -> Bytes32;

    /// Merkle path for `leaf_index`; signers MUST query via an anonymous transport to preserve unlinkability.
    fn merkle_path(&self, leaf_index: u32) -> Result<RiPath, MerkleError>;

    /// Block at which `root` was first current, or `None`.
    fn root_first_seen(&self, root: &Bytes32) -> Option<u64>;
}
