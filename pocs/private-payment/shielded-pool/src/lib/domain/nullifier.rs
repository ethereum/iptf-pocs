use alloy::primitives::B256;
use serde::{
    Deserialize,
    Serialize,
};

/// A nullifier prevents double-spending by marking a commitment as spent.
/// Only the spending key holder can compute the nullifier.
/// nullifier = poseidon2(commitment, spending_key)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Nullifier(pub B256);

impl Nullifier {
    /// Create a nullifier from raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(B256::from(bytes))
    }

    /// Get the raw bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_ref()
    }
}

impl From<B256> for Nullifier {
    fn from(value: B256) -> Self {
        Self(value)
    }
}

impl From<Nullifier> for B256 {
    fn from(value: Nullifier) -> Self {
        value.0
    }
}
