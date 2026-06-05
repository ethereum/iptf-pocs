use alloy::primitives::B256;
use serde::{
    Deserialize,
    Serialize,
};

/// A nullifier prevents double-spending by marking a commitment as spent in a
/// given epoch. Only the spending-key holder can compute it.
///
/// In this extension the nullifier is per-epoch:
/// `η_e = poseidon3(commitment, spending_key, epoch_id)` (see
/// [`crate::domain::commitment::Commitment::nullifier`]). The same note yields a
/// distinct nullifier in each epoch; whether a given `η_e` is "active" (current
/// epoch, becomes the on-chain spend artifact) or "phantom" (a past epoch in
/// which the note was not spent, used only for chain-proof non-membership) is
/// contextual and tracked by the chain-proof / spend layers, not by this value.
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
