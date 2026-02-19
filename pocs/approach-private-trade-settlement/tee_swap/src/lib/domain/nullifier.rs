use alloy_primitives::B256;

/// A nullifier prevents double-spending by marking a commitment as spent.
/// In the TEE swap protocol, the nullifier is derived from the commitment and salt,
/// making it canonical regardless of which spending path (claim or refund) is used.
/// nullifier = H("tee_swap.nullifier", commitment, salt)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Nullifier(pub B256);

impl Nullifier {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(B256::from(bytes))
    }

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
