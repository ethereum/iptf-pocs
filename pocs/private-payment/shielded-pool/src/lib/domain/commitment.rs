use alloy::primitives::B256;
use serde::{
    Deserialize,
    Serialize,
};

use crate::{
    crypto::poseidon::poseidon2,
    domain::nullifier::Nullifier,
};

use super::keys::SpendingKey;

/// A commitment is the on-chain representation of a note.
/// It hides all note contents while allowing proof of ownership.
/// commitment = poseidon4(token, amount, owner_pubkey, salt)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Commitment(pub B256);

impl Commitment {
    /// Create a commitment from raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(B256::from(bytes))
    }

    /// Get the raw bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_ref()
    }

    /// Compute the nullifier for this commitment given the spending key.
    /// nullifier = poseidon2(commitment, spending_key)
    pub fn nullifier(&self, spending_key: &SpendingKey) -> Nullifier {
        let hash = poseidon2(self.0, spending_key.0);
        Nullifier(hash)
    }
}

impl From<B256> for Commitment {
    fn from(value: B256) -> Self {
        Self(value)
    }
}

impl From<Commitment> for B256 {
    fn from(value: Commitment) -> Self {
        value.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_commitment_nullifier_deterministic() {
        let commitment = Commitment(B256::repeat_byte(0x42));
        let sk = SpendingKey::from_bytes([0x01; 32]);

        let nullifier1 = commitment.nullifier(&sk);
        let nullifier2 = commitment.nullifier(&sk);

        assert_eq!(nullifier1, nullifier2);
    }

    #[test]
    fn test_commitment_nullifier_different_keys() {
        let commitment = Commitment(B256::repeat_byte(0x42));
        let sk1 = SpendingKey::from_bytes([0x01; 32]);
        let sk2 = SpendingKey::from_bytes([0x02; 32]);

        let nullifier1 = commitment.nullifier(&sk1);
        let nullifier2 = commitment.nullifier(&sk2);

        assert_ne!(nullifier1, nullifier2);
    }
}
