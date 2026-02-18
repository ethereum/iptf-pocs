use alloy_primitives::B256;

use crate::crypto::poseidon::{domain_tag, poseidon3};
use crate::domain::nullifier::Nullifier;

/// A commitment is the on-chain representation of a note.
/// It hides all note contents while allowing proof of ownership.
/// commitment = H("tee_swap.commitment", chainId, value, assetId, owner, fallbackOwner, timeout, salt)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Commitment(pub B256);

impl Commitment {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(B256::from(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_ref()
    }

    /// Compute the nullifier for this commitment given the salt.
    /// nullifier = H("tee_swap.nullifier", commitment, salt)
    pub fn nullifier(&self, salt: B256) -> Nullifier {
        let tag = domain_tag("tee_swap.nullifier");
        let hash = poseidon3(tag, self.0, salt);
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
        let salt = B256::repeat_byte(0x01);

        let nullifier1 = commitment.nullifier(salt);
        let nullifier2 = commitment.nullifier(salt);

        assert_eq!(nullifier1, nullifier2);
    }

    #[test]
    fn test_commitment_nullifier_different_salts() {
        let commitment = Commitment(B256::repeat_byte(0x42));
        let salt1 = B256::repeat_byte(0x01);
        let salt2 = B256::repeat_byte(0x02);

        let nullifier1 = commitment.nullifier(salt1);
        let nullifier2 = commitment.nullifier(salt2);

        assert_ne!(nullifier1, nullifier2);
    }
}
