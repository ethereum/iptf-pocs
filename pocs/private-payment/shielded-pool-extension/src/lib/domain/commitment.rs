use alloy::primitives::B256;
use serde::{
    Deserialize,
    Serialize,
};

use super::keys::SpendingKey;
use crate::{
    crypto::poseidon::poseidon3,
    domain::{
        epoch::Epoch,
        nullifier::Nullifier,
    },
};

/// A commitment is the on-chain representation of a note.
/// It hides all note contents while allowing proof of ownership.
///
/// Extended vs parent: the preimage now binds `epoch_created`, so
/// `commitment = poseidon5(token, amount, owner_pubkey, salt, epoch_created)`
/// (computed by [`crate::domain::note::Note::commitment`]). Binding the epoch
/// lets the verifier enforce that a note's chain proof covers its full lifetime.
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

    /// Compute the per-epoch nullifier for this commitment.
    ///
    /// `η_e = poseidon3(commitment, spending_key, epoch_id)`
    ///
    /// `epoch` is the epoch the nullifier is derived for, not necessarily the
    /// note's `epoch_created`: the chain proof derives phantom nullifiers for
    /// each past epoch `[epoch_created, currentEpoch - 1]`, and the spend
    /// derives the active nullifier for `currentEpoch`.
    pub fn nullifier(&self, spending_key: &SpendingKey, epoch: Epoch) -> Nullifier {
        let hash = poseidon3(self.0, spending_key.0, epoch.as_field());
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

        let n1 = commitment.nullifier(&sk, Epoch(3));
        let n2 = commitment.nullifier(&sk, Epoch(3));

        assert_eq!(n1, n2);
    }

    #[test]
    fn test_commitment_nullifier_different_keys() {
        let commitment = Commitment(B256::repeat_byte(0x42));
        let sk1 = SpendingKey::from_bytes([0x01; 32]);
        let sk2 = SpendingKey::from_bytes([0x02; 32]);

        assert_ne!(
            commitment.nullifier(&sk1, Epoch(0)),
            commitment.nullifier(&sk2, Epoch(0))
        );
    }

    #[test]
    fn test_commitment_nullifier_different_epochs() {
        // The same note produces a distinct nullifier in each epoch.
        let commitment = Commitment(B256::repeat_byte(0x42));
        let sk = SpendingKey::from_bytes([0x01; 32]);

        assert_ne!(
            commitment.nullifier(&sk, Epoch(0)),
            commitment.nullifier(&sk, Epoch(1))
        );
    }
}
