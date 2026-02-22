use alloy_primitives::{B256, U256};
use rand::Rng;

use super::commitment::Commitment;
use super::nullifier::Nullifier;
use crate::crypto::poseidon::{
    DOMAIN_COMMITMENT, DOMAIN_NULLIFIER, poseidon3, poseidon8,
};

/// A time-locked note representing a private UTXO in the TEE swap protocol.
///
/// Notes support dual spending conditions: a primary owner (stealth address)
/// for claiming, and a fallback owner for refunding after timeout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Note {
    /// Network identifier (binds note to a specific chain)
    pub chain_id: B256,
    /// Amount (uint64)
    pub value: u64,
    /// Asset identifier (e.g. USD, BOND)
    pub asset_id: B256,
    /// Primary owner — stealth address public key
    pub owner: B256,
    /// Fallback owner — original owner for refund path
    pub fallback_owner: B256,
    /// Timestamp after which fallback owner can spend
    pub timeout: B256,
    /// Random blinding factor
    pub salt: B256,
}

impl Note {
    /// Create a new note with a random salt.
    pub fn new(
        chain_id: B256,
        value: u64,
        asset_id: B256,
        owner: B256,
        fallback_owner: B256,
        timeout: B256,
    ) -> Self {
        let mut rng = rand::thread_rng();
        let mut salt_bytes = [0u8; 32];
        rng.fill(&mut salt_bytes);
        salt_bytes[0] &= 0x1F; // zero top 3 bits → 253-bit, safe for XOR in BN254 field

        Self {
            chain_id,
            value,
            asset_id,
            owner,
            fallback_owner,
            timeout,
            salt: B256::from(salt_bytes),
        }
    }

    /// Create a note with a specific salt (for testing or reconstruction).
    pub fn with_salt(
        chain_id: B256,
        value: u64,
        asset_id: B256,
        owner: B256,
        fallback_owner: B256,
        timeout: B256,
        salt: B256,
    ) -> Self {
        Self {
            chain_id,
            value,
            asset_id,
            owner,
            fallback_owner,
            timeout,
            salt,
        }
    }

    /// Compute the commitment for this note.
    /// commitment = H(DOMAIN_COMMITMENT, chainId, value, assetId, owner, fallbackOwner, timeout, salt)
    pub fn commitment(&self) -> Commitment {
        let value_b256: B256 = U256::from(self.value).into();

        let hash = poseidon8(
            DOMAIN_COMMITMENT,
            self.chain_id,
            value_b256,
            self.asset_id,
            self.owner,
            self.fallback_owner,
            self.timeout,
            self.salt,
        );
        Commitment(hash)
    }

    /// Compute the nullifier for this note.
    /// nullifier = H(DOMAIN_NULLIFIER, commitment, salt)
    ///
    /// The nullifier is canonical — it is the same regardless of whether
    /// the claim path or the refund path is used to spend the note.
    pub fn nullifier(&self) -> Nullifier {
        let commitment = self.commitment();
        let hash = poseidon3(DOMAIN_NULLIFIER, commitment.0, self.salt);
        Nullifier(hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_note() -> Note {
        Note::with_salt(
            B256::left_padding_from(&[1]),          // chain_id = 1
            1000,                                   // value
            B256::repeat_byte(0xAA),                // asset_id
            B256::repeat_byte(0xBB),                // owner
            B256::repeat_byte(0xCC),                // fallback_owner
            B256::left_padding_from(&[0x01, 0x00]), // timeout
            B256::repeat_byte(0x01),                // salt
        )
    }

    #[test]
    fn test_note_commitment_deterministic() {
        let note1 = test_note();
        let note2 = test_note();

        assert_eq!(note1.commitment(), note2.commitment());
    }

    #[test]
    fn test_note_commitment_different_salts() {
        let note1 = Note::new(
            B256::left_padding_from(&[1]),
            1000,
            B256::repeat_byte(0xAA),
            B256::repeat_byte(0xBB),
            B256::repeat_byte(0xCC),
            B256::ZERO,
        );
        let note2 = Note::new(
            B256::left_padding_from(&[1]),
            1000,
            B256::repeat_byte(0xAA),
            B256::repeat_byte(0xBB),
            B256::repeat_byte(0xCC),
            B256::ZERO,
        );

        // Random salts should produce different commitments
        assert_ne!(note1.commitment(), note2.commitment());
    }

    #[test]
    fn test_note_nullifier_deterministic() {
        let note = test_note();

        let nullifier1 = note.nullifier();
        let nullifier2 = note.nullifier();

        assert_eq!(nullifier1, nullifier2, "Nullifier should be deterministic");
    }

    #[test]
    fn test_note_nullifier_canonical() {
        // The nullifier depends on commitment + salt, not on a spending key.
        // This ensures the same nullifier is produced regardless of claim vs refund path.
        let note = test_note();
        let commitment = note.commitment();

        // Nullifier computed via Note should match Commitment::nullifier(salt)
        let nullifier_via_note = note.nullifier();
        let nullifier_via_commitment = commitment.nullifier(note.salt);

        assert_eq!(nullifier_via_note, nullifier_via_commitment);
    }

    #[test]
    fn test_note_different_values_different_commitments() {
        let note1 = Note::with_salt(
            B256::left_padding_from(&[1]),
            1000,
            B256::repeat_byte(0xAA),
            B256::repeat_byte(0xBB),
            B256::repeat_byte(0xCC),
            B256::ZERO,
            B256::repeat_byte(0x01),
        );
        let note2 = Note::with_salt(
            B256::left_padding_from(&[1]),
            2000, // different value
            B256::repeat_byte(0xAA),
            B256::repeat_byte(0xBB),
            B256::repeat_byte(0xCC),
            B256::ZERO,
            B256::repeat_byte(0x01),
        );

        assert_ne!(note1.commitment(), note2.commitment());
    }

    #[test]
    fn test_note_different_owners_different_commitments() {
        let note1 = Note::with_salt(
            B256::left_padding_from(&[1]),
            1000,
            B256::repeat_byte(0xAA),
            B256::repeat_byte(0xBB), // owner
            B256::repeat_byte(0xCC),
            B256::ZERO,
            B256::repeat_byte(0x01),
        );
        let note2 = Note::with_salt(
            B256::left_padding_from(&[1]),
            1000,
            B256::repeat_byte(0xAA),
            B256::repeat_byte(0xDD), // different owner
            B256::repeat_byte(0xCC),
            B256::ZERO,
            B256::repeat_byte(0x01),
        );

        assert_ne!(note1.commitment(), note2.commitment());
    }
}
