use serde::{
    Deserialize,
    Serialize,
};

use super::keys::ViewingPubkey;
use crate::domain::commitment::Commitment;

/// An encrypted note payload using ECIES (secp256k1 + ChaCha20-Poly1305).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedNote {
    /// Ephemeral public key used for ECDH (compressed SEC1 format, 33 bytes)
    pub ephemeral_pubkey: Vec<u8>,
    /// Encrypted note data (ChaCha20-Poly1305 ciphertext + tag)
    pub ciphertext: Vec<u8>,
}

impl EncryptedNote {
    /// Create from raw components.
    pub fn new(ephemeral_pubkey: Vec<u8>, ciphertext: Vec<u8>) -> Self {
        Self {
            ephemeral_pubkey,
            ciphertext,
        }
    }

    /// Serialize to bytes for on-chain storage.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes =
            Vec::with_capacity(1 + self.ephemeral_pubkey.len() + self.ciphertext.len());
        bytes.push(self.ephemeral_pubkey.len() as u8);
        bytes.extend_from_slice(&self.ephemeral_pubkey);
        bytes.extend_from_slice(&self.ciphertext);
        bytes
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.is_empty() {
            return Err("Empty bytes");
        }

        let pubkey_len = bytes[0] as usize;
        if bytes.len() < 1 + pubkey_len {
            return Err("Invalid encrypted note format");
        }

        let ephemeral_pubkey = bytes[1..1 + pubkey_len].to_vec();
        let ciphertext = bytes[1 + pubkey_len..].to_vec();

        Ok(Self {
            ephemeral_pubkey,
            ciphertext,
        })
    }
}

/// A P2P message containing an encrypted note and its commitment.
/// Used for off-chain note delivery between transactors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct P2pMessage {
    /// The encrypted note
    pub encrypted_note: EncryptedNote,
    /// The commitment (for identifying the note on-chain)
    pub commitment: Commitment,
    /// The recipient's viewing public key (for routing)
    pub recipient_viewing_pubkey: ViewingPubkey,
}

impl P2pMessage {
    /// Create a new P2P message.
    pub fn new(
        encrypted_note: EncryptedNote,
        commitment: Commitment,
        recipient_viewing_pubkey: ViewingPubkey,
    ) -> Self {
        Self {
            encrypted_note,
            commitment,
            recipient_viewing_pubkey,
        }
    }
}

/// Encrypted notes payload for on-chain transfer events.
/// Contains two encrypted notes (one for each output).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedTransferNotes {
    /// Encrypted note for output 1
    pub note_1: EncryptedNote,
    /// Encrypted note for output 2
    pub note_2: EncryptedNote,
}

impl EncryptedTransferNotes {
    /// Create from two encrypted notes.
    pub fn new(note_1: EncryptedNote, note_2: EncryptedNote) -> Self {
        Self { note_1, note_2 }
    }

    /// Serialize to bytes for on-chain storage.
    pub fn to_bytes(&self) -> Vec<u8> {
        let bytes_1 = self.note_1.to_bytes();
        let bytes_2 = self.note_2.to_bytes();

        let mut bytes = Vec::with_capacity(4 + bytes_1.len() + bytes_2.len());
        bytes.extend_from_slice(&(bytes_1.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&bytes_1);
        bytes.extend_from_slice(&bytes_2);
        bytes
    }

    /// Deserialize from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() < 4 {
            return Err("Invalid encrypted transfer notes format");
        }

        let len_1 = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        if bytes.len() < 4 + len_1 {
            return Err("Invalid encrypted transfer notes format");
        }

        let note_1 = EncryptedNote::from_bytes(&bytes[4..4 + len_1])?;
        let note_2 = EncryptedNote::from_bytes(&bytes[4 + len_1..])?;

        Ok(Self { note_1, note_2 })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypted_note_roundtrip() {
        let note = EncryptedNote::new(vec![0x02; 33], vec![0xAB; 100]);
        let bytes = note.to_bytes();
        let recovered = EncryptedNote::from_bytes(&bytes).unwrap();

        assert_eq!(note.ephemeral_pubkey, recovered.ephemeral_pubkey);
        assert_eq!(note.ciphertext, recovered.ciphertext);
    }

    #[test]
    fn test_encrypted_transfer_notes_roundtrip() {
        let note_1 = EncryptedNote::new(vec![0x02; 33], vec![0xAB; 100]);
        let note_2 = EncryptedNote::new(vec![0x03; 33], vec![0xCD; 80]);
        let notes = EncryptedTransferNotes::new(note_1, note_2);

        let bytes = notes.to_bytes();
        let recovered = EncryptedTransferNotes::from_bytes(&bytes).unwrap();

        assert_eq!(
            notes.note_1.ephemeral_pubkey,
            recovered.note_1.ephemeral_pubkey
        );
        assert_eq!(notes.note_1.ciphertext, recovered.note_1.ciphertext);
        assert_eq!(
            notes.note_2.ephemeral_pubkey,
            recovered.note_2.ephemeral_pubkey
        );
        assert_eq!(notes.note_2.ciphertext, recovered.note_2.ciphertext);
    }
}
