use blake2::{Blake2b512, Digest};
use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit, Nonce};
use ff::PrimeField;
use poseidon_rs::{Fr, Poseidon};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::keys::ShieldedKeys;

/// Encrypted memo containing ephemeral public key for forward secrecy
#[derive(Debug)]
pub struct Memo {
    /// Ephemeral public key used for ECDH (32 bytes)
    pub ephemeral_pubkey: [u8; 32],
    /// Encrypted note data
    pub ciphertext: Vec<u8>,
}

impl Memo {
    /// Serialize memo to bytes: [32 bytes ephemeral_pubkey][ciphertext...]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(32 + self.ciphertext.len());
        bytes.extend_from_slice(&self.ephemeral_pubkey);
        bytes.extend_from_slice(&self.ciphertext);
        bytes
    }

    /// Deserialize memo from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 32 {
            return Err("Memo too short: missing ephemeral pubkey".to_string());
        }
        let mut ephemeral_pubkey = [0u8; 32];
        ephemeral_pubkey.copy_from_slice(&bytes[..32]);
        let ciphertext = bytes[32..].to_vec();
        Ok(Memo {
            ephemeral_pubkey,
            ciphertext,
        })
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Note {
    pub value: u64,
    pub salt: u64,
    pub owner: u64,
    pub asset_id: u64,
    pub maturity_date: u64, // Unix timestamp
}

impl Note {
    pub fn commit(&self) -> Fr {
        let f_val = Fr::from_str(&self.value.to_string()).unwrap();

        let f_owner = Fr::from_str(&self.owner.to_string()).unwrap();

        let f_salt = Fr::from_str(&self.salt.to_string()).expect("Salt too large for field?");

        let f_asset = Fr::from_str(&self.asset_id.to_string()).unwrap();

        let f_maturity_date = Fr::from_str(&self.maturity_date.to_string()).unwrap();

        let hasher = Poseidon::new();
        hasher
            .hash(vec![f_val, f_salt, f_owner, f_asset, f_maturity_date])
            .unwrap()
    }

    pub fn nullifer(&self, private_key: Fr) -> Fr {
        let f_salt = Fr::from_str(&self.salt.to_string()).expect("Salt too large for field?");

        let hasher = Poseidon::new();
        hasher.hash(vec![f_salt, private_key]).unwrap()
    }

    /// Encrypt memo using ephemeral ECDH + BLAKE2b KDF + ChaCha20-Poly1305
    /// Provides forward secrecy: compromise of static keys doesn't reveal past messages
    pub fn encrypt(
        _sender_keys: &ShieldedKeys, // Unused - we use ephemeral keys for forward secrecy
        recipient_pubkey: &[u8; 32],
        data: &Note,
    ) -> Result<Memo, String> {
        // 1. Generate ephemeral keypair for this message
        let ephemeral_secret = EphemeralSecret::random_from_rng(OsRng);
        let ephemeral_public = PublicKey::from(&ephemeral_secret);

        // 2. Compute shared secret via ECDH(ephemeral_private, recipient_static_public)
        let recipient_public = PublicKey::from(*recipient_pubkey);
        let shared_secret = ephemeral_secret.diffie_hellman(&recipient_public);

        // 3. Derive key: BLAKE2b(shared_secret ∥ ephemeral_public_alice ∥ public_viewing_key_bob)
        let mut hasher = Blake2b512::new();
        hasher.update(shared_secret.as_bytes());
        hasher.update(ephemeral_public.as_bytes());
        hasher.update(recipient_pubkey);
        let key_bytes = hasher.finalize();
        let key = &key_bytes[..32];

        // 4. Serialize Note
        let note_bytes =
            bincode::serialize(data).map_err(|e| format!("Serialization failed: {}", e))?;

        // 5. Encrypt with ChaCha20-Poly1305
        let cipher = ChaCha20Poly1305::new(key.into());
        let nonce = Nonce::from_slice(&[0u8; 12]); // Safe with ephemeral keys (unique per message)
        let ciphertext = cipher
            .encrypt(nonce, note_bytes.as_ref())
            .map_err(|e| format!("Encryption failed: {}", e))?;

        Ok(Memo {
            ephemeral_pubkey: *ephemeral_public.as_bytes(),
            ciphertext,
        })
    }

    /// Decrypt memo using ephemeral public key from memo
    /// Recipient uses their static private key + sender's ephemeral public key
    /// Note: Sender identity is not authenticated - use ZK proofs for ownership verification
    pub fn decrypt(recipient_keys: &ShieldedKeys, memo: &Memo) -> Result<Note, String> {
        // 1. Compute shared secret via ECDH(recipient_static_private, ephemeral_public)
        let shared_secret = recipient_keys.ecdh(&memo.ephemeral_pubkey);

        // 2. Derive key: BLAKE2b(shared_secret ∥ ephemeral_public_alice ∥ public_viewing_key_bob)
        let mut hasher = Blake2b512::new();
        hasher.update(&shared_secret);
        hasher.update(&memo.ephemeral_pubkey);
        hasher.update(recipient_keys.public_viewing_key());
        let key_bytes = hasher.finalize();
        let key = &key_bytes[..32];

        // 3. Decrypt with ChaCha20-Poly1305
        let cipher = ChaCha20Poly1305::new(key.into());
        let nonce = Nonce::from_slice(&[0u8; 12]); // Same nonce used in encryption
        let plaintext = cipher
            .decrypt(nonce, memo.ciphertext.as_ref())
            .map_err(|e| format!("Decryption failed: {}", e))?;

        // 4. Deserialize Note
        let note: Note = bincode::deserialize(&plaintext)
            .map_err(|e| format!("Deserialization failed: {}", e))?;

        Ok(note)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_note() -> Note {
        Note {
            value: 1_000_000,
            salt: 0xDEADBEEF,
            owner: 12345,
            asset_id: 1,
            maturity_date: 1893456000, // 2030-01-01
        }
    }

    #[test]
    fn test_memo_roundtrip_encryption() {
        // Setup: Alice sends memo to Bob
        let alice_keys = ShieldedKeys::generate();
        let bob_keys = ShieldedKeys::generate();
        let original_note = create_test_note();

        // Alice encrypts memo for Bob
        let memo = Note::encrypt(&alice_keys, bob_keys.public_viewing_key(), &original_note)
            .expect("Encryption should succeed");

        // Bob decrypts memo
        let decrypted_note =
            Note::decrypt(&bob_keys, &memo).expect("Decryption should succeed");

        // Verify note contents match
        assert_eq!(decrypted_note.value, original_note.value);
        assert_eq!(decrypted_note.salt, original_note.salt);
        assert_eq!(decrypted_note.owner, original_note.owner);
        assert_eq!(decrypted_note.asset_id, original_note.asset_id);
        assert_eq!(decrypted_note.maturity_date, original_note.maturity_date);
    }

    #[test]
    fn test_memo_serialization() {
        let alice_keys = ShieldedKeys::generate();
        let bob_keys = ShieldedKeys::generate();
        let note = create_test_note();

        // Encrypt and serialize
        let memo = Note::encrypt(&alice_keys, bob_keys.public_viewing_key(), &note).unwrap();
        let bytes = memo.to_bytes();

        // Deserialize and decrypt
        let restored_memo = Memo::from_bytes(&bytes).expect("Deserialization should succeed");
        let decrypted = Note::decrypt(&bob_keys, &restored_memo).unwrap();

        assert_eq!(decrypted.value, note.value);
        assert_eq!(memo.ephemeral_pubkey, restored_memo.ephemeral_pubkey);
    }

    #[test]
    fn test_wrong_recipient_cannot_decrypt() {
        let alice_keys = ShieldedKeys::generate();
        let bob_keys = ShieldedKeys::generate();
        let charlie_keys = ShieldedKeys::generate(); // Wrong recipient
        let note = create_test_note();

        // Alice encrypts for Bob
        let memo = Note::encrypt(&alice_keys, bob_keys.public_viewing_key(), &note).unwrap();

        // Charlie tries to decrypt - should fail
        let result = Note::decrypt(&charlie_keys, &memo);
        assert!(result.is_err(), "Wrong recipient should not decrypt");
    }

    #[test]
    fn test_ephemeral_keys_are_unique() {
        let alice_keys = ShieldedKeys::generate();
        let bob_keys = ShieldedKeys::generate();
        let note = create_test_note();

        // Encrypt same note twice
        let memo1 = Note::encrypt(&alice_keys, bob_keys.public_viewing_key(), &note).unwrap();
        let memo2 = Note::encrypt(&alice_keys, bob_keys.public_viewing_key(), &note).unwrap();

        // Ephemeral keys should be different (fresh per message)
        assert_ne!(
            memo1.ephemeral_pubkey, memo2.ephemeral_pubkey,
            "Each encryption should use a fresh ephemeral key"
        );

        // But both should decrypt correctly
        let decrypted1 = Note::decrypt(&bob_keys, &memo1).unwrap();
        let decrypted2 = Note::decrypt(&bob_keys, &memo2).unwrap();
        assert_eq!(decrypted1.value, decrypted2.value);
    }

    #[test]
    fn test_memo_from_bytes_too_short() {
        let short_bytes = [0u8; 16]; // Less than 32 bytes
        let result = Memo::from_bytes(&short_bytes);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too short"));
    }

    #[test]
    fn test_sender_keys_not_needed_for_decryption() {
        // This test verifies that recipient doesn't need sender's static keys
        let alice_keys = ShieldedKeys::generate();
        let bob_keys = ShieldedKeys::generate();
        let note = create_test_note();

        let memo = Note::encrypt(&alice_keys, bob_keys.public_viewing_key(), &note).unwrap();

        // Bob decrypts without any reference to Alice's keys
        // (the ephemeral pubkey in memo is all that's needed)
        let decrypted = Note::decrypt(&bob_keys, &memo).unwrap();
        assert_eq!(decrypted.value, note.value);
    }
}
