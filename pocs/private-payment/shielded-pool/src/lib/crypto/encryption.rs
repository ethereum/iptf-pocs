use crate::domain::{
    encrypted::EncryptedNote,
    keys::{
        ViewingKey,
        ViewingPubkey,
    },
    note::Note,
};
use chacha20poly1305::{
    ChaCha20Poly1305,
    Nonce,
    aead::{
        Aead,
        KeyInit,
    },
};
use hkdf::Hkdf;
use k256::{
    PublicKey,
    ecdh::EphemeralSecret,
    elliptic_curve::sec1::ToEncodedPoint,
};
use sha2::{
    Digest,
    Sha256,
};

/// Domain separator for HKDF key derivation.
const HKDF_INFO: &[u8] = b"shielded-pool-note-encryption-v1";

/// Encrypt a note for a recipient using ECIES.
///
/// Scheme:
/// 1. Generate ephemeral keypair
/// 2. ECDH: shared_secret = ephemeral_secret * recipient_pubkey
/// 3. HKDF: derive symmetric key from shared_secret
/// 4. ChaCha20-Poly1305: encrypt note with derived key
pub fn encrypt_note(note: &Note, recipient: &ViewingPubkey) -> EncryptedNote {
    // Serialize the note
    let plaintext = serde_json::to_vec(note).expect("Note serialization should not fail");

    // Generate ephemeral keypair
    let ephemeral_secret = EphemeralSecret::random(&mut rand::thread_rng());
    let ephemeral_pubkey = ephemeral_secret.public_key();

    // ECDH: compute shared secret
    let shared_secret = ephemeral_secret.diffie_hellman(recipient.public_key());

    // HKDF: derive encryption key
    let hkdf = Hkdf::<Sha256>::new(None, shared_secret.raw_secret_bytes().as_slice());
    let mut encryption_key = [0u8; 32];
    hkdf.expand(HKDF_INFO, &mut encryption_key)
        .expect("HKDF expand should not fail with 32 byte output");

    // ChaCha20-Poly1305 encrypt
    // Use first 12 bytes of shared secret hash as nonce (deterministic for same ephemeral key)
    let mut nonce_bytes = [0u8; 12];
    let nonce_material = Sha256::digest(shared_secret.raw_secret_bytes().as_slice());
    nonce_bytes.copy_from_slice(&nonce_material[..12]);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let cipher = ChaCha20Poly1305::new_from_slice(&encryption_key)
        .expect("ChaCha20Poly1305 key should be valid");
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_slice())
        .expect("Encryption should not fail");

    // Serialize ephemeral public key (compressed SEC1)
    let ephemeral_pubkey_bytes =
        ephemeral_pubkey.to_encoded_point(true).as_bytes().to_vec();

    EncryptedNote::new(ephemeral_pubkey_bytes, ciphertext)
}

/// Decrypt a note using the recipient's viewing key.
///
/// Scheme:
/// 1. Parse ephemeral public key
/// 2. ECDH: shared_secret = viewing_key * ephemeral_pubkey
/// 3. HKDF: derive symmetric key from shared_secret
/// 4. ChaCha20-Poly1305: decrypt ciphertext
pub fn decrypt_note(
    encrypted: &EncryptedNote,
    viewing_key: &ViewingKey,
) -> Result<Note, DecryptionError> {
    // Parse ephemeral public key
    let ephemeral_pubkey = PublicKey::from_sec1_bytes(&encrypted.ephemeral_pubkey)
        .map_err(|_| DecryptionError::InvalidEphemeralKey)?;

    // ECDH: compute shared secret
    let shared_secret = k256::ecdh::diffie_hellman(
        viewing_key.secret_key().to_nonzero_scalar(),
        ephemeral_pubkey.as_affine(),
    );

    // HKDF: derive encryption key
    let hkdf = Hkdf::<Sha256>::new(None, shared_secret.raw_secret_bytes().as_slice());
    let mut encryption_key = [0u8; 32];
    hkdf.expand(HKDF_INFO, &mut encryption_key)
        .map_err(|_| DecryptionError::KeyDerivationFailed)?;

    // Derive nonce (same as encryption)
    let mut nonce_bytes = [0u8; 12];
    let nonce_material = Sha256::digest(shared_secret.raw_secret_bytes().as_slice());
    nonce_bytes.copy_from_slice(&nonce_material[..12]);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // ChaCha20-Poly1305 decrypt
    let cipher = ChaCha20Poly1305::new_from_slice(&encryption_key)
        .map_err(|_| DecryptionError::CipherInitFailed)?;
    let plaintext = cipher
        .decrypt(nonce, encrypted.ciphertext.as_slice())
        .map_err(|_| DecryptionError::DecryptionFailed)?;

    // Deserialize note
    serde_json::from_slice(&plaintext).map_err(|_| DecryptionError::DeserializationFailed)
}

/// Errors that can occur during decryption.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DecryptionError {
    #[error("Invalid ephemeral public key")]
    InvalidEphemeralKey,
    #[error("Key derivation failed")]
    KeyDerivationFailed,
    #[error("Cipher initialization failed")]
    CipherInitFailed,
    #[error("Decryption failed (wrong key or corrupted data)")]
    DecryptionFailed,
    #[error("Failed to deserialize note")]
    DeserializationFailed,
}

#[cfg(test)]
mod tests {
    use alloy::primitives::{
        Address,
        U256,
    };

    use super::*;
    use crate::domain::keys::SpendingKey;

    fn create_test_note() -> Note {
        let sk = SpendingKey::random();
        let owner = sk.derive_owner_pubkey();
        Note::new(Address::ZERO, U256::from(1000u64), owner)
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let note = create_test_note();
        let viewing_key = ViewingKey::random();
        let viewing_pubkey = viewing_key.derive_viewing_pubkey();

        let encrypted = encrypt_note(&note, &viewing_pubkey);
        let decrypted = decrypt_note(&encrypted, &viewing_key).unwrap();

        assert_eq!(note.token, decrypted.token);
        assert_eq!(note.amount, decrypted.amount);
        assert_eq!(note.owner_pubkey, decrypted.owner_pubkey);
        assert_eq!(note.salt, decrypted.salt);
    }

    #[test]
    fn test_decrypt_with_wrong_key_fails() {
        let note = create_test_note();
        let viewing_key = ViewingKey::random();
        let viewing_pubkey = viewing_key.derive_viewing_pubkey();

        let encrypted = encrypt_note(&note, &viewing_pubkey);

        // Try to decrypt with a different key
        let wrong_key = ViewingKey::random();
        let result = decrypt_note(&encrypted, &wrong_key);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), DecryptionError::DecryptionFailed);
    }

    #[test]
    fn test_encrypt_produces_different_ciphertext() {
        let note = create_test_note();
        let viewing_key = ViewingKey::random();
        let viewing_pubkey = viewing_key.derive_viewing_pubkey();

        // Encrypt twice - should produce different ciphertexts due to random ephemeral keys
        let encrypted1 = encrypt_note(&note, &viewing_pubkey);
        let encrypted2 = encrypt_note(&note, &viewing_pubkey);

        assert_ne!(encrypted1.ephemeral_pubkey, encrypted2.ephemeral_pubkey);
        assert_ne!(encrypted1.ciphertext, encrypted2.ciphertext);

        // But both should decrypt to the same note
        let decrypted1 = decrypt_note(&encrypted1, &viewing_key).unwrap();
        let decrypted2 = decrypt_note(&encrypted2, &viewing_key).unwrap();

        assert_eq!(decrypted1.token, decrypted2.token);
        assert_eq!(decrypted1.amount, decrypted2.amount);
        assert_eq!(decrypted1.salt, decrypted2.salt);
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let note = create_test_note();
        let viewing_key = ViewingKey::random();
        let viewing_pubkey = viewing_key.derive_viewing_pubkey();

        let mut encrypted = encrypt_note(&note, &viewing_pubkey);

        // Tamper with ciphertext
        if let Some(byte) = encrypted.ciphertext.get_mut(0) {
            *byte ^= 0xFF;
        }

        let result = decrypt_note(&encrypted, &viewing_key);
        assert!(result.is_err());
    }
}
