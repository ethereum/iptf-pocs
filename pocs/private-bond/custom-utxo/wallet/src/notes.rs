use blake2::{Blake2b512, Digest};
use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit, Nonce};
use ff::PrimeField;
use poseidon_rs::{Fr, Poseidon};
use serde::{Deserialize, Serialize};

use crate::keys::ShieldedKeys;

pub struct Memo {
    pub ciphertext: Vec<u8>,
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

    /// Encrypt memo using BLAKE2b KDF + ChaCha20-Poly1305
    pub fn encrypt(
        sender_keys: &ShieldedKeys,
        recipient_pubkey: &[u8; 32],
        data: &Note,
    ) -> Result<Memo, String> {
        // 1. Compute shared secret via ECDH
        let shared_secret = sender_keys.ecdh(recipient_pubkey);

        // 2. Derive key using BLAKE2b(shared_secret || alice_pub || bob_pub)
        let mut hasher = Blake2b512::new();
        hasher.update(&shared_secret);
        hasher.update(sender_keys.public_viewing_key());
        hasher.update(recipient_pubkey);
        let key_bytes = hasher.finalize();
        let key = &key_bytes[..32];

        // 3. Serialize Note
        let note_bytes =
            bincode::serialize(data).map_err(|e| format!("Serialization failed: {}", e))?;

        // 4. Encrypt with ChaCha20-Poly1305
        let cipher = ChaCha20Poly1305::new(key.into());
        let nonce = Nonce::from_slice(&[0u8; 12]); // Deterministic nonce
        let ciphertext = cipher
            .encrypt(nonce, note_bytes.as_ref())
            .map_err(|e| format!("Encryption failed: {}", e))?;

        Ok(Memo { ciphertext })
    }

    /// Decrypt memo (only recipient can do this)
    pub fn decrypt(
        recipient_keys: &ShieldedKeys,
        sender_pubkey: &[u8; 32],
        memo: &Memo,
    ) -> Result<Note, String> {
        // 1. Compute shared secret via ECDH
        let shared_secret = recipient_keys.ecdh(sender_pubkey);

        // 2. Derive key using BLAKE2b(shared_secret || sender_pub || recipient_pub)
        let mut hasher = Blake2b512::new();
        hasher.update(&shared_secret);
        hasher.update(sender_pubkey);
        hasher.update(recipient_keys.public_viewing_key());
        let key_bytes = hasher.finalize();
        let key = &key_bytes[..32];

        // 3. Decrypt with ChaCha20-Poly1305
        let cipher = ChaCha20Poly1305::new(key.into());
        let nonce = Nonce::from_slice(&[0u8; 12]); // Same deterministic nonce
        let plaintext = cipher
            .decrypt(nonce, memo.ciphertext.as_ref())
            .map_err(|e| format!("Decryption failed: {}", e))?;

        // 4. Deserialize Note
        let note: Note = bincode::deserialize(&plaintext)
            .map_err(|e| format!("Deserialization failed: {}", e))?;

        Ok(note)
    }
}
