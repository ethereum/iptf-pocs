//! Voucher AEAD: X25519 + HKDF-SHA256 + ChaCha20-Poly1305 with AAD.
//!
//! The companion encrypts a serialized `SignedVoucher` to the relay's
//! current X25519 static public key. Each envelope carries a fresh ephemeral
//! X25519 public key and a randomly sampled 12-byte nonce. The AAD binds
//! `ephemeral_pub || relay_id` so a network attacker cannot rewrite the
//! routing field without invalidating the AEAD tag. The relay maintains a
//! key archive of `(current, previous)` so that vouchers in flight across a
//! rotation are still decryptable.

use chacha20poly1305::{
    ChaCha20Poly1305,
    Nonce,
    aead::{
        Aead,
        KeyInit,
        Payload,
    },
};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use thiserror::Error;
use x25519_dalek::{
    PublicKey,
    StaticSecret,
};

use crate::types::{
    Bytes32,
    EncryptedVoucher,
};

const HKDF_INFO: &[u8] = b"RDR/voucher-aead/v1";

#[derive(Debug, Error)]
pub enum AeadError {
    #[error("ephemeral pubkey malformed")]
    BadEphemeralKey,
    #[error("AEAD decryption failed")]
    DecryptFailed,
    #[error("AEAD encryption failed")]
    EncryptFailed,
}

/// Encrypt a serialized voucher to a relay's X25519 static public key.
/// `relay_id` is bound into the AEAD AAD so any tampering with the routing
/// field invalidates the tag.
pub fn encrypt_to_relay(
    relay_pk: &PublicKey,
    relay_id: Bytes32,
    plaintext: &[u8],
) -> Result<EncryptedVoucher, AeadError> {
    let mut rng = rand::thread_rng();

    // Fresh ephemeral X25519 keypair.
    let mut eph_seed = [0u8; 32];
    rng.fill_bytes(&mut eph_seed);
    let ephemeral_secret = StaticSecret::from(eph_seed);
    let ephemeral_pub: PublicKey = (&ephemeral_secret).into();

    let shared = ephemeral_secret.diffie_hellman(relay_pk);
    let key = derive_aead_key(shared.as_bytes());

    // Sample a random 12-byte nonce per envelope. Nonce uniqueness is the
    // sole responsibility of the OsRng draw; no XOR mixing.
    let mut nonce_bytes = [0u8; 12];
    rng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let aad = build_aad(ephemeral_pub.as_bytes(), &relay_id);
    let cipher = ChaCha20Poly1305::new_from_slice(&key).expect("ChaCha20-Poly1305 key");
    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| AeadError::EncryptFailed)?;

    Ok(EncryptedVoucher {
        ephemeral_pub: *ephemeral_pub.as_bytes(),
        nonce: nonce_bytes,
        ciphertext,
        relay_id,
    })
}

/// Decrypt a voucher envelope with one of the relay's static keys. The
/// relay tries `current`, then `previous`, then errs. This function decrypts
/// against a single key; the `Relay` adapter loops over the archive.
pub fn decrypt_from_companion(
    relay_sk: &StaticSecret,
    env: &EncryptedVoucher,
) -> Result<Vec<u8>, AeadError> {
    let eph_pub = PublicKey::from(env.ephemeral_pub);
    let shared = relay_sk.diffie_hellman(&eph_pub);
    let key = derive_aead_key(shared.as_bytes());

    let nonce = Nonce::from_slice(&env.nonce);
    let aad = build_aad(&env.ephemeral_pub, &env.relay_id);

    let cipher = ChaCha20Poly1305::new_from_slice(&key).expect("ChaCha20-Poly1305 key");
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: env.ciphertext.as_slice(),
                aad: &aad,
            },
        )
        .map_err(|_| AeadError::DecryptFailed)
}

fn derive_aead_key(shared: &[u8]) -> Bytes32 {
    let hkdf = Hkdf::<Sha256>::new(None, shared);
    let mut key = [0u8; 32];
    hkdf.expand(HKDF_INFO, &mut key).expect("HKDF expand");
    key
}

fn build_aad(ephemeral_pub: &[u8; 32], relay_id: &Bytes32) -> [u8; 64] {
    let mut aad = [0u8; 64];
    aad[..32].copy_from_slice(ephemeral_pub);
    aad[32..].copy_from_slice(relay_id);
    aad
}

#[cfg(test)]
mod tests {
    use rand::RngCore;
    use x25519_dalek::{
        PublicKey,
        StaticSecret,
    };

    use super::*;

    fn fresh_relay() -> (StaticSecret, PublicKey) {
        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);
        let sk = StaticSecret::from(seed);
        let pk: PublicKey = (&sk).into();
        (sk, pk)
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let (sk, pk) = fresh_relay();
        let plaintext = b"voucher-bytes";
        let env = encrypt_to_relay(&pk, [0u8; 32], plaintext).unwrap();
        let plain2 = decrypt_from_companion(&sk, &env).unwrap();
        assert_eq!(plain2, plaintext);
    }

    #[test]
    fn test_decrypt_with_wrong_key_fails() {
        let (_sk, pk) = fresh_relay();
        let (sk2, _pk2) = fresh_relay();
        let env = encrypt_to_relay(&pk, [0u8; 32], b"hello").unwrap();
        assert!(decrypt_from_companion(&sk2, &env).is_err());
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let (sk, pk) = fresh_relay();
        let mut env = encrypt_to_relay(&pk, [0u8; 32], b"hello").unwrap();
        env.ciphertext[0] ^= 0xff;
        assert!(decrypt_from_companion(&sk, &env).is_err());
    }

    #[test]
    fn test_two_envelopes_differ() {
        let (_sk, pk) = fresh_relay();
        let e1 = encrypt_to_relay(&pk, [0u8; 32], b"hello").unwrap();
        let e2 = encrypt_to_relay(&pk, [0u8; 32], b"hello").unwrap();
        // Fresh ephemeral keys per call -> different ciphertexts.
        assert_ne!(e1.ephemeral_pub, e2.ephemeral_pub);
        assert_ne!(e1.ciphertext, e2.ciphertext);
    }

    #[test]
    fn test_relay_id_is_authenticated() {
        use rand::RngCore;
        use x25519_dalek::{
            PublicKey,
            StaticSecret,
        };
        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);
        let sk = StaticSecret::from(seed);
        let pk = PublicKey::from(&sk);
        let mut env = encrypt_to_relay(&pk, [0xAA; 32], b"hello").unwrap();
        env.relay_id = [0xBB; 32];
        assert!(decrypt_from_companion(&sk, &env).is_err());
    }
}
