use alloy_primitives::B256;

use super::poseidon::{poseidon2, DOMAIN_SALT_ENC};

/// XOR two B256 values byte-by-byte.
pub fn xor_b256(a: B256, b: B256) -> B256 {
    let a_bytes = a.as_slice();
    let b_bytes = b.as_slice();
    let mut result = [0u8; 32];
    for i in 0..32 {
        result[i] = a_bytes[i] ^ b_bytes[i];
    }
    B256::from(result)
}

/// Encrypt a salt using XOR with an ECDH-derived key.
///
/// ```text
/// encryption_key = H(DOMAIN_SALT_ENC, shared_secret.x)
/// encrypted_salt = salt XOR encryption_key
/// ```
pub fn encrypt_salt(salt: B256, shared_secret_x: B256) -> B256 {
    let enc_key = poseidon2(DOMAIN_SALT_ENC, shared_secret_x);
    xor_b256(salt, enc_key)
}

/// Decrypt a salt using XOR with an ECDH-derived key.
/// XOR is self-inverse, so decryption is identical to encryption.
pub fn decrypt_salt(encrypted_salt: B256, shared_secret_x: B256) -> B256 {
    encrypt_salt(encrypted_salt, shared_secret_x)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let salt = B256::repeat_byte(0x42);
        let shared_x = B256::repeat_byte(0xAB);

        let encrypted = encrypt_salt(salt, shared_x);
        let decrypted = decrypt_salt(encrypted, shared_x);

        assert_eq!(salt, decrypted);
    }

    #[test]
    fn test_encryption_changes_value() {
        let salt = B256::repeat_byte(0x42);
        let shared_x = B256::repeat_byte(0xAB);

        let encrypted = encrypt_salt(salt, shared_x);
        assert_ne!(salt, encrypted);
    }

    #[test]
    fn test_different_keys_produce_different_ciphertexts() {
        let salt = B256::repeat_byte(0x42);
        let shared_x1 = B256::repeat_byte(0xAB);
        let shared_x2 = B256::repeat_byte(0xCD);

        let enc1 = encrypt_salt(salt, shared_x1);
        let enc2 = encrypt_salt(salt, shared_x2);

        assert_ne!(enc1, enc2);
    }

    #[test]
    fn test_xor_self_inverse() {
        let a = B256::repeat_byte(0xFF);
        let b = B256::repeat_byte(0x55);

        let xored = xor_b256(a, b);
        let back = xor_b256(xored, b);

        assert_eq!(a, back);
    }

    #[test]
    fn test_xor_with_zero() {
        let a = B256::repeat_byte(0x42);
        assert_eq!(xor_b256(a, B256::ZERO), a);
    }
}
