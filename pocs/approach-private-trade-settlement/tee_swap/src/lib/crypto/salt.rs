use alloy_primitives::B256;

use super::poseidon::{poseidon2, DOMAIN_SALT_ENC};

/// Right-shift a B256 by 3 bits
fn shr3(v: B256) -> B256 {
    let bytes = v.as_slice();
    let mut out = [0u8; 32];
    out[0] = bytes[0] >> 3;
    for i in 1..32 {
        out[i] = (bytes[i] >> 3) | ((bytes[i - 1] & 7) << 5);
    }
    B256::from(out)
}

/// Left-shift a B256 by 3 bits
fn shl3(v: B256) -> B256 {
    let bytes = v.as_slice();
    let mut out = [0u8; 32];
    out[31] = bytes[31] << 3;
    for i in (0..31).rev() {
        out[i] = (bytes[i] << 3) | (bytes[i + 1] >> 5);
    }
    B256::from(out)
}

/// XOR two B256 values byte-by-byte
fn xor_b256(a: B256, b: B256) -> B256 {
    let a_bytes = a.as_slice();
    let b_bytes = b.as_slice();
    let mut result = [0u8; 32];
    for i in 0..32 {
        result[i] = a_bytes[i] ^ b_bytes[i];
    }
    B256::from(result)
}

/// Encrypt a salt: `shr3(salt) XOR shr3(enc_key)`.
/// Salt must have bottom 3 bits = 0 for lossless decryption.
pub fn encrypt_salt(salt: B256, shared_secret_x: B256) -> B256 {
    let enc_key = poseidon2(DOMAIN_SALT_ENC, shared_secret_x);
    xor_b256(shr3(salt), shr3(enc_key))
}

/// Decrypt a salt: `shl3(encrypted XOR shr3(enc_key))`.
pub fn decrypt_salt(encrypted_salt: B256, shared_secret_x: B256) -> B256 {
    let enc_key = poseidon2(DOMAIN_SALT_ENC, shared_secret_x);
    shl3(xor_b256(encrypted_salt, shr3(enc_key)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Produce a canonical field element with bottom 3 bits cleared.
    fn aligned_salt(seed: u8) -> B256 {
        let h = poseidon2(B256::left_padding_from(&[seed]), B256::ZERO);
        let mut bytes: [u8; 32] = h.0;
        bytes[31] &= 0xF8; // clear bottom 3 bits
        B256::from(bytes)
    }

    fn canonical_field(seed: u8) -> B256 {
        poseidon2(B256::left_padding_from(&[seed]), B256::ZERO)
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let salt = aligned_salt(1);
        let shared_x = canonical_field(2);

        let encrypted = encrypt_salt(salt, shared_x);
        let decrypted = decrypt_salt(encrypted, shared_x);

        assert_eq!(salt, decrypted);
    }

    #[test]
    fn test_encryption_changes_value() {
        let salt = aligned_salt(1);
        let shared_x = canonical_field(2);

        let encrypted = encrypt_salt(salt, shared_x);
        assert_ne!(salt, encrypted);
    }

    #[test]
    fn test_different_keys_produce_different_ciphertexts() {
        let salt = aligned_salt(1);
        let shared_x1 = canonical_field(2);
        let shared_x2 = canonical_field(3);

        let enc1 = encrypt_salt(salt, shared_x1);
        let enc2 = encrypt_salt(salt, shared_x2);

        assert_ne!(enc1, enc2);
    }

    #[test]
    fn test_shr3_shl3_roundtrip_aligned() {
        let v = aligned_salt(42);
        assert_eq!(shl3(shr3(v)), v);
    }

    #[test]
    fn test_xor_self_inverse() {
        let a = shr3(canonical_field(1));
        let b = shr3(canonical_field(2));
        let xored = xor_b256(a, b);
        let back = xor_b256(xored, b);
        assert_eq!(a, back);
    }

    #[test]
    fn test_encrypt_with_zero_shared_secret() {
        let salt = aligned_salt(1);
        let encrypted = encrypt_salt(salt, B256::ZERO);
        let decrypted = decrypt_salt(encrypted, B256::ZERO);
        assert_eq!(salt, decrypted);
    }
}
