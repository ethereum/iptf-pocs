use alloy_primitives::B256;
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use light_poseidon::{Poseidon, PoseidonHasher};

/// Convert B256 to BN254 field element.
fn b256_to_fr(value: B256) -> Fr {
    Fr::from_be_bytes_mod_order(value.as_ref())
}

/// Convert BN254 field element to B256.
fn fr_to_b256(value: Fr) -> B256 {
    let big_int = value.into_bigint();
    let bytes = big_int.to_bytes_be();
    B256::from_slice(&bytes)
}

/// Encode a domain tag string as a B256 field element.
///
/// The UTF-8 bytes are right-aligned (big-endian) in a 32-byte array.
/// The tag must be at most 31 bytes to stay within the BN254 field.
pub fn domain_tag(tag: &str) -> B256 {
    let bytes = tag.as_bytes();
    assert!(
        bytes.len() <= 31,
        "Domain tag must be at most 31 bytes, got {}",
        bytes.len()
    );
    let mut padded = [0u8; 32];
    padded[32 - bytes.len()..].copy_from_slice(bytes);
    B256::from(padded)
}

/// Poseidon hash with 2 inputs (for Merkle tree nodes).
pub fn poseidon2(a: B256, b: B256) -> B256 {
    let mut hasher = Poseidon::<Fr>::new_circom(2).expect("Failed to create Poseidon hasher");
    let inputs = [b256_to_fr(a), b256_to_fr(b)];
    let result = hasher
        .hash(&inputs)
        .expect("Failed to compute Poseidon hash");
    fr_to_b256(result)
}

/// Poseidon hash with 3 inputs (for nullifier: domain + commitment + salt).
pub fn poseidon3(a: B256, b: B256, c: B256) -> B256 {
    let mut hasher = Poseidon::<Fr>::new_circom(3).expect("Failed to create Poseidon hasher");
    let inputs = [b256_to_fr(a), b256_to_fr(b), b256_to_fr(c)];
    let result = hasher
        .hash(&inputs)
        .expect("Failed to compute Poseidon hash");
    fr_to_b256(result)
}

/// Poseidon hash with 8 inputs (for commitment: domain + 7 note fields).
pub fn poseidon8(a: B256, b: B256, c: B256, d: B256, e: B256, f: B256, g: B256, h: B256) -> B256 {
    let mut hasher = Poseidon::<Fr>::new_circom(8).expect("Failed to create Poseidon hasher");
    let inputs = [
        b256_to_fr(a),
        b256_to_fr(b),
        b256_to_fr(c),
        b256_to_fr(d),
        b256_to_fr(e),
        b256_to_fr(f),
        b256_to_fr(g),
        b256_to_fr(h),
    ];
    let result = hasher
        .hash(&inputs)
        .expect("Failed to compute Poseidon hash");
    fr_to_b256(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_tag_encoding() {
        let tag = domain_tag("tee_swap.commitment");
        // Should be right-aligned in 32 bytes
        let bytes = tag.as_slice();
        // "tee_swap.commitment" is 19 bytes, so first 13 bytes should be zero
        assert!(bytes[..13].iter().all(|&b| b == 0));
        assert_eq!(&bytes[13..], b"tee_swap.commitment");
    }

    #[test]
    #[should_panic(expected = "Domain tag must be at most 31 bytes")]
    fn test_domain_tag_too_long() {
        domain_tag("this string is way too long and exceeds thirty one bytes limit");
    }

    #[test]
    fn test_poseidon2_deterministic() {
        let a = B256::repeat_byte(0x01);
        let b = B256::repeat_byte(0x02);
        let hash1 = poseidon2(a, b);
        let hash2 = poseidon2(a, b);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_poseidon2_order_matters() {
        let a = B256::repeat_byte(0x01);
        let b = B256::repeat_byte(0x02);
        let hash1 = poseidon2(a, b);
        let hash2 = poseidon2(b, a);
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_poseidon3_deterministic() {
        let a = B256::repeat_byte(0x01);
        let b = B256::repeat_byte(0x02);
        let c = B256::repeat_byte(0x03);
        let hash1 = poseidon3(a, b, c);
        let hash2 = poseidon3(a, b, c);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_poseidon3_input_sensitivity() {
        let a = B256::repeat_byte(0x01);
        let b = B256::repeat_byte(0x02);
        let c1 = B256::repeat_byte(0x03);
        let c2 = B256::repeat_byte(0x04);
        assert_ne!(poseidon3(a, b, c1), poseidon3(a, b, c2));
    }

    #[test]
    fn test_poseidon8_deterministic() {
        let vals: Vec<B256> = (1..=8).map(|i| B256::repeat_byte(i)).collect();
        let hash1 = poseidon8(
            vals[0], vals[1], vals[2], vals[3], vals[4], vals[5], vals[6], vals[7],
        );
        let hash2 = poseidon8(
            vals[0], vals[1], vals[2], vals[3], vals[4], vals[5], vals[6], vals[7],
        );
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_poseidon8_input_sensitivity() {
        let vals: Vec<B256> = (1..=8).map(|i| B256::repeat_byte(i)).collect();
        let hash1 = poseidon8(
            vals[0], vals[1], vals[2], vals[3], vals[4], vals[5], vals[6], vals[7],
        );
        // Change last input
        let hash2 = poseidon8(
            vals[0],
            vals[1],
            vals[2],
            vals[3],
            vals[4],
            vals[5],
            vals[6],
            B256::repeat_byte(0xFF),
        );
        assert_ne!(hash1, hash2);
    }
}
