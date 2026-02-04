use alloy::primitives::B256;
use ark_bn254::Fr;
use ark_ff::{
    BigInteger,
    PrimeField,
};
use light_poseidon::{
    Poseidon,
    PoseidonHasher,
};

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

/// Poseidon hash with 1 input (for key derivation).
/// Used for: owner_pubkey = poseidon1(spending_key)
pub fn poseidon1(a: B256) -> B256 {
    let mut hasher =
        Poseidon::<Fr>::new_circom(1).expect("Failed to create Poseidon hasher");
    let input = b256_to_fr(a);
    let result = hasher
        .hash(&[input])
        .expect("Failed to compute Poseidon hash");
    fr_to_b256(result)
}

/// Poseidon hash with 2 inputs (for nullifiers and Merkle nodes).
/// Used for:
/// - nullifier = poseidon2(commitment, spending_key)
/// - merkle_node = poseidon2(left, right)
pub fn poseidon2(a: B256, b: B256) -> B256 {
    let mut hasher =
        Poseidon::<Fr>::new_circom(2).expect("Failed to create Poseidon hasher");
    let inputs = [b256_to_fr(a), b256_to_fr(b)];
    let result = hasher
        .hash(&inputs)
        .expect("Failed to compute Poseidon hash");
    fr_to_b256(result)
}

/// Poseidon hash with 4 inputs (for note commitments and attestation leaves).
/// Used for:
/// - commitment = poseidon4(token, amount, owner_pubkey, salt)
/// - attestation_leaf = poseidon4(subject_pubkey, attester, issued_at, expires_at)
pub fn poseidon4(a: B256, b: B256, c: B256, d: B256) -> B256 {
    let mut hasher =
        Poseidon::<Fr>::new_circom(4).expect("Failed to create Poseidon hasher");
    let inputs = [b256_to_fr(a), b256_to_fr(b), b256_to_fr(c), b256_to_fr(d)];
    let result = hasher
        .hash(&inputs)
        .expect("Failed to compute Poseidon hash");
    fr_to_b256(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poseidon1_deterministic() {
        let input = B256::repeat_byte(0x42);
        let hash1 = poseidon1(input);
        let hash2 = poseidon1(input);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_poseidon1_different_inputs() {
        let input1 = B256::repeat_byte(0x01);
        let input2 = B256::repeat_byte(0x02);
        let hash1 = poseidon1(input1);
        let hash2 = poseidon1(input2);
        assert_ne!(hash1, hash2);
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
    fn test_poseidon4_deterministic() {
        let a = B256::repeat_byte(0x01);
        let b = B256::repeat_byte(0x02);
        let c = B256::repeat_byte(0x03);
        let d = B256::repeat_byte(0x04);
        let hash1 = poseidon4(a, b, c, d);
        let hash2 = poseidon4(a, b, c, d);
        assert_eq!(hash1, hash2);
    }
}
