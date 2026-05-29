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

// NOTE on cross-implementation consistency: these `new_circom(n)` parameters
// MUST match the Noir `poseidon::bn254::hash_n` parameters for every arity, or
// off-chain commitments/nullifiers won't match the in-circuit reconstruction.
// The parent relies on this for arities 2 and 4; this extension additionally
// relies on arities 3 (per-epoch nullifier) and 5 (extended commitment). The
// deposit-circuit checkpoint verifies the new arities against Noir.

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

/// Poseidon hash with 2 inputs (Merkle inner nodes, chain-proof accumulator fold).
/// Used for:
/// - merkle_node = poseidon2(left, right)
/// - accumulator = poseidon2(accumulator_prev, frozen_root)
pub fn poseidon2(a: B256, b: B256) -> B256 {
    let mut hasher =
        Poseidon::<Fr>::new_circom(2).expect("Failed to create Poseidon hasher");
    let inputs = [b256_to_fr(a), b256_to_fr(b)];
    let result = hasher
        .hash(&inputs)
        .expect("Failed to compute Poseidon hash");
    fr_to_b256(result)
}

/// Poseidon hash with 3 inputs (per-epoch nullifiers).
/// Used for: η_e = poseidon3(commitment, spending_key, epoch_id)
pub fn poseidon3(a: B256, b: B256, c: B256) -> B256 {
    let mut hasher =
        Poseidon::<Fr>::new_circom(3).expect("Failed to create Poseidon hasher");
    let inputs = [b256_to_fr(a), b256_to_fr(b), b256_to_fr(c)];
    let result = hasher
        .hash(&inputs)
        .expect("Failed to compute Poseidon hash");
    fr_to_b256(result)
}

/// Poseidon hash with 4 inputs (attestation leaves).
/// Used for: attestation_leaf = poseidon4(subject_pubkey, attester, issued_at, expires_at)
pub fn poseidon4(a: B256, b: B256, c: B256, d: B256) -> B256 {
    let mut hasher =
        Poseidon::<Fr>::new_circom(4).expect("Failed to create Poseidon hasher");
    let inputs = [b256_to_fr(a), b256_to_fr(b), b256_to_fr(c), b256_to_fr(d)];
    let result = hasher
        .hash(&inputs)
        .expect("Failed to compute Poseidon hash");
    fr_to_b256(result)
}

/// Poseidon hash with 5 inputs (extended note commitments).
/// Used for: commitment = poseidon5(token, amount, owner_pubkey, salt, epoch_created)
pub fn poseidon5(a: B256, b: B256, c: B256, d: B256, e: B256) -> B256 {
    let mut hasher =
        Poseidon::<Fr>::new_circom(5).expect("Failed to create Poseidon hasher");
    let inputs = [
        b256_to_fr(a),
        b256_to_fr(b),
        b256_to_fr(c),
        b256_to_fr(d),
        b256_to_fr(e),
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
    fn test_poseidon1_deterministic() {
        let input = B256::repeat_byte(0x42);
        assert_eq!(poseidon1(input), poseidon1(input));
    }

    #[test]
    fn test_poseidon2_order_matters() {
        let a = B256::repeat_byte(0x01);
        let b = B256::repeat_byte(0x02);
        assert_ne!(poseidon2(a, b), poseidon2(b, a));
    }

    #[test]
    fn test_poseidon3_deterministic() {
        let a = B256::repeat_byte(0x01);
        let b = B256::repeat_byte(0x02);
        let c = B256::repeat_byte(0x03);
        assert_eq!(poseidon3(a, b, c), poseidon3(a, b, c));
    }

    #[test]
    fn test_poseidon3_epoch_separation() {
        // Same (commitment, key), different epoch -> different nullifier.
        let commitment = B256::repeat_byte(0x42);
        let key = B256::repeat_byte(0x07);
        let e0 = B256::ZERO;
        let e1 = B256::from(alloy::primitives::U256::from(1u64));
        assert_ne!(poseidon3(commitment, key, e0), poseidon3(commitment, key, e1));
    }

    #[test]
    fn test_poseidon5_deterministic() {
        let a = B256::repeat_byte(0x01);
        let b = B256::repeat_byte(0x02);
        let c = B256::repeat_byte(0x03);
        let d = B256::repeat_byte(0x04);
        let e = B256::repeat_byte(0x05);
        assert_eq!(poseidon5(a, b, c, d, e), poseidon5(a, b, c, d, e));
    }

    #[test]
    fn test_poseidon5_epoch_separation() {
        // Same note fields, different epoch_created -> different commitment.
        let token = B256::repeat_byte(0x11);
        let amount = B256::repeat_byte(0x22);
        let owner = B256::repeat_byte(0x33);
        let salt = B256::repeat_byte(0x44);
        let e0 = B256::ZERO;
        let e1 = B256::from(alloy::primitives::U256::from(1u64));
        assert_ne!(
            poseidon5(token, amount, owner, salt, e0),
            poseidon5(token, amount, owner, salt, e1)
        );
    }

    // Cross-implementation vectors. These MUST equal the Noir
    // `poseidon::bn254::hash_n` outputs for the same inputs, or off-chain
    // commitments/nullifiers diverge from the in-circuit reconstruction. The
    // deposit circuit pins POSEIDON5_12345 against Noir
    // (`test_poseidon5_matches_rust`); the chain-update/spend circuits pin
    // POSEIDON3_123 likewise. If a vector here changes (e.g. a poseidon lib
    // bump), the matching Noir test MUST be updated in lockstep.
    const POSEIDON3_123: &str =
        "0x0e7732d89e6939c0ff03d5e58dab6302f3230e269dc5b968f725df34ab36d732";
    const POSEIDON5_12345: &str =
        "0x0dab9449e4a1398a15224c0b15a49d598b2174d305a316c918125f8feeb123c0";

    fn small(n: u64) -> B256 {
        B256::from(alloy::primitives::U256::from(n))
    }

    #[test]
    fn test_poseidon3_known_vector() {
        assert_eq!(
            poseidon3(small(1), small(2), small(3)),
            POSEIDON3_123.parse::<B256>().unwrap()
        );
    }

    #[test]
    fn test_poseidon5_known_vector() {
        assert_eq!(
            poseidon5(small(1), small(2), small(3), small(4), small(5)),
            POSEIDON5_12345.parse::<B256>().unwrap()
        );
    }
}
