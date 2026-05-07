//! HMAC-SHA256 helpers.
//!
//! - `derive_stealth_scalar`: on-card per-claim stealth scalar derivation.
//!   `m` is the master secret; `(round_id, claim_contract, chain_id)` form
//!   the per-claim domain. Output is `(x mod (n - 1)) + 1` reduced into
//!   the secp256k1 scalar field, so the result is non-zero.
//! - `derive_auth_token`: companion-side HMAC over the round header so the
//!   card can verify the auth token before signing.

use hmac::{
    Hmac,
    Mac,
};
use k256::{
    NonZeroScalar,
    SecretKey,
    elliptic_curve::{
        ops::Reduce,
        scalar::ScalarPrimitive,
    },
};
use num_bigint::BigUint;
use sha2::Sha256;

use crate::{
    DOMAIN_STEALTH,
    types::{
        Address,
        Bytes32,
        U256Be,
    },
};

type HmacSha256 = Hmac<Sha256>;

/// secp256k1 group order `n` in big-endian.
const SECP256K1_N_BE: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c,
    0xd0, 0x36, 0x41, 0x41,
];

/// Internal: literal SPEC reduction `(x mod (n - 1)) + 1` mapped into a
/// secp256k1 `NonZeroScalar`. The result is in `[1, n - 1]` by construction.
fn reduce_tag_to_scalar(tag: &[u8; 32]) -> NonZeroScalar {
    let n = BigUint::from_bytes_be(&SECP256K1_N_BE);
    let n_minus_one = &n - 1u32;
    let tag_int = BigUint::from_bytes_be(tag);
    let reduced = tag_int % &n_minus_one; // [0, n - 2]
    let result = &reduced + 1u32; // [1, n - 1]

    let mut be = [0u8; 32];
    let r_be = result.to_bytes_be();
    be[32 - r_be.len()..].copy_from_slice(&r_be);

    let scalar = <k256::Scalar as Reduce<k256::U256>>::reduce_bytes((&be).into());
    NonZeroScalar::new(scalar).expect("non-zero by construction: result in [1, n-1]")
}

/// `derivedScalar = HMAC-SHA256(m, DOMAIN_STEALTH || roundId ||
/// claimContract || chainId)`; reduced to `(x mod (n - 1)) + 1`.
///
/// The literal SPEC formula computed via `num-bigint` so the boundary is
/// unbiased: `x = HMAC tag as big-endian integer`, output is in `[1, n - 1]`.
pub fn derive_stealth_scalar(
    m: &SecretKey,
    round_id: &Bytes32,
    claim_contract: &Address,
    chain_id: &U256Be,
) -> SecretKey {
    let m_bytes = m.to_bytes();

    let mut mac =
        HmacSha256::new_from_slice(&m_bytes).expect("HMAC accepts any key length");
    mac.update(DOMAIN_STEALTH);
    mac.update(round_id);
    mac.update(claim_contract);
    mac.update(chain_id.as_bytes());
    let tag = mac.finalize().into_bytes();

    let mut tag_arr = [0u8; 32];
    tag_arr.copy_from_slice(&tag);

    let nzs = reduce_tag_to_scalar(&tag_arr);
    let primitive: ScalarPrimitive<k256::Secp256k1> = (*nzs.as_ref()).into();
    SecretKey::new(primitive)
}

/// `authToken = HMAC-SHA256(companion_pre_key, H_header)`. Card verifies it
/// before honoring `SIGN_VOUCHER`.
pub fn derive_auth_token(companion_pre_key: &Bytes32, h_header: &Bytes32) -> Bytes32 {
    let mut mac = HmacSha256::new_from_slice(companion_pre_key)
        .expect("HMAC accepts any key length");
    mac.update(h_header);
    let tag = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&tag);
    out
}

#[cfg(test)]
mod tests {
    use k256::elliptic_curve::rand_core::OsRng;

    use super::*;

    #[test]
    fn test_stealth_scalar_deterministic() {
        let m = SecretKey::random(&mut OsRng);
        let round = [0xa1u8; 32];
        let cc: Address = [0xcc; 20];
        let chain = U256Be::from_u64(11_155_111);
        let s1 = derive_stealth_scalar(&m, &round, &cc, &chain);
        let s2 = derive_stealth_scalar(&m, &round, &cc, &chain);
        assert_eq!(s1.to_bytes(), s2.to_bytes());
    }

    #[test]
    fn test_stealth_scalar_changes_with_round() {
        let m = SecretKey::random(&mut OsRng);
        let cc: Address = [0xcc; 20];
        let chain = U256Be::from_u64(1);
        let mut r1 = [0u8; 32];
        r1[0] = 0x01;
        let mut r2 = [0u8; 32];
        r2[0] = 0x02;
        let s1 = derive_stealth_scalar(&m, &r1, &cc, &chain);
        let s2 = derive_stealth_scalar(&m, &r2, &cc, &chain);
        assert_ne!(s1.to_bytes(), s2.to_bytes());
    }

    #[test]
    fn test_stealth_scalar_matches_spec_formula() {
        // Boundary witness: tag = 0xFF..FF (32 bytes) is well above n - 1, so
        // the literal `(x mod (n - 1)) + 1` reduction must be exercised.
        let tag = [0xFFu8; 32];

        // Compute expected directly with num-bigint, mirroring the SPEC.
        let n = BigUint::from_bytes_be(&SECP256K1_N_BE);
        let n_minus_one = &n - 1u32;
        let tag_int = BigUint::from_bytes_be(&tag);
        let expected_int = (&tag_int % &n_minus_one) + 1u32;

        let mut expected_be = [0u8; 32];
        let raw = expected_int.to_bytes_be();
        expected_be[32 - raw.len()..].copy_from_slice(&raw);

        let nzs = reduce_tag_to_scalar(&tag);
        let actual_be: [u8; 32] = nzs.to_bytes().into();

        assert_eq!(
            actual_be, expected_be,
            "reduce_tag_to_scalar must match (x mod (n-1)) + 1 byte-for-byte"
        );

        // Range check: expected lies in [1, n - 1].
        assert!(expected_int >= BigUint::from(1u32));
        assert!(expected_int < n);

        // And the actual scalar is non-zero (already implied by NonZeroScalar
        // construction, but assert explicitly for SPEC clarity).
        assert_ne!(actual_be, [0u8; 32]);
    }

    #[test]
    fn test_auth_token_deterministic() {
        let key = [0xabu8; 32];
        let header = [0xcdu8; 32];
        let t1 = derive_auth_token(&key, &header);
        let t2 = derive_auth_token(&key, &header);
        assert_eq!(t1, t2);
    }

    #[test]
    fn test_auth_token_changes_with_header() {
        let key = [0xabu8; 32];
        let mut h1 = [0u8; 32];
        h1[0] = 1;
        let mut h2 = [0u8; 32];
        h2[0] = 2;
        assert_ne!(derive_auth_token(&key, &h1), derive_auth_token(&key, &h2));
    }
}
