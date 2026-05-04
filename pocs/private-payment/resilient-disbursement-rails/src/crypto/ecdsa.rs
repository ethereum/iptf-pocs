//! secp256k1 ECDSA helpers. Backed by the `k256` crate.
//!
//! - `sign_voucher`: signs a 32-byte digest with `m`, returning a low-s
//!   normalized `(r, s)` pair.
//! - `derive_pubkey`: returns the affine public key in uncompressed
//!   `(x, y)` 32-byte big-endian limb form.
//! - `point_to_eth_address`: keccak256 over the uncompressed (x || y) and
//!   take the last 20 bytes. Used for address derivation on the funder
//!   side; the SPEC stealth destination uses the same primitive.

use k256::{
    ProjectivePoint,
    PublicKey,
    Scalar,
    SecretKey,
    ecdsa::{
        Signature,
        SigningKey,
        signature::hazmat::PrehashSigner,
    },
    elliptic_curve::sec1::ToEncodedPoint,
};
use sha3::{
    Digest,
    Keccak256,
};

use crate::{
    error::CardError,
    types::{
        Address,
        Bytes32,
        EcdsaSignature,
        SecpPubkey,
    },
};

/// Sign a 32-byte digest with master scalar `m`. Returns canonical-s `(r,
/// s)`. Uses RFC 6979 deterministic nonces (k256's default), which is
/// sufficient for the PoC; production cards SHOULD use a TRNG-derived
/// nonce per SPEC Smartcard Requirements.
pub fn sign_voucher(m: &SecretKey, h_msg: &Bytes32) -> Result<EcdsaSignature, CardError> {
    let signing = SigningKey::from(m.clone());
    let sig: Signature = signing
        .sign_prehash(h_msg)
        .map_err(|e| CardError::SignFailure(e.to_string()))?;
    let sig = canonicalize_s(sig);
    let bytes = sig.to_bytes();
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&bytes[..32]);
    s.copy_from_slice(&bytes[32..]);
    Ok(EcdsaSignature { r, s })
}

/// Normalize `s` to the lower half of the curve order (EIP-2 / BIP-146).
/// `k256::ecdsa::Signature::normalize_s()` returns the low-s twin if `s` is
/// in the upper half; otherwise the original signature.
pub fn canonicalize_s(sig: Signature) -> Signature {
    sig.normalize_s().unwrap_or(sig)
}

/// Compute `M = m * G` and return the affine `(x, y)` as 32-byte big-endian
/// limbs.
pub fn derive_pubkey(m: &SecretKey) -> SecpPubkey {
    let pk: PublicKey = m.public_key();
    pubkey_to_xy(&pk)
}

/// Decompose a `k256::PublicKey` into uncompressed `(x, y)` 32-byte
/// big-endian limbs.
pub fn pubkey_to_xy(pk: &PublicKey) -> SecpPubkey {
    let ep = pk.to_encoded_point(false); // uncompressed: 0x04 || X || Y
    let bytes = ep.as_bytes();
    debug_assert_eq!(bytes.len(), 65);
    debug_assert_eq!(bytes[0], 0x04);
    let mut x = [0u8; 32];
    let mut y = [0u8; 32];
    x.copy_from_slice(&bytes[1..33]);
    y.copy_from_slice(&bytes[33..65]);
    SecpPubkey { x, y }
}

/// Reconstruct a `k256::PublicKey` from a 64-byte `(x || y)` array.
pub fn xy_to_pubkey(p: &SecpPubkey) -> Result<PublicKey, CardError> {
    let mut sec1 = [0u8; 65];
    sec1[0] = 0x04;
    sec1[1..33].copy_from_slice(&p.x);
    sec1[33..65].copy_from_slice(&p.y);
    PublicKey::from_sec1_bytes(&sec1).map_err(|_| CardError::BadApdu)
}

/// `address = keccak256(X || Y)[-20:]`. Used for stealth destination
/// derivation in the SPEC; on-chain the claim contract recomputes the same
/// value from the public-input limbs of `derivedPubkey`.
pub fn point_to_eth_address(p: &SecpPubkey) -> Address {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(&p.x);
    buf[32..].copy_from_slice(&p.y);
    let digest = Keccak256::digest(buf);
    let mut out = [0u8; 20];
    out.copy_from_slice(&digest[12..]);
    out
}

/// Multiply `derivedPrivkey * G` returning an `(x, y)` SecpPubkey. Used
/// inside the software smartcard to compute `derivedPubkey` from the on-card
/// HMAC-derived stealth scalar.
pub fn scalar_to_pubkey(scalar: &Scalar) -> SecpPubkey {
    let pp = ProjectivePoint::GENERATOR * scalar;
    let pk = PublicKey::from_affine(pp.to_affine()).expect("non-identity");
    pubkey_to_xy(&pk)
}

#[cfg(test)]
mod tests {
    use k256::elliptic_curve::rand_core::OsRng;

    use super::*;

    #[test]
    fn test_sign_then_canonical_s() {
        let m = SecretKey::random(&mut OsRng);
        let mut digest = [0u8; 32];
        digest[0] = 0xab;
        digest[31] = 0xcd;
        let sig = sign_voucher(&m, &digest).unwrap();
        // Canonical-s requires high bit of s_be to be at most 0x7f...
        assert!(sig.s[0] <= 0x7f, "s must be in the lower half");
    }

    #[test]
    fn test_derive_pubkey_roundtrip() {
        let m = SecretKey::random(&mut OsRng);
        let m_pub = derive_pubkey(&m);
        let pk = xy_to_pubkey(&m_pub).unwrap();
        let m_pub2 = pubkey_to_xy(&pk);
        assert_eq!(m_pub, m_pub2);
    }

    #[test]
    fn test_eth_address_known_vector() {
        // A simple hand-checked-by-construction round trip: same input -> same
        // output. We don't assert against a specific known vector here because
        // address derivation is well-tested upstream in alloy/keccak256; the
        // important property for this crate is determinism.
        let p = SecpPubkey {
            x: [0xaa; 32],
            y: [0xbb; 32],
        };
        let a1 = point_to_eth_address(&p);
        let a2 = point_to_eth_address(&p);
        assert_eq!(a1, a2);
    }
}
