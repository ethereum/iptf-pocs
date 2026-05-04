//! k-of-n multisig signature primitive.
//!
//! Mirrors the on-chain `Multisig.sol` 65-byte (r || s || v) ECDSA signature
//! shape, with v in {27, 28}. Digest is signed raw (no EIP-191 wrapping)
//! since SPEC header / roster digests are already domain-tagged SHA-256.
//!
//! Wire format (used by `encode_threshold` / `decode_threshold`):
//!
//! ```text
//! bytes[0]              = count (u8, must equal threshold)
//! bytes[1 + i*85 .. ]   = signer_i (20) || r_i (32) || s_i (32) || v_i (1)
//! total length          = 1 + threshold * 85
//! ```

use k256::{
    SecretKey,
    ecdsa::{
        RecoveryId,
        Signature,
        SigningKey,
        VerifyingKey,
    },
};
use sha3::{
    Digest,
    Keccak256,
};
use thiserror::Error;

use crate::types::{
    Address,
    Bytes32,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MultiSignature {
    pub signer: Address,
    pub signature: [u8; 65],
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum MultisigError {
    #[error("multisig signature count does not equal threshold")]
    WrongCount,
    #[error("multisig contains a duplicate signer")]
    DuplicateSigner,
    #[error("multisig signer is not in the owner set")]
    UnknownSigner,
    #[error("multisig signature failed ECDSA recovery / signer-address mismatch")]
    BadSignature,
}

const SIG_RECORD_LEN: usize = 20 + 65;

pub fn sign_digest(signer_sk: &SecretKey, digest: &Bytes32) -> MultiSignature {
    let signing = SigningKey::from(signer_sk.clone());
    let (sig, recid) = signing
        .sign_prehash_recoverable(digest)
        .expect("k256 RFC6979 prehash sign cannot fail for a valid SecretKey");

    // High-s normalization flips the y-parity bit of the recovery id.
    let (sig, recid) = match sig.normalize_s() {
        Some(low) => (
            low,
            RecoveryId::new(!recid.is_y_odd(), recid.is_x_reduced()),
        ),
        None => (sig, recid),
    };

    let bytes = sig.to_bytes();
    let mut out = [0u8; 65];
    out[..32].copy_from_slice(&bytes[..32]);
    out[32..64].copy_from_slice(&bytes[32..]);
    out[64] = 27 + (recid.is_y_odd() as u8);

    let signer = address_from_verifying_key(signing.verifying_key());
    MultiSignature {
        signer,
        signature: out,
    }
}

pub fn verify_threshold(
    digest: &Bytes32,
    sigs: &[MultiSignature],
    owners: &[Address],
    threshold: usize,
) -> Result<(), MultisigError> {
    if sigs.len() != threshold {
        return Err(MultisigError::WrongCount);
    }

    for i in 0..sigs.len() {
        for j in (i + 1)..sigs.len() {
            if sigs[i].signer == sigs[j].signer {
                return Err(MultisigError::DuplicateSigner);
            }
        }
    }

    for s in sigs {
        if !owners.iter().any(|o| o == &s.signer) {
            return Err(MultisigError::UnknownSigner);
        }
        recover_and_check(digest, s)?;
    }

    Ok(())
}

pub fn encode_threshold(sigs: &[MultiSignature]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + sigs.len() * SIG_RECORD_LEN);
    out.push(sigs.len() as u8);
    for s in sigs {
        out.extend_from_slice(&s.signer);
        out.extend_from_slice(&s.signature);
    }
    out
}

pub fn decode_threshold(
    bytes: &[u8],
    expected_count: usize,
) -> Result<Vec<MultiSignature>, MultisigError> {
    if bytes.is_empty() {
        return Err(MultisigError::WrongCount);
    }
    let count = bytes[0] as usize;
    if count != expected_count {
        return Err(MultisigError::WrongCount);
    }
    let want_len = 1 + expected_count * SIG_RECORD_LEN;
    if bytes.len() != want_len {
        return Err(MultisigError::WrongCount);
    }

    let mut out = Vec::with_capacity(expected_count);
    for i in 0..expected_count {
        let off = 1 + i * SIG_RECORD_LEN;
        let mut signer = [0u8; 20];
        signer.copy_from_slice(&bytes[off..off + 20]);
        let mut signature = [0u8; 65];
        signature.copy_from_slice(&bytes[off + 20..off + SIG_RECORD_LEN]);
        out.push(MultiSignature { signer, signature });
    }
    Ok(out)
}

fn recover_and_check(digest: &Bytes32, ms: &MultiSignature) -> Result<(), MultisigError> {
    let v = ms.signature[64];
    if v != 27 && v != 28 {
        return Err(MultisigError::BadSignature);
    }
    let recid = RecoveryId::from_byte(v - 27).ok_or(MultisigError::BadSignature)?;

    let mut rs = [0u8; 64];
    rs.copy_from_slice(&ms.signature[..64]);
    let sig = Signature::from_slice(&rs).map_err(|_| MultisigError::BadSignature)?;

    let vk = VerifyingKey::recover_from_prehash(digest, &sig, recid)
        .map_err(|_| MultisigError::BadSignature)?;

    if address_from_verifying_key(&vk) != ms.signer {
        return Err(MultisigError::BadSignature);
    }
    Ok(())
}

pub fn address_from_verifying_key(vk: &VerifyingKey) -> Address {
    let ep = vk.to_encoded_point(false);
    let bytes = ep.as_bytes();
    debug_assert_eq!(bytes.len(), 65);
    debug_assert_eq!(bytes[0], 0x04);
    let digest = Keccak256::digest(&bytes[1..]);
    let mut out = [0u8; 20];
    out.copy_from_slice(&digest[12..]);
    out
}

#[cfg(test)]
mod tests {
    use k256::elliptic_curve::rand_core::OsRng;

    use super::*;

    fn fresh_signer() -> (SecretKey, Address) {
        let sk = SecretKey::random(&mut OsRng);
        let signing = SigningKey::from(sk.clone());
        let addr = address_from_verifying_key(signing.verifying_key());
        (sk, addr)
    }

    fn make_owners(n: usize) -> Vec<(SecretKey, Address)> {
        (0..n).map(|_| fresh_signer()).collect()
    }

    fn digest_with(byte: u8) -> Bytes32 {
        let mut d = [0u8; 32];
        for (i, slot) in d.iter_mut().enumerate() {
            *slot = byte ^ (i as u8);
        }
        d
    }

    #[test]
    fn round_trip_4_of_7() {
        let owners_pairs = make_owners(7);
        let owners: Vec<Address> = owners_pairs.iter().map(|(_, a)| *a).collect();
        let digest = digest_with(0xA1);

        let sigs: Vec<MultiSignature> = owners_pairs
            .iter()
            .take(4)
            .map(|(sk, _)| sign_digest(sk, &digest))
            .collect();

        for (i, s) in sigs.iter().enumerate() {
            assert_eq!(s.signer, owners_pairs[i].1);
        }
        verify_threshold(&digest, &sigs, &owners, 4).expect("must verify");
    }

    #[test]
    fn rejects_wrong_count_under() {
        let owners_pairs = make_owners(7);
        let owners: Vec<Address> = owners_pairs.iter().map(|(_, a)| *a).collect();
        let digest = digest_with(0xB2);
        let sigs: Vec<MultiSignature> = owners_pairs
            .iter()
            .take(3)
            .map(|(sk, _)| sign_digest(sk, &digest))
            .collect();

        assert_eq!(
            verify_threshold(&digest, &sigs, &owners, 4),
            Err(MultisigError::WrongCount)
        );
    }

    #[test]
    fn rejects_wrong_count_over() {
        let owners_pairs = make_owners(7);
        let owners: Vec<Address> = owners_pairs.iter().map(|(_, a)| *a).collect();
        let digest = digest_with(0xC3);
        let sigs: Vec<MultiSignature> = owners_pairs
            .iter()
            .take(5)
            .map(|(sk, _)| sign_digest(sk, &digest))
            .collect();

        assert_eq!(
            verify_threshold(&digest, &sigs, &owners, 4),
            Err(MultisigError::WrongCount)
        );
    }

    #[test]
    fn rejects_duplicate_signer() {
        let owners_pairs = make_owners(7);
        let owners: Vec<Address> = owners_pairs.iter().map(|(_, a)| *a).collect();
        let digest = digest_with(0xD4);
        let s0 = sign_digest(&owners_pairs[0].0, &digest);
        let s1 = sign_digest(&owners_pairs[1].0, &digest);
        let s2 = sign_digest(&owners_pairs[2].0, &digest);
        let sigs = vec![s0, s1, s2, s0];

        assert_eq!(
            verify_threshold(&digest, &sigs, &owners, 4),
            Err(MultisigError::DuplicateSigner)
        );
    }

    #[test]
    fn rejects_unknown_signer() {
        let owners_pairs = make_owners(7);
        let owners: Vec<Address> = owners_pairs.iter().map(|(_, a)| *a).collect();
        let outsider = fresh_signer();
        let digest = digest_with(0xE5);
        let mut sigs: Vec<MultiSignature> = owners_pairs
            .iter()
            .take(3)
            .map(|(sk, _)| sign_digest(sk, &digest))
            .collect();
        sigs.push(sign_digest(&outsider.0, &digest));

        assert_eq!(
            verify_threshold(&digest, &sigs, &owners, 4),
            Err(MultisigError::UnknownSigner)
        );
    }

    #[test]
    fn rejects_tampered_byte() {
        let owners_pairs = make_owners(7);
        let owners: Vec<Address> = owners_pairs.iter().map(|(_, a)| *a).collect();
        let digest = digest_with(0xF6);
        let mut sigs: Vec<MultiSignature> = owners_pairs
            .iter()
            .take(4)
            .map(|(sk, _)| sign_digest(sk, &digest))
            .collect();
        sigs[0].signature[5] ^= 0x01;

        assert_eq!(
            verify_threshold(&digest, &sigs, &owners, 4),
            Err(MultisigError::BadSignature)
        );
    }

    #[test]
    fn encode_decode_round_trip() {
        let owners_pairs = make_owners(7);
        let digest = digest_with(0x07);
        let sigs: Vec<MultiSignature> = owners_pairs
            .iter()
            .take(4)
            .map(|(sk, _)| sign_digest(sk, &digest))
            .collect();

        let bytes = encode_threshold(&sigs);
        let decoded = decode_threshold(&bytes, 4).expect("must decode");

        assert_eq!(decoded.len(), sigs.len());
        for (a, b) in decoded.iter().zip(sigs.iter()) {
            assert_eq!(a.signer, b.signer);
            assert_eq!(a.signature, b.signature);
        }
        assert_eq!(encode_threshold(&decoded), bytes);
        assert_eq!(bytes.len(), 1 + 4 * SIG_RECORD_LEN);
    }

    #[test]
    fn decode_rejects_count_mismatch() {
        let owners_pairs = make_owners(7);
        let digest = digest_with(0x08);
        let sigs: Vec<MultiSignature> = owners_pairs
            .iter()
            .take(4)
            .map(|(sk, _)| sign_digest(sk, &digest))
            .collect();
        let bytes = encode_threshold(&sigs);

        assert_eq!(
            decode_threshold(&bytes, 5).unwrap_err(),
            MultisigError::WrongCount
        );
        assert_eq!(
            decode_threshold(&bytes, 3).unwrap_err(),
            MultisigError::WrongCount
        );
    }

    #[test]
    fn decode_rejects_truncated() {
        let owners_pairs = make_owners(7);
        let digest = digest_with(0x09);
        let sigs: Vec<MultiSignature> = owners_pairs
            .iter()
            .take(4)
            .map(|(sk, _)| sign_digest(sk, &digest))
            .collect();
        let mut bytes = encode_threshold(&sigs);
        bytes.pop();

        assert_eq!(
            decode_threshold(&bytes, 4).unwrap_err(),
            MultisigError::WrongCount
        );
    }
}
