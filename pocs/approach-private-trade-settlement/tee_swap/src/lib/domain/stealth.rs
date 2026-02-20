use alloy_primitives::B256;
use ark_ec::{CurveGroup, PrimeGroup};
use ark_grumpkin::{Affine, Fr as GrumpkinScalar, Projective};
use ark_std::UniformRand;

use crate::crypto::stealth::affine_x_to_b256;

/// A meta key pair for stealth address derivation.
///
/// The meta public key is shared publicly (or via the swap terms). A sender
/// uses it to derive a one-time stealth address that only the meta key owner
/// can spend from.
#[derive(Debug, Clone)]
pub struct MetaKeyPair {
    /// Secret key (Grumpkin scalar)
    pub sk: GrumpkinScalar,
    /// Public key (Grumpkin affine point)
    pub pk: Affine,
}

impl MetaKeyPair {
    /// Generate a new random meta key pair.
    pub fn generate<R: rand::Rng + ?Sized>(rng: &mut R) -> Self {
        let sk = GrumpkinScalar::rand(rng);
        let pk = (Projective::generator() * sk).into_affine();
        Self { sk, pk }
    }

    /// Reconstruct from a known secret key.
    pub fn from_secret(sk: GrumpkinScalar) -> Self {
        let pk = (Projective::generator() * sk).into_affine();
        Self { sk, pk }
    }

    /// Get the public key x-coordinate as B256 (for use in note fields).
    pub fn pk_x(&self) -> B256 {
        affine_x_to_b256(&self.pk)
    }
}

/// An ephemeral key pair used by the sender for a single swap.
///
/// The ephemeral secret `r` is used to derive the stealth address and encrypt
/// the salt. The ephemeral public key `R = r·G` is revealed by the TEE after
/// both parties lock their notes.
#[derive(Debug, Clone)]
pub struct EphemeralKeyPair {
    /// Ephemeral secret key (Grumpkin scalar)
    pub r: GrumpkinScalar,
    /// Ephemeral public key R = r·G (Grumpkin affine point)
    pub r_pub: Affine,
}

impl EphemeralKeyPair {
    /// Generate a new random ephemeral key pair.
    pub fn generate<R: rand::Rng + ?Sized>(rng: &mut R) -> Self {
        let r = GrumpkinScalar::rand(rng);
        let r_pub = (Projective::generator() * r).into_affine();
        Self { r, r_pub }
    }

    /// Get the public key x-coordinate as B256.
    pub fn r_pub_x(&self) -> B256 {
        affine_x_to_b256(&self.r_pub)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_meta_key_pair_generation() {
        let mut rng = ark_std::test_rng();
        let kp = MetaKeyPair::generate(&mut rng);

        // pk = sk · G
        let expected_pk = (Projective::generator() * kp.sk).into_affine();
        assert_eq!(kp.pk, expected_pk);
    }

    #[test]
    fn test_meta_key_pair_from_secret() {
        let mut rng = ark_std::test_rng();
        let sk = GrumpkinScalar::rand(&mut rng);
        let kp = MetaKeyPair::from_secret(sk);

        let expected_pk = (Projective::generator() * sk).into_affine();
        assert_eq!(kp.pk, expected_pk);
    }

    #[test]
    fn test_meta_key_pair_pk_x_nonzero() {
        let mut rng = ark_std::test_rng();
        let kp = MetaKeyPair::generate(&mut rng);
        assert_ne!(kp.pk_x(), B256::ZERO);
    }

    #[test]
    fn test_ephemeral_key_pair_generation() {
        let mut rng = ark_std::test_rng();
        let ekp = EphemeralKeyPair::generate(&mut rng);

        let expected_r_pub = (Projective::generator() * ekp.r).into_affine();
        assert_eq!(ekp.r_pub, expected_r_pub);
    }

    #[test]
    fn test_ephemeral_key_pair_r_pub_x_nonzero() {
        let mut rng = ark_std::test_rng();
        let ekp = EphemeralKeyPair::generate(&mut rng);
        assert_ne!(ekp.r_pub_x(), B256::ZERO);
    }

    #[test]
    fn test_different_key_pairs_are_different() {
        let mut rng = ark_std::test_rng();
        let kp1 = MetaKeyPair::generate(&mut rng);
        let kp2 = MetaKeyPair::generate(&mut rng);
        assert_ne!(kp1.pk_x(), kp2.pk_x());
    }
}
