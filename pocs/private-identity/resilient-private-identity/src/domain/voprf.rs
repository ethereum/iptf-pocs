/// vOPRF domain logic: blinding, DLEQ proofs, Shamir secret sharing, and
/// Lagrange aggregation.
///
/// Combined from the former voprf/blinding.rs, voprf/dleq.rs, and the
/// pure-math portions of voprf/mock_mpc.rs.
use ark_bn254::{
    Fq,
    Fr,
    G1Affine,
    G1Projective,
};
use ark_ec::{
    AffineRepr,
    CurveGroup,
};
use ark_ff::{
    BigInteger,
    Field,
    PrimeField,
};
use ark_std::UniformRand;
use sha2::{
    Digest,
    Sha256,
};

use crate::poseidon::hash_h2c;

use crate::types::DleqProof;

// Blinding helpers

/// Blind a curve point by multiplying with a random scalar.
pub fn blind(g_id: G1Affine, r: Fr) -> G1Affine {
    (G1Projective::from(g_id) * r).into_affine()
}

/// Unblind a curve point by dividing out the blinding factor.
pub fn unblind(aggregated: G1Affine, r: Fr) -> G1Affine {
    (G1Projective::from(aggregated) * r.inverse().unwrap()).into_affine()
}

// SVDW (Fouque-Tibouchi) hash-to-curve for BN254

/// sqrt(-3) mod q, even-parity canonical root.
/// Computed: (-Fq(3)).sqrt(), negated if odd.
fn svdw_sqrt_neg3() -> Fq {
    use core::str::FromStr;
    Fq::from_str(
        "21888242871839275217838484774961031245859103671646299620740479376884814904650",
    )
    .unwrap()
}

/// C1 = (sqrt(-3) - 1) / 2 mod q.
fn svdw_c1() -> Fq {
    use core::str::FromStr;
    Fq::from_str(
        "21888242871839275220042445260109153167277707414472061641714758635765020556616",
    )
    .unwrap()
}

/// SVDW candidate x-coordinates from field element t.
fn svdw_candidates(t: Fq) -> [Fq; 3] {
    let sqrt_neg3 = svdw_sqrt_neg3();
    let c1 = svdw_c1();

    let t2 = t * t;
    let denom = Fq::from(4u64) + t2;
    let w = sqrt_neg3 * t * denom.inverse().unwrap();

    let x1 = c1 - t * w;
    let x2 = -(Fq::from(1u64) + x1);
    let w2 = w * w;
    let x3 = Fq::from(1u64) + w2.inverse().unwrap();

    [x1, x2, x3]
}

/// Canonicalize y to even parity. If y is odd, return q - y (which is even).
fn canonicalize_y(y: Fq) -> Fq {
    let y_bytes = y.into_bigint().to_bytes_le();
    if y_bytes[0] & 1 == 1 {
        -y // odd → negate to get even
    } else {
        y
    }
}

/// Fr → Fq conversion. Since Fr modulus < Fq modulus, the value is preserved.
fn fr_to_fq(fr: Fr) -> Fq {
    Fq::from_le_bytes_mod_order(&fr.into_bigint().to_bytes_le())
}

/// Result of SVDW hash-to-curve, including all witnesses needed for the circuit.
pub struct SvdwResult {
    /// The curve point G_id.
    pub point: G1Affine,
    /// Which candidate index was selected (0, 1, or 2).
    pub index: u8,
    /// Division witness: w = sqrt(-3) * t / (4 + t²).
    pub w: Fq,
    /// Inverse witness: 1/w².
    pub inv_w2: Fq,
    /// Non-QR witnesses for earlier failed candidates. sqrt(-rhs) for each i < index.
    /// Unused slots are Fq::from(0).
    pub non_qr_witnesses: [Fq; 2],
}

/// Fouque-Tibouchi (SVDW) hash-to-curve for BN254 G1.
///
/// Maps user_id_hash to a BN254 curve point deterministically using the
/// Shallue-van de Woestijne construction adapted for BN curves (j=0).
///
/// 1. t = Poseidon(DOMAIN_H2C, user_id_hash): single hash
/// 2. Compute 3 candidate x-coordinates via SVDW algebraic map
/// 3. Select first candidate where x³+3 is a quadratic residue
/// 4. y = sqrt(x³+3), canonicalized to even parity
///
/// Returns SvdwResult with the point and all circuit witnesses.
/// The discrete log of G_id w.r.t. G is unknown, preventing ratio attacks.
pub fn hash_to_curve(user_id_hash: Fr) -> SvdwResult {
    let t_fr = hash_h2c(user_id_hash);
    assert!(t_fr != Fr::from(0u64), "hash_to_curve: t must be nonzero");

    let t = fr_to_fq(t_fr);
    let sqrt_neg3 = svdw_sqrt_neg3();

    let t2 = t * t;
    let denom = Fq::from(4u64) + t2;
    let w = sqrt_neg3 * t * denom.inverse().unwrap();
    let w2 = w * w;
    let inv_w2 = w2.inverse().unwrap();

    let candidates = svdw_candidates(t);
    let mut non_qr_witnesses = [Fq::from(0u64); 2];

    for (i, &x) in candidates.iter().enumerate() {
        let rhs = x * x * x + Fq::from(3u64);

        if let Some(y) = rhs.sqrt() {
            // Compute non-QR witnesses for earlier candidates
            for j in 0..i {
                let rhs_j =
                    candidates[j] * candidates[j] * candidates[j] + Fq::from(3u64);
                let neg_rhs_j = -rhs_j;
                non_qr_witnesses[j] = neg_rhs_j.sqrt().expect("non-QR * (-1) must be QR");
            }

            let y_final = canonicalize_y(y);
            let point = G1Affine::new_unchecked(x, y_final);
            assert!(point.is_on_curve(), "hash_to_curve: point not on curve");
            assert!(!point.is_zero(), "hash_to_curve: point is identity");

            return SvdwResult {
                point,
                index: i as u8,
                w,
                inv_w2,
                non_qr_witnesses,
            };
        }
    }
    unreachable!("SVDW always produces at least one valid candidate");
}

// DLEQ proofs

/// Serialize an Fq coordinate to 32 bytes big-endian.
fn fq_to_be_bytes(fq: &Fq) -> [u8; 32] {
    let bigint = fq.into_bigint();
    let le_bytes = bigint.to_bytes_le();
    let mut be_bytes = [0u8; 32];
    for i in 0..32 {
        be_bytes[i] = le_bytes[31 - i];
    }
    be_bytes
}

/// Convert 32 SHA-256 output bytes to an Fr element via the
/// byte-by-byte accumulation that matches the Noir circuit:
/// c = sum(byte[i] * 256^(31-i))
fn bytes_to_fr(bytes: &[u8; 32]) -> Fr {
    let mut result = Fr::from(0u64);
    let base = Fr::from(256u64);
    for &b in bytes.iter() {
        result = result * base + Fr::from(b as u64);
    }
    result
}

/// Serialize a G1Affine point as x || y, each as 32 bytes big-endian.
fn point_bytes(p: &G1Affine) -> [u8; 64] {
    let x_bytes = fq_to_be_bytes(&p.x);
    let y_bytes = fq_to_be_bytes(&p.y);
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&x_bytes);
    out[32..].copy_from_slice(&y_bytes);
    out
}

/// Fiat-Shamir challenge: c = SHA-256(G || PK || G_id || Q || R1 || R2) mod r
///
/// 6 points, each serialized as x(32B BE) || y(32B BE) = 64 bytes.
/// Total: 384 bytes.
fn fiat_shamir_challenge(
    g: &G1Affine,
    pk: &G1Affine,
    g_id: &G1Affine,
    q: &G1Affine,
    r1: &G1Affine,
    r2: &G1Affine,
) -> Fr {
    let mut data = [0u8; 384];
    data[0..64].copy_from_slice(&point_bytes(g));
    data[64..128].copy_from_slice(&point_bytes(pk));
    data[128..192].copy_from_slice(&point_bytes(g_id));
    data[192..256].copy_from_slice(&point_bytes(q));
    data[256..320].copy_from_slice(&point_bytes(r1));
    data[320..384].copy_from_slice(&point_bytes(r2));

    let hash = Sha256::digest(&data);
    let hash_arr: [u8; 32] = hash.into();
    bytes_to_fr(&hash_arr)
}

/// Produce a DLEQ proof that PK = secret * G and Q = secret * G_id.
///
/// Returns (Q, proof) where Q is the evaluated vOPRF output.
pub fn prove_dleq(secret: Fr, g_id: G1Affine) -> (G1Affine, DleqProof) {
    let g = G1Affine::generator();
    let pk: G1Affine = (G1Projective::from(g) * secret).into_affine();
    let q: G1Affine = (G1Projective::from(g_id) * secret).into_affine();

    let k = Fr::rand(&mut ark_std::rand::thread_rng());
    let r1: G1Affine = (G1Projective::from(g) * k).into_affine();
    let r2: G1Affine = (G1Projective::from(g_id) * k).into_affine();

    let c = fiat_shamir_challenge(&g, &pk, &g_id, &q, &r1, &r2);
    let z = k - c * secret;

    (q, DleqProof { c, z })
}

/// Verify a DLEQ proof: check that PK and Q use the same discrete log
/// relative to G and G_id respectively.
pub fn verify_dleq(pk: G1Affine, g_id: G1Affine, q: G1Affine, proof: &DleqProof) -> bool {
    let g = G1Affine::generator();
    let r1: G1Affine = (G1Projective::from(g) * proof.z
        + G1Projective::from(pk) * proof.c)
        .into_affine();
    let r2: G1Affine = (G1Projective::from(g_id) * proof.z
        + G1Projective::from(q) * proof.c)
        .into_affine();
    let c_prime = fiat_shamir_challenge(&g, &pk, &g_id, &q, &r1, &r2);
    proof.c == c_prime
}

// Shamir secret sharing & Lagrange aggregation

/// Split a secret into n shares using a random polynomial of degree t-1
/// (Shamir's secret sharing). Evaluation points are 1..=n.
pub fn share_secret(secret: Fr, t: usize, n: usize) -> Vec<(usize, Fr)> {
    assert!(t >= 1, "threshold must be >= 1");
    assert!(t <= n, "threshold must be <= n");

    let mut rng = ark_std::rand::thread_rng();

    // Random polynomial: coeffs[0] = secret, coeffs[1..t-1] = random
    let mut coeffs = Vec::with_capacity(t);
    coeffs.push(secret);
    for _ in 1..t {
        coeffs.push(Fr::rand(&mut rng));
    }

    // Evaluate at x = 1, 2, ..., n
    (1..=n)
        .map(|i| {
            let x = Fr::from(i as u64);
            let mut y = Fr::from(0u64);
            let mut x_pow = Fr::from(1u64);
            for coeff in &coeffs {
                y += *coeff * x_pow;
                x_pow *= x;
            }
            (i, y)
        })
        .collect()
}

/// Compute Lagrange coefficients for reconstruction at x=0
/// given the set of evaluation points (indices).
pub fn lagrange_coefficients(indices: &[usize]) -> Vec<Fr> {
    indices
        .iter()
        .map(|&i| {
            let xi = Fr::from(i as u64);
            let mut num = Fr::from(1u64);
            let mut den = Fr::from(1u64);
            for &j in indices {
                if j != i {
                    let xj = Fr::from(j as u64);
                    num *= xj; // 0 - xj = -xj, but we want lambda for x=0
                    den *= xj - xi;
                }
            }
            // lambda_i = prod_{j!=i} (0 - xj) / (xi - xj) = prod_{j!=i} (-xj / (xi - xj))
            // = prod_{j!=i} (xj / (xj - xi))
            num * den.inverse().unwrap()
        })
        .collect()
}

/// Aggregate partial evaluations using Lagrange interpolation to recover
/// the full vOPRF output: result = sum(lambda_i * partial_i)
pub fn aggregate(partials: &[(usize, G1Affine)]) -> G1Affine {
    let indices: Vec<usize> = partials.iter().map(|(idx, _)| *idx).collect();
    let lambdas = lagrange_coefficients(&indices);

    let mut result = G1Projective::from(G1Affine::identity());
    for (lambda, (_, point)) in lambdas.iter().zip(partials.iter()) {
        result += G1Projective::from(*point) * lambda;
    }
    result.into_affine()
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_svdw_constants_computation() {
        // Compute sqrt(-3) in Fq
        let neg3 = -Fq::from(3u64);
        let s = neg3.sqrt().expect("sqrt(-3) must exist in BN254 Fq");

        // Verify s² == -3
        assert_eq!(s * s, neg3, "s² != -3");

        // Canonicalize to even parity (LSB == 0)
        let s_bigint = s.into_bigint();
        let s_bytes = s_bigint.to_bytes_le();
        let s_is_even = s_bytes[0] & 1 == 0;
        let sqrt_neg3 = if s_is_even { s } else { -s };

        // Verify canonicalized value
        assert_eq!(sqrt_neg3 * sqrt_neg3, neg3);
        let sn3_bytes = sqrt_neg3.into_bigint().to_bytes_le();
        assert_eq!(sn3_bytes[0] & 1, 0, "SQRT_NEG3 must have even parity");

        // Compute C1 = (SQRT_NEG3 - 1) / 2
        let one = Fq::from(1u64);
        let two_inv = Fq::from(2u64).inverse().unwrap();
        let c1 = (sqrt_neg3 - one) * two_inv;

        // Verify 2*c1 + 1 == sqrt_neg3
        assert_eq!(c1 + c1 + one, sqrt_neg3);

        // Check both fit in Fr (value < Fr modulus)
        let fr_modulus_bytes = Fr::MODULUS.to_bytes_le();
        let sn3_le = sqrt_neg3.into_bigint().to_bytes_le();
        let c1_le = c1.into_bigint().to_bytes_le();

        // Compare as big-endian (reverse for lexicographic comparison)
        let sn3_fits = {
            let mut sn3_be: Vec<u8> = sn3_le.iter().copied().rev().collect();
            let mut fr_be: Vec<u8> = fr_modulus_bytes.iter().copied().rev().collect();
            sn3_be.resize(32, 0);
            fr_be.resize(32, 0);
            sn3_be < fr_be
        };
        let c1_fits = {
            let mut c1_be: Vec<u8> = c1_le.iter().copied().rev().collect();
            let mut fr_be: Vec<u8> = fr_modulus_bytes.iter().copied().rev().collect();
            c1_be.resize(32, 0);
            fr_be.resize(32, 0);
            c1_be < fr_be
        };

        assert!(sn3_fits, "SQRT_NEG3 does not fit in Fr!");
        assert!(c1_fits, "C1 does not fit in Fr!");

        // Print decimal representations for Noir embedding
        println!("SQRT_NEG3 = {}", sqrt_neg3.into_bigint());
        println!("C1        = {}", c1.into_bigint());
    }

    fn test_user_id_hash(input: &[u8]) -> Fr {
        let hash = Sha256::digest(input);
        Fr::from_be_bytes_mod_order(&hash)
    }

    #[test]
    fn test_blind_unblind_roundtrip() {
        let mut rng = ark_std::rand::thread_rng();
        let svdw = hash_to_curve(test_user_id_hash(b"alice@example.com"));
        let r = Fr::rand(&mut rng);

        let blinded = blind(svdw.point, r);
        let unblinded = unblind(blinded, r);
        assert_eq!(svdw.point, unblinded);
    }

    #[test]
    fn test_hash_to_curve_deterministic() {
        let r1 = hash_to_curve(test_user_id_hash(b"test-user"));
        let r2 = hash_to_curve(test_user_id_hash(b"test-user"));
        assert_eq!(r1.point, r2.point);
        assert_eq!(r1.index, r2.index);
    }

    #[test]
    fn test_hash_to_curve_different_inputs() {
        let r1 = hash_to_curve(test_user_id_hash(b"alice"));
        let r2 = hash_to_curve(test_user_id_hash(b"bob"));
        assert_ne!(r1.point, r2.point);
    }

    #[test]
    fn test_hash_to_curve_point_on_curve() {
        let svdw = hash_to_curve(test_user_id_hash(b"test@example.com"));
        assert!(svdw.point.is_on_curve());
        assert!(!svdw.point.is_zero());
        assert!(svdw.index < 3);
    }

    #[test]
    fn test_svdw_y_parity() {
        // Verify all outputs have even-parity y
        for input in &[b"alice" as &[u8], b"bob", b"carol", b"dave", b"eve"] {
            let svdw = hash_to_curve(test_user_id_hash(input));
            let y_bytes = svdw.point.y.into_bigint().to_bytes_le();
            assert_eq!(
                y_bytes[0] & 1,
                0,
                "y must have even parity for input {:?}",
                input
            );
        }
    }

    #[test]
    fn test_svdw_witnesses_valid() {
        // Verify non-QR witnesses satisfy w² == -rhs for earlier candidates
        let svdw = hash_to_curve(test_user_id_hash(b"witness-test"));
        let t_fr = hash_h2c(test_user_id_hash(b"witness-test"));
        let t = fr_to_fq(t_fr);
        let candidates = svdw_candidates(t);

        for j in 0..(svdw.index as usize) {
            let rhs = candidates[j] * candidates[j] * candidates[j] + Fq::from(3u64);
            let neg_rhs = -rhs;
            let w = svdw.non_qr_witnesses[j];
            assert_eq!(w * w, neg_rhs, "non-QR witness invalid for candidate {j}");
        }

        // Verify division witnesses
        let sqrt_neg3 = svdw_sqrt_neg3();
        let t2 = t * t;
        let denom = Fq::from(4u64) + t2;
        assert_eq!(svdw.w * denom, sqrt_neg3 * t, "w witness invalid");
        assert_eq!(
            svdw.inv_w2 * svdw.w * svdw.w,
            Fq::from(1u64),
            "inv_w2 witness invalid"
        );
    }

    #[test]
    fn test_generate_link_proof_prover_toml() {
        use crate::poseidon::hash_link;

        let user_id_hash = test_user_id_hash(b"prover-toml-test");
        let salt = Fr::from(12345u64);
        let r = Fr::from(67890u64);

        let svdw = hash_to_curve(user_id_hash);
        let g_id = svdw.point;
        let identity_commitment = hash_link(user_id_hash, salt);
        let blinded_request = blind(g_id, r);

        println!("--- Prover.toml for link_proof ---");
        println!(
            "identity_commitment = \"{}\"",
            Fr::into_bigint(identity_commitment)
        );
        println!(
            "blinded_request_x = \"{}\"",
            blinded_request.x.into_bigint()
        );
        println!(
            "blinded_request_y = \"{}\"",
            blinded_request.y.into_bigint()
        );
        println!("g_id_x = \"{}\"", g_id.x.into_bigint());
        println!("g_id_y = \"{}\"", g_id.y.into_bigint());
        println!("user_id_hash = \"{}\"", Fr::into_bigint(user_id_hash));
        println!("salt = \"{}\"", Fr::into_bigint(salt));
        println!("r = \"{}\"", Fr::into_bigint(r));
        println!("svdw_index = \"{}\"", svdw.index);
        println!("svdw_w = \"{}\"", svdw.w.into_bigint());
        println!("svdw_inv_w2 = \"{}\"", svdw.inv_w2.into_bigint());
        println!(
            "non_qr_witness_0 = \"{}\"",
            svdw.non_qr_witnesses[0].into_bigint()
        );
        println!(
            "non_qr_witness_1 = \"{}\"",
            svdw.non_qr_witnesses[1].into_bigint()
        );

        // Sanity: y must be even
        let y_bytes = g_id.y.into_bigint().to_bytes_le();
        assert_eq!(y_bytes[0] & 1, 0, "g_id_y must be even");
    }

    #[test]
    fn test_prove_verify_roundtrip() {
        let secret = Fr::rand(&mut ark_std::rand::thread_rng());
        let svdw = hash_to_curve(test_user_id_hash(b"alice@example.com"));
        let (q, proof) = prove_dleq(secret, svdw.point);

        let g = G1Affine::generator();
        let pk: G1Affine = (G1Projective::from(g) * secret).into_affine();

        assert!(verify_dleq(pk, svdw.point, q, &proof));
    }

    #[test]
    fn test_wrong_secret_fails() {
        let secret = Fr::rand(&mut ark_std::rand::thread_rng());
        let wrong_secret = Fr::rand(&mut ark_std::rand::thread_rng());
        let svdw = hash_to_curve(test_user_id_hash(b"bob@example.com"));
        let (q, proof) = prove_dleq(secret, svdw.point);

        // Compute PK with the wrong secret
        let g = G1Affine::generator();
        let wrong_pk: G1Affine = (G1Projective::from(g) * wrong_secret).into_affine();

        assert!(!verify_dleq(wrong_pk, svdw.point, q, &proof));
    }

    #[test]
    fn test_fq_to_be_bytes_roundtrip() {
        let val = Fq::from(42u64);
        let bytes = fq_to_be_bytes(&val);
        // Last byte should be 42, rest should be 0
        assert_eq!(bytes[31], 42);
        for &b in &bytes[..31] {
            assert_eq!(b, 0);
        }
    }

    #[test]
    fn test_bytes_to_fr() {
        let mut bytes = [0u8; 32];
        bytes[31] = 42;
        let fr = bytes_to_fr(&bytes);
        assert_eq!(fr, Fr::from(42u64));
    }

    #[test]
    fn test_shamir_reconstruction() {
        let mut rng = ark_std::rand::thread_rng();
        let secret = Fr::rand(&mut rng);
        let t = 3;
        let n = 5;
        let shares = share_secret(secret, t, n);

        // Reconstruct using the first t shares
        let subset: Vec<usize> = shares[..t].iter().map(|(i, _)| *i).collect();
        let lambdas = lagrange_coefficients(&subset);

        let mut reconstructed = Fr::from(0u64);
        for (lambda, (_, share)) in lambdas.iter().zip(shares[..t].iter()) {
            reconstructed += *lambda * share;
        }
        assert_eq!(secret, reconstructed);
    }
}
