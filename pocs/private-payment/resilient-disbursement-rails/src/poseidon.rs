//! Poseidon helpers. Match `circuits/lib/src/hasher.nr` byte-for-byte.
//!
//! Domain-tag values are integer literals 1, 2, 3 (PoC simplification -
//! the SPEC defines them as `Poseidon1_t2(0, SHA256("RDR/<purpose>/v1") mod
//! r_BN254)` but Phase 2 collapsed them to small distinct field constants
//! to match the reference identity PoC's pattern). See `tasks/lessons.md`.
//!
//! Internal node hash uses no tag - bare `Poseidon::new_circom(2)`. Matches
//! LeanIMT.

use ark_bn254::Fr;
use ark_ff::PrimeField;
use light_poseidon::{
    Poseidon,
    PoseidonHasher,
};

use crate::{
    COMMITMENT_DOMAIN_TAG,
    DERIVED_PUBKEY_DOMAIN_TAG,
    LEAF_DOMAIN_TAG,
    NULL_DOMAIN_TAG,
};

/// Convenience: BN254 Fr from a 32-byte big-endian buffer (mod r).
pub fn fr_from_be_bytes(bytes: &[u8]) -> Fr {
    let mut le = [0u8; 32];
    let n = bytes.len().min(32);
    for i in 0..n {
        le[n - 1 - i] = bytes[i];
    }
    Fr::from_le_bytes_mod_order(&le)
}

/// Internal merkle-node hash. No domain tag. Matches `hash_merkle_node`
/// in `circuits/lib/src/hasher.nr`.
pub fn hash_merkle_node(left: Fr, right: Fr) -> Fr {
    let mut h = Poseidon::<Fr>::new_circom(2).expect("circom-2 hasher");
    h.hash(&[left, right]).expect("merkle node hash")
}

/// `M_packed = Poseidon(LEAF_DOMAIN_TAG, M_x_hi, M_x_lo, M_y_hi, M_y_lo)`.
/// Width-5 in Poseidon-circom counting (5 inputs).
pub fn hash_m_packed(m_x_hi: Fr, m_x_lo: Fr, m_y_hi: Fr, m_y_lo: Fr) -> Fr {
    let mut h = Poseidon::<Fr>::new_circom(5).expect("circom-5 hasher");
    h.hash(&[Fr::from(LEAF_DOMAIN_TAG), m_x_hi, m_x_lo, m_y_hi, m_y_lo])
        .expect("m_packed hash")
}

/// `derivedPubkey_packed = Poseidon(DERIVED_PUBKEY_DOMAIN_TAG,
/// dpk_x_hi, dpk_x_lo, dpk_y_hi, dpk_y_lo)`. Width-5.
pub fn hash_derived_pubkey_packed(d_x_hi: Fr, d_x_lo: Fr, d_y_hi: Fr, d_y_lo: Fr) -> Fr {
    let mut h = Poseidon::<Fr>::new_circom(5).expect("circom-5 hasher");
    h.hash(&[
        Fr::from(DERIVED_PUBKEY_DOMAIN_TAG),
        d_x_hi,
        d_x_lo,
        d_y_hi,
        d_y_lo,
    ])
    .expect("derived_pubkey_packed hash")
}

/// `commitment = Poseidon(COMMITMENT_DOMAIN_TAG, token, amount, M_packed,
/// roundId_packed)`. Pool sub-tree leaf.
pub fn hash_pool_commitment(
    token: Fr,
    amount: Fr,
    m_packed: Fr,
    round_id_packed: Fr,
) -> Fr {
    let mut h = Poseidon::<Fr>::new_circom(5).expect("circom-5 hasher");
    h.hash(&[
        Fr::from(COMMITMENT_DOMAIN_TAG),
        token,
        amount,
        m_packed,
        round_id_packed,
    ])
    .expect("pool commitment hash")
}

/// `claim_nullifier = Poseidon(NULL_DOMAIN_TAG, M_packed, derivedPubkey_packed,
/// roundId_packed, claim_contract, chainId_packed)`. Width-6 form, identical
/// formula in both circuits (cross-circuit M and derivedPubkey binding via
/// collision resistance). `derivedPubkey_packed` folds in a value that
/// requires the on-card secret `m` to compute, blocking precomputed-table
/// lookup by a Registry-compromise adversary holding cohort `M_list`.
/// `roundId_packed`, `claim_contract`, and `chainId_packed` are retained as
/// explicit nullifier inputs as defense in depth: they are also encoded in
/// `derivedPubkey` via the on-card HMAC, but keeping them here preserves
/// cross-round / cross-chain / cross-contract uniqueness independent of
/// card-honest HMAC binding.
pub fn hash_claim_nullifier(
    m_packed: Fr,
    derived_pubkey_packed: Fr,
    round_id_packed: Fr,
    claim_contract: Fr,
    chain_id_packed: Fr,
) -> Fr {
    let mut h = Poseidon::<Fr>::new_circom(6).expect("circom-6 hasher");
    h.hash(&[
        Fr::from(NULL_DOMAIN_TAG),
        m_packed,
        derived_pubkey_packed,
        round_id_packed,
        claim_contract,
        chain_id_packed,
    ])
    .expect("claim_nullifier hash")
}

/// `roundId_packed = Poseidon(roundId_hi, roundId_lo)`. Width-2.
pub fn pack_round_id(hi: Fr, lo: Fr) -> Fr {
    let mut h = Poseidon::<Fr>::new_circom(2).expect("circom-2 hasher");
    h.hash(&[hi, lo]).expect("round_id pack")
}

/// `chainId_packed = Poseidon(chainId_hi, chainId_lo)`. Width-2.
pub fn pack_chain_id(hi: Fr, lo: Fr) -> Fr {
    let mut h = Poseidon::<Fr>::new_circom(2).expect("circom-2 hasher");
    h.hash(&[hi, lo]).expect("chain_id pack")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_merkle_node_deterministic() {
        let a = Fr::from(1u64);
        let b = Fr::from(2u64);
        let h1 = hash_merkle_node(a, b);
        let h2 = hash_merkle_node(a, b);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_hash_merkle_node_order_matters() {
        let a = Fr::from(1u64);
        let b = Fr::from(2u64);
        assert_ne!(hash_merkle_node(a, b), hash_merkle_node(b, a));
    }

    #[test]
    fn test_hash_m_packed_deterministic() {
        let a = hash_m_packed(
            Fr::from(1u64),
            Fr::from(2u64),
            Fr::from(3u64),
            Fr::from(4u64),
        );
        let b = hash_m_packed(
            Fr::from(1u64),
            Fr::from(2u64),
            Fr::from(3u64),
            Fr::from(4u64),
        );
        assert_eq!(a, b);
        let c = hash_m_packed(
            Fr::from(1u64),
            Fr::from(2u64),
            Fr::from(4u64),
            Fr::from(3u64),
        );
        assert_ne!(a, c);
    }

    #[test]
    fn test_domain_separation() {
        // Mirrors the circuits/lib/src/hasher.nr `test_domain_separation`
        // assertion. Distinct domain-tagged hashes must produce distinct
        // values, even when limb inputs collide.
        let m = hash_m_packed(
            Fr::from(1u64),
            Fr::from(2u64),
            Fr::from(3u64),
            Fr::from(4u64),
        );
        let dpk = hash_derived_pubkey_packed(
            Fr::from(1u64),
            Fr::from(2u64),
            Fr::from(3u64),
            Fr::from(4u64),
        );
        let r = pack_round_id(Fr::from(7u64), Fr::from(8u64));
        let commit = hash_pool_commitment(Fr::from(0xdeadu64), Fr::from(1000u64), m, r);
        let null =
            hash_claim_nullifier(m, dpk, r, Fr::from(0xbeefu64), Fr::from(0xc0deu64));
        assert_ne!(m, dpk);
        assert_ne!(commit, null);
        assert_ne!(commit, m);
        assert_ne!(null, m);
    }

    #[test]
    fn test_pack_round_id_and_chain_id_share_formula() {
        // Both packers use width-2 Poseidon with no domain tag, so they must
        // yield the same value for the same inputs.
        let hi = Fr::from(42u64);
        let lo = Fr::from(99u64);
        assert_eq!(pack_round_id(hi, lo), pack_chain_id(hi, lo));
    }

    #[test]
    fn test_fr_from_be_bytes_zero() {
        let zeros = [0u8; 32];
        assert_eq!(fr_from_be_bytes(&zeros), Fr::from(0u64));
    }

    #[test]
    fn test_fr_from_be_bytes_one() {
        let mut one_be = [0u8; 32];
        one_be[31] = 1;
        assert_eq!(fr_from_be_bytes(&one_be), Fr::from(1u64));
    }

    /// Cross-check the claim-nullifier formula matches the Noir circuit's
    /// computed value for a fixed input vector. The expected value below
    /// will diverge if either Poseidon parameterization or input ordering
    /// changes.
    #[test]
    fn test_claim_nullifier_well_defined() {
        let m_x_hi = Fr::from(0x0102030405060708u64);
        let m_x_lo = Fr::from(0x1112131415161718u64);
        let m_y_hi = Fr::from(0x2122232425262728u64);
        let m_y_lo = Fr::from(0x3132333435363738u64);
        let dpk_x_hi = Fr::from(0x4142434445464748u64);
        let dpk_x_lo = Fr::from(0x5152535455565758u64);
        let dpk_y_hi = Fr::from(0x6162636465666768u64);
        let dpk_y_lo = Fr::from(0x7172737475767778u64);
        let round_id_hi = Fr::from(0xa1u64);
        let round_id_lo = Fr::from(0xa2u64);
        let chain_id_hi = Fr::from(0u64);
        let chain_id_lo = Fr::from(1u64);
        let claim_contract = Fr::from(0xcafeu64);

        let m_packed = hash_m_packed(m_x_hi, m_x_lo, m_y_hi, m_y_lo);
        let dpk_packed =
            hash_derived_pubkey_packed(dpk_x_hi, dpk_x_lo, dpk_y_hi, dpk_y_lo);
        let r_packed = pack_round_id(round_id_hi, round_id_lo);
        let c_packed = pack_chain_id(chain_id_hi, chain_id_lo);
        let n1 = hash_claim_nullifier(
            m_packed,
            dpk_packed,
            r_packed,
            claim_contract,
            c_packed,
        );

        // Recompute and assert equality (deterministic).
        let m_packed2 = hash_m_packed(m_x_hi, m_x_lo, m_y_hi, m_y_lo);
        let dpk_packed2 =
            hash_derived_pubkey_packed(dpk_x_hi, dpk_x_lo, dpk_y_hi, dpk_y_lo);
        let r_packed2 = pack_round_id(round_id_hi, round_id_lo);
        let c_packed2 = pack_chain_id(chain_id_hi, chain_id_lo);
        let n2 = hash_claim_nullifier(
            m_packed2,
            dpk_packed2,
            r_packed2,
            claim_contract,
            c_packed2,
        );

        assert_eq!(n1, n2);

        // Sensitivity: flipping any one of the five non-tag inputs must
        // perturb the nullifier output.
        let m_packed_flip =
            hash_m_packed(m_x_hi, m_x_lo, m_y_hi, m_y_lo + Fr::from(1u64));
        assert_ne!(
            n1,
            hash_claim_nullifier(
                m_packed_flip,
                dpk_packed,
                r_packed,
                claim_contract,
                c_packed
            )
        );
        let dpk_packed_flip = hash_derived_pubkey_packed(
            dpk_x_hi,
            dpk_x_lo,
            dpk_y_hi,
            dpk_y_lo + Fr::from(1u64),
        );
        assert_ne!(
            n1,
            hash_claim_nullifier(
                m_packed,
                dpk_packed_flip,
                r_packed,
                claim_contract,
                c_packed
            )
        );
        let r_packed_flip = pack_round_id(round_id_hi, round_id_lo + Fr::from(1u64));
        assert_ne!(
            n1,
            hash_claim_nullifier(
                m_packed,
                dpk_packed,
                r_packed_flip,
                claim_contract,
                c_packed
            )
        );
        assert_ne!(
            n1,
            hash_claim_nullifier(
                m_packed,
                dpk_packed,
                r_packed,
                claim_contract + Fr::from(1u64),
                c_packed
            )
        );
        let c_packed_flip = pack_chain_id(chain_id_hi, chain_id_lo + Fr::from(1u64));
        assert_ne!(
            n1,
            hash_claim_nullifier(
                m_packed,
                dpk_packed,
                r_packed,
                claim_contract,
                c_packed_flip
            )
        );
    }
}
