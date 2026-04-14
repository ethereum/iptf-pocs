use ark_bn254::{
    Fq,
    Fr,
    G1Affine,
};

// Domain tag constants matching circuits/lib/src/domain.nr
// NOTE: DOMAIN_MERKLE_NODE (0) omitted -- merkle hashing uses no tag
pub const DOMAIN_LEAF: u64 = 1;
pub const DOMAIN_NULLIFIER: u64 = 2;
pub const DOMAIN_ENROLLMENT_NULL: u64 = 3;
pub const DOMAIN_ATTR: u64 = 4;
pub const DOMAIN_EXTERNAL_NULLIFIER: u64 = 5;
pub const DOMAIN_NAME: u64 = 6;
pub const DOMAIN_LINK: u64 = 7;
pub const DOMAIN_H2C: u64 = 8;

#[derive(Debug, Clone)]
pub struct Identity {
    pub identity_secret: Fr,
    pub attrs: [Fr; 4],
    pub version: u32,
    pub leaf_index: u32,
}

#[derive(Debug, Clone)]
pub struct EnrollmentData {
    pub leaf: Fr,
    pub enrollment_nullifier: Fr,
    pub raw_nullifier: G1Affine,
    pub g_id: G1Affine,
    pub mpc_public_key: G1Affine,
    pub chaum_pedersen_proof: DleqProof,
}

#[derive(Debug, Clone)]
pub struct DleqProof {
    pub c: Fr,
    pub z: Fr,
}

#[derive(Debug, Clone)]
pub struct MembershipProofData {
    pub proof_bytes: Vec<u8>,
    pub root: Fr,
    pub nullifier: Fr,
    pub external_nullifier: Fr,
    pub version: u32,
    pub predicate_type: u32,
    pub predicate_attr_index: u32,
    pub predicate_value: Fr,
    pub predicate_result: Fr,
}

#[derive(Debug, Clone)]
pub struct MerklePath {
    pub siblings: Vec<Fr>,
    pub indices: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct Predicate {
    pub predicate_type: u32,
    pub attr_index: u32,
    pub value: Fr,
}

/// SVDW circuit witnesses for the link proof.
/// Contains all values the prover needs to supply alongside the public inputs.
#[derive(Debug, Clone)]
pub struct SvdwWitnesses {
    /// Which SVDW candidate was selected (0, 1, or 2).
    pub index: u8,
    /// Division witness: w = sqrt(-3) * t / (4 + t²).
    pub w: Fq,
    /// Inverse witness: 1/w².
    pub inv_w2: Fq,
    /// Non-QR witnesses for earlier failed candidates.
    pub non_qr_witnesses: [Fq; 2],
}

/// A partial evaluation from a single MPC node.
#[derive(Debug, Clone)]
pub struct PartialEvaluation {
    pub node_index: usize,
    pub partial: G1Affine,
    pub proof: DleqProof,
}
