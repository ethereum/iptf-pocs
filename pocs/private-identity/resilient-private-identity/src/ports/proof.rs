use ark_bn254::{
    Fr,
    G1Affine,
};

use crate::{
    error::ProofError,
    types::{
        DleqProof,
        MerklePath,
        Predicate,
        SvdwWitnesses,
    },
};

/// Verifies a link proof (pi_link). Used by MPC nodes to gate OPRF evaluation.
/// Separate from ProofBackend because MPC nodes verify but don't generate proofs.
pub trait LinkProofVerifier: Send + Sync {
    fn verify_link_proof(
        &self,
        proof: &[u8],
        identity_commitment: Fr,
        blinded_request: G1Affine,
        g_id: G1Affine,
    ) -> Result<bool, ProofError>;
}

pub trait ProofBackend: Send + Sync {
    fn generate_membership_proof(
        &self,
        identity_secret: Fr,
        attrs: &[Fr; 4],
        version: u32,
        merkle_path: &MerklePath,
        root: Fr,
        external_nullifier: Fr,
        predicate: &Predicate,
    ) -> Result<Vec<u8>, ProofError>;

    fn generate_enrollment_proof(
        &self,
        identity_secret: Fr,
        attrs: &[Fr; 4],
        version: u32,
        g_id: G1Affine,
        raw_nullifier: G1Affine,
        mpc_public_key: G1Affine,
        dleq_proof: &DleqProof,
    ) -> Result<Vec<u8>, ProofError>;

    fn generate_link_proof(
        &self,
        user_id_hash: Fr,
        salt: Fr,
        r: Fr,
        g_id: G1Affine,
        identity_commitment: Fr,
        blinded_request: G1Affine,
        svdw: &SvdwWitnesses,
    ) -> Result<Vec<u8>, ProofError>;
}
