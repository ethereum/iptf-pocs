use ark_bn254::{
    Fr,
    G1Affine,
};

use crate::{
    error::ProofError,
    ports::proof::{
        LinkProofVerifier,
        ProofBackend,
    },
    types::{
        DleqProof,
        MerklePath,
        Predicate,
        SvdwWitnesses,
    },
};

pub struct MockProofBackend;

impl LinkProofVerifier for MockProofBackend {
    fn verify_link_proof(
        &self,
        proof: &[u8],
        _identity_commitment: Fr,
        _blinded_request: G1Affine,
        _g_id: G1Affine,
    ) -> Result<bool, ProofError> {
        Ok(!proof.is_empty())
    }
}

impl ProofBackend for MockProofBackend {
    fn generate_membership_proof(
        &self,
        _identity_secret: Fr,
        _attrs: &[Fr; 4],
        _version: u32,
        _merkle_path: &MerklePath,
        _root: Fr,
        _external_nullifier: Fr,
        _predicate: &Predicate,
    ) -> Result<Vec<u8>, ProofError> {
        Ok(vec![0xDE, 0xAD])
    }

    fn generate_enrollment_proof(
        &self,
        _identity_secret: Fr,
        _attrs: &[Fr; 4],
        _version: u32,
        _g_id: G1Affine,
        _raw_nullifier: G1Affine,
        _mpc_public_key: G1Affine,
        _dleq_proof: &DleqProof,
    ) -> Result<Vec<u8>, ProofError> {
        Ok(vec![0xBE, 0xEF])
    }

    fn generate_link_proof(
        &self,
        _user_id_hash: Fr,
        _salt: Fr,
        _r: Fr,
        _g_id: G1Affine,
        _identity_commitment: Fr,
        _blinded_request: G1Affine,
        _svdw: &SvdwWitnesses,
    ) -> Result<Vec<u8>, ProofError> {
        Ok(vec![0xCA, 0xFE])
    }
}
